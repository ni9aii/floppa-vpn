mod api;
mod auth;
mod dns;
mod net;
mod reconnect;
mod rollback;
mod service;
mod stop;
mod tunnel;
mod vless;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use floppa_tunnel_config::TunnelConfig;

use api::ApiClientError;

const DEFAULT_API_URL: &str = "https://floppa.okhsunrog.dev/api";

/// `EX_NOPERM` (sysexits.h): the token was rejected or has expired. Distinct from a generic
/// exit 1 so systemd can tell "re-auth needed" apart from a transient failure via
/// `RestartPreventExitStatus=77` (see service.rs).
const EXIT_AUTH: i32 = 77;

#[derive(Parser)]
#[command(name = "floppa-cli", about = "CLI client for Floppa VPN")]
struct Cli {
    /// Write debug logs to a file (e.g. /tmp/floppa-cli.log)
    #[arg(long, global = true)]
    log_file: Option<String>,

    /// Login token file (default: <config dir>/floppa-cli/token; under sudo, the invoking
    /// user's config dir). Being `global = true`, this also applies to `service
    /// install`/`print`, where it sets the `--token-file` value baked into the generated unit's
    /// `Environment=FLOPPA_TOKEN_FILE=...` line — it must NOT be redeclared as a local field on
    /// `ServiceAction`, or clap treats the two same-named args as one shared arg id and the env
    /// var silently applies even when `--token-file` isn't passed on the `service` subcommand
    /// line.
    #[arg(long, global = true, env = "FLOPPA_TOKEN_FILE")]
    token_file: Option<std::path::PathBuf>,

    /// Login token, bypassing the token file (prefer the env var over the flag)
    #[arg(long, global = true, env = "FLOPPA_TOKEN", hide_env_values = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in via Telegram (opens browser)
    Login {
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// Connect to VPN (auto-detects WireGuard/AmneziaWG .conf or VLESS URI)
    Connect {
        /// Config file (.conf) or VLESS URI file
        #[arg(long)]
        config: Option<String>,
        /// Tunnel protocol (AmneziaWG by default, like the app)
        #[arg(long, value_enum, default_value_t = api::Protocol::AmneziaWg)]
        protocol: api::Protocol,
        /// TUN interface name
        #[arg(long, default_value = tunnel::DEFAULT_INTERFACE_NAME)]
        interface: String,
        /// Skip DNS configuration
        #[arg(long)]
        no_dns: bool,
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// List your peers
    Peers {
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// Fetch and print config (WireGuard/AmneziaWG .conf or VLESS URI)
    Config {
        /// Tunnel protocol (AmneziaWG by default, like the app)
        #[arg(long, value_enum, default_value_t = api::Protocol::AmneziaWg)]
        protocol: api::Protocol,
        /// Peer ID (WireGuard/AmneziaWG only; uses first active peer of that protocol if omitted)
        #[arg(long)]
        peer_id: Option<i64>,
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// Sign out: end this login's session on the server and remove the saved token
    Logout {
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// Manage the systemd unit (install/uninstall the connector as a service)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Disconnect a running `floppa-cli connect` from another shell
    Stop {
        /// TUN interface name
        #[arg(long, default_value = tunnel::DEFAULT_INTERFACE_NAME)]
        interface: String,
        /// Target a specific connect process (needed if more than one is running)
        #[arg(long)]
        pid: Option<u32>,
        /// SIGKILL if a plain SIGTERM doesn't bring the interface down in time
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Write /etc/systemd/system/floppa-cli.service and enable it (needs root)
    Install {
        /// Config file (.conf) or VLESS URI file (resolved to an absolute path).
        /// Omit for API mode (the unit calls the Floppa API to fetch a peer/config).
        #[arg(long)]
        config: Option<String>,
        /// Tunnel protocol (AmneziaWG by default, like the app)
        #[arg(long, value_enum, default_value_t = api::Protocol::AmneziaWg)]
        protocol: api::Protocol,
        /// TUN interface name
        #[arg(long, default_value = tunnel::DEFAULT_INTERFACE_NAME)]
        interface: String,
        /// Skip DNS configuration
        #[arg(long)]
        no_dns: bool,
        /// Write debug logs to this file (passed through to the unit's ExecStart)
        #[arg(long)]
        log_file: Option<String>,
        /// Enable only, do not start immediately
        #[arg(long)]
        no_start: bool,
    },
    /// Stop, disable and remove the systemd unit (needs root)
    Uninstall,
    /// Print the unit file to stdout without touching the system
    Print {
        /// Config file (.conf) or VLESS URI file. Omit for API mode.
        #[arg(long)]
        config: Option<String>,
        #[arg(long, value_enum, default_value_t = api::Protocol::AmneziaWg)]
        protocol: api::Protocol,
        #[arg(long, default_value = tunnel::DEFAULT_INTERFACE_NAME)]
        interface: String,
        #[arg(long)]
        no_dns: bool,
        #[arg(long)]
        log_file: Option<String>,
    },
}

fn is_vless(config_str: &str) -> bool {
    config_str.trim().starts_with("vless://")
}

/// Warn (never fail) if the local, unverified read of the token's `exp` claim says it's already
/// past or close to expiry. This is advisory only: the server's 401 is the sole authority for
/// whether the token is actually rejected (see `main`'s exit-code classification). A skewed
/// system clock must not be able to turn this into a hard error.
fn warn_if_expiring(token: &str) {
    let Some(expiry) = auth::token_expiry(token) else {
        return;
    };
    let now = std::time::SystemTime::now();
    match expiry.duration_since(now) {
        Err(_) => eprintln!("Warning: token appears expired — re-login if this fails."),
        Ok(remaining) if remaining <= std::time::Duration::from_secs(24 * 3600) => {
            let hours = remaining.as_secs() / 3600;
            eprintln!("Warning: token expires in {hours}h");
        }
        Ok(_) => {}
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // _guard must live until it is explicitly dropped (below) to flush the file appender. It
    // must NOT still be alive when `std::process::exit` is called: `exit` skips destructors
    // entirely, so a guard dropped only by scope-exit-after-exit would never flush and
    // `--log-file` would lose its tail. So: compute the exit code first, `drop(_guard)`
    // explicitly, THEN call `exit`.
    let _guard = if let Some(ref log_path) = cli.log_file {
        let path = std::path::Path::new(log_path);
        let dir = path.parent().unwrap_or(std::path::Path::new("."));
        let filename = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f.to_string(),
            None => {
                eprintln!("Error: invalid log file path: {log_path}");
                std::process::exit(1);
            }
        };
        let file_appender = tracing_appender::rolling::never(dir, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_writer(non_blocking)
            .with_env_filter(env_filter)
            .init();
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(env_filter)
            .init();
        None
    };

    let result = run(cli).await;

    let code: i32 = match result {
        Ok(()) => 0,
        Err(err) => {
            if let Some(ApiClientError::Unauthorized) = err.downcast_ref::<ApiClientError>() {
                eprintln!("Token expired or rejected. Run `floppa-cli login` again.");
                EXIT_AUTH
            } else {
                eprintln!("Error: {err:#}");
                1
            }
        }
    };

    // Explicit drop BEFORE exit — see the trap noted above.
    drop(_guard);
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<()> {
    let tokens = auth::TokenSource::new(cli.token, cli.token_file.clone());
    let token_file_str = cli
        .token_file
        .as_deref()
        .and_then(|p| p.to_str())
        .map(str::to_string);

    match cli.command {
        Command::Login { api_url } => {
            auth::login(&api_url, &tokens).await?;
        }
        Command::Connect {
            config,
            protocol,
            interface,
            no_dns,
            api_url,
        } => {
            let config_str = match config {
                Some(path) => std::fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read config file: {path}"))?,
                None => {
                    let token = tokens.require()?;
                    warn_if_expiring(&token);
                    let client = api::ApiClient::new(&api_url, &token);
                    let me = client.get_me().await?;
                    if let Some(ref sub) = me.subscription {
                        eprintln!(
                            "Plan: {} (speed limit: {})",
                            sub.plan_name,
                            sub.speed_limit_mbps
                                .map(|s| format!("{s} Mbps"))
                                .unwrap_or_else(|| "unlimited".into())
                        );
                    } else {
                        bail!("No active subscription");
                    }
                    client
                        .config_for(protocol, &auth::device_identity()?)
                        .await?
                }
            };

            if is_vless(&config_str) {
                connect_vless(&config_str, &interface, no_dns).await?;
            } else {
                connect_wireguard(&config_str, &interface, no_dns).await?;
            }
        }
        Command::Peers { api_url } => {
            let token = tokens.require()?;
            let client = api::ApiClient::new(&api_url, &token);
            let peers = client.list_peers().await?;
            if peers.is_empty() {
                eprintln!("No peers found.");
            } else {
                println!(
                    "{:<6} {:<18} {:<14} {:<10} Device",
                    "ID", "IP", "Status", "Protocol"
                );
                for p in &peers {
                    println!(
                        "{:<6} {:<18} {:<14} {:<10} {}",
                        p.id,
                        p.assigned_ip,
                        p.sync_status,
                        p.protocol,
                        p.device_name.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        Command::Config {
            protocol,
            peer_id,
            api_url,
        } => {
            let token = tokens.require()?;
            let client = api::ApiClient::new(&api_url, &token);
            let config = match (protocol, peer_id) {
                (api::Protocol::WireGuard | api::Protocol::AmneziaWg, Some(id)) => {
                    client.get_peer_config(id).await?
                }
                (api::Protocol::Vless, Some(_)) => bail!("--peer-id does not apply to VLESS"),
                (protocol, None) => {
                    client
                        .config_for(protocol, &auth::device_identity()?)
                        .await?
                }
            };
            print!("{config}");
        }
        Command::Logout { api_url } => {
            // Best effort on the server side: a token the server no longer accepts (expired,
            // already signed out elsewhere) is exactly the one that must still go locally.
            if let Some(token) = tokens.load()? {
                match auth::session_id(&token) {
                    Some(session_id) => {
                        match api::ApiClient::new(&api_url, &token)
                            .delete_session(session_id)
                            .await
                        {
                            Ok(()) => eprintln!("Session ended on the server."),
                            Err(
                                api::ApiClientError::Unauthorized
                                | api::ApiClientError::NotFound(_),
                            ) => {
                                eprintln!("The server had already ended this session.")
                            }
                            Err(e) => eprintln!("Could not end the session on the server: {e}"),
                        }
                    }
                    None => {
                        eprintln!("Token has no session to end on the server; removing it locally.")
                    }
                }
            }
            tokens.remove()?;
            eprintln!("Logged out.");
        }
        Command::Service { action } => match action {
            ServiceAction::Install {
                config,
                protocol,
                interface,
                no_dns,
                log_file,
                no_start,
            } => {
                service::install(
                    config.as_deref(),
                    protocol.as_str(),
                    &interface,
                    no_dns,
                    log_file.as_deref(),
                    token_file_str.as_deref(),
                    !no_start,
                )?;
            }
            ServiceAction::Uninstall => {
                service::uninstall()?;
            }
            ServiceAction::Print {
                config,
                protocol,
                interface,
                no_dns,
                log_file,
            } => {
                service::print_unit(
                    config.as_deref(),
                    protocol.as_str(),
                    &interface,
                    no_dns,
                    log_file.as_deref(),
                    token_file_str.as_deref(),
                )?;
            }
        },
        Command::Stop {
            interface,
            pid,
            force,
        } => {
            stop::stop(&interface, pid, force)?;
        }
    }

    Ok(())
}

/// The running tunnel, whichever protocol backs it.
enum Tunnel {
    WireGuard(tunnel::FloppaDevice),
    Vless(shoes_lite::api::VlessTunnel),
}

impl Tunnel {
    async fn stop(self) -> Result<()> {
        match self {
            Tunnel::WireGuard(device) => {
                device.stop().await;
                Ok(())
            }
            Tunnel::Vless(tunnel) => tunnel
                .stop()
                .await
                .map_err(|e| anyhow::anyhow!("VLESS tunnel stop failed: {e}")),
        }
    }
}

/// Tear down a previous (rollback, tunnel) generation, explicitly and completely, before a
/// rebuild constructs the next one.
///
/// Ordering is load-bearing: `Rollback::run` disarms the guard (`take()`s both its fields), so
/// once this returns, dropping the (now-empty) `Rollback` is a harmless no-op — see
/// rollback.rs. If instead the new tunnel were built first and this teardown ran second, it
/// would silently rip out the routes/DNS the new tunnel had just applied. This is exactly the
/// hazard `reconnect`'s rebuild loop creates: it calls the closure repeatedly for the lifetime
/// of the process, so a stale guard firing at the wrong moment is a real, if intermittent,
/// failure mode — not a hypothetical one.
async fn teardown_previous(mut rollback: rollback::Rollback, tunnel: Tunnel) {
    if let Err(e) = rollback.run() {
        eprintln!("Rollback of previous tunnel incomplete: {e:#}");
    }
    if let Err(e) = tunnel.stop().await {
        eprintln!("Failed to stop previous tunnel: {e:#}");
    }
}

async fn connect_wireguard(config_str: &str, interface: &str, no_dns: bool) -> Result<()> {
    let interface = interface.to_string();
    let config_str = config_str.to_string();

    // Shared, rebuildable tunnel state: the live tunnel plus the rollback guard that undoes its
    // host-side changes (routes, DNS). Neither is `Clone`, so both live inside a `RefCell` the
    // rebuild closure swaps on every (re)connect.
    let state: std::rc::Rc<std::cell::RefCell<Option<(rollback::Rollback, Tunnel)>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    let rebuild = {
        let state = state.clone();
        let config_str = config_str.clone();
        let interface = interface.clone();
        move || -> reconnect::BoxFutureLocal<Result<()>> {
            let state = state.clone();
            let config_str = config_str.clone();
            let interface = interface.clone();
            Box::pin(async move {
                // Tear down any previous generation BEFORE building the new one.
                let previous = state.borrow_mut().take();
                if let Some((old_rollback, old_tunnel)) = previous {
                    teardown_previous(old_rollback, old_tunnel).await;
                }

                let config =
                    TunnelConfig::parse(&config_str).context("Invalid WireGuard config")?;
                let endpoint = tunnel::resolve_endpoint(&config).await?;
                let name = if config.is_amneziawg() {
                    "AmneziaWG"
                } else {
                    "WireGuard"
                };
                eprintln!("Creating {name} tunnel on {interface}...");
                let device = tunnel::create_tunnel(&config, endpoint, &interface).await?;
                eprintln!("Configuring networking...");
                let addr = tunnel::bring_up_interface(&config, &interface)?;
                let mut rollback = rollback::Rollback::new(net::configure_routes(
                    endpoint.ip(),
                    &config.peer.allowed_ips,
                    &interface,
                )?);
                eprintln!("VPN IP: {}", addr.ip());
                eprintln!("Endpoint: {} ({endpoint})", config.peer.endpoint);

                let dns_servers: Vec<String> = config
                    .dns_servers()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                if !no_dns && !dns_servers.is_empty() {
                    rollback.set_dns(dns::apply(&interface, &dns_servers)?);
                }

                *state.borrow_mut() = Some((rollback, Tunnel::WireGuard(device)));
                Ok(())
            })
        }
    };

    let health = {
        let state = state.clone();
        let stale_after = reconnect::ReconnectConfig::default().handshake_stale_after;
        move || -> reconnect::BoxFutureLocal<Result<bool>> {
            let state = state.clone();
            Box::pin(async move {
                // Take the state out of the shared cell for the duration of the read so we
                // don't hold a RefCell borrow across an await point.
                let held = state.borrow_mut().take();
                let Some((rollback, tunnel)) = held else {
                    return Ok(false);
                };
                let healthy = match &tunnel {
                    Tunnel::WireGuard(device) => {
                        device
                            .read(async |dr| {
                                dr.peers()
                                    .await
                                    .iter()
                                    .filter_map(|p| p.stats.last_handshake)
                                    .max()
                                    .map(|hs| {
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default();
                                        now.saturating_sub(hs) <= stale_after
                                    })
                                    .unwrap_or(false)
                            })
                            .await
                    }
                    Tunnel::Vless(_) => unreachable!("connect_wireguard only builds WireGuard tunnels"),
                };
                *state.borrow_mut() = Some((rollback, tunnel));
                Ok(healthy)
            })
        }
    };

    let signal = reconnect::ReconnectSignal::default();
    let _watcher = reconnect::spawn_resume_watcher(signal.clone());

    // The reconnect loop owns the lifecycle from here; it drives rebuild/health until a
    // shutdown signal arrives. We reuse Ctrl+C as the abort.
    let shutdown = Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    });
    let result = reconnect::run(
        reconnect::ReconnectConfig::default(),
        Box::new(health),
        Box::new(rebuild),
        &signal,
        shutdown,
    )
    .await;

    eprintln!("\nDisconnecting...");
    // Final teardown happens once, here, after the reconnect loop has returned — not inside the
    // rebuild closure, and not via a `Drop` firing on some other generation's guard.
    let final_state = state.borrow_mut().take();
    if let Some((rollback, tunnel)) = final_state {
        teardown_previous(rollback, tunnel).await;
    }
    result?;
    eprintln!("Disconnected.");
    Ok(())
}

async fn connect_vless(config_str: &str, interface: &str, no_dns: bool) -> Result<()> {
    let interface = interface.to_string();
    let config_str = config_str.trim().to_string();

    let state: std::rc::Rc<std::cell::RefCell<Option<(rollback::Rollback, Tunnel)>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    let rebuild = {
        let state = state.clone();
        let config_str = config_str.clone();
        let interface = interface.clone();
        move || -> reconnect::BoxFutureLocal<Result<()>> {
            let state = state.clone();
            let config_str = config_str.clone();
            let interface = interface.clone();
            Box::pin(async move {
                let previous = state.borrow_mut().take();
                if let Some((old_rollback, old_tunnel)) = previous {
                    teardown_previous(old_rollback, old_tunnel).await;
                }

                let config = vless::parse_uri(config_str.as_str())?;
                eprintln!("Creating VLESS+REALITY tunnel on {interface}...");
                eprintln!("Server: {}", config.server_addr);
                eprintln!("SNI: {}", config.server_name);
                let tunnel = vless::create_tunnel(&config, &interface).await?;

                eprintln!("Configuring networking...");
                let endpoint = vless::endpoint_ip(&config).await?;
                let mut rollback = rollback::Rollback::new(net::configure_routes(
                    endpoint,
                    &vless::allowed_ips_networks(&config)?,
                    &interface,
                )?);
                eprintln!("VPN IP: {}", config.address.as_deref().unwrap_or("unknown"));
                eprintln!("Endpoint: {}", config.server_addr);

                if !no_dns && let Some(ref dns) = config.dns {
                    let servers: Vec<String> =
                        dns.split(',').map(|s| s.trim().to_string()).collect();
                    if !servers.is_empty() {
                        rollback.set_dns(dns::apply(&interface, &servers)?);
                    }
                }

                *state.borrow_mut() = Some((rollback, Tunnel::Vless(tunnel)));
                Ok(())
            })
        }
    };

    let health = {
        let config_str = config_str.clone();
        move || -> reconnect::BoxFutureLocal<Result<bool>> {
            let config_str = config_str.clone();
            Box::pin(async move {
                let cfg = match vless::parse_uri(config_str.as_str()) {
                    Ok(c) => c,
                    Err(_) => return Ok(false),
                };
                let reachable = std::net::TcpStream::connect_timeout(
                    &cfg.server_addr
                        .parse()
                        .unwrap_or_else(|_| "127.0.0.1:443".parse().unwrap()),
                    std::time::Duration::from_secs(3),
                )
                .is_ok();
                Ok(reachable)
            })
        }
    };

    let signal = reconnect::ReconnectSignal::default();
    let _watcher = reconnect::spawn_resume_watcher(signal.clone());

    let shutdown = Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    });
    let result = reconnect::run(
        reconnect::ReconnectConfig::default(),
        Box::new(health),
        Box::new(rebuild),
        &signal,
        shutdown,
    )
    .await;

    eprintln!("\nDisconnecting...");
    let final_state = state.borrow_mut().take();
    if let Some((rollback, tunnel)) = final_state {
        teardown_previous(rollback, tunnel).await;
    }
    result?;
    eprintln!("Disconnected.");
    Ok(())
}
