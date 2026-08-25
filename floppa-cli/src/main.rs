mod api;
mod auth;
mod dns;
mod reconnect;
mod service;
mod tunnel;
mod vless;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

const DEFAULT_API_URL: &str = "https://floppa.okhsunrog.dev/api";

/// `EX_NOPERM` (sysexits.h): the token was rejected or has expired. Distinct
/// from a generic exit 1 so systemd can tell "re-auth needed" apart from a
/// transient failure via `RestartPreventExitStatus=77` (see service.rs).
const EXIT_AUTH: i32 = 77;

#[derive(Parser)]
#[command(name = "floppa-cli", about = "CLI client for Floppa VPN")]
struct Cli {
    /// Write debug logs to a file (e.g. /tmp/floppa-cli.log)
    #[arg(long, global = true)]
    log_file: Option<String>,

    /// Override the saved-token path (also settable via FLOPPA_TOKEN_FILE).
    /// Needed when running as root (e.g. under systemd), since root's config
    /// directory is not the user's. Being `global = true`, this also applies
    /// to `service install`/`print`, where it sets the `--token-file` value
    /// baked into the generated unit's `Environment=FLOPPA_TOKEN_FILE=...`
    /// line — it must NOT be redeclared as a local field on `ServiceAction`,
    /// or clap treats the two same-named args as one shared arg id and the
    /// env var silently applies even when `--token-file` isn't passed on the
    /// `service` subcommand line.
    #[arg(long, global = true, env = "FLOPPA_TOKEN_FILE")]
    token_file: Option<String>,

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
        /// Protocol: wireguard (default), amneziawg, or vless
        #[arg(long, default_value = "wireguard")]
        protocol: String,
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
        /// Protocol: wireguard (default), amneziawg, or vless
        #[arg(long, default_value = "wireguard")]
        protocol: String,
        /// Peer ID (WireGuard/AmneziaWG only; uses first active peer of that protocol if omitted)
        #[arg(long)]
        peer_id: Option<i64>,
        #[arg(long, env = "FLOPPA_API_URL", default_value = DEFAULT_API_URL)]
        api_url: String,
    },
    /// Remove saved login token
    Logout,
    /// Manage the systemd unit (install/uninstall the connector as a service)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
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
        /// Protocol: wireguard (default), amneziawg, or vless
        #[arg(long, default_value = "wireguard")]
        protocol: String,
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
        #[arg(long, default_value = "wireguard")]
        protocol: String,
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

/// Warn (never fail) if the local, unverified read of the token's `exp` claim
/// says it's already past or close to expiry. This is advisory only: the
/// server's 401 is the sole authority for whether the token is actually
/// rejected (see `run`'s exit-code classification). A skewed system clock
/// must not be able to turn this into a hard error.
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

    // _guard must live until it is explicitly dropped (below) to flush the
    // file appender. It must NOT still be alive when `std::process::exit` is
    // called: `exit` skips destructors entirely, so a guard dropped only by
    // scope-exit-after-exit would never flush and `--log-file` would lose its
    // tail. So: compute the exit code first, `drop(_guard)` explicitly, THEN
    // call `exit`.
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
    tracing_log::LogTracer::init().ok();

    let result = run(cli).await;

    let code: i32 = match result {
        Ok(()) => 0,
        Err(err) => {
            if err.downcast_ref::<api::ApiError>().is_some() {
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
    let token_file = cli.token_file.as_deref();

    match cli.command {
        Command::Login { api_url } => {
            auth::login(&api_url, token_file).await?;
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
                    let token = auth::load_token(token_file)?
                        .context("Not logged in. Run `floppa-cli login` first.")?;
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
                    if protocol == "vless" {
                        client.get_vless_config().await?
                    } else {
                        client.find_or_create_peer(&protocol).await?
                    }
                }
            };

            if is_vless(&config_str) {
                connect_vless(&config_str, &interface, no_dns).await?;
            } else {
                connect_wireguard(&config_str, &interface, no_dns).await?;
            }
        }
        Command::Peers { api_url } => {
            let token = auth::load_token(token_file)?
                .context("Not logged in. Run `floppa-cli login` first.")?;
            let client = api::ApiClient::new(&api_url, &token);
            let peers = client.list_peers().await?;
            if peers.is_empty() {
                eprintln!("No peers found.");
            } else {
                println!("{:<6} {:<18} {:<14} Device", "ID", "IP", "Status");
                for p in &peers {
                    println!(
                        "{:<6} {:<18} {:<14} {}",
                        p.id,
                        p.assigned_ip,
                        p.sync_status,
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
            let token = auth::load_token(token_file)?
                .context("Not logged in. Run `floppa-cli login` first.")?;
            let client = api::ApiClient::new(&api_url, &token);
            let config = if protocol == "vless" {
                client.get_vless_config().await?
            } else {
                match peer_id {
                    Some(id) => client.get_peer_config(id).await?,
                    None => client.find_or_create_peer(&protocol).await?,
                }
            };
            print!("{config}");
        }
        Command::Logout => {
            auth::logout(token_file)?;
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
                    &protocol,
                    &interface,
                    no_dns,
                    log_file.as_deref(),
                    token_file,
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
                    &protocol,
                    &interface,
                    no_dns,
                    log_file.as_deref(),
                    token_file,
                )?;
            }
        },
    }

    Ok(())
}

async fn connect_wireguard(config_str: &str, interface: &str, no_dns: bool) -> Result<()> {
    let interface = interface.to_string();
    let config_str = config_str.to_string();

    // Shared, rebuildable tunnel state. `Device` is not `Clone` and is torn
    // down via `stop(self)`, so it lives inside a RefCell we swap on rebuild.
    let device: std::rc::Rc<std::cell::RefCell<Option<tunnel::FloppaDevice>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    let rebuild = {
        let device = device.clone();
        let config_str = config_str.clone();
        let interface = interface.clone();
        move || -> reconnect::BoxFutureLocal<Result<()>> {
            let device = device.clone();
            let config_str = config_str.clone();
            let interface = interface.clone();
            Box::pin(async move {
                // Tear down any previous instance before rebuilding.
                let prev = device.borrow_mut().take();
                if let Some(d) = prev {
                    d.stop().await;
                }
                if !no_dns {
                    let _ = dns::restore_dns();
                }

                let wg_config = tunnel::WgConfig::from_config_str(&config_str)?;
                eprintln!("Creating WireGuard tunnel on {interface}...");
                let dev = tunnel::create_tunnel(&wg_config, &interface).await?;
                eprintln!("Configuring networking...");
                tunnel::configure_networking(&wg_config, &interface).await?;
                if !no_dns {
                    dns::set_dns(&wg_config)?;
                }
                *device.borrow_mut() = Some(dev);
                Ok(())
            })
        }
    };

    let health = {
        let device = device.clone();
        let stale_after = reconnect::ReconnectConfig::default().handshake_stale_after;
        move || -> reconnect::BoxFutureLocal<Result<bool>> {
            let device = device.clone();
            Box::pin(async move {
                // Take the device out of the shared cell for the duration of the
                // read so we don't hold a RefCell borrow across an await point.
                let held = device.borrow_mut().take();
                let Some(d) = held else {
                    *device.borrow_mut() = None;
                    return Ok(false);
                };
                // Find the newest handshake across peers; if it is older than the
                // stale threshold (or missing), the tunnel is considered down.
                let result = d
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
                    .await;
                *device.borrow_mut() = Some(d);
                Ok(result)
            })
        }
    };

    let signal = reconnect::ReconnectSignal::default();
    let _watcher = reconnect::spawn_resume_watcher(signal.clone());

    // The reconnect loop owns the lifecycle from here; it drives rebuild/health
    // until a shutdown signal arrives. We reuse Ctrl+C / SIGTERM as the abort.
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
    if !no_dns {
        let _ = dns::restore_dns();
    }
    // Extract the device from the shared cell before awaiting stop().
    let dev = device.borrow_mut().take();
    if let Some(d) = dev {
        d.stop().await;
    }
    result?;
    eprintln!("Disconnected.");
    Ok(())
}

async fn connect_vless(config_str: &str, interface: &str, no_dns: bool) -> Result<()> {
    let interface = interface.to_string();
    let config_str = config_str.trim().to_string();

    let tunnel: std::rc::Rc<std::cell::RefCell<Option<shoes_lite::api::VlessTunnel>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    let rebuild = {
        let tunnel = tunnel.clone();
        let config_str = config_str.clone();
        let interface = interface.clone();
        move || -> reconnect::BoxFutureLocal<Result<()>> {
            let tunnel = tunnel.clone();
            let config_str = config_str.clone();
            let interface = interface.clone();
            Box::pin(async move {
                // Tear down any previous instance before rebuilding.
                let prev = tunnel.borrow_mut().take();
                if let Some(t) = prev {
                    let _ = t.stop().await;
                }
                if !no_dns {
                    let _ = dns::restore_dns();
                }

                let config = vless::parse_uri(config_str.as_str())?;
                eprintln!("Creating VLESS+REALITY tunnel on {interface}...");
                eprintln!("Server: {}", config.server_addr);
                eprintln!("SNI: {}", config.server_name);
                let t = vless::create_tunnel(&config, &interface).await?;
                eprintln!("Configuring networking...");
                vless::configure_networking(&config, &interface).await?;
                if !no_dns && let Some(ref dns) = config.dns {
                    let servers: Vec<String> =
                        dns.split(',').map(|s| s.trim().to_string()).collect();
                    if !servers.is_empty() {
                        dns::write_dns(&servers)?;
                    }
                }
                *tunnel.borrow_mut() = Some(t);
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
    if !no_dns {
        let _ = dns::restore_dns();
    }
    let tunnel_dev = tunnel.borrow_mut().take();
    if let Some(t) = tunnel_dev {
        let _ = t.stop().await;
    }
    result?;
    eprintln!("Disconnected.");
    Ok(())
}
