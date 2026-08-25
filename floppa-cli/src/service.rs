//! `floppa-cli service` — install/uninstall a systemd unit that runs the
//! connector on boot and restarts it if it exits with a fatal error.
//!
//! The in-process reconnect loop (see `reconnect.rs`) already recovers from
//! transient drops and sleep/resume; the systemd unit only adds boot-time
//! start and recovery from a hard process exit.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

const UNIT_NAME: &str = "floppa-cli.service";
const UNIT_PATH: &str = "/etc/systemd/system/floppa-cli.service";

/// Render the systemd unit text for the current binary and connect arguments.
///
/// `config` is `None` for API mode: the unit calls `floppa-cli connect` with
/// no `--config`, so the connector fetches (or creates) a peer/config from
/// the Floppa API using the saved token instead of reading a `.conf` file.
#[allow(clippy::too_many_arguments)]
fn render_unit(
    exec_path: &Path,
    config: Option<&str>,
    protocol: &str,
    interface: &str,
    no_dns: bool,
    log_file: Option<&str>,
    token_file: Option<&str>,
) -> String {
    // Build the ExecStart line from the concrete arguments the user chose so the
    // unit is self-contained and reproducible.
    let mut exec = format!(
        "{} connect --protocol {} --interface {}",
        exec_path.display(),
        protocol,
        interface,
    );
    if let Some(config) = config {
        exec.push_str(&format!(" --config {config}"));
    }
    if no_dns {
        exec.push_str(" --no-dns");
    }
    if let Some(log_file) = log_file {
        exec.push_str(&format!(" --log-file {log_file}"));
    }

    let environment = match token_file {
        Some(path) => format!("Environment=FLOPPA_TOKEN_FILE={path}\n"),
        None => String::new(),
    };

    format!(
        "[Unit]\n\
         Description=Floppa VPN CLI client ({protocol})\n\
         Documentation=https://github.com/ni9aii/floppa-CLI/blob/main/docs/RECONNECT.md\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=120\n\
         StartLimitBurst=10\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         {environment}ExecStart={exec}\n\
         # Auto-reconnect is handled in-process (see docs/RECONNECT.md); this\n\
         # only recovers from a fatal process exit.\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # A 401 from the API (expired/rejected token) is fatal, not transient —\n\
         # exit 77 (EX_NOPERM) means \"stop and tell the user\", not \"retry\".\n\
         # Without this, an expired token burns the whole StartLimitBurst in\n\
         # seconds and leaves the unit in start-limit-hit.\n\
         RestartPreventExitStatus=77\n\
         # A clean SIGINT/SIGTERM shutdown (130/143) is not a failure.\n\
         SuccessExitStatus=0 130 143\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

fn require_root() -> Result<()> {
    // Writing to /etc/systemd/system and calling systemctl both need root.
    if effective_uid() != 0 {
        bail!("`floppa-cli service` needs root. Re-run with sudo.");
    }
    Ok(())
}

// Effective UID without pulling in the `libc` crate: shell out to `id -u`,
// which is universally available. Returns a non-zero value (treated as
// "not root") if anything goes wrong.
fn effective_uid() -> u32 {
    match Command::new("id").arg("-u").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u32>()
            .unwrap_or(1),
        _ => 1,
    }
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run: systemctl {}", args.join(" ")))?;
    if !status.success() {
        bail!(
            "systemctl {} failed (exit {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

/// Install and enable the unit. `config`, when given, must be a path to a
/// .conf / VLESS URI file (a relative path is resolved to absolute so the
/// unit works from any cwd). `None` renders an API-mode unit — no
/// `--config`, canonicalization is skipped entirely.
#[allow(clippy::too_many_arguments)]
pub fn install(
    config: Option<&str>,
    protocol: &str,
    interface: &str,
    no_dns: bool,
    log_file: Option<&str>,
    token_file: Option<&str>,
    enable_now: bool,
) -> Result<()> {
    require_root()?;

    let exec_path = std::env::current_exe().context("Cannot resolve path to floppa-cli binary")?;

    // Resolve the config path to absolute; the unit runs with an unspecified
    // cwd. Only done when a config was actually given — API mode has none.
    let config_abs: Option<PathBuf> = match config {
        Some(config) => Some(
            std::fs::canonicalize(config)
                .with_context(|| format!("Config file not found: {config}"))?,
        ),
        None => None,
    };
    let config_str = config_abs.as_ref().map(|p| p.to_string_lossy().to_string());

    let unit = render_unit(
        &exec_path,
        config_str.as_deref(),
        protocol,
        interface,
        no_dns,
        log_file,
        token_file,
    );
    std::fs::write(UNIT_PATH, unit).with_context(|| format!("Failed to write {UNIT_PATH}"))?;
    eprintln!("Wrote {UNIT_PATH}");

    systemctl(&["daemon-reload"])?;
    if enable_now {
        systemctl(&["enable", "--now", UNIT_NAME])?;
        eprintln!("Enabled and started {UNIT_NAME}");
        eprintln!("Check status: systemctl status {UNIT_NAME}");
    } else {
        systemctl(&["enable", UNIT_NAME])?;
        eprintln!("Enabled {UNIT_NAME} (not started). Start with: systemctl start {UNIT_NAME}");
    }
    Ok(())
}

/// Stop, disable and remove the unit.
pub fn uninstall() -> Result<()> {
    require_root()?;

    if Path::new(UNIT_PATH).exists() {
        // Best-effort disable+stop; ignore errors if it was never started.
        let _ = systemctl(&["disable", "--now", UNIT_NAME]);
        std::fs::remove_file(UNIT_PATH).with_context(|| format!("Failed to remove {UNIT_PATH}"))?;
        eprintln!("Removed {UNIT_PATH}");
        systemctl(&["daemon-reload"])?;
    } else {
        eprintln!("{UNIT_PATH} not present; nothing to uninstall.");
    }
    Ok(())
}

/// Print the unit that would be written, without touching the system.
pub fn print_unit(
    config: Option<&str>,
    protocol: &str,
    interface: &str,
    no_dns: bool,
    log_file: Option<&str>,
    token_file: Option<&str>,
) -> Result<()> {
    let exec_path =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/floppa-cli"));
    print!(
        "{}",
        render_unit(
            &exec_path,
            config,
            protocol,
            interface,
            no_dns,
            log_file,
            token_file,
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn unit_contains_exec_and_restart() {
        let unit = render_unit(
            &PathBuf::from("/usr/local/bin/floppa-cli"),
            Some("/etc/floppa-cli/client.conf"),
            "wireguard",
            "floppa0",
            false,
            None,
            None,
        );
        assert!(unit.contains("ExecStart=/usr/local/bin/floppa-cli connect"));
        assert!(unit.contains("--config /etc/floppa-cli/client.conf"));
        assert!(unit.contains("--protocol wireguard"));
        assert!(unit.contains("--interface floppa0"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(!unit.contains("--no-dns"));
        assert!(unit.contains("RestartPreventExitStatus=77"));
        assert!(unit.contains("SuccessExitStatus=0 130 143"));
    }

    #[test]
    fn unit_appends_no_dns_flag() {
        let unit = render_unit(
            &PathBuf::from("/usr/local/bin/floppa-cli"),
            Some("/cfg"),
            "vless",
            "floppa0",
            true,
            None,
            None,
        );
        assert!(unit.contains("--no-dns"));
        assert!(unit.contains("Description=Floppa VPN CLI client (vless)"));
    }

    #[test]
    fn unit_with_no_config_renders_api_mode() {
        let unit = render_unit(
            &PathBuf::from("/usr/local/bin/floppa-cli"),
            None,
            "amneziawg",
            "floppa1",
            true,
            Some("/var/log/floppa-cli.log"),
            None,
        );
        assert!(!unit.contains("--config"));
        assert!(unit.contains("ExecStart=/usr/local/bin/floppa-cli connect --protocol amneziawg --interface floppa1"));
        assert!(unit.contains("--log-file /var/log/floppa-cli.log"));
        assert!(unit.contains("RestartPreventExitStatus=77"));
    }

    #[test]
    fn unit_with_token_file_emits_environment() {
        let unit = render_unit(
            &PathBuf::from("/usr/local/bin/floppa-cli"),
            None,
            "wireguard",
            "floppa1",
            false,
            None,
            Some("/home/user/.config/floppa-cli/token"),
        );
        assert!(unit.contains("Environment=FLOPPA_TOKEN_FILE=/home/user/.config/floppa-cli/token"));
    }

    #[test]
    fn unit_without_token_file_has_no_environment_line() {
        let unit = render_unit(
            &PathBuf::from("/usr/local/bin/floppa-cli"),
            Some("/cfg"),
            "wireguard",
            "floppa1",
            false,
            None,
            None,
        );
        assert!(!unit.contains("Environment="));
    }
}
