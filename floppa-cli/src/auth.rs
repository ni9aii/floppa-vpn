use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::api::ApiClient;

fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Cannot determine config directory"))?
        .join("floppa-cli");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Resolve the token file path. `override_path` (the `--token-file` /
/// `FLOPPA_TOKEN_FILE` value) wins when set — this is what lets a unit
/// running as `User=root` read a token that was saved by a normal user.
fn token_path(override_path: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("token"))
}

pub fn load_token(override_path: Option<&str>) -> Result<Option<String>> {
    let path = token_path(override_path)?;
    if path.exists() {
        let token = fs::read_to_string(&path)
            .context("Failed to read token file")?
            .trim()
            .to_string();
        if token.is_empty() {
            return Ok(None);
        }
        Ok(Some(token))
    } else {
        Ok(None)
    }
}

fn save_token(token: &str, override_path: Option<&str>) -> Result<()> {
    let path = token_path(override_path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&path, token).context("Failed to save token")?;
    // Restrict permissions. This applies to the --token-file override path
    // too: a root-readable token in the user's home is the same secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn logout(override_path: Option<&str>) -> Result<()> {
    let path = token_path(override_path)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Decode the `exp` claim from a JWT without verifying the signature. This is
/// advisory only — used to warn the user before expiry — never to reject a
/// token. Returns `None` for anything that isn't a parsable JWT with a
/// numeric `exp`; callers must treat that as "unknown", not "expired".
pub fn token_expiry(token: &str) -> Option<SystemTime> {
    use base64::Engine;

    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    let exp = payload.get("exp")?.as_u64()?;
    // `checked_add`, not `+`: an out-of-range `exp` (garbage or hostile token)
    // must fall through to `None` like any other unparsable claim, not panic
    // via `SystemTime`'s `Add` overflow. This function must never turn into a
    // hard error — see its doc comment.
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp))
}

/// Run the login flow: start local server, open browser, capture code, exchange for JWT.
pub async fn login(api_url: &str, token_file: Option<&str>) -> Result<()> {
    // Bind to a random port on 127.0.0.1
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let auth_url = format!(
        "{}/auth/telegram/start?redirect_uri={}",
        api_url.trim_end_matches('/'),
        urlencoding(&redirect_uri)
    );

    eprintln!("Opening browser for Telegram login...");
    eprintln!("If it doesn't open, visit: {auth_url}");

    if open::that(&auth_url).is_err() {
        eprintln!("Failed to open browser automatically.");
    }

    // Wait for the callback
    let code = wait_for_callback(listener).await?;

    // Exchange code for JWT
    let auth = ApiClient::exchange_code(api_url, &code).await?;
    save_token(&auth.token, token_file)?;

    let name = auth
        .user
        .username
        .as_deref()
        .or(auth.user.first_name.as_deref())
        .unwrap_or("user");

    eprintln!("Logged in as {name} (id: {})", auth.user.id);

    match token_expiry(&auth.token) {
        Some(exp) => eprintln!("Token valid until {}", format_time(exp)),
        None => eprintln!("Could not determine token expiry (unexpected token format)."),
    }

    Ok(())
}

/// Render a `SystemTime` as a UTC `YYYY-MM-DD HH:MM:SS UTC` timestamp without
/// pulling in a date/time crate — good enough for a human-facing log line.
fn format_time(t: SystemTime) -> String {
    let secs = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (hour, minute, second) = (time_of_day / 3600, (time_of_day / 60) % 60, time_of_day % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Days-since-epoch to (year, month, day), UTC civil calendar. Standard
/// algorithm (Howard Hinnant's `civil_from_days`); avoids a date/time crate
/// dependency for what is otherwise a one-line format.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Wait for a single HTTP GET request on the callback listener, extract `code` param.
async fn wait_for_callback(listener: TcpListener) -> Result<String> {
    let (mut stream, _) = listener
        .accept()
        .await
        .context("Failed to accept callback connection")?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse GET /callback?code=XYZ HTTP/1.1
    let code = request
        .lines()
        .next()
        .and_then(|line| {
            let path = line.split_whitespace().nth(1)?;
            let query = path.split('?').nth(1)?;
            query.split('&').find_map(|param| {
                let (k, v) = param.split_once('=')?;
                if k == "code" {
                    Some(v.to_string())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| anyhow!("No 'code' parameter in callback"))?;

    // Respond with success page
    let body = r#"<!DOCTYPE html>
<html><head><title>Floppa VPN</title></head>
<body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
<div style="text-align:center">
<h1>Login successful!</h1>
<p>You can close this tab and return to the terminal.</p>
</div></body></html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok(code)
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Build a minimal unsigned JWT with the given payload JSON — good enough
    /// for testing the (unverified) decode path.
    fn fake_jwt(payload_json: &str) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn token_expiry_reads_known_exp() {
        let token = fake_jwt(r#"{"sub":"1","exp":1735689600}"#);
        let expiry = token_expiry(&token).expect("should decode exp");
        assert_eq!(
            expiry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_735_689_600)
        );
    }

    #[test]
    fn token_expiry_none_for_malformed_jwt() {
        assert!(token_expiry("not.a.jwt").is_none());
    }

    #[test]
    fn token_expiry_none_for_opaque_token() {
        assert!(token_expiry("just-some-opaque-token-string").is_none());
    }

    #[test]
    fn format_time_renders_known_date() {
        // 1735689600 = 2025-01-01T00:00:00Z
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_735_689_600);
        assert_eq!(format_time(t), "2025-01-01 00:00:00 UTC");
    }
}
