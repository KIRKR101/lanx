pub mod recv;
pub mod relay;

use std::net::ToSocketAddrs;

const DEFAULT_RELAY_SENDER_PORT: u16 = 53318;
const DEFAULT_RELAY_RECEIVER_PORT: u16 = 53319;

pub fn resolve_relay(
    value: Option<Option<String>>,
    receiver: bool,
) -> anyhow::Result<Option<String>> {
    match value {
        Some(Some(address)) => Ok(Some(address)),
        Some(None) => {
            let host = saved_relay()?;
            let port = if receiver {
                DEFAULT_RELAY_RECEIVER_PORT
            } else {
                DEFAULT_RELAY_SENDER_PORT
            };
            let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{host}]")
            } else {
                host
            };
            Ok(Some(format!("{host}:{port}")))
        }
        None => Ok(None),
    }
}

fn config_path() -> anyhow::Result<std::path::PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("APPDATA is not set"))?
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
            })
            .ok_or_else(|| anyhow::anyhow!("XDG_CONFIG_HOME or HOME is not set"))?
    };
    Ok(base.join("lanx").join("relay"))
}

fn saved_relay() -> anyhow::Result<String> {
    let path = config_path()?;
    let value = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("no relay configured; run `lanx relay set <host>`"))?;
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("no relay configured; run `lanx relay set <host>`");
    }
    Ok(value.to_owned())
}

pub fn set_relay(host: String) -> anyhow::Result<()> {
    if host.is_empty()
        || host.contains('/')
        || host.chars().any(char::is_whitespace)
        || (host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err())
    {
        anyhow::bail!("invalid relay host: {host}");
    }
    for port in [DEFAULT_RELAY_SENDER_PORT, DEFAULT_RELAY_RECEIVER_PORT] {
        let address = format_relay_address(&host, port);
        let reachable = address.to_socket_addrs().map_or(false, |mut addresses| {
            addresses.any(|address| {
                std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(3))
                    .is_ok()
            })
        });
        if !reachable {
            eprintln!("warning: relay is not reachable at {address}");
        }
    }
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{host}\n"))?;
    println!("saved relay: {host}");
    Ok(())
}

fn format_relay_address(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn clear_relay() -> anyhow::Result<()> {
    let path = config_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => println!("cleared saved relay"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("no saved relay")
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub fn show_relay() -> anyhow::Result<()> {
    println!("{}", saved_relay()?);
    Ok(())
}
pub mod send;

/// Validate that parallel > 1 is not used with --relay.
pub fn validate_parallel_relay(parallel: u16, relay: &Option<String>) -> anyhow::Result<()> {
    if relay.is_some() && parallel > 1 {
        anyhow::bail!("--parallel > 1 is not supported with --relay");
    }
    Ok(())
}

/// Resolve the handshake passphrase: explicit `--psk` wins, otherwise the
/// `LANX_PSK` env var when set and non-empty. Returns `None` when neither
/// is provided (code-only authentication).
pub fn resolve_passphrase(opt: Option<String>) -> Option<String> {
    if let Some(p) = opt {
        if p.is_empty() {
            return None;
        }
        return Some(p);
    }
    std::env::var("LANX_PSK").ok().filter(|v| !v.is_empty())
}

pub fn relay_auth_token() -> Option<String> {
    std::env::var("LANX_RELAY_AUTH_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

pub fn relay_connect_hint(relay: &str, role: &str) -> String {
    format!(
        "connect to relay {relay} ({role} endpoint) failed; verify `lanx relay` is running \
         and the relay firewall exposes both listener ports; if registration fails after \
         connection, check that the auth token matches; \
         test the relay with `lanx doctor --relay <sender-host>:53318`"
    )
}

/// Warn when a relay target is not LAN-local: the pairing ID is visible
/// to the relay and network path, so short codes without `--psk` are
/// guessable there. Public targets get the strong warning; unparseable
/// hostnames get a softer can't-verify note.
pub fn warn_if_public_relay(relay: &str) {
    use lanx_net::discovery::{classify_relay_target, RelayVisibility};
    match classify_relay_target(relay) {
        RelayVisibility::Private => {}
        RelayVisibility::Public => {
            eprintln!(
                "  {} {}",
                crate::ui::yellow("!"),
                crate::ui::yellow(&format!(
                    "relay {relay} looks public (not LAN-private); pairing IDs are visible to \
                     the relay and network — use --code-words 4 (sender) and --psk for internet relays"
                )),
            );
        }
        RelayVisibility::Unknown => {
            eprintln!(
                "  {} {}",
                crate::ui::yellow("!"),
                crate::ui::yellow(&format!(
                    "relay {relay} is not a LAN IP literal; if it routes over the internet, \
                     pairing IDs are visible on the path — consider --psk"
                )),
            );
        }
    }
}
