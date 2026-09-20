pub mod recv;
pub mod relay;

use std::net::ToSocketAddrs;

const DEFAULT_RELAY_SENDER_PORT: u16 = 53318;
const DEFAULT_RELAY_RECEIVER_PORT: u16 = 53319;

/// How the relay transport was selected. The default stays direct-only
/// until relay fallback is proven stable; `--relay auto` is the explicit
/// opt-in for automatic selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// No relay: direct connection only (default).
    Direct,
    /// One explicit relay address (or the saved relay expanded per role).
    Explicit(String),
    /// Automatic selection: direct discovery, then the saved relay, then
    /// the public pool — in that order.
    Auto,
}

pub fn resolve_relay_mode(
    value: Option<Option<String>>,
    receiver: bool,
) -> anyhow::Result<RelayMode> {
    match value {
        Some(Some(address)) if address.eq_ignore_ascii_case("auto") => Ok(RelayMode::Auto),
        Some(Some(address)) => Ok(RelayMode::Explicit(address)),
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
            Ok(RelayMode::Explicit(format!("{host}:{port}")))
        }
        None => Ok(RelayMode::Direct),
    }
}

/// Saved relay expanded for `--relay auto` receivers
/// (`host:53319`), or `None` when no relay was saved with
/// `lanx relay set <host>`.
pub fn saved_relay_for_auto() -> Option<String> {
    let host = saved_relay().ok()?;
    Some(format_relay_address(&host, DEFAULT_RELAY_RECEIVER_PORT))
}

/// Ordered relay fallback candidates for `--relay auto` (sender side
/// uses the sender-port expansion, receiver side the receiver-port one):
/// saved relay first, then the public pool in file order.
pub fn auto_relay_candidates(receiver: bool) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(host) = saved_relay() {
        let port = if receiver {
            DEFAULT_RELAY_RECEIVER_PORT
        } else {
            DEFAULT_RELAY_SENDER_PORT
        };
        out.push(format_relay_address(&host, port));
    }
    out.extend(load_public_pool());
    out
}

/// Message printed when `--relay auto` has no public fallback to try:
/// an empty pool means no public fallback exists.
pub fn empty_pool_warning() -> String {
    "no public relays configured: automatic fallback will try direct discovery \
     and the saved relay only; add public relays with \
     `lanx relay pool add <host:port>` (single-port relay address)"
        .to_string()
}

fn config_dir() -> anyhow::Result<std::path::PathBuf> {
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
    Ok(base.join("lanx"))
}

fn config_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(config_dir()?.join("relay"))
}

/// Default port for public pool entries without an explicit port: the
/// single-port relay listener. Pool entries are unified addresses — both
/// sender and receiver dial the same `host:port`.
pub const PUBLIC_POOL_DEFAULT_PORT: u16 = 53318;

fn public_pool_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(config_dir()?.join("public_relays"))
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
        let reachable = address.to_socket_addrs().is_ok_and(|mut addresses| {
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

/// Validate and normalize one public pool entry into `host:port` form.
/// Accepts `host`, `host:port`, and `[v6]` / `[v6]:port`; a missing port
/// defaults to [`PUBLIC_POOL_DEFAULT_PORT`]. Hostnames, IPv4 literals,
/// and bracketed IPv6 literals are all accepted — resolution (with
/// IPv4/IPv6 fallback, or proxy-side DNS when a proxy is set) happens
/// at connect time, so this only checks shape.
pub fn parse_pool_entry(raw: &str) -> anyhow::Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        anyhow::bail!("empty relay entry");
    }
    if s.contains('/') || s.chars().any(char::is_whitespace) {
        anyhow::bail!("invalid relay entry: {raw:?}");
    }
    if let Some(rest) = s.strip_prefix('[') {
        // Bracketed IPv6: [host] or [host]:port.
        let (host, port) = match rest.split_once("]:") {
            Some((host, port)) => (host, Some(port)),
            None => match rest.strip_suffix(']') {
                Some(host) => (host, None),
                None => anyhow::bail!("invalid relay entry: {raw:?}"),
            },
        };
        if host.is_empty() || host.contains('[') || host.contains(']') {
            anyhow::bail!("invalid relay entry: {raw:?}");
        }
        let port = match port {
            Some(p) => parse_pool_port(p, raw)?,
            None => PUBLIC_POOL_DEFAULT_PORT,
        };
        return Ok(format!("[{host}]:{port}"));
    }
    if s.chars().filter(|&c| c == ':').count() > 1 {
        anyhow::bail!(
            "invalid relay entry: {raw:?} (bracket IPv6 literals like [2001:db8::1]:53318)"
        );
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            (host, parse_pool_port(port, raw)?)
        }
        _ => (s, PUBLIC_POOL_DEFAULT_PORT),
    };
    if host.is_empty() || host.contains(':') || host.contains('[') || host.contains(']') {
        anyhow::bail!("invalid relay entry: {raw:?}");
    }
    // Reject a trailing-colon typo explicitly (e.g. "host:").
    if s.ends_with(':') {
        anyhow::bail!("invalid relay entry: {raw:?}");
    }
    Ok(format!("{host}:{port}"))
}

fn parse_pool_port(port: &str, raw: &str) -> anyhow::Result<u16> {
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid relay entry: {raw:?}"))?;
    if port == 0 {
        anyhow::bail!("invalid relay entry: {raw:?} (port 0 is not usable)");
    }
    Ok(port)
}

/// Load the public relay pool from the normal Lanx config directory.
/// Missing file means an empty pool. Invalid lines are ignored with a
/// stderr warning; the returned entries are normalized `host:port`
/// strings in file order, deduplicated.
pub fn load_public_pool() -> Vec<String> {
    let path = match public_pool_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("warning: cannot locate Lanx config: {e}");
            return Vec::new();
        }
    };
    load_pool_from(&path)
}

fn load_pool_from(path: &std::path::Path) -> Vec<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            eprintln!("warning: cannot read public relay pool: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_pool_entry(line) {
            Ok(entry) => {
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
            Err(_) => eprintln!("warning: ignoring invalid public relay entry: {line:?}"),
        }
    }
    out
}

/// Print the public relay pool, one entry per line.
pub fn list_public_pool() -> anyhow::Result<()> {
    for entry in load_public_pool() {
        println!("{entry}");
    }
    Ok(())
}

/// Add one entry to the public relay pool.
pub fn add_public_relay(raw: String) -> anyhow::Result<()> {
    let entry = parse_pool_entry(&raw)?;
    let path = public_pool_path()?;
    let mut entries = load_pool_from(&path);
    if entries.contains(&entry) {
        println!("already in public relay pool: {entry}");
        return Ok(());
    }
    entries.push(entry.clone());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, entries.join("\n") + "\n")?;
    println!("added to public relay pool: {entry}");
    Ok(())
}

/// Remove one entry from the public relay pool.
pub fn remove_public_relay(raw: String) -> anyhow::Result<()> {
    let entry = parse_pool_entry(&raw)?;
    let path = public_pool_path()?;
    let entries = load_pool_from(&path);
    if !entries.contains(&entry) {
        println!("not in public relay pool: {entry}");
        return Ok(());
    }
    let kept: Vec<_> = entries.into_iter().filter(|e| e != &entry).collect();
    if kept.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    } else if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::write(&path, kept.join("\n") + "\n")?;
    }
    println!("removed from public relay pool: {entry}");
    Ok(())
}

/// Delete the public relay pool file.
pub fn clear_public_pool() -> anyhow::Result<()> {
    let path = public_pool_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => println!("cleared public relay pool"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("public relay pool is already empty")
        }
        Err(e) => return Err(e.into()),
    }
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

/// Resolve the SOCKS5 proxy: explicit `--proxy` wins, otherwise the
/// `LANX_PROXY` env var when set and non-empty. Accepts
/// `socks5://[user[:pass]@]host:port` (or `socks5h://`, same behavior)
/// and bare `host:port`. Returns `None` for direct connections.
pub fn resolve_proxy(opt: Option<String>) -> anyhow::Result<Option<lanx_net::socks::Socks5Config>> {
    let raw = match opt {
        Some(value) if !value.is_empty() => value,
        Some(_) => return Ok(None),
        None => match std::env::var("LANX_PROXY") {
            Ok(value) if !value.is_empty() => value,
            _ => return Ok(None),
        },
    };
    lanx_net::socks::parse_socks5_proxy(&raw)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("invalid proxy {raw:?}: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_entries_accept_hostnames_and_ports() {
        assert_eq!(
            parse_pool_entry("relay.example.com:53318").unwrap(),
            "relay.example.com:53318"
        );
        assert_eq!(
            parse_pool_entry("relay.example.com").unwrap(),
            format!("relay.example.com:{PUBLIC_POOL_DEFAULT_PORT}")
        );
        assert_eq!(
            parse_pool_entry("192.0.2.10:6000").unwrap(),
            "192.0.2.10:6000"
        );
        assert_eq!(
            parse_pool_entry("[2001:db8::1]:53318").unwrap(),
            "[2001:db8::1]:53318"
        );
        assert_eq!(
            parse_pool_entry("[2001:db8::1]").unwrap(),
            format!("[2001:db8::1]:{PUBLIC_POOL_DEFAULT_PORT}")
        );
    }

    #[test]
    fn pool_entries_reject_bad_shapes() {
        for bad in [
            "",
            "   ",
            "host:0",
            "host:notaport",
            "host:",
            "2001:db8::1",
            "[2001:db8::1",
            "a/b:1234",
            "ho st:1234",
        ] {
            assert!(parse_pool_entry(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn pool_file_ignores_invalid_lines_with_dedup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("public_relays");
        std::fs::write(
            &path,
            "# comment\n\nrelay.example.com:53318\nbad entry here\n192.0.2.10\nrelay.example.com:53318\n",
        )
        .expect("write pool");
        let entries = load_pool_from(&path);
        assert_eq!(
            entries,
            vec![
                "relay.example.com:53318".to_string(),
                format!("192.0.2.10:{PUBLIC_POOL_DEFAULT_PORT}"),
            ]
        );
    }

    #[test]
    fn missing_pool_file_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load_pool_from(&dir.path().join("absent")).is_empty());
    }

    #[test]
    fn relay_auto_is_explicit_opt_in() {
        assert_eq!(resolve_relay_mode(None, false).unwrap(), RelayMode::Direct);
        assert_eq!(resolve_relay_mode(None, true).unwrap(), RelayMode::Direct);
        for spelling in ["auto", "AUTO", "Auto"] {
            assert_eq!(
                resolve_relay_mode(Some(Some(spelling.to_string())), false).unwrap(),
                RelayMode::Auto
            );
            assert_eq!(
                resolve_relay_mode(Some(Some(spelling.to_string())), true).unwrap(),
                RelayMode::Auto
            );
        }
        // An explicit address keeps working and never becomes auto.
        assert_eq!(
            resolve_relay_mode(Some(Some("relay.example.com:53318".to_string())), false).unwrap(),
            RelayMode::Explicit("relay.example.com:53318".to_string())
        );
        // A host named like auto with a port stays an explicit address.
        assert!(matches!(
            resolve_relay_mode(Some(Some("auto:53318".to_string())), false).unwrap(),
            RelayMode::Explicit(_)
        ));
    }

    #[test]
    fn empty_pool_warning_explains_how_to_configure() {
        let warning = empty_pool_warning();
        assert!(warning.contains("lanx relay pool add"), "{warning}");
    }

    #[test]
    fn proxy_parsing_accepts_urls_and_bare_endpoints() {
        let cfg = resolve_proxy(Some("socks5://127.0.0.1:9050".to_string())).expect("url");
        assert_eq!(
            cfg.expect("some").proxy_target,
            "127.0.0.1:9050".to_string()
        );
        let cfg = resolve_proxy(Some("127.0.0.1:9050".to_string())).expect("bare");
        assert!(cfg.is_some());
        assert!(resolve_proxy(Some(String::new())).expect("empty").is_none());
        assert!(resolve_proxy(Some("http://proxy:1080".to_string())).is_err());
    }
}
