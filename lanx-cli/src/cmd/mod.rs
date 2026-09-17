pub mod recv;
pub mod relay;
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
