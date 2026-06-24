//! Resolve a CLI target — either an explicit `ip:port` or a pairing code —
//! into a `SocketAddr`.

use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum Target {
    Addr(SocketAddr),
    Code(String),
}

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("invalid ip:port: {0}")]
    InvalidAddr(String),
    #[error("invalid pairing code: {0}")]
    InvalidCode(String),
    #[error("discovery failed: {0}")]
    Discovery(String),
}

/// Parse a CLI target into either an explicit address or a pairing code.
///
/// # Errors
///
/// Returns `TargetError::InvalidAddr` if `s` is not a valid `ip:port`
/// and does not look like a pairing code.
pub fn parse_target(s: &str) -> Result<Target, TargetError> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Target::Addr(addr));
    }
    if looks_like_code(s) {
        return Ok(Target::Code(s.to_string()));
    }
    Err(TargetError::InvalidAddr(s.to_string()))
}

fn looks_like_code(s: &str) -> bool {
    // Format: digit-word-word (3 dash-separated segments, last two are words).
    let parts: Vec<_> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    // Digit must be a single ASCII digit (0-9), matching the format
    // `port % 10` used by generate_code.
    if parts[0].len() != 1 || !parts[0].chars().next().unwrap().is_ascii_digit() {
        return false;
    }
    // Validate that words are alphabetic. We do NOT enforce wordlist
    // membership here because generate_code produces codes from the
    // wordlist, but a user may mistype or use a future expanded list.
    // If the code doesn't match any sender, discovery will time out
    // with a clear message.
    parts[1].chars().all(|c| c.is_ascii_alphabetic())
        && parts[2].chars().all(|c| c.is_ascii_alphabetic())
}

/// Resolve a `Target` into a concrete `SocketAddr`.
///
/// # Errors
///
/// Returns `TargetError::Discovery` if UDP discovery fails to find a
/// matching sender within the timeout.
pub async fn resolve_target(
    target: Target,
    timeout: std::time::Duration,
) -> Result<SocketAddr, TargetError> {
    match target {
        Target::Addr(a) => Ok(a),
        Target::Code(code) => {
            let expected = crate::discovery::code_to_hash(&code);
            let addr = crate::discovery::discover(&expected, timeout)
                .await
                .map_err(|e| TargetError::Discovery(e.to_string()))?;
            Ok(addr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_code_accepted() {
        assert!(matches!(parse_target("7-cobalt-fox"), Ok(Target::Code(_))));
    }

    #[test]
    fn multi_digit_number_rejected() {
        // Only single-digit prefixes (0-9) are valid per the code format.
        assert!(matches!(
            parse_target("99-cobalt-fox"),
            Err(TargetError::InvalidAddr(_))
        ));
    }

    #[test]
    fn non_numeric_prefix_rejected() {
        assert!(matches!(
            parse_target("a-cobalt-fox"),
            Err(TargetError::InvalidAddr(_))
        ));
    }

    #[test]
    fn ip_port_accepted() {
        assert!(matches!(
            parse_target("192.168.1.1:51234"),
            Ok(Target::Addr(_))
        ));
    }

    #[test]
    fn case_insensitive_code_accepted() {
        // Case normalization in code_to_hash ensures "7-Cobalt-Fox" and
        // "7-cobalt-fox" produce the same hash.
        assert!(matches!(parse_target("7-Cobalt-Fox"), Ok(Target::Code(_))));
    }

    #[test]
    fn non_wordlist_code_accepted() {
        // looks_like_code intentionally validates format only, not wordlist
        // membership. Discovery will time out if no sender matches.
        assert!(matches!(parse_target("7-hello-world"), Ok(Target::Code(_))));
    }
}
