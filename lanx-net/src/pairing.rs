//! Resolve a CLI target, either an explicit `ip:port` or a pairing code,
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
    let s = s.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Target::Addr(addr));
    }
    if looks_like_code(s) {
        return Ok(Target::Code(s.to_string()));
    }
    Err(TargetError::InvalidAddr(s.to_string()))
}

fn looks_like_code(s: &str) -> bool {
    // Trimmed by caller; also trim here defensively for direct callers.
    // Format: digit-word-...-word (a single ASCII digit plus 2-5 words).
    // Accepts legacy 2-word codes and new longer codes from
    // `--code-words`. Wordlist membership is intentionally not checked
    // (a user may mistype or use a future expanded wordlist; discovery
    // times out with a clear message). The segmentation rules live in
    // [`crate::discovery::code_word_count`] so this parser and that
    // one cannot drift apart on `MIN_CODE_WORDS`/`MAX_CODE_WORDS`.
    crate::discovery::code_word_count(s.trim()) >= crate::discovery::MIN_CODE_WORDS
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
            let addr = crate::discovery::discover(&expected, &code, timeout)
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
        assert!(matches!(
            parse_target("7-cobalt-fox-tundra"),
            Ok(Target::Code(_))
        ));
        assert!(matches!(
            parse_target("7-cobalt-fox-tundra-river-lake"),
            Ok(Target::Code(_))
        ));
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

    #[test]
    fn surrounding_whitespace_trimmed() {
        assert!(matches!(
            parse_target("  7-cobalt-fox\n"),
            Ok(Target::Code(_))
        ));
        assert!(matches!(
            parse_target("  192.168.1.1:51234  "),
            Ok(Target::Addr(_))
        ));
    }
}
