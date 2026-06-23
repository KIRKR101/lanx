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
    if parts[0].parse::<u32>().is_err() {
        return false;
    }
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
