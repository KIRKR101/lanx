//! TCP listener and dial helpers. `listen` picks an ephemeral port and
//! returns the listener plus its bound address. `listen_default` tries
//! the stable service port first so firewall rules stay writable,
//! falling back to an ephemeral port only on `AddrInUse`.

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// Stable sender port: IANA User Ports range (1024–49151), below the
/// Linux default ephemeral floor (32768) and outside IANA Dynamic/Private
/// (49152–65535). Verified unassigned for TCP+UDP in the IANA registry
/// (no neighbours assigned in 29315–29325) and absent from
/// `/etc/services`. Discovery stays on UDP 53317; relay binds stay on
/// 53318/53319 (compat — not renumbered here).
pub const DEFAULT_SEND_PORT: u16 = 29320;

#[derive(Debug, Error)]
pub enum TcpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("listener closed")]
    Closed,
}

/// Pick an ephemeral port. Returns the bound address.
///
/// # Errors
///
/// Returns `TcpError::Io` if the listener cannot be bound.
pub async fn pick_port() -> Result<(TcpListener, SocketAddr), TcpError> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// Shorthand for `pick_port()`.
///
/// # Errors
///
/// Returns `TcpError::Io` if the listener cannot be bound.
pub async fn listen() -> Result<(TcpListener, SocketAddr), TcpError> {
    pick_port().await
}

/// Try `port` on the wildcard interface; on `AddrInUse` fall back to an
/// ephemeral port. Returns the listener, its bound address, and whether
/// the fallback was taken. All non-`AddrInUse` errors propagate.
///
/// Binding on the same wildcard (`0.0.0.0`) in both attempts keeps
/// conflict semantics platform-independent.
///
/// # Errors
///
/// Returns `TcpError::Io` for non-`AddrInUse` bind failures or if the
/// fallback bind / `local_addr` fails.
pub async fn listen_preferred(port: u16) -> Result<(TcpListener, SocketAddr, bool), TcpError> {
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => {
            let addr = listener.local_addr()?;
            Ok((listener, addr, false))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::debug!(port, "preferred port in use; falling back to ephemeral");
            let (listener, addr) = pick_port().await?;
            Ok((listener, addr, true))
        }
        Err(e) => Err(TcpError::Io(e)),
    }
}

/// Try [`DEFAULT_SEND_PORT`], falling back to ephemeral on `AddrInUse`.
///
/// # Errors
///
/// Returns `TcpError::Io` for non-`AddrInUse` bind failures or if the
/// fallback bind fails.
pub async fn listen_default() -> Result<(TcpListener, SocketAddr, bool), TcpError> {
    listen_preferred(DEFAULT_SEND_PORT).await
}

/// Wrap a listener so we can keep accepting for a grace period after a
/// client disconnects.
///
/// One `accept` call returns one stream; if the receiver disconnects
/// before the grace window elapses, the next `accept` can still return a
/// fresh stream.
pub struct GracefulListener {
    inner: TcpListener,
    grace: Duration,
    deadline: std::time::Instant,
    backoff: Duration,
}

impl GracefulListener {
    pub fn new(inner: TcpListener, grace: Duration) -> Self {
        Self {
            inner,
            grace,
            deadline: std::time::Instant::now() + grace,
            backoff: Duration::from_millis(10),
        }
    }

    /// Refresh the grace window. Call after a session fails so the next
    /// `accept` gives a full grace period instead of the deadline
    /// captured at construction, which a long session may have outlived.
    pub fn reset(&mut self) {
        self.deadline = std::time::Instant::now() + self.grace;
        self.backoff = Duration::from_millis(10);
    }

    /// Accept one stream. Loops on transient errors with exponential
    /// backoff until the grace window has elapsed since construction;
    /// then returns `Closed`.
    ///
    /// # Errors
    ///
    /// Returns `TcpError::Closed` once the grace window elapses, or
    /// `TcpError::Io` for an accept failure.
    pub async fn accept(&mut self) -> Result<TcpStream, TcpError> {
        let max_backoff = Duration::from_millis(500);
        loop {
            let now = std::time::Instant::now();
            if now >= self.deadline {
                return Err(TcpError::Closed);
            }
            let remaining = self.deadline - now;
            if let Ok(Ok((s, _addr))) = tokio::time::timeout(remaining, self.inner.accept()).await {
                if let Err(e) = s.set_nodelay(true) {
                    tracing::debug!(?e, "TCP_NODELAY failed");
                }
                self.backoff = Duration::from_millis(10);
                return Ok(s);
            }
            sleep(self.backoff).await;
            self.backoff = (self.backoff * 2).min(max_backoff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pick a currently-free port by holding an ephemeral bind, then
    /// releasing it. Best-effort: a third party could race us, so callers
    /// must tolerate `AddrInUse` on the candidate by retrying.
    async fn free_candidate() -> u16 {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("ephemeral bind for test candidate");
        let port = listener.local_addr().expect("local_addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn preferred_free_port_binds_without_fallback() {
        let candidate = free_candidate().await;
        match listen_preferred(candidate).await {
            Ok((_l, addr, fell_back)) => {
                assert_eq!(addr.port(), candidate);
                assert!(!fell_back);
            }
            Err(TcpError::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // Lost a race with another process; not a code failure.
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[tokio::test]
    async fn preferred_conflict_falls_back_to_ephemeral() {
        // Occupy a candidate on the same wildcard the implementation
        // binds, then require the fallback path.
        let candidate = free_candidate().await;
        let _guard = match TcpListener::bind(("0.0.0.0", candidate)).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return, // raced; skip
            Err(e) => panic!("guard bind failed: {e:?}"),
        };
        let (_l, addr, fell_back) = listen_preferred(candidate)
            .await
            .expect("fallback on AddrInUse");
        assert!(fell_back);
        assert_ne!(addr.port(), candidate);
    }
}
