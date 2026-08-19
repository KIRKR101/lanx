//! TCP listener and dial helpers. `listen` picks an ephemeral port and
//! returns the listener plus its bound address.

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

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
