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
pub async fn pick_port() -> Result<(TcpListener, SocketAddr), TcpError> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

pub async fn listen() -> Result<(TcpListener, SocketAddr), TcpError> {
    pick_port().await
}

/// Wrap a listener so we can keep accepting for a grace period after a
/// client disconnects (resume scenario A from `plan.md` §8). One `accept`
/// call returns one stream; if the receiver disconnects before the grace
/// window elapses, the next `accept` can still return a fresh stream.
pub struct GracefulListener {
    inner: TcpListener,
    grace: Duration,
    closed: bool,
}

impl GracefulListener {
    pub fn new(inner: TcpListener, grace: Duration) -> Self {
        Self {
            inner,
            grace,
            closed: false,
        }
    }

    /// Close the listener. Subsequent `accept` calls return `Closed`
    /// immediately.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Accept one stream. Loops on transient errors until the grace
    /// window has elapsed since construction; then returns `Closed`.
    pub async fn accept(&mut self) -> Result<TcpStream, TcpError> {
        use std::time::Instant;
        let deadline = Instant::now() + self.grace;
        loop {
            if self.closed {
                return Err(TcpError::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(TcpError::Closed);
            }
            let remaining = deadline - now;
            match tokio::time::timeout(remaining, self.inner.accept()).await {
                Ok(Ok((s, _addr))) => {
                    s.set_nodelay(true).ok();
                    return Ok(s);
                }
                Ok(Err(_)) | Err(_) => {
                    sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}
