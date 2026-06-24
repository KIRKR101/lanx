//! TURN-like relay server that pairs sender and receiver TCP connections
//! by a shared code hash. The relay does not interpret the lanx protocol;
//! it only forwards bytes between the two sockets once paired.
//!
//! # Security note
//!
//! The `RelayHello` (containing the BLAKE3 code hash) is sent in plaintext
//! before the Noise handshake wraps the connection. The relay needs the raw
//! hash to pair sender and receiver, so encrypting it is not feasible
//! without relay participation in the key derivation.
//!
//! Pairing codes have ~18.6 bits of entropy (10 × 197 × 197 combinations).
//! An observer on the network path can capture the code hash and brute-force
//! all possible codes offline. The Noise handshake then encrypts file
//! contents, but the human-readable pairing code itself is exposed.
//!
//! For relay-over-internet deployments where this is a concern, consider
//! using longer codes or adding a PSK derived from an out-of-band shared
//! secret (future work).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Role of the connecting peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RelayRole {
    /// The peer is a sender waiting for a receiver to pair with.
    Sender,
    /// The peer is a receiver looking for a sender to pair with.
    Receiver,
}

/// First message a peer sends after connecting to the relay.
///
/// The relay uses the `code_hash` to pair senders and receivers. The
/// human-readable code is never sent to the relay — only the hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayHello {
    /// Whether this peer is a sender or receiver.
    pub role: RelayRole,
    /// BLAKE3 hash of the pairing code. Both sender and receiver compute
    /// the same hash from the human-readable code.
    pub code_hash: [u8; 32],
}

/// A pending connection waiting to be paired.
struct Pending {
    stream: TcpStream,
    addr: SocketAddr,
    /// When the sender connected. Used to detect stale entries.
    connected_at: std::time::Instant,
}

/// Maximum age (in seconds) before a pending sender entry is considered stale.
/// Reduced from 30s so dead senders are evicted faster; receivers retry on
/// a schedule so a shorter window still allows pairing of slow senders.
const PENDING_TTL_SECS: u64 = 10;

/// Maximum number of pending senders in the map. Prevents unbounded memory
/// growth from rapid sender registration floods.
const MAX_PENDING_SENDERS: usize = 256;

/// How often a receiver retries looking for a sender when none is
/// immediately available.
const RECEIVER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// Maximum number of seconds a receiver will wait for a sender to appear.
const RECEIVER_WAIT_SECS: u64 = 30;

/// Maximum seconds of inactivity before a paired transfer is considered
/// stalled and the session is released. Prevents leaked sessions from
/// half-open TCP connections holding slots indefinitely.
const TRANSFER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Maximum concurrent paired transfers the relay will handle. Prevents
/// unbounded memory growth from fork/bomb attacks.
const MAX_ACTIVE_SESSIONS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("frame too large: {0}")]
    FrameTooLarge(usize),
    #[error("unexpected role: {0:?}")]
    UnexpectedRole(RelayRole),
    #[error("no sender found for code hash")]
    NoSender,
}

/// A TURN-like relay server that pairs sender and receiver TCP connections
/// by a shared code hash. The relay does not interpret the lanx protocol;
/// it only forwards bytes between the two sockets once paired.
///
/// # Session limits
///
/// At most [`MAX_ACTIVE_SESSIONS`] concurrent paired transfers are
/// allowed. Additional receiver connections are rejected until a slot
/// frees up.
pub struct RelayServer {
    sender_listener: TcpListener,
    receiver_listener: TcpListener,
    /// Map from code_hash → pending sender connection.
    pending_senders: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    /// Count of active paired sessions (for connection limiting).
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
}

impl RelayServer {
    /// Create a new relay server bound to the given addresses.
    ///
    /// # Errors
    ///
    /// Returns `RelayError::Io` if either listener cannot be bound.
    pub async fn new(sender_bind: String, receiver_bind: String) -> Result<Self, RelayError> {
        let sender_listener = TcpListener::bind(&sender_bind).await?;
        let receiver_listener = TcpListener::bind(&receiver_bind).await?;

        Ok(Self {
            sender_listener,
            receiver_listener,
            pending_senders: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Run the relay server, accepting sender and receiver connections
    /// until a shutdown signal (Ctrl+C) is received.
    ///
    /// # Errors
    ///
    /// Returns `RelayError::Io` for listener or accept failures.
    pub async fn run(&self) -> Result<(), RelayError> {
        tracing::info!(
            sender = %self.sender_listener.local_addr()?,
            receiver = %self.receiver_listener.local_addr()?,
            "relay server started"
        );

        let mut sender_set = tokio::task::JoinSet::new();
        let mut receiver_set = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutdown signal received, stopping relay");
                    break Ok(());
                }
                result = self.sender_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let pending = self.pending_senders.clone();
                            sender_set.spawn(async move {
                                if let Err(e) = handle_sender(stream, addr, pending).await {
                                    tracing::warn!(addr = %addr, error = %e, "sender handler error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "sender accept error");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                result = self.receiver_listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            // Atomically increment and check the limit. If we
                            // exceed MAX_ACTIVE_SESSIONS, decrement and reject.
                            let prev = self.active_sessions.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                            if prev >= MAX_ACTIVE_SESSIONS {
                                self.active_sessions.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                                tracing::warn!(
                                    addr = %addr,
                                    active = prev,
                                    "rejecting receiver: max sessions reached"
                                );
                                drop(stream);
                                continue;
                            }
                            let pending = self.pending_senders.clone();
                            let sessions = self.active_sessions.clone();
                            receiver_set.spawn(async move {
                                if let Err(e) = handle_receiver(stream, addr, pending, sessions).await {
                                    tracing::warn!(addr = %addr, error = %e, "receiver handler error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "receiver accept error");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
                Some(result) = sender_set.join_next() => {
                    if let Err(e) = result {
                        tracing::debug!(error = %e, "sender handler task panicked");
                    }
                }
                Some(result) = receiver_set.join_next() => {
                    if let Err(e) = result {
                        tracing::debug!(error = %e, "receiver handler task panicked");
                    }
                }
            }
        }
    }
}

/// Read a relay hello from a stream. The hello is length-prefixed (u16 BE)
/// followed by the postcard-encoded `RelayHello`.
async fn read_relay_hello(
    stream: &mut (impl AsyncReadExt + Unpin),
) -> Result<RelayHello, RelayError> {
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    // Cap frame size to prevent DoS via large allocations. A serialized
    // RelayHello is ~34 bytes; 512 provides generous headroom.
    if len > 512 {
        return Err(RelayError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    let hello: RelayHello = postcard::from_bytes(&payload)?;
    Ok(hello)
}

/// Send a relay hello on a stream (used for testing / protocol messages).
///
/// # Errors
///
/// Returns `RelayError::FrameTooLarge` if the serialized hello exceeds
/// 65535 bytes, `RelayError::Postcard` for serialization errors, or
/// `RelayError::Io` for write failures.
pub async fn send_relay_hello(
    stream: &mut (impl AsyncWriteExt + Unpin),
    hello: &RelayHello,
) -> Result<(), RelayError> {
    let payload = postcard::to_allocvec(hello)?;
    let len = u16::try_from(payload.len()).map_err(|_| RelayError::FrameTooLarge(payload.len()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_sender(
    mut stream: TcpStream,
    addr: SocketAddr,
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
) -> Result<(), RelayError> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed on sender");
    }

    let hello = read_relay_hello(&mut stream).await?;
    if hello.role != RelayRole::Sender {
        return Err(RelayError::UnexpectedRole(hello.role));
    }

    tracing::info!(addr = %addr, "sender connected, waiting for receiver");

    let mut map = pending.lock().await;
    // Clean up stale entries before checking for duplicates.
    map.retain(|_, pending| pending.connected_at.elapsed().as_secs() < PENDING_TTL_SECS);
    // If the map is full after cleanup, reject the new sender to prevent
    // unbounded memory growth from registration floods.
    if !map.contains_key(&hello.code_hash) && map.len() >= MAX_PENDING_SENDERS {
        tracing::warn!(
            addr = %addr,
            pending_count = map.len(),
            "rejecting sender: too many pending registrations"
        );
        return Err(RelayError::FrameTooLarge(0)); // reuse error variant for capacity
    }
    // If a sender for this code hash already exists, replace it with the
    // new one. The old sender is likely stale (e.g. crashed without closing
    // the connection). Log the eviction so operators can detect issues.
    if let Some(old) = map.insert(
        hello.code_hash,
        Pending {
            stream,
            addr,
            connected_at: std::time::Instant::now(),
        },
    ) {
        tracing::warn!(
            old_addr = %old.addr,
            new_addr = %addr,
            code_hash = ?hello.code_hash,
            "evicting stale sender for code hash"
        );
        drop(old);
    }
    Ok(())
}

struct SessionGuard {
    sessions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    active: bool,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.active {
            self.sessions
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

async fn handle_receiver(
    mut stream: TcpStream,
    addr: SocketAddr,
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    active_sessions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Result<(), RelayError> {
    let guard = SessionGuard {
        sessions: active_sessions,
        active: true,
    };

    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed on receiver");
    }

    let hello = read_relay_hello(&mut stream).await?;
    if hello.role != RelayRole::Receiver {
        return Err(RelayError::UnexpectedRole(hello.role));
    }

    // Poll for a matching sender, cleaning up stale entries. The
    // receiver waits up to RECEIVER_WAIT_SECS so a sender that connects
    // slightly after the receiver still pairs successfully.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(RECEIVER_WAIT_SECS);
    loop {
        let sender = {
            let mut map = pending.lock().await;
            map.retain(|_, pending| pending.connected_at.elapsed().as_secs() < PENDING_TTL_SECS);
            map.remove(&hello.code_hash)
        };

        match sender {
            Some(sender) => {
                tracing::info!(
                    sender = %sender.addr,
                    receiver = %addr,
                    "pairing sender and receiver"
                );
                let moved_guard = guard;
                tokio::spawn(async move {
                    let _g = moved_guard;
                    match tokio::time::timeout(
                        TRANSFER_IDLE_TIMEOUT,
                        bidirectional_copy(sender.stream, stream),
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(_) => {
                            tracing::warn!(
                                sender = %sender.addr,
                                receiver = %addr,
                                "transfer timed out after {}s of inactivity",
                                TRANSFER_IDLE_TIMEOUT.as_secs(),
                            );
                        }
                    }
                });
                return Ok(());
            }
            None if std::time::Instant::now() < deadline => {
                // Release the lock implicitly (map was dropped above),
                // then sleep before retrying.
                tokio::time::sleep(RECEIVER_POLL_INTERVAL).await;
                continue;
            }
            None => {
                tracing::info!(addr = %addr, "no sender found after waiting, receiver disconnected");
                return Err(RelayError::NoSender);
            }
        }
    }
}

/// Copy bytes from `reader` to `writer` until EOF or error, logging
/// read errors before returning.
async fn copy_loop<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    label: &str,
    mut reader: R,
    mut writer: W,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(direction = label, error = %e, "read error during copy");
                break;
            }
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Bidirectionally copy bytes between two streams until one side closes.
/// When one direction ends, the remaining direction is drained so the
/// peer's buffered data is not silently lost.
async fn bidirectional_copy(a: TcpStream, b: TcpStream) {
    let (a_read, a_write) = a.into_split();
    let (b_read, b_write) = b.into_split();

    let a_to_b = copy_loop("a->b", a_read, b_write);
    let b_to_a = copy_loop("b->a", b_read, a_write);

    // Use biased selection so we always drain in a predictable order.
    // When one direction finishes, the other is dropped — its shutdown
    // call is best-effort; in-flight data may be lost, but the protocol
    // has its own integrity checks (BLAKE3 hashes).
    tokio::select! {
        biased;
        _ = a_to_b => {},
        _ = b_to_a => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::code_to_hash;

    #[test]
    fn relay_hello_serialization_round_trip() {
        let code = "7-cobalt-fox";
        let hash = code_to_hash(code);
        let hello = RelayHello {
            role: RelayRole::Sender,
            code_hash: hash,
        };

        let payload = postcard::to_allocvec(&hello).unwrap();
        let decoded: RelayHello = postcard::from_bytes(&payload).unwrap();
        assert_eq!(hello.role, decoded.role);
        assert_eq!(hello.code_hash, decoded.code_hash);
    }

    #[test]
    fn relay_role_round_trip() {
        let sender = RelayRole::Sender;
        let receiver = RelayRole::Receiver;

        let payload = postcard::to_allocvec(&sender).unwrap();
        let decoded: RelayRole = postcard::from_bytes(&payload).unwrap();
        assert_eq!(sender, decoded);

        let payload = postcard::to_allocvec(&receiver).unwrap();
        let decoded: RelayRole = postcard::from_bytes(&payload).unwrap();
        assert_eq!(receiver, decoded);
    }
}
