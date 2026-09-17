//! TURN-like relay server that pairs sender and receiver TCP connections
//! by a shared pairing ID. The relay does not interpret the lanx protocol;
//! it only forwards bytes between the two sockets once paired.
//!
//! # Security note
//!
//! The `RelayHello` (containing the pairing ID derived via
//! `code_to_pairing_id`) is sent in plaintext before the Noise handshake
//! wraps the connection. The relay needs the raw ID to pair sender and
//! receiver, so encrypting it is not feasible without relay participation
//! in the key derivation. Treat the pairing ID as *public*: secrecy comes
//! from the PSK mixed into the `Noise_NNpsk0` handshake
//! (`code_to_psk`), which the relay never sees.
//!
//! Guessing mitigations in this file: receivers that guess wrong wait up
//! to `RECEIVER_WAIT_SECS` and are rate-limited per IP
//! (`MAX_FAILED_ATTEMPTS_PER_WINDOW`); a second sender cannot evict the
//! first for the same ID (`RelayError::CodeInUse`, surfaced to the sender
//! via the one-byte `RELAY_ACK_*` reply); lookup timing is negligible
//! next to the wait plus network jitter.
//!
//! Internet-facing deployments should additionally use `--code-words 4`
//! (or higher) and an out-of-band `--psk` passphrase.

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
/// The relay pairs senders and receivers by `code_hash` (a public pairing
/// ID from `code_to_pairing_id`) and receives no human-readable pairing
/// code and no handshake PSK.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayHello {
    /// Whether this peer is a sender or receiver.
    pub role: RelayRole,
    /// Public pairing ID. Both sender and receiver compute the same ID
    /// from the human-readable code. Observable by the relay and the
    /// network path; guessing the underlying code still requires
    /// completing the PSK-bound Noise handshake.
    pub code_hash: [u8; 32],
    /// Optional operator-provided token checked before pairing.
    pub auth_token: Option<String>,
}

/// A pending connection waiting to be paired.
struct Pending {
    stream: TcpStream,
    addr: SocketAddr,
    /// Time when the sender connected, used to detect stale entries.
    connected_at: std::time::Instant,
}

/// Maximum age (in seconds) before a pending sender entry is considered stale.
/// 5 minutes: comfortably covers human out-of-band code relay (phone/chat)
/// while still bounding memory via `MAX_PENDING_SENDERS`. Must stay well
/// above `RECEIVER_WAIT_SECS` so a receiver arriving shortly after the
/// sender always finds it.
const PENDING_TTL_SECS: u64 = 300;

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
/// Maximum concurrent paired transfers the relay will handle. Prevents
/// unbounded memory growth from fork/bomb attacks.
const MAX_ACTIVE_SESSIONS: usize = 256;
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Maximum failed pairing attempts per IP within `RATE_LIMIT_WINDOW`
/// before the relay starts rejecting with [`RelayError::RateLimited`].
/// Legitimate use needs ~1 attempt; guessing needs thousands, so a tight
/// budget mostly hurts attackers. The 11th failure inside the window is
/// rejected; counts only *failed* looks (no sender found), not
/// successful pairings.
const MAX_FAILED_ATTEMPTS_PER_WINDOW: u32 = 10;
/// Sliding window for the per-IP failure budget.
const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Cap on tracked IPs. `record_failure` prunes expired/empty entries once
/// past this so a long-running public relay can't accumulate one entry
/// per scanner IP forever.
const MAX_TRACKED_IPS: usize = 1024;

/// Sender registration reply, one byte written by the server right after
/// the sender's hello. Lets a rejected sender tell "code already in use,
/// re-run send" apart from a generic connection failure.
pub const RELAY_ACK_OK: u8 = 0;
/// Pairing ID already registered by another live sender.
pub const RELAY_ACK_IN_USE: u8 = 1;
/// Server at capacity (`MAX_PENDING_SENDERS`).
pub const RELAY_ACK_FULL: u8 = 2;

/// Per-IP failure counters for relay guessing rate limiting.
#[derive(Debug, Default)]
struct AttemptTracker {
    /// IP -> timestamps of recent *failed* pairing looks.
    failures: HashMap<std::net::IpAddr, Vec<std::time::Instant>>,
}

impl AttemptTracker {
    /// Record a failure; returns true if the IP is now over budget
    /// (more than `MAX_FAILED_ATTEMPTS_PER_WINDOW` fresh failures).
    fn record_failure(&mut self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        if self.failures.len() > MAX_TRACKED_IPS {
            // Prune dead keys so scanner churn can't grow the map forever.
            self.failures.retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
                !v.is_empty()
            });
        }
        let entries = self.failures.entry(ip).or_default();
        entries.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
        entries.push(now);
        entries.len() as u32 > MAX_FAILED_ATTEMPTS_PER_WINDOW
    }

    fn is_limited(&self, ip: &std::net::IpAddr) -> bool {
        if let Some(entries) = self.failures.get(ip) {
            let now = std::time::Instant::now();
            let fresh = entries
                .iter()
                .filter(|t| now.duration_since(**t) < RATE_LIMIT_WINDOW)
                .count() as u32;
            fresh > MAX_FAILED_ATTEMPTS_PER_WINDOW
        } else {
            false
        }
    }
}

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
    #[error("code already registered by another sender; retry when it expires")]
    CodeInUse,
    #[error("too many failed pairing attempts; slow down and retry")]
    RateLimited,
    #[error("server at capacity; try again later")]
    Capacity,
    #[error("relay authentication failed")]
    Authentication,
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub max_sessions: usize,
    pub idle_timeout: std::time::Duration,
    pub auth_token: Option<String>,
    pub metrics: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_sessions: MAX_ACTIVE_SESSIONS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            auth_token: None,
            metrics: false,
        }
    }
}

/// A TURN-like relay server that pairs sender and receiver TCP connections
/// by a shared pairing ID. The relay does not interpret the lanx protocol;
/// it only forwards bytes between the two sockets once paired.
///
/// # Session limits
///
/// At most [`MAX_ACTIVE_SESSIONS`] concurrent paired transfers are
/// allowed. The slot is reserved at pairing time (not at accept), so
/// unauthenticated receivers waiting for a sender hold nothing.
/// Receivers that repeatedly guess wrong IDs are rate-limited
/// per IP (`MAX_FAILED_ATTEMPTS_PER_WINDOW` per `RATE_LIMIT_WINDOW`).
pub struct RelayServer {
    sender_listener: TcpListener,
    receiver_listener: TcpListener,
    /// Pending sender connections keyed by pairing ID.
    pending_senders: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    /// Count of active paired sessions (for connection limiting).
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
    /// Per-IP failed-guess counters for rate limiting receivers.
    attempts: Arc<Mutex<AttemptTracker>>,
    config: RelayConfig,
}

impl RelayServer {
    /// Create a new relay server bound to the given addresses.
    ///
    /// # Errors
    ///
    /// Returns `RelayError::Io` if either listener cannot be bound.
    pub async fn new(sender_bind: String, receiver_bind: String) -> Result<Self, RelayError> {
        Self::new_with_config(sender_bind, receiver_bind, RelayConfig::default()).await
    }

    pub async fn new_with_config(
        sender_bind: String,
        receiver_bind: String,
        config: RelayConfig,
    ) -> Result<Self, RelayError> {
        let sender_listener = TcpListener::bind(&sender_bind).await?;
        let receiver_listener = TcpListener::bind(&receiver_bind).await?;

        Ok(Self {
            sender_listener,
            receiver_listener,
            pending_senders: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            attempts: Arc::new(Mutex::new(AttemptTracker::default())),
            config,
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
        if self.config.metrics {
            tracing::info!("relay metrics enabled; active_sessions is reported every 60s");
        }

        let mut sender_set = tokio::task::JoinSet::new();
        let mut receiver_set = tokio::task::JoinSet::new();
        let mut metrics_tick = tokio::time::interval(std::time::Duration::from_secs(60));

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
                            let auth_token = self.config.auth_token.clone();
                            sender_set.spawn(async move {
                                if let Err(e) = handle_sender(stream, addr, pending, auth_token).await {
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
                            // No slot reserved here: receivers only take a
                            // session slot once actually paired (see
                            // `handle_receiver`), so unauthenticated
                            // guessers idling through the wait cannot
                            // exhaust `MAX_ACTIVE_SESSIONS`.
                            let pending = self.pending_senders.clone();
                            let sessions = self.active_sessions.clone();
                            let attempts = self.attempts.clone();
                            let config = self.config.clone();
                            receiver_set.spawn(async move {
                                if let Err(e) = handle_receiver(stream, addr, pending, sessions, attempts, config).await {
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
                _ = metrics_tick.tick(), if self.config.metrics => {
                    let pending = self.pending_senders.lock().await.len();
                    let active = self.active_sessions.load(std::sync::atomic::Ordering::Acquire);
                    tracing::info!(pending_senders = pending, active_sessions = active, "relay metrics");
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

/// Read the one-byte sender registration reply (see `RELAY_ACK_*`).
/// The server sends this right after a sender hello; receivers get no
/// reply (they block until paired or the wait expires).
///
/// # Errors
///
/// Returns `RelayError::Io` if the byte cannot be read.
pub async fn read_relay_ack(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<u8, RelayError> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn handle_sender(
    mut stream: TcpStream,
    addr: SocketAddr,
    pending: Arc<Mutex<HashMap<[u8; 32], Pending>>>,
    auth_token: Option<String>,
) -> Result<(), RelayError> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed on sender");
    }

    let hello = read_relay_hello(&mut stream).await?;
    if auth_token.as_deref() != hello.auth_token.as_deref() {
        return Err(RelayError::Authentication);
    }
    if hello.role != RelayRole::Sender {
        return Err(RelayError::UnexpectedRole(hello.role));
    }

    tracing::info!(addr = %addr, "sender connected, waiting for receiver");

    // Decide under the lock, then do network I/O unlocked: holding the
    // map mutex across `write_all` would let one stalled sender block
    // all other registrations and pairings. Re-check under a second
    // lock before inserting (a rival may have won the race; losers get
    // `CodeInUse`, never an eviction).
    enum Decision {
        Accept,
        InUse,
        Full(usize),
    }
    let decision = {
        let mut map = pending.lock().await;
        // Clean up stale entries before checking for duplicates.
        map.retain(|_, pending| pending.connected_at.elapsed().as_secs() < PENDING_TTL_SECS);
        if map.contains_key(&hello.code_hash) {
            Decision::InUse
        } else if map.len() >= MAX_PENDING_SENDERS {
            Decision::Full(map.len())
        } else {
            Decision::Accept
        }
    };
    // Helper: tell the sender *why* registration failed before dropping
    // the stream, so "code already registered" doesn't look like a
    // generic connection failure.
    async fn ack(stream: &mut TcpStream, byte: u8) -> std::io::Result<()> {
        stream.write_all(&[byte]).await
    }
    match decision {
        Decision::Full(count) => {
            tracing::warn!(
                addr = %addr,
                pending_count = count,
                "rejecting sender: too many pending registrations"
            );
            if let Err(e) = ack(&mut stream, RELAY_ACK_FULL).await {
                tracing::debug!(?e, "failed to send relay ack");
            }
            return Err(RelayError::Capacity);
        }
        Decision::InUse => {
            // Never evict a live sender: a second registration for the
            // same ID is either a sender restart (old one is stale and
            // was already reaped above) or a hijack attempt. Reject it
            // so an attacker cannot steal a receiver waiting on someone
            // else's code.
            tracing::warn!(
                addr = %addr,
                "rejecting sender: pairing ID already registered"
            );
            if let Err(e) = ack(&mut stream, RELAY_ACK_IN_USE).await {
                tracing::debug!(?e, "failed to send relay ack");
            }
            return Err(RelayError::CodeInUse);
        }
        Decision::Accept => {}
    }
    if let Err(e) = ack(&mut stream, RELAY_ACK_OK).await {
        tracing::debug!(?e, "failed to send relay ack");
        return Err(RelayError::Io(e));
    }
    {
        let mut map = pending.lock().await;
        map.retain(|_, pending| pending.connected_at.elapsed().as_secs() < PENDING_TTL_SECS);
        if map.contains_key(&hello.code_hash) {
            // Lost a registration race after the ack: report in-use
            // rather than evicting the winner. (The ack already said OK;
            // the sender will see the Noise handshake stall and retry
            // with a fresh code — no silent hijack either way.)
            tracing::warn!(
                addr = %addr,
                "lost sender registration race; reporting in-use"
            );
            return Err(RelayError::CodeInUse);
        }
        if map.len() >= MAX_PENDING_SENDERS {
            tracing::warn!(
                addr = %addr,
                "lost sender registration race; server filled meanwhile"
            );
            return Err(RelayError::Capacity);
        }
        map.insert(
            hello.code_hash,
            Pending {
                stream,
                addr,
                connected_at: std::time::Instant::now(),
            },
        );
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
    attempts: Arc<Mutex<AttemptTracker>>,
    config: RelayConfig,
) -> Result<(), RelayError> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(?e, "TCP_NODELAY failed on receiver");
    }

    let hello = read_relay_hello(&mut stream).await?;
    if config.auth_token.as_deref() != hello.auth_token.as_deref() {
        return Err(RelayError::Authentication);
    }
    if hello.role != RelayRole::Receiver {
        return Err(RelayError::UnexpectedRole(hello.role));
    }

    // Pre-check the per-IP guess budget before the (slow) wait loop so a
    // scanner burning through IDs gets cut off fast.
    {
        let tracker = attempts.lock().await;
        if tracker.is_limited(&addr.ip()) {
            tracing::warn!(addr = %addr, "rate-limiting receiver: too many failed attempts");
            return Err(RelayError::RateLimited);
        }
    }

    // Poll for a matching sender, cleaning up stale entries. The
    // receiver waits up to RECEIVER_WAIT_SECS so a sender that connects
    // slightly after the receiver still pairs successfully. A wrong
    // guess costs the full wait, so each guess is expensive and
    // rate-limited (see AttemptTracker); hash-lookup timing is
    // negligible next to the 30 s wait plus network jitter.
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
                // Reserve the session slot only now that pairing
                // succeeded: waiting receivers hold nothing, so guessers
                // cannot exhaust sessions by idling. If full, return the
                // sender to pending (fresh timestamp) so a later retry
                // can still find it.
                let prev = active_sessions.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                if prev >= config.max_sessions {
                    active_sessions.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    tracing::warn!(
                        receiver = %addr,
                        active = prev,
                        "rejecting paired receiver: max sessions reached"
                    );
                    pending.lock().await.insert(
                        hello.code_hash,
                        Pending {
                            stream: sender.stream,
                            addr: sender.addr,
                            connected_at: std::time::Instant::now(),
                        },
                    );
                    return Err(RelayError::Capacity);
                }
                let guard = SessionGuard {
                    sessions: active_sessions,
                    active: true,
                };
                let moved_guard = guard;
                tokio::spawn(async move {
                    let _g = moved_guard;
                    match tokio::time::timeout(
                        config.idle_timeout,
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
                                config.idle_timeout.as_secs(),
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
                // Failed guess: count it toward the per-IP budget.
                let limited = attempts.lock().await.record_failure(addr.ip());
                if limited {
                    tracing::warn!(addr = %addr, "receiver IP now rate-limited after repeated failures");
                    return Err(RelayError::RateLimited);
                }
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

    // Drain the remaining direction after one side closes. Its shutdown is
    // best-effort; BLAKE3 verifies the transferred data.
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
            auth_token: None,
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

    #[tokio::test]
    async fn relay_ack_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&[RELAY_ACK_IN_USE]).await.unwrap();
        assert_eq!(read_relay_ack(&mut b).await.unwrap(), RELAY_ACK_IN_USE);
        assert_ne!(RELAY_ACK_OK, RELAY_ACK_IN_USE);
        assert_ne!(RELAY_ACK_OK, RELAY_ACK_FULL);
        assert_ne!(RELAY_ACK_IN_USE, RELAY_ACK_FULL);
    }

    #[test]
    fn error_variants_render_distinctly() {
        // Guards against reusing one variant for another (e.g. capacity
        // reported as a frame error): each must identify its own cause.
        let capacity = RelayError::Capacity.to_string();
        let in_use = RelayError::CodeInUse.to_string();
        let limited = RelayError::RateLimited.to_string();
        let no_sender = RelayError::NoSender.to_string();
        assert!(capacity.contains("capacity"), "got: {capacity}");
        assert_ne!(capacity, RelayError::FrameTooLarge(0).to_string());
        assert_ne!(in_use, limited);
        assert_ne!(in_use, no_sender);
    }

    #[test]
    fn attempt_tracker_budgets_failures() {
        let mut t = AttemptTracker::default();
        let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!t.is_limited(&ip));
        // Exactly the budget is still fine; the next one trips the limit.
        for _ in 0..MAX_FAILED_ATTEMPTS_PER_WINDOW {
            assert!(!t.record_failure(ip));
        }
        assert!(!t.is_limited(&ip));
        assert!(t.record_failure(ip));
        assert!(t.is_limited(&ip));
        // Other IPs unaffected.
        let other: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        assert!(!other.eq(&ip));
        assert!(!t.is_limited(&other));
    }

    #[test]
    fn attempt_tracker_prunes_dead_keys() {
        let mut t = AttemptTracker::default();
        // Simulate a scanner wave: many IPs with long-expired failures.
        let stale =
            std::time::Instant::now() - RATE_LIMIT_WINDOW - std::time::Duration::from_secs(1);
        for i in 0..(MAX_TRACKED_IPS + 10) {
            let ip: std::net::IpAddr = format!("10.{}.{}.1", (i >> 8) & 0xff, i & 0xff)
                .parse()
                .unwrap();
            t.failures.insert(ip, vec![stale]);
        }
        assert!(t.failures.len() > MAX_TRACKED_IPS);
        // Next failure triggers the prune; all stale keys are reaped.
        let fresh: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        t.record_failure(fresh);
        assert_eq!(t.failures.len(), 1);
    }
}
