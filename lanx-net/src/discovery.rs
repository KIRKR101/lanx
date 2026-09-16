//! UDP-broadcast discovery + pairing codes.
//!
//! Wire format: on UDP port 53317, send a small postcard-encoded packet
//! containing `{port: u16, code_hash: [u8; 32]}`.
//! Receivers filter by `code_hash`. The pairing code embeds the last
//! digit of the port as a lightweight UX hint, but this is *not*
//! security — the full port is broadcast in the clear and the code is
//! easily brute-forced. Encryption is a v2 concern (plan §1).

use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub const DISCOVERY_PORT: u16 = 53317;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Announce {
    port: u16,
    code_hash: [u8; 32],
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "timed out waiting for sender (no matching broadcast on UDP port {DISCOVERY_PORT}); \
         make sure both machines are on the same network, check firewalls for UDP {DISCOVERY_PORT}, \
         or connect directly with `lanx recv <ip:port>` shown on the sender"
    )]
    Timeout,
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Short wordlist (kept inline to avoid an extra build step)
/// 197 unique words, ~7.6 bits of entropy per word.
/// (10 digits × 197 × 197 = 388,090 possible codes, ~18.6 bits total.)
const WORDS: &[&str] = &[
    "amber", "apple", "azure", "basil", "birch", "cobalt", "comet", "coral", "crimson", "delta",
    "echo", "ember", "fable", "fern", "fjord", "flint", "frost", "garnet", "ginger", "glade",
    "harbor", "hawk", "hazel", "ivory", "jade", "kestrel", "lake", "lark", "lemon", "lilac",
    "lotus", "lunar", "maple", "marble", "merlin", "mint", "mossy", "neon", "noble", "ocean",
    "olive", "onyx", "opal", "otter", "pebble", "pine", "plum", "polar", "quartz", "quill",
    "raven", "reed", "river", "roan", "rose", "rusty", "sable", "sage", "satin", "scarlet",
    "shore", "silk", "slate", "snow", "spruce", "storm", "sumac", "swann", "tiger", "topaz",
    "tundra", "umber", "valley", "velvet", "violet", "willow", "wisp", "yarrow", "yew", "zinc",
    "alpha", "beta", "gamma", "epsilon", "zeta", "eta", "theta", "acorn", "arrow", "badge",
    "beach", "blaze", "bloom", "breeze", "brook", "cedar", "cliff", "clover", "crane", "daisy",
    "dawn", "drift", "eagle", "flame", "flora", "forge", "glen", "grove", "heron", "iris",
    "jasper", "kelp", "knoll", "leech", "linen", "mango", "marsh", "nexus", "nymph", "oasis",
    "orchid", "osprey", "owl", "pearl", "plume", "proxy", "quail", "rain", "ridge", "ripple",
    "scarf", "shale", "spear", "sprig", "stone", "swift", "thorn", "tide", "torch", "trail",
    "trout", "vine", "wade", "wren", "yacht", "zephyr", "anchor", "basin", "berry", "blade",
    "bluff", "cabin", "canyon", "creek", "crest", "crown", "dell", "dune", "fawn", "gale", "hare",
    "haven", "helm", "herb", "hickory", "isle", "kite", "lance", "lily", "lynx", "mage", "moss",
    "nard", "nest", "nimbus", "nova", "oak", "orca", "peak", "pond", "puma", "rift", "rill",
    "robin", "seal", "sloe", "span", "spar", "spur", "star", "stem", "swan", "tarn", "tile",
    "vale", "vole", "wasp",
];

/// Build a code of the form `digit-word-word`. The `digit` is derived
/// from the port; the two words come from a small wordlist.
#[must_use]
pub fn generate_code(port: u16) -> String {
    let mut rng = rand::thread_rng();
    let digit = (port % 10).to_string();
    let w1 = WORDS
        .choose(&mut rng)
        .expect("WORDS is non-empty (compile-time const)");
    let w2 = WORDS
        .choose(&mut rng)
        .expect("WORDS is non-empty (compile-time const)");
    format!("{digit}-{w1}-{w2}")
}

/// Normalize a pairing code before hashing: trim surrounding
/// whitespace (copy-paste artifacts) and lowercase for
/// case-insensitive pairing.
fn normalize_code(code: &str) -> String {
    code.trim().to_lowercase()
}

/// The hash receivers compare against announcements.
///
/// BLAKE3 hashes the normalized code string to produce a 32-byte
/// digest. The sender announces the hash; the receiver hashes the
/// entered code locally and compares. Normalization (trim +
/// lowercase) ensures case-insensitive pairing (e.g. "7-Cobalt-Fox"
/// and "  7-cobalt-fox\n" produce the same hash).
#[must_use]
pub fn code_to_hash(code: &str) -> [u8; 32] {
    let normalized = normalize_code(code);
    let h = blake3::hash(normalized.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Handle for an active broadcast. Dropping or calling `stop()` ends the
/// broadcast task.
pub struct DiscoveryHandle {
    stop: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl DiscoveryHandle {
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        if let Err(e) = self.join.await {
            tracing::debug!(?e, "discovery task panicked");
        }
    }
}

/// Start broadcasting on all non-loopback IPv4 interfaces. Returns a
/// handle whose `stop` future completes when you drop it (or call
/// `stop()`).
///
/// # Errors
///
/// Returns an I/O error if the UDP socket cannot be bound.
pub async fn start_broadcasting(port: u16, code: &str) -> std::io::Result<DiscoveryHandle> {
    let code_hash = code_to_hash(code);
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "discovery bind failed");
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let _ = sock.set_broadcast(true);
        // Best-effort: SO_BROADCAST failure means broadcast discovery may
        // not work, but we continue anyway (unicast still functions).
        let payload = match postcard::to_allocvec(&Announce { port, code_hash }) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(?e, "announce encode failed");
                let _ = ready_tx.send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("announce encode: {e}"),
                )));
                return;
            }
        };
        // Signal that broadcasting is ready.
        let _ = ready_tx.send(Ok(()));
        let mut cached_addrs: Option<(Vec<Ipv4Addr>, Instant)> = None;
        let cache_ttl = Duration::from_secs(10);
        loop {
            if *rx.borrow() {
                return;
            }
            // Re-enumerate broadcast addresses every 10 seconds instead of
            // every tick to reduce syscall overhead.
            let addrs = match &cached_addrs {
                Some((addrs, expiry)) if Instant::now() < *expiry => addrs.clone(),
                _ => {
                    let addrs = broadcast_addrs().await;
                    cached_addrs = Some((addrs.clone(), Instant::now() + cache_ttl));
                    addrs
                }
            };
            for addr in &addrs {
                let target = SocketAddr::V4(SocketAddrV4::new(*addr, DISCOVERY_PORT));
                if let Err(e) = sock.send_to(&payload, target).await {
                    tracing::debug!(addr = %addr, error = %e, "discovery broadcast send failed");
                }
            }
            tokio::select! {
                () = tokio::time::sleep(ANNOUNCE_INTERVAL) => {}
                _ = rx.changed() => return,
            }
        }
    });
    // Wait for the task to signal readiness (or failure) before returning.
    match ready_rx.await {
        Ok(Ok(())) => Ok(DiscoveryHandle { stop: tx, join }),
        Ok(Err(e)) => {
            // Task already exited with error; propagate it.
            drop(join);
            Err(e)
        }
        Err(_) => {
            // Task panicked during startup.
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "discovery task failed during startup",
            ))
        }
    }
}

/// Listen for broadcasts matching `expected_hash` for at most `dur`.
///
/// # Errors
///
/// Returns `DiscoveryError::Timeout` if no matching announcement arrives
/// within the timeout, `DiscoveryError::Postcard` if an announcement is
/// malformed, or `DiscoveryError::Io` for socket failures.
pub async fn discover(
    expected_hash: &[u8; 32],
    dur: Duration,
) -> Result<SocketAddr, DiscoveryError> {
    let sock = match UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                port = DISCOVERY_PORT,
                error = %e,
                "failed to bind UDP port for discovery; \
                 another instance may be running on this port"
            );
            return Err(e.into());
        }
    };
    if let Err(e) = sock.set_broadcast(true) {
        tracing::warn!(?e, "SO_BROADCAST failed; discovery may not work");
    }
    let mut buf = [0u8; 256];
    let res = timeout(dur, async {
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            if let Ok(a) = postcard::from_bytes::<Announce>(&buf[..n]) {
                if &a.code_hash == expected_hash {
                    let target_ip = match src.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        std::net::IpAddr::V6(v6) => {
                            // Try to extract an IPv4-mapped address (e.g.
                            // ::ffff:192.168.1.5 → 192.168.1.5). This handles
                            // dual-stack hosts that send from IPv6-mapped IPv4.
                            if let Some(v4) = v6.to_ipv4_mapped() {
                                v4
                            } else {
                                tracing::warn!(
                                    src = %v6,
                                    "discovery response from non-mapped IPv6 address; \
                                     cannot connect via IPv4"
                                );
                                Ipv4Addr::UNSPECIFIED
                            }
                        }
                    };
                    return Ok::<SocketAddr, std::io::Error>(SocketAddr::V4(SocketAddrV4::new(
                        target_ip, a.port,
                    )));
                }
            }
        }
    })
    .await
    .map_err(|_| DiscoveryError::Timeout)??;
    Ok(res)
}

async fn broadcast_addrs() -> Vec<Ipv4Addr> {
    // Use OS-reported directed broadcasts (via getifaddrs netmask) plus
    // limited broadcast. The old class-based heuristic guessed wrong
    // subnets (e.g. 172.20.x.x → 172.31.255.255) and omitted
    // 255.255.255.255, which broke Linux↔Mac discovery.
    crate::interfaces::broadcast_addrs().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_format() {
        let port: u16 = 51234;
        let c = generate_code(port);
        let parts: Vec<_> = c.split('-').collect();
        assert_eq!(parts.len(), 3);
        // Digit must be a single ASCII digit matching port % 10.
        let expected_digit = (port % 10).to_string();
        assert_eq!(parts[0], expected_digit);
        assert!(parts[0].len() == 1 && parts[0].chars().next().unwrap().is_ascii_digit());
    }
    #[test]
    fn hash_stable() {
        assert_eq!(code_to_hash("7-cobalt-fox"), code_to_hash("7-cobalt-fox"));
    }
    #[test]
    fn hash_normalizes_case_and_whitespace() {
        assert_eq!(code_to_hash("7-cobalt-fox"), code_to_hash("7-Cobalt-Fox"));
        assert_eq!(
            code_to_hash("7-cobalt-fox"),
            code_to_hash("  7-cobalt-fox\n")
        );
    }
    #[test]
    fn wordlist_unique() {
        // Ensure no duplicate words in the wordlist (duplicates waste entropy).
        let mut words: Vec<&str> = WORDS.to_vec();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), WORDS.len(), "WORDLIST contains duplicates");
    }
}
