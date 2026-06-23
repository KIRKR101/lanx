//! UDP-broadcast discovery + pairing codes.
//!
//! Wire format: on UDP port 53317, send a small postcard-encoded packet
//! containing `{port: u16, code_hash: [u8; 32]}`.
//! Receivers filter by `code_hash`. The pairing code embeds the port
//! so a hostile broadcaster can't trivially redirect, but this is *not*
//! security — it's a UX hint. Encryption is a v2 concern (plan §1).

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
    #[error("timed out waiting for sender")]
    Timeout,
    #[error("postcard: {0}")]
    Postcard(#[from] postcard::Error),
}

/// Short wordlist — kept inline to avoid an extra build step.
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

/// The hash receivers compare against announcements. We do BLAKE3 of the
/// code string, then truncate to 32 bytes (BLAKE3 default). The sender
/// announces the hash; the receiver hashes the entered code locally
/// and compares.
pub fn code_to_hash(code: &str) -> [u8; 32] {
    let h = blake3::hash(code.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Start broadcasting on all non-loopback IPv4 interfaces. Returns a
/// handle whose `stop` future completes when you drop it (or call
/// `stop()`).
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
                let _ = sock.send_to(&payload, target).await;
            }
            tokio::select! {
                _ = tokio::time::sleep(ANNOUNCE_INTERVAL) => {}
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

/// Listen for broadcasts matching `expected_hash` for at most `timeout`.
pub async fn discover(
    expected_hash: &[u8; 32],
    dur: Duration,
) -> Result<SocketAddr, DiscoveryError> {
    let sock = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?;
    if let Err(e) = sock.set_broadcast(true) {
        tracing::warn!(?e, "SO_BROADCAST failed; discovery may not work");
    }
    let mut buf = [0u8; 256];
    let res = timeout(dur, async {
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            if let Ok(a) = postcard::from_bytes::<Announce>(&buf[..n]) {
                if &a.code_hash == expected_hash {
                    return Ok::<SocketAddr, std::io::Error>(SocketAddr::V4(SocketAddrV4::new(
                        match src.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => Ipv4Addr::UNSPECIFIED,
                        },
                        a.port,
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
    // Best-effort: get all interface IPv4 addrs and form broadcast addrs
    // by setting the host portion. If we can't enumerate, fall back to
    // limited broadcast.
    let mut out = Vec::new();
    let addrs = crate::interfaces::list_non_loopback_v4().await;
    if addrs.is_empty() {
        out.push(Ipv4Addr::BROADCAST);
    } else {
        for ip in addrs {
            if let Some(bcast) = ipv4_broadcast(&ip) {
                out.push(bcast);
            } else {
                out.push(Ipv4Addr::BROADCAST);
            }
        }
    }
    if out.is_empty() {
        out.push(Ipv4Addr::BROADCAST);
    }
    out
}

/// Compute a broadcast address for a host IP. Uses the most common
/// private-range subnet masks rather than assuming /24. Falls back to
/// limited broadcast (255.255.255.255) for public or unrecognized ranges.
///
/// Note: This is best-effort for a LAN discovery tool. For exact subnet
/// mask information, the OS routing table or netlink would be needed,
/// which is out of scope for a zero-configuration pairing tool.
fn ipv4_broadcast(host: &Ipv4Addr) -> Option<Ipv4Addr> {
    if host.is_loopback() {
        return None;
    }
    let o = host.octets();
    match o[0] {
        // 10.0.0.0/8 — class A private range. Most deployments use /8
        // or /16; using the class-A broadcast covers both.
        10 => Some(Ipv4Addr::new(10, 255, 255, 255)),
        // 172.16.0.0/12 — class B private range, typically /12 or /16
        172 if (16..=31).contains(&o[1]) => Some(Ipv4Addr::new(172, 31, 255, 255)),
        // 192.168.0.0/16 — class C private range, most commonly /24
        192 if o[1] == 168 => Some(Ipv4Addr::new(192, 168, o[2], 255)),
        // 169.254.0.0/16 — link-local, typically /16
        169 if o[1] == 254 => Some(Ipv4Addr::new(169, 254, 255, 255)),
        // Public or unrecognized: use limited broadcast as fallback.
        _ => Some(Ipv4Addr::BROADCAST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_format() {
        let c = generate_code(51234);
        let parts: Vec<_> = c.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u32>().is_ok());
    }
    #[test]
    fn hash_stable() {
        assert_eq!(code_to_hash("7-cobalt-fox"), code_to_hash("7-cobalt-fox"));
    }
    #[test]
    fn broadcast_excludes_loopback() {
        assert!(ipv4_broadcast(&Ipv4Addr::new(127, 0, 0, 1)).is_none());
        assert!(ipv4_broadcast(&Ipv4Addr::new(192, 168, 1, 5)).is_some());
    }
    #[test]
    fn broadcast_address_per_subnet() {
        // 10.x.x.x → 10.255.255.255 (class A)
        let b = ipv4_broadcast(&Ipv4Addr::new(10, 0, 1, 42)).unwrap();
        assert_eq!(b, Ipv4Addr::new(10, 255, 255, 255));
        // 172.16-31.x.x → 172.31.255.255 (class B private)
        let b = ipv4_broadcast(&Ipv4Addr::new(172, 20, 3, 9)).unwrap();
        assert_eq!(b, Ipv4Addr::new(172, 31, 255, 255));
        // 192.168.x.x → 192.168.x.255 (class C)
        let b = ipv4_broadcast(&Ipv4Addr::new(192, 168, 5, 100)).unwrap();
        assert_eq!(b, Ipv4Addr::new(192, 168, 5, 255));
        // Public IP → limited broadcast
        let b = ipv4_broadcast(&Ipv4Addr::new(8, 8, 8, 8)).unwrap();
        assert_eq!(b, Ipv4Addr::BROADCAST);
    }
    #[test]
    fn wordlist_unique() {
        // Ensure no duplicate words in the wordlist (duplicates waste entropy).
        let mut words: Vec<&str> = WORDS.to_vec();
        words.sort();
        words.dedup();
        assert_eq!(words.len(), WORDS.len(), "WORDLIST contains duplicates");
    }
}
