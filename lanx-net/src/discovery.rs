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
use std::time::Duration;
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
const WORDS: &[&str] = &[
    "amber", "apple", "azure", "basil", "birch", "cobalt", "comet", "coral",
    "crimson", "delta", "echo", "ember", "fable", "fern", "fjord", "flint",
    "frost", "garnet", "ginger", "glade", "harbor", "hawk", "hazel", "ivory",
    "jade", "kestrel", "lake", "lark", "lemon", "lilac", "lotus", "lunar",
    "maple", "marble", "merlin", "mint", "mossy", "neon", "noble", "ocean",
    "olive", "onyx", "opal", "otter", "pebble", "pine", "plum", "polar",
    "quartz", "quill", "raven", "reed", "river", "roan", "rose", "rusty",
    "sable", "sage", "satin", "scarlet", "shore", "silk", "slate", "snow",
    "spruce", "storm", "sumac", "swann", "tiger", "topaz", "tundra", "umber",
    "valley", "velvet", "violet", "willow", "wisp", "yarrow", "yew", "zinc",
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
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
        let _ = self.join.await;
    }
}

pub async fn start_broadcasting(port: u16, code: &str) -> std::io::Result<DiscoveryHandle> {
    let code_hash = code_to_hash(code);
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let join = tokio::spawn(async move {
        let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "discovery bind failed");
                return;
            }
        };
        let _ = sock.set_broadcast(true);
        let payload = match postcard::to_allocvec(&Announce { port, code_hash }) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(?e, "announce encode failed");
                return;
            }
        };
        loop {
            if *rx.borrow() {
                return;
            }
            // Broadcast to all non-loopback interface bcast addrs.
            let addrs = broadcast_addrs().await;
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
    Ok(DiscoveryHandle { stop: tx, join })
}

/// Listen for broadcasts matching `expected_hash` for at most `timeout`.
pub async fn discover(expected_hash: &[u8; 32], dur: Duration) -> Result<SocketAddr, DiscoveryError> {
    let sock = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?;
    sock.set_broadcast(true).ok();
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
    match get_local_addrs().await {
        Ok(addrs) => {
            for ip in addrs {
                if let Some(bcast) = ipv4_broadcast(&ip) {
                    out.push(bcast);
                } else {
                    out.push(Ipv4Addr::BROADCAST);
                }
            }
        }
        Err(_) => out.push(Ipv4Addr::BROADCAST),
    }
    if out.is_empty() {
        out.push(Ipv4Addr::BROADCAST);
    }
    out
}

async fn get_local_addrs() -> std::io::Result<Vec<Ipv4Addr>> {
    // Enumerate every non-loopback IPv4 address on every interface. We use
    // `if-addrs` (a thin wrapper over `getifaddrs` / `GetAdaptersInfo`),
    // which works on Linux, macOS, BSDs, and Windows.
    //
    // This is blocking I/O (it calls libc), so we run it on the blocking
    // pool to avoid stalling the async runtime.
    let ifaces = tokio::task::spawn_blocking(if_addrs::get_if_addrs)
        .await
        .map_err(|e| std::io::Error::other(format!("if-addrs join: {e}")))?
        .map_err(|e| std::io::Error::other(format!("if-addrs: {e}")))?;
    let mut out: Vec<Ipv4Addr> = ifaces
        .into_iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// Compute a /24 broadcast for a host IP. Returns None for loopback.
fn ipv4_broadcast(host: &Ipv4Addr) -> Option<Ipv4Addr> {
    if host.is_loopback() {
        return None;
    }
    let o = host.octets();
    Some(Ipv4Addr::new(o[0], o[1], o[2], 255))
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
}
