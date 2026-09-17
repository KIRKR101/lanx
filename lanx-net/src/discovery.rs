//! UDP-broadcast discovery + pairing codes.
//!
//! Wire format: on UDP port 53317, send a small postcard-encoded packet
//! containing `{port: u16, code_hash: [u8; 32], auth_tag: [u8; 32]}`.
//! Receivers filter by `code_hash` (now a domain-separated pairing ID,
//! see [`code_to_pairing_id`]).
//!
//! # Security model (v2)
//!
//! The pairing ID broadcast/relayed in the clear is a *public identifier*,
//! not a secret. Secrecy comes from the PSK derived from the code
//! ([`code_to_psk`]) and mixed into the `Noise_NNpsk0` handshake
//! (`lanx-core/src/crypto.rs`). A passive observer or curious relay can see
//! *which* pairing ID is active but must still guess the code online to
//! complete the handshake, and relay guesses are rate-limited.
//!
//! Default codes are `digit-word-word-word` (≈28 bits with the bundled
//! wordlist); `--code-words 4` reaches ≈36 bits. For internet relays also
//! set `--psk` so the final handshake key has high entropy even if the
//! spoken code is short.
//!
//! The leading digit is a random discriminator, intentionally decoupled
//! from the port so a stable service port does not pin every code to the
//! same digit.

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
    auth_tag: [u8; 32],
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
/// ~294 unique words, ~8.2 bits of entropy per word.
/// Default `digit + 3 words`: 10 × 294³ ≈ 2.5e8 combos, ~27.9 bits.
/// With `--code-words 4`: 10 × 294⁴ ≈ 7.5e10 combos, ~36.1 bits.
/// Legacy 2-word codes (≈19.7 bits) are still *accepted* for pairing but
/// never *generated*; they print a weakness warning.
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
    // Extension batch: short, typable, unambiguous words (ASCII alpha only).
    "almond", "anvil", "apron", "arbor", "aster", "atlas", "autumn", "badger", "bamboo", "banjo",
    "bark", "barley", "beacon", "beaver", "bison", "blizzard", "boron", "boulder", "brave",
    "brisk", "bronze", "bramble", "buffalo", "burrow", "butter", "cactus", "camel", "caribou",
    "cascade", "cavern", "celery", "cherry", "chime", "cinder", "citrus", "clove", "cobble",
    "copper", "cougar", "coyote", "crag", "cricket", "crisp", "daffodil", "dagger", "dazzle",
    "denim", "dew", "dial", "dolphin", "donkey", "dove", "dragon", "durian", "ebony", "eclipse",
    "elm", "emerald", "falcon", "fiber", "finch", "firefly", "flannel", "flicker", "flurry", "fox",
    "fresco", "gecko", "glacier", "gleam", "glimmer", "goblin", "golem", "guava", "gypsum", "halo",
    "hamster", "harp", "honey", "hurdle", "hyena", "igloo", "indigo", "inlet", "jackal", "juniper",
    "kettle", "koala", "lagoon", "lantern", "laser", "lemur", "llama", "magma", "magpie", "mantis",
    "meadow", "melon", "mesa", "meteor", "mongoose", "monsoon", "murmur", "narwhal", "needle",
    "noodle", "nugget",
];

/// Default number of words in a generated code (plus the leading digit).
pub const DEFAULT_CODE_WORDS: usize = 3;
/// Minimum/maximum words accepted by the parser and `--code-words`.
pub const MIN_CODE_WORDS: usize = 2;
pub const MAX_CODE_WORDS: usize = 5;

/// Build a code of the form `digit-word-...-word` with
/// [`DEFAULT_CODE_WORDS`] words. The `digit` is a random 0-9
/// discriminator, decoupled from the port. Words come from [`WORDS`]
/// via a cryptographically seeded RNG.
#[must_use]
pub fn generate_code() -> String {
    generate_code_with_words(DEFAULT_CODE_WORDS)
}

/// Build a code with `n` words. `n` is clamped to
/// `MIN_CODE_WORDS..=MAX_CODE_WORDS` so a bad CLI value cannot produce
/// a degenerate (low-entropy) or absurdly long code.
#[must_use]
pub fn generate_code_with_words(n: usize) -> String {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::from_entropy();
    let n = n.clamp(MIN_CODE_WORDS, MAX_CODE_WORDS);
    let digit: u8 = rng.gen_range(0..10);
    let mut code = digit.to_string();
    for _ in 0..n {
        let w = WORDS
            .choose(&mut rng)
            .expect("WORDS is non-empty (compile-time const)");
        code.push('-');
        code.push_str(w);
    }
    code
}

/// Number of word segments in a code (excluding the leading digit).
/// Returns 0 for malformed input: wrong segment count, non-digit prefix,
/// or any empty/non-alphabetic word.
#[must_use]
pub fn code_word_count(code: &str) -> usize {
    let parts: Vec<_> = code.trim().split('-').collect();
    if parts.len() < MIN_CODE_WORDS + 1 || parts.len() > MAX_CODE_WORDS + 1 {
        return 0;
    }
    if parts[0].len() != 1 || !parts[0].chars().next().unwrap().is_ascii_digit() {
        return 0;
    }
    if !parts[1..]
        .iter()
        .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return 0;
    }
    parts.len() - 1
}

/// Estimated entropy (bits) of a code with `n` words:
/// `log2(10 × WORDS.len()ⁿ)`.
#[must_use]
pub fn entropy_bits_for_words(n: usize) -> f64 {
    (10.0 * (WORDS.len() as f64).powi(n as i32)).log2()
}

/// Estimated entropy (bits) of a concrete code string, from its word
/// count. Returns 0.0 for malformed input.
#[must_use]
pub fn code_entropy_bits(code: &str) -> f64 {
    let n = code_word_count(code);
    if n < MIN_CODE_WORDS {
        return 0.0;
    }
    entropy_bits_for_words(n)
}

/// Normalize a pairing code before hashing: trim surrounding
/// whitespace (copy-paste artifacts) and lowercase for
/// case-insensitive pairing.
fn normalize_code(code: &str) -> String {
    code.trim().to_lowercase()
}

/// Back-compat alias for [`code_to_pairing_id`].
///
/// NOTE: despite the name, this is NOT the pre-v2 value
/// (`BLAKE3(normalized_code)`). v2 derives a domain-separated pairing ID,
/// so mixed-version peers compute different lookups and pairing fails
/// closed with a discovery timeout instead of an insecure session.
/// Kept only so old call sites keep compiling; new code must call
/// [`code_to_pairing_id`] for lookup and [`code_to_psk`] for the Noise
/// handshake.
#[must_use]
pub fn code_to_hash(code: &str) -> [u8; 32] {
    code_to_pairing_id(code)
}

/// Public pairing identifier broadcast over UDP and sent to the relay
/// in the clear. Domain-separated (`lanx pairing id v1`) so it cannot
/// be confused with the handshake PSK. Seeing it gives an attacker no
/// advantage beyond knowing *which* session to target: completing the
/// Noise handshake still requires the code itself.
#[must_use]
pub fn code_to_pairing_id(code: &str) -> [u8; 32] {
    let normalized = normalize_code(code);
    let mut hasher = blake3::Hasher::new_derive_key("lanx pairing id v1");
    hasher.update(normalized.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Handshake PSK for `Noise_NNpsk0`, derived from the pairing code and
/// an optional user passphrase (`--psk`).
///
/// Domain-separated (`lanx psk v1` / `lanx psk v1 with passphrase`) so
/// the PSK cannot be confused with the public pairing ID. Both sides
/// must supply the same passphrase (or both omit it) or the handshake
/// fails. The passphrase is never transmitted; it only strengthens the
/// locally derived key.
#[must_use]
pub fn code_to_psk(code: &str, passphrase: Option<&str>) -> [u8; 32] {
    let normalized = normalize_code(code);
    match passphrase {
        None => {
            let mut hasher = blake3::Hasher::new_derive_key("lanx psk v1");
            hasher.update(normalized.as_bytes());
            *hasher.finalize().as_bytes()
        }
        Some(pw) => {
            let mut hasher = blake3::Hasher::new_derive_key("lanx psk v1 with passphrase");
            hasher.update(normalized.as_bytes());
            hasher.update(b"\n");
            hasher.update(pw.as_bytes());
            *hasher.finalize().as_bytes()
        }
    }
}

/// How reachable a `--relay` target looks. Used to tailor the warning:
/// `Public` gets the strong pairing-visibility warning, `Unknown`
/// (unparseable hostname) gets a softer can't-verify note, and LAN-local
/// targets stay silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayVisibility {
    /// Loopback, private, link-local, unspecified, or multicast.
    Private,
    /// Globally reachable address.
    Public,
    /// Not an IP literal (e.g. `relay.example.com:53319` or `localhost`);
    /// reachability can't be proven locally. `localhost` itself is
    /// classified `Private`.
    Unknown,
}

/// Classify a `--relay` target. Accepts bare IPs and `host:port` /
/// `[v6]:port` forms.
#[must_use]
pub fn classify_relay_target(s: &str) -> RelayVisibility {
    let host = s
        .rsplit_once(':')
        .map_or(s, |(h, _)| h)
        .trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return RelayVisibility::Private;
    }
    let ip: Option<std::net::IpAddr> = s.parse().ok().or_else(|| host.parse().ok());
    match ip {
        None => RelayVisibility::Unknown,
        Some(std::net::IpAddr::V4(v4)) => {
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                RelayVisibility::Private
            } else {
                RelayVisibility::Public
            }
        }
        Some(std::net::IpAddr::V6(v6)) => {
            if v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.is_multicast()
            {
                RelayVisibility::Private
            } else {
                RelayVisibility::Public
            }
        }
    }
}

/// Returns true if `s` looks like a globally reachable relay target.
/// `Unknown` hostnames count as public here (fail-closed warning);
/// callers that want tailored wording should use [`classify_relay_target`].
#[must_use]
pub fn relay_target_is_public(s: &str) -> bool {
    classify_relay_target(s) != RelayVisibility::Private
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
    let auth_tag = discovery_auth_tag(code, port, &code_hash);
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
        if let Err(e) = sock.set_broadcast(true) {
            let _ = ready_tx.send(Err(e));
            return;
        }
        let payload = match postcard::to_allocvec(&Announce {
            port,
            code_hash,
            auth_tag,
        }) {
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
            // The task exited with an error; propagate it.
            drop(join);
            Err(e)
        }
        Err(_) => {
            // Task panicked during startup.
            Err(std::io::Error::other(
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
    code: &str,
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
                if &a.code_hash == expected_hash
                    && a.port != 0
                    && a.auth_tag == discovery_auth_tag(code, a.port, &a.code_hash)
                {
                    let target_ip = match src.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        std::net::IpAddr::V6(v6) => {
                            // Try to extract an IPv4-mapped address (e.g.
                            // ::ffff:192.168.1.5 maps to 192.168.1.5. This handles
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

fn discovery_auth_tag(code: &str, port: u16, code_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(2 + code_hash.len() + 16);
    input.extend_from_slice(b"lanx discovery v1");
    input.extend_from_slice(&port.to_be_bytes());
    input.extend_from_slice(code_hash);
    *blake3::keyed_hash(&code_to_psk(code, None), &input).as_bytes()
}

async fn broadcast_addrs() -> Vec<Ipv4Addr> {
    // Use OS-reported directed broadcasts plus the limited broadcast address.
    crate::interfaces::broadcast_addrs().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_format() {
        let c = generate_code();
        let parts: Vec<_> = c.split('-').collect();
        assert_eq!(parts.len(), DEFAULT_CODE_WORDS + 1);
        // Digit is a random single ASCII digit (format only, not port-derived).
        assert_eq!(parts[0].len(), 1);
        assert!(parts[0].chars().next().unwrap().is_ascii_digit());
        for p in &parts[1..] {
            assert!(!p.is_empty());
        }
    }
    #[test]
    fn code_word_count_clamped() {
        assert_eq!(
            generate_code_with_words(0).split('-').count(),
            MIN_CODE_WORDS + 1
        );
        assert_eq!(
            generate_code_with_words(99).split('-').count(),
            MAX_CODE_WORDS + 1
        );
        assert_eq!(generate_code_with_words(4).split('-').count(), 5);
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
    fn pairing_id_differs_from_psk() {
        // Separation of public identifier and handshake secret.
        assert_ne!(
            code_to_pairing_id("7-cobalt-fox-tundra"),
            code_to_psk("7-cobalt-fox-tundra", None)
        );
    }
    #[test]
    fn psk_passphrase_changes_key() {
        assert_ne!(
            code_to_psk("7-cobalt-fox-tundra", None),
            code_to_psk("7-cobalt-fox-tundra", Some("secret"))
        );
        assert_eq!(
            code_to_psk("7-cobalt-fox-tundra", Some("secret")),
            code_to_psk("7-Cobalt-Fox-Tundra", Some("secret"))
        );
    }
    #[test]
    fn entropy_grows_with_words() {
        let e2 = entropy_bits_for_words(2);
        let e3 = entropy_bits_for_words(3);
        let e4 = entropy_bits_for_words(4);
        assert!(e2 > 18.0 && e2 < e3 && e3 < e4);
        assert!(e4 > 32.0, "4-word codes should exceed 32 bits, got {e4}");
    }
    #[test]
    fn public_relay_detection() {
        assert!(!relay_target_is_public("192.168.1.100:53319"));
        assert!(!relay_target_is_public("127.0.0.1:53319"));
        assert!(!relay_target_is_public("10.0.0.5:53319"));
        assert!(relay_target_is_public("203.0.113.7:53319"));
        assert!(relay_target_is_public("8.8.8.8:53319"));
    }
    #[test]
    fn relay_visibility_classification() {
        use RelayVisibility::{Private, Public, Unknown};
        assert_eq!(classify_relay_target("localhost:53319"), Private);
        assert_eq!(classify_relay_target("localhost"), Private);
        assert_eq!(classify_relay_target("0.0.0.0:53319"), Private);
        assert_eq!(classify_relay_target("::"), Private);
        assert_eq!(classify_relay_target("224.0.0.1:53319"), Private);
        assert_eq!(classify_relay_target("169.254.10.1:53319"), Private);
        assert_eq!(classify_relay_target("::1"), Private);
        assert_eq!(classify_relay_target("relay.example.com:53319"), Unknown);
        assert_eq!(classify_relay_target("203.0.113.7:53319"), Public);
    }
    #[test]
    fn word_count_rejects_malformed() {
        assert_eq!(code_word_count("7-cobalt-fox-tundra"), 3);
        assert_eq!(code_word_count("7-a-b-"), 0);
        assert_eq!(code_word_count("7-cobalt-"), 0);
        assert_eq!(code_word_count("7-cobalt-fox-tundra-river-lake-extra"), 0);
        assert_eq!(code_word_count("x-cobalt-fox"), 0);
        assert_eq!(code_entropy_bits("7-a-b-"), 0.0);
    }
    #[test]
    fn wordlist_unique_and_alpha() {
        // Ensure no duplicate words in the wordlist (duplicates waste entropy).
        let mut words: Vec<&str> = WORDS.to_vec();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), WORDS.len(), "WORDLIST contains duplicates");
        for w in WORDS {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "non-lowercase word: {w}"
            );
        }
    }
}
