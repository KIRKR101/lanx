//! TCP listener and dial helpers. `pick_port` picks an ephemeral port and
//! returns the listener plus its bound address. `listen_default` tries
//! the stable service port first so firewall rules stay writable,
//! falling back to an ephemeral port only on `AddrInUse`.

use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// Stable sender port: IANA User Ports range (1024-49151) per RFC6335,
/// below the Linux default ephemeral floor (32768) and outside the IANA
/// Dynamic range (49152-65535). Checked against
/// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
/// Port 29320 is currently unassigned. Binding falls back to an ephemeral
/// port when it is already in use.
/// Discovery uses UDP 53317. Relay binds use 53318 and 53319.
pub const DEFAULT_SEND_PORT: u16 = 29320;

#[derive(Debug, Error)]
pub enum TcpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("listener closed")]
    Closed,
}

/// Split a `host:port` target into its host and port parts. Accepts
/// `host:port`, IPv4 `ip:port`, and bracketed `[v6]:port` forms.
pub fn split_host_port(target: &str) -> Result<(&str, u16), std::io::Error> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid address, expected [ipv6]:port: {target}"),
            )
        })?;
        let port: u16 = port.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid port in address: {target}"),
            )
        })?;
        return Ok((host, port));
    }
    let (host, port) = target.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid address, expected host:port: {target}"),
        )
    })?;
    if host.is_empty() || port.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid address, expected host:port: {target}"),
        ));
    }
    let port: u16 = port.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid port in address: {target}"),
        )
    })?;
    Ok((host, port))
}

/// Resolve a `host:port` target to all of its socket addresses (DNS plus
/// both IP families). IP literals yield exactly one address; hostnames
/// are resolved asynchronously so this never blocks the executor.
///
/// # Errors
///
/// Returns an I/O error if the target shape is invalid or DNS resolution
/// finds no addresses.
pub async fn resolve_target_addrs(target: &str) -> Result<Vec<SocketAddr>, std::io::Error> {
    let target = target.trim();
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let (host, port) = split_host_port(target)?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("address resolved to no endpoints: {target}"),
        ));
    }
    Ok(addrs)
}

/// Order resolved addresses for fallback dialing: preserve DNS order
/// within each family but interleave IPv4 and IPv6 so one broken family
/// cannot starve the other.
fn interleave_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let v4: Vec<_> = addrs.iter().filter(|a| a.is_ipv4()).copied().collect();
    let v6: Vec<_> = addrs.iter().filter(|a| a.is_ipv6()).copied().collect();
    let mut out = Vec::with_capacity(addrs.len());
    let mut v4 = v4.into_iter();
    let mut v6 = v6.into_iter();
    // Alternate families starting with whichever DNS listed first, so a
    // stalled family cannot delay every address of the working one.
    let mut v6_turn = addrs.first().is_some_and(|a| a.is_ipv6());
    loop {
        let next = if v6_turn {
            v6.next().or_else(|| v4.next())
        } else {
            v4.next().or_else(|| v6.next())
        };
        match next {
            Some(addr) => {
                // Only flip when both families still have addresses;
                // otherwise drain the remainder in order.
                if v4.len() > 0 && v6.len() > 0 {
                    v6_turn = !v6_turn;
                }
                out.push(addr);
            }
            None => break,
        }
    }
    out
}

/// Connect to the first reachable address in `addrs`, trying each in
/// turn with `timeout` per attempt. Returns the stream and the address
/// that succeeded.
///
/// # Errors
///
/// Returns the last connection error when every address fails.
pub async fn connect_addrs(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), std::io::Error> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no addresses to connect to",
        ));
    }
    let mut last_error: Option<std::io::Error> = None;
    for addr in interleave_families(addrs) {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok((stream, addr)),
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => {
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connect {addr} timed out"),
                ));
            }
        }
    }
    Err(last_error.expect("non-empty addrs always sets last_error"))
}

/// Connect to a `host:port` target with IPv4/IPv6 fallback: resolve all
/// addresses and try each in turn. Returns the stream and the address
/// that succeeded.
///
/// # Errors
///
/// Returns an I/O error if resolution fails or every address refuses
/// the connection.
pub async fn connect_with_fallback(
    target: &str,
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), std::io::Error> {
    let addrs = resolve_target_addrs(target).await?;
    connect_addrs(&addrs, timeout).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "connect {target} failed (tried {} address(es)): {e}",
                addrs.len()
            ),
        )
    })
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

/// Bind a sender listener to a specific local address. With no explicit port,
/// try the stable sender port and fall back to an ephemeral port if occupied.
pub async fn listen_on(
    bind: &str,
    port: Option<u16>,
) -> Result<(TcpListener, SocketAddr), TcpError> {
    let ip: std::net::IpAddr = bind.parse().map_err(|_| {
        TcpError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid bind address: {bind}"),
        ))
    })?;
    let preferred = port.unwrap_or(DEFAULT_SEND_PORT);
    match TcpListener::bind(SocketAddr::new(ip, preferred)).await {
        Ok(listener) => {
            let addr = listener.local_addr()?;
            Ok((listener, addr))
        }
        Err(e) if port.is_none() && e.kind() == std::io::ErrorKind::AddrInUse => {
            let listener = TcpListener::bind(SocketAddr::new(ip, 0)).await?;
            let addr = listener.local_addr()?;
            Ok((listener, addr))
        }
        Err(e) => Err(TcpError::Io(e)),
    }
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

    #[tokio::test]
    async fn resolve_ip_literals_without_dns() {
        let addrs = resolve_target_addrs("127.0.0.1:29320").await.expect("v4");
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv4());
        let addrs = resolve_target_addrs("[::1]:29320").await.expect("v6");
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv6());
    }

    #[tokio::test]
    async fn resolve_localhost_covers_both_families() {
        // `localhost` normally resolves to 127.0.0.1 and/or ::1; either
        // way we must get at least one usable address.
        let addrs = resolve_target_addrs("localhost:29320")
            .await
            .expect("localhost resolves");
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 29320));
    }

    #[tokio::test]
    async fn resolve_rejects_bad_shapes() {
        for bad in ["", "noport", "host:", ":1234", "[::1]", "host:notaport"] {
            assert!(resolve_target_addrs(bad).await.is_err(), "resolved {bad:?}");
        }
    }

    #[test]
    fn interleave_keeps_dns_order_within_families() {
        let v4a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let v4b: SocketAddr = "127.0.0.2:1".parse().unwrap();
        let v6a: SocketAddr = "[::1]:1".parse().unwrap();
        // v4 first in DNS: v4, v6, v4.
        assert_eq!(interleave_families(&[v4a, v6a, v4b]), vec![v4a, v6a, v4b]);
        // v6 first in DNS: v6, v4, v4.
        assert_eq!(interleave_families(&[v6a, v4a, v4b]), vec![v6a, v4a, v4b]);
    }

    #[tokio::test]
    async fn connect_skips_dead_addresses() {
        // First address is unroutable; the second is a live listener.
        // TEST-NET-1 (192.0.2.1) is reserved by RFC 5737 and unroutable.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let live = listener.local_addr().expect("addr");
        let dead: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let (stream, used) = tokio::time::timeout(
            Duration::from_secs(15),
            connect_addrs(&[dead, live], Duration::from_secs(3)),
        )
        .await
        .expect("outer timeout")
        .expect("fallback connects");
        assert_eq!(used, live);
        drop(stream);
    }

    #[tokio::test]
    async fn connect_with_fallback_reaches_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let target = format!("127.0.0.1:{port}");
        let (_stream, used) = connect_with_fallback(&target, Duration::from_secs(5))
            .await
            .expect("connect");
        assert_eq!(used.port(), port);
    }
}
