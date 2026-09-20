//! Minimal SOCKS5 client (RFC 1928 + username/password RFC 1929) for
//! relay traffic.
//!
//! The relay TCP stream carries both the relay control exchange
//! (challenge/hello/ack) and the Noise-encrypted transfer, so proxying
//! that one stream covers control and transfer traffic alike.
//!
//! Hostnames are always sent to the proxy as `ATYP DOMAINNAME`: the
//! client never resolves the relay address locally. That keeps
//! proxy-side DNS (Tor's `socks5h` behavior) working and avoids leaking
//! relay hostnames through local DNS.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parsed `--proxy` / `LANX_PROXY` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Config {
    /// Proxy endpoint as `host:port` (resolved locally at connect time
    /// with IPv4/IPv6 fallback; typically `127.0.0.1:9050` for Tor).
    pub proxy_target: String,
    /// Optional RFC 1929 credentials.
    pub username: Option<String>,
    /// Optional RFC 1929 credentials.
    pub password: Option<String>,
}

/// Parse a proxy value: `socks5://[user[:pass]@]host:port`,
/// `socks5h://...` (same behavior — DNS is always proxy-side), or a
/// bare `host:port` (assumed SOCKS5).
///
/// # Errors
///
/// Returns a message for missing ports, bad URLs, or unsupported
/// schemes (only SOCKS5 is supported).
pub fn parse_socks5_proxy(raw: &str) -> Result<Socks5Config, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty proxy address".to_string());
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_lowercase()), rest),
        None => (None, s),
    };
    if let Some(scheme) = scheme {
        if scheme != "socks5" && scheme != "socks5h" {
            return Err(format!(
                "unsupported proxy scheme {scheme:?}: use socks5://host:port"
            ));
        }
    }
    // Split optional userinfo: [user[:pass]@]host:port.
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, rest),
    };
    let (username, password) = match userinfo {
        Some(info) => {
            if info.is_empty() {
                return Err(format!("invalid proxy credentials in {raw:?}"));
            }
            match info.split_once(':') {
                Some((user, pass)) => {
                    if user.is_empty() {
                        return Err(format!("invalid proxy credentials in {raw:?}"));
                    }
                    (Some(user.to_string()), Some(pass.to_string()))
                }
                None => (Some(info.to_string()), None),
            }
        }
        None => (None, None),
    };
    // A port is required so there is no ambiguity with Tor's 9050/9150.
    let (_, port) = crate::tcp::split_host_port(hostport)
        .map_err(|_| format!("invalid proxy address {raw:?}: expected host:port"))?;
    let _ = port;
    Ok(Socks5Config {
        proxy_target: hostport.to_string(),
        username,
        password,
    })
}

/// Target host split for the SOCKS5 request: IP literals go as
/// `ATYP IPv4/IPv6`, everything else as `ATYP DOMAINNAME` (proxy-side
/// DNS — never resolved locally).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SocksTarget {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String),
}

fn classify_target_host(host: &str) -> Result<SocksTarget, std::io::Error> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(v4) => SocksTarget::V4(v4.octets()),
            std::net::IpAddr::V6(v6) => SocksTarget::V6(v6.octets()),
        });
    }
    if host.is_empty() || host.len() > 255 || host.contains('/') || host.contains(' ') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid relay hostname for SOCKS5: {host:?}"),
        ));
    }
    Ok(SocksTarget::Domain(host.to_string()))
}

/// Connect to the SOCKS5 proxy and ask it to open `target_host:port`.
/// Returns a stream already connected to the target through the proxy.
///
/// # Errors
///
/// Returns an I/O error if the proxy is unreachable, the handshake or
/// authentication fails, or the proxy refuses the request.
pub async fn connect_via_socks5(
    proxy: &Socks5Config,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, std::io::Error> {
    let target = classify_target_host(target_host)?;
    let (mut stream, _) = crate::tcp::connect_with_fallback(&proxy.proxy_target, timeout).await?;

    // Greeting: version, methods. Offer username/password auth only when
    // credentials are configured; otherwise no-auth only.
    if proxy.username.is_some() {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    stream.flush().await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad SOCKS5 version: {}", method_reply[0]),
        ));
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => {
            let (user, pass) = match (&proxy.username, &proxy.password) {
                (Some(user), pass) => (user.as_str(), pass.as_deref().unwrap_or("")),
                (None, _) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "proxy requires username/password authentication",
                    ));
                }
            };
            if user.len() > 255 || pass.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS5 username/password limited to 255 bytes",
                ));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            stream.flush().await?;
            let mut auth_reply = [0u8; 2];
            stream.read_exact(&mut auth_reply).await?;
            if auth_reply != [0x01, 0x00] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SOCKS5 username/password rejected",
                ));
            }
        }
        0xFF => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "proxy offers no acceptable authentication method",
            ));
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 method: {other:#04x}"),
            ));
        }
    }

    // CONNECT request. Domain names go as-is: the proxy resolves them.
    let mut req = vec![0x05, 0x01, 0x00];
    match &target {
        SocksTarget::V4(octets) => {
            req.push(0x01);
            req.extend_from_slice(octets);
        }
        SocksTarget::V6(octets) => {
            req.push(0x04);
            req.extend_from_slice(octets);
        }
        SocksTarget::Domain(name) => {
            req.push(0x03);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
        }
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad SOCKS5 reply version: {}", header[0]),
        ));
    }
    if header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "proxy refused connection to {target_host}:{target_port}: {}",
                socks_reply_error(header[1])
            ),
        ));
    }
    // Consume the bound address (variable length by ATYP).
    match header[3] {
        0x01 => {
            let mut buf = [0u8; 4 + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 16 + 2];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad SOCKS5 reply address type: {other:#04x}"),
            ));
        }
    }
    Ok(stream)
}

fn socks_reply_error(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

/// Dial a relay `host:port` target, directly (with IPv4/IPv6 fallback)
/// or through a SOCKS5 proxy (proxy-side DNS, no local resolution of
/// the relay hostname). Returns the connected stream.
///
/// # Errors
///
/// Returns an I/O error if resolution (direct) or the proxy handshake
/// fails, or no route connects.
pub async fn dial_relay(
    relay_target: &str,
    proxy: Option<&Socks5Config>,
    timeout: Duration,
) -> Result<TcpStream, std::io::Error> {
    match proxy {
        Some(proxy) => {
            let (host, port) = crate::tcp::split_host_port(relay_target)?;
            connect_via_socks5(proxy, host, port, timeout).await
        }
        None => {
            let (stream, _) = crate::tcp::connect_with_fallback(relay_target, timeout).await?;
            Ok(stream)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parse_proxy_urls() {
        let cfg = parse_socks5_proxy("socks5://127.0.0.1:9050").expect("url");
        assert_eq!(cfg.proxy_target, "127.0.0.1:9050");
        assert_eq!(cfg.username, None);
        let cfg = parse_socks5_proxy("socks5h://127.0.0.1:9050").expect("h url");
        assert_eq!(cfg.proxy_target, "127.0.0.1:9050");
        let cfg = parse_socks5_proxy("127.0.0.1:9050").expect("bare");
        assert_eq!(cfg.proxy_target, "127.0.0.1:9050");
        let cfg = parse_socks5_proxy("socks5://user:pass@proxy:1080").expect("auth");
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
        let cfg = parse_socks5_proxy("socks5://user@proxy:1080").expect("user only");
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password, None);
    }

    #[test]
    fn parse_proxy_rejects_bad_values() {
        for bad in [
            "",
            "http://proxy:1080",
            "socks4://proxy:1080",
            "socks5://proxy-without-port",
            "socks5://:1080",
        ] {
            assert!(parse_socks5_proxy(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn target_classification_prefers_proxy_side_dns() {
        assert!(matches!(
            classify_target_host("relay.example.com").expect("domain"),
            SocksTarget::Domain(_)
        ));
        assert!(matches!(
            classify_target_host("192.0.2.1").expect("v4"),
            SocksTarget::V4(_)
        ));
        assert!(matches!(
            classify_target_host("2001:db8::1").expect("v6"),
            SocksTarget::V6(_)
        ));
    }

    /// Minimal in-test SOCKS5 server. Records the requested ATYP, maps
    /// any DOMAIN to 127.0.0.1 (like Tor would for .onion), and pipes
    /// the connection to the real target.
    async fn fake_socks5_server(
        listener: tokio::net::TcpListener,
        require_auth: Option<(String, String)>,
        atyp_seen: tokio::sync::mpsc::UnboundedSender<u8>,
    ) {
        let (mut client, _) = listener.accept().await.expect("proxy accept");
        // Greeting.
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.expect("greet");
        let nmethods = greet[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await.expect("methods");
        let want_auth = require_auth.is_some();
        let choice = if want_auth && methods.contains(&0x02) {
            0x02
        } else if !want_auth && methods.contains(&0x00) {
            0x00
        } else {
            client.write_all(&[0x05, 0xFF]).await.expect("no method");
            return;
        };
        client
            .write_all(&[0x05, choice])
            .await
            .expect("method reply");
        if choice == 0x02 {
            let (user, pass) = require_auth.clone().expect("auth pair");
            let mut ver = [0u8; 2];
            client.read_exact(&mut ver).await.expect("auth ver");
            let ulen = ver[1] as usize;
            let mut ubuf = vec![0u8; ulen];
            client.read_exact(&mut ubuf).await.expect("user");
            let mut plen = [0u8; 1];
            client.read_exact(&mut plen).await.expect("plen");
            let mut pbuf = vec![0u8; plen[0] as usize];
            client.read_exact(&mut pbuf).await.expect("pass");
            let ok = ubuf == user.as_bytes() && pbuf == pass.as_bytes();
            client
                .write_all(&[0x01, u8::from(!ok)])
                .await
                .expect("auth reply");
            if !ok {
                return;
            }
        }
        // Request.
        let mut head = [0u8; 4];
        client.read_exact(&mut head).await.expect("req head");
        let _ = atyp_seen.send(head[3]);
        let (host, port) = match head[3] {
            0x01 => {
                let mut b = [0u8; 6];
                client.read_exact(&mut b).await.expect("v4 req");
                let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                (ip.to_string(), u16::from_be_bytes([b[4], b[5]]))
            }
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await.expect("domain len");
                let mut b = vec![0u8; len[0] as usize + 2];
                client.read_exact(&mut b).await.expect("domain req");
                let name = String::from_utf8_lossy(&b[..len[0] as usize]).to_string();
                // Proxy-side DNS: every domain maps to loopback here.
                let _ = name;
                let port = u16::from_be_bytes([b[len[0] as usize], b[len[0] as usize + 1]]);
                ("127.0.0.1".to_string(), port)
            }
            0x04 => {
                let mut b = [0u8; 18];
                client.read_exact(&mut b).await.expect("v6 req");
                ("::1".to_string(), u16::from_be_bytes([b[16], b[17]]))
            }
            other => panic!("unexpected atyp {other:#04x}"),
        };
        let upstream = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(_) => {
                client
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("refused");
                return;
            }
        };
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("success");
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut uw) => {},
            _ = tokio::io::copy(&mut ur, &mut cw) => {},
        }
    }

    #[tokio::test]
    async fn proxy_side_dns_needs_no_local_resolution() {
        // `invalid.` never resolves locally; the fake proxy maps any
        // domain to loopback, proving the client sent ATYP DOMAINNAME
        // instead of resolving first.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo bind");
        let echo_port = echo.local_addr().expect("echo addr").port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.expect("echo accept");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.expect("echo read");
            s.write_all(&buf).await.expect("echo write");
        });
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy bind");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let (atyp_tx, mut atyp_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(fake_socks5_server(proxy_listener, None, atyp_tx));

        let proxy = Socks5Config {
            proxy_target: proxy_addr.to_string(),
            username: None,
            password: None,
        };
        // NOTE: `echo.invalid` does not exist in DNS on purpose.
        let target = format!("echo.invalid:{echo_port}");
        let (host, port) = crate::tcp::split_host_port(&target).expect("split");
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            connect_via_socks5(&proxy, host, port, Duration::from_secs(5)),
        )
        .await
        .expect("timeout")
        .expect("via proxy");
        assert_eq!(atyp_rx.recv().await, Some(0x03));
        stream.write_all(b"hello").await.expect("write");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn proxy_forwards_ip_literals_and_auth() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo bind");
        let echo_port = echo.local_addr().expect("echo addr").port();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.expect("echo accept");
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.expect("echo read");
            s.write_all(&buf).await.expect("echo write");
        });
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy bind");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let (atyp_tx, mut atyp_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(fake_socks5_server(
            proxy_listener,
            Some(("user".to_string(), "pass".to_string())),
            atyp_tx,
        ));

        let proxy = parse_socks5_proxy(&format!("socks5://user:pass@{proxy_addr}")).expect("parse");
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            dial_relay(
                &format!("127.0.0.1:{echo_port}"),
                Some(&proxy),
                Duration::from_secs(5),
            ),
        )
        .await
        .expect("timeout")
        .expect("dial");
        assert_eq!(atyp_rx.recv().await, Some(0x01));
        stream.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
    }
}
