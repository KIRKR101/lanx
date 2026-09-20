use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::{TcpListener, UdpSocket};

pub async fn run(
    relay: Option<String>,
    relay_receiver: Option<String>,
    port: u16,
    proxy: Option<lanx_net::socks::Socks5Config>,
) -> Result<()> {
    println!("lanx doctor");
    let interfaces = crate::iface::list_non_loopback_v4().await;
    if interfaces.is_empty() {
        println!("WARN  no non-loopback IPv4 interfaces found");
    } else {
        println!(
            "OK    interfaces: {}",
            interfaces
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    check_tcp_port(port).await;
    match UdpSocket::bind(("0.0.0.0", lanx_net::discovery::DISCOVERY_PORT)).await {
        Ok(_) => println!(
            "OK    UDP discovery port {} is available",
            lanx_net::discovery::DISCOVERY_PORT
        ),
        Err(error) => println!(
            "WARN  UDP discovery port {} unavailable: {error}",
            lanx_net::discovery::DISCOVERY_PORT
        ),
    }
    check_writable(Path::new("."));

    if let Some(relay) = relay {
        // `--relay auto` checks every fallback route in selection order:
        // direct (the sender port above already covers it), then the
        // saved relay, then each public pool entry.
        if relay.eq_ignore_ascii_case("auto") {
            for candidate in crate::cmd::auto_relay_candidates(true) {
                let addresses = resolve_socket_addrs(&candidate).await.unwrap_or_default();
                check_relay_endpoint("relay", &candidate, &candidate, &addresses, &proxy).await;
            }
            if crate::cmd::auto_relay_candidates(true).is_empty() {
                println!(
                    "WARN  no saved or public relays configured for --relay auto ({})",
                    crate::cmd::empty_pool_warning()
                );
            }
            return Ok(());
        }
        // Resolve asynchronously (DNS + both families); with a proxy the
        // relay hostname stays proxy-side and these addresses are only
        // used to infer the default receiver port.
        let sender = resolve_socket_addrs(&relay)
            .await
            .context("resolve relay sender address")?;
        let (receiver_label, receiver_target, receiver) = match relay_receiver {
            Some(address) => {
                let addrs = resolve_socket_addrs(&address)
                    .await
                    .context("resolve relay receiver address")?;
                (address.clone(), address, addrs)
            }
            None => {
                let receiver = sender
                    .iter()
                    .map(|address| {
                        Ok(SocketAddr::new(
                            address.ip(),
                            address
                                .port()
                                .checked_add(1)
                                .context("relay sender port is too large to infer receiver port")?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let target = receiver
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| format!("{relay} (sender port + 1)"));
                (format!("{relay} (sender port + 1)"), target, receiver)
            }
        };
        check_relay_endpoint("sender", &relay, &relay, &sender, &proxy).await;
        check_relay_endpoint(
            "receiver",
            &receiver_label,
            &receiver_target,
            &receiver,
            &proxy,
        )
        .await;
    }
    Ok(())
}

async fn resolve_socket_addrs(address: &str) -> Result<Vec<SocketAddr>> {
    lanx_net::tcp::resolve_target_addrs(address)
        .await
        .with_context(|| format!("invalid relay address: {address}"))
}

async fn check_relay_endpoint(
    role: &str,
    label: &str,
    target: &str,
    addresses: &[SocketAddr],
    proxy: &Option<lanx_net::socks::Socks5Config>,
) {
    // With a proxy the relay hostname resolves proxy-side; otherwise try
    // every resolved address (IPv4/IPv6 fallback) before reporting.
    let result = match proxy {
        Some(proxy) => {
            lanx_net::socks::dial_relay(target, Some(proxy), std::time::Duration::from_secs(5))
                .await
                .map(|_| ())
        }
        None => lanx_net::tcp::connect_addrs(addresses, std::time::Duration::from_secs(3))
            .await
            .map(|_| ()),
    };
    match result {
        Ok(()) => println!("OK    relay {role} endpoint reachable: {label}"),
        Err(error) => {
            println!("WARN  relay {role} endpoint unreachable: {label}: {error}");
        }
    }
}

async fn check_tcp_port(port: u16) {
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(_) => println!("OK    TCP sender port {port} is available"),
        Err(error) => println!("WARN  TCP sender port {port} unavailable: {error}"),
    }
}

fn check_writable(path: &Path) {
    match tempfile::tempdir_in(path) {
        Ok(_) => println!("OK    current directory is writable"),
        Err(error) => println!("WARN  current directory is not writable: {error}"),
    }
}
