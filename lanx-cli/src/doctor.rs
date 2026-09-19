use anyhow::{Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn run(relay: Option<String>, relay_receiver: Option<String>, port: u16) -> Result<()> {
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
        let sender = resolve_socket_addrs(&relay).context("resolve relay sender address")?;
        let (receiver_label, receiver) = match relay_receiver {
            Some(address) => (
                address.clone(),
                resolve_socket_addrs(&address).context("resolve relay receiver address")?,
            ),
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
                (format!("{relay} (sender port + 1)"), receiver)
            }
        };
        check_relay_endpoint("sender", &relay, &sender).await;
        check_relay_endpoint("receiver", &receiver_label, &receiver).await;
    }
    Ok(())
}

fn resolve_socket_addrs(address: &str) -> Result<Vec<SocketAddr>> {
    let addresses = address
        .to_socket_addrs()
        .with_context(|| format!("invalid relay address: {address}"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        anyhow::bail!("relay address resolved to no endpoints: {address}");
    }
    Ok(addresses)
}

async fn check_relay_endpoint(role: &str, label: &str, addresses: &[SocketAddr]) {
    let mut last_error = String::from("connection failed");
    for address in addresses {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(_)) => {
                println!("OK    relay {role} endpoint reachable: {label}");
                return;
            }
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = String::from("connection timed out"),
        }
    }
    println!("WARN  relay {role} endpoint unreachable: {label}: {last_error}");
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
