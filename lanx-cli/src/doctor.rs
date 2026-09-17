use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn run(relay: Option<String>, port: u16) -> Result<()> {
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
        let addr: SocketAddr = relay
            .parse()
            .with_context(|| format!("invalid relay address: {relay}"))?;
        match tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
            .await
        {
            Ok(Ok(_)) => println!("OK    relay reachable: {relay}"),
            Ok(Err(error)) => println!("WARN  relay unreachable: {relay}: {error}"),
            Err(_) => println!("WARN  relay connection timed out: {relay}"),
        }
    }
    Ok(())
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
