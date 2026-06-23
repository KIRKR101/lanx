//! Enumerate local non-loopback IPv4 addresses so the sender can print
//! every reachable interface (Wi-Fi, Ethernet, Docker, etc.).

use std::net::Ipv4Addr;

/// Return all non-loopback, non-unspecified, non-link-local IPv4 addresses
/// on this host, sorted, deduplicated.
///
/// Implemented in terms of `lanx-net`'s interface enumeration, which uses
/// the `if-addrs` crate (`getifaddrs` / `GetAdaptersInfo`) and works on
/// Linux, macOS, BSDs, and Windows.
pub fn list_non_loopback_v4() -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = lanx_net::interfaces::list_non_loopback_v4();
    out.retain(|ip| !ip.is_unspecified() && !ip.is_link_local());
    out.sort();
    out.dedup();
    out
}
