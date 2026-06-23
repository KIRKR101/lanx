//! Cross-platform enumeration of local IPv4 addresses.
//!
//! Implemented via the `if-addrs` crate (a thin wrapper over
//! `getifaddrs` on Unix and `GetAdaptersInfo` on Windows). Loopback and
//! unspecified addresses are filtered out; the caller may apply further
//! filters (e.g. dropping link-local).
//!
//! This runs on the blocking pool because the underlying syscalls are
//! blocking.

use std::net::IpAddr;
use std::net::Ipv4Addr;

pub fn list_non_loopback_v4() -> Vec<Ipv4Addr> {
    let res = tokio::task::block_in_place(if_addrs::get_if_addrs);
    let Ok(ifaces) = res else {
        tracing::warn!(error = ?res.err(), "interface enumeration failed");
        return Vec::new();
    };
    let mut out: Vec<Ipv4Addr> = ifaces
        .into_iter()
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn returns_at_most_loopback_on_isolated_host() {
        // We can't assert much portably — on a normal dev machine this
        // returns at least one real address. On a hermetic CI runner it
        // may return only loopback (which we filter out). So the only
        // universal assertion is: nothing loopback, nothing unspecified.
        for ip in list_non_loopback_v4() {
            assert!(!ip.is_loopback(), "loopback leaked: {ip}");
            assert!(!ip.is_unspecified(), "unspecified leaked: {ip}");
        }
    }
}
