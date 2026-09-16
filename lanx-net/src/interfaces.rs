//! Cross-platform enumeration of local IPv4 addresses.
//!
//! Implemented via the `if-addrs` crate (a thin wrapper over
//! `getifaddrs` on Unix and `GetAdaptersInfo` on Windows). Loopback and
//! unspecified addresses are filtered out; the caller may apply further
//! filters (e.g. dropping link-local).
//!
//! This is a blocking operation (underlying syscalls), so callers
//! should run it on a blocking thread via `tokio::task::spawn_blocking`.

use std::net::IpAddr;
use std::net::Ipv4Addr;

/// Enumerate non-loopback, non-unspecified IPv4 addresses.
///
/// **Important:** This function performs blocking I/O. In an async
/// context, wrap it with `tokio::task::spawn_blocking` to avoid
/// stalling the executor.
pub fn list_non_loopback_v4_sync() -> Vec<Ipv4Addr> {
    let res = if_addrs::get_if_addrs();
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

/// Async wrapper: runs `list_non_loopback_v4_sync` on the blocking pool.
pub async fn list_non_loopback_v4() -> Vec<Ipv4Addr> {
    tokio::task::spawn_blocking(list_non_loopback_v4_sync)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "interface enumeration task panicked");
            Vec::new()
        })
}

/// Enumerate directed-broadcast addresses for all usable IPv4 interfaces.
///
/// Uses the OS-provided broadcast address from `getifaddrs` when
/// available, falling back to `ip | !netmask` when the OS does not
/// report one. Loopback, unspecified, down, and link-local interfaces
/// are skipped. The returned list never contains duplicates.
pub fn broadcast_addrs_sync() -> Vec<Ipv4Addr> {
    let res = if_addrs::get_if_addrs();
    let Ok(ifaces) = res else {
        tracing::warn!(error = ?res.err(), "interface enumeration failed");
        return vec![Ipv4Addr::BROADCAST];
    };
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for iface in ifaces {
        let if_addrs::IfAddr::V4(v4) = &iface.addr else {
            continue;
        };
        if v4.ip.is_loopback() || v4.ip.is_unspecified() || v4.ip.is_link_local() {
            continue;
        }
        if iface.oper_status != if_addrs::IfOperStatus::Up
            && iface.oper_status != if_addrs::IfOperStatus::Unknown
        {
            continue;
        }
        if let Some(bcast) = v4.broadcast {
            if !bcast.is_unspecified() && !bcast.is_loopback() {
                out.push(bcast);
                continue;
            }
        }
        // Fallback: compute from netmask (ip | !mask). A zero netmask
        // means the OS gave us nothing usable — skip it.
        let mask = u32::from(v4.netmask);
        if mask == 0 {
            continue;
        }
        let bcast = Ipv4Addr::from(u32::from(v4.ip) | !mask);
        if !bcast.is_unspecified() && !bcast.is_loopback() {
            out.push(bcast);
        }
    }
    out.sort();
    out.dedup();
    // Always include limited broadcast as a last resort: it reaches the
    // local link even when our netmask/broadcast computation is wrong
    // (VPNs, odd masks, AP isolation quirks), and it is what makes
    // same-host testing work.
    if !out.contains(&Ipv4Addr::BROADCAST) {
        out.push(Ipv4Addr::BROADCAST);
    }
    out
}

/// Async wrapper: runs `broadcast_addrs_sync` on the blocking pool.
pub async fn broadcast_addrs() -> Vec<Ipv4Addr> {
    tokio::task::spawn_blocking(broadcast_addrs_sync)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "interface enumeration task panicked");
            vec![Ipv4Addr::BROADCAST]
        })
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
        for ip in list_non_loopback_v4_sync() {
            assert!(!ip.is_loopback(), "loopback leaked: {ip}");
            assert!(!ip.is_unspecified(), "unspecified leaked: {ip}");
        }
    }

    #[test]
    fn broadcast_targets_always_include_limited_broadcast() {
        // Regression: discovery used to send only to heuristic directed
        // broadcasts and omitted 255.255.255.255, breaking Linux↔Mac
        // pairing when the heuristic guessed the wrong subnet.
        let addrs = broadcast_addrs_sync();
        assert!(
            addrs.contains(&Ipv4Addr::BROADCAST),
            "limited broadcast missing: {addrs:?}"
        );
        for ip in &addrs {
            assert!(!ip.is_loopback(), "loopback leaked: {ip}");
            assert!(!ip.is_unspecified(), "unspecified leaked: {ip}");
        }
        let mut sorted = addrs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, {
            let mut a = addrs.clone();
            a.sort();
            a
        });
    }
}
