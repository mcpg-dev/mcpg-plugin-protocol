//! Shared security utilities for MCPG plugins.
//!
//! Provides IP range classification used by the DNS rebinding guard
//! (`safe_dns` in the gateway core) and by plugin HTTP clients that
//! need to reject responses from private backends.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` if the address is in a private, loopback, link-local,
/// CGNAT, multicast, broadcast, unspecified, or ULA range.
///
/// Callers use this to block DNS rebinding attacks: a hostname that
/// resolves to a public IP at config time can be re-pointed to a
/// private IP at dispatch time. Checking the *resolved* address
/// against this function prevents the gateway from connecting to
/// infrastructure it should never reach on behalf of untrusted input.
pub fn is_private_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4_is_blocked(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                || is_ipv4_mapped_private(v6)
        }
    }
}

/// Check if a `reqwest::Response` connected to a private IP.
///
/// Call this after every outbound HTTP request in a plugin. Returns
/// `Err(reason)` when the remote address is private and
/// `allow_private` is false.
pub fn check_response_remote_addr(
    remote_addr: Option<std::net::SocketAddr>,
    allow_private: bool,
) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    if let Some(addr) = remote_addr
        && is_private_address(&addr.ip())
    {
        return Err(format!(
            "DNS rebinding blocked: response came from private address {}",
            addr.ip()
        ));
    }
    Ok(())
}

/// Validate a resolved `SocketAddr` before connecting.
///
/// Returns `Err(reason)` when the IP is private and `allow_private`
/// is false.
pub fn validate_resolved_addr(
    addr: &std::net::SocketAddr,
    allow_private: bool,
) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    if is_private_address(&addr.ip()) {
        return Err(format!(
            "DNS rebinding blocked: resolved address {} is private/loopback/link-local",
            addr.ip()
        ));
    }
    Ok(())
}

// -- IPv4 helpers --

fn is_cgnat(v4: &Ipv4Addr) -> bool {
    // 100.64.0.0/10
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

fn is_reserved_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    // 0.0.0.0/8, 240.0.0.0/4
    o[0] == 0 || o[0] >= 240
}

// -- IPv6 helpers --

fn is_unique_local_v6(v6: &Ipv6Addr) -> bool {
    // fc00::/7
    (v6.segments()[0] & 0xFE00) == 0xFC00
}

fn is_link_local_v6(v6: &Ipv6Addr) -> bool {
    // fe80::/10
    (v6.segments()[0] & 0xFFC0) == 0xFE80
}

/// True when an IPv4 address falls in any range the guard blocks.
fn v4_is_blocked(v4: &Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_multicast()
        || is_cgnat(v4)
        || is_reserved_v4(v4)
}

/// An IPv4 address embedded in an IPv6 one, for the three encodings that
/// actually reach a socket as IPv4.
///
/// The check has to follow the embedding, not just the outer form: to the
/// kernel `::ffff:127.0.0.1` and `64:ff9b::169.254.169.254` are routes to
/// loopback and to link-local, while to a naive IPv6 range test they are
/// ordinary global addresses.
fn embedded_v4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let segs = v6.segments();
    let low = |segs: &[u16; 8]| {
        Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            segs[6] as u8,
            (segs[7] >> 8) as u8,
            segs[7] as u8,
        )
    };
    // ::ffff:a.b.c.d — IPv4-mapped.
    if segs[..5].iter().all(|s| *s == 0) && segs[5] == 0xFFFF {
        return Some(low(&segs));
    }
    // 64:ff9b::a.b.c.d — the NAT64 well-known prefix (RFC 6052). A dual-stack
    // deployment routes these straight at the embedded IPv4.
    if segs[0] == 0x0064 && segs[1] == 0xFF9B && segs[2..6].iter().all(|s| *s == 0) {
        return Some(low(&segs));
    }
    // ::a.b.c.d — IPv4-compatible. Deprecated by RFC 4291 but still accepted
    // by some stacks. `::` and `::1` are already caught as unspecified and
    // loopback, so only a genuine embedded address reaches here.
    if segs[..6].iter().all(|s| *s == 0) && !(segs[6] == 0 && segs[7] <= 1) {
        return Some(low(&segs));
    }
    None
}

/// IPv6 forms that carry an IPv4 address must be checked against the
/// inner IPv4 ranges too, otherwise the guard is bypassed by rebinding to
/// `::ffff:127.0.0.1` or `64:ff9b::169.254.169.254`.
fn is_ipv4_mapped_private(v6: &Ipv6Addr) -> bool {
    embedded_v4(v6).is_some_and(|v4| v4_is_blocked(&v4))
}

/// Human-readable list of blocked ranges for error messages.
pub const PRIVATE_RANGES_DOC: &str = "\
Blocked IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, \
127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, 0.0.0.0/8, 240.0.0.0/4, \
multicast, ::1, fe80::/10, fc00::/7, and any private IPv4 embedded \
via ::ffff:, 64:ff9b:: (NAT64) or ::<v4>";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn public_ipv4_not_private() {
        let addr: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_address(&addr));
    }

    #[test]
    fn loopback_is_private() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn rfc1918_is_private() {
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(is_private_address(&addr), "{ip} should be private");
        }
    }

    #[test]
    fn link_local_is_private() {
        let addr: IpAddr = "169.254.1.1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn cgnat_is_private() {
        let addr: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn ipv6_loopback_is_private() {
        let addr: IpAddr = "::1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn ipv6_link_local_is_private() {
        let addr: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn ipv6_ula_is_private() {
        let addr: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_address(&addr));
    }

    #[test]
    fn ipv6_mapped_loopback_is_private() {
        // ::ffff:127.0.0.1
        let addr: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001));
        assert!(
            is_private_address(&addr),
            "IPv6-mapped 127.0.0.1 must be private"
        );
    }

    #[test]
    fn ipv6_mapped_rfc1918_is_private() {
        // ::ffff:10.0.0.1
        let addr: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001));
        assert!(
            is_private_address(&addr),
            "IPv6-mapped 10.0.0.1 must be private"
        );
    }

    #[test]
    fn ipv6_mapped_public_not_private() {
        // ::ffff:8.8.8.8
        let addr: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808));
        assert!(
            !is_private_address(&addr),
            "IPv6-mapped 8.8.8.8 should not be private"
        );
    }

    #[test]
    fn public_ipv6_not_private() {
        let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_private_address(&addr));
    }

    #[test]
    fn validate_resolved_addr_blocks_private() {
        let addr = "127.0.0.1:80".parse().unwrap();
        assert!(validate_resolved_addr(&addr, false).is_err());
        assert!(validate_resolved_addr(&addr, true).is_ok());
    }

    #[test]
    fn validate_resolved_addr_allows_public() {
        let addr = "8.8.8.8:443".parse().unwrap();
        assert!(validate_resolved_addr(&addr, false).is_ok());
    }

    /// NAT64 and IPv4-compatible IPv6 carry an IPv4 destination the kernel
    /// routes to. Classifying them by their outer IPv6 form alone reads
    /// them as ordinary global addresses, which defeats every guard built
    /// on this function.
    #[test]
    fn ipv6_embedded_private_v4_is_private() {
        for (label, addr) in [
            // 64:ff9b::169.254.169.254 — NAT64 to the metadata service.
            (
                "nat64 link-local",
                Ipv6Addr::new(0x0064, 0xFF9B, 0, 0, 0, 0, 0xA9FE, 0xA9FE),
            ),
            // 64:ff9b::127.0.0.1
            (
                "nat64 loopback",
                Ipv6Addr::new(0x0064, 0xFF9B, 0, 0, 0, 0, 0x7F00, 0x0001),
            ),
            // 64:ff9b::10.0.0.1
            (
                "nat64 rfc1918",
                Ipv6Addr::new(0x0064, 0xFF9B, 0, 0, 0, 0, 0x0A00, 0x0001),
            ),
            // ::127.0.0.1 — IPv4-compatible.
            (
                "v4-compatible loopback",
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7F00, 0x0001),
            ),
            // ::169.254.169.254
            (
                "v4-compatible link-local",
                Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xA9FE, 0xA9FE),
            ),
        ] {
            assert!(
                is_private_address(&IpAddr::V6(addr)),
                "{label} ({addr}) must be treated as private"
            );
        }
    }

    /// The same encodings around a public address must still be allowed —
    /// the fix must not turn NAT64 into a blanket block.
    #[test]
    fn ipv6_embedded_public_v4_is_allowed() {
        // 64:ff9b::8.8.8.8 and ::ffff:8.8.8.8
        for addr in [
            Ipv6Addr::new(0x0064, 0xFF9B, 0, 0, 0, 0, 0x0808, 0x0808),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808),
        ] {
            assert!(
                !is_private_address(&IpAddr::V6(addr)),
                "{addr} embeds a public address and must be allowed"
            );
        }
        // A genuine global IPv6 address is unaffected.
        let global: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!is_private_address(&global));
    }
}
