//! Anti-SSRF / anti-DNS-rebinding protection and validated connection to upstreams.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

/// Network error or SSRF block when connecting to the upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    DnsFailed(String),
    BlockedPrivateIp(IpAddr),
    ConnectFailed(String),
    ConnectTimeout,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::DnsFailed(msg) => write!(f, "DNS resolution failed: {msg}"),
            NetError::BlockedPrivateIp(ip) => {
                write!(f, "connection blocked by anti-SSRF policy (non-public IP: {ip})")
            }
            NetError::ConnectFailed(msg) => write!(f, "failed to connect to upstream: {msg}"),
            NetError::ConnectTimeout => f.write_str("timeout connecting to upstream"),
        }
    }
}

impl std::error::Error for NetError {}

/// Connection policy towards upstreams.
///
/// In production it always has `allow_private_ips = false` and an empty `host_overrides`.
/// The test fields are only used from automated tests on `localhost`.
#[derive(Debug, Clone, Default)]
pub struct ConnectPolicy {
    pub allow_private_ips: bool,
    pub host_overrides: HashMap<(String, u16), SocketAddr>,
}

/// Returns `true` only if `ip` is a publicly routable internet address.
///
/// Rejects loopback, RFC1918, link-local/metadata (`169.254.0.0/16`, `fe80::/10`),
/// CGNAT (`100.64.0.0/10`), ULA (`fc00::/7`), multicast, reserved, 6to4, NAT64
/// and IPv4-mapped/compatible IPv6.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    // 0.0.0.0/8 ("this network")
    if a == 0 {
        return false;
    }
    // 10.0.0.0/8 (RFC1918)
    if a == 10 {
        return false;
    }
    // 100.64.0.0/10 (CGNAT / RFC6598)
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // 127.0.0.0/8 (loopback)
    if a == 127 {
        return false;
    }
    // 169.254.0.0/16 (link-local and cloud metadata 169.254.169.254)
    if a == 169 && b == 254 {
        return false;
    }
    // 172.16.0.0/12 (RFC1918)
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments)
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    // 192.0.2.0/24 (TEST-NET-1)
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    // 192.88.99.0/24 (6to4 relay anycast, obsolete)
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    // 192.168.0.0/16 (RFC1918)
    if a == 192 && b == 168 {
        return false;
    }
    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved + broadcast 255.255.255.255)
    if a >= 224 {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) → evaluate as IPv4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }

    let segs = ip.segments();
    // Only the Global Unicast block (2000::/3) is publicly routable on the internet.
    // This automatically rules out ::, ::1, ::a.b.c.d, fc00::/7 (ULA), fe80::/10 (link-local),
    // fec0::/10, ff00::/8 (multicast), 64:ff9b::/96 (NAT64), etc.
    if (segs[0] & 0xe000) != 0x2000 {
        return false;
    }
    // 2001:db8::/32 (documentation)
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return false;
    }
    // 2001:2::/48 (benchmarking)
    if segs[0] == 0x2001 && segs[1] == 0x0002 && segs[2] == 0x0000 {
        return false;
    }
    // 2001:10::/28 and 2001:20::/28 (ORCHID / ORCHIDv2)
    if segs[0] == 0x2001 && ((segs[1] & 0xfff0) == 0x0010 || (segs[1] & 0xfff0) == 0x0020) {
        return false;
    }
    // 2002::/16 (6to4 can embed a private IPv4 into segs[1..=2])
    if segs[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        );
        return is_public_ipv4(embedded);
    }
    true
}

/// Resolves `host:port` **once only**, validates that all returned IPs comply with the
/// policy anti-SSRF and connects directly to the validated IP (avoiding DNS rebinding).
pub async fn connect_validated(
    host: &str,
    port: u16,
    timeout: Duration,
    policy: &ConnectPolicy,
) -> Result<(TcpStream, SocketAddr), NetError> {
    let host_lower = host.to_ascii_lowercase();

    let addrs: Vec<SocketAddr> = if let Some(&override_addr) =
        policy.host_overrides.get(&(host_lower.clone(), port))
    {
        vec![override_addr]
    } else {
        tokio::net::lookup_host((host_lower.as_str(), port))
            .await
            .map_err(|e| NetError::DnsFailed(e.to_string()))?
            .collect()
    };

    if addrs.is_empty() {
        return Err(NetError::DnsFailed(format!(
            "DNS returned no addresses for '{host_lower}'"
        )));
    }

    if !policy.allow_private_ips {
        for addr in &addrs {
            if !is_public_ip(addr.ip()) {
                return Err(NetError::BlockedPrivateIp(addr.ip()));
            }
        }
    }

    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok((stream, addr));
            }
            Ok(Err(e)) => last_err = Some(NetError::ConnectFailed(e.to_string())),
            Err(_) => last_err = Some(NetError::ConnectTimeout),
        }
    }

    Err(last_err.unwrap_or_else(|| NetError::ConnectFailed("no reachable addresses".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_classification_blocks_all_private_and_metadata_ranges() {
        let blocked = [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.5",
            "::ffff:192.168.1.10",
            "64:ff9b::10.0.0.1",
            "2001:db8::1",
            "2002:7f00:0001::1", // 6to4 -> 127.0.0.1
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_public_ip(ip), "should block {ip}");
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.63.255.255",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:1.1.1.1",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_public_ip(ip), "should allow {ip}");
        }
    }
}
