// SPDX-License-Identifier: AGPL-3.0-only
//! Operator-configured network trust for the password-reset request lane
//! (issue #526). `RESET_TRUSTED_CIDRS` names networks whose reset requests
//! may use the trusted lane; `TRUSTED_PROXY_CIDRS` names reverse proxies whose
//! `X-Forwarded-For` header may be believed. The client address is the socket
// peer unless that peer is a configured proxy, so a caller cannot reach the
//! trusted lane by spoofing the header from outside.

use std::net::{IpAddr, SocketAddr};

/// One IPv4 or IPv6 network. A bare address means a full-length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `address/prefix` or a bare `address`. Invalid addresses and
    /// prefixes wider than the address family yield `None`.
    pub fn parse(entry: &str) -> Option<Self> {
        /// Sentinel for an omitted prefix; a real prefix never exceeds 128.
        const HOST_PREFIX: u8 = u8::MAX;
        let (address, prefix) = match entry.rsplit_once('/') {
            Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
            None => (entry, HOST_PREFIX),
        };
        let address: IpAddr = address.parse().ok()?;
        let maximum = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = if prefix == HOST_PREFIX {
            maximum
        } else if prefix <= maximum {
            prefix
        } else {
            return None;
        };
        Some(Self {
            network: address,
            prefix,
        })
    }

    /// Whether `address` falls inside this network. The two families never
    /// overlap; a v4 address does not match a v6 network even in mapped form.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = v4_mask(self.prefix);
                (network.to_bits() & mask) == (address.to_bits() & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = v6_mask(self.prefix);
                (network.to_bits() & mask) == (address.to_bits() & mask)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    }
}

fn parse_list(value: Option<&str>, error: &'static str) -> Result<Vec<Cidr>, &'static str> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.len() > 4096 {
        return Err(error);
    }
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| Cidr::parse(entry.trim()).ok_or(error))
        .collect()
}

/// The trusted networks an operator configured for the reset lane. Empty by
/// default: without configuration no address is trusted and
/// `X-Forwarded-For` is never believed.
#[derive(Clone, Debug, Default)]
pub struct TrustedNetworks {
    reset_trusted: Vec<Cidr>,
    trusted_proxies: Vec<Cidr>,
}

impl TrustedNetworks {
    /// Parse both comma-separated CIDR lists. Any invalid entry is a startup
    /// error rather than a silently trusted or ignored network.
    pub fn parse(
        reset_trusted: Option<&str>,
        trusted_proxies: Option<&str>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            reset_trusted: parse_list(reset_trusted, "invalid RESET_TRUSTED_CIDRS")?,
            trusted_proxies: parse_list(trusted_proxies, "invalid TRUSTED_PROXY_CIDRS")?,
        })
    }

    fn is_trusted_proxy(&self, address: IpAddr) -> bool {
        self.trusted_proxies
            .iter()
            .any(|cidr| cidr.contains(address))
    }

    /// The client address a reset request came from. It is the socket peer,
    /// unless that peer is a configured trusted proxy and supplied an
    /// `X-Forwarded-For` chain; then the chain is walked right to left past
    /// trusted proxies, because each appending proxy is to the right of the
    /// address it observed. A chain made only of trusted proxies resolves to
    /// its leftmost entry. An unparsable entry ends the walk with no address:
    /// the walk must never fall through to an entry further left, because a
    /// client can inject arbitrary left entries. An empty header also
    /// resolves to nothing, so the proxy itself is not treated as a client.
    fn client_address(&self, peer: Option<IpAddr>, forwarded_for: Option<&str>) -> Option<IpAddr> {
        let peer = peer?;
        // Without a forwarded chain from a trusted proxy, the peer itself is
        // the client; a header from anyone else is ignored entirely.
        let list = match forwarded_for {
            Some(list) if self.is_trusted_proxy(peer) => list,
            _ => return Some(peer),
        };
        let entries: Vec<&str> = list.split(',').map(str::trim).collect();
        for entry in entries.iter().rev() {
            let Ok(address) = entry.parse::<IpAddr>() else {
                // Fail closed: an unparsable entry proves nothing about the
                // real client, so no address from this chain is returned.
                return None;
            };
            if !self.is_trusted_proxy(address) {
                return Some(address);
            }
        }
        // Every entry is a trusted proxy: the chain resolves to its leftmost
        // entry, and an unparsable leftmost still resolves to nothing.
        entries.first()?.parse::<IpAddr>().ok()
    }

    /// Whether a reset request from `peer` (optionally behind a trusted
    /// proxy's `X-Forwarded-For`) comes from a trusted network and may use
    /// the trusted lane.
    pub fn reset_trusted_client(
        &self,
        peer: Option<SocketAddr>,
        forwarded_for: Option<&str>,
    ) -> bool {
        self.client_address(peer.map(|socket| socket.ip()), forwarded_for)
            .is_some_and(|address| self.reset_trusted.iter().any(|cidr| cidr.contains(address)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn socket(address: &str) -> SocketAddr {
        format!("{address}:443").parse().unwrap()
    }

    fn configured() -> TrustedNetworks {
        TrustedNetworks::parse(
            Some("198.51.100.0/24,2001:db8:beef::/48"),
            Some("203.0.113.0/24"),
        )
        .unwrap()
    }

    #[test]
    fn cidr_parsing_accepts_both_families_and_rejects_garbage() {
        assert_eq!(
            Cidr::parse("198.51.100.0/24").unwrap(),
            Cidr {
                network: "198.51.100.0".parse::<IpAddr>().unwrap(),
                prefix: 24
            }
        );
        // A bare address is a full-length prefix.
        assert_eq!(
            Cidr::parse("198.51.100.7").unwrap(),
            Cidr::parse("198.51.100.7/32").unwrap()
        );
        assert_eq!(Cidr::parse("2001:db8:beef::/48").unwrap().prefix, 48);
        for rejected in [
            "198.51.100.0/33",
            "2001:db8::/129",
            "198.51.100.256/24",
            "not-an-address",
            "198.51.100.0/",
            "/24",
            "",
        ] {
            assert!(Cidr::parse(rejected).is_none(), "{rejected} parsed");
        }
    }

    #[test]
    fn cidr_matching_is_family_and_prefix_scoped() {
        let networks = configured();
        let v4 = Cidr::parse("198.51.100.0/24").unwrap();
        assert!(v4.contains("198.51.100.0".parse::<IpAddr>().unwrap()));
        assert!(v4.contains("198.51.100.255".parse::<IpAddr>().unwrap()));
        assert!(!v4.contains("198.51.101.0".parse::<IpAddr>().unwrap()));
        assert!(!v4.contains("203.0.113.1".parse::<IpAddr>().unwrap()));
        let v6 = Cidr::parse("2001:db8:beef::/48").unwrap();
        assert!(v6.contains("2001:db8:beef:ffff::1".parse::<IpAddr>().unwrap()));
        assert!(!v6.contains("2001:db8:ffff::1".parse::<IpAddr>().unwrap()));
        // Families never mix, even through v4-mapped forms.
        assert!(!v6.contains("198.51.100.7".parse::<IpAddr>().unwrap()));
        assert!(!v4.contains("2001:db8:beef::1".parse::<IpAddr>().unwrap()));
        assert!(networks.is_trusted_proxy("203.0.113.9".parse::<IpAddr>().unwrap()));
        assert!(!networks.is_trusted_proxy("203.0.114.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_rejects_invalid_entries_and_accepts_empty_configuration() {
        assert!(
            TrustedNetworks::parse(None, None)
                .unwrap()
                .reset_trusted
                .is_empty()
        );
        assert!(
            TrustedNetworks::parse(Some(""), Some(""))
                .unwrap()
                .trusted_proxies
                .is_empty()
        );
        assert_eq!(
            TrustedNetworks::parse(Some(" 198.51.100.0/24 ,2001:db8::/32 "), None)
                .unwrap()
                .reset_trusted
                .len(),
            2
        );
        assert!(TrustedNetworks::parse(Some("198.51.100.0/24,banana"), None).is_err());
        assert!(TrustedNetworks::parse(None, Some("203.0.113.1/40")).is_err());
        let long = "198.51.100.0/24,".repeat(300);
        assert!(TrustedNetworks::parse(Some(&long), None).is_err());
    }

    #[test]
    fn socket_peer_alone_decides_trust_without_proxies() {
        let networks = TrustedNetworks::parse(Some("198.51.100.0/24"), None).unwrap();
        assert!(networks.reset_trusted_client(Some(socket("198.51.100.7")), None));
        assert!(!networks.reset_trusted_client(Some(socket("203.0.113.7")), None));
        assert!(!networks.reset_trusted_client(None, None));
    }

    #[test]
    fn the_walk_uses_the_rightmost_non_proxy_entry_not_the_leftmost() {
        let networks = configured();
        // The attacker-injected left entry names a trusted address, but the
        // rightmost non-proxy entry is the real client and is untrusted.
        assert!(
            !networks
                .reset_trusted_client(Some(socket("203.0.113.5")), Some("198.51.100.9, 192.0.2.8"))
        );
        // Dually, a spoofed untrusted left entry cannot untrust a real
        // trusted client on the right.
        assert!(
            networks
                .reset_trusted_client(Some(socket("203.0.113.5")), Some("192.0.2.8, 198.51.100.9"))
        );
    }

    #[test]
    fn an_unparsable_forwarded_entry_fails_the_walk_closed() {
        let networks = configured();
        // A proxy that appends ip:port (or any unparsable form) makes the
        // rightmost entry useless; the walk must not fall through to the
        // attacker-controlled left entry.
        assert!(!networks.reset_trusted_client(
            Some(socket("203.0.113.5")),
            Some("198.51.100.9, 192.0.2.8:51234")
        ));
        assert!(!networks.reset_trusted_client(
            Some(socket("203.0.113.5")),
            Some("198.51.100.9, not-an-address")
        ));
        assert!(!networks.reset_trusted_client(Some(socket("203.0.113.5")), Some("")));
    }

    #[test]
    fn forwarded_for_is_believed_only_from_a_trusted_peer() {
        let networks = configured();
        let spoofed = Some("198.51.100.9");
        // A direct caller in the trusted network: trusted.
        assert!(networks.reset_trusted_client(Some(socket("198.51.100.7")), None));
        // A spoofed header from an untrusted direct peer: ignored.
        assert!(!networks.reset_trusted_client(Some(socket("192.0.2.8")), spoofed));
        // No peer information at all: the header cannot be believed.
        assert!(!networks.reset_trusted_client(None, spoofed));
        // A trusted proxy reporting a trusted client: trusted.
        assert!(networks.reset_trusted_client(Some(socket("203.0.113.5")), Some("198.51.100.9")));
        // A trusted proxy reporting an untrusted client: not trusted.
        assert!(!networks.reset_trusted_client(Some(socket("203.0.113.5")), Some("192.0.2.8")));
        // A chain of trusted proxies: the first non-proxy entry wins, so a
        // client cannot push a spoofed address past an appending proxy.
        assert!(networks.reset_trusted_client(
            Some(socket("203.0.113.5")),
            Some("198.51.100.9, 203.0.113.4")
        ));
        assert!(
            !networks
                .reset_trusted_client(Some(socket("203.0.113.5")), Some("192.0.2.8, 203.0.113.4"))
        );
        // A chain made only of trusted proxies resolves to its leftmost
        // entry, and an unparsable or empty header trusts nothing.
        assert!(networks.reset_trusted_client(
            Some(socket("203.0.113.5")),
            Some("198.51.100.9, 203.0.113.4, 203.0.113.5")
        ));
        assert!(!networks.reset_trusted_client(
            Some(socket("203.0.113.5")),
            Some("203.0.113.4, 203.0.113.5")
        ));
        assert!(!networks.reset_trusted_client(Some(socket("203.0.113.5")), Some("")));
        assert!(!networks.reset_trusted_client(Some(socket("203.0.113.5")), Some("garbage")));
    }
}
