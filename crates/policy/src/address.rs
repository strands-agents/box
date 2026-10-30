//! The spellings of a pinned destination address that `context.input.ip4` and `context.input.ip6`
//! carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::schema::attr;

/// Each address attribute and the spelling `ip` carries for it.
pub(crate) fn fields(ip: IpAddr) -> [(&'static str, Option<String>); 2] {
    [(attr::IP4, v4(ip)), (attr::IP6, v6(ip))]
}

/// `ip4` as a rule reads it: the IPv4 address itself, or the one an IPv6 wire form carries.
pub(crate) fn v4(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => Some(v4.to_string()),
        IpAddr::V6(v6) => embedded_v4(v6).map(|v4| v4.to_string()),
    }
}

/// `ip6` as a rule reads it: the compressed lowercase wire form, and nothing for an IPv4
/// destination.
pub(crate) fn v6(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => Some(v6.to_string()),
    }
}

/// The IPv4 address `v6` carries, for each transition encoding that embeds one.
pub(crate) fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let segments = v6.segments();
    let octets = v6.octets();
    let last_four = |mask: u8| {
        Ipv4Addr::new(
            octets[12] ^ mask,
            octets[13] ^ mask,
            octets[14] ^ mask,
            octets[15] ^ mask,
        )
    };
    // IPv4-compatible. `::` and `::1` are the unspecified and loopback addresses.
    if segments[..6] == [0, 0, 0, 0, 0, 0] && (segments[6] != 0 || segments[7] > 1) {
        return Some(last_four(0x00));
    }
    // NAT64: the address follows the well-known `64:ff9b::/96` prefix.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(last_four(0x00));
    }
    // IPv4-translated: the address follows the `::ffff:0:0:0/96` prefix.
    if segments[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return Some(last_four(0x00));
    }
    // 6to4: the address follows the `2002` prefix.
    if segments[0] == 0x2002 {
        let [a, b] = segments[1].to_be_bytes();
        let [c, d] = segments[2].to_be_bytes();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    // Teredo: the last 32 bits, inverted.
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return Some(last_four(0xff));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(literal: &str) -> IpAddr {
        literal.parse().expect("an address")
    }

    fn spelled(literal: &str) -> (Option<String>, Option<String>) {
        let address = address(literal);
        (v4(address), v6(address))
    }

    /// An IPv6 wire form that carries an IPv4 address populates both: `ip4` is the address it
    /// carries, and `ip6` is the wire form it arrived as.
    #[test]
    fn every_ipv6_encoding_of_an_ipv4_address_populates_both() {
        for (encoding, literal, wire) in [
            (
                "IPv4-mapped",
                "::ffff:169.254.169.254",
                "::ffff:169.254.169.254",
            ),
            (
                "IPv4-mapped, hex",
                "::ffff:a9fe:a9fe",
                "::ffff:169.254.169.254",
            ),
            ("IPv4-compatible", "::169.254.169.254", "::a9fe:a9fe"),
            ("6to4", "2002:a9fe:a9fe::", "2002:a9fe:a9fe::"),
            ("Teredo", "2001:0:0:0:0:0:5601:5601", "2001::5601:5601"),
            (
                "NAT64 well-known prefix",
                "64:ff9b::169.254.169.254",
                "64:ff9b::a9fe:a9fe",
            ),
            (
                "NAT64 well-known prefix, hex",
                "64:ff9b::a9fe:a9fe",
                "64:ff9b::a9fe:a9fe",
            ),
            (
                "IPv4-translated",
                "::ffff:0:169.254.169.254",
                "::ffff:0:a9fe:a9fe",
            ),
            (
                "IPv4-translated, hex",
                "::ffff:0:a9fe:a9fe",
                "::ffff:0:a9fe:a9fe",
            ),
        ] {
            assert_eq!(
                spelled(literal),
                (Some("169.254.169.254".to_string()), Some(wire.to_string())),
                "{encoding} ({literal})"
            );
        }
    }

    /// An IPv4 destination populates `ip4` alone. One IPv4 address has many IPv6 encodings, so
    /// there is no IPv6 form to report and none is computed.
    #[test]
    fn an_ipv4_destination_populates_ip4_and_no_ip6() {
        for literal in ["169.254.169.254", "127.0.0.1", "0.0.0.0", "203.0.113.7"] {
            assert_eq!(
                spelled(literal),
                (Some(literal.to_string()), None),
                "{literal}"
            );
        }
    }

    /// An address outside every embedding prefix carries no IPv4 address, so `ip4` is absent and
    /// a rule's `context.input has ip4` is false for it.
    #[test]
    fn an_ipv6_address_that_carries_no_ipv4_address_populates_ip6_alone() {
        for literal in [
            "fd00:ec2::254",
            "2001:db8::1",
            "fe80::1",
            "64:ff9c::a9fe:a9fe",
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b::1:a9fe:a9fe",
            "::fffe:0:a9fe:a9fe",
            "::ffff:1:a9fe:a9fe",
        ] {
            assert_eq!(
                spelled(literal),
                (None, Some(literal.to_string())),
                "{literal}"
            );
        }
    }

    #[test]
    fn ip6_is_compressed_and_lowercase() {
        assert_eq!(
            v6(address("FD00:00EC:0000:0000:0000:0000:0000:0254")),
            Some("fd00:ec::254".to_string())
        );
        assert_eq!(
            v6(address("fd00:ec2:0::254")),
            Some("fd00:ec2::254".to_string())
        );
        assert_eq!(v6(address("FE80::1")), Some("fe80::1".to_string()));
    }

    #[test]
    fn unspecified_and_loopback_carry_no_ipv4_address() {
        assert_eq!(spelled("::"), (None, Some("::".to_string())));
        assert_eq!(spelled("::1"), (None, Some("::1".to_string())));
    }
}
