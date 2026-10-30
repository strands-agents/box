//! The `ip4` and `ip6` spellings a pinned destination address carries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::schema::attr;

/// Each address attribute an address populates, in the spelling a rule reads.
pub(crate) fn attributes(ip: IpAddr) -> Vec<(&'static str, String)> {
    [(attr::IP4, ip4(ip)), (attr::IP6, ip6(ip))]
        .into_iter()
        .filter_map(|(name, spelling)| spelling.map(|spelling| (name, spelling)))
        .collect()
}

/// `ip4` as a rule reads it: the dotted quad, for an IPv4 address and for each IPv6 encoding that
/// carries one.
pub(crate) fn ip4(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => Some(v4.to_string()),
        IpAddr::V6(v6) => embedded_v4(v6).map(|v4| v4.to_string()),
    }
}

/// `ip6` as a rule reads it: the wire form, compressed and in lowercase. An IPv4 destination
/// carries none, because one IPv4 address has many IPv6 encodings.
pub(crate) fn ip6(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(_) => None,
        IpAddr::V6(v6) => Some(v6.to_string()),
    }
}

/// The IPv4 address `v6` carries, for each transition encoding that embeds one.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
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

    fn parse(literal: &str) -> IpAddr {
        literal.parse().expect("an address")
    }

    fn spellings(literal: &str) -> (Option<String>, Option<String>) {
        let address = parse(literal);
        (ip4(address), ip6(address))
    }

    #[test]
    fn every_ipv6_encoding_of_an_ipv4_address_populates_both_attributes() {
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
                spellings(literal),
                (Some("169.254.169.254".to_string()), Some(wire.to_string())),
                "{encoding} ({literal})"
            );
        }
    }

    /// One IPv4 address has many IPv6 encodings, so there is no IPv6 form to compute for one.
    #[test]
    fn a_plain_ipv4_destination_carries_no_ipv6_form() {
        assert_eq!(
            spellings("169.254.169.254"),
            (Some("169.254.169.254".to_string()), None)
        );
    }

    #[test]
    fn ipv6_is_compressed_and_lowercase() {
        assert_eq!(
            spellings("FD00:00EC:0000:0000:0000:0000:0000:0254"),
            (None, Some("fd00:ec::254".to_string()))
        );
        assert_eq!(
            spellings("fd00:ec2:0::254"),
            (None, Some("fd00:ec2::254".to_string()))
        );
        assert_eq!(spellings("FE80::1"), (None, Some("fe80::1".to_string())));
    }

    /// An address outside every embedding prefix carries no IPv4 address, although its last 32
    /// bits spell one.
    #[test]
    fn an_unrecognized_encoding_carries_no_ipv4_address() {
        for literal in [
            "64:ff9c::a9fe:a9fe",
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b::1:a9fe:a9fe",
            "::fffe:0:a9fe:a9fe",
            "::ffff:1:a9fe:a9fe",
        ] {
            assert_eq!(
                spellings(literal),
                (None, Some(literal.to_string())),
                "{literal} embeds no address"
            );
        }
    }

    #[test]
    fn unspecified_and_loopback_carry_no_ipv4_address() {
        assert_eq!(spellings("::"), (None, Some("::".to_string())));
        assert_eq!(spellings("::1"), (None, Some("::1".to_string())));
    }

    /// Both attributes reach a decision through one function, so a request leg and an outcome leg
    /// cannot carry different sets.
    #[test]
    fn only_the_attributes_an_address_carries_are_populated() {
        assert_eq!(
            attributes(parse("64:ff9b::a9fe:a9fe")),
            vec![
                ("ip4", "169.254.169.254".to_string()),
                ("ip6", "64:ff9b::a9fe:a9fe".to_string()),
            ]
        );
        assert_eq!(
            attributes(parse("203.0.113.7")),
            vec![("ip4", "203.0.113.7".to_string())]
        );
        assert_eq!(
            attributes(parse("fd00:ec2::254")),
            vec![("ip6", "fd00:ec2::254".to_string())]
        );
    }
}
