//! The one spelling of a pinned destination address that `context.input.ip` carries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `ip` as a rule reads it: an IPv6 address that carries an IPv4 address becomes that IPv4
/// address, and an IPv6 address uses its compressed lowercase form.
pub(crate) fn canonical(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6).map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
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

    fn spelled(literal: &str) -> String {
        canonical(literal.parse().expect("an address"))
    }

    #[test]
    fn every_ipv6_encoding_of_an_ipv4_address_is_that_address() {
        for (encoding, literal) in [
            ("IPv4", "169.254.169.254"),
            ("IPv4-mapped", "::ffff:169.254.169.254"),
            ("IPv4-mapped, hex", "::ffff:a9fe:a9fe"),
            ("IPv4-compatible", "::169.254.169.254"),
            ("6to4", "2002:a9fe:a9fe::"),
            ("Teredo", "2001:0:0:0:0:0:5601:5601"),
            ("NAT64 well-known prefix", "64:ff9b::169.254.169.254"),
            ("NAT64 well-known prefix, hex", "64:ff9b::a9fe:a9fe"),
            ("IPv4-translated", "::ffff:0:169.254.169.254"),
            ("IPv4-translated, hex", "::ffff:0:a9fe:a9fe"),
        ] {
            assert_eq!(
                spelled(literal),
                "169.254.169.254",
                "{encoding} ({literal})"
            );
        }
    }

    #[test]
    fn ipv6_is_compressed_and_lowercase() {
        assert_eq!(
            spelled("FD00:00EC:0000:0000:0000:0000:0000:0254"),
            "fd00:ec::254"
        );
        assert_eq!(spelled("fd00:ec2:0::254"), "fd00:ec2::254");
        assert_eq!(spelled("FE80::1"), "fe80::1");
        // An address outside every embedding prefix keeps its IPv6 form, although its last 32
        // bits spell an IPv4 address.
        for literal in [
            "64:ff9c::a9fe:a9fe",
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b::1:a9fe:a9fe",
            "::fffe:0:a9fe:a9fe",
            "::ffff:1:a9fe:a9fe",
        ] {
            assert_eq!(spelled(literal), literal, "{literal} embeds no address");
        }
    }

    #[test]
    fn unspecified_and_loopback_stay_ipv6() {
        assert_eq!(spelled("::"), "::");
        assert_eq!(spelled("::1"), "::1");
    }
}
