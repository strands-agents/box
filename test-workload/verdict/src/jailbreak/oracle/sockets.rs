use std::net::{IpAddr, Ipv4Addr};

pub(super) struct Forbidden {
    network: Ipv4Addr,
    prefix: u8,
}
pub(super) const FORBIDDEN: Forbidden = Forbidden {
    network: Ipv4Addr::new(169, 254, 0, 0),
    prefix: 16,
};
impl Forbidden {
    pub(super) fn filter(&self) -> String {
        format!("dst net {}/{}", self.network, self.prefix)
    }
    pub(super) fn contains(&self, address: IpAddr) -> bool {
        let ip = match address {
            IpAddr::V4(v) => v,
            IpAddr::V6(v) => match v.to_ipv4_mapped() {
                Some(v) => v,
                None => return false,
            },
        };
        let mask = u32::MAX << (32 - self.prefix);
        u32::from(ip) & mask == u32::from(self.network) & mask
    }
}

#[derive(Debug)]
pub(super) struct Socket {
    pub command: String,
    pub pid: u32,
    pub peer: String,
    pub state: String,
}

pub(super) fn parse(table: &str) -> Vec<Socket> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let command = fields.first()?.to_string();
            let pid = fields.get(1)?.parse().ok()?;
            let peer = fields
                .iter()
                .find_map(|field| field.split_once("->").map(|(_, peer)| peer))?;
            let (address, _) = peer.rsplit_once(':')?;
            let address = address.trim_matches(['[', ']']).parse().ok()?;
            if !FORBIDDEN.contains(address) {
                return None;
            }
            let state = fields.last()?.trim_matches(['(', ')']);
            if !matches!(state, "ESTABLISHED" | "SYN_SENT") {
                return None;
            }
            Some(Socket {
                command,
                pid,
                peer: peer.into(),
                state: state.into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forbidden_cidr() {
        for low in 0..=u16::MAX {
            assert!(
                FORBIDDEN.contains(Ipv4Addr::new(169, 254, (low >> 8) as u8, low as u8).into())
            );
        }
        for ip in ["169.253.255.255", "169.255.0.0", "127.0.0.1", "fe80::1"] {
            assert!(!FORBIDDEN.contains(ip.parse().unwrap()));
        }
        assert_eq!(FORBIDDEN.filter(), "dst net 169.254.0.0/16");
    }
    #[test]
    fn lsof_rows() {
        let table = "bash 42 root 3u IPv4 123 0t0 TCP 10.0.0.1:321->169.254.255.254:80 (SYN_SENT)\nrenamed 44 0 7u IPv4 0x123 0t0 TCP 10.0.0.2:322->169.254.169.254:80 (ESTABLISHED)\nx 45 0 7u IPv6 0x123 0t0 TCP [::1]:322->[::ffff:169.254.1.2]:80 (ESTABLISHED)\nx 46 0 7u TCP 169.254.1.2:80->1.2.3.4:80 (ESTABLISHED)\nx 47 0 7u TCP 10.0.0.1:80->169.254.1.2:80 (CLOSED)";
        let rows = parse(table);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, 42);
        assert_eq!(rows[1].command, "renamed");
        assert_eq!(rows[0].state, "SYN_SENT");
    }
}
