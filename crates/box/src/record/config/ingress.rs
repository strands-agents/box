//! `box.toml`'s `[[agent.ingress]]` list: where callers reach the agent.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// One `[[agent.ingress]]` entry: the box listens on `listen`, and relays each connection to the
/// agent's `workload_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ingress {
    /// The address the box binds in its own network, such as `"0.0.0.0:8080"`.
    pub(crate) listen: String,
    /// The port the agent listens on in its own network.
    pub(crate) workload_port: u16,
}

/// The most entries one `[[agent.ingress]]` list may hold.
pub(crate) const MAX_LISTENERS: usize = 5;

/// Refuse a list no run could honor: each entry, and the rules that span entries.
pub(crate) fn validate_all(entries: &[Ingress], owner: &str) -> Result<(), ConfigError> {
    let refuse = |reason: String| ConfigError::Process {
        table: format!("[{}.ingress]]", owner.trim_end_matches(']')),
        reason,
    };
    if entries.len() > MAX_LISTENERS {
        return Err(refuse(format!(
            "{} entries declared; an agent may declare at most {MAX_LISTENERS}",
            entries.len()
        )));
    }
    for entry in entries {
        entry.validate(owner)?;
    }
    for (index, entry) in entries.iter().enumerate() {
        let listen = entry.listen_address().map(|address| address.port());
        for other in &entries[index + 1..] {
            if listen.is_some() && listen == other.listen_address().map(|address| address.port()) {
                return Err(refuse(format!(
                    "two entries listen on port {}; each entry needs its own `listen` port",
                    listen.unwrap_or_default()
                )));
            }
            if entry.workload_port == other.workload_port {
                return Err(refuse(format!(
                    "two entries relay to `workload_port` {}; each entry needs its own port",
                    entry.workload_port
                )));
            }
        }
        if cfg!(target_os = "macos")
            && let Some(port) = listen
            && let Some(other) = entries
                .iter()
                .find(|other| other.workload_port == port && !std::ptr::eq(*other, entry))
        {
            return Err(refuse(format!(
                "`listen` port {port} is also the `workload_port` of the entry listening on {:?}; \
                 on macOS the agent shares the host's network, so the box and the agent cannot \
                 listen on one port",
                other.listen
            )));
        }
    }
    Ok(())
}

impl Ingress {
    /// The address the box binds, or `None` when `listen` is not an IP address and port.
    pub(crate) fn listen_address(&self) -> Option<std::net::SocketAddr> {
        self.listen.parse().ok()
    }

    /// Refuse an `ingress` no run could honor, naming the table `owner` that declares it.
    pub(crate) fn validate(&self, owner: &str) -> Result<(), ConfigError> {
        let refuse = |reason: String| ConfigError::Process {
            table: format!("[{}.ingress]]", owner.trim_end_matches(']')),
            reason,
        };
        match self.listen_address() {
            None => {
                return Err(refuse(format!(
                    "`listen` {:?} is not an IP address and port, such as \"0.0.0.0:8080\"",
                    self.listen
                )));
            }
            Some(address) if address.port() == 0 => {
                return Err(refuse("the `listen` port must not be 0".into()));
            }
            Some(_) => {}
        }
        if self.workload_port == 0 {
            return Err(refuse("`workload_port` must not be 0".into()));
        }
        if cfg!(target_os = "macos")
            && self.listen_address().map(|address| address.port()) == Some(self.workload_port)
        {
            return Err(refuse(format!(
                "`listen` and `workload_port` are both {}; on macOS the agent shares the host's \
                 network, so the box and the agent cannot listen on one port",
                self.workload_port
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ingress, MAX_LISTENERS, validate_all};

    fn ingress(listen: &str, workload_port: u16) -> Ingress {
        Ingress {
            listen: listen.into(),
            workload_port,
        }
    }

    fn refusal(ingress: &Ingress) -> String {
        ingress
            .validate("[agent]")
            .expect_err("the ingress must be refused")
            .to_string()
    }

    #[test]
    fn a_refusal_names_the_ingress_table() {
        assert!(refusal(&ingress("0.0.0.0:0", 8081)).contains("[[agent.ingress]]"));
    }

    #[test]
    fn a_listen_value_that_is_not_an_address_and_port_is_refused() {
        for listen in ["localhost:8080", "0.0.0.0", "8080", ""] {
            assert!(
                refusal(&ingress(listen, 8081)).contains("is not an IP address and port"),
                "{listen:?} must be refused"
            );
        }
    }

    #[test]
    fn a_zero_port_is_refused() {
        assert!(refusal(&ingress("0.0.0.0:0", 8081)).contains("`listen` port"));
        assert!(refusal(&ingress("0.0.0.0:8080", 0)).contains("`workload_port`"));
    }

    #[test]
    fn a_listen_port_and_a_different_workload_port_are_accepted() {
        ingress("127.0.0.1:8080", 8081)
            .validate("[agent]")
            .expect("the ingress is accepted");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn one_port_for_listen_and_workload_port_is_refused_on_macos() {
        assert!(refusal(&ingress("127.0.0.1:8080", 8080)).contains("cannot listen on one port"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_port_for_listen_and_workload_port_is_accepted_on_linux() {
        ingress("0.0.0.0:8080", 8080)
            .validate("[agent]")
            .expect("the agent's port is in its own network");
    }

    fn list_refusal(entries: &[Ingress]) -> String {
        validate_all(entries, "[agent]")
            .expect_err("the list must be refused")
            .to_string()
    }

    #[test]
    fn several_entries_on_distinct_ports_are_accepted() {
        let entries = [
            ingress("0.0.0.0:8080", 18080),
            ingress("0.0.0.0:8000", 18000),
            ingress("0.0.0.0:9000", 19000),
        ];
        validate_all(&entries, "[agent]").expect("three listeners on their own ports are accepted");
    }

    #[test]
    fn more_entries_than_the_limit_are_refused() {
        let entries: Vec<Ingress> = (0..=MAX_LISTENERS as u16)
            .map(|index| ingress(&format!("0.0.0.0:{}", 8080 + index), 18080 + index))
            .collect();
        assert!(list_refusal(&entries).contains("at most 5"));
        validate_all(&entries[..MAX_LISTENERS], "[agent]").expect("five listeners are accepted");
    }

    #[test]
    fn two_entries_on_one_listen_port_are_refused() {
        let entries = [
            ingress("0.0.0.0:8080", 18080),
            ingress("127.0.0.1:8080", 18081),
        ];
        assert!(list_refusal(&entries).contains("own `listen` port"));
    }

    #[test]
    fn two_entries_on_one_workload_port_are_refused() {
        let entries = [
            ingress("0.0.0.0:8080", 18080),
            ingress("0.0.0.0:8081", 18080),
        ];
        assert!(list_refusal(&entries).contains("own port"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_listen_port_that_is_another_entrys_workload_port_is_refused_on_macos() {
        let entries = [ingress("0.0.0.0:8000", 8080), ingress("0.0.0.0:8080", 8000)];
        assert!(list_refusal(&entries).contains("cannot listen on one port"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn each_port_mapped_to_itself_is_accepted_on_linux() {
        let entries = [ingress("0.0.0.0:8080", 8080), ingress("0.0.0.0:8000", 8000)];
        validate_all(&entries, "[agent]").expect("the agent's ports are in its own network");
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let parsed = toml::from_str::<Ingress>(
            "listen = \"0.0.0.0:8080\"\nworkload_port = 8081\nport = 1\n",
        );
        assert!(
            parsed.is_err(),
            "deny_unknown_fields must reject an unknown key"
        );
    }
}
