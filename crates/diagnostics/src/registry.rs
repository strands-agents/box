//! Every message code: one row per kind of message, and the one place a code is numbered.
//!
//! | Area | Owns |
//! |---|---|
//! | `P` | policy: loading, decisions, history |
//! | `T` | telemetry |
//! | `B` | the box's trusted process |
//! | `H` | the helper programs, whose messages the agent reads |
//!
//! Two digits name a block of one kind of thing; two more number a code within it. The docs page
//! `docs/user/message-codes.md` explains each code and what to do about it.

use crate::Severity;

macro_rules! codes {
    ($($code:ident => $severity:ident, $label:literal, $meaning:literal;)+) => {
        /// One kind of message.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Code {
            $(
                #[doc = $meaning]
                $code,
            )+
        }

        impl Code {
            /// Every code, in order.
            pub const ALL: &'static [Self] = &[$(Self::$code),+];

            /// The code as a line spells it.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$code => stringify!($code),)+
                }
            }

            /// The severity every message of this kind has.
            pub const fn severity(self) -> Severity {
                match self {
                    $(Self::$code => codes!(@severity $severity),)+
                }
            }

            /// A plural noun phrase for a count of these messages.
            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$code => $label,)+
                }
            }

            /// One sentence on what a message of this kind means.
            pub const fn meaning(self) -> &'static str {
                match self {
                    $(Self::$code => $meaning,)+
                }
            }
        }
    };
    (@severity error) => { Severity::Error };
    (@severity warning) => { Severity::Warning };
    (@severity note) => { Severity::Note };
}

codes! {
    // Policy: loading.
    P0101 => warning, "home patterns after a wildcard", "A `like` pattern names the operator's home after a wildcard, so the load cannot judge what it reaches.";
    P0102 => warning, "programs spelled as a path", "A `program` literal holds a path separator, so it matches only that spelling of the program.";
    P0103 => warning, "temporal permits that may be inert", "A permit's temporal clause sits beside another permit for the same principal and action, so its budget may never apply.";
    // Policy: decisions.
    P0201 => warning, "policy evaluation failures", "A rule errored while it decided a request, so the request was denied.";
    P0202 => warning, "requests policy could not check", "Policy could not check a request, so it was denied as an internal fault.";
    // Policy: history.
    P0301 => warning, "unrecorded policy outcomes", "Outcomes that later decisions depend on were not recorded in the policy history.";
    P0302 => warning, "policy history flush failures", "The policy history was not written to disk when it was due.";

    // Telemetry.
    T0101 => warning, "lost telemetry records", "Telemetry records were lost before they reached a target.";
    T0102 => warning, "telemetry export failures", "One export of telemetry records to a target failed.";
    T0103 => error, "telemetry target failures", "A telemetry target could not be opened, so the box did not start.";

    // Box: refusals at startup.
    B0101 => error, "invalid configurations", "The configuration is not valid, so the box did not start.";
    B0102 => error, "refused filesystem grants", "A filesystem grant is refused, so the box did not start.";
    B0103 => error, "refused policies", "The policy could not be read, checked, or installed, so the box did not start.";
    B0104 => error, "credential setup failures", "A credential or secret source could not be set up, so the box did not start.";
    B0105 => error, "box directories holding another box", "The box directory holds another box, a newer record, or history that disagrees with its record.";
    B0106 => error, "boxes already running", "The box is already running, or this process already ran a box.";
    B0107 => error, "incomplete installations", "A program the box needs is missing from its installation, or cannot be trusted.";
    B0108 => error, "hosts that cannot contain a box", "This host cannot harden the box's process or build its sandboxes, so the box did not start.";
    B0109 => error, "MCP servers that could not be prepared", "A declared MCP server could not be prepared, so the box did not start.";
    B0110 => error, "egress gateway failures", "The egress gateway or its relay failed, so the box did not start or stopped.";
    B0111 => error, "broker socket failures", "The socket the box's interpreters reach could not be served.";
    // Box: startup disclosures.
    B0201 => note, "filesystem grant disclosures", "A process reaches these paths directly, with no policy decision.";
    B0202 => note, "exposed credential stores", "A process's filesystem grant reaches a credential store.";
    B0203 => note, "secret source disclosures", "A secret source runs a host program outside every sandbox, or skips a path it protects.";
    B0204 => note, "host certificate disclosures", "The egress gateway also trusts root certificates from this host's trust store.";
    B0205 => warning, "host trust store failures", "The host's trust store could not be read, so the gateway trusts only its own roots.";
    B0206 => note, "file watching disclosures", "File watching may disclose names and event metadata outside the process's grants.";
    B0207 => note, "tools left out", "A tool's program is not installed, so the box left the tool out of this run.";
    B0208 => note, "bare name disclosures", "How a bare program name in the Shell resolves differs from what a table suggests.";
    B0209 => note, "clear-text MCP telemetry disclosures", "A telemetry target receives each MCP tool call's arguments and output in clear text.";
    // Box: lifecycle.
    B0301 => note, "box state changes", "The box was created, opened, or refreshed.";
    B0302 => note, "workload starts", "The box starts its workload.";
    // Box: MCP at run time.
    B0401 => warning, "unread MCP catalogs", "A server's tool catalog could not be read, so its calls are decided without per-tool actions.";
    B0402 => warning, "unloaded MCP tool rules", "A server's per-tool policy rules did not load, so they decide none of its calls.";
    // Box: egress and fetch.
    B0501 => warning, "failed upstream requests", "A request through the egress gateway to an upstream failed.";
    B0502 => warning, "fetches with no egress route", "A Monty fetch was refused because no egress route reaches it.";
    B0503 => warning, "fetches refused by the address floor", "A Monty fetch was refused because it names a private or local address.";
    // Box: credentials at run time.
    B0601 => warning, "secret source failures", "A secret source program failed to read a secret.";
    B0602 => warning, "credential conditions", "A credential capability reported a condition that does not stop the run.";
    // Box: ingress.
    B0701 => note, "ingress relays", "A host listener is relayed to a port of the agent.";
    B0702 => warning, "ingress accept failures", "Accepting a caller on a host listener failed, and the relay retries.";
    B0703 => warning, "unanswered ingress ports", "The agent's port did not answer a relayed caller.";
    // Box: native filesystem policy.
    B0801 => note, "native filesystem limits", "This host's kernel limits what native filesystem policy can intercept.";
    B0802 => warning, "refused native filesystem requests", "Native filesystem policy refused a request it cannot decide.";
    B0803 => warning, "failed native filesystem requests", "A native filesystem request was denied because deciding it failed.";
    B0804 => note, "native filesystem enforcement starts", "Native filesystem enforcement is ready.";
    // Box: sandbox supervisors.
    B0901 => error, "namespace reaper failures", "The namespace reaper failed, so it stopped the sandbox.";
    B0902 => error, "filesystem query supervisor failures", "The filesystem query supervisor failed.";
    // Box: shutdown.
    B1001 => warning, "shutdown failures", "Part of the box's shutdown failed.";
    // Box: broker connections.
    B1101 => warning, "rejected broker clients", "The broker rejected a client of its socket.";
    B1102 => warning, "failed broker clients", "Serving a client of the broker's socket failed.";

    // Helper programs, read by the agent.
    H0101 => error, "protocol version mismatches", "The alias and the box speak different protocol versions.";
    H0102 => error, "malformed broker frames", "The box refused a malformed frame from the alias.";
    H0103 => error, "calls over budget", "A call exceeded a size or output budget, such as the stdin limit.";
    H0104 => error, "calls refused for flow control", "A call was refused because the program was busy or its input was not read in time.";
    H0105 => error, "calls past their deadline", "A call outlived its deadline.";
    H0201 => error, "alias input failures", "The alias could not read its input.";
    H0202 => error, "alias start failures", "The alias could not start or reach the box.";
    H0301 => error, "ordinary programs not found", "No ordinary program by that name is on the agent's `PATH`.";
    H0302 => error, "ordinary programs that could not run", "The ordinary program could not be run.";
    H0401 => error, "sandbox setup failures", "Applying a sandbox failed before its program started.";
    H0402 => warning, "containment warnings", "A sandbox's configuration carries a limit the operator should know.";
}

impl Code {
    /// The code a line spells, if it is one.
    pub fn named(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|code| code.as_str() == text)
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_code_is_in_its_area_and_block_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for code in Code::ALL {
            let text = code.as_str();
            assert!(seen.insert(text), "{text} is declared twice");
            let (area, digits) = text.split_at(1);
            assert!(matches!(area, "P" | "T" | "B" | "H"), "{text}");
            assert!(
                digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_digit()),
                "{text}"
            );
            assert!(
                !digits.ends_with("00"),
                "{text} numbers a block, not a code"
            );
            assert_eq!(Code::named(text), Some(*code));
            assert!(code.meaning().ends_with('.'), "{text}");
        }
    }

    #[test]
    fn each_code_is_used_by_box_core() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut sources = String::new();
        let mut pending = vec![crates.clone()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if path.is_dir() {
                    if !matches!(
                        name.as_str(),
                        "cli" | "diagnostics" | "box-bench" | "target"
                    ) {
                        pending.push(path);
                    }
                } else if name.ends_with(".rs") {
                    sources.push_str(&std::fs::read_to_string(&path).unwrap());
                }
            }
        }
        for code in Code::ALL {
            assert!(
                sources.contains(code.as_str()),
                "{code} is declared and no Box Core source uses it"
            );
        }
    }

    #[test]
    fn the_docs_page_lists_each_code_as_the_registry_does() {
        let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/user/message-codes.md");
        let page = std::fs::read_to_string(page).unwrap();
        let listed: Vec<(&str, &str)> = page
            .lines()
            .filter_map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                let code = cells.get(1)?.strip_prefix('`')?.strip_suffix('`')?;
                Code::named(code)?;
                Some((code, *cells.get(2)?))
            })
            .collect();
        let expected: Vec<(&str, &str)> = Code::ALL
            .iter()
            .map(|code| (code.as_str(), code.severity().as_str()))
            .collect();
        assert_eq!(listed, expected, "docs/user/message-codes.md");
    }
}
