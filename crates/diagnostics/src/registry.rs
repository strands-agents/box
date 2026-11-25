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

use crate::{Severity, Source};

macro_rules! codes {
    ($($code:ident => $source:ident $severity:ident, $label:literal, $meaning:literal;)+) => {
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

            /// The program or part of the box that every message of this kind names as its source.
            pub const fn source(self) -> Source {
                match self {
                    $(Self::$code => codes!(@source $source),)+
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
    (@source strands_box) => { Source::StrandsBox };
    (@source policy) => { Source::Policy };
    (@source telemetry) => { Source::Telemetry };
    (@source alias) => { Source::SockAlias };
    (@source trampoline) => { Source::ContainTrampoline };
    (@severity error) => { Severity::Error };
    (@severity warning) => { Severity::Warning };
    (@severity note) => { Severity::Note };
}

codes! {
    // Policy: loading.
    P0101 => policy warning, "home patterns after a wildcard", "A `like` pattern names the operator's home after a wildcard, so the load cannot judge what it reaches.";
    P0102 => policy warning, "programs spelled as a path", "A `program` literal holds a path separator, so it matches only that spelling of the program.";
    P0103 => policy warning, "temporal permits that may be inert", "A permit's temporal clause sits beside another permit for the same principal and action, so its budget may never apply.";
    // Policy: decisions.
    P0201 => policy warning, "policy evaluation failures", "A rule errored while it decided a request, so the request was denied.";
    P0202 => policy warning, "requests policy could not check", "Policy could not check a request, so it was denied as an internal fault.";
    // Policy: history.
    P0301 => policy warning, "unrecorded policy outcomes", "Outcomes that later decisions depend on were not recorded in the policy history.";
    P0302 => policy warning, "policy history flush failures", "The policy history was not written to disk when it was due.";
    P0303 => policy error, "policy history flush refusals", "The policy history could not be written to disk, so the box stopped.";

    // Telemetry.
    T0101 => telemetry warning, "lost telemetry records", "Telemetry records were lost before they reached a target.";
    T0102 => telemetry warning, "telemetry export failures", "One export of telemetry records to a target failed.";
    T0103 => telemetry error, "telemetry target failures", "A telemetry target could not be opened, so the box did not start.";

    // Box: refusals at startup.
    B0101 => strands_box error, "invalid configurations", "The configuration is not valid, so the box did not start.";
    B0102 => strands_box error, "refused filesystem grants", "A filesystem grant is refused, so the box did not start.";
    B0103 => strands_box error, "refused policies", "The policy could not be read, checked, or installed, so the box did not start.";
    B0104 => strands_box error, "credential setup failures", "A credential or secret source could not be set up, so the box did not start.";
    B0105 => strands_box error, "box directories holding another box", "The box directory holds another box, a newer record, or history that disagrees with its record.";
    B0106 => strands_box error, "boxes already running", "The box is already running, or this process already ran a box.";
    B0107 => strands_box error, "incomplete installations", "A program the box needs is missing from its installation, or cannot be trusted.";
    B0108 => strands_box error, "hosts that cannot contain a box", "This host cannot harden the box's process or build its sandboxes, so the box did not start.";
    B0109 => strands_box error, "MCP servers that could not be prepared", "A declared MCP server could not be prepared, so the box did not start.";
    B0110 => strands_box error, "egress gateway failures", "The egress gateway or its relay failed, so the box did not start or stopped.";
    B0111 => strands_box error, "broker socket failures", "The socket the box's interpreters reach could not be served.";
    B0112 => strands_box error, "refused library callbacks", "The library caller's `on_ready` callback returned an error or changed native filesystem policy from off to on after startup preparation, so the box did not start its workload.";
    B0113 => strands_box error, "secret source failures", "A secret source program failed to read a secret, so the box did not start.";
    // Box: startup disclosures.
    B0201 => strands_box note, "filesystem grant disclosures", "A process reaches these paths directly, with no policy decision.";
    B0202 => strands_box note, "exposed credential stores", "A process's filesystem grant reaches a credential store.";
    B0203 => strands_box note, "secret source disclosures", "A secret source runs a host program outside every sandbox, or skips a path it protects.";
    B0204 => strands_box note, "host certificate disclosures", "The egress gateway also trusts root certificates from this host's trust store.";
    B0205 => strands_box warning, "host trust store failures", "The host's trust store could not be read, so the gateway trusts only its own roots.";
    B0206 => strands_box note, "file watching disclosures", "File watching may disclose names and event metadata outside the process's grants.";
    B0207 => strands_box note, "tools left out", "A tool's program is not installed, so the box left the tool out of this run.";
    B0208 => strands_box note, "bare name disclosures", "How a bare program name in the Shell resolves differs from what a table suggests.";
    B0209 => strands_box note, "clear-text MCP telemetry disclosures", "A telemetry target receives each MCP tool call's arguments and output in clear text.";
    B0210 => strands_box note, "native egress disclosures", "A process connects to the network directly, with no egress gateway, no network policy decision, and no credential injection.";
    B0211 => strands_box note, "native trust disclosures", "Box gives a process with native egress no proxy and no certificate authority, so its client uses its own defaults.";
    B0212 => strands_box warning, "replaceable programs", "A process's write grant reaches the program it runs, so the process can replace that program.";
    B0213 => strands_box note, "log-only mode disclosures", "The policy runs in log-only mode, so each denial is recorded and the action goes ahead.";
    // Box: lifecycle.
    B0301 => strands_box note, "box state changes", "The box was created, opened, or refreshed.";
    B0302 => strands_box note, "workload starts", "The box starts its workload.";
    // Box: MCP at run time.
    B0401 => strands_box warning, "unread MCP catalogs", "A server's tool catalog could not be read, so its calls are decided without per-tool actions.";
    B0402 => strands_box warning, "unloaded MCP tool rules", "A server's per-tool policy rules did not load, so they decide none of its calls.";
    // Box: egress and fetch.
    B0501 => strands_box warning, "failed upstream requests", "A request through the egress gateway to an upstream failed.";
    B0502 => strands_box warning, "fetches with no egress route", "A Monty fetch was refused because no egress route reaches it.";
    B0503 => strands_box warning, "fetches refused by the address floor", "A Monty fetch was refused before it was sent: its URL names a private or local address, or a scheme Box does not fetch.";
    // Box: credentials at run time.
    B0602 => strands_box warning, "credential conditions", "A credential capability reported a condition that does not stop the run.";
    // Box: ingress.
    B0701 => strands_box note, "ingress relays", "A host listener is relayed to a port of the agent.";
    B0702 => strands_box warning, "ingress accept failures", "Accepting a caller on a host listener failed, and the relay retries.";
    B0703 => strands_box warning, "unanswered ingress ports", "The agent's port did not answer a relayed caller.";
    B0704 => strands_box error, "ingress listener failures", "An ingress listener could not be bound or relayed, so the box did not start or stopped.";
    // Box: native filesystem policy.
    B0801 => strands_box note, "native filesystem limits", "This host's kernel limits what native filesystem policy can intercept.";
    B0802 => strands_box warning, "refused native filesystem requests", "Native filesystem policy refused a request it cannot decide.";
    B0803 => strands_box warning, "failed native filesystem requests", "A native filesystem request was denied because deciding it failed.";
    B0804 => strands_box note, "native filesystem enforcement starts", "Native filesystem enforcement is ready.";
    // Box: during and after the run.
    B1001 => strands_box warning, "shutdown failures", "Part of the box's shutdown failed.";
    B1002 => strands_box warning, "discarded messages", "Box held its messages while the workload drew on the terminal, and discarded those past its limit.";
    B1003 => strands_box error, "native enforcement failures during a run", "Native filesystem policy failed after the workload started, or did not stop cleanly, so the box stopped.";
    // Box: broker connections.
    B1101 => strands_box warning, "rejected broker clients", "The broker rejected a client of its socket.";
    B1102 => strands_box warning, "failed broker clients", "Serving a client of the broker's socket failed.";
    // Box: messages to the agent, written into a command's stderr.
    B1201 => strands_box warning, "truncated command input", "A command's stdin was longer than the limit, so the command received only the first part.";
    B1202 => strands_box error, "refused start directories", "A command could not start in the directory it named.";
    B1203 => strands_box error, "call deadlines out of range", "A call's deadline is past this platform's clock range, so the call did not run.";

    // Helper programs, read by the agent.
    H0101 => alias error, "protocol version mismatches", "The alias and the box speak different protocol versions.";
    H0102 => alias error, "malformed broker frames", "The box refused a malformed frame from the alias.";
    H0103 => alias error, "calls over budget", "A call exceeded a size or output budget, such as the stdin limit.";
    H0104 => alias error, "calls refused for flow control", "A call was refused because the program was busy or its input was not read in time.";
    H0105 => alias error, "calls past their deadline", "A call outlived its deadline.";
    H0106 => alias error, "other refused calls", "The box refused the call for a reason the text names, such as an undeclared MCP command or a program that failed to start.";
    H0201 => alias error, "alias input failures", "The alias could not read its input.";
    H0202 => alias error, "alias start failures", "The alias could not start or reach the box.";
    H0203 => alias error, "alias usage mistakes", "The alias was run with arguments, input, or a working directory it cannot use.";
    H0301 => alias error, "ordinary programs not found", "No ordinary program by that name is on the agent's `PATH`.";
    H0302 => alias error, "ordinary programs that could not run", "The ordinary program could not be run.";
    H0401 => trampoline error, "sandbox setup failures", "Applying a sandbox failed before its program started.";
    H0402 => trampoline warning, "containment warnings", "A sandbox's configuration carries a limit the operator should know.";
    // Helpers: the sandbox supervisors the trampoline starts.
    H0501 => trampoline error, "namespace reaper failures", "The namespace reaper failed, so it stopped the sandbox.";
    H0502 => trampoline error, "filesystem query supervisor failures", "The filesystem query supervisor failed.";
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
            let sources: &[Source] = match area {
                "P" => &[Source::Policy],
                "T" => &[Source::Telemetry],
                "B" => &[Source::StrandsBox],
                _ => &[Source::SockAlias, Source::ContainTrampoline],
            };
            assert!(
                sources.contains(&code.source()),
                "{text} prints under {}",
                code.source()
            );
            assert!(code.meaning().ends_with('.'), "{text}");
        }
    }

    /// The production code of one source file: no unit-test module, no comment line, and runs
    /// of whitespace joined, so a code that only a test or a comment names is not a use.
    fn production(text: &str) -> String {
        let mut text = text.to_string();
        // Drop each `#[cfg(test)] mod <name> { ... }`, whatever the module is called.
        while let Some(start) = text.find("#[cfg(test)]") {
            let rest = text[start + "#[cfg(test)]".len()..].trim_start();
            if !rest.starts_with("mod ") || !rest.contains('{') {
                text.replace_range(start..start + "#[cfg(test)]".len(), "");
                continue;
            }
            let open = text.len() - rest.len() + rest.find('{').unwrap();
            let mut depth = 0;
            let mut end = text.len();
            for (offset, byte) in text.bytes().enumerate().skip(open) {
                match byte {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = offset + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            text.replace_range(start..end, "");
        }
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        lines
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("( ", "(")
    }

    /// Whether `sources` names `code` in a `Code::` path or as a `diag!` argument.
    fn uses(sources: &str, code: &str) -> bool {
        let writer = sources.match_indices("diag!(into ").any(|(at, form)| {
            let call = &sources[at + form.len()..];
            call.split_once(", ")
                .is_some_and(|(_, rest)| rest.starts_with(&format!("{code},")))
        });
        writer
            || [
                format!("Code::{code}"),
                format!("diag!({code},"),
                format!("diag!(text {code},"),
            ]
            .iter()
            .any(|shape| sources.contains(shape.as_str()))
    }

    #[test]
    fn a_use_counts_only_in_production_code() {
        let source = "fn f() { diag!(into out, B0201, \"x\"); }\n#[cfg(test)]\nmod probes {\n    fn g() { diag!(B0202, \"y\"); }\n}\nconst NOTE: &str = \"see, B0203, here\";";
        let production = production(source);
        assert!(uses(&production, "B0201"), "{production}");
        assert!(
            !uses(&production, "B0202"),
            "a test module of any name is not a use"
        );
        assert!(!uses(&production, "B0203"), "a code in prose is not a use");
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
                        "cli" | "diagnostics" | "box-bench" | "target" | "tests" | "examples"
                    ) {
                        pending.push(path);
                    }
                } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
                    sources.push_str(&production(&std::fs::read_to_string(&path).unwrap()));
                    sources.push(' ');
                }
            }
        }
        for code in Code::ALL {
            let code = code.as_str();
            let used = uses(&sources, code);
            assert!(
                used,
                "{code} is declared and no Box Core production code uses it"
            );
        }
    }

    #[test]
    fn the_docs_page_lists_each_code_as_the_registry_does() {
        let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/user/message-codes.md");
        let page = std::fs::read_to_string(page).unwrap();
        let listed: Vec<(&str, &str, &str)> = page
            .lines()
            .filter_map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                let code = cells.get(1)?.strip_prefix('`')?.strip_suffix('`')?;
                let shaped = code.len() == 5
                    && code.starts_with(['P', 'T', 'B', 'H'])
                    && code[1..].bytes().all(|byte| byte.is_ascii_digit());
                if !shaped {
                    return None;
                }
                assert!(
                    Code::named(code).is_some(),
                    "{code} is on the page and not in the registry"
                );
                assert!(
                    cells.get(4).is_some_and(|todo| !todo.is_empty()),
                    "{code} has no \"What to do\" on the page"
                );
                Some((code, *cells.get(2)?, *cells.get(3)?))
            })
            .collect();
        let expected: Vec<(&str, &str, &str)> = Code::ALL
            .iter()
            .map(|code| (code.as_str(), code.severity().as_str(), code.meaning()))
            .collect();
        assert_eq!(listed, expected, "docs/user/message-codes.md");
    }
}
