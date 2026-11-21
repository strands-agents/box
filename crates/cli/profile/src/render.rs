use crate::host::Host;
use crate::tool::Found;

/// The signal groups the one telemetry target takes.
///
/// `metrics` is absent: an agent's metrics reach every target unnamed. `logs` selects Box Core's
/// unmatched MCP routing records, and an agent's log records reach every target unnamed.
pub(crate) const SIGNAL_GROUPS: [&str; 4] = ["deny", "permit", "trace", "logs"];

// Bare tool hosts receive connection permission on the standard HTTPS port.
const DEFAULT_TOOL_HOST_PORT: u16 = 443;

/// Policy rules that `box` writes, one per line, and the `@id` of each.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    lines: Vec<String>,
    pub(crate) ids: Vec<String>,
}

impl Rules {
    /// Add the rule `rule` with the `@id` `id`.
    pub(crate) fn add(&mut self, id: &str, rule: &str) {
        self.lines.push(format!("@id({id:?}) {rule}"));
        self.ids.push(id.to_string());
    }

    /// Add the rule `rule` with the `@id` `id` and the `@description` `description`, which a denial
    /// prints after the rule's id.
    pub(crate) fn add_described(&mut self, id: &str, description: &str, rule: &str) {
        self.lines.push(format!(
            "@id({id:?}) @description({}) {rule}",
            literal(description)
        ));
        self.ids.push(id.to_string());
    }

    /// Add an empty line.
    pub(crate) fn gap(&mut self) {
        self.lines.push(String::new());
    }

    /// The rules as policy text, each line ended.
    pub(crate) fn text(&self) -> String {
        if self.lines.is_empty() {
            return String::new();
        }
        self.lines.join("\n") + "\n"
    }
}

/// The permits that start each tool, decide each action of its grammar, and reach each host its
/// packages come from.
pub fn tool_rules(tools: &[Found], host: &Host) -> Rules {
    let mut rules = Rules::default();
    for tool in tools {
        rules.add(
            &format!("spawn_{}", tool.name),
            &format!(
                r#"permit (principal, action == Box::Action::"shell:spawn", resource) when {{ context.input.program_path == {path} && context.input.program == {program} }};"#,
                path = literal(&host.tilde(&tool.identity)),
                program = literal(&tool.program),
            ),
        );
        if let Some(namespace) = &tool.grammar {
            rules.add(
                &format!("tool_{}", tool.name),
                &format!(
                    r#"permit (principal, action in [{namespace}::Action::"*", {namespace}::Action::"unmodeled"], resource);"#
                ),
            );
        }
    }
    let mut hosts: Vec<&str> = Vec::new();
    for host in tools.iter().flat_map(|tool| &tool.hosts) {
        if !hosts.contains(&host.as_str()) {
            hosts.push(host);
        }
    }
    if !hosts.is_empty() {
        let condition = any_of(
            &hosts
                .iter()
                .map(|host| format!("context.input.host == {}", literal(host)))
                .collect::<Vec<_>>(),
        );
        rules.gap();
        rules.add(
            "package_hosts_connect",
            &format!(
                r#"permit (principal, action == Box::Action::"net:connect", resource) when {{ ({condition}) && context.input.port == {DEFAULT_TOOL_HOST_PORT} }};"#
            ),
        );
        rules.add(
            "package_hosts_request",
            &format!(
                r#"permit (principal, action == Box::Action::"http:request", resource) when {{ {condition} }};"#
            ),
        );
    }
    rules
}

/// The most terms that one `||` chain in a written rule joins.
const TERMS_PER_CHAIN: usize = 8;

/// `terms` joined with `||`, in groups of at most `TERMS_PER_CHAIN` terms in parentheses.
pub(crate) fn any_of(terms: &[String]) -> String {
    if terms.len() <= TERMS_PER_CHAIN {
        return terms.join(" || ");
    }
    let groups: Vec<String> = terms
        .chunks(TERMS_PER_CHAIN)
        .map(|group| format!("({})", group.join(" || ")))
        .collect();
    any_of(&groups)
}

/// `text` as a quoted policy string literal.
pub(crate) fn literal(text: &str) -> String {
    quoted(text, false)
}

/// A `like` pattern matching every path strictly below `directory`, with `*` in it literal.
pub(crate) fn pattern_below(directory: &str) -> String {
    let mut quoted = quoted(directory, true);
    quoted.insert_str(quoted.len() - 1, "/*");
    quoted
}

fn quoted(text: &str, pattern: bool) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '*' if pattern => out.push_str("\\*"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => out.push_str(&format!("\\u{{{:x}}}", other as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
