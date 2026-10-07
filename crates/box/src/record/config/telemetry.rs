//! `box.toml`'s `[telemetry.<label>]` declarations: where a box's records go.
//!
//! A declared target REPLACES the box's default destination, so this module owns both halves — what
//! an operator may write, and the collector request a run builds from what was stored.
//!
//! An absent `include` means every signal, so a target receives the harness's own spans, logs and
//! metrics without naming one. The five words below are how an operator NARROWS that.
//!
//! The `telemetry` crate's own items are imported by name rather than qualified, because this module
//! shares its spelling and `telemetry::Signal` would read as `self::Signal`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use telemetry::{Signal, Target, TargetKind, TargetSecret, TelemetryConfig};

use crate::error::{BoxError, ConfigError};
// The `[[egress]]` vocabulary owns these: a telemetry target's secret is a credential,
// and it follows the same header convention.
use super::{BEARER_PREFIX, DEFAULT_HEADER, ENV_SCHEME};

/// Refuse a file destination the workload could truncate.
///
/// The test is `box_directory` itself, because a caller selects that path and no directory above it
/// belongs to Box. Both spellings of each side are compared, because a symlink laundering the
/// authored path resolves only through its deepest existing ancestor.
fn refuse_a_workload_reachable_destination(
    expanded: &str,
    box_directory: &Path,
) -> Result<(), String> {
    let path = Path::new(expanded);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{expanded:?} carries a `..` component; write the path it names, so the destination \
             this box opens is the one you read"
        ));
    }
    let roots = [
        box_directory.to_path_buf(),
        crate::record::layout::canonical(box_directory),
    ];
    let spellings = [
        path.to_path_buf(),
        crate::record::layout::resolved_to_its_deepest_existing_ancestor(path),
    ];
    for root in &roots {
        let private = root.join(crate::record::layout::PRIVATE_DIRECTORY);
        for spelling in &spellings {
            if spelling.starts_with(root) && !spelling.starts_with(&private) {
                return Err(format!(
                    "{expanded:?} is inside the box directory {} but outside its private tree, \
                     where a process could truncate it; name a destination under `private/`, or \
                     outside the box, or declare no target and take the default",
                    root.display()
                ));
            }
        }
    }
    Ok(())
}

/// A destination with a leading `~/` replaced by the operator's home.
fn expanded_home_path(destination: &str, operator_home: Option<&Path>) -> Option<String> {
    let Some(relative) = destination
        .strip_prefix("~/")
        .or_else(|| destination.strip_prefix("~").filter(|rest| rest.is_empty()))
    else {
        return Some(destination.to_string());
    };
    let home = operator_home?;
    Some(home.join(relative).to_string_lossy().into_owned())
}

/// The spelling an operator may use beside the credential vocabulary's own.
const TELEMETRY_ALIAS_SCHEME: &str = "secret://";

/// One word an operator writes in `include`, and the signals it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignalGroup {
    /// Every effective denial.
    Deny,
    /// Every effective permit.
    Permit,
    /// The agent's own spans, and this box's control-plane operations.
    Trace,
    /// The agent's own log records.
    Logs,
    /// The agent's own metrics.
    Metrics,
}

impl SignalGroup {
    /// The signals this word names.
    fn signals(self) -> Vec<Signal> {
        match self {
            Self::Deny => vec![Signal::PolicyDenied],
            Self::Permit => vec![Signal::PolicyPermitted],
            Self::Trace => vec![Signal::AgentTrace, Signal::ControlPlane],
            Self::Logs => vec![Signal::AgentLogs],
            Self::Metrics => vec![Signal::AgentMetrics],
        }
    }

    /// Every word an operator may write, for a refusal that lists them.
    fn every() -> [Self; 5] {
        [
            Self::Deny,
            Self::Permit,
            Self::Trace,
            Self::Logs,
            Self::Metrics,
        ]
    }

    /// The `box.toml` spelling.
    fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Permit => "permit",
            Self::Trace => "trace",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }
}

/// The signals an `include` list names, in a deterministic order.
///
/// No two words share a signal, so `checked` refusing a repeated word is what keeps this free of
/// duplicates.
fn signals_for(include: &[SignalGroup]) -> Vec<Signal> {
    let mut signals: Vec<Signal> = include.iter().flat_map(|group| group.signals()).collect();
    signals.sort_unstable();
    signals
}

/// One `[telemetry.<label>]`: where records go, and how much of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetryEntry {
    /// Which exporter this target selects. Serde refuses a spelling that is not one.
    pub(crate) kind: TargetKind,

    /// Where this target sends records.
    pub(crate) destination: String,

    /// Which records reach this target. Serde refuses a spelling that is not one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) include: Option<Vec<SignalGroup>>,

    /// The secret the box attaches on the way out, and the header carrying it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<TelemetrySecret>,
}

/// Which secret a telemetry target attaches, and under which header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TelemetrySecret {
    /// The secret to attach, as a URI: `env://NAME` or `secret://NAME`.
    #[serde(rename = "ref")]
    pub(crate) reference: String,

    /// The header to attach it under. Defaults to `Authorization` with a `Bearer ` prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) header: Option<String>,
}

/// A telemetry secret reference, as the credential vocabulary spells it.
fn telemetry_secret_uri(reference: &str) -> Result<String, String> {
    let reference = reference.trim();
    if let Some(name) = reference.strip_prefix(TELEMETRY_ALIAS_SCHEME) {
        if name.is_empty() {
            return Err(format!(
                "the {TELEMETRY_ALIAS_SCHEME} reference names no variable"
            ));
        }
        return Ok(format!("{ENV_SCHEME}{name}"));
    }
    if reference.starts_with(ENV_SCHEME) {
        return Ok(reference.to_string());
    }
    Err(format!(
        "`secret.ref` names no scheme this box reads; write `{ENV_SCHEME}NAME` or \
         `{TELEMETRY_ALIAS_SCHEME}NAME`, never the value itself. The value is deliberately not \
         echoed here, in case it is one"
    ))
}

/// The refusal a declared target carries, naming the target the operator keyed it under.
fn refuse(name: &str, reason: String) -> ConfigError {
    ConfigError::Telemetry {
        name: name.to_string(),
        reason,
    }
}

/// One declared target as the collector's own value.
fn target_for(
    entry: &TelemetryEntry,
    home: Option<&Path>,
    box_directory: &Path,
    secret: Option<TargetSecret>,
) -> Result<Target, String> {
    // `~/…` is expanded here and nowhere else, so one answer decides which file a relative-looking
    // destination names. Absolute after this, which is what the collector requires of a file target.
    let destination = match entry.kind {
        TargetKind::File => {
            let expanded = expanded_home_path(entry.destination.trim(), home).ok_or_else(|| {
                "a `~/`-relative destination needs the operator's home, which this box cannot \
                 resolve"
                    .to_string()
            })?;
            refuse_a_workload_reachable_destination(&expanded, box_directory)?;
            expanded
        }
        _ => entry.destination.trim().to_string(),
    };

    let mut target = Target::new(entry.kind, destination);
    if let Some(include) = &entry.include {
        target = target.receiving(signals_for(include));
    }
    if let Some(secret) = secret {
        target = target.with_secret(secret);
    }
    Ok(target)
}

/// The secret a target attaches, resolved through `credentials`.
fn resolved_secret(secret: &TelemetrySecret) -> Result<TargetSecret, BoxError> {
    let uri = telemetry_secret_uri(&secret.reference).map_err(|reason| ConfigError::Telemetry {
        name: "secret".to_string(),
        reason,
    })?;
    let locator = credentials::Locator::parse_uri(&uri).map_err(|source| ConfigError::Locator {
        locator: "<telemetry secret>".to_string(),
        source,
    })?;
    let resolved = credentials::Backend::local()
        .resolve(&locator)
        .map_err(|source| ConfigError::Locator {
            locator: "<telemetry secret>".to_string(),
            source,
        })?;

    // `Authorization` conventionally carries a prefix and every other header carries the bare value.
    let header = secret.header.as_deref().unwrap_or(DEFAULT_HEADER);
    let value = if header.eq_ignore_ascii_case(DEFAULT_HEADER) {
        format!("{BEARER_PREFIX}{}", resolved.as_str())
    } else {
        resolved.as_str().to_string()
    };
    Ok(TargetSecret::new(header, value))
}

/// The stored telemetry entries as one collector request.
pub(crate) fn config_for(
    box_name: &str,
    entries: &BTreeMap<String, TelemetryEntry>,
    layout: &crate::record::layout::BoxRoot,
) -> Result<TelemetryConfig, BoxError> {
    let mut request = TelemetryConfig::for_box(box_name);
    if entries.is_empty() {
        let destination = layout.telemetry_file();
        let file = layout.open_telemetry_file()?;
        return Ok(request.with_target(Target::opened_file(destination.to_string_lossy(), file)));
    }

    for (name, entry) in entries {
        let secret = match &entry.secret {
            Some(secret) => Some(resolved_secret(secret)?),
            None => None,
        };
        request = request.with_target(
            target_for(entry, layout.operator_home(), layout.root(), secret)
                .map_err(|reason| refuse(name, reason))?,
        );
    }
    Ok(request)
}

/// The declared telemetry targets, refusing every spelling the collector cannot honour.
pub(crate) fn checked(
    entries: &BTreeMap<String, TelemetryEntry>,
    box_directory: &Path,
) -> Result<BTreeMap<String, TelemetryEntry>, ConfigError> {
    let home = crate::record::layout::operator_home_directory().ok();

    for (name, entry) in entries {
        {
            // **A file target names an absolute path**, judged on the AUTHORED spelling. A relative
            // one opens against whatever working directory the box's trusted process holds, so two
            if entry.kind == TargetKind::File {
                let destination = entry.destination.trim();
                // Exactly the tilde forms `expanded_home_path` rewrites, and no other:
                let home_relative = destination == "~" || destination.starts_with("~/");
                if !home_relative && !Path::new(destination).is_absolute() {
                    return Err(refuse(
                        name,
                        format!(
                            "a file destination must be absolute or begin with `~/`; \
                             {destination:?} would open against the box's working directory"
                        ),
                    ));
                }
            }
            // **Both `include` refusals are stated here**, because the collector's own messages name
            // the record spellings, and `include` accepts none of them.
            if let Some(include) = &entry.include {
                if include.is_empty() {
                    let every: Vec<&str> = SignalGroup::every()
                        .iter()
                        .map(|group| group.as_str())
                        .collect();
                    return Err(refuse(
                        name,
                        format!(
                            "the target names no signal, so nothing would reach it; write one or \
                             more of: {}",
                            every.join(", ")
                        ),
                    ));
                }
                for (index, group) in include.iter().enumerate() {
                    if include[..index].contains(group) {
                        return Err(refuse(
                            name,
                            format!("the target names {} twice", group.as_str()),
                        ));
                    }
                }
            }
            if let Some(secret) = &entry.secret {
                telemetry_secret_uri(&secret.reference).map_err(|reason| refuse(name, reason))?;
            }

            // **Every remaining rule belongs to the collector, so ask it rather than restate it.**
            // Two copies disagreed on `HTTPS://`, so `configure` refused what `run` accepted. The
            let probe = target_for(
                entry,
                home.as_deref(),
                box_directory,
                entry
                    .secret
                    .as_ref()
                    .map(|_| TargetSecret::new("probe", "")),
            )
            .map_err(|reason| refuse(name, reason))?;
            TelemetryConfig::for_box("probe")
                .with_target(probe)
                .validate()
                .map_err(|error| refuse(name, error.to_string()))?;
        }
    }
    Ok(entries.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A destination inside the box directory but outside `private/` is refused**, because a
    /// process a spec grants reach there could truncate the record of its own denials.
    ///
    /// Two positives pair with the refusals. Without them a check that refuses everything passes,
    /// and the guard is one `starts_with` against a directory a caller now chooses — so an
    /// anchor pointing at nothing would look identical to an anchor working.
    #[test]
    fn a_destination_inside_the_box_directory_outside_private_is_refused() {
        let box_directory = Path::new("/var/lib/boxes/codex");

        let refusal = refuse_a_workload_reachable_destination(
            box_directory.join("trust/records.jsonl").to_str().unwrap(),
            box_directory,
        )
        .expect_err("a path beside `private/` is reachable by a grant, so it must be refused");
        assert!(
            refusal.contains("outside its private tree"),
            "the refusal must name why: {refusal}"
        );

        let refusal = refuse_a_workload_reachable_destination(
            box_directory
                .join("private/../trust/records.jsonl")
                .to_str()
                .unwrap(),
            box_directory,
        )
        .expect_err("a `..` component must be refused rather than resolved");
        assert!(refusal.contains("`..`"), "{refusal}");

        refuse_a_workload_reachable_destination(
            box_directory
                .join("private/telemetry/records.jsonl")
                .to_str()
                .unwrap(),
            box_directory,
        )
        .expect("the private tree is the one destination inside the box that is allowed");

        refuse_a_workload_reachable_destination("/var/log/box.jsonl", box_directory)
            .expect("a destination outside the box directory is allowed");
    }

    /// A sibling whose path merely *starts with* the box directory's spelling is not inside it.
    #[test]
    fn a_sibling_sharing_the_box_directorys_prefix_is_not_inside_it() {
        refuse_a_workload_reachable_destination(
            "/var/lib/boxes/codex-notes/records.jsonl",
            Path::new("/var/lib/boxes/codex"),
        )
        .expect("a sibling directory is outside the box, whatever its name begins with");
    }

    /// **A secret reference is a reference.** `secret://NAME` means `env://NAME`, and a bare value is
    /// refused without being echoed, in case it is one.
    #[test]
    fn a_secret_reference_is_normalized_and_a_literal_is_refused() {
        assert_eq!(
            telemetry_secret_uri("secret://HONEYCOMB_KEY").expect("the alias is accepted"),
            format!("{ENV_SCHEME}HONEYCOMB_KEY")
        );
        assert_eq!(
            telemetry_secret_uri("env://HONEYCOMB_KEY").expect("the canonical form is accepted"),
            "env://HONEYCOMB_KEY"
        );
        assert!(
            telemetry_secret_uri("secret://").is_err(),
            "an empty name names no variable"
        );

        let refusal = telemetry_secret_uri("hcaik_live_abcdef")
            .expect_err("a literal value is not a reference");
        assert!(
            !refusal.contains("hcaik_live_abcdef"),
            "the refusal must not echo the value, in case it is a secret: {refusal}"
        );
    }

    /// A file destination must be absolute or `~/`-relative, judged on the AUTHORED spelling.
    #[test]
    fn a_relative_file_destination_is_refused() {
        let entry = TelemetryEntry {
            kind: TargetKind::File,
            destination: "records.jsonl".to_string(),
            include: None,
            secret: None,
        };
        let entries = BTreeMap::from([("decisions".to_string(), entry)]);
        let refusal = checked(&entries, Path::new("/var/lib/boxes/codex"))
            .expect_err("a relative file destination must be refused");
        assert!(refusal.to_string().contains("absolute"), "{refusal}");
        // The refusal names the target the operator keyed it under, not a position in an array.
        assert!(refusal.to_string().contains("decisions"), "{refusal}");
    }

    /// **`trace` names both the agent's spans and the control plane**, so neither is selectable on
    /// its own, and the five words together name every signal the box files.
    ///
    /// `logs` and `metrics` are separate words rather than part of `trace`, because a harness log is
    /// not a span and an operator narrowing to spans must not silently also take metrics.
    #[test]
    fn the_five_words_expand_through_the_production_path() {
        assert_eq!(
            signals_for(&[SignalGroup::Deny]),
            vec![Signal::PolicyDenied]
        );
        assert_eq!(
            signals_for(&[SignalGroup::Permit]),
            vec![Signal::PolicyPermitted]
        );
        assert_eq!(
            signals_for(&[SignalGroup::Trace]),
            vec![Signal::AgentTrace, Signal::ControlPlane]
        );
        assert_eq!(signals_for(&[SignalGroup::Logs]), vec![Signal::AgentLogs]);
        assert_eq!(
            signals_for(&[SignalGroup::Metrics]),
            vec![Signal::AgentMetrics]
        );

        // Counted against the crate's own set, so a seventh signal no word reaches fails here.
        let every = signals_for(&SignalGroup::every());
        assert_eq!(every.len(), Signal::every().len(), "{every:?}");
    }

    /// **An absent `include` takes every signal**, so an operator who names nothing still receives
    /// the harness's own logs and metrics.
    ///
    /// Read through `target_for`, which is the one path a run takes, rather than through
    /// `Signal::default_signals` — the box could otherwise call `receiving` with a narrower set and
    /// this assertion would still pass.
    #[test]
    fn an_absent_include_takes_every_signal() {
        let entry = TelemetryEntry {
            kind: TargetKind::File,
            destination: "/tmp/records.jsonl".to_string(),
            include: None,
            secret: None,
        };
        let target = target_for(&entry, None, Path::new("/var/lib/boxes/codex"), None)
            .expect("the entry is well formed");
        assert_eq!(
            target.signals().len(),
            Signal::every().len(),
            "an absent include must reach every signal: {:?}",
            target.signals()
        );
        for expected in [Signal::AgentLogs, Signal::AgentMetrics, Signal::AgentTrace] {
            assert!(
                target.signals().contains(&expected),
                "{} must arrive with no include written",
                expected.as_str()
            );
        }
    }

    /// **An empty `include` and a repeated word are both refused in the operator's own vocabulary**,
    /// because the collector's own messages name the record spellings instead.
    #[test]
    fn an_empty_or_repeated_include_is_refused_naming_the_five_words() {
        let entry = |include: Vec<SignalGroup>| TelemetryEntry {
            kind: TargetKind::File,
            destination: "/tmp/records.jsonl".to_string(),
            include: Some(include),
            secret: None,
        };

        let empty = checked(
            &BTreeMap::from([("decisions".to_string(), entry(vec![]))]),
            Path::new("/var/lib/boxes/codex"),
        )
        .expect_err("an empty include names no signal")
        .to_string();
        assert!(empty.contains("no signal"), "{empty}");
        for word in ["deny", "permit", "trace", "logs", "metrics"] {
            assert!(
                empty.contains(word),
                "the refusal must list {word}, which an operator may write: {empty}"
            );
        }

        let repeated = checked(
            &BTreeMap::from([(
                "decisions".to_string(),
                entry(vec![SignalGroup::Deny, SignalGroup::Deny]),
            )]),
            Path::new("/var/lib/boxes/codex"),
        )
        .expect_err("a repeated word is refused rather than deduplicated in silence")
        .to_string();
        assert!(repeated.contains("deny twice"), "{repeated}");
    }

    /// **An empty declaration is unrepresentable**, now that a name holds one target rather than an
    /// array. `[[telemetry.file]]` with no entries was a kind naming no target, and `checked` had to
    /// refuse it; `[telemetry.<name>]` cannot be written that way.
    #[test]
    fn no_declaration_can_name_a_kind_without_a_target() {
        assert!(
            checked(&BTreeMap::new(), Path::new("/var/lib/boxes/codex"))
                .expect("no targets is not an error")
                .is_empty()
        );
    }
}
