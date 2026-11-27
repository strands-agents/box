//! DNS-name enrichment through a real `strands-box run`: the classification source's answer
//! reaches the authored policy before the gateway resolves the name.

use std::path::Path;
use std::process::Output;

#[path = "support/fixture.rs"]
mod fixture;

use fixture::Request;

/// A box that refuses a labelled host and a host its source did not answer about.
const THREAT_POLICY: &str = r#"
permit(principal, action == Box::Action::"net:connect", resource);
@id("block_malware")
forbid(principal, action == Box::Action::"net:connect", resource)
when { context.input.enrichment.threat.labels.contains("malware") };
@id("require_answer")
forbid(principal, action == Box::Action::"net:connect", resource)
unless { context.input.enrichment.threat.answered };
"#;

/// The `[enrichment.threat]` table, answering from the fixture at `fixture`.
fn threat_table(fixture: &Path) -> String {
    format!(
        "[enrichment.threat]\nkind = \"in-memory\"\nendpoint = \"file://{}\"\n\
         outputs = [\"malware\"]\nmin_confidence = \"HIGH\"\n",
        fixture.display()
    )
}

/// A classification fixture that labels `evil.invalid` and answers every other name clean.
fn fixture_file(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("classification.json");
    std::fs::write(
        &path,
        r#"{"ttl": 300, "hosts": {"evil.invalid": {"malware": "high"}}}"#,
    )
    .expect("the fixture writes");
    path
}

fn seen(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A workload that connects to a labelled `.invalid` name gets the policy's refusal at CONNECT,
/// which the gateway answers before any DNS query; a clean `.invalid` name passes policy and
/// fails only at resolution.
#[test]
fn a_labelled_name_is_refused_by_policy_before_it_is_resolved() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let classification = tempfile::tempdir().expect("a fixture directory");
    let fixture = fixture_file(classification.path());
    let box_ =
        Request::with_config("enrichment-refusal", THREAT_POLICY, &threat_table(&fixture)).expect();
    let probe = |host: &str| {
        box_.run(&[
            env!("CARGO_BIN_EXE_box-egress-probe"),
            &format!("https://{host}/v1/upload"),
            "HOME",
        ])
    };

    let labelled = seen(&probe("evil.invalid"));
    assert!(
        labelled.contains("status=403"),
        "the policy refuses the labelled name at CONNECT: {labelled}"
    );
    assert!(
        labelled.contains(
            "note[B0215]: [enrichment.threat] sends its classification source (kind \
             \"in-memory\") the DNS name of each host the workload connects to, before policy \
             decides the connection, unless policy refuses the host whatever the source answers."
        ),
        "the run discloses what leaves the box: {labelled}"
    );
    assert!(
        !labelled.contains(&fixture.display().to_string()),
        "the endpoint is not printed: {labelled}"
    );

    let clean = seen(&probe("clean.invalid"));
    assert!(
        clean.contains("status=") && !clean.contains("status=403"),
        "a clean name passes policy and fails only at resolution: {clean}"
    );
}

/// Each `strands.box.enrichment.<name>.answered` value on the run's `net:connect` decision records.
fn answered_values(root: &Path, name: &str) -> Vec<serde_json::Value> {
    let key = format!("strands.box.enrichment.{name}.answered");
    let text = std::fs::read_to_string(root.join("private/telemetry/records.jsonl"))
        .expect("the run drains its decision records");
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .flat_map(|request| {
            let logs = request["resourceLogs"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            logs.into_iter()
                .flat_map(|resource| {
                    resource["scopeLogs"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                })
                .flat_map(|scope| scope["logRecords"].as_array().cloned().unwrap_or_default())
                .flat_map(|record| record["attributes"].as_array().cloned().unwrap_or_default())
        })
        .filter(|attribute| attribute["key"] == key.as_str())
        .map(|attribute| attribute["value"].clone())
        .collect()
}

/// A table no rule reads gets no name: the run opens no source for it, so its entry reads
/// unanswered on the decision even for a host its fixture labels, and stderr says it is unused.
#[test]
fn a_table_no_rule_reads_is_never_asked() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    let classification = tempfile::tempdir().expect("a fixture directory");
    let fixture = fixture_file(classification.path());
    let tables = format!(
        "{}{}",
        threat_table(&fixture),
        threat_table(&fixture).replace("[enrichment.threat]", "[enrichment.unused]")
    );
    let box_ = Request::with_config("enrichment-unused", THREAT_POLICY, &tables).expect();

    let output = seen(&box_.run(&[
        env!("CARGO_BIN_EXE_box-egress-probe"),
        "https://evil.invalid/v1/upload",
        "HOME",
    ]));
    assert!(
        output.contains(
            "note[B0215]: [enrichment.unused] is unused: no rule reads it, so Box sends it no DNS \
             name."
        ),
        "{output}"
    );
    for (name, answered, why) in [
        (
            "threat",
            true,
            "the read table answers about the labelled host",
        ),
        ("unused", false, "the unread table is never asked about it"),
    ] {
        let values = answered_values(&box_.root(), name);
        assert!(
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| *value == serde_json::json!({ "boolValue": answered })),
            "{why}: {values:?}\n{output}"
        );
    }
}

/// `box policy generate-schema` writes each declared entry on the `net:connect` input, so the
/// written schema strict-validates a rule that reads it.
#[test]
fn the_generated_schema_declares_each_enrichment_entry() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace is created");
    let fixture = fixture_file(&workspace);
    let config = workspace.join("box.toml");
    std::fs::write(
        &config,
        format!(
            "name = \"enrichment-schema\"\nbox_dir = \"/nonexistent/enrichment-schema\"\n{}",
            threat_table(&fixture)
        ),
    )
    .expect("the config writes");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_strands-box"))
        .args(["policy", "generate-schema", "--config"])
        .arg(&config)
        .args(["--output-dir", "schemas"])
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("the schema command runs");
    assert!(output.status.success(), "{}", seen(&output));

    let actions = std::fs::read_to_string(workspace.join("schemas/actions.cedarschema"))
        .expect("the action schema is written");
    let (schema, _) =
        cedar_policy::Schema::from_cedarschema_str(&actions).expect("the action schema parses");
    let rules: cedar_policy::PolicySet = THREAT_POLICY.parse().expect("the rules parse");
    let validated =
        cedar_policy::Validator::new(schema).validate(&rules, cedar_policy::ValidationMode::Strict);
    assert!(
        validated.validation_passed(),
        "{:?}\n{actions}",
        validated.validation_errors().collect::<Vec<_>>()
    );
}
