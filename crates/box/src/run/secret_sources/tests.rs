//! Tests of the secret sources of one run, each against a stand-in program: a shell script in a
//! temp dir.

use std::path::{Path, PathBuf};

use super::*;
use crate::record::config::ProcessTables;
use crate::record::config::RECORD_VERSION;
use crate::record::config::telemetry::TelemetryEntry;

/// The shell that runs each stand-in program.
const SHELL: &str = "/bin/sh";

/// A stand-in program that prints `tok-NAME`, one JSON object for the name `object`, and fails
/// with a message on stderr for the name `absent`.
pub(crate) const PRINTER: &str = "case \"$1\" in\n\
     object) printf '{\"A\":\"a-value\",\"B\":\"b-value\"}' ;;\n\
     absent) echo 'no item BoxTest in the vault Personal' >&2; exit 1 ;;\n\
     *) printf 'tok-%s' \"$1\" ;;\n\
     esac";

/// One stand-in program in its own directory, which the script reads as `$D`.
pub(crate) struct StandIn {
    directory: tempfile::TempDir,
}

impl StandIn {
    /// Write `script`, which appends one line to `$D/runs` each time it starts.
    pub(crate) fn new(script: &str) -> Self {
        let directory = tempfile::tempdir().expect("the temp dir is writable");
        let body = format!(
            "D='{}'\necho run >> \"$D/runs\"\n{script}\n",
            directory
                .path()
                .canonicalize()
                .expect("the temp dir resolves")
                .display()
        );
        std::fs::write(directory.path().join("program.sh"), body).expect("the script is written");
        Self { directory }
    }

    /// The directory of the program, in its canonical spelling.
    fn path(&self) -> PathBuf {
        self.directory
            .path()
            .canonicalize()
            .expect("the temp dir resolves")
    }

    /// One `[secret-source.<scheme>]` table whose program is `program`, with this script as its
    /// first argument.
    pub(crate) fn table(&self, scheme: &str, program: &Path) -> String {
        let quoted = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
        format!(
            "[secret-source.{scheme}]\nprotocol = \"box.secret-source.v1\"\n\
             command = [{}, {}, \"{{ref}}\"]\n",
            quoted(program),
            quoted(&self.path().join("program.sh"))
        )
    }

    /// How many times the program started.
    pub(crate) fn runs(&self) -> usize {
        std::fs::read_to_string(self.path().join("runs"))
            .unwrap_or_default()
            .lines()
            .count()
    }
}

/// The sources of the `[secret-source.<scheme>]` tables in `text`, on a protected operating
/// system with the feature on.
pub(crate) fn sources(text: &str) -> Result<SecretSources, BoxError> {
    SecretSources::for_tests(&crate::record::config::secret_source::tests::entries(text))
}

/// The sources that read `op://` and `aws-secretsmanager://` through `program`.
pub(crate) fn printer_sources(program: &StandIn) -> SecretSources {
    sources(&format!(
        "{}{}",
        program.table("op", Path::new(SHELL)),
        program.table("aws-secretsmanager", Path::new(SHELL))
    ))
    .expect("the stand-in programs are checked")
}

fn secret_use(entry: &str, reference: &str) -> SecretUse {
    SecretUse {
        entry: entry.to_string(),
        reference: reference.to_string(),
    }
}

/// The read of `entry` through the stand-in for `scheme`, as the collector records it.
fn fetched(entry: &str, scheme: &str, returned: bool) -> Fetched {
    Fetched {
        entry: entry.to_string(),
        detail: format!("source `{scheme}`, program /bin/sh, reference {scheme}://[REDACTED]"),
        returned,
    }
}

/// What a fetch of `uses` records, writes for the operator, and refuses.
fn fetch(sources: &SecretSources, uses: &[SecretUse]) -> (Vec<Fetched>, String, Option<String>) {
    let mut diagnostics = Vec::new();
    let (fetched, read) = sources.fetch(uses, &mut diagnostics);
    (
        fetched,
        String::from_utf8(diagnostics).expect("the diagnostics are UTF-8"),
        read.err().map(|refusal| refusal.to_string()),
    )
}

/// A record whose egress entries, remote MCP servers, and telemetry targets are the tables of
/// `text`.
fn record(text: &str) -> Record {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Tables {
        #[serde(default)]
        egress: BTreeMap<String, EgressEntry>,
        #[serde(default)]
        mcp: BTreeMap<String, EgressEntry>,
        #[serde(default)]
        telemetry: BTreeMap<String, TelemetryEntry>,
    }
    let tables: Tables = toml::from_str(text).expect("the test tables parse");
    Record {
        version: RECORD_VERSION,
        experimental_features: Default::default(),
        file_attributes: false,
        gateway: Default::default(),
        limits: Default::default(),
        monty: true,
        box_id: "box-0123456789abcdef".to_string(),
        box_dir: PathBuf::from("/var/lib/boxes/probe"),
        name: "probe".to_string(),
        policy: None,
        agent: None,
        tool: BTreeMap::new(),
        egress: tables.egress,
        remote_mcp: tables.mcp,
        mcp: Vec::new(),
        contained_mcp: BTreeMap::new(),
        telemetry: tables.telemetry,
        secret_source: Default::default(),
    }
}

#[test]
fn a_configuration_with_no_declaration_reads_through_the_local_sources() {
    let sources = SecretSources::none();
    assert_eq!(
        format!("{:?}", sources.backend()),
        format!("{:?}", Backend::local())
    );
    let mut lines = Vec::new();
    sources.disclose(&mut lines).expect("the lines write");
    assert_eq!(lines, b"");
    assert!(!sources.reads("op://Personal/GitHub/token"));
    assert_eq!(fetch(&sources, &[]), (Vec::new(), String::new(), None));
}

#[test]
fn startup_names_each_declared_source_and_its_program() {
    let program = StandIn::new(PRINTER);
    // A path can hold a control character, and a line shows none.
    let odd = program.path().join("to\u{1b}ol");
    std::os::unix::fs::symlink(SHELL, &odd).expect("the link is made");
    let sources = sources(&format!(
        "{}{}",
        program.table("op", Path::new(SHELL)),
        program.table("vault", &odd)
    ))
    .expect("the stand-in programs are checked");
    let mut lines = Vec::new();
    sources.disclose(&mut lines).expect("the lines write");
    assert_eq!(
        String::from_utf8(lines).expect("the lines are UTF-8"),
        format!(
            "strands-box: [secret-source.op]: reads each op:// secret with /bin/sh, which runs \
             outside every sandbox\n\
             strands-box: [secret-source.vault]: reads each vault:// secret with {}/to\\u{{1b}}ol, \
             which runs outside every sandbox\n",
            program.path().display()
        )
    );
    assert_eq!(program.runs(), 0, "a line starts no program");
}

#[test]
fn each_entry_whose_secret_a_declared_source_reads_is_a_use() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    let record = record(
        r#"
        [egress.github]
        destinations = ["api.github.com"]
        secret.ref = "op://Personal/GitHub/token"
        secret.env = "GH_TOKEN"

        [egress.plain]
        destinations = ["api.example.com"]
        secret.ref = "env://EXAMPLE_TOKEN"

        [egress.signed]
        destinations = ["bedrock-runtime.us-east-1.amazonaws.com"]
        secret.ref = "aws://default"

        [egress.undeclared]
        destinations = ["vault.example.com"]
        secret.ref = "vault://kv/key"
        secret.env = "VAULT_KEY"

        [egress.rerouted]
        destinations = ["api.internal.example.com"]
        secret.ref = "env://INTERNAL_TOKEN"
        [[egress.rerouted.backends]]
        url = "https://gateway.example.com"
        auth.ref = "aws-secretsmanager://box/gateway#TOKEN"

        [mcp.web]
        destinations = ["mcp.example.com"]
        protocol = "mcp"
        secret.ref = "op://Personal/Web/token"
        secret.env = "WEB_TOKEN"

        [telemetry.file]
        kind = "file"
        destination = "/var/log/box.jsonl"

        [telemetry.plain]
        kind = "otlp"
        destination = "https://otlp.example.com"
        secret.ref = "secret://OTLP_KEY"

        [telemetry.vendor]
        kind = "otlp"
        destination = "https://api.vendor.example.com/otel"
        secret.ref = " aws-secretsmanager://box/telemetry#KEY "
        secret.header = "x-api-key"
        "#,
    );
    assert_eq!(
        sources.telemetry_uses(&record),
        [secret_use(
            "[telemetry.vendor] secret.ref",
            "aws-secretsmanager://box/telemetry#KEY"
        )]
    );
    assert_eq!(
        sources.route_uses(&record),
        [
            secret_use("[egress.github] secret.ref", "op://Personal/GitHub/token"),
            secret_use(
                "[egress.rerouted] backends.auth.ref",
                "aws-secretsmanager://box/gateway#TOKEN"
            ),
            secret_use("[mcp.web] secret.ref", "op://Personal/Web/token"),
        ]
    );
    assert_eq!(program.runs(), 0, "a list of uses starts no program");
}

#[test]
fn a_fetch_reads_each_use_and_states_each_read() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    let uses = [
        secret_use("[egress.github] secret.ref", "op://Personal/GitHub/token"),
        secret_use("[mcp.web] secret.ref", "aws-secretsmanager://object#A"),
    ];
    assert_eq!(
        fetch(&sources, &uses),
        (
            vec![
                fetched("[egress.github] secret.ref", "op", true),
                fetched("[mcp.web] secret.ref", "aws-secretsmanager", true),
            ],
            String::new(),
            None
        )
    );
    assert_eq!(program.runs(), 2);
    // Each vault of the run then reads the held secret, and starts no program.
    let read = |reference: &str| {
        sources
            .backend()
            .resolve(&Locator::parse_uri(reference).expect("the reference parses"))
            .expect("the backend holds the secret")
            .to_string()
    };
    assert_eq!(
        read("op://Personal/GitHub/token"),
        "tok-Personal/GitHub/token"
    );
    assert_eq!(read("aws-secretsmanager://object#A"), "a-value");
    assert_eq!(program.runs(), 2);
}

#[test]
fn a_telemetry_target_and_a_route_with_one_secret_run_the_program_once() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    let record = record(
        r#"
        [egress.vendor]
        destinations = ["api.vendor.example.com"]
        secret.ref = "aws-secretsmanager://object#B"
        secret.env = "VENDOR_KEY"

        [telemetry.vendor]
        kind = "otlp"
        destination = "https://api.vendor.example.com/otel"
        secret.ref = "aws-secretsmanager://object#A"
        "#,
    );
    // The two steps of a run: the telemetry targets, then the routes.
    let (first, _, refusal) = fetch(&sources, &sources.telemetry_uses(&record));
    assert_eq!(refusal, None);
    assert_eq!(program.runs(), 1);
    let (second, _, refusal) = fetch(&sources, &sources.route_uses(&record));
    assert_eq!(refusal, None);
    assert_eq!(program.runs(), 1, "the second step reuses the held secret");
    assert_eq!(
        [first, second].concat(),
        [
            fetched("[telemetry.vendor] secret.ref", "aws-secretsmanager", true),
            fetched("[egress.vendor] secret.ref", "aws-secretsmanager", true),
        ]
    );
}

#[test]
fn a_failed_fetch_names_its_entry_and_stops_the_later_reads() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    let uses = [
        secret_use("[egress.first] secret.ref", "op://first"),
        secret_use("[egress.github] secret.ref", "op://absent#FIELD"),
        secret_use("[egress.later] secret.ref", "op://later"),
    ];
    assert_eq!(
        fetch(&sources, &uses),
        (
            vec![
                fetched("[egress.first] secret.ref", "op", true),
                fetched("[egress.github] secret.ref", "op", false),
            ],
            // The words of the program reach the operator, and no record or refusal holds them.
            "strands-box: [egress.github] secret.ref: credential error: the secret source \
             \"op\" (\"/bin/sh\") for op://[REDACTED] exited unsuccessfully (exit status: 1): \
             no item BoxTest in the vault Personal\n"
                .to_string(),
            Some(
                "`[egress.github] secret.ref` names a secret that the secret source `op` \
                 (/bin/sh) did not return, so the box does not start"
                    .to_string()
            )
        )
    );
    assert_eq!(program.runs(), 2, "no read follows the one that failed");
}

#[test]
fn a_reference_that_the_runner_refuses_names_its_entry() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    for (reference, reason) in [
        (
            "op://-n/item",
            "the reference op://[REDACTED] is malformed: the text after `://` starts with `-`, \
             which a program can read as a flag",
        ),
        (
            "aws-secretsmanager://box/telemetry#",
            "the reference aws-secretsmanager://[REDACTED] is malformed: it names no field \
             after `#`",
        ),
        (
            "op://plain#FIELD",
            "the secret source \"op\" (\"/bin/sh\") for op://[REDACTED] returned a secret that \
             is not a JSON object, so it has no `#FIELD`",
        ),
    ] {
        let scheme = reference.split_once("://").expect("a URI").0;
        assert_eq!(
            fetch(
                &sources,
                &[secret_use("[telemetry.vendor] secret.ref", reference)]
            ),
            (
                vec![fetched("[telemetry.vendor] secret.ref", scheme, false)],
                format!("strands-box: [telemetry.vendor] secret.ref: credential error: {reason}\n"),
                Some(format!(
                    "`[telemetry.vendor] secret.ref` names a secret that the secret source \
                     `{scheme}` (/bin/sh) did not return, so the box does not start"
                ))
            ),
            "for {reference}"
        );
    }
    assert_eq!(
        program.runs(),
        1,
        "only the last reference starts the program"
    );
}

#[test]
fn a_program_path_that_names_another_file_after_the_check_stops_the_fetch() {
    let program = StandIn::new(PRINTER);
    let link = program.path().join("op");
    std::os::unix::fs::symlink(SHELL, &link).expect("the link is made");
    let sources = sources(&program.table("op", &link)).expect("the program is checked");
    std::fs::remove_file(&link).expect("the link is removed");
    std::os::unix::fs::symlink("/bin/cat", &link).expect("the link names another file");

    let (read, diagnostics, refusal) = fetch(
        &sources,
        &[secret_use("[egress.github] secret.ref", "op://item")],
    );
    assert_eq!(
        read,
        [Fetched {
            entry: "[egress.github] secret.ref".to_string(),
            detail: format!(
                "source `op`, program {}, reference op://[REDACTED]",
                link.display()
            ),
            returned: false,
        }]
    );
    assert_eq!(
        diagnostics,
        format!(
            "strands-box: [egress.github] secret.ref: credential error: the secret source \
             \"op\" ({link:?}) for op://[REDACTED] did not start: its program file changed \
             after the box checked it\n"
        )
    );
    assert_eq!(
        refusal,
        Some(format!(
            "`[egress.github] secret.ref` names a secret that the secret source `op` ({}) did \
             not return, so the box does not start",
            link.display()
        ))
    );
    assert_eq!(program.runs(), 0);
}

#[test]
fn a_program_that_box_cannot_check_is_refused_before_a_fetch() {
    let program = StandIn::new(PRINTER);
    let directory = program.path();
    let plain = directory.join("program.sh");
    for (path, reason) in [
        (
            directory.join("absent"),
            format!(
                "its program cannot run: containment config failed: path does not exist: {}",
                directory.join("absent").display()
            ),
        ),
        (
            plain.clone(),
            format!(
                "its program cannot run: executable is not an executable regular file: {}",
                plain.display()
            ),
        ),
        (
            directory.to_path_buf(),
            format!(
                "its program cannot run: executable is not an executable regular file: {}",
                directory.display()
            ),
        ),
    ] {
        assert_eq!(
            sources(&program.table("op", &path))
                .expect_err("the program is refused")
                .to_string(),
            format!("invalid `[secret-source.op]` table: {reason}"),
            "for {}",
            path.display()
        );
    }
    assert_eq!(program.runs(), 0);
}

/// The process tables of a configuration whose agent reads and writes `folder`.
fn agent_writes(folder: &Path) -> ProcessTables {
    let quoted = toml::Value::String(folder.display().to_string()).to_string();
    let agent = toml::from_str(&format!(
        "command = [\"/bin/bash\"]\n[filesystem]\nread = [{quoted}]\nwrite = [{quoted}]\n"
    ))
    .expect("the agent table parses");
    ProcessTables {
        tables: vec![("[agent]".to_string(), agent)],
        policy: None,
        declares_stdio_mcp: false,
        source_paths: Vec::new(),
    }
}

#[test]
fn a_write_grant_over_a_source_program_is_refused_and_starts_no_program() {
    let program = StandIn::new(PRINTER);
    let (bin, output) = (program.path().join("bin"), program.path().join("output"));
    for folder in [&bin, &output] {
        std::fs::create_dir(folder).expect("the folder is made");
    }
    let link = bin.join("op");
    std::os::unix::fs::symlink(SHELL, &link).expect("the link is made");
    let sources = sources(&program.table("op", &link)).expect("the program is checked");

    let refusal = sources
        .refuse_exposure(&agent_writes(&bin), &[])
        .expect_err("the agent can replace the link to the program")
        .to_string();
    assert_eq!(
        refusal,
        format!(
            "`[agent]` filesystem entry {:?} is refused: this write grant can change \
             [secret-source.op] command {} or its path. Keep the program of each secret source \
             outside every process's write grants",
            bin.display().to_string(),
            Path::new(SHELL)
                .canonicalize()
                .expect("the shell resolves")
                .display()
        )
    );
    sources
        .refuse_exposure(&agent_writes(&output), &[])
        .expect("a grant beside the program is not refused");
    // A configuration that declares no source judges no list here, also a list that the
    // judgement refuses, so its checks keep their order.
    assert!(
        sources.refuse_exposure(&agent_writes(&link), &[]).is_err(),
        "the judgement refuses a list entry that is a symbolic link"
    );
    SecretSources::none()
        .refuse_exposure(&agent_writes(&link), &[])
        .expect("no source, no judgement");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

/// The process tables of a configuration whose `[agent]` table has `body` after its command,
/// beside the secret sources `entries`.
fn agent_beside(body: &str, entries: &BTreeMap<String, SecretSourceEntry>) -> ProcessTables {
    let agent = toml::from_str(&format!("command = [\"/bin/bash\"]\n{body}"))
        .expect("the agent table parses");
    ProcessTables {
        tables: vec![("[agent]".to_string(), agent)],
        policy: None,
        declares_stdio_mcp: false,
        source_paths: crate::record::config::secret_source::protected_paths(entries),
    }
}

#[test]
fn a_grant_over_a_path_of_a_source_is_refused_and_starts_no_program() {
    let program = StandIn::new(PRINTER);
    let (store, beside) = (program.path().join("store"), program.path().join("beside"));
    for folder in [&store, &beside] {
        std::fs::create_dir(folder).expect("the folder is made");
    }
    let quoted = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let entries = crate::record::config::secret_source::tests::entries(&format!(
        "{}reads = [{}]\n",
        program.table("op", Path::new(SHELL)),
        quoted(&store)
    ));
    let sources = SecretSources::for_tests(&entries).expect("the program is checked");

    let refusal = sources
        .refuse_exposure(
            &agent_beside(
                &format!("[filesystem]\nread = [{}]\n", quoted(&store)),
                &entries,
            ),
            &[],
        )
        .expect_err("the agent can read a path of the source")
        .to_string();
    assert_eq!(
        refusal,
        format!(
            "`[agent]` filesystem entry {0:?} is refused: this grant reaches {0}, which the \
             secret source `op` keeps from each workload (its `reads` entry {0:?}). Keep each \
             grant outside the paths that a secret source names in `reads` and `deny`",
            store.display().to_string()
        )
    );
    sources
        .refuse_exposure(
            &agent_beside(
                &format!("[filesystem]\nread = [{}]\n", quoted(&beside)),
                &entries,
            ),
            &[],
        )
        .expect("a grant beside the path is not refused");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

#[test]
fn a_write_grant_over_an_argument_file_of_a_source_is_refused_and_starts_no_program() {
    let program = StandIn::new(PRINTER);
    let entries = crate::record::config::secret_source::tests::entries(
        &program.table("op", Path::new(SHELL)),
    );
    let sources = SecretSources::for_tests(&entries).expect("the program is checked");
    let folder = toml::Value::String(program.path().display().to_string()).to_string();

    let refusal = sources
        .refuse_exposure(
            &agent_beside(
                &format!("[filesystem]\nread = [{folder}]\nwrite = [{folder}]\n"),
                &entries,
            ),
            &[],
        )
        .expect_err("the agent can replace the script that the source runs")
        .to_string();
    assert_eq!(
        refusal,
        format!(
            "`[agent]` filesystem entry {:?} is refused: this write grant can change {}, a file \
             that the `command` of [secret-source.op] names, or its path. Keep each file that a \
             secret source command names outside every process's write grants",
            program.path().display().to_string(),
            program.path().join("program.sh").display()
        )
    );
    sources
        .refuse_exposure(
            &agent_beside(&format!("[filesystem]\nread = [{folder}]\n"), &entries),
            &[],
        )
        .expect("a read grant cannot change the script");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

#[test]
fn a_table_that_holds_a_credential_of_a_vault_is_refused_and_starts_no_program() {
    use crate::record::config::secret_source::tests::environment;
    let program = StandIn::new(PRINTER);
    let entries = crate::record::config::secret_source::tests::entries(&format!(
        "{}pass-env = [\"OP_ACCOUNT\"]\npass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_SESSION_*\"]\n",
        program.table("op", Path::new(SHELL))
    ));
    let operator = [
        ("OP_SERVICE_ACCOUNT_TOKEN", "ops_token_of_the_operator"),
        ("OP_SESSION_team", "session_of_the_operator"),
        ("OP_ACCOUNT", "my.1password.com"),
    ];
    let sources = SecretSources::for_tests(&entries).expect("the program is checked");
    let judge = |body: &str, operator: &[(&str, &str)]| {
        sources.refuse_exposure_in(&agent_beside(body, &entries), &[], || environment(operator))
    };

    // A value that an operator pasted into a table, under a name of its own, for a prefix entry.
    let refusal = judge(
        "[env]\nGITHUB_TOKEN = \"session_of_the_operator\"\n",
        &operator,
    )
    .expect_err("the agent holds the session of the vault")
    .to_string();
    assert_eq!(
        refusal,
        "invalid `[agent]` table: `env.GITHUB_TOKEN` holds the value of the variable \
         OP_SESSION_team, which is a credential of the secret source `op` (its \
         `pass-secret-env` names it), so no workload can hold it"
    );
    for body in [
        // A placeholder under the name of the credential, and a plain setting.
        "[env]\nOP_SERVICE_ACCOUNT_TOKEN = \"strands_box_placeholder\"\n",
        "[env]\nOP_ACCOUNT = \"my.1password.com\"\n",
    ] {
        judge(body, &operator).expect("the table holds no credential");
    }
    // The same table beside an operator who sets no credential.
    judge("[env]\nGITHUB_TOKEN = \"session_of_the_operator\"\n", &[])
        .expect("no credential, no refusal");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

#[test]
fn the_sources_read_each_credential_of_a_vault_when_they_judge_a_table() {
    use crate::record::config::secret_source::tests::environment;
    let program = StandIn::new(PRINTER);
    let entries = crate::record::config::secret_source::tests::entries(&format!(
        "{}pass-secret-env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_SESSION_*\"]\n",
        program.table("op", Path::new(SHELL))
    ));
    let sources = SecretSources::for_tests(&entries).expect("the program is checked");
    let tables = agent_beside(
        "[env]\nGITHUB_TOKEN = \"value_of_the_operator\"\n",
        &entries,
    );
    // The variable that each refusal names, for one table and one set of sources.
    let judged = |operator: &[(&str, &str)]| {
        sources
            .refuse_exposure_in(&tables, &[], || environment(operator))
            .map_err(|refusal| {
                ["OP_SERVICE_ACCOUNT_TOKEN", "OP_SESSION_team"]
                    .into_iter()
                    .find(|name| refusal.to_string().contains(name))
            })
    };

    // The sources keep no value of an earlier operator: each call reads its own environment.
    assert_eq!(
        [
            judged(&[("OP_SERVICE_ACCOUNT_TOKEN", "value_of_the_operator")]),
            judged(&[]),
            judged(&[("OP_SESSION_team", "value_of_the_operator")]),
            judged(&[("OP_SERVICE_ACCOUNT_TOKEN", "another_value")]),
        ],
        [
            Err(Some("OP_SERVICE_ACCOUNT_TOKEN")),
            Ok(()),
            Err(Some("OP_SESSION_team")),
            Ok(()),
        ]
    );
    // A configuration that declares no source copies no variable of the operator.
    SecretSources::none()
        .refuse_exposure_in(&tables, &[], || -> Vec<_> {
            panic!("no source, no read of the environment")
        })
        .expect("no source, no judgement");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

#[test]
fn the_sources_read_no_secret_after_they_close() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    let uses = [secret_use("[egress.github] secret.ref", "op://item")];
    assert_eq!(fetch(&sources, &uses).2, None);
    sources.close();
    assert_eq!(
        fetch(&sources, &uses),
        (
            vec![fetched("[egress.github] secret.ref", "op", false)],
            "strands-box: [egress.github] secret.ref: credential error: the secret source \
             \"op\" (\"/bin/sh\") for op://[REDACTED] is closed: the box reads each secret once, \
             before the workload starts\n"
                .to_string(),
            Some(
                "`[egress.github] secret.ref` names a secret that the secret source `op` \
                 (/bin/sh) did not return, so the box does not start"
                    .to_string()
            )
        )
    );
    assert_eq!(program.runs(), 1);
}

#[test]
fn a_read_is_recorded_as_one_control_plane_record() {
    assert_eq!(ControlOperation::SecretFetched.as_str(), "secret_fetched");
    let ok = format!(
        "{:?}",
        fetched("[egress.github] secret.ref", "op", true).record()
    );
    let refused = format!(
        "{:?}",
        fetched("[egress.github] secret.ref", "op", false).record()
    );
    let fields = |record: &str| {
        record
            .split_once(", unix_nanos")
            .expect("the record ends with its time")
            .0
            .to_string()
    };
    assert_eq!(
        fields(&ok),
        "ControlRecord { operation: SecretFetched, subject: Some(\"[egress.github] \
         secret.ref\"), refusal: None, detail: Some(\"source `op`, program /bin/sh, reference \
         op://[REDACTED]\")"
    );
    assert_eq!(
        fields(&refused),
        "ControlRecord { operation: SecretFetched, subject: Some(\"[egress.github] \
         secret.ref\"), refusal: Some(\"the secret source returned no secret; the standard \
         error of the box holds the reason\"), detail: Some(\"source `op`, program /bin/sh, \
         reference op://[REDACTED]\")"
    );
}
