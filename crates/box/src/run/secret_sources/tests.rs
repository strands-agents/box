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

/// The sources of the `[secret-source.<scheme>]` tables in `text`, with the feature on, with each
/// program file checked and no table judged.
pub(crate) fn sources(text: &str) -> Result<SecretSources, BoxError> {
    SecretSources::for_tests(&crate::record::config::secret_source::tests::entries(text))
}

impl SecretSources {
    /// The one backend of these sources, which only a test reads before a read step.
    pub(crate) fn backend(&self) -> &Backend {
        &self.backend
    }

    /// The sources of `entries`, with the feature on, with each program file checked and no table
    /// judged.
    pub(crate) fn for_tests(
        entries: &BTreeMap<String, SecretSourceEntry>,
    ) -> Result<Self, BoxError> {
        Self::open(entries, DeclaredSources::for_tests(entries))
    }

    /// [`check`](Self::check) of `record`, with the feature on.
    pub(crate) fn check_for_tests(
        record: &Record,
        disclosure: impl std::io::Write,
    ) -> Result<Self, BoxError> {
        let declared = DeclaredSources::for_tests(&record.secret_source);
        Self::checked_for_record(record, declared, &[], disclosure)
    }
}

impl RouteSecrets {
    /// The secrets of a record that declares no source, after its two reads.
    pub(crate) fn none() -> Self {
        let (_, telemetry) = SecretSources::check(&record(""), &[], std::io::sink())
            .expect("no declaration, no refusal")
            .fetch_telemetry(std::io::sink());
        let (_, routes) = telemetry
            .expect("no secret, no failed read")
            .fetch_routes(std::io::sink());
        routes.expect("no secret, no failed read")
    }
}

/// The process tables of a configuration that declares no process.
fn no_tables() -> ProcessTables {
    ProcessTables {
        tables: Vec::new(),
        policy: None,
        declares_stdio_mcp: false,
        source_paths: Vec::new(),
    }
}

/// What [`SecretSources::checked`] makes of the tables in `text` beside `tables`: the sources or
/// the refusal, and each line that it wrote.
fn checked(text: &str, tables: &ProcessTables) -> (Result<SecretSources, String>, String) {
    let entries = crate::record::config::secret_source::tests::entries(text);
    let mut lines = Vec::new();
    let sources = SecretSources::checked(
        &entries,
        DeclaredSources::for_tests(&entries),
        tables,
        &[],
        &mut lines,
    )
    .map_err(|refusal| refusal.to_string());
    (
        sources,
        String::from_utf8(lines).expect("the lines are UTF-8"),
    )
}

/// The secret that `backend` reads for `reference`, or its refusal.
fn read(backend: &Backend, reference: &str) -> Result<String, String> {
    backend
        .resolve(&Locator::parse_uri(reference).expect("the reference parses"))
        .map(|secret| secret.to_string())
        .map_err(|refusal| refusal.to_string())
}

/// Why a closed source refuses a read of `op://item`.
const CLOSED: &str = "credential error: the secret source \"op\" (\"/bin/sh\") for \
                      op://[REDACTED] is closed: the box reads each secret once, before the \
                      workload starts";

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
        locator: Locator::parse_uri(reference).expect("the reference parses"),
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
    let mut lines = Vec::new();
    let sources =
        SecretSources::check(&record(""), &[], &mut lines).expect("no declaration, no refusal");
    assert_eq!(
        format!("{:?}", sources.backend()),
        format!("{:?}", Backend::local())
    );
    assert_eq!(lines, b"");
    assert!(!sources.reads("op://Personal/GitHub/token"));
    // Each read step reads nothing, and gives the next one.
    let (fetched, telemetry) = sources.fetch_telemetry(&mut lines);
    assert_eq!(fetched, []);
    let (fetched, routes) = telemetry
        .expect("no secret, no failed read")
        .fetch_routes(&mut lines);
    assert_eq!(fetched, []);
    assert!(routes.is_ok());
    assert_eq!(lines, b"");
}

#[test]
fn the_check_names_each_declared_source_and_its_program() {
    let program = StandIn::new(PRINTER);
    // A path can hold a control character, and a line shows none.
    let odd = program.path().join("to\u{1b}ol");
    std::os::unix::fs::symlink(SHELL, &odd).expect("the link is made");
    let (sources, lines) = checked(
        &format!(
            "{}{}",
            program.table("op", Path::new(SHELL)),
            program.table("vault", &odd)
        ),
        &no_tables(),
    );
    sources.expect("the stand-in programs are checked");
    assert_eq!(
        lines,
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
    // The check of a record holds each use, for the two reads.
    let sources = printer_sources(&program).reading(&record);
    assert_eq!(
        sources.telemetry,
        [secret_use(
            "[telemetry.vendor] secret.ref",
            "aws-secretsmanager://box/telemetry#KEY"
        )]
    );
    assert_eq!(
        sources.routes,
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
fn the_check_of_a_record_gives_the_sources_that_read_each_of_its_secrets() {
    let program = StandIn::new(PRINTER);
    let mut record = record(
        r#"
        [egress.github]
        destinations = ["api.github.com"]
        secret.ref = "op://Personal/GitHub/token"
        secret.env = "GH_TOKEN"

        [telemetry.vendor]
        kind = "otlp"
        destination = "https://api.vendor.example.com/otel"
        secret.ref = "op://Personal/Vendor/key"
        "#,
    );
    record.secret_source = crate::record::config::secret_source::tests::entries(
        &program.table("op", Path::new(SHELL)),
    );
    let mut lines = Vec::new();
    let sources =
        SecretSources::check_for_tests(&record, &mut lines).expect("the program is checked");
    assert_eq!(
        String::from_utf8(lines).expect("the lines are UTF-8"),
        "strands-box: [secret-source.op]: reads each op:// secret with /bin/sh, which runs \
         outside every sandbox\n"
    );
    assert_eq!(program.runs(), 0, "the check starts no program");

    let mut said = Vec::new();
    let (first, telemetry) = sources.fetch_telemetry(&mut said);
    assert_eq!(
        first,
        [fetched("[telemetry.vendor] secret.ref", "op", true)]
    );
    assert_eq!(program.runs(), 1);
    let (second, routes) = telemetry
        .expect("the program returns the secret")
        .fetch_routes(&mut said);
    assert_eq!(second, [fetched("[egress.github] secret.ref", "op", true)]);
    assert_eq!(program.runs(), 2);
    assert_eq!(
        read(
            routes.expect("the program returns the secret").backend(),
            "op://Personal/GitHub/token"
        ),
        Ok("tok-Personal/GitHub/token".to_string())
    );
    assert_eq!(program.runs(), 2);
    assert_eq!(said, b"");
}

#[test]
fn the_sources_read_a_reference_by_the_scheme_that_credentials_routes() {
    let program = StandIn::new(PRINTER);
    let sources = printer_sources(&program);
    for (reference, read) in [
        ("op://Personal/GitHub/token", true),
        ("op://item#FIELD", true),
        ("op://a://b", true),
        ("aws-secretsmanager://box/telemetry#KEY", true),
        // No source of this run reads the scheme.
        ("vault://kv/key", false),
        ("env://NAME", false),
        ("aws://", false),
        // `credentials` refuses the text as a reference, so no source reads it.
        ("op://", false),
        ("://orphan", false),
        ("op:/item", false),
        ("op", false),
        ("", false),
        // The scheme is the text before `://` as written: no trim, and no change of case.
        (" op://item", false),
        ("op ://item", false),
        ("OP://item", false),
    ] {
        assert_eq!(sources.reads(reference), read, "for {reference:?}");
        // The answer is for the scheme that the backend routes the reference by.
        let routed = Locator::parse_uri(reference).ok();
        assert_eq!(
            read,
            routed
                .as_ref()
                .is_some_and(|locator| ["op", "aws-secretsmanager"].contains(&locator.scheme())),
            "for {reference:?}"
        );
        // A use holds the reference as the backend gets it.
        assert_eq!(
            sources.locator(reference),
            routed.filter(|_| read),
            "for {reference:?}"
        );
    }
    assert_eq!(program.runs(), 0, "the answer starts no program");
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
    let sources = sources.reading(&record);
    let mut said = Vec::new();
    let (first, telemetry) = sources.fetch_telemetry(&mut said);
    let telemetry = telemetry.expect("the program returns the secret");
    assert_eq!(program.runs(), 1);
    let (second, routes) = telemetry.fetch_routes(&mut said);
    let routes = routes.expect("the backend holds the secret");
    assert_eq!(program.runs(), 1, "the second step reuses the held secret");
    assert_eq!(
        [first, second].concat(),
        [
            fetched("[telemetry.vendor] secret.ref", "aws-secretsmanager", true),
            fetched("[egress.vendor] secret.ref", "aws-secretsmanager", true),
        ]
    );
    // Each vault then takes its secret from the one backend, and starts no program.
    assert_eq!(
        read(routes.backend(), "aws-secretsmanager://object#B"),
        Ok("b-value".to_string())
    );
    assert_eq!(program.runs(), 1);
    assert_eq!(said, b"");
}

#[test]
fn a_read_that_fails_gives_no_value_to_the_next_step() {
    let program = StandIn::new(PRINTER);
    let failed = |tables: &str| {
        let sources = printer_sources(&program).reading(&record(tables));
        let backend = sources.backend().clone();
        let mut said = Vec::new();
        let (fetched, telemetry) = sources.fetch_telemetry(&mut said);
        let refusal = match telemetry {
            Ok(telemetry) => {
                let (later, routes) = telemetry.fetch_routes(&mut said);
                assert_eq!(
                    later.len(),
                    1,
                    "the route is read after the telemetry target"
                );
                routes.expect_err("the route names an absent secret")
            }
            Err(refusal) => {
                assert_eq!(fetched.len(), 1, "the telemetry target is read first");
                refusal
            }
        };
        // The step that failed took the sources with it, so they are closed.
        assert_eq!(read(&backend, "op://item"), Err(CLOSED.to_string()));
        refusal.to_string()
    };
    assert_eq!(
        failed(
            r#"
            [egress.github]
            destinations = ["api.github.com"]
            secret.ref = "op://item"
            secret.env = "GH_TOKEN"

            [telemetry.vendor]
            kind = "otlp"
            destination = "https://api.vendor.example.com/otel"
            secret.ref = "op://absent"
            "#
        ),
        "`[telemetry.vendor] secret.ref` names a secret that the secret source `op` (/bin/sh) \
         did not return, so the box does not start"
    );
    assert_eq!(
        program.runs(),
        1,
        "no route is read after the target that failed"
    );
    assert_eq!(
        failed(
            r#"
            [egress.github]
            destinations = ["api.github.com"]
            secret.ref = "op://absent"
            secret.env = "GH_TOKEN"
            "#
        ),
        "`[egress.github] secret.ref` names a secret that the secret source `op` (/bin/sh) did \
         not return, so the box does not start"
    );
    assert_eq!(program.runs(), 2);
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
    for (reference, scheme, reason) in [
        (
            "op://-n/item",
            "op",
            "the reference op://[REDACTED] is malformed: the text after `://` starts with `-`, \
             which a program can read as a flag",
        ),
        (
            "aws-secretsmanager://box/telemetry#",
            "aws-secretsmanager",
            "the reference aws-secretsmanager://[REDACTED] is malformed: it names no field \
             after `#`",
        ),
        (
            "op://plain#FIELD",
            "op",
            "the secret source \"op\" (\"/bin/sh\") for op://[REDACTED] returned a secret that \
             is not a JSON object, so it has no `#FIELD`",
        ),
    ] {
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
    let table = program.table("op", &link);
    let line = format!(
        "strands-box: [secret-source.op]: reads each op:// secret with {}, which runs outside \
         every sandbox\n",
        link.display()
    );

    // The check gives no sources to read with, and names no source, for a refused table.
    let (refused, lines) = checked(&table, &agent_writes(&bin));
    assert_eq!(
        (refused.err(), lines),
        (
            Some(format!(
                "`[agent]` filesystem entry {:?} is refused: this write grant can change \
                 [secret-source.op] command {} or its path. Keep the program of each secret \
                 source outside every process's write grants",
                bin.display().to_string(),
                Path::new(SHELL)
                    .canonicalize()
                    .expect("the shell resolves")
                    .display()
            )),
            String::new()
        )
    );
    let (sources, lines) = checked(&table, &agent_writes(&output));
    sources.expect("a grant beside the program is not refused");
    assert_eq!(lines, line);
    // A configuration that declares no source judges no list here, also a list that the
    // judgement refuses, so its checks keep their order.
    let (refused, lines) = checked(&table, &agent_writes(&link));
    assert!(
        refused.is_err(),
        "the judgement refuses a list entry that is a symbolic link"
    );
    assert_eq!(lines, "");
    let (sources, lines) = checked("", &agent_writes(&link));
    sources.expect("no source, no judgement");
    assert_eq!(lines, "");
    assert_eq!(program.runs(), 0, "the check starts no program");
}

/// **The check skips an entry whose path is absent, where only a present path is protected, and
/// names it after the line of its source**, also in a configuration with no process table.
#[test]
fn an_absent_path_of_a_source_is_skipped_and_named_with_no_process_table() {
    let program = StandIn::new(PRINTER);
    let (store, socket) = (
        program.path().join("store"),
        program.path().join("later/sock"),
    );
    let quoted = |path: &Path| toml::Value::String(path.display().to_string()).to_string();
    let table = format!(
        "{}reads = [{}]\ndeny = [{}]\n",
        program.table("op", Path::new(SHELL)),
        quoted(&store),
        quoted(&socket)
    );
    let line = format!(
        "strands-box: [secret-source.op]: reads each op:// secret with {SHELL}, which runs \
         outside every sandbox\n"
    );
    let skipped = |list: &str, path: &Path| {
        format!(
            "strands-box: [secret-source.op]: `{list}` entry {:?} names {}, which does not \
             exist when the box starts, so no sandbox denies it in this run\n",
            path.display().to_string(),
            path.display()
        )
    };

    let (sources, lines) = checked(&table, &no_tables());
    sources.expect("an absent path stops no box");
    if cfg!(target_os = "linux") {
        let (reads, deny) = (skipped("reads", &store), skipped("deny", &socket));
        assert_eq!(lines, format!("{line}{reads}{deny}"));
    } else {
        assert_eq!(
            lines, line,
            "a path that is absent is protected by its name"
        );
    }
    std::fs::create_dir(&store).expect("the folder is made");
    let (sources, lines) = checked(&table, &no_tables());
    sources.expect("the path is there");
    if cfg!(target_os = "linux") {
        assert_eq!(lines, format!("{line}{}", skipped("deny", &socket)));
    } else {
        assert_eq!(lines, line);
    }
    // A link whose target holds a line break: the line spells the target escaped, as one line.
    let link = program.path().join("link");
    std::os::unix::fs::symlink("gone\nstrands-box: forged", &link).expect("the link is made");
    let table = format!(
        "{}deny = [{}]\n",
        program.table("op", Path::new(SHELL)),
        quoted(&link)
    );
    let (sources, lines) = checked(&table, &no_tables());
    sources.expect("an absent target stops no box");
    if cfg!(target_os = "linux") {
        assert_eq!(lines.lines().count(), 2, "{lines}");
        assert!(
            lines.contains("/gone\\nstrands-box: forged, which does not exist"),
            "{lines}"
        );
    }
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
fn a_check_for_references_checks_no_table_that_no_reference_reads() {
    let program = StandIn::new(PRINTER);
    // The program of this table does not exist, and the feature is off.
    let entries = crate::record::config::secret_source::tests::entries(
        &program.table("op", &program.path().join("absent")),
    );
    let check = |references: &[&str]| {
        let mut lines = Vec::new();
        let sources = SecretSources::check_for_references(
            &entries,
            false,
            &no_tables(),
            references.iter().copied(),
            &mut lines,
        );
        assert_eq!(
            lines, b"",
            "a table that is not checked or is refused has no line"
        );
        sources.map_err(|refusal| refusal.to_string())
    };

    for references in [
        &[][..],
        // `credentials` routes none of these to the declared scheme.
        &[
            "env://GH_TOKEN",
            "vault://kv/key",
            "op",
            "op://",
            " op://item",
            "OP://item",
        ],
    ] {
        let sources = check(references).expect("no reference reads the table");
        assert_eq!(
            format!("{:?}", sources.backend()),
            format!("{:?}", Backend::local())
        );
        assert!(!sources.reads("op://Personal/GitHub/token"));
    }
    // A reference in the declared scheme makes the check of a run, which refuses this table.
    let refusal =
        check(&["env://GH_TOKEN", "op://Personal/GitHub/token"]).expect_err("the table is checked");
    assert!(
        refusal.starts_with("invalid `[secret-source.op]` table: "),
        "{refusal}"
    );
    assert_eq!(program.runs(), 0);
}

#[test]
fn the_sources_read_no_secret_after_the_vaults_take_them() {
    let program = StandIn::new(PRINTER);
    let record = record(
        r#"
        [egress.github]
        destinations = ["api.github.com"]
        secret.ref = "op://item"
        secret.env = "GH_TOKEN"
        "#,
    );
    let sources = printer_sources(&program).reading(&record);
    // A clone that a later step kept shares the one set of sources.
    let kept = sources.backend().clone();
    let (_, telemetry) = sources.fetch_telemetry(std::io::sink());
    let (_, routes) = telemetry
        .expect("no telemetry secret")
        .fetch_routes(std::io::sink());
    let routes = routes.expect("the program returns the secret");
    assert_eq!(read(&kept, "op://item"), Ok("tok-item".to_string()));
    assert_eq!(program.runs(), 1);

    // The vaults consume the value, and its end closes each declared source.
    drop(routes);
    assert_eq!(read(&kept, "op://item"), Err(CLOSED.to_string()));
    assert_eq!(read(&kept, "op://other"), Err(CLOSED.to_string()));
    assert_eq!(program.runs(), 1);

    // The sources of a run that stops before a read close as well.
    let unread = printer_sources(&program);
    let kept = unread.backend().clone();
    drop(unread);
    assert_eq!(read(&kept, "op://item"), Err(CLOSED.to_string()));
    assert_eq!(program.runs(), 1);
}

/// Each function of the text `source` that another module can call, with the type that holds
/// it, and with `(run)` after one that only a module of `crate::run` can call.
fn doors(source: &str) -> Vec<String> {
    let mut holder = "";
    let mut doors = Vec::new();
    for line in source.lines() {
        if let Some(name) = line.strip_prefix("impl ") {
            holder = name.trim_end_matches(" {");
        } else {
            let line = line.trim_start();
            let (function, reach) = match line.strip_prefix("pub(crate) fn ") {
                Some(function) => (function, ""),
                None => match line.strip_prefix("pub(in crate::run) fn ") {
                    Some(function) => (function, " (run)"),
                    None => continue,
                },
            };
            let name = function
                .split(|character: char| !character.is_alphanumeric() && character != '_')
                .next()
                .unwrap_or_default();
            doors.push(format!("{holder}::{name}{reach}"));
        }
    }
    doors
}

/// **Only the check builds the sources, and only the sources read**: the module gives no other
/// door, and no field, so a caller cannot read a secret before the check or after the vaults,
/// and `command::run` gets no backend from the sources of a run.
#[test]
fn only_the_check_builds_the_sources_and_only_they_read() {
    let source = include_str!("../secret_sources.rs");
    assert_eq!(
        doors(source),
        [
            "Fetched::record",
            // The two doors in: each one runs the whole check.
            "SecretSources::check",
            "SecretSources::check_for_references",
            // The two reads: each one takes the value of the step before it.
            "SecretSources::fetch_telemetry",
            // The backend of a run, for the collector and the vaults in `crate::run` alone.
            "TelemetrySecrets::backend (run)",
            "TelemetrySecrets::fetch_routes",
            "RouteSecrets::backend (run)",
            // `policy generate-schema`, whose type has no read step and reaches no vault.
            "SchemaSecrets::reads",
            "SchemaSecrets::backend",
        ]
    );
    let test_only = source.matches("cfg(test)").count();
    assert_eq!(test_only, 1, "the one test item is the test module");
    for line in source.lines() {
        let line = line.trim_start();
        assert!(
            !line.starts_with("pub ") && !line.starts_with("pub(super)"),
            "an item that another crate or module sees: {line}"
        );
        let field = line.starts_with("pub(crate) ")
            && !line.starts_with("pub(crate) fn ")
            && !line.starts_with("pub(crate) struct ")
            && !line.starts_with("pub(crate) mod tests;");
        assert!(
            !field,
            "a field or an item that a caller can build with: {line}"
        );
    }
    // Each visible item is a door above, one of the five types, or the test module, so no
    // field of a tuple and no other `pub(in ...)` item is a door.
    let visible = source.matches("pub(").count() + source.matches("pub ").count();
    assert_eq!(visible, doors(source).len() + 5 + 1, "a visible item");
    // No trait builds, copies, or opens a state.
    let implementations: Vec<&str> = source
        .lines()
        .filter(|line| line.starts_with("impl"))
        .collect();
    assert_eq!(
        implementations,
        [
            "impl Fetched {",
            "impl SecretSources {",
            "impl Drop for SecretSources {",
            "impl TelemetrySecrets {",
            "impl RouteSecrets {",
            "impl SchemaSecrets {",
        ]
    );
    // No other file of the module holds a door.
    let modules: Vec<&str> = source
        .lines()
        .filter(|line| line.contains("mod "))
        .collect();
    assert_eq!(modules, ["pub(crate) mod tests;"]);
    // No state of the sources is copied or built from nothing.
    for state in [
        "SecretSources",
        "TelemetrySecrets",
        "RouteSecrets",
        "SchemaSecrets",
    ] {
        let declared = source
            .split_once(&format!("\npub(crate) struct {state}"))
            .expect("the module declares the state")
            .0;
        let attribute = declared.rsplit('\n').next().unwrap_or_default();
        assert_eq!(attribute, "#[derive(Debug)]", "for {state}");
    }
}

/// Each file under `src` whose text holds one of `names`.
fn files_that_name(names: &[&str]) -> Vec<String> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut folders = vec![source.clone()];
    while let Some(folder) = folders.pop() {
        for entry in std::fs::read_dir(&folder).expect("the source folder lists") {
            let path = entry.expect("an entry of the source folder").path();
            if path.is_dir() {
                folders.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).expect("the source file reads");
                if names.iter().any(|name| text.contains(name)) {
                    let file = path.strip_prefix(&source).expect("a file under `src`");
                    files.push(file.display().to_string());
                }
            }
        }
    }
    files.sort();
    files
}

/// **One file builds a declared backend, and one command gets the sources that have no read
/// step**: no other file of the crate names either door, so a run reads a declared secret
/// through its own checked sources alone.
#[test]
fn only_generate_schema_reads_a_declared_secret_with_no_read_step() {
    // This file is in each list, because it names both doors here.
    assert_eq!(
        files_that_name(&["Backend::declared"]),
        ["run/secret_sources.rs", "run/secret_sources/tests.rs"]
    );
    assert_eq!(
        files_that_name(&["check_for_references", "SchemaSecrets"]),
        [
            "command/policy.rs",
            "run/secret_sources.rs",
            "run/secret_sources/tests.rs",
        ]
    );
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
