//! `run`: one locked configuration snapshot and one contained agent.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use policy::{Policy, ToolGrammars};

use crate::error::{BoxError, ConfigError, DaemonError};
use crate::record::config::process::ProcessSpec;
use crate::record::config::{
    AuthoritySource, ConfigureRequest, Record, RunContract, trailing_arguments,
};
use crate::record::layout::BoxRoot;
use crate::run::commands::ConfiguredCommands;
use crate::run::contain::boundary::{
    Boundary, EgressMode, Launch, RuntimeReach, ShebangInterpreters, Site, file_watching_disclosure,
};
use crate::run::contain::supervise::Contained;
use crate::run::hosted::HostedBox;
use crate::run::lock::Lock;
use crate::run::secret_sources::{SecretSources, TelemetrySecrets};
use crate::run::telemetry;

/// One locked box, before this run holds any authority over it.
struct LockedRun {
    root: BoxRoot,
    record: Record,
    /// The agent's effective working directory, canonical.
    workspace: PathBuf,
    /// The arguments `run` appends to `[agent] command`.
    trailing: Vec<String>,
    policy: Option<Policy>,
    grammars: ToolGrammars,
    /// The program each grammar in `grammars` decides, including a left-out tool's.
    grammar_programs: std::collections::BTreeSet<String>,
    sources: Vec<AuthoritySource>,
    owned: Lock,
}

impl LockedRun {
    fn announce_credential_stores(&self) -> Result<(), BoxError> {
        let operator_home = crate::record::layout::operator_home_directory()?;
        let mut stderr = std::io::stderr().lock();
        write_credential_stores(&self.record, &operator_home, &mut stderr)
            .map_err(|source| ConfigError::Disclosure { source })?;
        Ok(())
    }
}

/// Every credential store a process names exactly, announced before anything runs.
fn write_credential_stores(
    record: &Record,
    operator_home: &Path,
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    let tables = record
        .agent
        .iter()
        .map(|spec| ("[agent]".to_string(), spec))
        .chain(
            record
                .tool
                .iter()
                .map(|(label, spec)| (format!("[tool.{label}]"), spec)),
        );
    for (table, spec) in tables {
        for (kind, spelling) in spec.credential_store_entries(operator_home) {
            let spelling: String = spelling.chars().flat_map(char::escape_default).collect();
            writeln!(
                output,
                "strands-box: {table}: exposes {spelling} ({})",
                kind.key()
            )?;
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
pub(crate) struct NativeSetup {
    contract: Option<RunContract>,
    guard: std::io::Result<Option<Arc<crate::run::native_enforcement::EntryGuard>>>,
}

#[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
pub(super) fn prepare_native(config: &Path, has_callback: bool) -> Result<NativeSetup, BoxError> {
    let contract = if has_callback {
        None
    } else {
        Some(read_contract(config)?)
    };
    let enabled = contract
        .as_ref()
        .is_none_or(RunContract::uses_native_filesystem);
    let guard = crate::run::native_enforcement::EntryGuard::prepare(enabled);
    if guard.is_err() {
        crate::run::native_enforcement::EntryGuard::prepare(false).map_err(|source| {
            crate::error::SuperviseError::Control {
                reason: format!("native filesystem capability removal failed: {source}"),
            }
        })?;
    }
    Ok(NativeSetup { contract, guard })
}

/// The program that each `[tool]` grammar in `record` decides.
fn grammar_programs(record: &Record) -> std::collections::BTreeSet<String> {
    record
        .tool
        .values()
        .filter(|spec| spec.grammar.is_some())
        .filter_map(crate::record::config::grammar::bound_name)
        .map(str::to_string)
        .collect()
}

/// One line for each `[tool]` and stdio `[mcp]` whose program a tool grammar of `programs` decides
/// in place of `shell:spawn`.
fn write_grammar_disclosures(
    record: &Record,
    programs: &std::collections::BTreeSet<String>,
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    use crate::record::config::grammar::{bound_name, called_name};
    let tables =
        record
            .tool
            .iter()
            .filter_map(|(label, spec)| Some((format!("[tool.{label}]"), bound_name(spec)?)))
            .chain(record.contained_mcp.iter().map(|(label, contained)| {
                (format!("[mcp.{label}]"), called_name(&contained.spec))
            }));
    for (table, program) in tables {
        if programs.contains(program) {
            writeln!(
                output,
                "strands-box: {table}: a spawn of `{program}` is decided by its tool grammar, and \
                 no `shell:spawn` rule applies to it"
            )?;
        }
    }
    Ok(())
}

/// What a bare `python3` or `python` runs when the bare-name lines don't already say it: with
/// `monty = false`, each name no tool answers, which the host's `PATH` resolves; with Monty on,
/// each tool declared under either name, which Monty leaves unused.
fn write_monty_disclosures(
    record: &Record,
    names: &crate::run::commands::BareNames,
    search_path: &std::ffi::OsStr,
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    use crate::record::config::grammar::bound_name;
    let escaped = |text: &str| -> String { text.chars().flat_map(char::escape_default).collect() };
    for name in ["python3", "python"] {
        if !record.monty && !names.declared.contains_key(name) {
            match crate::run::contain::executable::find_on(name, search_path) {
                Some(path) => writeln!(
                    output,
                    "strands-box: monty = false and no [tool] answers `{name}`, so a bare \
                     `{name}` in the Shell runs {}, the file `PATH` finds",
                    escaped(&path.to_string_lossy())
                )?,
                None => writeln!(
                    output,
                    "strands-box: monty = false and neither a [tool] nor `PATH` has `{name}`, so \
                     a bare `{name}` in the Shell is not found"
                )?,
            }
        }
        if record.monty {
            for (label, spec) in &record.tool {
                if bound_name(spec) == Some(name) {
                    writeln!(
                        output,
                        "strands-box: [tool.{label}]: not used for a bare `{name}`, because Monty \
                         answers it; set monty = false at the top of box.toml to use the tool"
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// One line for each `[tool]` this run leaves out because its program is not installed.
fn write_left_out_tools(
    left_out: &[crate::run::commands::LeftOut],
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    for tool in left_out {
        let program: String = tool
            .program
            .chars()
            .flat_map(char::escape_default)
            .collect();
        writeln!(
            output,
            "strands-box: {} left out: {program} not found",
            tool.table
        )?;
    }
    Ok(())
}

/// Disclose each telemetry target that receives MCP tool-call values in clear text.
fn write_tool_call_disclosures(
    record: &Record,
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    for (label, entry) in &record.telemetry {
        if entry.takes_tool_calls() {
            writeln!(
                output,
                "strands-box: [telemetry.{label}] names mcp_tool_calls, so {} receives each MCP tool \
                 call's arguments and output in clear text, including any secret a tool takes or \
                 returns",
                entry.shown_destination()
            )?;
        }
    }
    Ok(())
}

/// One line for each bare name a `[tool]` answers to in the hosted Shell, and the file it runs.
fn write_bare_name_disclosures(
    names: &crate::run::commands::BareNames,
    mut output: impl std::io::Write,
) -> std::io::Result<()> {
    let escaped = |text: &str| -> String { text.chars().flat_map(char::escape_default).collect() };
    for (name, (path, tables)) in &names.declared {
        writeln!(
            output,
            "strands-box: {}: a bare `{}` in the Shell runs {}",
            tables.join(", "),
            escaped(name),
            escaped(&path.to_string_lossy())
        )?;
    }
    for (name, tables) in &names.passed_over {
        writeln!(
            output,
            "strands-box: {}: runs another program path, so a bare `{}` in the Shell runs \
             the file of `[tool.{}]`, whose label is that name",
            tables.join(", "),
            escaped(name),
            escaped(name)
        )?;
    }
    for (name, tables) in &names.shared {
        writeln!(
            output,
            "strands-box: {}: these tables run different program paths, so a bare `{}` \
             in the Shell runs the file that `PATH` finds",
            tables.join(", "),
            escaped(name)
        )?;
    }
    Ok(())
}

/// Run one contained agent from one locked configuration snapshot.
pub(crate) async fn execute(
    config: &Path,
    argv: &[OsString],
    terminal: Option<std::fs::File>,
    signals: Option<crate::run::contain::supervise::Signals>,
    box_id: Option<&str>,
    policy_decisions: Option<crate::PolicyDecisionSender>,
    #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
    native_setup: NativeSetup,
) -> Result<ExitCode, BoxError> {
    #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
    let ((locked, secrets), entry_guard) = {
        let NativeSetup { contract, guard } = native_setup;
        let contract = match contract {
            Some(contract) => contract,
            None => read_contract(config)?,
        };
        let guard = if contract.uses_native_filesystem() {
            Some(
                guard
                    .map_err(|source| crate::error::SuperviseError::Control {
                        reason: format!("native filesystem setup failed: {source}"),
                    })?
                    .ok_or_else(|| crate::error::SuperviseError::Control {
                        reason: "native filesystem interception requires CAP_BPF and CAP_PERFMON"
                            .to_string(),
                    })?,
            )
        } else {
            drop(guard);
            None
        };
        (prepare_contract(contract, config, argv, box_id)?, guard)
    };
    #[cfg(not(all(target_os = "linux", feature = "native-filesystem-policy")))]
    let (locked, secrets) = prepare(config, argv, box_id)?;
    locked.announce_credential_stores()?;
    // No collector exists yet, so a read that fails here is stated on stderr alone.
    let (fetched, secrets) =
        off_the_worker(move || secrets.fetch_telemetry(std::io::stderr())).await;
    let secrets = secrets?;
    let collector = telemetry::open(&locked.root, &locked.record, &secrets)?;
    let name = locked.root.name().to_string();
    collector.control(telemetry::ControlRecord::completed(
        telemetry::ControlOperation::BoxStarted,
        &name,
    ));
    for read in &fetched {
        collector.control(read.record());
    }

    let outcome = hosted(
        locked,
        secrets,
        Arc::clone(&collector),
        policy_decisions,
        terminal,
        signals,
        #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
        entry_guard,
    )
    .await;

    // The one teardown point, so every exit above records the stop and every queued record
    // reaches its target. `drained` is the only route out of the collector's queue, and the
    // `?`-returns above reach no `HostedBox` to drain from. A workload that exits non-zero is
    // still `Ok`, because the box did its work; only a `BoxError` is the box's own failure.
    collector.control(match &outcome {
        Ok(_) => {
            telemetry::ControlRecord::completed(telemetry::ControlOperation::BoxStopped, &name)
        }
        Err(refusal) => telemetry::ControlRecord::refused(
            telemetry::ControlOperation::BoxStopped,
            &name,
            &refusal.to_string(),
        ),
    });
    collector.drained().await;
    outcome
}

/// Run one read of the declared secrets off the async worker, because a program can take its
/// whole timeout.
async fn off_the_worker<Read: Send + 'static>(
    read: impl FnOnce() -> Read + Send + 'static,
) -> Read {
    tokio::task::spawn_blocking(read)
        .await
        .expect("the secret source task panicked")
}

/// Open this box's authority, translate every declared process, and supervise the agent.
async fn hosted(
    locked: LockedRun,
    secrets: TelemetrySecrets,
    collector: Arc<telemetry::Collector>,
    policy_decisions: Option<crate::PolicyDecisionSender>,
    terminal: Option<std::fs::File>,
    signals: Option<crate::run::contain::supervise::Signals>,
    #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))] entry_guard: Option<
        std::sync::Arc<crate::run::native_enforcement::EntryGuard>,
    >,
) -> Result<ExitCode, BoxError> {
    let sources: Vec<Policy> = locked.policy.into_iter().collect();
    let subject = telemetry::policy_subject(&sources);
    let operator = crate::record::config::policy_operator()?;
    let policy = match HostedBox::prepare_policy(&locked.root, &operator, sources, locked.grammars)
    {
        Ok(engine) => {
            for warning in engine.warnings() {
                eprintln!("strands-box: warning: {warning}");
            }
            collector.control(telemetry::ControlRecord::completed(
                telemetry::ControlOperation::PolicyInstalled,
                &subject,
            ));
            engine
        }
        Err(refusal) => {
            collector.control(telemetry::ControlRecord::refused(
                telemetry::ControlOperation::PolicyRefused,
                &subject,
                &refusal.to_string(),
            ));
            return Err(refusal);
        }
    };

    // Validate any declared credsd credential, and sign once with each telemetry `aws://` profile,
    // before the workload starts, so a missing daemon, an unusable environment, or a profile that
    // cannot sign fails here rather than at the first signed request. The checks do blocking I/O
    // with a per-environment deadline, so run them off the async worker: a slow or hung daemon then
    // delays this startup alone and never stalls the runtime.
    let egress = locked.record.egress.clone();
    let remote_mcp = locked.record.remote_mcp.clone();
    let telemetry_targets = locked.record.telemetry.clone();
    tokio::task::spawn_blocking(move || {
        crate::run::credential::preflight_credsd(&egress, &remote_mcp, &telemetry_targets)?;
        crate::record::config::telemetry::preflight_aws(&telemetry_targets)
    })
    .await
    .expect("the credential preflight task panicked")?;

    let agent = locked
        .record
        .agent
        .clone()
        .ok_or(ConfigError::EmptyWorkload)?;
    let home = agent_home(&agent)?;
    let commands = Arc::new(ConfiguredCommands::load(&locked.record)?);
    let policy = Arc::new(HostedBox::bind_tool_grammars(
        policy,
        &locked.record,
        &commands,
        &crate::run::contain::executable::host_search_path(),
    )?);
    write_grammar_disclosures(
        &locked.record,
        &locked.grammar_programs,
        std::io::stderr().lock(),
    )
    .map_err(|source| ConfigError::Disclosure { source })?;
    let search_path = crate::run::contain::executable::host_search_path();
    let names = commands.bare_names(&locked.record, &search_path);
    write_bare_name_disclosures(&names, std::io::stderr().lock())
        .map_err(|source| ConfigError::Disclosure { source })?;
    write_monty_disclosures(
        &locked.record,
        &names,
        &search_path,
        std::io::stderr().lock(),
    )
    .map_err(|source| ConfigError::Disclosure { source })?;
    // Read each other secret that a declared source holds, after the checks above, which need
    // none, so no vault program runs for a box that one of them stops. The checks of
    // `HostedBox::open` come after this read.
    let (fetched, secrets) = off_the_worker(move || secrets.fetch_routes(std::io::stderr())).await;
    for read in &fetched {
        collector.control(read.record());
    }
    let secrets = secrets?;

    write_tool_call_disclosures(&locked.record, std::io::stderr().lock())
        .map_err(|source| ConfigError::Disclosure { source })?;
    eprintln!("strands-box: starting workload");
    let control = Arc::clone(&collector);
    let hosted = HostedBox::open(
        &locked.root,
        &locked.record,
        policy,
        commands,
        collector,
        policy_decisions,
        secrets,
        &locked.sources,
        locked.owned,
        &locked.workspace,
        &home,
        #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
        entry_guard,
    )?;
    let site = Site {
        attachment: hosted.attachment(),
        layout: &locked.root,
        stored: &locked.record,
        protected_sources: &locked.sources,
    };
    for (label, spec) in &locked.record.tool {
        let table = format!("[tool.{label}]");
        let boundary = Boundary::translate(
            spec,
            Launch {
                table: &table,
                trailing: &[],
                fallback_workspace: &locked.workspace,
                shebang_interpreters: ShebangInterpreters::Granted,
                runtime_reach: RuntimeReach::Leaf,
                argument_zero: None,
                egress: EgressMode::for_spec(spec),
                approved: hosted.approved().table(&table),
            },
            &site,
        )?;
        eprintln!("{}", boundary.disclosure());
    }
    for (label, contained) in &locked.record.contained_mcp {
        let table = format!("[mcp.{label}]");
        let reach = hosted
            .approved()
            .table(&table)
            .ok_or_else(|| ConfigError::Contract {
                reason: format!("{table} has no reach judged for this run"),
            })?;
        eprintln!("strands-box: {table} starts on demand; approved direct filesystem grants:");
        for grant in &reach.grants {
            eprintln!("{}", grant.disclosure());
        }
        if cfg!(target_os = "macos") && contained.spec.file_watching {
            eprintln!("{}", file_watching_disclosure(&table));
        }
    }
    let boundary = Boundary::translate(
        &agent,
        Launch {
            table: "[agent]",
            trailing: &locked.trailing,
            fallback_workspace: &locked.workspace,
            shebang_interpreters: ShebangInterpreters::Granted,
            // A harness reads its own configuration and talks to a model. It compiles nothing, so it
            // receives no part of leaf containment — the frameworks and loader libraries belong to
            // a tool's leaf.
            runtime_reach: RuntimeReach::Agent,
            argument_zero: None,
            egress: EgressMode::Gateway,
            approved: hosted.approved().table("[agent]"),
        },
        &site,
    )?;
    eprintln!("{}", boundary.disclosure());
    // The record waits for the trampoline's `exec` to succeed, so a containment or `exec` failure
    // after the spawn writes none.
    let name = locked.root.name().to_string();
    let contained = Contained::spawn(
        boundary,
        &locked.root,
        hosted,
        terminal,
        signals,
        move || {
            control.control(telemetry::ControlRecord::completed(
                telemetry::ControlOperation::WorkloadStarted,
                &name,
            ));
        },
    )
    .await?;
    contained.wait().await
}

/// The agent's `HOME`: its `env.HOME`, else the operator's own home.
fn agent_home(agent: &ProcessSpec) -> Result<PathBuf, BoxError> {
    match agent.env.get("HOME") {
        Some(home) => Ok(PathBuf::from(home)),
        None => crate::record::layout::operator_home_directory(),
    }
}

fn read_contract(config: &Path) -> Result<RunContract, BoxError> {
    let invocation = std::env::current_dir().map_err(|source| ConfigError::Read {
        path: PathBuf::from("."),
        source,
    })?;
    RunContract::read(config, &invocation)
}

#[cfg(not(all(target_os = "linux", feature = "native-filesystem-policy")))]
fn prepare(
    config: &Path,
    argv: &[OsString],
    box_id: Option<&str>,
) -> Result<(LockedRun, SecretSources), BoxError> {
    prepare_contract(read_contract(config)?, config, argv, box_id)
}

/// The tools of one run, chosen once.
#[derive(Debug)]
struct SettledTools {
    /// The stored record without each tool that the run leaves out.
    record: Record,
    /// Each tool that the run leaves out, or the refusal of that choice.
    left_out: Result<Vec<crate::run::commands::LeftOut>, BoxError>,
}

/// The tools that one run of `stored` keeps, and the secret sources that `check` gives for the
/// record with those tools alone.
fn settle_tools(
    stored: &Record,
    check: impl FnOnce(&Record) -> Result<SecretSources, BoxError>,
) -> Result<(SettledTools, SecretSources), BoxError> {
    let mut record = stored.clone();
    // A refusal of this choice removes no tool, so the check then judges each table as written.
    let left_out = crate::run::commands::leave_out_absent(&mut record);
    let secrets = check(&record)?;
    Ok((SettledTools { record, left_out }, secrets))
}

/// Lock the box directory of `contract`, check its secret sources, and commit its record.
fn prepare_contract(
    contract: RunContract,
    config: &Path,
    argv: &[OsString],
    box_id: Option<&str>,
) -> Result<(LockedRun, SecretSources), BoxError> {
    #[cfg(all(target_os = "macos", feature = "native-filesystem-policy"))]
    if contract.experimental_features().native_filesystem_policy {
        crate::run::native_enforcement::preflight()?;
    }
    #[cfg(all(target_os = "linux", feature = "native-filesystem-policy"))]
    if contract.uses_native_filesystem() {
        crate::run::native_enforcement::preflight()?;
    }
    contract.validate_declared_directory()?;
    let (mut root, root_lock) = BoxRoot::lock_directory(contract.box_directory())?;
    contract.validate_directory(root.root())?;
    root.settle_identity(box_id)?;
    let workspace = contract.workspace().to_path_buf();
    let request = contract.into_request(&root)?;
    let existed = root.is_configured();
    request.verify_sources()?;
    // The one check of the declared sources: each program file, each table that lets a workload
    // go around a source, and one line for each source. Only the value that it returns reads a
    // secret, and only through its two read steps: it gives no backend to this module. It starts
    // no program and reads no box state, and it comes before the record is committed, so a
    // refusal stores nothing in a new box directory, as a refusal of the configuration does. The
    // tools that this run leaves out are chosen first, once, so the check judges each table that
    // this run starts and no other. The `left out` lines and a refusal of that choice come after
    // the record is stored.
    let (SettledTools { record, left_out }, secrets) = settle_tools(&request.record, |record| {
        SecretSources::check(record, &request.sources, std::io::stderr())
    })?;
    if existed {
        root.initialize()?;
    } else {
        root.initialize_first_use(&request.record)?;
    }
    let owned = acquire_run_lock(&root)?;
    root.verify_history_matches_record()?;

    let aliased = request.record.mcp.clone();
    if !existed || !project_matches_record(&request, &root)? {
        crate::run::configure::write(&root, &request, &owned)?;
        let state = if existed { "updated" } else { "created" };
        eprintln!(
            "strands-box: box {} {state} · config {}",
            root.box_id(),
            config.display()
        );
    } else if crate::run::broker::aliases::is_stale(&root, &aliased) {
        crate::run::broker::aliases::materialize(&root, &aliased, &owned)?;
        eprintln!("strands-box: box {} alias image refreshed", root.box_id());
    }

    request.verify_sources()?;
    drop(root_lock);
    // The grammars of the record as written decide a program by its name, for a left-out tool too.
    let grammar_programs = grammar_programs(&request.record);
    let left_out = left_out?;
    write_left_out_tools(&left_out, std::io::stderr().lock())
        .map_err(|source| ConfigError::Disclosure { source })?;
    let locked = LockedRun {
        root,
        record,
        workspace,
        trailing: trailing_arguments(argv)?,
        policy: request.policy,
        grammars: request.grammars,
        grammar_programs,
        sources: request.sources,
        owned,
    };
    Ok((locked, secrets))
}

fn acquire_run_lock(root: &BoxRoot) -> Result<Lock, BoxError> {
    let path = root.lock();
    let file = root
        .open_lock_file(true)?
        .expect("creating the ownership lock returns one file");
    Lock::try_acquire_file(file, &path)?.ok_or_else(|| {
        DaemonError::AlreadyRunning {
            name: root.name().to_string(),
        }
        .into()
    })
}

fn project_matches_record(request: &ConfigureRequest, root: &BoxRoot) -> Result<bool, BoxError> {
    if root.read_record()? != request.record {
        return Ok(false);
    }
    let stored_policy = root.read_policy()?;
    let authored_policy = request.policy.as_ref().map(|source| source.text.clone());
    Ok(stored_policy == authored_policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::record::config::RECORD_VERSION;
    use crate::record::config::process::Filesystem;

    fn record_with(agent: Option<ProcessSpec>, tools: BTreeMap<String, ProcessSpec>) -> Record {
        Record {
            version: RECORD_VERSION,
            experimental_features: Default::default(),
            file_attributes: false,
            monty: true,
            gateway: Default::default(),
            limits: Default::default(),
            box_id: "box-0123456789abcdef".to_string(),
            box_dir: PathBuf::from("/var/lib/boxes/probe"),
            name: "probe".to_string(),
            policy: None,
            agent,
            tool: tools,
            egress: BTreeMap::new(),
            remote_mcp: BTreeMap::new(),
            mcp: Vec::new(),
            contained_mcp: BTreeMap::new(),
            telemetry: BTreeMap::new(),
            secret_source: Default::default(),
        }
    }

    fn spec(command: &str, read: &[&str], write: &[&str]) -> ProcessSpec {
        ProcessSpec {
            file_watching: false,
            native_filesystem_policy: None,
            command: vec![command.to_string()],
            workspace: None,
            env: BTreeMap::new(),
            filesystem: Filesystem {
                read: read.iter().map(PathBuf::from).collect(),
                write: write.iter().map(PathBuf::from).collect(),
                ..Filesystem::default()
            },
            network: None,
            grammar: None,
            ingress: Vec::new(),
        }
    }

    #[test]
    fn startup_announces_each_credential_store_and_operation() {
        let record = record_with(
            Some(spec("claude", &["~/.gitconfig"], &[])),
            BTreeMap::from([(
                "aws-suite".to_string(),
                spec("aws", &["~/.aws", "~/.gitconfig"], &["~/.aws/sso/cache"]),
            )]),
        );
        let mut output = Vec::new();

        write_credential_stores(&record, Path::new("/Users/me"), &mut output)
            .expect("the announcement writes");

        assert_eq!(
            String::from_utf8(output).expect("the announcement is UTF-8"),
            "strands-box: [tool.aws-suite]: exposes ~/.aws (read)\n\
             strands-box: [tool.aws-suite]: exposes ~/.aws/sso/cache (write)\n"
        );
    }

    /// Only a target that names `mcp_tool_calls` is disclosed, because only it receives the values.
    #[test]
    fn startup_discloses_each_telemetry_target_that_takes_tool_calls() {
        use crate::record::config::telemetry::{SignalGroup, TelemetryEntry};
        let entry =
            |include: Option<Vec<SignalGroup>>| TelemetryEntry::file("/tmp/records.jsonl", include);
        let mut record = record_with(None, BTreeMap::new());
        record.telemetry = BTreeMap::from([
            (
                "local".to_string(),
                entry(Some(vec![SignalGroup::Deny, SignalGroup::McpToolCalls])),
            ),
            ("plain".to_string(), entry(None)),
            ("verdicts".to_string(), entry(Some(vec![SignalGroup::Deny]))),
        ]);
        let mut output = Vec::new();

        write_tool_call_disclosures(&record, &mut output).expect("the disclosure writes");

        assert_eq!(
            String::from_utf8(output).expect("the disclosure is UTF-8"),
            "strands-box: [telemetry.local] names mcp_tool_calls, so /tmp/records.jsonl receives each \
             MCP tool call's arguments and output in clear text, including any secret a tool takes \
             or returns\n"
        );
    }

    #[test]
    fn startup_discloses_each_tool_that_a_grammar_decides_under_its_bound_name() {
        let npm: ProcessSpec = toml::from_str(
            "command = [\"/usr/lib/node_modules/npm/bin/npm-cli.js\"]\n[grammar]\nformat = 1\n\
             program = \"npm\"\n",
        )
        .expect("the tool parses");
        let record = record_with(
            None,
            BTreeMap::from([
                ("npm".to_string(), npm),
                (
                    "brew_npm".to_string(),
                    spec("/opt/homebrew/bin/npm", &[], &[]),
                ),
                (
                    "npm_cli".to_string(),
                    spec("/opt/other/npm-cli.js", &[], &[]),
                ),
            ]),
        );
        let mut record = record;
        record.contained_mcp.insert(
            "wrapped".to_string(),
            crate::record::config::process::ContainedMcp {
                spec: spec("/opt/wrap/npm", &[], &[]),
            },
        );
        let mut output = Vec::new();

        write_grammar_disclosures(&record, &grammar_programs(&record), &mut output)
            .expect("the disclosure writes");

        assert_eq!(
            String::from_utf8(output).expect("the disclosure is UTF-8"),
            "strands-box: [tool.brew_npm]: a spawn of `npm` is decided by its tool grammar, and \
             no `shell:spawn` rule applies to it\n\
             strands-box: [tool.npm]: a spawn of `npm` is decided by its tool grammar, and no \
             `shell:spawn` rule applies to it\n\
             strands-box: [mcp.wrapped]: a spawn of `npm` is decided by its tool grammar, and no \
             `shell:spawn` rule applies to it\n"
        );
    }

    /// **A left-out tool's grammar is still disclosed for each tool that it decides**: a spawn of
    /// an installed `git` reads as the grammar of the `git` tool that the run leaves out.
    #[test]
    fn startup_discloses_a_left_out_tools_grammar_for_each_tool_it_still_decides() {
        let optional: ProcessSpec = toml::from_str(
            "command = [\"/nonexistent/strands-box/missing/git\"]\n[grammar]\nformat = 1\n\
             program = \"git\"\n",
        )
        .expect("the tool parses");
        let mut record = record_with(
            None,
            BTreeMap::from([
                ("optional_git".to_string(), optional),
                ("system_git".to_string(), spec("/usr/bin/git", &[], &[])),
            ]),
        );
        let programs = grammar_programs(&record);
        record.tool.remove("optional_git");
        let mut output = Vec::new();

        write_grammar_disclosures(&record, &programs, &mut output).expect("the disclosure writes");

        assert_eq!(
            String::from_utf8(output).expect("the disclosure is UTF-8"),
            "strands-box: [tool.system_git]: a spawn of `git` is decided by its tool grammar, \
             and no `shell:spawn` rule applies to it\n"
        );
    }

    /// **The startup notes say what a bare `python3` runs when the bare-name lines don't.** With
    /// Monty on, a tool declared under the name is reported unused; with `monty = false`, a name no
    /// tool answers is left to `PATH`; a name a tool answers gets only its bare-name line.
    #[test]
    fn startup_says_what_a_bare_python_runs() {
        let tools = BTreeMap::from([("python3".to_string(), spec("/venv/bin/python3", &[], &[]))]);
        let mut record = record_with(None, tools);
        let none = crate::run::commands::BareNames::default();
        let lines = |record: &Record,
                     names: &crate::run::commands::BareNames,
                     search_path: &std::ffi::OsStr| {
            let mut output = Vec::new();
            write_monty_disclosures(record, names, search_path, &mut output)
                .expect("the notes write");
            String::from_utf8(output).expect("UTF-8")
        };
        let empty = std::ffi::OsStr::new("");

        assert_eq!(
            lines(&record, &none, empty),
            "strands-box: [tool.python3]: not used for a bare `python3`, because Monty answers \
             it; set monty = false at the top of box.toml to use the tool\n"
        );

        record.monty = false;
        let answered = crate::run::commands::BareNames {
            declared: BTreeMap::from([(
                "python3".to_string(),
                (
                    PathBuf::from("/venv/bin/python3"),
                    vec!["[tool.python3]".to_string()],
                ),
            )]),
            ..Default::default()
        };
        assert_eq!(
            lines(&record, &answered, empty),
            "strands-box: monty = false and neither a [tool] nor `PATH` has `python`, so a bare \
             `python` in the Shell is not found\n"
        );

        let bin = tempfile::tempdir().expect("a PATH folder");
        let python = bin.path().join("python");
        std::fs::write(&python, "").expect("a python file");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        assert_eq!(
            lines(&record, &answered, bin.path().as_os_str()),
            format!(
                "strands-box: monty = false and no [tool] answers `python`, so a bare `python` in \
                 the Shell runs {}, the file `PATH` finds\n",
                python.display()
            )
        );
    }

    #[test]
    fn startup_names_the_file_each_bare_name_runs() {
        let names = crate::run::commands::BareNames {
            declared: BTreeMap::from([(
                "git".to_string(),
                (
                    PathBuf::from("/Dev/usr/bin/git"),
                    vec!["[tool.git]".to_string(), "[tool.git_status]".to_string()],
                ),
            )]),
            shared: BTreeMap::from([(
                "node".to_string(),
                vec!["[tool.brew_node]".to_string(), "[tool.node]".to_string()],
            )]),
            passed_over: BTreeMap::from([("git".to_string(), vec!["[tool.brew_git]".to_string()])]),
        };
        let mut output = Vec::new();

        write_bare_name_disclosures(&names, &mut output).expect("the disclosure writes");

        assert_eq!(
            String::from_utf8(output).expect("the disclosure is UTF-8"),
            "strands-box: [tool.git], [tool.git_status]: a bare `git` in the Shell runs \
             /Dev/usr/bin/git\n\
             strands-box: [tool.brew_git]: runs another program path, so a bare `git` in the Shell \
             runs the file of `[tool.git]`, whose label is that name\n\
             strands-box: [tool.brew_node], [tool.node]: these tables run different program paths, \
             so a bare `node` in the Shell runs the file that `PATH` finds\n"
        );
    }

    #[test]
    fn startup_names_each_tool_it_leaves_out() {
        let left_out = [
            crate::run::commands::LeftOut {
                table: "[tool.tsx]".to_string(),
                program: "tsx".to_string(),
            },
            crate::run::commands::LeftOut {
                table: "[tool.node]".to_string(),
                program: "/opt/node/bin/node\u{1b}[2J".to_string(),
            },
        ];
        let mut output = Vec::new();

        write_left_out_tools(&left_out, &mut output).expect("the disclosure writes");

        assert_eq!(
            String::from_utf8(output).expect("the disclosure is UTF-8"),
            "strands-box: [tool.tsx] left out: tsx not found\n\
             strands-box: [tool.node] left out: /opt/node/bin/node\\u{1b}[2J not found\n"
        );
    }

    /// **The check of the secret sources judges the tables of the tools that the run keeps**: a
    /// left-out tool brings no table to it, the same table refuses the run when its program is
    /// installed, and a refusal to leave a tool out waits for the check.
    #[cfg(unix)]
    #[test]
    fn the_secret_source_check_judges_no_table_of_a_left_out_tool() {
        use crate::run::secret_sources::tests::{PRINTER, StandIn};

        let program = StandIn::new(PRINTER);
        let folder = tempfile::tempdir().expect("a directory");
        let bin = folder.path().canonicalize().expect("canonical").join("bin");
        std::fs::create_dir(&bin).expect("the folder is made");
        let link = bin.join("op");
        std::os::unix::fs::symlink("/bin/sh", &link).expect("the link is made");
        let folder_of_the_source = bin.to_str().expect("UTF-8");
        let absent = bin.join("absent").display().to_string();
        // The tool reads and writes the folder that holds the program path of the source.
        let stored = |command: &str, grants: &[&str]| {
            let mut record = record_with(
                Some(spec("/bin/sh", &[], &[])),
                BTreeMap::from([("gone".to_string(), spec(command, grants, grants))]),
            );
            record.secret_source =
                crate::record::config::secret_source::tests::entries(&program.table("op", &link));
            record
        };
        let check = |record: &Record| SecretSources::check_for_tests(record, std::io::sink());

        let (SettledTools { record, left_out }, _) =
            settle_tools(&stored(&absent, &[folder_of_the_source]), check)
                .expect("no table of a left-out tool is judged");
        let installed = settle_tools(&stored("/bin/sh", &[folder_of_the_source]), check)
            .expect_err("the table of a tool that the run keeps is judged")
            .to_string();
        let unexpandable = bin.join("${ABSENT}").display().to_string();
        let (as_written, _) = settle_tools(&stored(&unexpandable, &[]), check)
            .expect("the check judges each table as written");
        let judged_as_written =
            settle_tools(&stored(&unexpandable, &[folder_of_the_source]), check)
                .expect_err("the check judges the table of a tool that the choice refuses")
                .to_string();

        assert_eq!(
            left_out.expect("the tool is left out"),
            [crate::run::commands::LeftOut {
                table: "[tool.gone]".to_string(),
                program: absent,
            }]
        );
        assert!(record.tool.is_empty());
        assert!(
            installed.starts_with("`[tool.gone]` filesystem entry")
                && installed.contains("this write grant can change [secret-source.op] command"),
            "{installed}"
        );
        assert!(
            as_written
                .left_out
                .expect_err("a program is never expanded")
                .to_string()
                .contains("a program is never expanded")
        );
        assert_eq!(as_written.record.tool.len(), 1);
        assert!(
            judged_as_written.starts_with("`[tool.gone]` filesystem entry")
                && judged_as_written
                    .contains("this write grant can change [secret-source.op] command"),
            "{judged_as_written}"
        );
        assert_eq!(program.runs(), 0, "the check starts no program");
    }

    #[test]
    fn startup_escapes_control_characters_in_a_stored_path() {
        let record = record_with(
            None,
            BTreeMap::from([(
                "aws-suite".to_string(),
                spec("aws", &["~/.aws/\u{1b}[2J\u{202e}"], &[]),
            )]),
        );
        let mut output = Vec::new();

        write_credential_stores(&record, Path::new("/Users/me"), &mut output)
            .expect("the announcement writes");

        assert_eq!(
            String::from_utf8(output).expect("the announcement is UTF-8"),
            "strands-box: [tool.aws-suite]: exposes ~/.aws/\\u{1b}[2J\\u{202e} (read)\n"
        );
    }
}
