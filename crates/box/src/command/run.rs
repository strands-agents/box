//! `run`: one locked configuration snapshot and one contained agent.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use policy::Policy;

use crate::error::{BoxError, ConfigError, DaemonError};
use crate::record::config::process::ProcessSpec;
use crate::record::config::{
    AuthoritySource, ConfigureRequest, Record, RunContract, trailing_arguments,
};
use crate::record::layout::BoxRoot;
use crate::run::contain::boundary::{
    Boundary, EgressMode, Launch, RuntimeReach, ShebangInterpreters, Site,
};
use crate::run::contain::supervise::Contained;
use crate::run::hosted::HostedBox;
use crate::run::lock::Lock;
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

/// Run one contained agent from one locked configuration snapshot.
pub(crate) async fn execute(config: &Path, argv: &[OsString]) -> Result<ExitCode, BoxError> {
    let locked = prepare(config, argv)?;
    locked.announce_credential_stores()?;
    let collector = telemetry::open(&locked.root, &locked.record)?;
    let name = locked.root.name().to_string();
    collector.control(telemetry::ControlRecord::completed(
        telemetry::ControlOperation::BoxStarted,
        &name,
    ));

    let outcome = hosted(locked, Arc::clone(&collector)).await;

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

/// Open this box's authority, translate every declared process, and supervise the agent.
async fn hosted(
    locked: LockedRun,
    collector: Arc<telemetry::Collector>,
) -> Result<ExitCode, BoxError> {
    let sources: Vec<Policy> = locked.policy.into_iter().collect();
    let subject = policy_subject(&sources);
    let operator = crate::record::config::policy_operator()?;
    let policy = match HostedBox::prepare_policy(&locked.root, &operator, sources) {
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

    // Validate any declared credsd credential before the workload starts, so a missing daemon or an
    // unusable environment fails here rather than at the first signed request. The check does
    // blocking socket I/O with a per-environment deadline, so run it off the async worker: a slow or
    // hung daemon then delays this startup alone and never stalls the runtime.
    let egress = locked.record.egress.clone();
    let remote_mcp = locked.record.remote_mcp.clone();
    tokio::task::spawn_blocking(move || {
        crate::run::credential::preflight_credsd(&egress, &remote_mcp)
    })
    .await
    .expect("the credsd preflight task panicked")?;

    let agent = locked
        .record
        .agent
        .clone()
        .ok_or(ConfigError::EmptyWorkload)?;
    let home = agent_home(&agent)?;
    eprintln!("strands-box: starting workload");
    let hosted = HostedBox::open(
        &locked.root,
        &locked.record,
        policy,
        collector,
        &locked.sources,
        locked.owned,
        &locked.workspace,
        &home,
    )?;
    let site = Site {
        attachment: hosted.attachment(),
        layout: &locked.root,
        stored: &locked.record,
        protected_sources: &locked.sources,
    };
    // Every tool is translated once now, so a tool that cannot run refuses the box before the agent
    // starts, and its grants are disclosed beside the agent's.
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
    let shares_proc = boundary.shares_proc();
    let recorder = Arc::clone(hosted.recorder());
    let contained = Contained::spawn(boundary, &locked.root, hosted).await?;
    if shares_proc {
        recorder.record(crate::run::telemetry::EffectiveDecision::shared_proc(
            "agent",
        ));
    }
    contained.wait().await
}

/// The agent's `HOME`: its `env.HOME`, else the operator's own home.
fn agent_home(agent: &ProcessSpec) -> Result<PathBuf, BoxError> {
    match agent.env.get("HOME") {
        Some(home) => Ok(PathBuf::from(home)),
        None => crate::record::layout::operator_home_directory(),
    }
}

fn prepare(config: &Path, argv: &[OsString]) -> Result<LockedRun, BoxError> {
    let invocation = std::env::current_dir().map_err(|source| ConfigError::Read {
        path: PathBuf::from("."),
        source,
    })?;
    let contract = RunContract::read(config, &invocation)?;
    contract.validate_declared_directory()?;
    let (mut root, root_lock) = BoxRoot::lock_directory(contract.box_directory())?;
    contract.validate_directory(root.root())?;
    root.settle_identity()?;
    let workspace = contract.workspace().to_path_buf();
    let request = contract.into_request(&root)?;
    let existed = root.is_configured();
    request.verify_sources()?;
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
    Ok(LockedRun {
        root,
        record: request.record,
        workspace,
        trailing: trailing_arguments(argv)?,
        policy: request.policy,
        sources: request.sources,
        owned,
    })
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

/// Which policy a control record names, by file name rather than by path.
fn policy_subject(sources: &[Policy]) -> String {
    if sources.is_empty() {
        return "<no authored policy>".to_string();
    }
    sources
        .iter()
        .map(|source| {
            source.origin.file_name().map_or_else(
                || source.origin.to_string_lossy().into_owned(),
                |name| name.to_string_lossy().into_owned(),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
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
            containment: Default::default(),
        }
    }

    fn spec(command: &str, read: &[&str], write: &[&str]) -> ProcessSpec {
        ProcessSpec {
            command: vec![command.to_string()],
            workspace: None,
            env: BTreeMap::new(),
            filesystem: Filesystem {
                read: read.iter().map(PathBuf::from).collect(),
                write: write.iter().map(PathBuf::from).collect(),
                ..Filesystem::default()
            },
            network: None,
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
