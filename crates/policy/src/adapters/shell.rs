//! Adapter from the policy facade to Strands Shell effect interception.

use std::collections::BTreeMap;
use std::io;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use strands_shell::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult,
    FsOperation as KernelFsOperation, FsPairOperation,
};

use crate::GovernedBox;
use crate::grammar::{
    CoverageRefusal, GrammarBindings, GrammarCoverage, GrammarInvocation, PendingGrammarResponse,
    ProgramFile,
};
use crate::outcome::FsResult;
use crate::path::{ApprovedPath, normalize_virtual};
use crate::request::FsOperation;
use crate::{Decision, Outcome, PolicyEngine, Principal, Request};

/// Binds one policy and Shell principal to the Shell effect-interception seam.
pub struct ShellPolicyInterceptor {
    policy: Arc<PolicyEngine>,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    /// The operator home a reported path is abbreviated against, when there is one.
    ///
    /// **This adapter mints its own [`ApprovedPath`], so it must report the same way
    /// `PathResolver` does.** The Shell resolves a path in its own VFS and hands the result over,
    /// which is why the mint is here rather than in the resolver — and it is also why a home set on
    /// the resolver alone had no effect on a Shell request. Measured: a `~`-relative rule denied a
    /// read of the project it named, because the decision still saw the host path.
    home: Option<std::path::PathBuf>,
    /// Credential paths keyed by the canonical identity a `shell:spawn` decision names.
    spawn_credentials: Arc<BTreeMap<String, Vec<String>>>,
    grammar_bindings: Arc<GrammarBindings>,
}

impl ShellPolicyInterceptor {
    /// Construct the Shell effect-interceptor handle.
    pub fn into_handle(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            policy,
            principal,
            governed,
            home: None,
            spawn_credentials: Arc::new(BTreeMap::new()),
            grammar_bindings: Arc::default(),
        })
    }

    /// Construct the handle, reporting every path under `home` as `~/<relative>`.
    ///
    /// A policy is checked into the operator's repository and must hold in every clone, and a host
    /// path holds only on the machine that wrote it. The effect is unaffected: `as_path` still
    /// answers the canonical identity the Shell resolved, and this crate keeps acting on that.
    pub fn into_handle_reporting_under(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
        home: impl Into<std::path::PathBuf>,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            policy,
            principal,
            governed,
            home: Some(home.into()),
            spawn_credentials: Arc::new(BTreeMap::new()),
            grammar_bindings: Arc::default(),
        })
    }

    /// Construct the handle with credential paths for selected host binaries.
    pub fn into_handle_with_spawn_credentials(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
        spawn_credentials: BTreeMap<String, Vec<String>>,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            policy,
            principal,
            governed,
            home: None,
            spawn_credentials: Arc::new(spawn_credentials),
            grammar_bindings: Arc::default(),
        })
    }

    /// Construct the reporting handle with credential paths for selected host binaries.
    pub fn into_handle_reporting_under_with_spawn_credentials(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
        home: impl Into<std::path::PathBuf>,
        spawn_credentials: BTreeMap<String, Vec<String>>,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            policy,
            principal,
            governed,
            home: Some(home.into()),
            spawn_credentials: Arc::new(spawn_credentials),
            grammar_bindings: Arc::default(),
        })
    }

    /// Construct the handle that decides a spawn of a program a tool grammar binds as its grammar
    /// action (docs/design/decisions.md#a-grammar-action-replaces-shell-spawn).
    #[cfg(test)]
    pub(crate) fn into_handle_with_grammar_bindings(
        policy: Arc<PolicyEngine>,
        principal: Principal,
        governed: GovernedBox,
        home: Option<std::path::PathBuf>,
        spawn_credentials: BTreeMap<String, Vec<String>>,
        grammar_bindings: GrammarBindings,
    ) -> Arc<dyn EffectInterceptor> {
        Arc::new(Self {
            policy,
            principal,
            governed,
            home,
            spawn_credentials: Arc::new(spawn_credentials),
            grammar_bindings: Arc::new(grammar_bindings),
        })
    }

    fn credential_reads(&self, program_path: &str) -> &[String] {
        credential_reads_for(&self.spawn_credentials, program_path)
    }

    fn permit(&self, admitted: Admitted) -> Box<dyn EffectPermit> {
        Box::new(PolicyEffectPermit {
            policy: Arc::clone(&self.policy),
            principal: self.principal.clone(),
            governed: self.governed.clone(),
            admitted,
            home: self.home.clone(),
        })
    }

    /// How the installed grammars cover a spawn of `program_path` spelled `program`, or `None` when
    /// `shell:spawn` decides it (docs/design/decisions.md#a-grammar-action-replaces-shell-spawn).
    fn grammar_coverage(&self, program: &str, program_path: &str) -> Option<GrammarCoverage<'_>> {
        if self.grammar_bindings.is_empty() {
            return None;
        }
        self.grammar_bindings
            .coverage(ProgramFile::read(program_path), program)
    }
}

fn denied(decision: &Decision) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, decision.to_string())
}

/// The denial for a spawn that Box refuses before any policy decides it.
fn refused_spawn(program_path: &str, refusal: &CoverageRefusal) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "policy denied this operation on '{program_path}' [tool-grammar]: {refusal}. \
             No policy can permit it."
        ),
    )
}

/// The policy spelling of a resolved shell path.
fn reported_path(path: &str, home: Option<&Path>) -> String {
    ApprovedPath::under_home(path, home).reported().into_owned()
}

/// The credential spellings recorded for the program a decision names, by that exact identity.
fn credential_reads_for<'a>(
    spawn_credentials: &'a BTreeMap<String, Vec<String>>,
    program_path: &str,
) -> &'a [String] {
    spawn_credentials
        .get(program_path)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Carry the kernel's operation into the policy vocabulary.
fn fs_operation(operation: KernelFsOperation) -> FsOperation {
    match operation {
        KernelFsOperation::ReadContent => FsOperation::ReadContent,
        // The kernel's `create`/`truncate` and `follow_symlinks` refinements collapse
        // into the coarse verb: the vocabulary starts coarse, because a field can be
        // added compatibly and never removed.
        KernelFsOperation::WriteContent { .. } => FsOperation::WriteContent,
        KernelFsOperation::ReadMetadata { .. } => FsOperation::ReadMetadata,
        KernelFsOperation::Enumerate => FsOperation::Enumerate,
        KernelFsOperation::Exec => FsOperation::ExecFile,
        KernelFsOperation::RemoveFile => FsOperation::RemoveFile,
        KernelFsOperation::RemoveDir => FsOperation::RemoveDir,
        KernelFsOperation::CreateDir => FsOperation::CreateDir,
        KernelFsOperation::SetPermissions { .. } => FsOperation::SetPermissions,
        KernelFsOperation::ChangeDir => FsOperation::ChangeDir,
        KernelFsOperation::ReadLink => FsOperation::ReadLink,
        _ => FsOperation::Other,
    }
}

/// Carry a two-path kernel operation into the policy vocabulary.
fn fs_pair_operation(operation: FsPairOperation) -> FsOperation {
    match operation {
        FsPairOperation::Rename { .. } => FsOperation::Rename,
        FsPairOperation::Symlink => FsOperation::Symlink,
        _ => FsOperation::Other,
    }
}

/// The path a two-path operation's source leg is judged on: a relative symlink target is joined
/// lexically onto the link's directory, and every other source is unchanged.
fn judged_source(from: &str, to: &str, operation: FsPairOperation) -> String {
    match operation {
        FsPairOperation::Symlink if !from.is_empty() && !from.starts_with('/') => {
            let link_dir = Path::new(to)
                .parent()
                .map(Path::to_string_lossy)
                .unwrap_or(std::borrow::Cow::Borrowed("/"));
            normalize_virtual(&format!("{link_dir}/{from}"))
                .to_string_lossy()
                .into_owned()
        }
        _ => from.to_string(),
    }
}

/// The removal a two-path kernel operation performs on what its destination holds.
fn destination_removal(operation: FsPairOperation) -> Option<FsOperation> {
    match operation {
        FsPairOperation::Rename {
            destination_exists: true,
            destination_is_dir,
        } => Some(if destination_is_dir {
            FsOperation::RemoveDir
        } else {
            FsOperation::RemoveFile
        }),
        _ => None,
    }
}

/// Translate the kernel's outcome into the policy vocabulary.
fn fs_result(result: EffectResult) -> FsResult {
    match result {
        EffectResult::Completed => FsResult::Completed,
        EffectResult::DescriptorIssued => FsResult::DescriptorIssued,
        EffectResult::Failed(_) => FsResult::Failed,
        EffectResult::Indeterminate => FsResult::Indeterminate,
        // An outcome this vocabulary does not name is recorded as unknown rather than
        // as success: a rule counting completions must not be handed a guess.
        _ => FsResult::Indeterminate,
    }
}

#[async_trait]
impl EffectInterceptor for ShellPolicyInterceptor {
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>> {
        // A `Locate` is a capability check the floor bounds, not an authorization.
        if let EffectAttempt::Filesystem {
            operation: KernelFsOperation::Locate,
            ..
        } = effect
        {
            return Ok(Box::new(LocatePermit));
        }
        let credential_reads = match effect {
            EffectAttempt::ShellSpawn { program_path, .. } => self.credential_reads(program_path),
            _ => &[],
        };
        let reported_program_path = match effect {
            EffectAttempt::ShellSpawn { program_path, .. } => {
                Some(reported_path(program_path, self.home.as_deref()))
            }
            _ => None,
        };
        let reported_cwd = match effect {
            EffectAttempt::ShellRun { cwd, .. } | EffectAttempt::ShellSpawn { cwd, .. } => {
                Some(reported_path(cwd, self.home.as_deref()))
            }
            _ => None,
        };
        if let EffectAttempt::ShellSpawn {
            program,
            program_path,
            args,
            cwd,
            ..
        } = effect
        {
            match self.grammar_coverage(program, program_path) {
                None => {}
                Some(GrammarCoverage::Refused(refusal)) => {
                    return Err(refused_spawn(program_path, &refusal));
                }
                Some(GrammarCoverage::Parsed { grammar, file }) => {
                    let invocation = GrammarInvocation::new(
                        grammar,
                        program,
                        &file,
                        self.home.as_deref(),
                        cwd,
                        args,
                        credential_reads,
                    );
                    let (decision, pending) = self.policy.decide_grammar_action(
                        &self.governed,
                        &self.principal,
                        &invocation,
                    );
                    return match pending {
                        Some(pending) => Ok(self.permit(Admitted::Grammar(pending))),
                        None => Err(denied(&decision)),
                    };
                }
            }
        }
        let decision = match effect {
            // One resolved command. The Shell has already parsed, expanded, and resolved
            // it, so `program` is what will run rather than what was typed.
            EffectAttempt::ShellRun {
                command,
                program,
                args,
                cwd,
                // `literal` is deliberately unread: a decision is about what runs, never about
                // how a word was spelled. Reading it would make the spelling a policy input.
                ..
            } => self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::ShellExec {
                    command,
                    program,
                    args,
                    cwd: reported_cwd.as_deref().unwrap_or(cwd),
                },
            ),
            // A host binary, raised through the passthrough path and judged as `shell:spawn`.
            EffectAttempt::ShellSpawn {
                command,
                program,
                program_path,
                args,
                cwd,
                ..
            } => self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::ShellSpawn {
                    command,
                    program,
                    program_path: reported_program_path.as_deref().unwrap_or(program_path),
                    credential_reads,
                    args,
                    cwd: reported_cwd.as_deref().unwrap_or(cwd),
                },
            ),
            // The Shell's VFS resolved this path already, so the adapter carries its
            // resolution rather than repeating it. `ApprovedPath::interpreter_resolved`
            // is where that trust is stated; the Shell performs no canonicity check of
            // its own, which is the LIVE GAP recorded in the crate's `AGENTS.md`.
            EffectAttempt::Filesystem { path, operation } => {
                let approved = ApprovedPath::under_home(*path, self.home.as_deref());
                self.policy.decide(
                    &self.governed,
                    &self.principal,
                    &Request::Fs {
                        path: &approved,
                        operation: fs_operation(*operation),
                    },
                )
            }
            // Every path a two-path operation touches must be authorized, and the
            // narrowest verdict governs: a permit naming the source carries no permission
            // over the target. A symlink's source is the path its target text resolves to
            // from the link's directory, per `judged_source`.
            //
            // The source leg is checked **twice** — once as the pair operation (a rename
            // rides `fs:move`, a symlink rides `fs:write`) and once as a content read
            // (`fs:read`, `operation == Box::FsReadOperation::"read_content"`). Both are load-bearing, in
            // opposite directions:
            //
            // - As the pair operation, so a rule permitting the mutation is what grants
            //   it, and a permit for reads alone cannot contribute to creating a link.
            // - As a content read, because the source's bytes become reachable through
            //   the new name. Without it a `forbid` on reads of a path — the ordinary way
            //   to fence off a secret — did not stop the agent from linking to it and
            //   reading it through the link.
            //
            // Checking only the pair action would silently drop that read `forbid`;
            // checking only the read would let a read permit authorize a mutation.
            //
            // A rename onto a bound destination removes what that destination held, so it
            // is also checked as `fs:delete` on the destination, as `remove_file` or
            // `remove_dir` by what is bound there.
            EffectAttempt::FilesystemPair {
                from,
                to,
                operation,
            } => {
                let pair_operation = fs_pair_operation(*operation);
                let source = ApprovedPath::under_home(
                    judged_source(from, to, *operation),
                    self.home.as_deref(),
                );
                let destination = ApprovedPath::under_home(*to, self.home.as_deref());
                let mut legs = vec![
                    Request::Fs {
                        path: &source,
                        operation: pair_operation,
                    },
                    Request::Fs {
                        path: &source,
                        operation: FsOperation::ReadContent,
                    },
                ];
                if let Some(removal) = destination_removal(*operation) {
                    legs.push(Request::Fs {
                        path: &destination,
                        operation: removal,
                    });
                }
                legs.push(Request::Fs {
                    path: &destination,
                    operation: pair_operation,
                });
                // First denial wins, and short-circuits: a later leg is never asked about
                // an effect already refused. The last leg's verdict stands when every
                // earlier one allowed, so an all-allow pair reports a real rule id.
                let mut legs = legs.iter();
                let mut verdict = self.policy.decide(
                    &self.governed,
                    &self.principal,
                    legs.next().expect("at least three legs"),
                );
                for leg in legs {
                    if !matches!(verdict, Decision::Allow { .. }) {
                        break;
                    }
                    verdict = self.policy.decide(&self.governed, &self.principal, leg);
                }
                verdict
            }
            // No network arm: the Shell raises no request attempt. An outbound
            // request is authorized at the egress boundary by
            // `EgressPolicyInterceptor`, which sees host, port, method, path, and
            // body size. Deciding here on method plus URL would be a second, coarser
            // authority over the same action — able to permit what the finer one
            // refused, with its own audit stream.
            //
            // No credential arm: the Shell holds no credentials and raises no
            // credential attempt. A credential binding is configuration, declared in
            // `.strands-box/box.toml` and resolved before any request.
            //
            // A variant added upstream reaches an adapter that cannot map it. Deny:
            // an unmapped effect must never pass unauthorized.
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "policy does not support this Shell effect",
                ));
            }
        };

        match decision {
            Decision::Allow { .. } => Ok(self.permit(Admitted::capture(
                effect,
                credential_reads,
                reported_program_path.as_deref(),
                reported_cwd.as_deref(),
            ))),
            Decision::Deny { .. } => Err(denied(&decision)),
        }
    }
}

/// What the permit remembers in order to build a history event.
enum Admitted {
    /// One resolved command whose program the Shell implements.
    Run {
        command: String,
        program: String,
        args: Vec<String>,
        cwd: String,
    },
    /// One resolved command executed by a host binary.
    Spawn {
        command: String,
        program: String,
        program_path: String,
        credential_reads: Vec<String>,
        args: Vec<String>,
        cwd: String,
    },
    /// One filesystem effect. A two-path operation is recorded against its *target* —
    /// the path the effect mutates — under the same operation both legs were authorized
    /// as, so the response names the action whose request was permitted.
    Filesystem {
        path: String,
        operation: FsOperation,
    },
    /// One filesystem pair whose rename source also needs a read response in history.
    FilesystemPair {
        source_read_path: Option<String>,
        target_path: String,
        destination_removal: Option<FsOperation>,
        operation: FsOperation,
    },
    /// One host binary that a grammar action decided, which owes that action's `::response`.
    Grammar(PendingGrammarResponse),
    /// An attempt this adapter does not map. It is only ever admitted if the
    /// authorization arm above allowed it, and it records nothing.
    Unmapped,
}

impl Admitted {
    fn capture(
        effect: &EffectAttempt<'_>,
        credential_reads: &[String],
        reported_program_path: Option<&str>,
        reported_cwd: Option<&str>,
    ) -> Self {
        match effect {
            EffectAttempt::ShellRun {
                command,
                program,
                args,
                cwd,
                ..
            } => Self::Run {
                command: (*command).to_string(),
                program: (*program).to_string(),
                args: args.to_vec(),
                cwd: reported_cwd.unwrap_or(cwd).to_string(),
            },
            EffectAttempt::ShellSpawn {
                command,
                program,
                program_path,
                args,
                cwd,
                ..
            } => Self::Spawn {
                command: (*command).to_string(),
                program: (*program).to_string(),
                program_path: reported_program_path.unwrap_or(program_path).to_string(),
                credential_reads: credential_reads.to_vec(),
                args: args.to_vec(),
                cwd: reported_cwd.unwrap_or(cwd).to_string(),
            },
            EffectAttempt::Filesystem { path, operation } => Self::Filesystem {
                path: (*path).to_string(),
                operation: fs_operation(*operation),
            },
            EffectAttempt::FilesystemPair {
                from,
                to,
                operation,
            } => Self::FilesystemPair {
                source_read_path: matches!(operation, FsPairOperation::Rename { .. })
                    .then(|| (*from).to_string()),
                target_path: (*to).to_string(),
                destination_removal: destination_removal(*operation),
                operation: fs_pair_operation(*operation),
            },
            _ => Self::Unmapped,
        }
    }
}

/// The permit for a `Locate`, which records nothing.
struct LocatePermit;

#[async_trait]
impl EffectPermit for LocatePermit {
    async fn record_outcome(self: Box<Self>, _outcome: EffectOutcome) -> io::Result<()> {
        Ok(())
    }

    fn mark_indeterminate(self: Box<Self>) {}
}

struct PolicyEffectPermit {
    policy: Arc<PolicyEngine>,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    admitted: Admitted,
    /// The operator home this permit abbreviates its recorded path against.
    ///
    /// Carried so the *response* event reports the same spelling the *request* event did. The
    /// engine keeps the two in separate bags, so a mismatch is an unmatched temporal predicate
    /// rather than an error — silent, and in the direction that weakens a rule.
    home: Option<std::path::PathBuf>,
}

impl PolicyEffectPermit {
    fn record_fs_outcome(
        &self,
        path: &str,
        operation: FsOperation,
        result: FsResult,
    ) -> Result<(), crate::PolicyError> {
        let reported = reported_path(path, self.home.as_deref());
        self.policy.record(
            &self.governed,
            &self.principal,
            &Outcome::Fs {
                path: Path::new(reported.as_str()),
                operation,
                result,
            },
        )
    }

    /// Submit this effect as history.
    fn submit(mut self, result: FsResult, reported_status: Option<i32>) -> io::Result<()> {
        let recorded = match std::mem::replace(&mut self.admitted, Admitted::Unmapped) {
            Admitted::Grammar(pending) => self
                .policy
                .record_grammar_response(pending, reported_status.unwrap_or(-1)),
            Admitted::Run {
                command,
                program,
                args,
                cwd,
            } => self.policy.record(
                &self.governed,
                &self.principal,
                &Outcome::ShellRun {
                    command: &command,
                    program: &program,
                    args: &args,
                    cwd: &cwd,
                    status: reported_status.unwrap_or(-1),
                },
            ),
            Admitted::Spawn {
                command,
                program,
                program_path,
                credential_reads,
                args,
                cwd,
            } => self.policy.record(
                &self.governed,
                &self.principal,
                &Outcome::ShellSpawn {
                    command: &command,
                    program: &program,
                    program_path: &program_path,
                    credential_reads: &credential_reads,
                    args: &args,
                    cwd: &cwd,
                    status: reported_status.unwrap_or(-1),
                },
            ),
            // **The REPORTED spelling, so both events agree.** The request event carries
            // `~/<relative>` and the resolution event is built from this one — and the engine keeps
            // them in two separate bags, so a value written to one and not the other leaves a
            // `when temporal { … }` predicate unresolved *silently*, as an unmatched clause rather
            // than an error.
            //
            // Measured: an exfiltration guard keyed on `Box::Action::"fs:read"::response` with an
            // `input.path` of `~/…/secret` never fired, because the resolution still carried the
            // host path. Egress stayed open after the secret was read, which is the one thing that
            // rule exists to close.
            Admitted::Filesystem { path, operation } => {
                self.record_fs_outcome(&path, operation, result)
            }
            Admitted::FilesystemPair {
                source_read_path,
                target_path,
                destination_removal,
                operation,
            } => source_read_path
                .as_ref()
                .filter(|_| result.response_result().is_some())
                .map_or(Ok(()), |source_read_path| {
                    self.record_fs_outcome(source_read_path, FsOperation::ReadContent, result)
                })
                .and_then(|()| {
                    destination_removal.map_or(Ok(()), |removal| {
                        self.record_fs_outcome(&target_path, removal, result)
                    })
                })
                .and_then(|()| self.record_fs_outcome(&target_path, operation, result)),
            Admitted::Unmapped => Ok(()),
        };

        if recorded.is_err() {
            let _ = writeln!(
                io::stderr().lock(),
                "strands-box: warning: policy outcome recording was not confirmed"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl EffectPermit for PolicyEffectPermit {
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()> {
        match outcome {
            EffectOutcome::ShellCommand { reported_status } => {
                (*self).submit(FsResult::Completed, Some(reported_status))
            }
            EffectOutcome::Kernel(result) => (*self).submit(fs_result(result), None),
            // An outcome variant added upstream is recorded as unknown rather than
            // dropped: a rule must see that the effect ended, even unclassifiable.
            _ => (*self).submit(FsResult::Indeterminate, None),
        }
    }

    fn mark_indeterminate(self: Box<Self>) {
        // An admitted effect whose execution ended with no outcome. Record it as
        // indeterminate rather than dropping it: a rule that counts attempts must still
        // see one happened.
        let _ = (*self).submit(FsResult::Indeterminate, None);
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::path::PathBuf;

    use super::*;
    use crate::Policy;
    use crate::rerun;

    struct InterceptorFixture {
        interceptor: Arc<dyn EffectInterceptor>,
        _history: tempfile::TempDir,
    }

    impl Deref for InterceptorFixture {
        type Target = dyn EffectInterceptor;

        fn deref(&self) -> &Self::Target {
            self.interceptor.as_ref()
        }
    }

    fn interceptor(source: &str) -> InterceptorFixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("shell-adapter-test.cedar"),
                text: source.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let interceptor = ShellPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        InterceptorFixture {
            interceptor,
            _history: history,
        }
    }

    fn interceptor_under_home(source: &str, home: &Path) -> InterceptorFixture {
        let history = tempfile::tempdir().expect("history directory");
        let policy = PolicyEngine::open(
            vec![Policy {
                origin: PathBuf::from("shell-adapter-test.cedar"),
                text: source.to_string(),
            }],
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let interceptor = ShellPolicyInterceptor::into_handle_reporting_under(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
            home,
        );
        InterceptorFixture {
            interceptor,
            _history: history,
        }
    }

    /// **A home-relative `program_path` rule decides a spawn under the home**, so `shell:spawn`
    /// and `fs:*` share one spelling; without a reported home the same rule denies.
    #[tokio::test]
    async fn a_home_relative_spawn_rule_matches_the_program_under_the_home() {
        let home = tempfile::tempdir().expect("a home");
        std::fs::create_dir_all(home.path().join("bin")).expect("a bin directory");
        std::fs::write(home.path().join("bin/tool"), "").expect("a program");
        let canonical_home = home.path().canonicalize().expect("canonical");
        let program = canonical_home.join("bin/tool").display().to_string();
        let source = r#"permit(
               principal == Box::Agent::"self",
               action == Box::Action::"shell:spawn",
               resource
           )
           when { context.input.program_path == "~/bin/tool" };"#;
        let attempt = EffectAttempt::ShellSpawn {
            command: "tool",
            program: "tool",
            program_path: &program,
            args: &[],
            literal: &[],
            cwd: "/home",
        };

        let permit = interceptor_under_home(source, &canonical_home)
            .intercept(&attempt)
            .await
            .expect("the home-relative rule matches the program under the home");
        permit
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
            .await
            .expect("outcome reporting is best effort");

        let denied = interceptor(source).intercept(&attempt).await;
        assert!(
            denied.is_err(),
            "without a reported home the rule does not match"
        );
    }

    #[tokio::test]
    async fn permits_only_the_exact_policy_command() {
        let interceptor = interceptor(
            r#"permit(
                   principal == Box::Agent::"self",
                   action == Box::Action::"shell:exec",
                   resource
               )
               when { context.input.command == "printf allowed" };"#,
        );

        let permit = interceptor
            .intercept(&EffectAttempt::ShellRun {
                command: "printf allowed",
                program: "printf",
                args: &["allowed".to_string()],
                literal: &[],
                cwd: "/home",
            })
            .await
            .expect("exact command is allowed");
        permit
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
            .await
            .expect("policy outcome reporting is best effort");

        let denied = match interceptor
            .intercept(&EffectAttempt::ShellRun {
                command: "printf denied",
                program: "printf",
                args: &["denied".to_string()],
                literal: &[],
                cwd: "/home",
            })
            .await
        {
            Ok(_) => panic!("different command is denied"),
            Err(error) => error,
        };
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            denied.to_string(),
            "policy denied this operation on 'printf' [default-deny]: No permit policy matched this request."
        );
    }

    /// **A two-path refusal names the leg that was denied**, whichever of the three it is.
    #[tokio::test]
    async fn a_pair_refusal_names_the_denied_leg() {
        const PERMITS: &str = r#"
            permit(principal, action == Box::Action::"fs:read", resource);
            permit(principal, action == Box::Action::"fs:move", resource);"#;
        let attempt = EffectAttempt::FilesystemPair {
            from: "/work/source.txt",
            to: "/work/target.txt",
            operation: FsPairOperation::Rename {
                destination_exists: false,
                destination_is_dir: false,
            },
        };
        for (forbid, denied, permitted) in [
            (
                r#"@id("no-target") forbid(principal, action == Box::Action::"fs:move", resource)
                   when { context.input.path == "/work/target.txt" };"#,
                "/work/target.txt",
                "/work/source.txt",
            ),
            (
                r#"@id("no-source") forbid(principal, action == Box::Action::"fs:read", resource)
                   when { context.input.path == "/work/source.txt" };"#,
                "/work/source.txt",
                "/work/target.txt",
            ),
        ] {
            let error = interceptor(&format!("{PERMITS}\n{forbid}"))
                .intercept(&attempt)
                .await
                .err()
                .expect("one leg is forbidden");
            let message = error.to_string();
            assert!(
                message.contains(&format!(
                    "policy denied this operation on '{denied}' [policy: no-"
                )),
                "{message}"
            );
            assert!(!message.contains(permitted), "{message}");
        }
    }

    #[tokio::test]
    async fn admitted_command_can_be_marked_indeterminate() {
        let interceptor = interceptor(
            r#"permit(
                   principal == Box::Agent::"self",
                   action == Box::Action::"shell:exec",
                   resource
               );"#,
        );
        let permit = interceptor
            .intercept(&EffectAttempt::ShellRun {
                command: "sleep 1",
                program: "sleep",
                args: &["1".to_string()],
                literal: &[],
                cwd: "/home",
            })
            .await
            .expect("command is admitted");

        permit.mark_indeterminate();
    }

    #[tokio::test]
    async fn an_indeterminate_command_records_status_minus_one() {
        let interceptor = interceptor(
            r#"permit(principal, action == Box::Action::"shell:exec", resource);
               @id("after_an_indeterminate_sleep")
               forbid(principal, action == Box::Action::"shell:exec", resource)
               when { context.input.program == "printf" }
               unless temporal {
                   formerly within 60s
                   Box::Action::"shell:exec"::response{ input.program: "sleep", output.status: -1 }
               };"#,
        );
        let gated = EffectAttempt::ShellRun {
            command: "printf gated",
            program: "printf",
            args: &["gated".to_string()],
            literal: &[],
            cwd: "/home",
        };
        let sleep = EffectAttempt::ShellRun {
            command: "sleep 1",
            program: "sleep",
            args: &["1".to_string()],
            literal: &[],
            cwd: "/home",
        };

        interceptor
            .intercept(&sleep)
            .await
            .expect("sleep is admitted")
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
            .await
            .expect("outcome reporting is best effort");
        assert!(
            interceptor.intercept(&gated).await.is_err(),
            "a reported status of 0 is not -1"
        );

        interceptor
            .intercept(&sleep)
            .await
            .expect("sleep is admitted")
            .mark_indeterminate();
        assert!(
            interceptor.intercept(&gated).await.is_ok(),
            "a command that ends with no reported status records -1"
        );
    }

    /// **A failed metadata read records an error**, so it charges no `::response` rule.
    #[tokio::test]
    async fn a_failed_metadata_read_records_an_error() {
        let interceptor = interceptor(
            r#"permit(principal, action == Box::Action::"fs:read", resource);
               @id("after_a_metadata_answer")
               forbid(principal, action == Box::Action::"fs:read", resource)
               when { context.input.path == "/work/gated" }
               when temporal {
                   formerly within 60s
                   Box::Action::"fs:read"::response{ input.path: "/work/refused" }
               };"#,
        );
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
            interceptor
                .intercept(&EffectAttempt::Filesystem {
                    path: "/work/refused",
                    operation: KernelFsOperation::ReadMetadata {
                        follow_symlinks: true,
                    },
                })
                .await
                .expect("the metadata read is admitted")
                .record_outcome(EffectOutcome::Kernel(EffectResult::Failed(kind)))
                .await
                .expect("outcome reporting is best effort");
        }
        assert!(
            interceptor
                .intercept(&EffectAttempt::Filesystem {
                    path: "/work/gated",
                    operation: KernelFsOperation::ReadContent,
                })
                .await
                .is_ok(),
            "a failed metadata read is not a response"
        );
    }

    /// **A relative symlink target is judged on the path it resolves to from the link's
    /// directory**, lexically: `.` and `..` close, surplus `..` stops at the root, a nested link
    /// resolves from its own directory, and an empty target, an absolute target, or a rename source
    /// is unchanged.
    #[test]
    fn a_relative_symlink_target_resolves_lexically_against_the_links_directory() {
        let symlink = FsPairOperation::Symlink;
        for (from, to, judged) in [
            ("file", "/work/link", "/work/file"),
            ("./file", "/work/link", "/work/file"),
            ("sub/./file", "/work/link", "/work/sub/file"),
            ("../file", "/work/nested/link", "/work/file"),
            (
                "../sibling/file",
                "/work/nested/deep/link",
                "/work/nested/sibling/file",
            ),
            ("../../etc/passwd", "/work/link", "/etc/passwd"),
            ("../../../../etc/passwd", "/work/link", "/etc/passwd"),
            ("file", "/link", "/file"),
            ("", "/work/link", ""),
            ("/work/file", "/work/link", "/work/file"),
            ("/etc/passwd", "/work/link", "/etc/passwd"),
        ] {
            assert_eq!(judged_source(from, to, symlink), judged, "{from} at {to}");
        }
        let rename = FsPairOperation::Rename {
            destination_exists: false,
            destination_is_dir: false,
        };
        assert_eq!(judged_source("file", "/work/link", rename), "file");
        assert_eq!(
            judged_source("/work/source", "/work/target", rename),
            "/work/source"
        );
    }

    /// **The symlink legs see the resolved source**: a scoped `fs:write` admits a relative
    /// target inside its scope, refuses one that climbs out, and a `fs:read` forbid on the
    /// resolved path still fences the link.
    #[tokio::test]
    async fn symlink_legs_are_decided_on_the_resolved_target() {
        const SCOPED: &str = r#"
            permit(principal, action == Box::Action::"fs:read", resource)
            when { context.input.path like "/work/*" };
            permit(principal, action == Box::Action::"fs:write", resource)
            when { context.input.path like "/work/*" };"#;
        let attempt = |from| EffectAttempt::FilesystemPair {
            from,
            to: "/work/link",
            operation: FsPairOperation::Symlink,
        };
        let scoped = interceptor(SCOPED);
        assert!(scoped.intercept(&attempt("file")).await.is_ok());
        assert!(scoped.intercept(&attempt("missing")).await.is_ok());
        let escaped = scoped
            .intercept(&attempt("../../etc/passwd"))
            .await
            .err()
            .expect("a target outside the scope is refused");
        assert!(
            escaped
                .to_string()
                .contains("policy denied this operation on '/etc/passwd' [default-deny]"),
            "{escaped}"
        );
        let fenced = interceptor(&format!(
            r#"{SCOPED}
            @id("no-secret") forbid(principal, action == Box::Action::"fs:read", resource)
            when {{ context.input.path == "/work/secret" }};"#
        ))
        .intercept(&attempt("secret"))
        .await
        .err()
        .expect("the read fence holds on the resolved path");
        assert!(
            fenced
                .to_string()
                .contains("policy denied this operation on '/work/secret' [policy: no-secret]"),
            "{fenced}"
        );
    }

    /// **Credential reads are keyed by the decision's exact identity**, so a same-named binary at
    /// another path carries none.
    #[test]
    fn credential_reads_are_keyed_by_the_decisions_program_path() {
        let map: BTreeMap<String, Vec<String>> =
            [("/usr/bin/aws-2.1".to_string(), vec!["~/.aws".to_string()])]
                .into_iter()
                .collect();
        assert_eq!(credential_reads_for(&map, "/usr/bin/aws-2.1"), ["~/.aws"]);
        assert!(credential_reads_for(&map, "/opt/other/aws-2.1").is_empty());
        assert!(credential_reads_for(&map, "aws-2.1").is_empty());
    }

    /// **`program_path` is spelled like `path`**: home-relative under the operator's home, canonical
    /// elsewhere, so one rule spelling serves `shell:spawn` and `fs:*`.
    #[test]
    fn a_program_under_the_home_is_reported_home_relative() {
        let home = tempfile::tempdir().expect("a home");
        let bin = home.path().join(".cargo/bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        std::fs::write(bin.join("rustup"), "").expect("a program");
        let canonical_home = home.path().canonicalize().expect("canonical");
        let program = canonical_home.join(".cargo/bin/rustup");
        assert_eq!(
            reported_path(&program.to_string_lossy(), Some(&canonical_home)),
            "~/.cargo/bin/rustup"
        );
        assert_eq!(
            reported_path("/usr/bin/git", Some(&canonical_home)),
            "/usr/bin/git"
        );
        assert_eq!(
            reported_path(&program.to_string_lossy(), None),
            program.to_string_lossy()
        );
    }

    /// A host directory that holds the program files a spawn names.
    struct Programs(tempfile::TempDir);

    impl Programs {
        fn new() -> Self {
            Self(tempfile::tempdir().expect("a program directory"))
        }

        /// The canonical path of a program file at `name`, written when absent.
        fn path(&self, name: &str) -> String {
            let path = self.0.path().join(name);
            if !path.exists() {
                std::fs::write(&path, name).expect("a program file");
            }
            path.canonicalize()
                .expect("a canonical path")
                .display()
                .to_string()
        }

        fn file(&self, name: &str) -> ProgramFile {
            ProgramFile::read(self.path(name)).expect("a readable program file")
        }

        /// Put a new file at `name`, as an update does: a rename over the old name.
        fn replace(&self, name: &str) {
            let staged = self.0.path().join(format!("{name}.new"));
            std::fs::write(&staged, "a new build").expect("a new program file");
            std::fs::rename(&staged, self.0.path().join(name)).expect("the rename");
        }

        /// Put a symlink to `target` at `name`, in one rename over what was there.
        fn link(&self, name: &str, target: &str) {
            let staged = self.0.path().join(format!("{name}.link"));
            std::os::unix::fs::symlink(self.path(target), &staged).expect("a symlink");
            std::fs::rename(&staged, self.0.path().join(name)).expect("the rename");
        }
    }

    fn grammar(name: &str) -> crate::grammar::Grammar {
        crate::grammar::Grammar::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/grammars/valid/{name}.grammar.toml")),
        )
        .expect("the fixture grammar loads")
    }

    /// An interceptor over an engine that knows `grammars`, with `bind` as its bindings.
    fn interceptor_with_grammars(
        source: &str,
        grammars: &[&str],
        bind: impl FnOnce(&mut GrammarBindings),
    ) -> InterceptorFixture {
        let history = tempfile::tempdir().expect("history directory");
        let installed: Vec<_> = grammars.iter().map(|name| grammar(name)).collect();
        let policy = PolicyEngine::open_with_grammars(
            vec![Policy {
                origin: PathBuf::from("shell-adapter-test.dw"),
                text: source.to_string(),
            }],
            &installed,
            &history.path().join("dogwood.redb"),
        )
        .expect("policy opens");
        let mut bindings = GrammarBindings::new(installed).expect("distinct grammars");
        bind(&mut bindings);
        InterceptorFixture {
            interceptor: ShellPolicyInterceptor::into_handle_with_grammar_bindings(
                Arc::new(policy),
                Principal::agent(),
                GovernedBox::assigned("test-box"),
                None,
                BTreeMap::new(),
                bindings,
            ),
            _history: history,
        }
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    fn spawn<'a>(program: &'a str, program_path: &'a str, args: &'a [String]) -> EffectAttempt<'a> {
        EffectAttempt::ShellSpawn {
            command: program,
            program,
            program_path,
            args,
            literal: &[],
            cwd: "/work",
        }
    }

    /// **A bound program is decided only as its grammar action**: a `shell:spawn` permit does not
    /// admit it, and a `shell:spawn` forbid does not refuse it.
    #[tokio::test]
    async fn a_bound_spawn_is_decided_as_its_grammar_action_and_never_as_shell_spawn() {
        let programs = Programs::new();
        let git = programs.path("git");
        let status = words(&["status"]);
        let push = words(&["push", "origin", "main"]);
        let bound = |source: &str| {
            interceptor_with_grammars(source, &["git"], |bindings| {
                bindings
                    .bind(&programs.file("git"), "git", "git")
                    .expect("git binds");
            })
        };

        let spawn_permitted =
            bound(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let refused = spawn_permitted
            .intercept(&spawn("git", &git, &status))
            .await
            .err()
            .expect("a shell:spawn permit does not admit a grammar action");
        assert_eq!(
            refused.to_string(),
            format!(
                "policy denied this operation on '{git}' [default-deny]: No permit policy matched \
                 this request."
            )
        );

        let grammar_permitted = bound(
            r#"permit (principal, action == Tool::git::Action::"status", resource);
               forbid (principal, action == Box::Action::"shell:spawn", resource);"#,
        );
        assert!(
            grammar_permitted
                .intercept(&spawn("git", &git, &status))
                .await
                .is_ok(),
            "the grammar action permit admits the spawn, and the shell:spawn forbid never sees it"
        );
        assert!(
            grammar_permitted
                .intercept(&spawn("git", &git, &push))
                .await
                .is_err(),
            "a grammar action that no rule permits is denied"
        );
    }

    const PUSH_AFTER_A_PASSING_TEST: &str = r#"
        permit (principal, action in Tool::git::Action::"*", resource);
        permit (principal, action in Tool::cargo::Action::"*", resource);
        @id("push_after_a_passing_test")
        forbid (principal, action == Tool::git::Action::"push", resource)
        unless temporal {
            formerly within 1h Tool::cargo::Action::"test"::response{ output.status: 0 }
        };
    "#;

    /// **An admitted grammar action records its `::response` with the exit status**, and a run that
    /// ends with no status records `-1`.
    #[tokio::test]
    async fn an_admitted_grammar_action_records_its_response_with_the_exit_status() {
        let programs = Programs::new();
        let (git, cargo) = (programs.path("git"), programs.path("cargo"));
        let interceptor =
            interceptor_with_grammars(PUSH_AFTER_A_PASSING_TEST, &["git", "cargo"], |b| {
                b.bind(&programs.file("git"), "git", "git")
                    .expect("git binds");
                b.bind(&programs.file("cargo"), "cargo", "cargo")
                    .expect("cargo binds");
            });
        let push = words(&["push", "origin", "main"]);
        let test = words(&["test"]);
        let (push, test) = (spawn("git", &git, &push), spawn("cargo", &cargo, &test));
        let pushed = || interceptor.intercept(&push);
        let tested = || interceptor.intercept(&test);

        assert!(pushed().await.is_err(), "no test has run");
        tested()
            .await
            .expect("the test run is admitted")
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 1 })
            .await
            .expect("outcome reporting is best effort");
        tested()
            .await
            .expect("the test run is admitted")
            .mark_indeterminate();
        let refused = pushed().await.err().expect("no test has passed");
        assert!(
            refused
                .to_string()
                .contains("[policy: push_after_a_passing_test]"),
            "{refused}"
        );
        tested()
            .await
            .expect("the test run is admitted")
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
            .await
            .expect("outcome reporting is best effort");
        assert!(pushed().await.is_ok(), "a test exited 0");
    }

    /// **A bound file called by an undeclared name, or a replaced bound file, is refused** even
    /// under a policy that permits every action, and a file that no grammar binds stays a
    /// `shell:spawn`.
    #[tokio::test]
    async fn an_undeclared_name_or_a_replaced_file_is_refused_whatever_the_policy_permits() {
        let programs = Programs::new();
        let (mise, git, make) = (
            programs.path("mise"),
            programs.path("git"),
            programs.path("make"),
        );
        let interceptor = interceptor_with_grammars(
            "permit (principal, action, resource);",
            &["git", "cargo", "aws"],
            |bindings| {
                let shim = programs.file("mise");
                bindings.bind(&shim, "cargo", "cargo").expect("cargo binds");
                bindings.bind(&shim, "aws", "aws").expect("aws binds");
                bindings.declare(&shim, "node");
                bindings
                    .bind(&programs.file("git"), "git", "git")
                    .expect("git binds");
            },
        );
        let none = words(&[]);
        programs.replace("git");

        for (case, program, program_path, expected) in [
            (
                "an undeclared name on the shim binary",
                "python",
                &mise,
                Some(format!(
                    "policy denied this operation on '{mise}' [tool-grammar]: `python` runs \
                     `{mise}`, which a tool grammar covers, but no `[tool]` declares the name \
                     `python`. No policy can permit it."
                )),
            ),
            (
                "an undeclared name spelled as a path",
                "/opt/shims/python",
                &mise,
                Some(format!(
                    "policy denied this operation on '{mise}' [tool-grammar]: `python` runs \
                     `{mise}`, which a tool grammar covers, but no `[tool]` declares the name \
                     `python`. No policy can permit it."
                )),
            ),
            (
                "a replaced bound file",
                "git",
                &git,
                Some(format!(
                    "policy denied this operation on '{git}' [tool-grammar]: `git` runs `{git}`, \
                     which a tool grammar bound, but the file at that path is no longer the file \
                     it bound. No policy can permit it."
                )),
            ),
            ("the first grammar on the shim binary", "cargo", &mise, None),
            ("the second grammar on the shim binary", "aws", &mise, None),
            ("a declared name with no grammar", "node", &mise, None),
            ("a file that no grammar binds", "make", &make, None),
        ] {
            let decided = interceptor
                .intercept(&spawn(program, program_path, &none))
                .await
                .err()
                .map(|error| error.to_string());
            assert_eq!(decided, expected, "{case}");
        }
    }

    fn replaced_message(name: &str, program_path: &str) -> String {
        format!(
            "policy denied this operation on '{program_path}' [tool-grammar]: `{name}` runs \
             `{program_path}`, which a tool grammar bound, but the file at that path is no longer the \
             file it bound. No policy can permit it."
        )
    }

    /// **A bound regular file replaced by a symlink is refused**, whether the symlink leads to a
    /// file that no grammar binds or to another bound file, and a `shell:spawn` permit does not
    /// admit it.
    #[tokio::test]
    async fn a_bound_file_replaced_by_a_symlink_is_refused() {
        for (case, target) in [
            ("an unbound file", "planted"),
            ("another bound file", "cargo"),
        ] {
            let programs = Programs::new();
            let planted = programs.path("planted");
            let cargo = programs.path("cargo");
            let interceptor = interceptor_with_grammars(
                r#"permit (principal, action == Box::Action::"shell:spawn", resource);
                   permit (principal, action in Tool::git::Action::"*", resource);
                   permit (principal, action in Tool::cargo::Action::"*", resource);"#,
                &["git", "cargo"],
                |bindings| {
                    bindings
                        .bind(&programs.file("git"), "git", "git")
                        .expect("git binds");
                    bindings
                        .bind(&programs.file("cargo"), "cargo", "cargo")
                        .expect("cargo binds");
                },
            );
            programs.link("git", target);
            let resolved = if target == "cargo" { &cargo } else { &planted };

            let refused = interceptor
                .intercept(&spawn("git", resolved, &words(&["status"])))
                .await
                .err()
                .map(|error| error.to_string());

            assert_eq!(refused, Some(replaced_message("git", resolved)), "{case}");
        }
    }

    /// **A shim binary that grammars bind under other names, replaced by a symlink, is refused**
    /// for a bound name and for an undeclared name, and a `shell:spawn` permit does not admit it.
    #[tokio::test]
    async fn a_replaced_shim_binary_is_refused_under_each_name_it_covered() {
        let programs = Programs::new();
        let planted = programs.path("planted");
        let interceptor = interceptor_with_grammars(
            r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#,
            &["cargo"],
            |bindings| {
                let shim = programs.file("mise");
                bindings.bind(&shim, "cargo", "cargo").expect("cargo binds");
                bindings.declare(&shim, "node");
            },
        );
        programs.link("mise", "planted");

        for (name, expected) in [
            ("cargo", Some(replaced_message("cargo", &planted))),
            ("python", Some(replaced_message("python", &planted))),
            ("node", None),
        ] {
            let decided = interceptor
                .intercept(&spawn(name, &planted, &words(&[])))
                .await
                .err()
                .map(|error| error.to_string());

            assert_eq!(decided, expected, "{name}");
        }
    }

    /// **A bound link retargeted to another bound file is refused**, and is never decided as the
    /// other file's grammar action.
    #[tokio::test]
    async fn a_bound_link_retargeted_to_another_bound_file_is_refused() {
        let programs = Programs::new();
        let cargo = programs.path("cargo");
        programs.path("git-2.50");
        programs.link("git", "git-2.50");
        let interceptor = interceptor_with_grammars(
            "permit (principal, action, resource);",
            &["git", "cargo"],
            |bindings| {
                let linked =
                    ProgramFile::read(programs.0.path().join("git")).expect("the link reads");
                bindings.bind(&linked, "git", "git").expect("git binds");
                let cargo = programs.file("cargo");
                bindings
                    .bind(&cargo, "cargo", "cargo")
                    .expect("cargo binds");
                bindings
                    .bind(&cargo, "git", "cargo")
                    .expect("cargo binds a second name on its own file");
            },
        );
        programs.link("git", "cargo");

        for program in ["git", &programs.0.path().join("git").display().to_string()] {
            let refused = interceptor
                .intercept(&spawn(program, &cargo, &words(&["test"])))
                .await
                .err()
                .map(|error| error.to_string());

            assert_eq!(refused, Some(replaced_message("git", &cargo)), "{program}");
        }
        assert!(
            interceptor
                .intercept(&spawn("cargo", &cargo, &words(&["test"])))
                .await
                .is_ok(),
            "the other file, by its own bound name, still decides as its grammar action"
        );
    }

    /// **A spawn spelled as the path of a bound file that is gone is refused**, and does not fall
    /// back to `shell:spawn`.
    #[tokio::test]
    async fn a_removed_bound_file_is_refused() {
        let programs = Programs::new();
        let git = programs.path("git");
        let interceptor = interceptor_with_grammars(
            r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#,
            &["git"],
            |bindings| {
                bindings
                    .bind(&programs.file("git"), "git", "git")
                    .expect("git binds");
            },
        );
        std::fs::remove_file(&git).expect("the file is removed");

        let refused = interceptor
            .intercept(&spawn(&git, &git, &words(&["status"])))
            .await
            .err()
            .expect("a removed bound file is refused");

        assert!(refused.to_string().contains("[tool-grammar]"), "{refused}");
    }

    /// **With empty bindings, every spawn decides exactly as `shell:spawn` decides it today**, and
    /// so does every spawn that no binding covers.
    #[tokio::test]
    async fn empty_bindings_decide_every_spawn_as_the_shell_spawn_path_does() {
        const POLICY: &str = r#"
            permit (principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program == "git" };
            @id("no-push")
            forbid (principal, action == Box::Action::"shell:spawn", resource)
            when { context.input has arg1 && context.input.arg1 == "push" };
            permit (principal, action == Box::Action::"shell:spawn", resource)
            when { context.input.program_path like "*/make" };
        "#;
        let programs = Programs::new();
        let (git, make, mise) = (
            programs.path("git"),
            programs.path("make"),
            programs.path("mise"),
        );
        let absent = programs.0.path().join("absent").display().to_string();
        let empty = |grammars: &[&str]| interceptor_with_grammars(POLICY, grammars, |_| {});
        let declared_only = interceptor_with_grammars(POLICY, &["git"], |bindings| {
            bindings.declare(&programs.file("mise"), "node");
        });
        let bound_elsewhere = interceptor_with_grammars(POLICY, &["git"], |bindings| {
            bindings
                .bind(&programs.file("vendored-git"), "git", "git")
                .expect("git binds another file");
        });
        let today = interceptor(POLICY);
        let engine = {
            let history = tempfile::tempdir().expect("history directory");
            let engine = PolicyEngine::open(
                vec![Policy {
                    origin: PathBuf::from("shell-adapter-test.dw"),
                    text: POLICY.to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("policy opens");
            (engine, history)
        };
        let gates = [
            ("no grammars", empty(&[])),
            (
                "installed grammars and no binding",
                empty(&["git", "cargo"]),
            ),
            ("a declared name and no binding", declared_only),
            ("a binding on another file", bound_elsewhere),
        ];

        for (program, program_path, args) in [
            ("git", &git, words(&["status"])),
            ("git", &git, words(&["push", "--force", "origin", "main"])),
            ("/opt/bin/git", &git, words(&["log"])),
            ("make", &make, words(&["all"])),
            ("node", &mise, words(&["index.js"])),
            ("python", &mise, words(&[])),
            ("ls", &absent, words(&["-l"])),
        ] {
            let attempt = spawn(program, program_path, &args);
            let direct = engine.0.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::ShellSpawn {
                    command: program,
                    program,
                    program_path,
                    credential_reads: &[],
                    args: &args,
                    cwd: "/work",
                },
            );
            let expected = (!direct.is_allow()).then(|| direct.to_string());
            let decided = |error: io::Result<Box<dyn EffectPermit>>| {
                error.err().map(|error| error.to_string())
            };
            assert_eq!(
                decided(today.intercept(&attempt).await),
                expected,
                "the default handle: {program} at {program_path}"
            );
            for (case, gate) in &gates {
                assert_eq!(
                    decided(gate.intercept(&attempt).await),
                    expected,
                    "{case}: {program} at {program_path}"
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "runs only as the child process that a_failed_record_keeps_the_effect_result_and_warns_once starts through rerun::stderr_of"]
    async fn a_permit_records_through_a_failed_store() {
        let history = tempfile::tempdir().expect("history directory");
        let policy = Arc::new(
            PolicyEngine::open(
                vec![Policy {
                    origin: PathBuf::from("shell-store-faults.dw"),
                    text: r#"permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);"#
                        .to_string(),
                }],
                &history.path().join("dogwood.redb"),
            )
            .expect("policy opens"),
        );
        let interceptor = ShellPolicyInterceptor::into_handle(
            Arc::clone(&policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        let permit = interceptor
            .intercept(&EffectAttempt::ShellRun {
                command: "printf allowed",
                program: "printf",
                args: &["allowed".to_string()],
                literal: &[],
                cwd: "/home",
            })
            .await
            .expect("the command is permitted");

        policy.poison_store_for_test();

        permit
            .record_outcome(EffectOutcome::ShellCommand { reported_status: 0 })
            .await
            .expect("a store fault must not change the effect's own result");
    }

    #[test]
    fn a_failed_record_keeps_the_effect_result_and_warns_once() {
        let stderr = rerun::stderr_of(&rerun::test_name(
            module_path!(),
            "a_permit_records_through_a_failed_store",
        ));
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("strands-box: warning"))
            .collect();
        assert_eq!(
            warnings,
            vec!["strands-box: warning: policy outcome recording was not confirmed"],
            "{stderr}"
        );
        assert!(!stderr.contains("printf"), "{stderr}");
    }
}
