//! Adapter from the policy facade to Monty's OS-call suspension seam.
//!
//! | | Shell adapter | this adapter |
//! |---|---|---|
//! | what arrives | `EffectAttempt` (the Shell already resolved it) | `OsFunctionCall` (a caller's spelling) |
//! | 1. classify | the granular `FsOperation` | `classify`, which also resolves the path |
//! | 2. decide | `PolicyEngine::decide` | `PolicyEngine::decide` |
//! | 3. permit or refuse | `Ok(EffectPermit)` / `Err(PermissionDenied)` | `Ok(ScriptPermit)` / `Err(ScriptRefusal)` |
//! | report | `EffectPermit::record_outcome` | [`ScriptPermit::record`] |
//! | unmapped input | denied | denied — and a *compile* error, see `classify` |
//!
//! [`Mediated`]: https://docs.rs/strands-shell

use std::io::Write as _;
use std::path::{Path, PathBuf};

use monty_types::{ExcType, FileMode, MontyException, OsFunctionCall};

use crate::GovernedBox;
use crate::outcome::FsResult;
use crate::path::{ApprovedPath, normalize_virtual};
use crate::request::FsOperation;
use crate::{Decision, Outcome, PolicyEngine, Principal, Request};

/// Binds one policy and Script principal to Monty's OS-call seam.
pub struct ScriptPolicyInterceptor<'p> {
    policy: &'p PolicyEngine,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    /// The operator home a reported path is abbreviated against, when there is one.
    ///
    /// **Both interpreters must report the SAME spelling, or a rule cannot be authored.** The Shell
    /// reports `~/<relative>`; without this, a Python `fs:*` request carried the host path, so one
    /// `context.input.path` meant two different things depending on which alias served the request.
    /// That is fail-closed for a `permit` and **fail-open for a `forbid`**: a
    /// `forbid fs:read when path like "~/.ssh/*"` matched through `bin/zsh` and matched nothing
    /// through `bin/python3`.
    home: Option<std::path::PathBuf>,
}

/// One admitted Monty OS call, and the resolved identity it was admitted for.
#[must_use = "an admitted effect must report its outcome, or history loses it"]
#[derive(Debug)]
pub struct ScriptPermit<'p> {
    policy: &'p PolicyEngine,
    principal: Principal,
    /// Integration metadata for the box this boundary serves.
    governed: GovernedBox,
    admitted: Admitted,
    /// Whether an outcome has been submitted, so `Drop` does not submit a second one.
    reported: bool,
}

/// What a permit remembers in order to record history.
#[derive(Debug)]
enum Admitted {
    /// A filesystem effect, against the path that was admitted.
    Filesystem {
        path: ApprovedPath,
        operation: FsOperation,
    },
    /// A rename whose source must also be visible as a read response in history.
    Rename {
        source_read_path: ApprovedPath,
        target_path: ApprovedPath,
        destination_removal: Option<FsOperation>,
    },
    /// A call with no resource a rule can name: a clock read, entropy, or a sleep.
    Ungoverned,
}

impl<'p> ScriptPolicyInterceptor<'p> {
    /// Bind a policy and principal to the seam.
    pub fn new(policy: &'p PolicyEngine, principal: Principal, governed: GovernedBox) -> Self {
        Self {
            policy,
            principal,
            governed,
            home: None,
        }
    }

    /// Report every path under `home` as `~/<relative>`, matching the Shell adapter.
    ///
    /// **Consuming, and both adapters must agree.** A path attribute whose spelling depends on which
    /// interpreter served the request cannot be authored against, and the asymmetry is fail-open for
    /// a `forbid`.
    #[must_use]
    pub fn reporting_under(mut self, home: impl Into<std::path::PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Admit one suspended OS call.
    pub fn admit(&self, call: &OsFunctionCall) -> Result<ScriptPermit<'p>, ScriptRefusal> {
        let admitted = Self::classify(call, self.home.as_deref())
            .ok_or_else(|| ScriptRefusal::Unsupported(call.on_no_handler()))?;

        let decision = match &admitted {
            Admitted::Filesystem { path, operation } => self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::Fs {
                    path,
                    operation: *operation,
                },
            ),
            Admitted::Rename { .. } => unreachable!("rename is admitted through admit_rename"),
            // The one kind admitted with no decision. See `Admitted::Ungoverned`.
            Admitted::Ungoverned => return Ok(self.permit(admitted)),
        };

        match decision {
            Decision::Allow { .. } => Ok(self.permit(admitted)),
            Decision::Deny { .. } => Err(policy_refusal(&decision)),
        }
    }

    /// The spelling a decision names for `path`.
    #[must_use]
    pub fn reported(&self, path: &str) -> String {
        resolve(path, self.home.as_deref()).reported().into_owned()
    }

    /// Issue a permit for an already-authorized effect.
    fn permit(&self, admitted: Admitted) -> ScriptPermit<'p> {
        ScriptPermit {
            policy: self.policy,
            principal: self.principal.clone(),
            governed: self.governed.clone(),
            admitted,
            reported: false,
        }
    }

    /// Resolve a call into the identity and verbs policy judges it under.
    fn classify(call: &OsFunctionCall, home: Option<&std::path::Path>) -> Option<Admitted> {
        let fs = |path: &str, operation| {
            Some(Admitted::Filesystem {
                path: resolve(path, home),
                operation,
            })
        };

        match call {
            // --- content reads ---
            OsFunctionCall::ReadText(p) | OsFunctionCall::ReadBytes(p) => {
                fs(p.as_str(), FsOperation::ReadContent)
            }

            // --- metadata reads ---
            //
            // `Stat` is metadata, not content: it is `read_metadata`, not
            // `read_content`. Upstream's glue maps it alongside content reads, which
            // makes an `fs:stat`-shaped rule permit `exists()` while refusing
            // `stat()`. Metadata is the enumeration channel and gets its own
            // operation so a rule can allow probing layout without disclosing bytes.
            //
            // `IsSymlink` answers a question about the link itself, without following
            // it. The vocabulary does not separate follow from no-follow — it starts
            // coarse — so every probe is one `read_metadata`.
            OsFunctionCall::Stat(p)
            | OsFunctionCall::Exists(p)
            | OsFunctionCall::IsFile(p)
            | OsFunctionCall::IsDir(p)
            | OsFunctionCall::IsSymlink(p) => fs(p.as_str(), FsOperation::ReadMetadata),

            // `resolve()` / `absolute()` perform no I/O — they are lexical path
            // arithmetic — but they answer a question about the namespace, so they are
            // metadata reads rather than content reads.
            OsFunctionCall::Resolve(p) | OsFunctionCall::Absolute(p) => {
                fs(p.as_str(), FsOperation::ReadMetadata)
            }

            // --- enumeration ---
            OsFunctionCall::Iterdir(p) => fs(p.as_str(), FsOperation::Enumerate),

            // --- content writes ---
            //
            // Writes, appends, and creating opens are one `write_content`: the
            // vocabulary does not separate create from truncate.
            OsFunctionCall::WriteText(a) => fs(a.path.as_str(), FsOperation::WriteContent),
            OsFunctionCall::WriteBytes(a) => fs(a.path.as_str(), FsOperation::WriteContent),
            OsFunctionCall::AppendText(a) => fs(a.path.as_str(), FsOperation::WriteContent),
            OsFunctionCall::AppendBytes(a) => fs(a.path.as_str(), FsOperation::WriteContent),

            // `open()` is judged by its mode, and a read-write mode grants both
            // capabilities, so it is admitted as the write it is: authorizing it as a
            // read would disclose a mutation under a read-only permit.
            OsFunctionCall::Open(a) => fs(a.path.as_str(), open_effect(a.mode)),

            // --- namespace mutation ---
            //
            // `Mkdir` names one path, so one decision covers it. `parents=True` does
            // not: it creates every missing ancestor, and admitting the leaf would let
            // a host doing the natural `create_dir_all(permit.path())` create
            // `/w/a` and `/w/a/b` with no decision at all. Refusing is the only
            // fail-closed answer available here, because `ScriptPermit` carries no way
            // to tell the caller "this one, but not recursively" — an obligation the
            // API cannot express is not an obligation.
            //
            // A script wanting a tree should create each level, which yields one
            // decision per directory. Admitting the whole walk would need a pair-style
            // attempt carrying every path, which the policy vocabulary does not have.
            OsFunctionCall::Mkdir(a) if a.parents => None,
            OsFunctionCall::Mkdir(a) => fs(a.path.as_str(), FsOperation::CreateDir),
            // Unlinking acts on the name, not on whatever it points at, so removing a
            // file and removing a directory stay distinct verbs.
            OsFunctionCall::Unlink(p) => fs(p.as_str(), FsOperation::RemoveFile),
            OsFunctionCall::Rmdir(p) => fs(p.as_str(), FsOperation::RemoveDir),

            // A rename has two identities and permission to move the source does not
            // carry permission to create the target. The caller admits each side, so
            // the pair is not classified here — see
            // [`ScriptPolicyInterceptor::admit_rename`].
            OsFunctionCall::Rename(_) => None,

            // --- environment ---
            //
            // `os.getenv("X")` and `os.environ` are **REFUSED**, not authorized.
            //
            // There is no `env:read` action in `policy/schema/actions.cedarschema`, so
            // there is no way to say "may read the environment" — and the obvious
            // workaround is unsound. Authorizing it as a read of a synthetic path like
            // `/<env>/X` fails because a script can *spell* that path:
            // `normalize_virtual_path("/<env>/X")` returns it unchanged, so one name
            // would cover two different effects. A rule meant for environment variables
            // would silently also permit a file read, and a broad `fs:read` rule would
            // silently permit reading the whole environment. Two effects sharing one
            // name is exactly the confusion an allowlist exists to prevent.
            //
            // Refusing is the fail-closed answer while the vocabulary is missing, and it
            // matters here specifically: the box projects credential *phantoms* into the
            // workload's environment (`box/src/boundary.rs`, `project_credentials`), so
            // "who may read the environment" is a real authorization question and not
            // one to answer by accident. The phantoms are not the secrets — the proxy
            // swaps them back at the boundary — but binding names and phantom values
            // are still not free to hand out.
            //
            // The fix is a schema addition (an `env:read` action over a variable-name
            // resource), after which this becomes an ordinary `fs`-style arm. Until then
            // a script that needs a value should be given it as a `MontyRun` input.
            // Pinned by `an_environment_read_is_refused_while_the_schema_cannot_name_it`.
            OsFunctionCall::Getenv(_) | OsFunctionCall::GetEnviron => None,

            // --- not governed ---
            OsFunctionCall::DateToday
            | OsFunctionCall::DateTimeNow(_)
            | OsFunctionCall::Time(_)
            | OsFunctionCall::Urandom(_)
            | OsFunctionCall::Sleep(_)
            | OsFunctionCall::SystemSleep(_)
            | OsFunctionCall::AsyncSleep(_)
            | OsFunctionCall::AsyncSystemSleep(_) => Some(Admitted::Ungoverned),
            // No catch-all arm, deliberately. `OsFunctionCall` is not `non_exhaustive`,
            // so this match is exhaustive and a variant added upstream is a *compile
            // error* here rather than a runtime denial. That is stronger than failing
            // closed: the new operation cannot reach a build at all until someone
            // states what it is. If upstream ever marks the enum `non_exhaustive`, add
            // `_ => None` — denied — and not a permissive default.
        }
    }

    /// Admit a rename, whose source content and two identities are authorized separately.
    ///
    /// `bound_at` answers what the rename replaces at the destination it is given, and the caller
    /// reads it only at a destination its floor approved.
    pub fn admit_rename(
        &self,
        call: &OsFunctionCall,
        bound_at: impl FnOnce(&Path) -> RenameDestination,
    ) -> Result<(PathBuf, PathBuf, ScriptPermit<'p>), ScriptRefusal> {
        let OsFunctionCall::Rename(args) = call else {
            return Err(ScriptRefusal::Unsupported(call.on_no_handler()));
        };

        let home = self.home.as_deref();
        let source = resolve(args.src.as_str(), home);
        let destination = resolve(args.dst.as_str(), home);

        // A move of the source name still makes the source's bytes reachable through the
        // destination. Without this leg, a `forbid fs:read` on the source is laundered by a
        // permitted rename and a later read from the new name.
        let source_read_decision = self.policy.decide(
            &self.governed,
            &self.principal,
            &Request::Fs {
                path: &source,
                operation: FsOperation::ReadContent,
            },
        );
        if !matches!(source_read_decision, Decision::Allow { .. }) {
            return Err(policy_refusal(&source_read_decision));
        }

        // The source is being removed from its name, which is a write to it.
        let source_decision = self.policy.decide(
            &self.governed,
            &self.principal,
            &Request::Fs {
                path: &source,
                operation: FsOperation::Rename,
            },
        );
        if !matches!(source_decision, Decision::Allow { .. }) {
            return Err(policy_refusal(&source_decision));
        }

        // A name bound at the destination is removed by the rename, so that removal is
        // decided as `fs:delete` on the destination before the move onto it.
        let destination_removal = bound_at(destination.as_path()).removal();
        if let Some(removal) = destination_removal {
            let removal_decision = self.policy.decide(
                &self.governed,
                &self.principal,
                &Request::Fs {
                    path: &destination,
                    operation: removal,
                },
            );
            if !matches!(removal_decision, Decision::Allow { .. }) {
                return Err(policy_refusal(&removal_decision));
            }
        }

        let destination_decision = self.policy.decide(
            &self.governed,
            &self.principal,
            &Request::Fs {
                path: &destination,
                operation: FsOperation::Rename,
            },
        );
        if !matches!(destination_decision, Decision::Allow { .. }) {
            return Err(policy_refusal(&destination_decision));
        }

        let permit = ScriptPermit {
            policy: self.policy,
            principal: self.principal.clone(),
            governed: self.governed.clone(),
            admitted: Admitted::Rename {
                source_read_path: source.clone(),
                target_path: destination.clone(),
                destination_removal,
            },
            reported: false,
        };
        Ok((
            source.as_path().to_path_buf(),
            destination.as_path().to_path_buf(),
            permit,
        ))
    }
}

fn policy_refusal(decision: &Decision) -> ScriptRefusal {
    ScriptRefusal::Denied(decision.clone())
}

/// What a rename finds bound at its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameDestination {
    /// No name is bound, so the rename removes nothing.
    Unbound,
    /// A file, symlink, or other non-directory is bound.
    File,
    /// A directory is bound.
    Directory,
}

impl RenameDestination {
    /// Read what is bound at `path` without following a final symlink.
    ///
    /// An error other than not-found reports a file, so the removal leg is raised.
    #[must_use]
    pub fn bound_at(path: &Path) -> Self {
        match std::fs::symlink_metadata(path) {
            Ok(bound) if bound.is_dir() => Self::Directory,
            Ok(_) => Self::File,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Unbound,
            Err(_) => Self::File,
        }
    }

    fn removal(self) -> Option<FsOperation> {
        match self {
            Self::Unbound => None,
            Self::File => Some(FsOperation::RemoveFile),
            Self::Directory => Some(FsOperation::RemoveDir),
        }
    }
}

/// Why a call was not admitted.
#[derive(Debug, Clone)]
pub enum ScriptRefusal {
    /// The call is not one this adapter admits.
    Unsupported(MontyException),
    /// Policy refused the effect.
    Denied(Decision),
}

impl ScriptRefusal {
    /// The `PermissionError` a script receives when this adapter renders the refusal itself.
    #[must_use]
    pub fn into_exception(self) -> MontyException {
        match self {
            Self::Unsupported(exception) => exception,
            Self::Denied(decision) => {
                MontyException::new(ExcType::PermissionError, Some(decision.to_string()))
            }
        }
    }
}

impl ScriptPermit<'_> {
    /// The resolved **virtual** path this effect was admitted for.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match &self.admitted {
            Admitted::Filesystem { path, .. } => Some(path.as_path()),
            Admitted::Rename { target_path, .. } => Some(target_path.as_path()),
            Admitted::Ungoverned => None,
        }
    }

    /// Report how the effect ended, submitting it as history.
    pub fn record(mut self, result: FsResult) -> Result<(), crate::PolicyError> {
        // Claim the report before submitting, so the `Drop` below does not submit a
        // second, contradictory outcome for the same effect.
        self.reported = true;
        self.submit(result)
    }

    fn record_fs_outcome(
        &self,
        path: &ApprovedPath,
        operation: FsOperation,
        result: FsResult,
    ) -> Result<(), crate::PolicyError> {
        let reported = path.reported();
        self.policy.record(
            &self.governed,
            &self.principal,
            &Outcome::Fs {
                path: std::path::Path::new(reported.as_ref()),
                operation,
                result,
            },
        )
    }

    /// Submit one outcome as history.
    fn submit(&self, result: FsResult) -> Result<(), crate::PolicyError> {
        match &self.admitted {
            Admitted::Filesystem { path, operation } => {
                self.record_fs_outcome(path, *operation, result)
            }
            Admitted::Rename {
                source_read_path,
                target_path,
                destination_removal,
            } => {
                if result.response_result().is_some() {
                    self.record_fs_outcome(source_read_path, FsOperation::ReadContent, result)?;
                }
                if let Some(removal) = destination_removal {
                    self.record_fs_outcome(target_path, *removal, result)?;
                }
                self.record_fs_outcome(target_path, FsOperation::Rename, result)
            }
            // Nothing to report: an ungoverned call has no filesystem identity.
            Admitted::Ungoverned => Ok(()),
        }
    }
}

impl Drop for ScriptPermit<'_> {
    /// Record an admitted effect whose outcome was never reported.
    fn drop(&mut self) {
        if !self.reported && self.submit(FsResult::Indeterminate).is_err() {
            let _ = writeln!(
                std::io::stderr().lock(),
                "strands-box: warning: policy outcome recording was not confirmed"
            );
        }
    }
}

/// The path policy decides on, normalized so `.` and `..` cannot alias it.
///
/// This is the approval, and it is deliberately lexical. A script path lives in the
/// interpreter's **virtual** namespace, so `std::fs::canonicalize` would answer about a
/// different namespace. The normalizer is shared with
/// [`PathResolver::approve_virtual`](crate::PathResolver::approve_virtual), so the two
/// cannot drift.
///
/// It follows no symlink. The crate's `AGENTS.md` records that gap and names the two
/// directions it runs in; the host compares its own canonical result against this value
/// and refuses a difference.
fn resolve(path: &str, home: Option<&std::path::Path>) -> ApprovedPath {
    ApprovedPath::under_home(normalize_virtual(path), home)
}

/// The operation an `open()` mode performs. Every writing mode — write, append, and
/// `r+` update — is one `write_content`.
fn open_effect(mode: FileMode) -> FsOperation {
    match mode {
        FileMode::Read(_) => FsOperation::ReadContent,
        FileMode::Write(_)
        | FileMode::WriteUpdate(_)
        | FileMode::Append(_)
        | FileMode::AppendUpdate(_)
        | FileMode::ReadUpdate(_) => FsOperation::WriteContent,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use dogwood_local_engine::fault_injection::{FaultInjector, FaultPoint};
    use monty_types::{MontyPath, PathStringDataArgs};

    use super::*;
    use crate::Policy;
    use crate::rerun;

    const WARNING: &str = "strands-box: warning: policy outcome recording was not confirmed";

    struct ReleaseOnDrop(Arc<FaultInjector>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn sources() -> Vec<Policy> {
        vec![Policy {
            origin: PathBuf::from("script-store-faults.dw"),
            text: r#"permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);"#
                .to_string(),
        }]
    }

    fn write_text(path: &Path, data: &str) -> OsFunctionCall {
        OsFunctionCall::WriteText(PathStringDataArgs {
            path: MontyPath::new(path.to_str().expect("utf-8 path").to_string()),
            data: data.to_string(),
        })
    }

    fn interceptor(policy: &PolicyEngine) -> ScriptPolicyInterceptor<'_> {
        ScriptPolicyInterceptor::new(
            policy,
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        )
    }

    #[test]
    fn a_slow_store_holds_the_effect_until_decide_returns() {
        let history = tempfile::tempdir().expect("history directory");
        let workspace = tempfile::tempdir().expect("workspace");
        let target = workspace.path().join("held.txt");
        let faults = Arc::new(FaultInjector::new());
        let policy = PolicyEngine::open_with_faults(
            sources(),
            &history.path().join("dogwood.redb"),
            Arc::clone(&faults),
        )
        .expect("policy opens");
        let interceptor = interceptor(&policy);
        let call = write_text(&target, "after the verdict");
        let (performed, effects) = mpsc::channel();

        faults.arm(FaultPoint::AppendBeforeCommit);
        std::thread::scope(|scope| {
            let _release = ReleaseOnDrop(Arc::clone(&faults));
            scope.spawn(|| {
                let permit = interceptor.admit(&call).expect("the write is permitted");
                fs::write(
                    permit.path().expect("a filesystem permit carries its path"),
                    "after the verdict",
                )
                .expect("the effect runs");
                permit
                    .record(FsResult::Completed)
                    .expect("the outcome records");
                performed.send(()).expect("the test is waiting");
            });
            assert!(
                faults.wait_until_reached(Duration::from_secs(30)),
                "the decision must reach the store's append"
            );
            assert!(
                matches!(
                    effects.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ),
                "no verdict may return while the store blocks"
            );
            assert!(
                !target.exists(),
                "the effect must not run before the decision is durable"
            );
            faults.release();
            effects
                .recv_timeout(Duration::from_secs(30))
                .expect("the decision completes once the store resumes");
        });

        assert_eq!(
            fs::read_to_string(&target).expect("the effect ran once the store resumed"),
            "after the verdict"
        );
    }

    #[test]
    fn a_failed_record_returns_the_store_fault_to_the_caller() {
        let history = tempfile::tempdir().expect("history directory");
        let workspace = tempfile::tempdir().expect("workspace");
        let target = workspace.path().join("written.txt");
        let policy = PolicyEngine::open(sources(), &history.path().join("dogwood.redb"))
            .expect("policy opens");
        let interceptor = interceptor(&policy);
        let permit = interceptor
            .admit(&write_text(&target, "kept"))
            .expect("the write is permitted");
        fs::write(
            permit.path().expect("a filesystem permit carries its path"),
            "kept",
        )
        .expect("the effect runs");

        policy.poison_store_for_test();

        let error = permit
            .record(FsResult::Completed)
            .expect_err("a store fault must reach the caller");
        assert!(error.to_string().contains("poisoned"), "{error}");
        let refusal = interceptor
            .admit(&write_text(&target, "again"))
            .expect_err("nothing is admitted after the store fault");
        assert!(
            refusal
                .into_exception()
                .message()
                .unwrap_or_default()
                .ends_with(" because the request could not be evaluated."),
        );
    }

    #[test]
    #[ignore = "runs only as the child process that a_failed_record_warns_once_and_names_no_path starts through rerun::stderr_of"]
    fn two_permits_meet_a_failed_store() {
        let history = tempfile::tempdir().expect("history directory");
        let workspace = tempfile::tempdir().expect("workspace");
        let secret = workspace.path().join("api-key.txt");
        let policy = PolicyEngine::open(sources(), &history.path().join("dogwood.redb"))
            .expect("policy opens");
        let interceptor = interceptor(&policy);
        let reported = interceptor
            .admit(&write_text(&secret, "hunter2"))
            .expect("the first write is permitted");
        let dropped = interceptor
            .admit(&write_text(&secret, "hunter2"))
            .expect("the second write is permitted");

        policy.poison_store_for_test();

        assert!(reported.record(FsResult::Completed).is_err());
        drop(dropped);
    }

    #[test]
    fn a_failed_record_warns_once_and_names_no_path() {
        let stderr = rerun::stderr_of(&rerun::test_name(
            module_path!(),
            "two_permits_meet_a_failed_store",
        ));
        let warnings: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("strands-box: warning"))
            .collect();
        assert_eq!(warnings, vec![WARNING], "{stderr}");
        assert!(
            !stderr.contains("api-key") && !stderr.contains("hunter2"),
            "{stderr}"
        );
    }
}
