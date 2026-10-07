//! Authored `fs:*` rules govern real Python effects run through Monty, end to end.
//!
//! These tests execute actual Python source in the Monty interpreter, service every OS
//! suspension through [`ScriptPolicyInterceptor`] against a real [`PolicyEngine`], and assert
//! the rules bite. Nothing is stubbed: the same `PolicyEngine::open` → `decide` → `record`
//! path the Shell adapter uses is the one under test here.
//!
//! The host loop below is also the reference for how an embedder drives this seam, and
//! it is deliberately small — that it fits in one function is the point of choosing the
//! interpreter's suspension boundary as the enforcement point.
//!
//! Two cases here assert **limitations** rather than defended properties, so that neither
//! can be closed silently or mistaken for coverage:
//! `script_symlink_aliasing_is_not_defended` (lexical normalization does not follow
//! symlinks) and `an_environment_read_is_refused_while_the_schema_cannot_name_it`
//! (`os.getenv` / `os.environ` are refused outright, because no `env:read` action
//! exists). Each names what would have to change for it to be updated.

#![cfg(feature = "script-adapter")]

mod support;

use std::fs;
use std::path::PathBuf;

use monty::{MontyRun, RunProgress};
use monty_types::{
    CompileOptions, ExcType, ExtFunctionResult, MontyException, MontyObject, MontyPath,
    OsFunctionCall, PrintWriter, ResourceTracker, unstable::MontyNode,
};
use policy::{
    FsResult, GovernedBox, Policy, Principal, RenameDestination, ScriptPolicyInterceptor,
};

/// The box this suite governs. One box, so one name.
const BOX_NAME: &str = "script-fs";

/// How one script run ended.
#[derive(Debug)]
enum Ran {
    /// The script completed. Carries whatever it evaluated to.
    Completed(MontyNode),
    /// The script raised, and nothing caught it.
    Raised(ExcType, String),
}

impl Ran {
    /// The exception message, for asserting *which* path was refused.
    fn message(&self) -> &str {
        match self {
            Ran::Completed(_) => "",
            Ran::Raised(_, message) => message,
        }
    }

    fn raised(&self) -> Option<ExcType> {
        match self {
            Ran::Raised(kind, _) => Some(*kind),
            Ran::Completed(_) => None,
        }
    }
}

/// Run `source` under `rules`, servicing every OS call through the adapter.
///
/// This is the whole integration: suspend, admit, perform the effect **against the
/// resolved path the permit carries**, record, resume. A denial is resumed as the
/// exception the adapter produced, so the script observes an ordinary Python error and
/// may catch it — the interpreter never sees a policy type.
fn run_governed(rules: &str, source: &str) -> Ran {
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("script-fs-e2e.cedar"),
        text: rules.to_string(),
    }])
    .expect("policy opens");
    let interceptor =
        ScriptPolicyInterceptor::new(&policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));

    let run = MontyRun::new(
        source.to_string(),
        "e2e.py",
        Vec::new(),
        CompileOptions::default(),
    )
    .expect("source compiles");
    let mut progress = match run.start(
        Vec::new(),
        ResourceTracker::default(),
        PrintWriter::Disabled,
    ) {
        Ok(progress) => progress,
        Err(exception) => return raised(&exception),
    };

    loop {
        progress = match progress {
            RunProgress::Complete(value) => {
                return Ran::Completed(monty_types::unstable::root_node(&value).clone());
            }

            RunProgress::OsCall(call) => {
                let function_call = call.function_call.clone();

                // A rename carries two identities, so it is admitted as a pair.
                let stepped = if matches!(function_call, OsFunctionCall::Rename(_)) {
                    match interceptor.admit_rename(&function_call, RenameDestination::bound_at) {
                        Ok((source_path, destination, permit)) => {
                            let outcome = fs::rename(&source_path, &destination);
                            let result = if outcome.is_ok() {
                                FsResult::Completed
                            } else {
                                FsResult::Failed
                            };
                            permit.record(result).expect("history records");
                            match outcome {
                                Ok(()) => call.resume(MontyObject::none(), PrintWriter::Disabled),
                                Err(error) => {
                                    call.resume(io_exception(&error), PrintWriter::Disabled)
                                }
                            }
                        }
                        Err(refusal) => {
                            call.resume(refusal.into_exception(), PrintWriter::Disabled)
                        }
                    }
                } else {
                    match interceptor.admit(&function_call) {
                        Ok(permit) => {
                            let (result, resume_with) = perform(&function_call, permit.path());
                            permit.record(result).expect("history records");
                            call.resume(resume_with, PrintWriter::Disabled)
                        }
                        // Resuming with the denial is what makes the refusal visible to
                        // Python as `PermissionError` rather than killing the run.
                        Err(refusal) => {
                            call.resume(refusal.into_exception(), PrintWriter::Disabled)
                        }
                    }
                };

                match stepped {
                    Ok(next) => next,
                    Err(exception) => return raised(&exception),
                }
            }

            // No external functions, name lookups, or futures are used by these
            // scripts. Reaching one means the test fixture drifted, not that policy
            // failed, so fail loudly rather than silently passing.
            other => panic!("unexpected suspension: {}", describe(&other)),
        };
    }
}

/// Perform one admitted effect against the resolved path, never the caller's spelling.
///
/// Only the operations these tests exercise are implemented; an admitted call this host
/// does not perform resumes as an error rather than pretending to succeed.
fn perform(
    call: &OsFunctionCall,
    resolved: Option<&std::path::Path>,
) -> (FsResult, ExtFunctionResult) {
    let Some(path) = resolved else {
        return (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::none()),
        );
    };

    match call {
        OsFunctionCall::ReadText(_) => match fs::read_to_string(path) {
            Ok(text) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::string(text)),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::WriteText(args) => match fs::write(path, args.data.as_str()) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::int(
                    args.data.as_str().len().try_into().unwrap_or(i64::MAX),
                )),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::Exists(_) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::bool(path.exists())),
        ),
        // Single-level only: the recursive form never reaches here, because the adapter
        // refuses it. `create_dir` rather than `create_dir_all` is the point — a host
        // that reached for the latter would create ancestors with no decision.
        OsFunctionCall::Mkdir(_) => match fs::create_dir(path) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::Rmdir(_) => match fs::remove_dir(path) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::Unlink(_) => match fs::remove_file(path) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        _ => (
            FsResult::Failed,
            MontyException::new(
                ExcType::RuntimeError,
                Some(format!("{} unsupported by this host", call.name())),
            )
            .into(),
        ),
    }
}

fn io_exception(error: &std::io::Error) -> MontyException {
    MontyException::new(ExcType::OSError, Some(error.to_string()))
}

fn raised(exception: &MontyException) -> Ran {
    Ran::Raised(
        exception.exc_type(),
        exception.message().unwrap_or_default().to_string(),
    )
}

fn describe(progress: &RunProgress) -> &'static str {
    match progress {
        RunProgress::Complete(_) => "complete",
        RunProgress::OsCall(_) => "os call",
        RunProgress::FunctionCall(_) => "function call",
        RunProgress::NameLookup(_) => "name lookup",
        RunProgress::ResolveFutures(_) => "resolve futures",
    }
}

/// Everything a script needs, so a test can subtract one rule and see it bite.
const PERMIT_ALL: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;

/// Reads permitted only under a workspace subtree.
const READ_WORKSPACE_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "/workspace/*" };
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
"#;

// ---------------------------------------------------------------------------
// The seam works at all: a permitted effect happens, a refused one raises.
// ---------------------------------------------------------------------------

#[test]
fn a_permitted_read_reaches_the_file() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("greeting.txt");
    fs::write(&file, "hello from python").expect("fixture writes");

    let source = format!(
        "from pathlib import Path\nPath({:?}).read_text()\n",
        file.to_str().expect("utf-8 path")
    );
    let ran = run_governed(PERMIT_ALL, &source);

    match ran {
        Ran::Completed(MontyNode::String(text)) => assert_eq!(text, "hello from python"),
        other => panic!("expected the file contents, got {other:?}"),
    }
}

#[test]
fn a_refused_read_raises_permission_error_rather_than_crashing() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("secret.txt");
    fs::write(&file, "classified").expect("fixture writes");

    // The file exists and is readable on the host; only policy stands in the way.
    let source = format!(
        "from pathlib import Path\nPath({:?}).read_text()\n",
        file.to_str().expect("utf-8 path")
    );
    let ran = run_governed(READ_WORKSPACE_ONLY, &source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "a denial must surface as PermissionError, not as a crash or a silent empty read: {ran:?}"
    );
    assert_eq!(
        fs::read_to_string(&file).expect("still there"),
        "classified"
    );
}

#[test]
fn a_script_can_catch_a_denial_like_any_python_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("secret.txt");
    fs::write(&file, "classified").expect("fixture writes");

    // Proves the denial is an ordinary exception in the interpreter, not a host-level
    // abort: Python semantics are preserved through the refusal.
    let source = format!(
        r#"
from pathlib import Path
try:
    Path({:?}).read_text()
    outcome = "read"
except PermissionError:
    outcome = "refused"
outcome
"#,
        file.to_str().expect("utf-8 path")
    );
    let ran = run_governed(READ_WORKSPACE_ONLY, &source);

    match ran {
        Ran::Completed(MontyNode::String(outcome)) => assert_eq!(outcome, "refused"),
        other => panic!("expected a caught denial, got {other:?}"),
    }
}

#[test]
fn a_python_denial_returns_the_policy_description() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("secret.txt");
    fs::write(&file, "classified").expect("fixture writes");
    let source = format!(
        "from pathlib import Path\nPath({:?}).read_text()\n",
        file.to_str().expect("utf-8 path")
    );
    let ran = run_governed(
        r#"@id("protected-content")
           @description("This file contains protected information.")
           forbid(principal, action == Box::Action::"fs:read", resource);"#,
        &source,
    );
    assert_eq!(ran.raised(), Some(ExcType::PermissionError));
    assert_eq!(
        ran.message(),
        format!(
            "policy denied this operation on '{}' [policy: protected-content]: This file contains protected information.",
            file.display()
        ),
        "{ran:?}"
    );
    assert_eq!(
        fs::read_to_string(file).expect("the file remains"),
        "classified"
    );
}

#[test]
fn a_python_rename_denial_describes_the_refused_leg() {
    let directory = tempfile::tempdir().expect("temp dir");
    let original = directory.path().join("original.txt");
    let destination = directory.path().join("destination.txt");
    fs::write(&original, "classified").expect("fixture writes");
    let source = format!(
        "from pathlib import Path\nPath({:?}).rename(Path({:?}))\n",
        original.to_str().expect("utf-8 path"),
        destination.to_str().expect("utf-8 path"),
    );
    for (action, path) in [
        ("fs:read", &original),
        ("fs:move", &original),
        ("fs:move", &destination),
    ] {
        let ran = run_governed(
            &format!(
                r#"{PERMIT_ALL}
                   @id("rename-refusal")
                   @description("This part of the rename is forbidden.")
                   forbid(principal, action == Box::Action::"{action}", resource)
                   when {{ context.input.path == {path:?} }};"#,
                path = path.to_str().expect("utf-8 path"),
            ),
            &source,
        );
        assert_eq!(ran.raised(), Some(ExcType::PermissionError), "{ran:?}");
        assert!(
            ran.message()
                .contains("This part of the rename is forbidden."),
            "{action} {path:?}: {ran:?}"
        );
        assert_eq!(
            fs::read_to_string(&original).expect("the source remains"),
            "classified"
        );
        assert!(!destination.exists());
    }
}

// ---------------------------------------------------------------------------
// The evasion classes the exploration found in the upstream glue.
// ---------------------------------------------------------------------------

/// `..` traversal must not satisfy a rule written for the directory it escapes.
///
/// This is the defect that motivated resolving before admitting: the raw spelling
/// `/workspace/out/../../secret.txt` matches `like "/workspace/*"` — Cedar's `*` spans
/// `/` — while the effect lands outside `/workspace` entirely. Authorizing the spelling
/// permits it; authorizing the resolved path refuses it.
#[test]
fn parent_traversal_cannot_launder_a_path_into_a_permitted_prefix() {
    let source = r#"
from pathlib import Path
Path("/workspace/out/../../secret.txt").read_text()
"#;
    let ran = run_governed(READ_WORKSPACE_ONLY, source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "`..` must be resolved before the decision, or a rule for /workspace/* covers /secret.txt: {ran:?}"
    );
    // Deliberately no assertion on the message. `on_no_handler` builds it from the
    // *original* `MontyPath`, so it reports the raw spelling — a `contains("/secret.txt")`
    // check would pass whether policy judged the resolved path or the raw one, and prove
    // nothing. The verdict above is the discriminating assertion, and it dies if
    // normalization is removed.
}

/// The same laundering in the direction that matters more: escaping a `forbid`.
///
/// The spelling is chosen so the forbid *only* matches after normalization. Unnormalized
/// it begins `/tmp/`, which `like "/secrets/*"` does not match — so a decision made on
/// the spelling lets the bare `permit` through and the read succeeds. Normalized it is
/// `/secrets/key.pem`, and the forbid overrides. A path that reads `/secrets/…` in both
/// forms would pass either way and prove nothing.
#[test]
fn parent_traversal_cannot_escape_a_forbid() {
    const FORBID_SECRETS: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.path like "/secrets/*" };
"#;

    let source = r#"
from pathlib import Path
Path("/tmp/../secrets/key.pem").read_text()
"#;
    let ran = run_governed(FORBID_SECRETS, source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "a forbid must catch a path that only normalizes into it: {ran:?}"
    );
}

/// A symlink at a permitted path still reaches its forbidden target.
///
/// **This test asserts a known limitation, not a defended property.** Normalization is
/// lexical, so it closes `..` and does nothing about symlinks: a link inside a permitted
/// subtree is judged on the link's own path, and the read follows it out. The test exists
/// so the gap is visible, cannot be closed by accident without someone updating it, and
/// is not mistaken for coverage. See the limitation note on `resolve` in
/// `src/adapters/script.rs`.
///
/// Closing it requires the host to canonicalize inside the decision path and accept the
/// TOCTOU window that introduces — the same amendment the Shell tracks. Until then,
/// containment (confining the workload to a subtree with no links leading out) is the
/// control that covers this, not policy.
#[test]
fn script_symlink_aliasing_is_not_defended() {
    let directory = tempfile::tempdir().expect("temp dir");
    let permitted = directory.path().join("workspace");
    fs::create_dir(&permitted).expect("fixture dir");
    let secret = directory.path().join("secret.txt");
    fs::write(&secret, "classified").expect("fixture writes");

    let link = permitted.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret, &link).expect("fixture links");
    #[cfg(not(unix))]
    return;

    // Permit only the workspace subtree the link lives in.
    let rules = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {{ context.input.path like "{}/*" }};
"#,
        permitted.to_str().expect("utf-8 path")
    );
    let source = format!(
        "from pathlib import Path\nPath({:?}).read_text()\n",
        link.to_str().expect("utf-8 path")
    );
    let ran = run_governed(&rules, &source);

    match ran {
        Ran::Completed(MontyNode::String(text)) => assert_eq!(
            text, "classified",
            "the read succeeded, which is the documented limitation"
        ),
        other => panic!(
            "symlink aliasing is expected to SUCCEED today — if this now fails, the gap \
             was closed and both this test and the limitation note on `resolve` should \
             be updated: {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Both identities of a rename, and the mode an `open` really performs.
// ---------------------------------------------------------------------------

/// A rename must be refused when only its *source* is permitted.
///
/// Permission to move a file out of a directory does not carry permission to create it
/// anywhere the script chooses, so both identities are decided and the narrower verdict
/// governs. Without the destination decision, a script with write access to a scratch
/// directory could move a payload into a protected one.
#[test]
fn a_rename_needs_its_destination_permitted_not_only_its_source() {
    let directory = tempfile::tempdir().expect("temp dir");
    let scratch = directory.path().join("scratch");
    let protected = directory.path().join("protected");
    fs::create_dir(&scratch).expect("fixture dir");
    fs::create_dir(&protected).expect("fixture dir");
    let payload = scratch.join("payload.txt");
    fs::write(&payload, "payload").expect("fixture writes");
    let target = protected.join("payload.txt");

    // Moves permitted under the scratch directory only. The source satisfies this; the
    // destination does not. A rename rides `fs:move`, and both its identities are decided.
    let rules = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource)
when {{ context.input.path like "{}/*" }};
"#,
        scratch.to_str().expect("utf-8 path")
    );
    let source = format!(
        "from pathlib import Path\nPath({:?}).rename({:?})\n",
        payload.to_str().expect("utf-8 path"),
        target.to_str().expect("utf-8 path")
    );
    let ran = run_governed(&rules, &source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "a rename whose destination is not permitted must be refused: {ran:?}"
    );
    assert!(
        !target.exists(),
        "the refused rename must not have landed the payload in the protected directory"
    );
    assert!(payload.exists(), "the source must be untouched");
}

/// A Python rename onto an existing file is refused by a `forbid` on deleting that file, and the
/// same rename onto an absent name is a plain move.
#[test]
fn a_python_rename_onto_an_existing_file_is_refused_by_a_forbid_on_deleting_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let protected = directory.path().join("protected.txt");
    let payload = directory.path().join("payload.txt");
    let fresh = directory.path().join("fresh.txt");
    fs::write(&protected, "original").expect("fixture writes");
    fs::write(&payload, "PWNED").expect("fixture writes");
    let rules = format!(
        r#"{PERMIT_ALL}
@id("no-delete")
forbid(principal, action == Box::Action::"fs:delete", resource)
when {{ context.input.path == {:?} }};
"#,
        protected.to_str().expect("utf-8 path")
    );

    let overwrite = run_governed(
        &rules,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            payload.to_str().expect("utf-8 path"),
            protected.to_str().expect("utf-8 path")
        ),
    );
    assert_eq!(
        overwrite.raised(),
        Some(ExcType::PermissionError),
        "a rename onto a file whose deletion is forbidden must be refused: {overwrite:?}"
    );
    assert!(
        overwrite.message().contains(&format!(
            "policy denied this operation on '{}' [policy: no-delete]",
            protected.to_str().expect("utf-8 path")
        )),
        "{}",
        overwrite.message()
    );
    assert_eq!(
        fs::read_to_string(&protected).expect("protected reads"),
        "original",
        "the protected file's content must be untouched"
    );
    assert!(
        payload.exists(),
        "the refused rename leaves its source in place"
    );

    let moved = run_governed(
        &rules,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            payload.to_str().expect("utf-8 path"),
            fresh.to_str().expect("utf-8 path")
        ),
    );
    assert!(
        moved.raised().is_none(),
        "the same rename onto an absent name is a plain move: {moved:?}"
    );
    assert_eq!(fs::read_to_string(&fresh).expect("moved"), "PWNED");
}

/// Without an `fs:delete` permit, a Python rename onto an existing file is refused by
/// default-deny, while `fs:move` alone still carries a rename onto an absent name.
#[test]
fn a_python_rename_onto_an_existing_file_needs_an_fs_delete_permit() {
    const WITHOUT_DELETE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;
    let directory = tempfile::tempdir().expect("temp dir");
    let existing = directory.path().join("existing.txt");
    let payload = directory.path().join("payload.txt");
    let fresh = directory.path().join("fresh.txt");
    fs::write(&existing, "original").expect("fixture writes");
    fs::write(&payload, "PWNED").expect("fixture writes");

    let overwrite = run_governed(
        WITHOUT_DELETE,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            payload.to_str().expect("utf-8 path"),
            existing.to_str().expect("utf-8 path")
        ),
    );
    assert_eq!(
        overwrite.raised(),
        Some(ExcType::PermissionError),
        "a rename onto an existing file needs an fs:delete permit: {overwrite:?}"
    );
    assert!(
        overwrite.message().contains(&format!(
            "policy denied this operation on '{}' [default-deny]",
            existing.to_str().expect("utf-8 path")
        )),
        "{}",
        overwrite.message()
    );
    assert_eq!(
        fs::read_to_string(&existing).expect("existing reads"),
        "original",
        "the existing file's content must be untouched"
    );

    let moved = run_governed(
        WITHOUT_DELETE,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            payload.to_str().expect("utf-8 path"),
            fresh.to_str().expect("utf-8 path")
        ),
    );
    assert!(
        moved.raised().is_none(),
        "fs:move alone carries a rename onto an absent name: {moved:?}"
    );
    assert_eq!(fs::read_to_string(&fresh).expect("moved"), "PWNED");
}

/// A Python rename onto an existing directory is a `remove_dir`, and onto a file a
/// `remove_file`, so a rule narrowed on either operation reaches the rename it names.
#[test]
fn a_python_rename_onto_a_directory_is_deleted_as_remove_dir() {
    const NO_REMOVE_DIR: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource)
when { context.input.operation == Box::FsDeleteOperation::"remove_file" };
"#;
    let directory = tempfile::tempdir().expect("temp dir");
    let source_dir = directory.path().join("source-dir");
    let target_dir = directory.path().join("target-dir");
    let source_file = directory.path().join("source.txt");
    let target_file = directory.path().join("target.txt");
    fs::create_dir(&source_dir).expect("fixture dir");
    fs::create_dir(&target_dir).expect("fixture dir");
    fs::write(&source_file, "new").expect("fixture writes");
    fs::write(&target_file, "old").expect("fixture writes");

    let onto_directory = run_governed(
        NO_REMOVE_DIR,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            source_dir.to_str().expect("utf-8 path"),
            target_dir.to_str().expect("utf-8 path")
        ),
    );
    assert_eq!(
        onto_directory.raised(),
        Some(ExcType::PermissionError),
        "a rename onto a directory is a remove_dir, which this policy does not permit: {onto_directory:?}"
    );
    assert!(
        onto_directory.message().contains(&format!(
            "policy denied this operation on '{}' [default-deny]",
            target_dir.to_str().expect("utf-8 path")
        )),
        "{}",
        onto_directory.message()
    );
    assert!(
        source_dir.exists() && target_dir.exists(),
        "both directories remain"
    );

    let onto_file = run_governed(
        NO_REMOVE_DIR,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            source_file.to_str().expect("utf-8 path"),
            target_file.to_str().expect("utf-8 path")
        ),
    );
    assert!(
        onto_file.raised().is_none(),
        "a rename onto a file is a remove_file, which this policy permits: {onto_file:?}"
    );
    assert_eq!(fs::read_to_string(&target_file).expect("replaced"), "new");
}

/// A destination whose state cannot be read is treated as bound, so the removal leg is raised
/// and an `fs:move`-only policy refuses the rename rather than letting it through unjudged.
#[test]
fn a_destination_whose_state_cannot_be_read_is_treated_as_bound() {
    const WITHOUT_DELETE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#;
    let directory = tempfile::tempdir().expect("temp dir");
    let payload = directory.path().join("payload.txt");
    let file = directory.path().join("file.txt");
    fs::write(&payload, "PWNED").expect("fixture writes");
    fs::write(&file, "a file, not a directory").expect("fixture writes");
    // A path beneath a regular file: `symlink_metadata` fails with `NotADirectory`, not `NotFound`.
    let unreadable = file.join("child");

    assert_eq!(
        RenameDestination::bound_at(&unreadable),
        RenameDestination::File,
        "a stat error other than not-found reads as a bound file"
    );
    assert_eq!(
        RenameDestination::bound_at(&directory.path().join("absent")),
        RenameDestination::Unbound,
        "not-found reads as unbound"
    );

    let ran = run_governed(
        WITHOUT_DELETE,
        &format!(
            "from pathlib import Path\nPath({:?}).rename({:?})\n",
            payload.to_str().expect("utf-8 path"),
            unreadable.to_str().expect("utf-8 path")
        ),
    );
    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "the removal leg is raised for a destination whose state cannot be read: {ran:?}"
    );
    assert!(
        ran.message().contains(&format!(
            "policy denied this operation on '{}' [default-deny]",
            unreadable.to_str().expect("utf-8 path")
        )),
        "{}",
        ran.message()
    );
    assert!(
        payload.exists(),
        "the refused rename leaves its source in place"
    );
}

/// A rename must also satisfy `fs:read` on its source.
///
/// A move changes only the name, but it still makes the source bytes reachable at the
/// destination. Without this leg, a script can rename `secret.txt` to `shared-secret.txt`
/// under a policy that forbids reading the first name and permits reading the second.
#[test]
fn a_rename_cannot_launder_a_read_denial_into_a_new_name() {
    let directory = tempfile::tempdir().expect("temp dir");
    let source_path = directory.path().join("secret.txt");
    let destination_path = directory.path().join("shared-secret.txt");
    fs::write(&source_path, "classified").expect("fixture writes");

    let rules = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {{ context.input.path like "{}{}shared-*" }};
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource)
when {{ context.input.path like "{}{}*" }};
"#,
        directory.path().display(),
        std::path::MAIN_SEPARATOR,
        directory.path().display(),
        std::path::MAIN_SEPARATOR,
    );
    let source = format!(
        r#"
from pathlib import Path
source = Path({:?})
destination = Path({:?})
try:
    source.rename(destination)
    outcome = destination.read_text()
except PermissionError:
    outcome = "refused"
outcome
"#,
        source_path.to_str().expect("utf-8 path"),
        destination_path.to_str().expect("utf-8 path")
    );
    let ran = run_governed(&rules, &source);

    match ran {
        Ran::Completed(MontyNode::String(outcome)) => assert_eq!(outcome, "refused"),
        other => panic!("the rename must be refused before the new name is readable: {other:?}"),
    }
    assert!(
        source_path.exists(),
        "the source must remain when the rename would launder a denied read"
    );
    assert!(
        !destination_path.exists(),
        "the destination must not be created when the rename is refused"
    );
}

/// A rename with both sides permitted proceeds, so the check above is not just a
/// blanket refusal of every rename.
#[test]
fn a_rename_with_both_identities_permitted_proceeds() {
    let directory = tempfile::tempdir().expect("temp dir");
    let from = directory.path().join("before.txt");
    let to = directory.path().join("after.txt");
    fs::write(&from, "moved").expect("fixture writes");

    let source = format!(
        "from pathlib import Path\nPath({:?}).rename({:?})\n",
        from.to_str().expect("utf-8 path"),
        to.to_str().expect("utf-8 path")
    );
    let ran = run_governed(PERMIT_ALL, &source);

    assert!(
        ran.raised().is_none(),
        "a fully permitted rename should succeed: {ran:?}"
    );
    assert_eq!(fs::read_to_string(&to).expect("moved"), "moved");
    assert!(!from.exists(), "the source name should be gone");
}

#[test]
fn a_rename_source_satisfies_a_response_keyed_precondition() {
    // The operator-facing temporal guard keys on
    // `fs:read::response`, so a successful rename must record the source as a completed read.
    let directory = tempfile::tempdir().expect("temp dir");
    let secret_path = directory.path().join("secret.txt");
    let loot_path = directory.path().join("loot.txt");
    let exfil_path = directory.path().join("exfil.txt");

    let rules = format!(
        r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
forbid(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource)
when temporal {{
    formerly within 3600s (
        Box::Action::"fs:read"::response{{
            input.path: "{secret}",
            input.operation: Box::FsReadOperation::"read_content"
        }}
    )
}};
"#,
        secret = secret_path.display(),
    );
    let source = format!(
        r#"
from pathlib import Path
secret = Path({secret:?})
loot = Path({loot:?})
exfil = Path({exfil:?})
secret.write_text("TOPSECRET")
secret.rename(loot)
payload = loot.read_text()
try:
    exfil.write_text("EXFIL")
    outcome = "allowed"
except PermissionError:
    outcome = payload + "::refused"
outcome
"#,
        secret = secret_path.to_str().expect("utf-8 path"),
        loot = loot_path.to_str().expect("utf-8 path"),
        exfil = exfil_path.to_str().expect("utf-8 path"),
    );
    let ran = run_governed(&rules, &source);

    match ran {
        Ran::Completed(MontyNode::String(outcome)) => {
            assert_eq!(
                outcome, "TOPSECRET::refused",
                "the rename must satisfy the temporal guard and deny the later write"
            );
        }
        other => panic!("the script must complete with the denied-write marker: {other:?}"),
    }
    assert!(
        !exfil_path.exists(),
        "the guarded write must not create the exfiltration file"
    );
}

/// An `open` in a writing mode is admitted as a write, not a read.
///
/// `open` is the one call whose verb depends on an argument rather than the operation
/// name, so a read-only policy must not satisfy it. The `+` update modes — where this
/// matters most, since `r+` mutates without creating or truncating — are rejected by the
/// interpreter itself today ("update modes ('+') are not yet supported"), so they cannot
/// be exercised end to end; `open_effect` maps them to `FsAccess::Write` for when they
/// land. `"w"` is the reachable case.
#[test]
fn a_writing_open_is_admitted_as_a_write() {
    const READ_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;

    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("data.txt");
    fs::write(&file, "original").expect("fixture writes");

    let source = format!("open({:?}, \"w\")\n", file.to_str().expect("utf-8 path"));
    let ran = run_governed(READ_ONLY, &source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "a writing open must not be satisfied by a read-only policy: {ran:?}"
    );
    assert_eq!(
        fs::read_to_string(&file).expect("still there"),
        "original",
        "the refused open must not have altered the file"
    );
}

/// `mkdir(parents=True)` is refused: it performs more effects than one decision covers.
///
/// The recursive form creates every missing ancestor, and only the leaf is named. Since
/// a permit carries no way to say "this one, but not recursively", refusing is the only
/// fail-closed answer — a host doing `create_dir_all(permit.path())` would otherwise
/// create the intermediate directories with no decision at all. Creating each level
/// explicitly still works and yields one decision per directory.
#[test]
fn a_recursive_mkdir_is_refused_even_when_writes_are_permitted() {
    let directory = tempfile::tempdir().expect("temp dir");
    let deep = directory.path().join("a/b/c");

    let source = format!(
        "from pathlib import Path\nPath({:?}).mkdir(parents=True)\n",
        deep.to_str().expect("utf-8 path")
    );
    let ran = run_governed(PERMIT_ALL, &source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "parents=True must be refused: one decision cannot cover N creations: {ran:?}"
    );
    assert!(
        !directory.path().join("a").exists(),
        "no ancestor may be created under a refused recursive mkdir"
    );
}

/// A single-level `mkdir` is permitted, so the refusal above is not blanket.
#[test]
fn a_single_level_mkdir_is_permitted() {
    let directory = tempfile::tempdir().expect("temp dir");
    let child = directory.path().join("child");

    let source = format!(
        "from pathlib import Path\nPath({:?}).mkdir()\n",
        child.to_str().expect("utf-8 path")
    );
    let ran = run_governed(PERMIT_ALL, &source);

    assert!(
        ran.raised().is_none(),
        "one directory is one decision and should be permitted: {ran:?}"
    );
}

/// Removing a file and removing a directory are distinguishable within one action.
///
/// Both ride `fs:delete`, so without the operation distinction a rule could not permit
/// tidying files while refusing to remove the directories holding them. `context.input
/// .operation` narrows within the coarse action.
#[test]
fn removing_a_file_is_distinguishable_from_removing_a_directory() {
    const UNLINK_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:delete", resource)
when { context.input.operation == Box::FsDeleteOperation::"remove_file" };
"#;

    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("scratch.txt");
    let subdir = directory.path().join("subdir");
    fs::write(&file, "scratch").expect("fixture writes");
    fs::create_dir(&subdir).expect("fixture dir");

    let unlink = run_governed(
        UNLINK_ONLY,
        &format!(
            "from pathlib import Path\nPath({:?}).unlink()\n",
            file.to_str().expect("utf-8 path")
        ),
    );
    assert!(
        unlink.raised().is_none(),
        "unlink should be permitted by a remove_file rule: {unlink:?}"
    );
    assert!(!file.exists(), "the permitted unlink should have happened");

    let rmdir = run_governed(
        UNLINK_ONLY,
        &format!(
            "from pathlib import Path\nPath({:?}).rmdir()\n",
            subdir.to_str().expect("utf-8 path")
        ),
    );
    assert_eq!(
        rmdir.raised(),
        Some(ExcType::PermissionError),
        "rmdir must not inherit a remove_file permit: {rmdir:?}"
    );
    assert!(subdir.exists(), "the refused rmdir must not have happened");
}

// ---------------------------------------------------------------------------
// Fail-closed: the property that inverts the upstream glue's `Option` default.
// ---------------------------------------------------------------------------

/// An operation with no rule permitting it is refused, not allowed through.
#[test]
fn an_unpermitted_operation_is_refused_by_the_allowlist() {
    const READ_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
"#;

    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("out.txt");

    let source = format!(
        "from pathlib import Path\nPath({:?}).write_text(\"payload\")\n",
        file.to_str().expect("utf-8 path")
    );
    let ran = run_governed(READ_ONLY, &source);

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "a write with only fs:read permitted must be refused: {ran:?}"
    );
    assert!(!file.exists(), "the refused write must not have happened");
}

/// Environment reads are refused, because this schema cannot express one.
///
/// There is no `env:read` action, and mapping the read onto a synthetic path is unsound
/// — a script can spell `/<env>/VAR`, and normalization leaves it unchanged, so one name
/// would cover two different effects. Denying is the fail-closed choice while the
/// vocabulary is missing, and it matters because the box projects credential phantoms
/// into the workload's environment. Update this test when an `env:read` action lands.
#[test]
fn an_environment_read_is_refused_while_the_schema_cannot_name_it() {
    // Permit every filesystem effect there is: the refusal must come from the
    // environment having no expressible action, not from a missing filesystem permit.
    let ran = run_governed(PERMIT_ALL, "import os\nos.getenv(\"PATH\")\n");

    // `RuntimeError`, not `PermissionError`: the adapter refuses via upstream's own
    // `on_no_handler`, which reserves `PermissionError` for filesystem paths and reports
    // a non-filesystem call as unsupported. That is the right shape here — the
    // capability genuinely is absent in this environment, and the message discloses
    // nothing about the variable asked for.
    assert_eq!(
        ran.raised(),
        Some(ExcType::RuntimeError),
        "an environment read must be refused, not silently permitted by a filesystem \
         rule: {ran:?}"
    );
    // Assert the exact message rather than that it lacks the variable name: the fixed
    // string structurally cannot contain one, so a `!contains("PATH")` check is vacuous.
    // Pinning the text is what would catch a future refusal that started interpolating.
    assert_eq!(
        ran.message(),
        "'os.getenv' is not supported in this environment",
        "the refusal should name the operation, never the variable asked for"
    );
}

/// An empty policy denies everything: absence of a rule is not permission.
#[test]
fn an_empty_policy_denies_every_effect() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("greeting.txt");
    fs::write(&file, "hello").expect("fixture writes");

    let source = format!(
        "from pathlib import Path\nPath({:?}).read_text()\n",
        file.to_str().expect("utf-8 path")
    );
    // A syntactically valid policy that permits nothing.
    let ran = run_governed(
        "forbid(principal, action, resource) when { false };",
        &source,
    );

    assert_eq!(
        ran.raised(),
        Some(ExcType::PermissionError),
        "no permit means denied: {ran:?}"
    );
}

// ---------------------------------------------------------------------------
// Operation granularity: the distinctions a rule needs in order to be useful.
// ---------------------------------------------------------------------------

/// Metadata probing can be permitted without granting content.
///
/// `exists()` is `read_metadata` and `read_text()` is `read_content`, so a rule can
/// allow a script to discover layout while refusing the bytes. Upstream's glue maps
/// `Path.stat()` alongside content reads, which collapses exactly this.
#[test]
fn metadata_reads_are_distinguishable_from_content_reads() {
    const METADATA_ONLY: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when { context.input.operation == Box::FsReadOperation::"read_metadata" };
"#;

    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("secret.txt");
    fs::write(&file, "classified").expect("fixture writes");
    let quoted = file.to_str().expect("utf-8 path");

    // The probe is permitted...
    let probe = run_governed(
        METADATA_ONLY,
        &format!("from pathlib import Path\nPath({quoted:?}).exists()\n"),
    );
    assert!(
        matches!(probe, Ran::Completed(MontyNode::Bool(true))),
        "exists() should be permitted as a metadata read, got {probe:?}"
    );

    // ...while the content read under the same rule is not.
    let read = run_governed(
        METADATA_ONLY,
        &format!("from pathlib import Path\nPath({quoted:?}).read_text()\n"),
    );
    assert_eq!(
        read.raised(),
        Some(ExcType::PermissionError),
        "read_text() must not inherit a metadata-only permit: {read:?}"
    );
}

// ---------------------------------------------------------------------------
// History: a completed effect is submitted, and a refused one is not.
// ---------------------------------------------------------------------------

/// A permitted effect is recorded, so a later rule can read what happened.
#[test]
fn a_completed_effect_is_submitted_as_history() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("greeting.txt");
    fs::write(&file, "hello").expect("fixture writes");

    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("script-history.cedar"),
        text: PERMIT_ALL.to_string(),
    }])
    .expect("policy opens");
    let interceptor =
        ScriptPolicyInterceptor::new(&policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));

    let call = OsFunctionCall::ReadText(MontyPath::new(
        file.to_str().expect("utf-8 path").to_string(),
    ));
    let permit = interceptor.admit(&call).expect("permitted");
    assert_eq!(
        permit.path().expect("a filesystem permit carries its path"),
        file.as_path(),
        "the permit must carry the resolved identity the effect will act on"
    );
    permit
        .record(FsResult::Completed)
        .expect("history accepts the outcome");
}

/// A permit dropped without reporting still records the effect, as indeterminate.
///
/// An early return or a panic must not remove an admitted effect from history: a rule
/// counting attempts would then undercount precisely on the error paths an attacker
/// would aim for. Mirrors the Shell's `KernelPermit`, whose `Drop` marks the same state.
/// The count walks `fs:read::response` events, which exist **only** because a permit
/// submitted an outcome — so this fails if `Drop` records nothing. Asserting the policy
/// merely "still works" after a drop would pass either way and prove nothing.
#[test]
fn a_dropped_permit_still_records_the_effect() {
    // Permit a read only while fewer than two reads have resolved. Dropping one permit
    // must consume budget exactly as reporting one does.
    let budget = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when temporal {
    exists (total: Long). (
        (count for (t: Timepoint). where (
            formerly within 60s (
                Box::Action::"fs:read"::response{ input.path: _ } && tp(t)
            )
        )) == total
        && total < 2
    )
};
"#;

    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("greeting.txt");
    fs::write(&file, "hello").expect("fixture writes");

    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("script-drop.cedar"),
        text: budget.to_string(),
    }])
    .expect("policy opens");
    let interceptor =
        ScriptPolicyInterceptor::new(&policy, Principal::agent(), GovernedBox::assigned(BOX_NAME));

    let call = OsFunctionCall::ReadText(MontyPath::new(
        file.to_str().expect("utf-8 path").to_string(),
    ));

    // Two admissions, each **dropped** without `record` — the shape of an early return
    // or a panic unwinding past the permit.
    for _ in 0..2 {
        drop(interceptor.admit(&call).expect("within budget"));
    }

    // If the dropped permits recorded nothing, the count is still 0 and this is
    // permitted. It must be refused, which is only possible if `Drop` submitted.
    assert!(
        interceptor.admit(&call).is_err(),
        "two dropped permits must consume the budget — a silently dropped effect lets a \
         rate limit undercount on exactly the error paths an attacker would aim for"
    );
}
