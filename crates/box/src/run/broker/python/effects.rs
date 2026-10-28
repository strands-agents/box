//! Filesystem effects of a Monty script: admission through policy, the reach floor, and the effect.

use std::io::{self, Read as _, Write as _};
use std::path::Path;
use std::sync::Arc;

use monty_types::{
    ExcType, ExtFunctionResult, MontyException, MontyFileHandle, MontyObject, MontyPath,
    OsFunctionCall, stat_result,
};
use policy::{FsResult, RenameDestination, ScriptPermit, ScriptPolicyInterceptor, ScriptRefusal};

use super::clock::{date_today, datetime_now, unix_seconds_now, urandom};
use crate::run::broker::held::HeldPath;
use crate::run::broker::reach::Reach;
use crate::run::telemetry::{DecisionRecorder, EffectiveDecision, ObservationCapture};

pub(super) struct MontyPep<'p> {
    pub(super) policy: ScriptPolicyInterceptor<'p>,
    pub(super) recorder: Arc<DecisionRecorder>,
}

impl<'p> MontyPep<'p> {
    fn admit(&self, call: &OsFunctionCall) -> Result<ScriptPermit<'p>, ScriptRefusal> {
        self.policy.admit(call)
    }

    /// Admit a rename; what is bound at the destination is read only after the floor approves it.
    fn admit_rename(
        &self,
        call: &OsFunctionCall,
        reach: &Reach,
        dst_spelled: &str,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf, ScriptPermit<'p>), ScriptRefusal> {
        self.policy.admit_rename(call, |destination| {
            match reach.approve_mutation(destination, dst_spelled) {
                Ok(approved) => RenameDestination::bound_at(&approved),
                // The floor refuses this destination after admission, so nothing is read there.
                Err(_) => RenameDestination::Unbound,
            }
        })
    }
}

/// Admit one suspension, perform it if permitted, and report the outcome.
pub(super) fn admit_and_perform(
    interceptor: &MontyPep<'_>,
    mut call: OsFunctionCall,
    reach: &Reach,
) -> Result<ExtFunctionResult, MontyException> {
    // The spelling the script used, kept before anything rewrites it. Every refusal below
    // names this rather than the path the box derived from it, because telling a caller about
    let spelled = call
        .fs_primary_path()
        .map(str::to_string)
        .unwrap_or_else(|| call.name().to_string());

    // A rename authorizes two endpoints, so keep both authored spellings before rooting — each
    // refusal must name the endpoint the script actually wrote, not the box's derived path.
    let rename_spellings = if let OsFunctionCall::Rename(args) = &call {
        Some((args.src.as_str().to_string(), args.dst.as_str().to_string()))
    } else {
        None
    };

    // The script's working directory, applied **before** admission so policy judges the path
    // the effect will touch. Monty has no working directory of its own, and the script
    let authored = call.clone();
    root_paths(&mut call, reach);
    let subject = monty_decision_subject(&call, &interceptor.policy);

    // A rename does not classify in `admit` (its two identities are authorized separately). It is
    // admitted through `admit_rename`, then both endpoints are floored before the move runs.
    if let Some((src_spelled, dst_spelled)) = rename_spellings {
        return perform_rename(
            interceptor,
            &call,
            &authored,
            reach,
            &src_spelled,
            &dst_spelled,
        );
    }

    // A denial is re-spelled for the same reason the floor's refusals are: admission
    // judges the rooted path, so the adapter's own message names a path the script never wrote.
    let capture = ObservationCapture::begin();
    let admitted = interceptor.admit(&call);
    let determined = capture.last();
    let permit = match admitted {
        Ok(permit) => permit,
        Err(refusal) => {
            let legs: Vec<(&str, &str)> = call
                .fs_primary_path()
                .map(|rooted| (rooted, spelled.as_str()))
                .into_iter()
                .collect();
            let denial = respell(refusal, &interceptor.policy, &authored, &legs);
            if let Some(subject) = subject {
                interceptor.recorder.record(EffectiveDecision::gate_deny(
                    subject.action,
                    subject.resource,
                    "monty-policy",
                    denial.message().unwrap_or("the policy refused the effect"),
                    determined.as_ref(),
                ));
            }
            return Err(denial);
        }
    };

    let Some(admitted) = permit.path() else {
        // No path, no filesystem effect: `os.urandom` is answered from the host's entropy, and a
        // clock read, which the VM answers itself under the default `OsPolicy`, from the system
        // clock in UTC; any other no-path call fails closed.
        let answer = match &call {
            OsFunctionCall::DateToday => MontyObject::date(date_today()),
            OsFunctionCall::DateTimeNow(zone) => MontyObject::datetime(datetime_now(zone.as_ref())),
            OsFunctionCall::Time(_) => MontyObject::float(unix_seconds_now()),
            OsFunctionCall::Urandom(args) => match urandom(args.size) {
                Ok(bytes) => bytes,
                Err(refused) => {
                    record(permit, FsResult::Failed);
                    return Err(refused);
                }
            },
            _ => {
                record(permit, FsResult::Failed);
                return Err(MontyException::new(
                    ExcType::RuntimeError,
                    Some(format!(
                        "{}: not supported by this box's Python (Monty)",
                        call.name()
                    )),
                ));
            }
        };
        record(permit, FsResult::Completed);
        return Ok(ExtFunctionResult::Return(answer));
    };

    // The path policy judged must be the path the effect uses. `ScriptPolicyInterceptor`
    // resolves **lexically** and never touches the filesystem; its own docs say symlink
    let approved = match if mutates_authority(&call) {
        reach.approve_mutation(admitted, &spelled)
    } else {
        reach.approve(admitted, &spelled)
    } {
        Ok(approved) => approved,
        Err(refused) => {
            if let Some(subject) = subject {
                interceptor
                    .recorder
                    .record(EffectiveDecision::enforcement_deny(
                        subject.action,
                        subject.resource,
                        "reach-floor",
                        refused.to_string(),
                    ));
            }
            // Refused by the floor, *after* policy allowed it — which is the point: policy
            // cannot widen this. Recorded as failed rather than dropped, because the attempt
            record(permit, FsResult::Failed);
            return Err(MontyException::new(
                ExcType::PermissionError,
                Some(refused.to_string()),
            ));
        }
    };

    if let Some(subject) = subject {
        interceptor.recorder.record(EffectiveDecision::gate_permit(
            subject.action,
            subject.resource,
            "monty-policy",
            determined.as_ref(),
        ));
    }
    let (result, resume_with) = perform(&call, &approved);
    record(permit, result);
    Ok(resume_with)
}

fn mutates_authority(call: &OsFunctionCall) -> bool {
    match call {
        OsFunctionCall::ReadText(_)
        | OsFunctionCall::ReadBytes(_)
        | OsFunctionCall::Stat(_)
        | OsFunctionCall::Exists(_)
        | OsFunctionCall::IsFile(_)
        | OsFunctionCall::IsDir(_)
        | OsFunctionCall::IsSymlink(_)
        | OsFunctionCall::Iterdir(_)
        | OsFunctionCall::Resolve(_)
        | OsFunctionCall::Absolute(_) => false,
        OsFunctionCall::Open(args) => !matches!(args.mode, monty_types::FileMode::Read(_)),
        OsFunctionCall::WriteText(_)
        | OsFunctionCall::AppendText(_)
        | OsFunctionCall::WriteBytes(_)
        | OsFunctionCall::AppendBytes(_)
        | OsFunctionCall::Mkdir(_)
        | OsFunctionCall::Unlink(_)
        | OsFunctionCall::Rmdir(_)
        | OsFunctionCall::Rename(_) => true,
        OsFunctionCall::Getenv(_)
        | OsFunctionCall::GetEnviron
        | OsFunctionCall::DateToday
        | OsFunctionCall::DateTimeNow(_)
        | OsFunctionCall::Urandom(_)
        | OsFunctionCall::Time(_)
        | OsFunctionCall::Sleep(_)
        | OsFunctionCall::SystemSleep(_)
        | OsFunctionCall::AsyncSleep(_)
        | OsFunctionCall::AsyncSystemSleep(_) => false,
    }
}

struct MontyDecisionSubject {
    action: &'static str,
    resource: String,
}

fn monty_decision_subject(
    call: &OsFunctionCall,
    interceptor: &ScriptPolicyInterceptor<'_>,
) -> Option<MontyDecisionSubject> {
    let subject = |path: &MontyPath, action| {
        Some(MontyDecisionSubject {
            action,
            resource: interceptor.reported(path.as_str()),
        })
    };
    match call {
        OsFunctionCall::ReadText(path)
        | OsFunctionCall::ReadBytes(path)
        | OsFunctionCall::Stat(path)
        | OsFunctionCall::Exists(path)
        | OsFunctionCall::IsFile(path)
        | OsFunctionCall::IsDir(path)
        | OsFunctionCall::IsSymlink(path)
        | OsFunctionCall::Iterdir(path)
        | OsFunctionCall::Resolve(path)
        | OsFunctionCall::Absolute(path) => subject(path, r#"Box::Action::"fs:read""#),
        OsFunctionCall::WriteText(args) | OsFunctionCall::AppendText(args) => {
            subject(&args.path, r#"Box::Action::"fs:write""#)
        }
        OsFunctionCall::WriteBytes(args) | OsFunctionCall::AppendBytes(args) => {
            subject(&args.path, r#"Box::Action::"fs:write""#)
        }
        OsFunctionCall::Open(args) => subject(
            &args.path,
            match args.mode {
                monty_types::FileMode::Read(_) => r#"Box::Action::"fs:read""#,
                _ => r#"Box::Action::"fs:write""#,
            },
        ),
        OsFunctionCall::Mkdir(args) if !args.parents => {
            subject(&args.path, r#"Box::Action::"fs:write""#)
        }
        OsFunctionCall::Unlink(path) | OsFunctionCall::Rmdir(path) => {
            subject(path, r#"Box::Action::"fs:delete""#)
        }
        OsFunctionCall::Rename(args) => subject(&args.dst, r#"Box::Action::"fs:move""#),
        OsFunctionCall::Mkdir(_)
        | OsFunctionCall::Getenv(_)
        | OsFunctionCall::GetEnviron
        | OsFunctionCall::DateToday
        | OsFunctionCall::DateTimeNow(_)
        | OsFunctionCall::Urandom(_)
        | OsFunctionCall::Time(_)
        | OsFunctionCall::Sleep(_)
        | OsFunctionCall::SystemSleep(_)
        | OsFunctionCall::AsyncSleep(_)
        | OsFunctionCall::AsyncSystemSleep(_) => None,
    }
}

/// Report a refusal in the spelling the caller used, not the path the box derived.
fn respell(
    refusal: ScriptRefusal,
    interceptor: &ScriptPolicyInterceptor<'_>,
    authored: &OsFunctionCall,
    legs: &[(&str, &str)],
) -> MontyException {
    match refusal {
        ScriptRefusal::Denied(decision) => {
            let spelled = legs
                .iter()
                .find(|(rooted, _)| interceptor.reported(rooted) == decision.resource())
                .or(legs.first())
                .map_or_else(
                    || decision.resource().to_string(),
                    |(_, spelled)| (*spelled).to_string(),
                );
            MontyException::new(
                ExcType::PermissionError,
                Some(decision.naming(spelled).to_string()),
            )
        }
        ScriptRefusal::Unsupported(_) => authored.on_no_handler(),
    }
}

/// Rewrite every path this call carries as an absolute name.
fn root_paths(call: &mut OsFunctionCall, reach: &Reach) {
    let rooted = |path: &MontyPath| {
        MontyPath::new(reach.absolute(path.as_str()).to_string_lossy().into_owned())
    };
    match call {
        OsFunctionCall::Exists(path)
        | OsFunctionCall::IsFile(path)
        | OsFunctionCall::IsDir(path)
        | OsFunctionCall::IsSymlink(path)
        | OsFunctionCall::ReadText(path)
        | OsFunctionCall::ReadBytes(path)
        | OsFunctionCall::Stat(path)
        | OsFunctionCall::Iterdir(path)
        | OsFunctionCall::Resolve(path)
        | OsFunctionCall::Absolute(path)
        | OsFunctionCall::Unlink(path)
        | OsFunctionCall::Rmdir(path) => *path = rooted(path),
        OsFunctionCall::WriteText(args) | OsFunctionCall::AppendText(args) => {
            args.path = rooted(&args.path);
        }
        OsFunctionCall::WriteBytes(args) | OsFunctionCall::AppendBytes(args) => {
            args.path = rooted(&args.path);
        }
        OsFunctionCall::Open(args) => args.path = rooted(&args.path),
        OsFunctionCall::Mkdir(args) => args.path = rooted(&args.path),
        // Both endpoints, because both are judged and both are acted on.
        OsFunctionCall::Rename(args) => {
            args.src = rooted(&args.src);
            args.dst = rooted(&args.dst);
        }
        // No path to root. An environment read is refused at admission, and a clock read, entropy,
        // and a sleep touch no file.
        OsFunctionCall::Getenv(_)
        | OsFunctionCall::GetEnviron
        | OsFunctionCall::DateToday
        | OsFunctionCall::DateTimeNow(_)
        | OsFunctionCall::Urandom(_)
        | OsFunctionCall::Time(_)
        | OsFunctionCall::Sleep(_)
        | OsFunctionCall::SystemSleep(_)
        | OsFunctionCall::AsyncSleep(_)
        | OsFunctionCall::AsyncSystemSleep(_) => {}
    }
}

/// Perform one admitted effect against the resolved path, following no symbolic link in it.
fn perform(call: &OsFunctionCall, path: &Path) -> (FsResult, ExtFunctionResult) {
    let held = match HeldPath::of(path) {
        Ok(held) => held,
        // A predicate answers false for a path it cannot reach, as `os.path.exists` does.
        Err(_) if is_predicate(call) => {
            return (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::bool(false)),
            );
        }
        Err(error) => return (FsResult::Failed, io_exception(&error).into()),
    };
    let is_kind = |kind: libc::mode_t| {
        held.stat()
            .is_ok_and(|metadata| metadata.st_mode & libc::S_IFMT == kind)
    };
    match call {
        OsFunctionCall::ReadText(_) => match read(&held) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => (
                    FsResult::Completed,
                    ExtFunctionResult::Return(MontyObject::string(text)),
                ),
                Err(_) => (
                    FsResult::Failed,
                    io_exception(&io::Error::new(
                        io::ErrorKind::InvalidData,
                        "stream did not contain valid UTF-8",
                    ))
                    .into(),
                ),
            },
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::WriteText(args) => match write(&held, args.data.as_bytes()) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::int(
                    args.data.as_str().len().try_into().unwrap_or(i64::MAX),
                )),
            ),
            Err(error) => (FsResult::Indeterminate, io_exception(&error).into()),
        },
        // `open()` returns a handle, which is a *value*: path, mode, position. The
        // interpreter's file methods suspend again for each read or write, so handing one
        OsFunctionCall::Open(args) => {
            // Existence checked here rather than trusted, so a read of a missing file raises
            // where CPython raises instead of at the first method call.
            if args.mode.create() || held.stat().is_ok() {
                (
                    FsResult::DescriptorIssued,
                    ExtFunctionResult::Return(MontyObject::file_handle(MontyFileHandle {
                        path: args.path.as_str().to_string(),
                        mode: args.mode,
                        position: 0,
                    })),
                )
            } else {
                (
                    FsResult::Failed,
                    io_exception(&io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{}: no such file or directory", args.path.as_str()),
                    ))
                    .into(),
                )
            }
        }
        OsFunctionCall::Exists(_) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::bool(held.stat().is_ok())),
        ),
        OsFunctionCall::IsFile(_) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::bool(is_kind(libc::S_IFREG))),
        ),
        OsFunctionCall::IsDir(_) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::bool(is_kind(libc::S_IFDIR))),
        ),
        // `create_dir`, never `create_dir_all`: the recursive form would create ancestors
        // policy never judged. The adapter refuses `Mkdir { parents: true }` for the same
        OsFunctionCall::Mkdir(_) => match held.create_directory() {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::Unlink(_) => match held.remove_file() {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::Rmdir(_) => match held.remove_directory() {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::none()),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::ReadBytes(_) => match read(&held) {
            Ok(bytes) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::bytes(bytes)),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        OsFunctionCall::WriteBytes(args) => match write(&held, &args.data) {
            Ok(()) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::int(
                    args.data.len().try_into().unwrap_or(i64::MAX),
                )),
            ),
            Err(error) => (FsResult::Indeterminate, io_exception(&error).into()),
        },
        // Append opens with `O_APPEND`, never truncating — `O_CREAT` matches CPython's
        // `"a"`/`"ab"`, which make a missing file.
        OsFunctionCall::AppendText(args) => append(&held, args.data.as_bytes()),
        OsFunctionCall::AppendBytes(args) => append(&held, &args.data),
        // Enumeration returns entry NAMES only — never a resolved host path.
        OsFunctionCall::Iterdir(_) => match held.entry_names() {
            Ok(names) => (
                FsResult::Completed,
                ExtFunctionResult::Return(MontyObject::list(
                    names
                        .into_iter()
                        .map(MontyObject::string)
                        .collect::<Vec<_>>(),
                )),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        // The leaf's own metadata, so this answers the question about the link itself. A missing
        // path is not a symlink, matching `os.path.islink`.
        OsFunctionCall::IsSymlink(_) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::bool(is_kind(libc::S_IFLNK))),
        ),
        // `Stat` returns the fields the Shell's `FileStat` carries, and **normalizes**
        // `uid`/`gid`/`nlink` to a fixed value so no host identity leaks.
        OsFunctionCall::Stat(_) => match held.stat() {
            Ok(metadata) => (
                FsResult::Completed,
                ExtFunctionResult::Return(normalized_stat(&metadata)),
            ),
            Err(error) => (FsResult::Failed, io_exception(&error).into()),
        },
        _ => (
            FsResult::Failed,
            MontyException::new(
                ExcType::RuntimeError,
                Some(format!(
                    "{}: not supported by this box's Python (Monty)",
                    call.name()
                )),
            )
            .into(),
        ),
    }
}

fn is_predicate(call: &OsFunctionCall) -> bool {
    matches!(
        call,
        OsFunctionCall::Exists(_)
            | OsFunctionCall::IsFile(_)
            | OsFunctionCall::IsDir(_)
            | OsFunctionCall::IsSymlink(_)
    )
}

/// A `stat_result` from the leaf's metadata, with `uid`/`gid`/`nlink` fixed.
#[allow(clippy::unnecessary_cast)]
fn normalized_stat(metadata: &libc::stat) -> MontyObject {
    const NORMALIZED_UID: i64 = 0;
    const NORMALIZED_GID: i64 = 0;
    const NORMALIZED_NLINK: i64 = 1;
    let seconds = |secs: i64, nanos: i64| secs as f64 + nanos as f64 / 1_000_000_000.0;
    stat_result(
        metadata.st_mode as i64,
        metadata.st_ino as i64,
        metadata.st_dev as i64,
        NORMALIZED_NLINK,
        NORMALIZED_UID,
        NORMALIZED_GID,
        metadata.st_size as i64,
        seconds(metadata.st_atime as i64, metadata.st_atime_nsec as i64),
        seconds(metadata.st_mtime as i64, metadata.st_mtime_nsec as i64),
        seconds(metadata.st_ctime as i64, metadata.st_ctime_nsec as i64),
    )
}

fn read(held: &HeldPath) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    held.open(libc::O_RDONLY)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write(held: &HeldPath, data: &[u8]) -> io::Result<()> {
    held.open(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)?
        .write_all(data)
}

pub(super) fn io_exception(error: &io::Error) -> MontyException {
    MontyException::new(ExcType::OSError, Some(error.to_string()))
}

/// Record a permit's outcome, warning to stderr if the durable write was not confirmed.
fn record(permit: ScriptPermit<'_>, result: FsResult) {
    if permit.record(result).is_err() {
        let _ = writeln!(
            io::stderr().lock(),
            "strands-box: warning: policy outcome recording was not confirmed"
        );
    }
}

/// Append `data` to the leaf, creating it if absent and never truncating (CPython `"a"`/`"ab"`).
fn append(held: &HeldPath, data: &[u8]) -> (FsResult, ExtFunctionResult) {
    let outcome = held
        .open(libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT)
        .and_then(|mut file| file.write_all(data).map(|()| data.len()));
    match outcome {
        Ok(written) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::int(written.try_into().unwrap_or(i64::MAX))),
        ),
        // A partial append leaves the file in an unknown state, so the write is `Indeterminate`.
        Err(error) => (FsResult::Indeterminate, io_exception(&error).into()),
    }
}

/// Admit and perform a rename, whose two endpoints are authorized and floored separately.
///
/// `Rename` does not classify in `admit` (its two identities need separate decisions), so it is
/// admitted through `admit_rename`, which decides both under `fs:move` and a bound destination
/// under `fs:delete`. Both endpoints are then floored on their canonical identity by
/// `Reach::approve` before the move runs, so neither the source nor the destination can resolve
/// outside the box's reachable set.
fn perform_rename(
    interceptor: &MontyPep<'_>,
    call: &OsFunctionCall,
    authored: &OsFunctionCall,
    reach: &Reach,
    src_spelled: &str,
    dst_spelled: &str,
) -> Result<ExtFunctionResult, MontyException> {
    let subject = monty_decision_subject(call, &interceptor.policy);
    let capture = ObservationCapture::begin();
    let admitted = interceptor.admit_rename(call, reach, dst_spelled);
    let determined = capture.last();
    let (source, destination, permit) = match admitted {
        Ok(admitted) => admitted,
        Err(refusal) => {
            let legs = match call {
                OsFunctionCall::Rename(args) => vec![
                    (args.src.as_str(), src_spelled),
                    (args.dst.as_str(), dst_spelled),
                ],
                _ => Vec::new(),
            };
            let denial = respell(refusal, &interceptor.policy, authored, &legs);
            if let Some(subject) = subject {
                interceptor.recorder.record(EffectiveDecision::gate_deny(
                    subject.action,
                    subject.resource,
                    "monty-policy",
                    denial.message().unwrap_or("the policy refused the effect"),
                    determined.as_ref(),
                ));
            }
            return Err(denial);
        }
    };

    let approved_src = match reach.approve_mutation(source.as_path(), src_spelled) {
        Ok(approved) => approved,
        Err(refused) => {
            interceptor
                .recorder
                .record(EffectiveDecision::enforcement_deny(
                    r#"Box::Action::"fs:move""#,
                    interceptor
                        .policy
                        .reported(source.to_string_lossy().as_ref()),
                    "reach-floor",
                    refused.to_string(),
                ));
            record(permit, FsResult::Failed);
            return Err(MontyException::new(
                ExcType::PermissionError,
                Some(refused.to_string()),
            ));
        }
    };
    let approved_dst = match reach.approve_mutation(destination.as_path(), dst_spelled) {
        Ok(approved) => approved,
        Err(refused) => {
            interceptor
                .recorder
                .record(EffectiveDecision::enforcement_deny(
                    r#"Box::Action::"fs:move""#,
                    interceptor
                        .policy
                        .reported(destination.to_string_lossy().as_ref()),
                    "reach-floor",
                    refused.to_string(),
                ));
            record(permit, FsResult::Failed);
            return Err(MontyException::new(
                ExcType::PermissionError,
                Some(refused.to_string()),
            ));
        }
    };

    if let Some(subject) = subject {
        interceptor.recorder.record(EffectiveDecision::gate_permit(
            subject.action,
            subject.resource,
            "monty-policy",
            determined.as_ref(),
        ));
    }
    let (result, resume_with) = match rename_approved(&approved_src, &approved_dst) {
        Ok(()) => (
            FsResult::Completed,
            ExtFunctionResult::Return(MontyObject::none()),
        ),
        Err(error) => (FsResult::Failed, io_exception(&error).into()),
    };
    record(permit, result);
    Ok(resume_with)
}

/// Move one approved path to another, following no symbolic link in either.
fn rename_approved(source: &Path, destination: &Path) -> io::Result<()> {
    HeldPath::of(source)?.rename_to(&HeldPath::of(destination)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use monty_types::unstable::{self, MontyNode};

    /// The node a result returned, or the result itself.
    fn returned(result: ExtFunctionResult) -> Result<MontyNode, ExtFunctionResult> {
        match result {
            ExtFunctionResult::Return(value) => Ok(unstable::root_node(&value).clone()),
            other => Err(other),
        }
    }

    use std::path::PathBuf;

    use monty_types::{
        GetenvArgs, MkdirCallArgs, PathBytesDataArgs, PathStringDataArgs, RenameCallArgs,
    };
    use policy::{GovernedBox, Policy, PolicyEngine, Principal};

    use crate::run::telemetry::{EffectiveRule, EffectiveVerdict, PolicyDecisionObserver};
    use crate::test_support::open_policy;

    use crate::run::broker::python::tests::{fixture, permissive};

    /// The canonical box home of a fixture.
    fn home(root: &tempfile::TempDir) -> PathBuf {
        root.path()
            .canonicalize()
            .expect("the root resolves")
            .join("home")
    }

    /// A relative spelling means the same file it means in the Shell.
    #[test]
    fn every_relative_path_is_rooted_at_the_box_home() {
        let (root, reach) = fixture();
        let home = home(&root);

        let mut read = OsFunctionCall::ReadText(MontyPath::new("notes.txt".to_string()));
        root_paths(&mut read, &reach);
        assert_eq!(
            read.fs_primary_path(),
            Some(home.join("notes.txt").to_str().expect("UTF-8")),
            "a bare name must resolve against the working directory"
        );

        let mut write = OsFunctionCall::WriteText(PathStringDataArgs {
            path: MontyPath::new("out.txt".to_string()),
            data: "x".to_string(),
        });
        root_paths(&mut write, &reach);
        assert_eq!(
            write.fs_primary_path(),
            Some(home.join("out.txt").to_str().expect("UTF-8"))
        );

        // Both endpoints, because both are judged and both are acted on.
        let mut rename = OsFunctionCall::Rename(RenameCallArgs {
            src: MontyPath::new("before".to_string()),
            dst: MontyPath::new("after".to_string()),
        });
        root_paths(&mut rename, &reach);
        let OsFunctionCall::Rename(args) = &rename else {
            unreachable!("the variant is unchanged");
        };
        assert_eq!(args.src.as_str(), home.join("before").to_str().unwrap());
        assert_eq!(args.dst.as_str(), home.join("after").to_str().unwrap());

        // An absolute spelling already names what it means, mount point included.
        let mut mounted =
            OsFunctionCall::ReadText(MontyPath::new("/workspace/main.rs".to_string()));
        root_paths(&mut mounted, &reach);
        assert_eq!(mounted.fs_primary_path(), Some("/workspace/main.rs"));

        // No path to root, and nothing to rewrite.
        let mut env = OsFunctionCall::Getenv(GetenvArgs {
            key: "HOME".to_string(),
            default: MontyObject::none(),
        });
        root_paths(&mut env, &reach);
        assert!(matches!(env, OsFunctionCall::Getenv(_)));
    }

    /// End to end, the rooted relative path is what the effect reads.
    #[test]
    fn a_relative_read_inside_the_home_is_performed() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("notes.txt"), "hello").expect("a file in the home");
        let policy = permissive();
        let interceptor = interceptor(&policy);

        let result = admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("notes.txt".to_string())),
            &reach,
        )
        .expect("a permitted read inside the home is performed");

        match returned(result) {
            Ok(MontyNode::String(text)) => assert_eq!(text, "hello"),
            other => panic!("a permitted read must return the file's text: {other:?}"),
        }
    }

    /// The floor refuses a non-canonical spelling **after** policy allowed it.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_home_is_refused_in_the_callers_spelling() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("outside.pem"), "s").expect("a file outside the set");
        std::os::unix::fs::symlink(resolved.join("outside.pem"), home(&root).join("link"))
            .expect("a link out of the home");
        let policy = permissive();
        let recorder = DecisionRecorder::discarding();
        let interceptor = MontyPep {
            policy: ScriptPolicyInterceptor::new(
                &policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
            ),
            recorder: Arc::clone(&recorder),
        };

        let refusal = admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("link".to_string())),
            &reach,
        )
        .expect_err("a link out of the reachable set is not the identity policy judged");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        let message = refusal.message().unwrap_or_default().to_string();
        assert!(
            message.starts_with("link: "),
            "the refusal must name the spelling the script used: {message}"
        );
        assert!(
            message.contains("not the identity policy judged"),
            "the refusal must come from canonicity, or a missing rooting step would read the \
             same: {message}"
        );
        assert!(
            !message.contains("outside.pem"),
            "the path behind the link must not leak into the refusal: {message}"
        );
        let recorded = recorder.recorded();
        let [decision] = recorded.as_slice() else {
            panic!("the Monty PEP must submit exactly one effective decision");
        };
        let (action, resource, rule, verdict, reason) = decision.parts();
        assert_eq!(action, r#"Box::Action::"fs:read""#);
        assert!(resource.ends_with("/home/link"), "{resource}");
        assert_eq!(
            rule,
            &crate::run::telemetry::EffectiveRule::Enforcement("reach-floor")
        );
        assert_eq!(verdict, crate::run::telemetry::EffectiveVerdict::Deny);
        assert!(reason.is_some_and(|reason| reason.contains("not the identity policy judged")));
    }

    /// A link between two paths *inside* the home cannot launder a path-scoped rule.
    #[cfg(unix)]
    #[test]
    fn an_intra_home_symlink_cannot_launder_a_scoped_read() {
        let (root, reach) = fixture();
        let home = home(&root);
        std::fs::create_dir(home.join("public")).expect("the public directory");
        std::fs::create_dir(home.join("private")).expect("the private directory");
        std::fs::write(home.join("private/secret"), "s").expect("the secret");
        std::os::unix::fs::symlink(home.join("private/secret"), home.join("public/alias"))
            .expect("a link from public to private");
        let policy = permissive();
        let interceptor = interceptor(&policy);

        let spelled = home.join("public/alias").display().to_string();
        let refusal = admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new(spelled.clone())),
            &reach,
        )
        .expect_err("a public spelling of a private file is not the identity policy judged");

        let message = refusal.message().unwrap_or_default().to_string();
        assert!(
            message.starts_with(&format!("{spelled}: ")),
            "the refusal names the spelling the script used: {message}"
        );
        assert!(
            message.contains("not the identity policy judged"),
            "the refusal must come from canonicity: nothing else sees this link, because both \
             ends are inside the reachable set: {message}"
        );
        assert!(
            !message.contains("secret"),
            "the private path must not leak into the refusal: {message}"
        );
    }

    /// **A dangling symlink inside the home cannot be written through.**
    ///
    /// `box/AGENTS.md` names this one of two escapes pinned by a test that must not be deleted.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_cannot_be_written_through() {
        let (root, reach) = fixture();
        let home = home(&root);
        let resolved = root.path().canonicalize().expect("the root resolves");

        // Outside every reachable root, and absent — so the link dangles.
        let target = resolved.join("OPERATOR_OWNED.txt");
        assert!(!target.exists(), "the fixture target must start absent");
        std::os::unix::fs::symlink(&target, home.join("escape.txt"))
            .expect("plant the dangling link inside the home");

        let policy = permissive();
        let interceptor = interceptor(&policy);

        let spelled = home.join("escape.txt").display().to_string();
        let refusal = admit_and_perform(
            &interceptor,
            OsFunctionCall::WriteText(PathStringDataArgs {
                path: MontyPath::new(spelled.clone()),
                data: "PWNED".to_string(),
            }),
            &reach,
        )
        .expect_err("a write through a dangling link must not be performed");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        let message = refusal.message().unwrap_or_default().to_string();
        assert!(
            message.starts_with(&format!("{spelled}: ")),
            "the refusal names the spelling the script used: {message}"
        );
        assert!(
            !target.exists(),
            "SANDBOX ESCAPE: the box wrote outside every reachable root through a dangling \
             link — {} now exists",
            target.display()
        );
    }

    /// The floor is beneath policy, and a path outside every root is refused whatever policy says.
    #[test]
    fn a_path_outside_every_reachable_root_is_refused() {
        let (_root, reach) = fixture();
        let policy = permissive();
        let interceptor = interceptor(&policy);

        let refusal = admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("/etc/passwd".to_string())),
            &reach,
        )
        .expect_err("no permit may open a path outside the box home and every declared bind");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert!(
            refusal
                .message()
                .unwrap_or_default()
                .starts_with("/etc/passwd: "),
            "the refusal names the caller's spelling: {refusal:?}"
        );
    }

    /// PolicyEngine decides first, and its refusal names the caller's spelling too.
    #[test]
    fn a_denied_effect_is_refused_by_policy_in_the_callers_spelling() {
        let (root, reach) = fixture();
        let home = home(&root);
        std::fs::write(home.join("notes.txt"), "hello").expect("a file in the home");
        let policy = open_policy(Vec::<Policy>::new());
        let interceptor = interceptor(&policy);

        for spelling in ["notes.txt", "./notes.txt", "sub/../notes.txt"] {
            let refusal = admit_and_perform(
                &interceptor,
                OsFunctionCall::ReadText(MontyPath::new(spelling.to_string())),
                &reach,
            )
            .expect_err("absent policy is default-deny, and a reachable path does not change that");

            let message = refusal.message().unwrap_or_default().to_string();
            assert!(
                message.starts_with(&format!(
                    "policy denied this operation on '{spelling}' [default-deny]"
                )),
                "the refusal must name what the script wrote: {message}"
            );
            assert!(
                !message.contains(home.to_str().expect("UTF-8")),
                "the box home must not reach a script through a refusal: {message}"
            );
            assert!(
                !message.contains("not the identity policy judged"),
                "a policy denial must not be reported as the floor's refusal: {message}"
            );
        }
    }

    /// **A rename refusal names the endpoint policy refused**, in the caller's spelling.
    #[test]
    fn a_rename_refusal_names_the_refused_endpoint() {
        for (forbidden, spelled) in [("b.txt", "sub/../b.txt"), ("a.txt", "./a.txt")] {
            let (root, reach) = fixture();
            let home = home(&root);
            std::fs::write(home.join("a.txt"), "hello").expect("a file in the home");
            let policy = open_policy(vec![Policy {
                origin: PathBuf::from("<test>"),
                text: format!(
                    r#"permit(principal, action, resource);
                       @id("no-{forbidden}")
                       forbid(principal, action == Box::Action::"fs:move", resource)
                       when {{ context.input.path like "*/{forbidden}" }};"#
                ),
            }]);
            let refusal = admit_and_perform(
                &interceptor(&policy),
                OsFunctionCall::Rename(RenameCallArgs {
                    src: MontyPath::new("./a.txt".to_string()),
                    dst: MontyPath::new("sub/../b.txt".to_string()),
                }),
                &reach,
            )
            .expect_err("one endpoint is forbidden");
            assert_eq!(
                refusal.message(),
                Some(
                    format!(
                        "policy denied this operation on '{spelled}' [policy: no-{forbidden}]."
                    )
                    .as_str()
                ),
            );
            assert!(home.join("a.txt").exists() && !home.join("b.txt").exists());
        }
    }

    /// **An unsupported call is refused in the caller's spelling**, whatever bytes the path holds.
    #[test]
    fn an_unsupported_call_is_refused_in_the_callers_spelling() {
        let (root, reach) = fixture();
        let home = home(&root);
        let policy = permissive();
        for spelling in ["no\u{a0}te/deep", "back\\slash/deep", "quo'te/deep"] {
            let refusal = admit_and_perform(
                &interceptor(&policy),
                OsFunctionCall::Mkdir(MkdirCallArgs {
                    path: MontyPath::new(spelling.to_string()),
                    parents: true,
                    exist_ok: false,
                }),
                &reach,
            )
            .expect_err("a recursive mkdir is not admitted");
            let message = refusal.message().unwrap_or_default().to_string();
            assert!(
                !message.contains(home.to_str().expect("UTF-8")),
                "the box home must not reach a script through a refusal: {message}"
            );
            assert!(message.contains("deep"), "{message}");
        }
    }

    #[test]
    fn a_read_denial_preserves_paths_in_policy_annotations() {
        assert_annotation_paths_preserved(OsFunctionCall::ReadText(MontyPath::new(
            "notes.txt".to_string(),
        )));
    }

    #[test]
    fn a_rename_denial_preserves_paths_in_policy_annotations() {
        assert_annotation_paths_preserved(OsFunctionCall::Rename(RenameCallArgs {
            src: MontyPath::new("notes.txt".to_string()),
            dst: MontyPath::new("moved.txt".to_string()),
        }));
    }

    fn assert_annotation_paths_preserved(call: OsFunctionCall) {
        let (root, reach) = fixture();
        let home = home(&root);
        let path = home.join("notes.txt");
        std::fs::write(&path, "hello").expect("a file in the home");
        let path = path.display().to_string();
        let id = format!("path:{path}");
        let description = format!("Protect {path}. Reference (Permission denied: '{path}').");
        let policy = open_policy(vec![Policy {
            origin: PathBuf::from("<test>"),
            text: format!(
                "@id({}) @description({}) forbid(principal, action, resource);",
                serde_json::to_string(&id).expect("a quoted ID"),
                serde_json::to_string(&description).expect("a quoted description"),
            ),
        }]);

        let refusal = admit_and_perform(&interceptor(&policy), call, &reach)
            .expect_err("the policy denies the operation");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert_eq!(
            refusal.message(),
            Some(
                format!(
                    "policy denied this operation on 'notes.txt' [policy: {id}]: {description}"
                )
                .as_str()
            )
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the source remains"),
            "hello"
        );
        assert!(!home.join("moved.txt").exists());
    }

    /// A Monty policy enforcement point that discards telemetry.
    fn interceptor(policy: &PolicyEngine) -> MontyPep<'_> {
        MontyPep {
            policy: ScriptPolicyInterceptor::new(
                policy,
                Principal::agent(),
                GovernedBox::assigned("codex"),
            ),
            recorder: DecisionRecorder::discarding(),
        }
    }

    /// The same enforcement point, with the recorder it submits to.
    fn recording_interceptor(policy: &PolicyEngine) -> (MontyPep<'_>, Arc<DecisionRecorder>) {
        let recorder = DecisionRecorder::discarding();
        (
            MontyPep {
                policy: ScriptPolicyInterceptor::new(
                    policy,
                    Principal::agent(),
                    GovernedBox::assigned("codex"),
                ),
                recorder: Arc::clone(&recorder),
            },
            recorder,
        )
    }

    /// **A Monty record names the authored policy that decided the effect.** The gate's own label
    /// said only that the interpreter asked; an audit reader needs the rule that answered.
    #[test]
    fn a_monty_record_names_the_policy_that_decided_the_effect() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("ok.txt"), "kept").expect("a fixture file");
        let policy = open_policy(vec![Policy {
            origin: PathBuf::from("<test>"),
            text: r#"
                @id("read-the-fixture") @description("one file")
                permit(principal, action == Box::Action::"fs:read", resource)
                when { context.input.path like "*/ok.txt" };
            "#
            .to_string(),
        }])
        .observed_by(Arc::new(PolicyDecisionObserver));
        let (interceptor, recorder) = recording_interceptor(&policy);

        admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("ok.txt".to_string())),
            &reach,
        )
        .expect("the authored permit admits the read");
        admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("elsewhere.txt".to_string())),
            &reach,
        )
        .expect_err("no permit names elsewhere.txt");

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 2);

        let (action, _, rule, verdict, _) = recorded[0].parts();
        assert_eq!(action, r#"Box::Action::"fs:read""#);
        assert!(
            matches!(rule, EffectiveRule::Policy(_)),
            "the permit names the authored rule rather than the gate: {rule:?}"
        );
        assert_eq!(verdict, EffectiveVerdict::Permit);
        assert_eq!(recorded[0].cause().as_str(), "permitted");
        let [attribution] = recorded[0].attribution() else {
            panic!("one determining policy");
        };
        assert_eq!(
            attribution.annotation_id.as_deref(),
            Some("read-the-fixture")
        );
        assert!(!attribution.token.is_empty());

        // A refusal no rule named still reports its class, and names no policy.
        let (_, _, _, verdict, _) = recorded[1].parts();
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(recorded[1].cause().as_str(), "no_match");
        assert!(recorded[1].attribution().is_empty());
    }

    /// The floor's own refusal keeps the floor's label, because the policy permit it overrode is not
    /// what decided. A deny-only floor sits beneath policy and never beside it.
    #[test]
    fn a_floor_refusal_over_a_policy_permit_keeps_the_floor_label() {
        let (root, reach) = fixture();
        let outside = root
            .path()
            .canonicalize()
            .expect("the root resolves")
            .join("outside.pem");
        std::fs::write(&outside, "s").expect("a file outside the set");
        std::os::unix::fs::symlink(&outside, home(&root).join("link")).expect("a symlink out");
        let policy = permissive().observed_by(Arc::new(PolicyDecisionObserver));
        let (interceptor, recorder) = recording_interceptor(&policy);

        admit_and_perform(
            &interceptor,
            OsFunctionCall::ReadText(MontyPath::new("link".to_string())),
            &reach,
        )
        .expect_err("the floor refuses a link out of the reachable set");

        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 1);
        let (_, _, rule, verdict, _) = recorded[0].parts();
        assert_eq!(*rule, EffectiveRule::Enforcement("reach-floor"));
        assert_eq!(verdict, EffectiveVerdict::Deny);
        assert_eq!(recorded[0].cause().as_str(), "enforcement");
        assert!(
            recorded[0].attribution().is_empty(),
            "the permit the floor overrode is not what decided"
        );
    }

    /// `os.listdir` returns entry names for a permitted directory.
    #[test]
    fn iterdir_lists_entry_names() {
        let (root, reach) = fixture();
        std::fs::create_dir(home(&root).join("sub")).expect("a subdir");
        std::fs::write(home(&root).join("sub/a.txt"), "a").expect("a file");
        std::fs::write(home(&root).join("sub/b.txt"), "b").expect("a file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Iterdir(MontyPath::new("sub".to_string())),
            &reach,
        )
        .expect("a permitted listdir is performed");

        let ExtFunctionResult::Return(value) = result else {
            panic!("iterdir must return a list: {result:?}");
        };
        let entries = value
            .as_ref()
            .items()
            .unwrap_or_else(|| panic!("iterdir must return a list: {value:?}"));
        let mut names: Vec<String> = entries
            .iter()
            .map(|entry| match entry.as_str() {
                Some(name) => name.to_string(),
                None => panic!("each entry must be a name string: {entry:?}"),
            })
            .collect();
        names.sort();
        assert_eq!(names, ["a.txt", "b.txt"]);
    }

    /// `open(p, "rb").read()` returns the file's bytes.
    #[test]
    fn read_bytes_returns_file_contents() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("b.bin"), [1u8, 2, 3]).expect("a file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::ReadBytes(MontyPath::new("b.bin".to_string())),
            &reach,
        )
        .expect("a permitted binary read is performed");

        assert!(matches!(
            returned(result),
            Ok(MontyNode::Bytes(ref bytes)) if bytes == &[1, 2, 3]));
    }

    /// `open(p, "wb").write(...)` writes the bytes and reports the count.
    #[test]
    fn write_bytes_writes_and_reports_the_count() {
        let (root, reach) = fixture();
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::WriteBytes(PathBytesDataArgs {
                path: MontyPath::new("out.bin".to_string()),
                data: vec![9, 9, 9, 9],
            }),
            &reach,
        )
        .expect("a permitted binary write is performed");

        assert!(matches!(returned(result), Ok(MontyNode::Int(4))));
        assert_eq!(
            std::fs::read(home(&root).join("out.bin")).expect("the file was written"),
            vec![9, 9, 9, 9]
        );
    }

    /// `open(p, "a")` appends and does not truncate.
    #[test]
    fn append_text_does_not_truncate() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("log.txt"), "one\n").expect("seed the file");
        let policy = permissive();

        admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::AppendText(PathStringDataArgs {
                path: MontyPath::new("log.txt".to_string()),
                data: "two\n".to_string(),
            }),
            &reach,
        )
        .expect("a permitted append is performed");

        assert_eq!(
            std::fs::read_to_string(home(&root).join("log.txt")).expect("read back"),
            "one\ntwo\n"
        );
    }

    /// `os.path.islink` is false for a regular file.
    #[test]
    fn is_symlink_is_false_for_a_regular_file() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("plain.txt"), "x").expect("a file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::IsSymlink(MontyPath::new("plain.txt".to_string())),
            &reach,
        )
        .expect("a permitted islink is performed");

        assert!(matches!(returned(result), Ok(MontyNode::Bool(false))));
    }

    /// `os.stat` normalizes `uid`/`gid`/`nlink` and keeps the real size.
    #[test]
    fn stat_normalizes_identity_and_keeps_size() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("f.txt"), "hello").expect("a file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Stat(MontyPath::new("f.txt".to_string())),
            &reach,
        )
        .expect("a permitted stat is performed");

        let ExtFunctionResult::Return(value) = result else {
            panic!("stat must return a StatResult: {result:?}");
        };
        let MontyNode::NamedTuple {
            field_names,
            values,
            ..
        } = unstable::node(value.as_ref())
        else {
            panic!("stat must return a StatResult: {value:?}");
        };
        let field = |name: &str| {
            let index = field_names
                .iter()
                .position(|candidate| candidate == name)
                .unwrap_or_else(|| panic!("StatResult has field {name}"));
            unstable::child(value.as_ref(), values[index]).as_int()
        };
        assert!(field("st_nlink") == Some(1), "nlink is normalized");
        assert!(field("st_uid") == Some(0), "uid is normalized");
        assert!(field("st_gid") == Some(0), "gid is normalized");
        assert!(field("st_size") == Some(5), "size is the real size");
    }

    /// `os.rename` moves a file between two permitted names inside the home.
    #[test]
    fn rename_moves_a_file_within_the_home() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("before.txt"), "data").expect("a file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rename(RenameCallArgs {
                src: MontyPath::new("before.txt".to_string()),
                dst: MontyPath::new("after.txt".to_string()),
            }),
            &reach,
        )
        .expect("a permitted rename is performed");

        assert!(matches!(returned(result), Ok(MontyNode::None)));
        assert!(
            !home(&root).join("before.txt").exists(),
            "the source name is gone"
        );
        assert_eq!(
            std::fs::read_to_string(home(&root).join("after.txt")).expect("read back"),
            "data"
        );
    }

    /// A rename whose **destination** resolves out of the home is refused, and no move runs.
    #[cfg(unix)]
    #[test]
    fn rename_refuses_a_destination_out_of_the_home() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(home(&root).join("secret.txt"), "s").expect("a file inside");
        std::fs::write(resolved.join("outside.txt"), "o").expect("a file outside");
        std::os::unix::fs::symlink(resolved.join("outside.txt"), home(&root).join("escape"))
            .expect("a link out of the home");
        let policy = permissive();

        let refusal = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rename(RenameCallArgs {
                src: MontyPath::new("secret.txt".to_string()),
                dst: MontyPath::new("escape".to_string()),
            }),
            &reach,
        )
        .expect_err("a rename onto a link out of the home is refused");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert!(
            refusal.message().unwrap_or_default().starts_with("escape"),
            "the refusal names the caller's destination spelling: {refusal:?}"
        );
        assert!(
            home(&root).join("secret.txt").exists(),
            "the source did not move"
        );
        assert_eq!(
            std::fs::read_to_string(resolved.join("outside.txt")).expect("read back"),
            "o",
            "the target outside the home is untouched"
        );
    }

    /// A rename whose **source** resolves out of the home is refused, and no destination is made.
    #[cfg(unix)]
    #[test]
    fn rename_refuses_a_source_out_of_the_home() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("outside.txt"), "o").expect("a file outside");
        std::os::unix::fs::symlink(resolved.join("outside.txt"), home(&root).join("pull"))
            .expect("a link out of the home");
        let policy = permissive();

        let refusal = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rename(RenameCallArgs {
                src: MontyPath::new("pull".to_string()),
                dst: MontyPath::new("here.txt".to_string()),
            }),
            &reach,
        )
        .expect_err("a rename from a link out of the home is refused");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert!(
            refusal.message().unwrap_or_default().starts_with("pull"),
            "the refusal names the caller's source spelling: {refusal:?}"
        );
        assert!(
            !home(&root).join("here.txt").exists(),
            "no destination was created"
        );
    }

    /// A rename cannot launder a denied read into a permitted new name.
    #[test]
    fn rename_refuses_when_the_source_read_is_denied() {
        let (root, reach) = fixture();
        let home = home(&root);
        std::fs::write(home.join("secret.txt"), "classified").expect("a file");
        let policy = open_policy(vec![Policy {
            origin: PathBuf::from("<test>"),
            text: format!(
                r#"
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource)
when {{ context.input.path like "{}/*shared-*" }};
permit(principal == Box::Agent::"self", action == Box::Action::"fs:move", resource);
"#,
                home.display()
            ),
        }]);

        let refusal = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rename(RenameCallArgs {
                src: MontyPath::new("secret.txt".to_string()),
                dst: MontyPath::new("shared-secret.txt".to_string()),
            }),
            &reach,
        )
        .expect_err("a source read denial must refuse the rename");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert!(
            home.join("secret.txt").exists(),
            "the source must remain when its read denial blocks the rename"
        );
        assert!(
            !home.join("shared-secret.txt").exists(),
            "the destination must not be created when the rename is refused"
        );
    }

    /// Absent policy is default-deny for a newly-performed effect (enumerate here).
    #[test]
    fn a_new_effect_denied_by_policy_is_refused() {
        let (root, reach) = fixture();
        std::fs::create_dir(home(&root).join("d")).expect("a dir");
        let policy = open_policy(Vec::<Policy>::new());

        let refusal = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Iterdir(MontyPath::new("d".to_string())),
            &reach,
        )
        .expect_err("absent policy denies enumerate");

        assert!(
            !refusal
                .message()
                .unwrap_or_default()
                .contains("not the identity policy judged"),
            "a policy denial must not be reported as the floor's refusal: {refusal:?}"
        );
    }

    /// Absent policy denies a rename, and neither endpoint changes.
    #[test]
    fn a_rename_denied_by_policy_moves_nothing() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("a.txt"), "a").expect("a file");
        let policy = open_policy(Vec::<Policy>::new());

        admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rename(RenameCallArgs {
                src: MontyPath::new("a.txt".to_string()),
                dst: MontyPath::new("b.txt".to_string()),
            }),
            &reach,
        )
        .expect_err("absent policy denies the move");

        assert!(
            home(&root).join("a.txt").exists(),
            "the source is unchanged"
        );
        assert!(
            !home(&root).join("b.txt").exists(),
            "no destination was created"
        );
    }

    /// `Resolve`/`Absolute` stay refused — they would return a host path.
    #[test]
    fn resolve_and_absolute_stay_refused() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("f.txt"), "x").expect("a file");
        let policy = permissive();

        for call in [
            OsFunctionCall::Resolve(MontyPath::new("f.txt".to_string())),
            OsFunctionCall::Absolute(MontyPath::new("f.txt".to_string())),
        ] {
            let name = call.name().to_string();
            let result = admit_and_perform(&interceptor(&policy), call, &reach)
                .expect("admission allows, but perform declines");
            match result {
                ExtFunctionResult::Error(exception) => assert!(
                    exception
                        .message()
                        .unwrap_or_default()
                        .contains("not supported by this box's Python (Monty)"),
                    "{name} must stay refused, not return a path"
                ),
                other => panic!("{name} must not return a value: {other:?}"),
            }
        }
    }

    /// `open(p, "ab")` appends bytes and does not truncate.
    #[test]
    fn append_bytes_does_not_truncate() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("log.bin"), [1u8, 2]).expect("seed the file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::AppendBytes(PathBytesDataArgs {
                path: MontyPath::new("log.bin".to_string()),
                data: vec![3, 4],
            }),
            &reach,
        )
        .expect("a permitted append is performed");

        assert!(matches!(returned(result), Ok(MontyNode::Int(2))));
        assert_eq!(
            std::fs::read(home(&root).join("log.bin")).expect("read back"),
            vec![1, 2, 3, 4]
        );
    }

    /// A performed effect whose I/O fails returns an `OSError`, not a broker failure.
    #[test]
    fn read_bytes_of_a_missing_file_returns_an_os_error() {
        let (_root, reach) = fixture();
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::ReadBytes(MontyPath::new("absent.bin".to_string())),
            &reach,
        )
        .expect("admission allows a reachable path; perform fails on the missing file");

        match result {
            ExtFunctionResult::Error(exception) => {
                assert_eq!(exception.exc_type(), ExcType::OSError);
            }
            other => panic!("a missing file must raise an OSError, not return a value: {other:?}"),
        }
    }

    /// The floor refuses a new single-path effect through a symlink out of the home, in the
    /// caller's spelling — the same deny-only floor the read/write arms share.
    #[cfg(unix)]
    #[test]
    fn read_bytes_through_a_symlink_out_of_the_home_is_refused() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("outside.bin"), [7u8]).expect("a file outside");
        std::os::unix::fs::symlink(resolved.join("outside.bin"), home(&root).join("link.bin"))
            .expect("a link out of the home");
        let policy = permissive();

        let refusal = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::ReadBytes(MontyPath::new("link.bin".to_string())),
            &reach,
        )
        .expect_err("a binary read through a link out of the home is refused");

        assert_eq!(refusal.exc_type(), ExcType::PermissionError);
        assert!(
            refusal
                .message()
                .unwrap_or_default()
                .starts_with("link.bin"),
            "the refusal names the caller's spelling: {refusal:?}"
        );
    }

    /// `Stat` reports the real size and a regular-file mode, not just the normalized identity.
    #[test]
    fn stat_reports_real_size_and_file_type() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("g.txt"), "abcd").expect("a 4-byte file");
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Stat(MontyPath::new("g.txt".to_string())),
            &reach,
        )
        .expect("a permitted stat is performed");

        let ExtFunctionResult::Return(value) = result else {
            panic!("stat must return a StatResult: {result:?}");
        };
        let MontyNode::NamedTuple {
            field_names,
            values,
            ..
        } = unstable::node(value.as_ref())
        else {
            panic!("stat must return a StatResult: {value:?}");
        };
        let field = |name: &str| {
            let index = field_names
                .iter()
                .position(|candidate| candidate == name)
                .unwrap_or_else(|| panic!("StatResult has field {name}"));
            unstable::child(value.as_ref(), values[index]).as_int()
        };
        assert!(field("st_size") == Some(4), "size is the real size");
        // The mode carries the regular-file type bit (S_IFREG, 0o100000), a real value.
        let Some(mode) = field("st_mode") else {
            panic!("st_mode is an int");
        };
        assert_eq!(
            mode & 0o170_000,
            0o100_000,
            "st_mode carries the regular-file type bits"
        );
    }

    /// The approved directory, swapped for a link out of the home after approval and before the
    /// effect, so every effect below runs in the window a racing workload wins.
    fn swap_for_a_link_after_approval(
        root: &tempfile::TempDir,
        reach: &Reach,
    ) -> (PathBuf, PathBuf) {
        let resolved = root.path().canonicalize().expect("the root resolves");
        let inside = home(root).join("dir");
        std::fs::create_dir(&inside).expect("a directory in the home");
        std::fs::write(inside.join("f.txt"), "inside").expect("a file in the home");
        std::fs::create_dir(resolved.join("outside")).expect("a directory outside the set");
        std::fs::write(resolved.join("outside/f.txt"), "secret").expect("a file outside the set");
        std::fs::create_dir(resolved.join("outside/sub")).expect("a directory outside the set");
        let approved = reach
            .approve(&inside.join("f.txt"), "dir/f.txt")
            .expect("the floor approves the path before the swap");
        std::fs::rename(&inside, home(root).join("dir-moved")).expect("move the directory away");
        std::os::unix::fs::symlink(resolved.join("outside"), &inside).expect("a link out");
        (approved, resolved.join("outside"))
    }

    /// No effect follows a directory that a workload swapped for a link after approval.
    #[test]
    fn an_ancestor_swapped_for_a_link_after_approval_is_never_followed() {
        let path = |leaf: &str| MontyPath::new(format!("dir/{leaf}"));
        let calls = [
            OsFunctionCall::ReadText(path("f.txt")),
            OsFunctionCall::ReadBytes(path("f.txt")),
            OsFunctionCall::WriteText(PathStringDataArgs {
                path: path("f.txt"),
                data: "x".to_string(),
            }),
            OsFunctionCall::WriteBytes(PathBytesDataArgs {
                path: path("f.txt"),
                data: vec![1],
            }),
            OsFunctionCall::AppendText(PathStringDataArgs {
                path: path("f.txt"),
                data: "x".to_string(),
            }),
            OsFunctionCall::AppendBytes(PathBytesDataArgs {
                path: path("f.txt"),
                data: vec![1],
            }),
            OsFunctionCall::Stat(path("f.txt")),
            OsFunctionCall::Unlink(path("f.txt")),
            OsFunctionCall::Mkdir(MkdirCallArgs {
                path: path("new"),
                parents: false,
                exist_ok: false,
            }),
            OsFunctionCall::Rmdir(path("sub")),
            OsFunctionCall::Iterdir(path("sub")),
        ];
        for call in calls {
            let (root, reach) = fixture();
            let (approved, outside) = swap_for_a_link_after_approval(&root, &reach);
            let approved = match &call {
                OsFunctionCall::Rmdir(_) | OsFunctionCall::Iterdir(_) => {
                    approved.with_file_name("sub")
                }
                OsFunctionCall::Mkdir(_) => approved.with_file_name("new"),
                _ => approved,
            };

            let (result, resumed) = perform(&call, &approved);

            assert_ne!(
                result,
                FsResult::Completed,
                "{} followed the link",
                call.name()
            );
            assert!(
                matches!(resumed, ExtFunctionResult::Error(_)),
                "{} must raise, not return",
                call.name()
            );
            assert_eq!(
                std::fs::read_to_string(outside.join("f.txt")).expect("the outside file survives"),
                "secret",
                "{} reached the file outside the set",
                call.name()
            );
            assert!(
                outside.join("sub").is_dir(),
                "{} removed a directory outside",
                call.name()
            );
            assert!(
                !outside.join("new").exists(),
                "{} created a directory outside",
                call.name()
            );
        }

        for call in [
            OsFunctionCall::Exists(path("f.txt")),
            OsFunctionCall::IsFile(path("f.txt")),
        ] {
            let (root, reach) = fixture();
            let (approved, _) = swap_for_a_link_after_approval(&root, &reach);
            assert!(
                matches!(
                    returned(perform(&call, &approved).1),
                    Ok(MontyNode::Bool(false))
                ),
                "{} answered about the file outside the set",
                call.name()
            );
        }
    }

    /// No effect follows a leaf that a workload swapped for a link after approval.
    #[test]
    fn a_leaf_swapped_for_a_link_after_approval_is_never_followed() {
        let leaf = || MontyPath::new("f.txt".to_string());
        let calls = [
            OsFunctionCall::ReadText(leaf()),
            OsFunctionCall::ReadBytes(leaf()),
            OsFunctionCall::WriteText(PathStringDataArgs {
                path: leaf(),
                data: "x".to_string(),
            }),
            OsFunctionCall::WriteBytes(PathBytesDataArgs {
                path: leaf(),
                data: vec![1],
            }),
            OsFunctionCall::AppendText(PathStringDataArgs {
                path: leaf(),
                data: "x".to_string(),
            }),
            OsFunctionCall::AppendBytes(PathBytesDataArgs {
                path: leaf(),
                data: vec![1],
            }),
        ];
        for call in calls {
            let (root, reach) = fixture();
            let resolved = root.path().canonicalize().expect("the root resolves");
            let inside = home(&root).join("f.txt");
            std::fs::write(&inside, "inside").expect("a file in the home");
            std::fs::write(resolved.join("outside.txt"), "secret").expect("a file outside");
            let approved = reach
                .approve(&inside, "f.txt")
                .expect("the floor approves the path before the swap");
            std::fs::remove_file(&inside).expect("remove the approved file");
            std::os::unix::fs::symlink(resolved.join("outside.txt"), &inside).expect("a link out");

            let (result, resumed) = perform(&call, &approved);

            assert_ne!(
                result,
                FsResult::Completed,
                "{} followed the link",
                call.name()
            );
            assert!(
                matches!(resumed, ExtFunctionResult::Error(_)),
                "{} must raise, not return",
                call.name()
            );
            assert_eq!(
                std::fs::read_to_string(resolved.join("outside.txt"))
                    .expect("the outside file survives"),
                "secret",
                "{} reached the file outside the set",
                call.name()
            );
        }

        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        let inside = home(&root).join("f.txt");
        std::fs::write(&inside, "inside").expect("a file in the home");
        std::fs::write(resolved.join("outside.txt"), "secret").expect("a file outside");
        let approved = reach.approve(&inside, "f.txt").expect("approved");
        std::fs::remove_file(&inside).expect("remove the approved file");
        std::os::unix::fs::symlink(resolved.join("outside.txt"), &inside).expect("a link out");
        let answer = |call| returned(perform(&call, &approved).1);
        assert!(matches!(
            answer(OsFunctionCall::IsSymlink(leaf())),
            Ok(MontyNode::Bool(true))
        ));
        assert!(matches!(
            answer(OsFunctionCall::IsFile(leaf())),
            Ok(MontyNode::Bool(false))
        ));
    }

    /// An ancestor the operator may search but not list is still walked to its leaf.
    #[test]
    fn a_search_only_ancestor_is_still_walked() {
        use std::os::unix::fs::PermissionsExt as _;
        let (root, _) = fixture();
        let locked = home(&root).join("locked");
        std::fs::create_dir(&locked).expect("a directory in the home");
        std::fs::write(locked.join("f.txt"), "inside").expect("a file in it");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o311))
            .expect("make the directory search-only");

        let read = perform(
            &OsFunctionCall::ReadText(MontyPath::new("locked/f.txt".to_string())),
            &locked.join("f.txt"),
        );

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("restore the directory");
        assert!(
            matches!(returned(read.1), Ok(MontyNode::String(ref text)) if text == "inside"),
            "a search-only ancestor must not refuse the walk"
        );
    }

    /// A rename never lands in a directory that a workload swapped for a link after approval.
    #[test]
    fn a_rename_never_lands_in_a_directory_swapped_for_a_link() {
        let (root, reach) = fixture();
        let (approved, outside) = swap_for_a_link_after_approval(&root, &reach);
        let source = home(&root).join("dir-moved/f.txt");

        let renamed = rename_approved(&source, &approved.with_file_name("moved.txt"));

        assert!(renamed.is_err(), "the rename followed the link");
        assert!(
            !outside.join("moved.txt").exists(),
            "the file landed outside the set"
        );
        assert!(source.exists(), "the source did not move");
    }

    /// `os.mkdir('d')` at a single level under an `fs:write` permit creates one directory.
    #[test]
    fn mkdir_creates_a_single_directory() {
        let (root, reach) = fixture();
        let policy = permissive();

        let result = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Mkdir(MkdirCallArgs {
                path: MontyPath::new("d".to_string()),
                parents: false,
                exist_ok: false,
            }),
            &reach,
        )
        .expect("a permitted single-level mkdir is performed");

        assert!(matches!(returned(result), Ok(MontyNode::None)));
        assert!(home(&root).join("d").is_dir(), "one directory was created");
    }

    /// `os.unlink` and `os.rmdir` remove a file and a directory under an `fs:delete` permit.
    #[test]
    fn unlink_and_rmdir_delete_within_the_home() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("gone.txt"), "x").expect("a file to remove");
        std::fs::create_dir(home(&root).join("gone-dir")).expect("a directory to remove");
        let policy = permissive();

        let unlinked = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Unlink(MontyPath::new("gone.txt".to_string())),
            &reach,
        )
        .expect("a permitted unlink is performed");
        assert!(matches!(returned(unlinked), Ok(MontyNode::None)));
        assert!(!home(&root).join("gone.txt").exists(), "the file is gone");

        let removed = admit_and_perform(
            &interceptor(&policy),
            OsFunctionCall::Rmdir(MontyPath::new("gone-dir".to_string())),
            &reach,
        )
        .expect("a permitted rmdir is performed");
        assert!(matches!(returned(removed), Ok(MontyNode::None)));
        assert!(
            !home(&root).join("gone-dir").exists(),
            "the directory is gone"
        );
    }

    /// `os.path.exists`, `Path.is_file`, and `Path.is_dir` each answer from real metadata.
    #[test]
    fn metadata_predicates_answer_from_real_metadata() {
        let (root, reach) = fixture();
        std::fs::write(home(&root).join("f.txt"), "x").expect("a file");
        std::fs::create_dir(home(&root).join("sub")).expect("a directory");
        let policy = permissive();

        let answer = |call| {
            admit_and_perform(&interceptor(&policy), call, &reach)
                .expect("a permitted metadata read is performed")
        };

        // `exists` is true for a present name and false for an absent one.
        assert!(matches!(
            returned(answer(OsFunctionCall::Exists(MontyPath::new(
                "f.txt".to_string()
            )))),
            Ok(MontyNode::Bool(true))
        ));
        assert!(matches!(
            returned(answer(OsFunctionCall::Exists(MontyPath::new(
                "absent".to_string()
            )))),
            Ok(MontyNode::Bool(false))
        ));

        // `is_file` distinguishes the file from the directory.
        assert!(matches!(
            returned(answer(OsFunctionCall::IsFile(MontyPath::new(
                "f.txt".to_string()
            )))),
            Ok(MontyNode::Bool(true))
        ));
        assert!(matches!(
            returned(answer(OsFunctionCall::IsFile(MontyPath::new(
                "sub".to_string()
            )))),
            Ok(MontyNode::Bool(false))
        ));

        // `is_dir` distinguishes the directory from the file.
        assert!(matches!(
            returned(answer(OsFunctionCall::IsDir(MontyPath::new(
                "sub".to_string()
            )))),
            Ok(MontyNode::Bool(true))
        ));
        assert!(matches!(
            returned(answer(OsFunctionCall::IsDir(MontyPath::new(
                "f.txt".to_string()
            )))),
            Ok(MontyNode::Bool(false))
        ));
    }

    /// **An environment read is refused**, because the box projects credential phantoms into the
    /// environment and the schema cannot name that authority.
    #[test]
    fn an_environment_read_is_refused_in_the_callers_spelling() {
        let (root, reach) = fixture();
        let home = home(&root);
        let policy = permissive();

        for call in [
            OsFunctionCall::Getenv(GetenvArgs {
                key: "HOME".to_string(),
                default: MontyObject::none(),
            }),
            OsFunctionCall::GetEnviron,
        ] {
            let name = call.name().to_string();
            let refusal = admit_and_perform(&interceptor(&policy), call, &reach)
                .expect_err("an environment read is not admitted, whatever policy says");
            let message = refusal.message().unwrap_or_default().to_string();
            assert!(
                message.contains(&name),
                "the refusal must name the environment call the script used: {message}"
            );
            assert!(
                !message.contains(home.to_str().expect("UTF-8")),
                "the box home must not reach a script through a refusal: {message}"
            );
        }
    }

    // The recorded `FsResult` is what a temporal rule later reads (`output.result`), so pin the
    // outcome `perform` reports per arm directly — reads and a rename fail as `Failed`, a partial
    // write as `Indeterminate` (matching the `WriteText` arm), and success as `Completed`.

    /// A read that cannot complete records `Failed`.
    #[test]
    fn a_failed_read_records_failed() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let missing = dir
            .path()
            .canonicalize()
            .expect("the scratch dir resolves")
            .join("absent.bin");
        let (result, _) = perform(
            &OsFunctionCall::ReadBytes(MontyPath::new(missing.to_string_lossy().into_owned())),
            &missing,
        );
        assert_eq!(result, FsResult::Failed);
    }

    /// A write whose I/O fails records `Indeterminate` — a partial write leaves an unknown state.
    #[test]
    fn a_failed_write_records_indeterminate() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        // Writing to a directory path fails, deterministically.
        let target = dir
            .path()
            .canonicalize()
            .expect("the scratch dir resolves")
            .join("a_directory");
        std::fs::create_dir(&target).expect("the directory");
        let (result, _) = perform(
            &OsFunctionCall::WriteBytes(PathBytesDataArgs {
                path: MontyPath::new(target.to_string_lossy().into_owned()),
                data: vec![1, 2, 3],
            }),
            &target,
        );
        assert_eq!(result, FsResult::Indeterminate);
    }

    /// A failed append records `Indeterminate` for the same reason a failed write does.
    #[test]
    fn a_failed_append_records_indeterminate() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let target = dir
            .path()
            .canonicalize()
            .expect("the scratch dir resolves")
            .join("a_directory");
        std::fs::create_dir(&target).expect("the directory");
        let (result, _) = perform(
            &OsFunctionCall::AppendBytes(PathBytesDataArgs {
                path: MontyPath::new(target.to_string_lossy().into_owned()),
                data: vec![1],
            }),
            &target,
        );
        assert_eq!(result, FsResult::Indeterminate);
    }

    /// A successful read and a successful write both record `Completed`.
    #[test]
    fn a_successful_effect_records_completed() {
        let dir = tempfile::tempdir().expect("a scratch dir");
        let existing = dir
            .path()
            .canonicalize()
            .expect("the scratch dir resolves")
            .join("f.bin");
        std::fs::write(&existing, [1u8]).expect("seed a file");
        let (read_result, _) = perform(
            &OsFunctionCall::ReadBytes(MontyPath::new(existing.to_string_lossy().into_owned())),
            &existing,
        );
        assert_eq!(read_result, FsResult::Completed);

        let fresh = dir
            .path()
            .canonicalize()
            .expect("the scratch dir resolves")
            .join("out.bin");
        let (write_result, _) = perform(
            &OsFunctionCall::WriteBytes(PathBytesDataArgs {
                path: MontyPath::new(fresh.to_string_lossy().into_owned()),
                data: vec![9],
            }),
            &fresh,
        );
        assert_eq!(write_result, FsResult::Completed);
    }

    #[test]
    fn a_clock_read_returns_a_real_value_not_none() {
        let (_root, reach) = fixture();
        let policy = permissive();
        let ix = interceptor(&policy);

        let today =
            admit_and_perform(&ix, OsFunctionCall::DateToday, &reach).expect("date.today()");
        match returned(today) {
            Ok(MontyNode::Date(date)) => {
                assert!(date.year >= 2024, "a real date, not None: {}", date.year);
            }
            other => panic!("DateToday must return a Date, got {other:?}"),
        }

        let now = admit_and_perform(&ix, OsFunctionCall::DateTimeNow(None), &reach)
            .expect("datetime.now()");
        match returned(now) {
            Ok(MontyNode::DateTime(datetime)) => {
                assert_eq!(datetime.offset_seconds, None, "a naive now() has no offset");
                assert!(datetime.year >= 2024);
            }
            other => panic!("DateTimeNow must return a DateTime, got {other:?}"),
        }
    }
}
