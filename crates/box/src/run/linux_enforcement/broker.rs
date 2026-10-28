//! Research broker for the shared Linux Box launch path.
use super::notify;
use crate::run::telemetry::{DecisionRecorder, EffectiveDecision};
use policy::{
    ApprovedPath, FsOperation, FsResult, GovernedBox, Outcome, PathResolver, PolicyEngine,
    Principal, Request,
};
use serde_json::{Value, json};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct BoxLookupError(io::Error);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const RESOLVE_NO_MAGICLINKS: u64 = 2;
const RESOLVE_NO_SYMLINKS: u64 = 4;
const RESOLVE_IN_ROOT: u64 = 16;
#[cfg(target_arch = "aarch64")]
const KERNEL_LARGEFILE: i32 = 0o400000;
#[cfg(not(target_arch = "aarch64"))]
const KERNEL_LARGEFILE: i32 = libc::O_LARGEFILE;
const NO_LINKS: u64 = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
const IN_ROOT: u64 = RESOLVE_IN_ROOT;
fn open(path: &str, flags: i32) -> io::Result<OwnedFd> {
    let path = CString::new(path)?;
    // SAFETY: CString supplies a live terminated path; open returns a new descriptor or an error.
    let fd = notify::checked(unsafe { libc::open(path.as_ptr(), flags, 0o600) })?;
    // SAFETY: The successful open returned a fresh descriptor; ownership transfers exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn openat2(root: i32, path: &[u8], flags: u64, mode: u64, resolve: u64) -> io::Result<OwnedFd> {
    let path = CString::new(path)?;
    let how = [flags, mode, resolve];
    // SAFETY: The terminated path and three-u64 open_how buffer remain live for this synchronous call.
    let fd = notify::checked(unsafe {
        libc::syscall(libc::SYS_openat2, root, path.as_ptr(), how.as_ptr(), 24) as i32
    })?;
    // SAFETY: The successful open returned a fresh descriptor; ownership transfers exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
struct RequestPath {
    directory: OwnedFd,
    relative: PathBuf,
    resolve: u64,
}

impl RequestPath {
    fn new(
        root: i32,
        request: &notify::Request,
        path: &Path,
        directory_arg: usize,
    ) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err("unsupported path component".into());
        }
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
        if path.is_absolute() {
            return Ok(Self {
                directory: openat2(root, b"/", flags as u64, 0, IN_ROOT | NO_LINKS)?,
                relative: path.to_path_buf(),
                resolve: IN_ROOT | RESOLVE_NO_MAGICLINKS,
            });
        }
        let directory_fd = request.data.args[directory_arg] as i32;
        let source = if directory_fd == libc::AT_FDCWD {
            format!("/proc/{}/cwd", request.pid)
        } else if directory_fd >= 0 {
            format!("/proc/{}/fd/{directory_fd}", request.pid)
        } else {
            return Err(io::Error::from_raw_os_error(libc::EBADF).into());
        };
        let directory = open(&source, flags)?;
        let name = std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
        let in_box = openat2(
            root,
            name.as_os_str().as_bytes(),
            flags as u64,
            0,
            IN_ROOT | NO_LINKS,
        )?;
        if entry_identity(&directory, libc::S_IFDIR)? != entry_identity(&in_box, libc::S_IFDIR)? {
            return Err("request directory is outside the captured Box view".into());
        }
        Ok(Self {
            directory: openat2(root, b"/", flags as u64, 0, IN_ROOT | NO_LINKS)?,
            relative: name.join(path),
            resolve: IN_ROOT | RESOLVE_NO_MAGICLINKS,
        })
    }

    fn pin(&self, flags: i32) -> io::Result<OwnedFd> {
        openat2(
            self.directory.as_raw_fd(),
            self.relative.as_os_str().as_bytes(),
            (libc::O_PATH | libc::O_CLOEXEC | (flags & (libc::O_NOFOLLOW | libc::O_DIRECTORY)))
                as u64,
            0,
            self.resolve,
        )
    }
}

fn operations(flags: u64) -> Option<Vec<FsOperation>> {
    let flags = i32::try_from(flags).ok()?;
    if flags & libc::O_PATH != 0 {
        return Some(vec![FsOperation::ReadMetadata]);
    }
    let supported = libc::O_ACCMODE
        | libc::O_CLOEXEC
        | libc::O_TRUNC
        | libc::O_APPEND
        | libc::O_NONBLOCK
        | libc::O_NOCTTY
        | libc::O_NOFOLLOW
        | KERNEL_LARGEFILE
        | libc::O_DIRECTORY;
    if flags & !supported != 0 {
        return None;
    }
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY if flags & (libc::O_TRUNC | libc::O_APPEND) == 0 => {
            Some(vec![FsOperation::ReadContent])
        }
        libc::O_WRONLY => Some(vec![FsOperation::WriteContent]),
        libc::O_RDWR => Some(vec![FsOperation::ReadContent, FsOperation::WriteContent]),
        _ => None,
    }
}

fn process_file(request: &notify::Request, path: &Path) -> Result<Option<PathBuf>> {
    if let Ok(relative) = path.strip_prefix("/proc/self") {
        if !["maps", "stat", "statm", "status", "cgroup"]
            .iter()
            .any(|name| relative == Path::new(name))
        {
            return Err("unsupported process file".into());
        }
        let status = std::fs::read_to_string(format!("/proc/{}/status", request.pid))?;
        let ids = status
            .lines()
            .find_map(|line| line.strip_prefix("NStgid:"))
            .ok_or("requester namespace process IDs absent")?;
        let id: u32 = ids
            .split_whitespace()
            .last()
            .ok_or("requester process ID absent")?
            .parse()?;
        if id < 2 {
            return Err("requester process ID is not a workload".into());
        }
        return Ok(Some(PathBuf::from(format!("/proc/{id}")).join(relative)));
    }
    if [
        "/proc/stat",
        "/proc/sys/vm/overcommit_memory",
        "/proc/sys/vm/mmap_min_addr",
    ]
    .iter()
    .any(|name| path == Path::new(name))
    {
        return Ok(Some(path.to_path_buf()));
    }
    Ok(None)
}

fn content_file(descriptor: &OwnedFd, path: &Path) -> io::Result<libc::stat> {
    // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
    notify::checked(unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) })?;
    let kind = stat.st_mode & libc::S_IFMT;
    let runtime_device = kind == libc::S_IFCHR
        && ["/dev/null", "/dev/random", "/dev/urandom"]
            .iter()
            .any(|name| path == Path::new(name));
    if !matches!(kind, libc::S_IFREG | libc::S_IFDIR) && !runtime_device {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(stat)
}

fn private_temporary_file(root: i32, path: &Path, object: &OwnedFd) -> io::Result<bool> {
    if !path.starts_with("/tmp") {
        return Ok(false);
    }
    let temporary = openat2(
        root,
        b"/tmp",
        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        0,
        IN_ROOT | NO_LINKS,
    )?;
    // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
    let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
    // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
    notify::checked(unsafe { libc::fstatfs(temporary.as_raw_fd(), &mut filesystem) })?;
    if filesystem.f_type != libc::TMPFS_MAGIC {
        return Ok(false);
    }
    let private_device = entry_identity(&temporary, libc::S_IFDIR)?.0;
    let host = open("/tmp", libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)?;
    // The launcher's private mount must differ from the host and contain the pinned object.
    Ok(private_device != entry_identity(&host, libc::S_IFDIR)?.0
        && private_device == entry_identity(object, 0)?.0)
}

struct Audit<'a> {
    recorder: &'a DecisionRecorder,
    pending: Vec<(FsOperation, policy::Decision)>,
    path: String,
    operation: FsOperation,
    allowed: bool,
    active: bool,
    reason: String,
}
impl<'a> Audit<'a> {
    fn new(recorder: &'a DecisionRecorder, path: String, operation: FsOperation) -> Self {
        Self {
            recorder,
            pending: Vec::new(),
            path,
            operation,
            allowed: false,
            active: true,
            reason: "native request did not complete".into(),
        }
    }
    fn refused(&mut self, reason: impl ToString) {
        self.reason = reason.to_string();
    }
}
fn action(operation: FsOperation) -> &'static str {
    match operation {
        FsOperation::ReadContent | FsOperation::ReadMetadata | FsOperation::Enumerate => "fs:read",
        FsOperation::RemoveFile | FsOperation::RemoveDir => "fs:delete",
        FsOperation::Rename => "fs:move",
        _ => "fs:write",
    }
}
impl Drop for Audit<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if self.pending.is_empty() {
            self.recorder.record(
                EffectiveDecision::enforcement_deny(
                    action(self.operation),
                    &self.path,
                    "native-filesystem-policy",
                    &self.reason,
                )
                .about(Some(telemetry::Subject::file(&self.path))),
            );
        }
        for (operation, decision) in &self.pending {
            let resource = decision.resource();
            let effective = if self.allowed || !decision.is_allow() {
                EffectiveDecision::from_policy(action(*operation), resource, decision)
            } else {
                EffectiveDecision::enforcement_deny(
                    action(*operation),
                    resource,
                    "native-filesystem-policy",
                    &self.reason,
                )
            };
            self.recorder
                .record(effective.about(Some(telemetry::Subject::file(resource))));
        }
    }
}

fn record(
    engine: &PolicyEngine,
    governed: &GovernedBox,
    path: &Path,
    operations: &[FsOperation],
    result: FsResult,
) -> Result<()> {
    for operation in operations {
        if matches!(result, FsResult::DescriptorIssued | FsResult::Completed) {
            super::fault::at("outcome")?;
        }
        engine.record(
            governed,
            &Principal::agent(),
            &Outcome::Fs {
                path,
                operation: *operation,
                result,
            },
        )?;
    }
    Ok(())
}

pub(super) fn file_request(
    resolver: &PathResolver,
    engine: &PolicyEngine,
    root: i32,
    listener: i32,
    request: &notify::Request,
    governed: &GovernedBox,
    recorder: &DecisionRecorder,
) -> Result<Value> {
    notify::valid(listener, request.id)?;
    let truncate = request.data.number == libc::SYS_truncate as i32;
    let flags = if truncate {
        libc::O_WRONLY | libc::O_CLOEXEC
    } else {
        request.data.args[2] as i32 & !(libc::O_CREAT | libc::O_EXCL)
    };
    let copied = notify::read_path(request, usize::from(!truncate))?;
    notify::valid(listener, request.id)?;
    let path = Path::new(std::str::from_utf8(&copied)?);
    let access = if flags & (libc::O_ACCMODE | libc::O_TRUNC) == 0 {
        FsOperation::ReadContent
    } else {
        FsOperation::WriteContent
    };
    let mut audit = Audit::new(recorder, path.display().to_string(), access);
    if request.data.number != libc::SYS_openat as i32 && !truncate {
        return Err("unexpected file syscall".into());
    }
    let Some(mut operations) = operations(flags as u64) else {
        static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("strands-box: native filesystem interception refused unsupported open flags");
        }
        audit.refused("unsupported open flags");
        notify::reply(listener, request.id, libc::EACCES)?;
        return Ok(
            json!({"refusal": "unsupported flags", "flags":request.data.args[2], "path":path, "decisions": []}),
        );
    };
    if flags & libc::O_PATH != 0 && super::PATH_HANDLES.get() != Some(&true) {
        audit.refused("kernel cannot transfer path-only handles");
        notify::reply(listener, request.id, libc::EOPNOTSUPP)?;
        return Ok(json!({"refusal":"kernel cannot transfer path-only handles", "decisions":[]}));
    }
    // Resolve in the captured Box view before asking policy.
    let prepared = (|| -> Result<_> {
        if let Some(process_path) = process_file(request, path)? {
            if operations != [FsOperation::ReadContent] {
                return Err("process files permit only read-only opens".into());
            }
            let pinned = openat2(
                root,
                process_path.as_os_str().as_bytes(),
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                0,
                RESOLVE_IN_ROOT | NO_LINKS,
            )
            .map_err(BoxLookupError)?;
            content_file(&pinned, &process_path)?;
            // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
            let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
            // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
            notify::checked(unsafe { libc::fstatfs(pinned.as_raw_fd(), &mut filesystem) })?;
            if filesystem.f_type != libc::PROC_SUPER_MAGIC {
                return Err("process file is outside the captured proc filesystem".into());
            }
            return Ok((resolver.approve_virtual(&process_path)?, pinned));
        }
        let resolved = RequestPath::new(root, request, path, 0)?;
        let pinned = resolved.pin(flags).map_err(BoxLookupError)?;
        let actual_path = std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
        // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
        let mut kind = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
        notify::checked(unsafe { libc::fstat(pinned.as_raw_fd(), &mut kind) })?;
        if kind.st_mode & libc::S_IFMT == libc::S_IFLNK && flags & libc::O_PATH == 0 {
            return Err(Box::new(BoxLookupError(io::Error::from_raw_os_error(
                libc::ELOOP,
            ))));
        }
        let identity = if flags & libc::O_PATH != 0 {
            // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
            let mut identity = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
            notify::checked(unsafe { libc::fstat(pinned.as_raw_fd(), &mut identity) })?;
            identity
        } else {
            content_file(&pinned, &actual_path)?
        };
        let link_handle = identity.st_mode & libc::S_IFMT == libc::S_IFLNK;
        if link_handle && flags & libc::O_PATH == 0 {
            return Err(Box::new(BoxLookupError(io::Error::from_raw_os_error(
                libc::ELOOP,
            ))));
        }
        if identity.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if operations == [FsOperation::ReadContent] {
                operations = vec![FsOperation::Enumerate];
            } else if operations != [FsOperation::ReadMetadata] {
                return Err("directory open requests content mutation".into());
            }
        } else if flags & libc::O_DIRECTORY != 0 {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR).into());
        }
        if private_temporary_file(root, &actual_path, &pinned)? {
            return Ok((resolver.approve_virtual(&actual_path)?, pinned));
        }
        let canonical = if link_handle {
            std::fs::canonicalize(actual_path.parent().ok_or("link has no parent")?)?
                .join(actual_path.file_name().ok_or("link has no name")?)
        } else {
            std::fs::canonicalize(&actual_path)?
        };
        let approved = if link_handle {
            resolver.approve_host_entry(&canonical)?
        } else {
            resolver.approve_host(&canonical)?
        };
        // Policy and the captured Box view must identify the same object.
        let host = openat2(
            libc::AT_FDCWD,
            canonical.as_os_str().as_bytes(),
            (libc::O_PATH | libc::O_CLOEXEC | if link_handle { libc::O_NOFOLLOW } else { 0 })
                as u64,
            0,
            RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )?;
        // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
        let mut host_identity = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
        notify::checked(unsafe { libc::fstat(host.as_raw_fd(), &mut host_identity) })?;
        if (identity.st_dev, identity.st_ino) != (host_identity.st_dev, host_identity.st_ino) {
            return Err("host and Box paths identify different files".into());
        }
        Ok((approved, pinned))
    })();
    let (approved, pinned) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            audit.refused(&error);
            let errno = error
                .downcast_ref::<BoxLookupError>()
                .and_then(|error| error.0.raw_os_error())
                .unwrap_or(libc::EACCES);
            notify::reply(listener, request.id, errno)?;
            return Ok(
                json!({"refusal": error.to_string(), "path":path, "flags":request.data.args[2], "broker_errno":errno, "decisions": []}),
            );
        }
    };
    let mut decisions = Vec::new();
    let mut permitted = Vec::new();
    for operation in &operations {
        super::fault::at("request")?;
        notify::valid(listener, request.id)?;
        let decision = engine.decide(
            governed,
            &Principal::agent(),
            &Request::Fs {
                path: &approved,
                operation: *operation,
            },
        );
        audit.pending.push((*operation, decision.clone()));
        if matches!(
            decision,
            policy::Decision::Deny {
                reason: policy::DenyReason::InternalFault,
                ..
            }
        ) {
            notify::reply(listener, request.id, libc::EACCES)?;
            return Err("native policy history failed".into());
        }
        decisions.push(json!({
            "operation": format!("{operation:?}"),
            "allow": decision.is_allow(),
            "decision": format!("{decision:?}"),
            "resource": decision.resource(),
        }));
        if !decision.is_allow() {
            audit.refused("a required policy check denied the operation");
            record(
                engine,
                governed,
                approved.as_path(),
                &permitted,
                FsResult::Failed,
            )?;
            notify::reply(listener, request.id, libc::EACCES)?;
            return Ok(json!({"decisions": decisions, "outcome": "denied"}));
        }
        permitted.push(*operation);
    }
    super::fault::at("entry-verified")?;
    notify::valid(listener, request.id)?;
    let source = if flags & libc::O_PATH != 0 {
        pinned.try_clone()
    } else {
        open(
            &format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            flags & !libc::O_NOFOLLOW,
        )
    };
    match source {
        Err(error) => {
            audit.refused(&error);
            record(
                engine,
                governed,
                approved.as_path(),
                &permitted,
                FsResult::Failed,
            )?;
            let errno = error.raw_os_error().ok_or("open failed without errno")?;
            notify::reply(listener, request.id, errno)?;
            Ok(json!({"decisions": decisions, "outcome": "failed", "broker_errno": errno}))
        }
        Ok(source) => {
            if truncate {
                notify::valid(listener, request.id)?;
                // SAFETY: The owned descriptor remains live; ftruncate validates the scalar length.
                let effect = notify::checked(unsafe {
                    libc::ftruncate(source.as_raw_fd(), request.data.args[1] as libc::off_t)
                });
                audit.allowed = effect.is_ok();
                if let Err(error) = &effect {
                    audit.refused(error);
                }
                record(
                    engine,
                    governed,
                    approved.as_path(),
                    &permitted,
                    if effect.is_ok() {
                        FsResult::Completed
                    } else {
                        FsResult::Failed
                    },
                )?;
                let errno = effect.err().and_then(|error| error.raw_os_error());
                notify::reply(listener, request.id, errno.unwrap_or(0))?;
                return Ok(
                    json!({"decisions":decisions, "outcome": if errno.is_some() { "failed" } else { "completed" }, "broker_errno":errno}),
                );
            }
            match notify::inject(
                listener,
                request.id,
                source.as_raw_fd(),
                request.data.args[2] & libc::O_CLOEXEC as u64 != 0,
            ) {
                Ok(descriptor) => {
                    audit.allowed = true;
                    record(
                        engine,
                        governed,
                        approved.as_path(),
                        &permitted,
                        FsResult::DescriptorIssued,
                    )?;
                    Ok(
                        json!({"decisions": decisions, "outcome": "descriptor_issued", "fd": descriptor}),
                    )
                }
                Err(error) => {
                    // An open with O_TRUNC may already have changed the file.
                    record(
                        engine,
                        governed,
                        approved.as_path(),
                        &permitted,
                        FsResult::Indeterminate,
                    )?;
                    Err(error.into())
                }
            }
        }
    }
}

struct Entry {
    path: ApprovedPath,
    parent: OwnedFd,
    leaf: CString,
    exists: bool,
    object: Option<OwnedFd>,
}

fn entry_identity(
    descriptor: &OwnedFd,
    expected: libc::mode_t,
) -> io::Result<(libc::dev_t, libc::ino_t)> {
    // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
    notify::checked(unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) })?;
    let kind = stat.st_mode & libc::S_IFMT;
    if (expected != 0 && kind != expected)
        || (expected == 0 && !matches!(kind, libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK))
    {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok((stat.st_dev, stat.st_ino))
}

fn entry(
    resolver: &PathResolver,
    root: i32,
    request: &notify::Request,
    bytes: &[u8],
    directory_arg: usize,
) -> Result<Entry> {
    let path = Path::new(std::str::from_utf8(bytes)?);
    let resolved = RequestPath::new(root, request, path, directory_arg)?;
    let relative = resolved.relative.as_os_str().as_bytes();
    let end = relative
        .iter()
        .rposition(|byte| *byte != b'/')
        .ok_or("entry has no name")?
        + 1;
    let start = relative[..end]
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index + 1);
    if matches!(&relative[start..end], b"." | b"..") {
        return Err(BoxLookupError(io::Error::from_raw_os_error(libc::EINVAL)).into());
    }
    let leaf = CString::new(&relative[start..])?;
    let flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    let relative_parent = if start == 0 {
        b".".as_slice()
    } else {
        &relative[..start]
    };
    let parent = openat2(
        resolved.directory.as_raw_fd(),
        relative_parent,
        flags,
        0,
        resolved.resolve,
    )
    .map_err(BoxLookupError)?;
    let actual_parent = std::fs::read_link(format!("/proc/self/fd/{}", parent.as_raw_fd()))?;
    let private = private_temporary_file(root, &actual_parent, &parent)?;
    let parent_path = if private {
        actual_parent
    } else {
        std::fs::canonicalize(actual_parent)?
    };
    let host = if private {
        parent.try_clone()?
    } else {
        openat2(
            libc::AT_FDCWD,
            parent_path.as_os_str().as_bytes(),
            flags,
            0,
            NO_LINKS,
        )?
    };
    if entry_identity(&parent, libc::S_IFDIR)? != entry_identity(&host, libc::S_IFDIR)? {
        return Err("host and Box parent directories differ".into());
    }
    let flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    let object = openat2(parent.as_raw_fd(), leaf.as_bytes(), flags, 0, NO_LINKS);
    let host_object = openat2(host.as_raw_fd(), leaf.as_bytes(), flags, 0, NO_LINKS);
    let object = match (object, host_object) {
        (Ok(object), Ok(host_object)) => {
            if entry_identity(&object, 0)? != entry_identity(&host_object, 0)? {
                return Err("host and Box directory entries differ".into());
            }
            Some(object)
        }
        (Err(box_error), Err(host_error))
            if box_error.raw_os_error() == Some(libc::ENOENT)
                && host_error.raw_os_error() == Some(libc::ENOENT) =>
        {
            None
        }
        _ => return Err("entry is inaccessible or different in the Box view".into()),
    };
    let name = parent_path.join(std::ffi::OsStr::from_bytes(leaf.as_bytes()));
    let approved = if private {
        resolver.approve_virtual(&name)?
    } else {
        resolver.approve_host_entry(&name)?
    };
    Ok(Entry {
        path: approved,
        parent,
        leaf,
        exists: object.is_some(),
        object,
    })
}

fn creation_entry(
    resolver: &PathResolver,
    root: i32,
    request: &notify::Request,
    mut source: Entry,
) -> Result<Entry> {
    if request.data.args[2] as i32 & (libc::O_EXCL | libc::O_NOFOLLOW) != 0 {
        return Ok(source);
    }
    for _ in 0..40 {
        let Some(object) = source.object.as_ref() else {
            return Ok(source);
        };
        // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
        notify::checked(unsafe { libc::fstat(object.as_raw_fd(), &mut stat) })?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return Ok(source);
        }
        // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
        let mut filesystem = unsafe { std::mem::zeroed::<libc::statfs>() };
        // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
        notify::checked(unsafe { libc::fstatfs(object.as_raw_fd(), &mut filesystem) })?;
        if filesystem.f_type == libc::PROC_SUPER_MAGIC {
            return Err(BoxLookupError(io::Error::from_raw_os_error(libc::ELOOP)).into());
        }
        let mut target = [0_u8; 4096];
        // SAFETY: The live descriptor and writable output buffer remain valid for this synchronous call.
        let length = notify::checked(unsafe {
            libc::readlinkat(
                object.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            ) as i32
        })? as usize;
        if length == target.len() {
            return Err(BoxLookupError(io::Error::from_raw_os_error(libc::ENAMETOOLONG)).into());
        }
        let target = Path::new(std::str::from_utf8(&target[..length])?);
        let target = source
            .path
            .as_path()
            .parent()
            .ok_or("link has no parent")?
            .join(target);
        source = entry(resolver, root, request, target.as_os_str().as_bytes(), 0)?;
    }
    Err(BoxLookupError(io::Error::from_raw_os_error(libc::ELOOP)).into())
}

impl Entry {
    fn verify(&self) -> io::Result<()> {
        let current = openat2(
            self.parent.as_raw_fd(),
            self.leaf.as_bytes(),
            (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            0,
            NO_LINKS,
        );
        match (&self.object, current) {
            (Some(approved), Ok(current))
                if entry_identity(approved, 0)? == entry_identity(&current, 0)? =>
            {
                Ok(())
            }
            (None, Err(error)) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            _ => Err(io::Error::from_raw_os_error(libc::EACCES)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn entry_request(
    guard: &super::guard::Worker,
    resolver: &PathResolver,
    engine: &policy::PolicyEngine,
    root: i32,
    listener: i32,
    request: &notify::Request,
    governed: &GovernedBox,
    recorder: &DecisionRecorder,
) -> Result<Value> {
    notify::valid(listener, request.id)?;
    let number = request.data.number as libc::c_long;
    let symlink = number == libc::SYS_symlinkat;
    let mkdir = number == libc::SYS_mkdirat;
    let rmdir = number == libc::SYS_unlinkat && request.data.args[2] == libc::AT_REMOVEDIR as u64;
    let bytes = notify::read_path(request, if symlink { 2 } else { 1 })?;
    let link_target = if symlink {
        Some(CString::new(notify::read_path(request, 0)?)?)
    } else {
        None
    };
    let rename = number == libc::SYS_renameat || number == libc::SYS_renameat2;
    let mut audit = Audit::new(
        recorder,
        String::from_utf8_lossy(&bytes).into_owned(),
        if rename {
            FsOperation::Rename
        } else if rmdir {
            FsOperation::RemoveDir
        } else if number == libc::SYS_unlinkat {
            FsOperation::RemoveFile
        } else if mkdir {
            FsOperation::CreateDir
        } else if symlink {
            FsOperation::Symlink
        } else {
            FsOperation::WriteContent
        },
    );
    let prepared = (|| -> Result<_> {
        if number == libc::SYS_openat
            && (request.data.args[2] & libc::O_CREAT as u64 == 0
                || operations(request.data.args[2] & !((libc::O_CREAT | libc::O_EXCL) as u64))
                    .is_none()
                || request.data.args[2] & libc::O_DIRECTORY as u64 != 0
                || request.data.args[3] & !0o777 != 0)
            || number == libc::SYS_unlinkat && request.data.args[2] != 0 && !rmdir
            || mkdir && request.data.args[2] & !0o777 != 0
            || number == libc::SYS_renameat2 && request.data.args[4] != 0
        {
            return Err("unsupported entry flags or mode".into());
        }
        if mkdir {
            let path = Path::new(std::str::from_utf8(&bytes)?);
            let resolved = RequestPath::new(root, request, path, 0)?;
            if resolved.pin(0).is_ok() {
                return Err(BoxLookupError(io::Error::from_raw_os_error(libc::EEXIST)).into());
            }
        }
        let source = entry(resolver, root, request, &bytes, usize::from(symlink))?;
        let source = if number == libc::SYS_openat {
            creation_entry(resolver, root, request, source)?
        } else {
            source
        };
        let destination = if rename {
            Some(entry(
                resolver,
                root,
                request,
                &notify::read_path(request, 3)?,
                2,
            )?)
        } else {
            None
        };
        if let Some(object) = destination.as_ref().and_then(|entry| entry.object.as_ref())
            && entry_identity(object, libc::S_IFDIR).is_ok()
        {
            return Err("replacing an existing directory is not supported".into());
        }
        if number != libc::SYS_openat && !mkdir && !symlink && !source.exists {
            return Err("source entry does not exist".into());
        }
        Ok((source, destination))
    })();
    let (source, destination) = match prepared {
        Ok(value) => value,
        Err(error) => {
            audit.refused(&error);
            let errno = error
                .downcast_ref::<BoxLookupError>()
                .and_then(|error| error.0.raw_os_error())
                .unwrap_or(libc::EACCES);
            notify::reply(listener, request.id, errno)?;
            return Ok(json!({"refusal":error.to_string(), "broker_errno":errno, "decisions":[]}));
        }
    };
    notify::valid(listener, request.id)?;
    if (mkdir || symlink) && source.exists {
        notify::reply(listener, request.id, libc::EEXIST)?;
        return Ok(
            json!({"refusal":"creation target already exists", "decisions":[], "broker_errno":libc::EEXIST}),
        );
    }
    if number == libc::SYS_openat && source.exists {
        if request.data.args[2] & libc::O_EXCL as u64 != 0 {
            notify::reply(listener, request.id, libc::EEXIST)?;
            return Ok(
                json!({"refusal":"exclusive creation target already exists", "decisions":[], "broker_errno":libc::EEXIST}),
            );
        }
        audit.active = false;
        return file_request(
            resolver, engine, root, listener, request, governed, recorder,
        );
    }
    let mut checks = match number {
        libc::SYS_openat => {
            let mut checks = vec![(&source.path, FsOperation::WriteContent)];
            if request.data.args[2] as i32 & libc::O_ACCMODE != libc::O_WRONLY {
                checks.push((&source.path, FsOperation::ReadContent));
            }
            checks
        }
        libc::SYS_mkdirat => vec![(&source.path, FsOperation::CreateDir)],
        libc::SYS_symlinkat => vec![(&source.path, FsOperation::Symlink)],
        libc::SYS_unlinkat => vec![(
            &source.path,
            if rmdir {
                FsOperation::RemoveDir
            } else {
                FsOperation::RemoveFile
            },
        )],
        _ if rename => {
            let destination = destination.as_ref().ok_or("rename destination absent")?;
            let mut checks = vec![
                (&source.path, FsOperation::Rename),
                (&source.path, FsOperation::ReadContent),
            ];
            if destination.exists {
                checks.push((&destination.path, FsOperation::RemoveFile));
            }
            checks.push((&destination.path, FsOperation::Rename));
            if destination.exists {
                checks.push((&destination.path, FsOperation::WriteContent));
            }
            checks
        }
        _ => return Err("unrecognized entry syscall".into()),
    };
    let principal = Principal::agent();
    let mut decisions = Vec::new();
    let mut permitted = Vec::new();
    for (path, operation) in checks.drain(..) {
        super::fault::at("request")?;
        notify::valid(listener, request.id)?;
        let decision = engine.decide(governed, &principal, &Request::Fs { path, operation });
        audit.pending.push((operation, decision.clone()));
        if matches!(
            decision,
            policy::Decision::Deny {
                reason: policy::DenyReason::InternalFault,
                ..
            }
        ) {
            notify::reply(listener, request.id, libc::EACCES)?;
            return Err("native policy history failed".into());
        }
        decisions.push(
            json!({"path":path.as_path(), "operation":format!("{operation:?}"),
            "allow":decision.is_allow(), "decision":format!("{decision:?}")}),
        );
        if !decision.is_allow() {
            audit.refused("a required policy check denied the operation");
            for (path, operation) in permitted {
                engine.record(
                    governed,
                    &principal,
                    &Outcome::Fs {
                        path,
                        operation,
                        result: FsResult::Failed,
                    },
                )?;
            }
            notify::reply(listener, request.id, libc::EACCES)?;
            return Ok(json!({"decisions":decisions, "outcome":"denied"}));
        }
        permitted.push((path.as_path(), operation));
    }
    super::fault::at("entry-checked")?;
    let verified = source
        .verify()
        .and_then(|()| destination.as_ref().map_or(Ok(()), Entry::verify));
    if let Err(error) = verified {
        audit.refused(&error);
        for (path, operation) in permitted {
            engine.record(
                governed,
                &principal,
                &Outcome::Fs {
                    path,
                    operation,
                    result: FsResult::Failed,
                },
            )?;
        }
        notify::reply(listener, request.id, libc::EACCES)?;
        return Ok(
            json!({"decisions":decisions,"outcome":"failed","refusal":"directory entry changed after authorization"}),
        );
    }
    super::fault::at("entry-verified")?;
    notify::valid(listener, request.id)?;
    // SAFETY: Owned descriptors and CStrings outlive these synchronous calls, including the guarded closures.
    let effect = unsafe {
        match number {
            libc::SYS_openat | libc::SYS_mkdirat => {
                let status = std::fs::read_to_string(format!("/proc/{}/status", request.pid))?;
                let mask = status
                    .lines()
                    .find_map(|line| line.strip_prefix("Umask:"))
                    .ok_or("requester umask absent")?;
                let mask = u32::from_str_radix(mask.trim(), 8)?;
                if mask & !0o777 != 0 {
                    return Err("invalid requester umask".into());
                }
                notify::valid(listener, request.id)?;
                let previous = libc::umask(mask);
                let created = if mkdir {
                    notify::checked(libc::mkdirat(
                        source.parent.as_raw_fd(),
                        source.leaf.as_ptr(),
                        request.data.args[2] as libc::mode_t,
                    ))
                } else {
                    notify::checked(libc::openat(
                        source.parent.as_raw_fd(),
                        source.leaf.as_ptr(),
                        request.data.args[2] as i32 | libc::O_EXCL | libc::O_CLOEXEC,
                        request.data.args[3] as libc::mode_t,
                    ))
                };
                libc::umask(previous);
                created
            }
            libc::SYS_symlinkat => notify::checked(libc::symlinkat(
                link_target.as_ref().ok_or("link target absent")?.as_ptr(),
                source.parent.as_raw_fd(),
                source.leaf.as_ptr(),
            )),
            libc::SYS_unlinkat => guard.effect(
                &source.parent,
                source.object.as_ref().ok_or("unlink identity absent")?,
                None,
                || {
                    notify::checked(libc::unlinkat(
                        source.parent.as_raw_fd(),
                        source.leaf.as_ptr(),
                        if rmdir { libc::AT_REMOVEDIR } else { 0 },
                    ))
                },
            ),
            _ => {
                let destination = destination.as_ref().ok_or("rename destination absent")?;
                let flags = if destination.exists {
                    0
                } else {
                    libc::RENAME_NOREPLACE
                };
                guard.effect(
                    &source.parent,
                    source.object.as_ref().ok_or("rename identity absent")?,
                    Some((&destination.parent, destination.object.as_ref())),
                    || {
                        notify::checked(libc::syscall(
                            libc::SYS_renameat2,
                            source.parent.as_raw_fd(),
                            source.leaf.as_ptr(),
                            destination.parent.as_raw_fd(),
                            destination.leaf.as_ptr(),
                            flags,
                        ) as i32)
                    },
                )
            }
        }
    };
    let error = effect.as_ref().err();
    let (result, outcome) = if error.is_some() {
        (FsResult::Failed, "failed")
    } else if number == libc::SYS_openat {
        // SAFETY: The successful open returned a fresh descriptor; ownership transfers exactly once.
        let descriptor = unsafe {
            OwnedFd::from_raw_fd(
                *effect
                    .as_ref()
                    .map_err(|error| io::Error::other(error.to_string()))?,
            )
        };
        if let Err(error) = notify::inject(
            listener,
            request.id,
            descriptor.as_raw_fd(),
            request.data.args[2] as i32 & libc::O_CLOEXEC != 0,
        ) {
            for (path, operation) in &permitted {
                engine.record(
                    governed,
                    &principal,
                    &Outcome::Fs {
                        path,
                        operation: *operation,
                        result: FsResult::Indeterminate,
                    },
                )?;
            }
            return Err(error.into());
        }
        audit.allowed = true;
        (FsResult::DescriptorIssued, "descriptor_issued")
    } else {
        (FsResult::Completed, "completed")
    };
    for (path, operation) in permitted {
        if matches!(result, FsResult::DescriptorIssued | FsResult::Completed) {
            super::fault::at("outcome")?;
        }
        engine.record(
            governed,
            &principal,
            &Outcome::Fs {
                path,
                operation,
                result,
            },
        )?;
    }
    if number != libc::SYS_openat || error.is_some() {
        audit.allowed = error.is_none();
        if let Some(error) = error {
            audit.refused(error);
        }
    }
    guard.check()?;
    let errno = error.and_then(io::Error::raw_os_error);
    if number != libc::SYS_openat || error.is_some() {
        notify::reply(listener, request.id, errno.unwrap_or(0))?;
    }
    Ok(json!({"decisions":decisions, "outcome":outcome, "broker_errno":errno}))
}

#[cfg(test)]
mod path_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn request(directory: i32) -> notify::Request {
        let mut request = notify::Request {
            pid: std::process::id(),
            ..Default::default()
        };
        request.data.args[0] = directory as u64;
        request
    }
    fn root(path: &Path) -> OwnedFd {
        openat2(
            libc::AT_FDCWD,
            path.as_os_str().as_bytes(),
            (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            0,
            NO_LINKS,
        )
        .unwrap()
    }
    fn bytes(fd: &OwnedFd) -> Vec<u8> {
        std::fs::read(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap()
    }
    #[test]
    fn absolute_link_targets_and_parent_components_stay_in_the_captured_root() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::create_dir(fixture.path().join("directory")).unwrap();
        std::fs::write(fixture.path().join("file"), b"captured").unwrap();
        symlink("/directory/../file", fixture.path().join("link")).unwrap();
        let root = root(fixture.path());
        for path in ["/link", "/directory/../../file", "/directory/../link"] {
            let resolved = RequestPath::new(
                root.as_raw_fd(),
                &request(libc::AT_FDCWD),
                Path::new(path),
                0,
            )
            .unwrap();
            assert_eq!(bytes(&resolved.pin(libc::O_RDONLY).unwrap()), b"captured");
        }
        let outside = RequestPath::new(
            root.as_raw_fd(),
            &request(libc::AT_FDCWD),
            Path::new("/../../etc/passwd"),
            0,
        )
        .unwrap();
        assert_eq!(
            outside.pin(0).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }
    #[test]
    fn directory_relative_links_and_parent_components_resolve() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(fixture.path().join("file"), b"relative").unwrap();
        symlink("../file", directory.join("link")).unwrap();
        let root = root(Path::new("/"));
        let directory = self::root(&directory);
        for path in ["../file", "link", "./../directory/link"] {
            let resolved = RequestPath::new(
                root.as_raw_fd(),
                &request(directory.as_raw_fd()),
                Path::new(path),
                0,
            )
            .unwrap();
            assert_eq!(bytes(&resolved.pin(0).unwrap()), b"relative");
        }
    }
    #[test]
    fn path_only_nofollow_keeps_the_link_identity() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("file"), b"contents").unwrap();
        symlink("file", fixture.path().join("link")).unwrap();
        let root = root(fixture.path());
        let resolved = RequestPath::new(
            root.as_raw_fd(),
            &request(libc::AT_FDCWD),
            Path::new("/link"),
            0,
        )
        .unwrap();
        let link = resolved.pin(libc::O_PATH | libc::O_NOFOLLOW).unwrap();
        // SAFETY: Zero is a valid initial representation of this integer-only C output structure.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: The descriptor is borrowed from a live owner and the output structure is writable.
        notify::checked(unsafe { libc::fstat(link.as_raw_fd(), &mut stat) }).unwrap();
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFLNK);
        assert_eq!(
            operations((libc::O_PATH | libc::O_TRUNC | libc::O_WRONLY) as u64),
            Some(vec![FsOperation::ReadMetadata])
        );
    }
    #[test]
    fn magic_links_are_refused_and_a_pinned_target_survives_replacement() {
        let fixture = tempfile::tempdir().unwrap();
        let file = fixture.path().join("file");
        std::fs::write(&file, b"approved").unwrap();
        let root = root(Path::new("/"));
        let resolved =
            RequestPath::new(root.as_raw_fd(), &request(libc::AT_FDCWD), &file, 0).unwrap();
        let pinned = resolved.pin(0).unwrap();
        let magic = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
        let resolved =
            RequestPath::new(root.as_raw_fd(), &request(libc::AT_FDCWD), &magic, 0).unwrap();
        assert_eq!(
            resolved.pin(0).unwrap_err().raw_os_error(),
            Some(libc::ELOOP)
        );
        std::fs::rename(&file, fixture.path().join("old")).unwrap();
        std::fs::write(&file, b"replacement").unwrap();
        assert_eq!(bytes(&pinned), b"approved");
    }
}
