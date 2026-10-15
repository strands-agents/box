//! Descendant filesystem authorization through this box's existing Dogwood engine.

use std::ffi::c_void;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use policy::{
    FsOperation, FsResult, GovernedBox, Outcome, PathResolver, PolicyEngine, Principal, Request,
};

use super::telemetry::{DecisionRecorder, EffectiveDecision};
use crate::error::NativeFilesystemError;

const OPEN: u32 = 1;
const CREATE: u32 = 2;
const UNLINK: u32 = 3;
const RENAME: u32 = 4;
const TRUNCATE: u32 = 5;
const AUTH: u32 = 1;
const NOTIFY: u32 = 2;
const REPLY: u32 = 3;
const FREAD: u32 = 1;
const FWRITE: u32 = 2;
const FILE_IDENTITY: u32 = 1;
const PARENT_IDENTITY: u32 = 2;

#[repr(C)]
struct RawEvent {
    kind: u32,
    phase: u32,
    flags: u32,
    mode: u32,
    sequence: u64,
    deadline: u64,
    pid: i32,
    valid: u32,
    source_dev: u64,
    source_ino: u64,
    destination_dev: u64,
    destination_ino: u64,
    source_identity: u32,
    destination_identity: u32,
    destination_exists: u32,
    destination_mode: u32,
    result: u32,
    path: [u8; 4096],
    destination: [u8; 4096],
}

unsafe extern "C" {
    fn box_es_start(
        context: *mut c_void,
        callback: unsafe extern "C" fn(*mut c_void, *const RawEvent, i32) -> bool,
        error: *mut i32,
        parent_dev: u64,
        parent_ino: u64,
    ) -> *mut c_void;
    fn box_es_prepare_bootstrap(client: *mut c_void, device: u64, inode: u64) -> bool;
    fn box_es_set_process_mode(client: *mut c_void, pid: i32, mediated: bool) -> bool;
    fn box_es_stop(client: *mut c_void) -> i32;
    #[cfg(test)]
    fn box_es_event_size() -> usize;
    #[cfg(test)]
    fn box_es_event_offset(field: usize) -> usize;
    #[cfg(test)]
    fn box_es_has_children(process: i32) -> bool;
}

struct Check {
    path: PathBuf,
    operation: FsOperation,
    action: &'static str,
    entry: bool,
}

struct Identity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

struct Plan {
    checks: Vec<Check>,
    identities: Vec<Identity>,
}

fn refused(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

#[derive(Debug)]
struct PolicyRefusal;

impl std::fmt::Display for PolicyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Dogwood denied this file operation")
    }
}

impl std::error::Error for PolicyRefusal {}

fn path(bytes: &[u8; 4096]) -> io::Result<PathBuf> {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| refused("unterminated kernel path"))?;
    // Policy serializes paths as text. Refuse non-UTF-8 rather than changing their identity.
    std::str::from_utf8(&bytes[..length]).map_err(|_| refused("non-UTF-8 kernel path"))?;
    let result = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..length]));
    if !result.is_absolute()
        || result.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(refused("invalid kernel path"));
    }
    Ok(result)
}

impl Plan {
    fn decode(event: &RawEvent) -> io::Result<Self> {
        if event.valid != 1 || event.phase != AUTH {
            return Err(refused("invalid authorization message"));
        }
        let source = path(&event.path)?;
        let identity_path = match event.source_identity {
            FILE_IDENTITY => source.clone(),
            PARENT_IDENTITY => source
                .parent()
                .ok_or_else(|| refused("missing parent"))?
                .to_path_buf(),
            _ => return Err(refused("missing source identity")),
        };
        let mut identities = vec![Identity {
            path: identity_path,
            device: event.source_dev,
            inode: event.source_ino,
        }];
        let mut checks = Vec::new();
        let mut add = |path: &Path, operation, action, entry| {
            checks.push(Check {
                path: path.into(),
                operation,
                action,
                entry,
            });
        };
        match event.kind {
            OPEN => {
                if event.flags & (FREAD | FWRITE) == 0 {
                    let modifiers = (libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                        | libc::O_NOCTTY
                        | libc::O_NOFOLLOW
                        | libc::O_SYMLINK) as u32;
                    let operation = match event.flags & !modifiers {
                        mode if mode == libc::O_EVTONLY as u32 => {
                            // Event-only descriptors still require content permission.
                            FsOperation::ReadContent
                        }
                        mode if mode == libc::O_EXEC as u32 => FsOperation::ExecFile,
                        _ => return Err(refused("open has unsupported access flags")),
                    };
                    add(&source, operation, "fs:read", false);
                }
                if event.flags & FREAD != 0 {
                    add(&source, FsOperation::ReadContent, "fs:read", false);
                }
                // FTRUNC can request a write even with a read-only descriptor.
                if event.flags & (FWRITE | libc::O_TRUNC as u32) != 0 {
                    add(&source, FsOperation::WriteContent, "fs:write", false);
                }
            }
            CREATE => {
                if event.destination_exists != 0 || event.source_identity != PARENT_IDENTITY {
                    return Err(refused("create requires a new directory entry"));
                }
                let operation = match event.mode & libc::S_IFMT as u32 {
                    value if value == libc::S_IFREG as u32 => FsOperation::WriteContent,
                    value if value == libc::S_IFDIR as u32 => FsOperation::CreateDir,
                    value if value == libc::S_IFLNK as u32 => FsOperation::Symlink,
                    _ => return Err(refused("unsupported created object")),
                };
                add(&source, operation, "fs:write", true);
            }
            UNLINK => {
                let operation = match event.mode & libc::S_IFMT as u32 {
                    value if value == libc::S_IFDIR as u32 => FsOperation::RemoveDir,
                    value if value == libc::S_IFREG as u32 || value == libc::S_IFLNK as u32 => {
                        FsOperation::RemoveFile
                    }
                    _ => return Err(refused("unsupported removed object")),
                };
                add(&source, operation, "fs:delete", true);
            }
            RENAME => {
                let destination = path(&event.destination)?;
                let replacement = match (event.destination_exists, event.destination_identity) {
                    (0, PARENT_IDENTITY) => false,
                    (1, FILE_IDENTITY)
                        if matches!(
                            event.destination_mode & libc::S_IFMT as u32,
                            mode if mode == libc::S_IFREG as u32 || mode == libc::S_IFLNK as u32
                        ) =>
                    {
                        true
                    }
                    _ => {
                        return Err(refused(
                            "rename destination type or identity is unsupported",
                        ));
                    }
                };
                identities.push(Identity {
                    path: if replacement {
                        destination.clone()
                    } else {
                        destination
                            .parent()
                            .ok_or_else(|| refused("missing destination parent"))?
                            .to_path_buf()
                    },
                    device: event.destination_dev,
                    inode: event.destination_ino,
                });
                add(&source, FsOperation::ReadContent, "fs:read", true);
                add(&source, FsOperation::Rename, "fs:move", true);
                add(&destination, FsOperation::Rename, "fs:move", true);
                if replacement {
                    add(&destination, FsOperation::RemoveFile, "fs:delete", true);
                    add(&destination, FsOperation::WriteContent, "fs:write", true);
                }
            }
            TRUNCATE => add(&source, FsOperation::WriteContent, "fs:write", false),
            _ => return Err(refused("unsupported authorization event")),
        }
        Ok(Self { checks, identities })
    }

    fn verify(&self) -> io::Result<()> {
        for identity in &self.identities {
            let metadata = identity.path.symlink_metadata()?;
            if metadata.dev() != identity.device || metadata.ino() != identity.inode {
                return Err(refused("kernel file identity no longer matches"));
            }
        }
        Ok(())
    }
}

struct PendingDecision {
    path: String,
    operation: FsOperation,
    action: &'static str,
    decision: policy::Decision,
}

#[derive(Default)]
struct Tracker {
    sequence: Option<u64>,
    pending: Vec<PendingDecision>,
    refusal: Option<String>,
    failed: bool,
    allowed: u64,
    denied: u64,
    notifications: u64,
}

impl Tracker {
    fn sequence(&mut self, next: u64) -> bool {
        let valid = self
            .sequence
            .is_none_or(|last| last.checked_add(1) == Some(next));
        self.sequence = Some(next);
        valid
    }
}

struct Context {
    engine: Arc<PolicyEngine>,
    recorder: Arc<DecisionRecorder>,
    governed: GovernedBox,
    resolver: PathResolver,
    fatal: tokio::sync::mpsc::UnboundedSender<crate::error::BoxError>,
    tracker: Mutex<Tracker>,
}

impl Context {
    fn diagnostic(&self, event: &RawEvent, origin: &str, reason: &str) {
        let reported = |bytes: &[u8; 4096]| {
            path(bytes).ok().map(|value| {
                self.resolver
                    .approve_host_entry(&value)
                    .map(|approved| approved.reported().into_owned())
                    .unwrap_or_else(|_| value.display().to_string())
            })
        };
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string();
        eprintln!(
            "MACOS_FILE_DIAGNOSTIC {}",
            serde_json::json!({
                "version": 1, "time_unix_ns": timestamp,
                "event": match event.kind {
                    OPEN => "open", CREATE => "create", UNLINK => "unlink",
                    RENAME => "rename", TRUNCATE => "truncate", _ => "unknown",
                },
                "sequence": event.sequence, "pid": event.pid, "flags": event.flags,
                "origin": origin, "verdict": "deny", "reason": reason,
                "path": reported(&event.path), "destination": reported(&event.destination),
            })
        );
    }

    fn failed(&self, tracker: &mut Tracker, error: NativeFilesystemError) {
        tracker.failed = true;
        let _ = self.fatal.send(error.into());
    }

    fn decide(&self, event: &RawEvent, pending: &mut Vec<PendingDecision>) -> io::Result<()> {
        let plan = Plan::decode(event)?;
        plan.verify()?;
        for check in &plan.checks {
            let approved = if check.entry {
                self.resolver.approve_host_entry(&check.path)
            } else {
                self.resolver.approve_host(&check.path)
            }
            .map_err(io::Error::other)?;
            let decision = self.engine.decide(
                &self.governed,
                &Principal::agent(),
                &Request::Fs {
                    path: &approved,
                    operation: check.operation,
                },
            );
            let allowed = decision.is_allow();
            pending.push(PendingDecision {
                path: approved.reported().into_owned(),
                operation: check.operation,
                action: check.action,
                decision,
            });
            if !allowed {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    PolicyRefusal,
                ));
            }
        }
        plan.verify()?;
        Ok(())
    }

    fn receive(&self, event: &RawEvent, status: i32) -> bool {
        let mut tracker = self.tracker.lock().unwrap_or_else(|e| e.into_inner());
        if event.phase == REPLY {
            if status != 0 {
                self.failed(&mut tracker, NativeFilesystemError::Reply);
            }
            let allowed = status == 0 && event.result == 1 && tracker.refusal.is_none();
            let refusal = tracker
                .refusal
                .take()
                .unwrap_or_else(|| "the kernel reply did not authorize this operation".to_string());
            let pending = std::mem::take(&mut tracker.pending);
            if pending.is_empty() && !allowed {
                let action = match event.kind {
                    OPEN => "fs:read",
                    UNLINK => "fs:delete",
                    RENAME => "fs:move",
                    _ => "fs:write",
                };
                let resource = path(&event.path)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "invalid kernel path".into());
                self.recorder.record(EffectiveDecision::enforcement_deny(
                    action,
                    resource,
                    "native-filesystem-policy",
                    &refusal,
                ));
            }
            for pending in pending {
                self.recorder
                    .record(if allowed || !pending.decision.is_allow() {
                        EffectiveDecision::from_policy(
                            pending.action,
                            &pending.path,
                            &pending.decision,
                        )
                    } else {
                        EffectiveDecision::enforcement_deny(
                            pending.action,
                            &pending.path,
                            "native-filesystem-policy",
                            &refusal,
                        )
                    });
                if allowed
                    && let Err(error) = self.engine.record(
                        &self.governed,
                        &Principal::agent(),
                        &Outcome::Fs {
                            path: Path::new(&pending.path),
                            operation: pending.operation,
                            result: FsResult::Indeterminate,
                        },
                    )
                {
                    self.failed(
                        &mut tracker,
                        NativeFilesystemError::Outcome { source: error },
                    );
                }
            }
            return false;
        }
        if !tracker.sequence(event.sequence) {
            self.failed(&mut tracker, NativeFilesystemError::Sequence);
        }
        if event.phase == NOTIFY {
            tracker.notifications += 1;
            return false;
        }
        tracker.pending.clear();
        tracker.refusal = None;
        if tracker.failed {
            tracker.denied += 1;
            tracker.refusal = Some("monitor failed before authorization".into());
            self.diagnostic(event, "adapter", "monitor failed before authorization");
            return false;
        }
        match self.decide(event, &mut tracker.pending) {
            Ok(()) => {
                tracker.allowed += 1;
                true
            }
            Err(error) => {
                tracker.refusal = Some(error.to_string());
                tracker.denied += 1;
                self.diagnostic(
                    event,
                    if error
                        .get_ref()
                        .is_some_and(|inner| inner.is::<PolicyRefusal>())
                    {
                        "dogwood"
                    } else {
                        "adapter"
                    },
                    &error.to_string(),
                );
                eprintln!(
                    "macOS file request denied: event={}, pid={}, supervisor={}, path={:?}: {error}",
                    event.kind,
                    event.pid,
                    std::process::id(),
                    path(&event.path).ok()
                );
                false
            }
        }
    }
}

unsafe extern "C" fn receive(context: *mut c_void, event: *const RawEvent, status: i32) -> bool {
    // SAFETY: the bridge calls synchronously with a live Context and stack-owned RawEvent.
    let context = unsafe { &*context.cast::<Context>() };
    let event = unsafe { &*event };
    if status == 4 {
        let _ = context.fatal.send(NativeFilesystemError::Tracking.into());
        return false;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.receive(event, status)
    }))
    .unwrap_or_else(|_| {
        let mut tracker = context.tracker.lock().unwrap_or_else(|e| e.into_inner());
        context.failed(&mut tracker, NativeFilesystemError::Panic);
        false
    })
}

struct Client(*mut c_void);
// SAFETY: Registration serializes access; FileMonitor drains callbacks before freeing the client.
unsafe impl Send for Client {}

#[derive(Clone)]
pub(crate) struct Registration(Arc<Mutex<Client>>);

impl Registration {
    pub(crate) fn prepare_bootstrap(&self, executable: &std::fs::File) -> io::Result<()> {
        let identity = executable.metadata()?;
        let client = self
            .0
            .lock()
            .map_err(|_| io::Error::other("native client lock failed"))?;
        // SAFETY: the lock excludes shutdown; the file is the verified private helper image.
        if client.0.is_null()
            || !unsafe { box_es_prepare_bootstrap(client.0, identity.dev(), identity.ino()) }
        {
            return Err(io::Error::other("native bootstrap identity refused"));
        }
        Ok(())
    }

    pub(crate) fn set_mode(&self, pid: i32, mediated: bool) -> io::Result<()> {
        let client = self
            .0
            .lock()
            .map_err(|_| io::Error::other("native client lock failed"))?;
        // SAFETY: the lock excludes client shutdown; the owned child waits at its launch gate.
        if client.0.is_null() || !unsafe { box_es_set_process_mode(client.0, pid, mediated) } {
            return Err(io::Error::other(
                "native filesystem process registration failed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct FileMonitor {
    registration: Registration,
    context: Option<Box<Context>>,
}

// SAFETY: Apple supports cross-thread client use. Drop exclusively drains this owned client.
unsafe impl Send for FileMonitor {}

impl FileMonitor {
    pub(crate) fn start(
        engine: Arc<PolicyEngine>,
        recorder: Arc<DecisionRecorder>,
        name: &str,
        home: &Path,
        fatal: tokio::sync::mpsc::UnboundedSender<crate::error::BoxError>,
    ) -> Result<Self, NativeFilesystemError> {
        let mut context = Box::new(Context {
            engine,
            recorder,
            governed: GovernedBox::assigned(name),
            resolver: PathResolver::over([PathBuf::from("/")])
                .map_err(|source| NativeFilesystemError::Paths { source })?
                .reporting_under(home),
            fatal,
            tracker: Mutex::new(Tracker::default()),
        });
        let mut error = 0;
        // SAFETY: the Box's address is stable until the bridge drains and deletes the client.
        let (device, inode) = parent_identity()?;
        let client = unsafe {
            box_es_start(
                (&mut *context as *mut Context).cast(),
                receive,
                &mut error,
                device,
                inode,
            )
        };
        if client.is_null() {
            return Err(startup_error(error));
        }
        eprintln!(
            "macOS file enforcement ready: five filesystem authorization events; deadline failures deny"
        );
        Ok(Self {
            registration: Registration(Arc::new(Mutex::new(Client(client)))),
            context: Some(context),
        })
    }
}

fn startup_error(code: i32) -> NativeFilesystemError {
    match code {
        -1 => NativeFilesystemError::Runtime,
        -2 => NativeFilesystemError::Allocation,
        -3 => NativeFilesystemError::Deadlines,
        -4 => NativeFilesystemError::Subscriptions,
        -5 => NativeFilesystemError::Sdk,
        -6 => NativeFilesystemError::Muting,
        -7 => NativeFilesystemError::ExistingChildren,
        code => NativeFilesystemError::Client { code },
    }
}

pub(crate) fn preflight() -> Result<(), NativeFilesystemError> {
    unsafe extern "C" fn refuse(_: *mut c_void, _: *const RawEvent, _: i32) -> bool {
        false
    }
    let mut error = 0;
    let (device, inode) = parent_identity()?;
    // SAFETY: this preflight callback borrows no context and always refuses authorization.
    let client = unsafe { box_es_start(std::ptr::null_mut(), refuse, &mut error, device, inode) };
    if client.is_null() {
        return Err(startup_error(error));
    }
    // SAFETY: no other owner can access this preflight client.
    let code = unsafe { box_es_stop(client) };
    if code == 0 {
        Ok(())
    } else {
        Err(NativeFilesystemError::Shutdown { code })
    }
}

fn parent_identity() -> Result<(u64, u64), NativeFilesystemError> {
    let identity = std::env::current_exe()
        .and_then(std::fs::metadata)
        .map_err(|source| NativeFilesystemError::BootstrapIdentity { source })?;
    Ok((identity.dev(), identity.ino()))
}

impl FileMonitor {
    pub(crate) fn registration(&self) -> Registration {
        self.registration.clone()
    }

    pub(crate) fn stop(&mut self) -> Result<(), NativeFilesystemError> {
        let mut client = self
            .registration
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if client.0.is_null() {
            return Ok(());
        }
        // SAFETY: the bridge retains the client and callback storage on incomplete shutdown.
        let code = unsafe { box_es_stop(client.0) };
        client.0 = std::ptr::null_mut();
        if let Some(context) = self.context.take()
            && code != 0
        {
            Box::leak(context);
        }
        if code == 0 {
            Ok(())
        } else {
            Err(NativeFilesystemError::Shutdown { code })
        }
    }
}

impl Drop for FileMonitor {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("{error}");
        }
    }
}

#[cfg(test)]
mod tests;
