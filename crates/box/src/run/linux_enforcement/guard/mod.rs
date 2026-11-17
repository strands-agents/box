//! File identity approvals bound to the worker's kernel task.
mod btf;
mod program;

use std::cell::Cell;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::Arc;

unsafe extern "C" {
    fn box_guard_capabilities(effective: *mut u64) -> i32;
    fn box_guard_drop_capabilities() -> i32;
    fn box_guard_map() -> i32;
    fn box_guard_update(map: i32, task: i32, value: *const u64) -> i32;
    fn box_guard_delete(map: i32, task: i32) -> i32;
    fn box_guard_load(
        code: *const program::Instruction,
        count: u32,
        hook: u32,
        log: *mut u8,
        size: u32,
    ) -> i32;
    fn box_guard_attach(program: i32) -> i32;
}
fn checked(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
fn descriptor(result: i32) -> io::Result<OwnedFd> {
    Ok(unsafe { OwnedFd::from_raw_fd(checked(result)?) })
}
pub(crate) struct Guard {
    map: OwnedFd,
    _links: Vec<OwnedFd>,
}
pub(super) struct Worker {
    failed: Cell<bool>,
    guard: Arc<Guard>,
    task: OwnedFd,
    _thread: PhantomData<Rc<()>>,
}
impl Guard {
    pub(crate) fn prepare(enabled: bool) -> io::Result<Option<Arc<Self>>> {
        let mut effective = 0_u64;
        checked(unsafe { box_guard_capabilities(&mut effective) })?;
        let required = (1_u64 << 39) | (1_u64 << 38);
        let guard = if !enabled || effective & required == 0 {
            Ok(None)
        } else if effective & required != required {
            Err(io::Error::other(
                "native entry guard requires CAP_BPF and CAP_PERFMON together",
            ))
        } else {
            Self::load().map(Some)
        };
        checked(unsafe { box_guard_drop_capabilities() })?;
        guard
    }

    pub(super) fn load() -> io::Result<Arc<Self>> {
        let btf = btf::Btf::read()?;
        let map = descriptor(unsafe { box_guard_map() })?;
        let mut links = Vec::new();
        for (name, operation, arguments) in [
            ("bpf_lsm_inode_unlink", 1, 2),
            ("bpf_lsm_inode_rename", 2, 4),
            ("bpf_lsm_inode_rmdir", 3, 2),
        ] {
            let code = program::build(&btf, map.as_raw_fd(), operation)?;
            let mut log = vec![0_u8; 1024 * 1024];
            let loaded = unsafe {
                box_guard_load(
                    code.as_ptr(),
                    code.len() as u32,
                    btf.hook(name, arguments)?,
                    log.as_mut_ptr(),
                    log.len() as u32,
                )
            };
            let program = descriptor(loaded).map_err(|error| {
                let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
                io::Error::new(
                    error.kind(),
                    format!(
                        "entry guard {name}: {error}; {}",
                        String::from_utf8_lossy(&log[..end])
                    ),
                )
            })?;
            links.push(descriptor(unsafe {
                box_guard_attach(program.as_raw_fd())
            })?);
        }
        Ok(Arc::new(Self { map, _links: links }))
    }
    pub(super) fn register(self: &Arc<Self>) -> io::Result<Worker> {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let task =
            descriptor(unsafe { libc::syscall(libc::SYS_pidfd_open, tid, libc::O_EXCL) as i32 })?;
        checked(unsafe {
            box_guard_update(self.map.as_raw_fd(), task.as_raw_fd(), [0_u64; 10].as_ptr())
        })?;
        Ok(Worker {
            failed: Cell::new(false),
            guard: Arc::clone(self),
            task,
            _thread: PhantomData,
        })
    }
}
fn identity(file: &OwnedFd) -> io::Result<[u64; 2]> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    checked(unsafe { libc::fstat(file.as_raw_fd(), &mut stat) })?;
    let device = (libc::major(stat.st_dev) as u64) << 20 | libc::minor(stat.st_dev) as u64;
    Ok([stat.st_ino, device])
}
impl Worker {
    pub(super) fn check(&self) -> io::Result<()> {
        if self.failed.get() {
            Err(io::Error::other(
                "native entry guard could not clear its approval",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn effect<T>(
        &self,
        source_parent: &OwnedFd,
        source: &OwnedFd,
        destination: Option<(&OwnedFd, Option<&OwnedFd>)>,
        effect: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        self.check()?;
        let mut token = [0_u64; 10];
        token[0] = 1;
        let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
        checked(unsafe { libc::fstat(source.as_raw_fd(), &mut metadata) })?;
        token[1] = if destination.is_some() {
            2
        } else if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR {
            3
        } else {
            1
        };
        token[2..4].copy_from_slice(&identity(source_parent)?);
        token[4..6].copy_from_slice(&identity(source)?);
        if let Some((parent, object)) = destination {
            token[6..8].copy_from_slice(&identity(parent)?);
            if let Some(object) = object {
                token[8..10].copy_from_slice(&identity(object)?);
            }
        }
        checked(unsafe {
            box_guard_update(
                self.guard.map.as_raw_fd(),
                self.task.as_raw_fd(),
                token.as_ptr(),
            )
        })?;
        let result = effect();
        let cleared = super::fault::at("guard-reset").and_then(|()| {
            checked(unsafe {
                box_guard_update(
                    self.guard.map.as_raw_fd(),
                    self.task.as_raw_fd(),
                    [0_u64; 10].as_ptr(),
                )
            })
            .map(|_| ())
        });
        if cleared.is_err() {
            self.failed.set(true);
        }
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        unsafe {
            box_guard_delete(self.guard.map.as_raw_fd(), self.task.as_raw_fd());
        }
    }
}

#[cfg(all(test, box_native_kernel_tests))]
mod tests;
