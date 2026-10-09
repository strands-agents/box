//! The static seccomp filter the namespace launcher installs before `exec`.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::error::ContainmentError;
use crate::model::Network;

use super::MECHANISM;

/// How this backend treats one syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Refused for every invocation, whatever its arguments.
    Deny,
    /// Refused for some arguments only. The rule carries the condition, so a
    /// permitted invocation falls through to the mismatch action.
    ArgumentScoped,
}

/// One syscall this backend takes an explicit position on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MediatedSyscall {
    /// The syscall's name, for diagnostics and for the completeness test's message.
    pub(crate) name: &'static str,
    /// Its number on the target architecture, from `libc`'s own table.
    pub(crate) number: libc::c_long,
    pub(crate) disposition: Disposition,
    /// Why this syscall is mediated.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) reason: &'static str,
}

/// One syscall permitted for the workload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PermittedSyscall {
    pub(crate) name: &'static str,
    pub(crate) number: libc::c_long,
}

/// Why a syscall that only one architecture numbers is permitted.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(all(test, target_arch = "x86_64")), allow(dead_code))]
pub(crate) enum ArchBasis {
    /// A legacy spelling of this shared permit, which reaches nothing the shared permit does not.
    Twin(&'static str),
    /// No shared permit has the same effect, so the entry states why it is safe.
    Exception(&'static str),
}

/// One syscall permitted on one architecture only.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ArchPermittedSyscall {
    pub(crate) name: &'static str,
    pub(crate) number: libc::c_long,
    #[cfg_attr(not(all(test, target_arch = "x86_64")), allow(dead_code))]
    pub(crate) basis: ArchBasis,
}

/// `fchmodat2`, which `libc` numbers on x86-64 and not on ARM64.
const FCHMODAT2: libc::c_long = 452;

pub(crate) const WORKLOAD_PERMITTED: &[PermittedSyscall] = &[
    PermittedSyscall {
        name: "getcwd",
        number: libc::SYS_getcwd,
    },
    PermittedSyscall {
        name: "eventfd2",
        number: libc::SYS_eventfd2,
    },
    PermittedSyscall {
        name: "epoll_create1",
        number: libc::SYS_epoll_create1,
    },
    // uSockets arms its event loop with a timerfd, and a permit table answers an unlisted call
    // with `EPERM`. `us_create_timer` reads that refusal as an allocation failure, returns null,
    // and Bun panics before the workload runs. The three spellings are the whole interface to a
    // descriptor the caller already owns, which reaches no path and no other process.
    PermittedSyscall {
        name: "timerfd_create",
        number: libc::SYS_timerfd_create,
    },
    PermittedSyscall {
        name: "timerfd_settime",
        number: libc::SYS_timerfd_settime,
    },
    PermittedSyscall {
        name: "timerfd_gettime",
        number: libc::SYS_timerfd_gettime,
    },
    PermittedSyscall {
        name: "epoll_ctl",
        number: libc::SYS_epoll_ctl,
    },
    PermittedSyscall {
        name: "epoll_pwait",
        number: libc::SYS_epoll_pwait,
    },
    PermittedSyscall {
        name: "dup",
        number: libc::SYS_dup,
    },
    PermittedSyscall {
        name: "dup3",
        number: libc::SYS_dup3,
    },
    PermittedSyscall {
        name: "fcntl",
        number: libc::SYS_fcntl,
    },
    PermittedSyscall {
        name: "flock",
        number: libc::SYS_flock,
    },
    PermittedSyscall {
        name: "pipe2",
        number: libc::SYS_pipe2,
    },
    PermittedSyscall {
        name: "inotify_init1",
        number: libc::SYS_inotify_init1,
    },
    PermittedSyscall {
        name: "inotify_add_watch",
        number: libc::SYS_inotify_add_watch,
    },
    PermittedSyscall {
        name: "inotify_rm_watch",
        number: libc::SYS_inotify_rm_watch,
    },
    PermittedSyscall {
        name: "ioctl",
        number: libc::SYS_ioctl,
    },
    PermittedSyscall {
        name: "mkdirat",
        number: libc::SYS_mkdirat,
    },
    PermittedSyscall {
        name: "unlinkat",
        number: libc::SYS_unlinkat,
    },
    PermittedSyscall {
        name: "symlinkat",
        number: libc::SYS_symlinkat,
    },
    PermittedSyscall {
        name: "renameat",
        number: libc::SYS_renameat,
    },
    PermittedSyscall {
        name: "ftruncate",
        number: libc::SYS_ftruncate,
    },
    PermittedSyscall {
        name: "faccessat",
        number: libc::SYS_faccessat,
    },
    PermittedSyscall {
        name: "faccessat2",
        number: libc::SYS_faccessat2,
    },
    PermittedSyscall {
        name: "chdir",
        number: libc::SYS_chdir,
    },
    PermittedSyscall {
        name: "fchmod",
        number: libc::SYS_fchmod,
    },
    PermittedSyscall {
        name: "fchmodat",
        number: libc::SYS_fchmodat,
    },
    // Kernel 6.6 added `fchmodat2`, and a permit table answers an unlisted call with `EPERM` rather
    // than `ENOSYS`. A glibc that tries the newer call first would read that refusal as a real
    // failure instead of falling back, so the newer spelling is permitted beside the older two.
    PermittedSyscall {
        name: "fchmodat2",
        number: FCHMODAT2,
    },
    // `umask` has no failing return in its C wrapper, so a refusal reads as a mask of every bit.
    // pip reads the mask before it installs a wheel that carries an executable entry, and a linker
    // asks for it to decide which execute bits its own output may carry.
    PermittedSyscall {
        name: "umask",
        number: libc::SYS_umask,
    },
    PermittedSyscall {
        name: "openat",
        number: libc::SYS_openat,
    },
    PermittedSyscall {
        name: "close",
        number: libc::SYS_close,
    },
    PermittedSyscall {
        name: "getdents64",
        number: libc::SYS_getdents64,
    },
    PermittedSyscall {
        name: "lseek",
        number: libc::SYS_lseek,
    },
    PermittedSyscall {
        name: "read",
        number: libc::SYS_read,
    },
    PermittedSyscall {
        name: "write",
        number: libc::SYS_write,
    },
    PermittedSyscall {
        name: "writev",
        number: libc::SYS_writev,
    },
    PermittedSyscall {
        name: "pread64",
        number: libc::SYS_pread64,
    },
    PermittedSyscall {
        name: "pwrite64",
        number: libc::SYS_pwrite64,
    },
    PermittedSyscall {
        name: "ppoll",
        number: libc::SYS_ppoll,
    },
    PermittedSyscall {
        name: "readlinkat",
        number: libc::SYS_readlinkat,
    },
    PermittedSyscall {
        name: "newfstatat",
        number: libc::SYS_newfstatat,
    },
    PermittedSyscall {
        name: "fstat",
        number: libc::SYS_fstat,
    },
    PermittedSyscall {
        name: "fsync",
        number: libc::SYS_fsync,
    },
    PermittedSyscall {
        name: "fdatasync",
        number: libc::SYS_fdatasync,
    },
    PermittedSyscall {
        name: "utimensat",
        number: libc::SYS_utimensat,
    },
    PermittedSyscall {
        name: "exit",
        number: libc::SYS_exit,
    },
    PermittedSyscall {
        name: "exit_group",
        number: libc::SYS_exit_group,
    },
    PermittedSyscall {
        name: "set_tid_address",
        number: libc::SYS_set_tid_address,
    },
    PermittedSyscall {
        name: "futex",
        number: libc::SYS_futex,
    },
    PermittedSyscall {
        name: "set_robust_list",
        number: libc::SYS_set_robust_list,
    },
    PermittedSyscall {
        name: "getrusage",
        number: libc::SYS_getrusage,
    },
    PermittedSyscall {
        name: "clock_gettime",
        number: libc::SYS_clock_gettime,
    },
    PermittedSyscall {
        name: "clock_nanosleep",
        number: libc::SYS_clock_nanosleep,
    },
    PermittedSyscall {
        name: "sched_setscheduler",
        number: libc::SYS_sched_setscheduler,
    },
    PermittedSyscall {
        name: "sched_getaffinity",
        number: libc::SYS_sched_getaffinity,
    },
    PermittedSyscall {
        name: "sched_yield",
        number: libc::SYS_sched_yield,
    },
    PermittedSyscall {
        name: "restart_syscall",
        number: libc::SYS_restart_syscall,
    },
    PermittedSyscall {
        name: "sigaltstack",
        number: libc::SYS_sigaltstack,
    },
    PermittedSyscall {
        name: "rt_sigaction",
        number: libc::SYS_rt_sigaction,
    },
    PermittedSyscall {
        name: "rt_sigprocmask",
        number: libc::SYS_rt_sigprocmask,
    },
    PermittedSyscall {
        name: "rt_sigreturn",
        number: libc::SYS_rt_sigreturn,
    },
    // Without this a workload cannot signal even itself: `raise` and `abort` are `tgkill`, and
    // JavaScriptCore suspends its own threads for a GC pass the same way, so Bun reports
    // "embedder failed to suspend thread" and stalls. The PID namespace is what bounds its
    // reach -- a thread the workload cannot see is a thread it cannot signal.
    PermittedSyscall {
        name: "tgkill",
        number: libc::SYS_tgkill,
    },
    PermittedSyscall {
        name: "setsid",
        number: libc::SYS_setsid,
    },
    PermittedSyscall {
        name: "setpgid",
        number: libc::SYS_setpgid,
    },
    PermittedSyscall {
        name: "getpgid",
        number: libc::SYS_getpgid,
    },
    PermittedSyscall {
        name: "uname",
        number: libc::SYS_uname,
    },
    PermittedSyscall {
        name: "prctl",
        number: libc::SYS_prctl,
    },
    PermittedSyscall {
        name: "getpid",
        number: libc::SYS_getpid,
    },
    PermittedSyscall {
        name: "getppid",
        number: libc::SYS_getppid,
    },
    PermittedSyscall {
        name: "getuid",
        number: libc::SYS_getuid,
    },
    PermittedSyscall {
        name: "geteuid",
        number: libc::SYS_geteuid,
    },
    PermittedSyscall {
        name: "getgid",
        number: libc::SYS_getgid,
    },
    PermittedSyscall {
        name: "getegid",
        number: libc::SYS_getegid,
    },
    PermittedSyscall {
        name: "getgroups",
        number: libc::SYS_getgroups,
    },
    PermittedSyscall {
        name: "gettid",
        number: libc::SYS_gettid,
    },
    PermittedSyscall {
        name: "sysinfo",
        number: libc::SYS_sysinfo,
    },
    PermittedSyscall {
        name: "socket",
        number: libc::SYS_socket,
    },
    PermittedSyscall {
        name: "socketpair",
        number: libc::SYS_socketpair,
    },
    PermittedSyscall {
        name: "connect",
        number: libc::SYS_connect,
    },
    PermittedSyscall {
        name: "bind",
        number: libc::SYS_bind,
    },
    PermittedSyscall {
        name: "listen",
        number: libc::SYS_listen,
    },
    PermittedSyscall {
        name: "accept",
        number: libc::SYS_accept,
    },
    PermittedSyscall {
        name: "accept4",
        number: libc::SYS_accept4,
    },
    PermittedSyscall {
        name: "getsockname",
        number: libc::SYS_getsockname,
    },
    PermittedSyscall {
        name: "getpeername",
        number: libc::SYS_getpeername,
    },
    PermittedSyscall {
        name: "sendto",
        number: libc::SYS_sendto,
    },
    PermittedSyscall {
        name: "recvfrom",
        number: libc::SYS_recvfrom,
    },
    PermittedSyscall {
        name: "setsockopt",
        number: libc::SYS_setsockopt,
    },
    PermittedSyscall {
        name: "getsockopt",
        number: libc::SYS_getsockopt,
    },
    PermittedSyscall {
        name: "shutdown",
        number: libc::SYS_shutdown,
    },
    PermittedSyscall {
        name: "brk",
        number: libc::SYS_brk,
    },
    PermittedSyscall {
        name: "munmap",
        number: libc::SYS_munmap,
    },
    PermittedSyscall {
        name: "clone",
        number: libc::SYS_clone,
    },
    PermittedSyscall {
        name: "execve",
        number: libc::SYS_execve,
    },
    PermittedSyscall {
        name: "mmap",
        number: libc::SYS_mmap,
    },
    PermittedSyscall {
        name: "mprotect",
        number: libc::SYS_mprotect,
    },
    PermittedSyscall {
        name: "madvise",
        number: libc::SYS_madvise,
    },
    PermittedSyscall {
        name: "wait4",
        number: libc::SYS_wait4,
    },
    PermittedSyscall {
        name: "prlimit64",
        number: libc::SYS_prlimit64,
    },
    PermittedSyscall {
        name: "getrandom",
        number: libc::SYS_getrandom,
    },
    PermittedSyscall {
        name: "statx",
        number: libc::SYS_statx,
    },
    PermittedSyscall {
        name: "rseq",
        number: libc::SYS_rseq,
    },
    PermittedSyscall {
        name: "pidfd_open",
        number: libc::SYS_pidfd_open,
    },
    PermittedSyscall {
        name: "close_range",
        number: libc::SYS_close_range,
    },
    PermittedSyscall {
        name: "epoll_pwait2",
        number: libc::SYS_epoll_pwait2,
    },
    PermittedSyscall {
        name: "clone3",
        number: libc::SYS_clone3,
    },
    PermittedSyscall {
        name: "unshare",
        number: libc::SYS_unshare,
    },
    PermittedSyscall {
        name: "setns",
        number: libc::SYS_setns,
    },
    PermittedSyscall {
        name: "umount2",
        number: libc::SYS_umount2,
    },
    PermittedSyscall {
        name: "pivot_root",
        number: libc::SYS_pivot_root,
    },
    PermittedSyscall {
        name: "chroot",
        number: libc::SYS_chroot,
    },
];

/// The permits only this architecture needs.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const ARCH_PERMITTED: &[ArchPermittedSyscall] = &[];

/// The permits only this architecture needs, for the reason that
/// `docs/design/decisions.md#the-linux-boundary-is-namespaces-not-landlock` states.
#[cfg(target_arch = "x86_64")]
pub(crate) const ARCH_PERMITTED: &[ArchPermittedSyscall] = &[
    ArchPermittedSyscall {
        name: "open",
        number: libc::SYS_open,
        basis: ArchBasis::Twin("openat"),
    },
    ArchPermittedSyscall {
        name: "creat",
        number: libc::SYS_creat,
        basis: ArchBasis::Twin("openat"),
    },
    ArchPermittedSyscall {
        name: "stat",
        number: libc::SYS_stat,
        basis: ArchBasis::Twin("newfstatat"),
    },
    ArchPermittedSyscall {
        name: "lstat",
        number: libc::SYS_lstat,
        basis: ArchBasis::Twin("newfstatat"),
    },
    ArchPermittedSyscall {
        name: "access",
        number: libc::SYS_access,
        basis: ArchBasis::Twin("faccessat"),
    },
    ArchPermittedSyscall {
        name: "readlink",
        number: libc::SYS_readlink,
        basis: ArchBasis::Twin("readlinkat"),
    },
    ArchPermittedSyscall {
        name: "getdents",
        number: libc::SYS_getdents,
        basis: ArchBasis::Twin("getdents64"),
    },
    ArchPermittedSyscall {
        name: "rename",
        number: libc::SYS_rename,
        basis: ArchBasis::Twin("renameat"),
    },
    ArchPermittedSyscall {
        name: "unlink",
        number: libc::SYS_unlink,
        basis: ArchBasis::Twin("unlinkat"),
    },
    ArchPermittedSyscall {
        name: "rmdir",
        number: libc::SYS_rmdir,
        basis: ArchBasis::Twin("unlinkat"),
    },
    ArchPermittedSyscall {
        name: "mkdir",
        number: libc::SYS_mkdir,
        basis: ArchBasis::Twin("mkdirat"),
    },
    ArchPermittedSyscall {
        name: "chmod",
        number: libc::SYS_chmod,
        basis: ArchBasis::Twin("fchmodat"),
    },
    ArchPermittedSyscall {
        name: "symlink",
        number: libc::SYS_symlink,
        basis: ArchBasis::Twin("symlinkat"),
    },
    ArchPermittedSyscall {
        name: "utime",
        number: libc::SYS_utime,
        basis: ArchBasis::Twin("utimensat"),
    },
    ArchPermittedSyscall {
        name: "utimes",
        number: libc::SYS_utimes,
        basis: ArchBasis::Twin("utimensat"),
    },
    ArchPermittedSyscall {
        name: "futimesat",
        number: libc::SYS_futimesat,
        basis: ArchBasis::Twin("utimensat"),
    },
    ArchPermittedSyscall {
        name: "poll",
        number: libc::SYS_poll,
        basis: ArchBasis::Twin("ppoll"),
    },
    // `pause` waits for a signal, which `ppoll` with no descriptor and no timeout also does.
    ArchPermittedSyscall {
        name: "pause",
        number: libc::SYS_pause,
        basis: ArchBasis::Twin("ppoll"),
    },
    ArchPermittedSyscall {
        name: "epoll_wait",
        number: libc::SYS_epoll_wait,
        basis: ArchBasis::Twin("epoll_pwait"),
    },
    ArchPermittedSyscall {
        name: "epoll_create",
        number: libc::SYS_epoll_create,
        basis: ArchBasis::Twin("epoll_create1"),
    },
    ArchPermittedSyscall {
        name: "eventfd",
        number: libc::SYS_eventfd,
        basis: ArchBasis::Twin("eventfd2"),
    },
    ArchPermittedSyscall {
        name: "inotify_init",
        number: libc::SYS_inotify_init,
        basis: ArchBasis::Twin("inotify_init1"),
    },
    ArchPermittedSyscall {
        name: "pipe",
        number: libc::SYS_pipe,
        basis: ArchBasis::Twin("pipe2"),
    },
    ArchPermittedSyscall {
        name: "dup2",
        number: libc::SYS_dup2,
        basis: ArchBasis::Twin("dup3"),
    },
    ArchPermittedSyscall {
        name: "fork",
        number: libc::SYS_fork,
        basis: ArchBasis::Twin("clone"),
    },
    ArchPermittedSyscall {
        name: "vfork",
        number: libc::SYS_vfork,
        basis: ArchBasis::Twin("clone"),
    },
    ArchPermittedSyscall {
        name: "time",
        number: libc::SYS_time,
        basis: ArchBasis::Twin("clock_gettime"),
    },
    ArchPermittedSyscall {
        name: "getpgrp",
        number: libc::SYS_getpgrp,
        basis: ArchBasis::Twin("getpgid"),
    },
    ArchPermittedSyscall {
        name: "arch_prctl",
        number: libc::SYS_arch_prctl,
        basis: ArchBasis::Exception(
            "glibc sets thread-local storage and the shadow stack with it, and AMX code requests \
             its register state with it; every subcommand changes only the calling process, and \
             none reaches a path, a socket, another process, a filter, or a namespace",
        ),
    },
];

/// Every syscall the namespace launcher mediates.
pub(crate) const MEDIATED: &[MediatedSyscall] = &[
    // --- W^X: an executable image the mount view cannot govern --------------- The mount view's
    // authority is PRESENCE, and a `noexec` writable bind closes exec of a file the workload wrote.
    MediatedSyscall {
        name: "memfd_create",
        number: libc::SYS_memfd_create,
        disposition: Disposition::Deny,
        reason: "an anonymous in-memory image has no path, so neither the mount view \
                 nor a noexec bind can govern executing it",
    },
    // `execveat` is argument-scoped, not denied outright: the flag is what makes it an fd-exec.
    MediatedSyscall {
        name: "execveat",
        number: libc::SYS_execveat,
        disposition: Disposition::ArgumentScoped,
        reason: "execveat with AT_EMPTY_PATH execs an inherited descriptor rather than \
                 a path, so the mount view never sees the bytes that run",
    },
    // Route 3 of W^X: writable memory becoming executable.
    MediatedSyscall {
        name: "mmap",
        number: libc::SYS_mmap,
        disposition: Disposition::ArgumentScoped,
        reason: "a mapping that is writable and executable at once is attacker-authored \
                 code the mount view cannot govern",
    },
    MediatedSyscall {
        name: "mprotect",
        number: libc::SYS_mprotect,
        disposition: Disposition::ArgumentScoped,
        reason: "adding PROT_EXEC turns a page the workload has already written into \
                 code, which is route 3 of W^X",
    },
    // `pkey_mprotect` reaches the same effect with a protection key argument, so denying only
    // `mprotect` would be the same shape of fail-open that denying only `mount` and only `unshare`
    // each turned out to be.
    MediatedSyscall {
        name: "pkey_mprotect",
        number: libc::SYS_pkey_mprotect,
        disposition: Disposition::ArgumentScoped,
        reason: "pkey_mprotect adds PROT_EXEC exactly as mprotect does, and denying only \
                 mprotect would leave the same route open under a second spelling",
    },
    // The new mount API reaches the same effect as `mount(2)` without calling it.
    MediatedSyscall {
        name: "fsopen",
        number: 430,
        disposition: Disposition::Deny,
        reason: "opens a filesystem context, the first step of a mount that never \
                 calls mount(2)",
    },
    MediatedSyscall {
        name: "fsconfig",
        number: 431,
        disposition: Disposition::Deny,
        reason: "configures and creates a superblock for that context",
    },
    MediatedSyscall {
        name: "fsmount",
        number: 432,
        disposition: Disposition::Deny,
        reason: "turns a configured superblock into an attachable mount",
    },
    MediatedSyscall {
        name: "move_mount",
        number: 429,
        disposition: Disposition::Deny,
        reason: "attaches a mount into the namespace, completing the bypass",
    },
    MediatedSyscall {
        name: "open_tree",
        number: 428,
        disposition: Disposition::Deny,
        reason: "clones a mount tree, which move_mount can then attach elsewhere",
    },
    MediatedSyscall {
        name: "fspick",
        number: 433,
        disposition: Disposition::Deny,
        reason: "picks an existing superblock for reconfiguration",
    },
    MediatedSyscall {
        name: "mount_setattr",
        number: 442,
        disposition: Disposition::Deny,
        reason: "changes mount attributes, so a read-only bind could be made \
                 writable; absent on 5.10 but named so a newer kernel is covered",
    },
    // KNOWN GAP: `open_tree_attr` (467, kernel >= 6.15) clones a mount and sets
    // attributes in one call, and is not in this table — the pinned libc 0.2.189
    // exports `SYS_open_tree_attr` for no supported arch, and a hand-written
    // number is against this crate's rule. Two backstops hold meanwhile: every
    // capability set is cleared and `no_new_privs` is set, so the whole mount
    // API returns `EPERM`. Add the entry when libc carries the constant.
    // Privilege and identity surfaces the namespaces do not close.
    MediatedSyscall {
        name: "setuid",
        number: libc::SYS_setuid,
        disposition: Disposition::Deny,
        reason: "the workload's identity is fixed; changing it inside the user \
                 namespace confuses every uid-shaped audit record",
    },
    MediatedSyscall {
        name: "setgid",
        number: libc::SYS_setgid,
        disposition: Disposition::Deny,
        reason: "the group counterpart of setuid",
    },
    MediatedSyscall {
        name: "setpgid",
        number: libc::SYS_setpgid,
        disposition: Disposition::ArgumentScoped,
        reason: "moving the workload or its children between process groups would \
                 complicate signal cleanup",
    },
    MediatedSyscall {
        name: "pidfd_getfd",
        number: 438,
        disposition: Disposition::Deny,
        reason: "steals a descriptor from another process, which would defeat the \
                 inherited-descriptor close",
    },
    MediatedSyscall {
        name: "open_by_handle_at",
        number: libc::SYS_open_by_handle_at,
        disposition: Disposition::Deny,
        reason: "opens a file by handle rather than by path, so the mount view's \
                 pathname boundary does not apply",
    },
    MediatedSyscall {
        name: "kexec_load",
        number: libc::SYS_kexec_load,
        disposition: Disposition::Deny,
        reason: "replaces the running kernel, which is outside every boundary here",
    },
    MediatedSyscall {
        name: "seccomp",
        number: libc::SYS_seccomp,
        disposition: Disposition::Deny,
        reason: "installing a further filter cannot loosen this one, but a notify \
                 listener would let the workload mediate its own descendants",
    },
    MediatedSyscall {
        name: "mount",
        number: libc::SYS_mount,
        disposition: Disposition::Deny,
        reason: "a mount would add a path the grants never authorized",
    },
    // --- Reaching another process's memory or execution ---------------------
    MediatedSyscall {
        name: "ptrace",
        number: libc::SYS_ptrace,
        disposition: Disposition::Deny,
        reason: "tracing a sibling reads and writes its memory, including secrets",
    },
    MediatedSyscall {
        name: "process_vm_readv",
        number: libc::SYS_process_vm_readv,
        disposition: Disposition::Deny,
        reason: "reads another process's address space without ptrace",
    },
    MediatedSyscall {
        name: "process_vm_writev",
        number: libc::SYS_process_vm_writev,
        disposition: Disposition::Deny,
        reason: "writes another process's address space without ptrace",
    },
    MediatedSyscall {
        name: "perf_event_open",
        number: libc::SYS_perf_event_open,
        disposition: Disposition::Deny,
        reason: "a side channel onto other processes, and a large kernel surface",
    },
    MediatedSyscall {
        name: "userfaultfd",
        number: libc::SYS_userfaultfd,
        disposition: Disposition::Deny,
        reason: "userspace fault handling is a standard exploitation primitive",
    },
    // --- Kernel-programming and key surfaces --------------------------------
    MediatedSyscall {
        name: "bpf",
        number: libc::SYS_bpf,
        disposition: Disposition::Deny,
        reason: "loading a program into the kernel is not the workload's to do",
    },
    MediatedSyscall {
        name: "init_module",
        number: libc::SYS_init_module,
        disposition: Disposition::Deny,
        reason: "a module runs in the kernel, outside every boundary here",
    },
    MediatedSyscall {
        name: "finit_module",
        number: libc::SYS_finit_module,
        disposition: Disposition::Deny,
        reason: "the descriptor-based spelling of init_module",
    },
    MediatedSyscall {
        name: "delete_module",
        number: libc::SYS_delete_module,
        disposition: Disposition::Deny,
        reason: "removing a module changes the kernel the boundary relies on",
    },
    MediatedSyscall {
        name: "add_key",
        number: libc::SYS_add_key,
        disposition: Disposition::Deny,
        reason: "the keyring is shared state the box does not mediate",
    },
    MediatedSyscall {
        name: "request_key",
        number: libc::SYS_request_key,
        disposition: Disposition::Deny,
        reason: "reads keyring material the box does not mediate",
    },
    MediatedSyscall {
        name: "keyctl",
        number: libc::SYS_keyctl,
        disposition: Disposition::Deny,
        reason: "manipulates keyring state the box does not mediate",
    },
    // --- An I/O route that bypasses the syscalls above ----------------------- io_uring submits
    // file and socket operations through a shared ring, so an operation performed that way is not
    // the syscall a filter matched on.
    MediatedSyscall {
        name: "io_uring_setup",
        number: libc::SYS_io_uring_setup,
        disposition: Disposition::Deny,
        reason: "a ring issues socket operations without the syscalls filtered here",
    },
    // --- The network route, argument-scoped ---------------------------------
    MediatedSyscall {
        name: "socket",
        number: libc::SYS_socket,
        disposition: Disposition::ArgumentScoped,
        reason: "only AF_UNIX and AF_INET may be created",
    },
    MediatedSyscall {
        name: "socketpair",
        number: libc::SYS_socketpair,
        disposition: Disposition::ArgumentScoped,
        reason: "only AF_UNIX connected socket pairs may be created",
    },
];

/// The two filters for one containment request.
#[derive(Debug)]
pub(crate) struct SyscallFilters {
    pub(crate) permit: BpfProgram,
    pub(crate) restrictions: BpfProgram,
}

/// The static system-call policy for one containment request.
#[derive(Debug)]
pub(crate) struct SyscallPolicy;

impl SyscallPolicy {
    /// Derive the policy from one request.
    pub(crate) fn for_config(_network: &Network) -> Self {
        Self
    }

    /// Compile both filters before containment starts.
    pub(crate) fn compile(&self) -> Result<SyscallFilters, ContainmentError> {
        let permit_rules = build_permit_rules(WORKLOAD_PERMITTED, ARCH_PERMITTED, true)?;
        let permit = compile_filter(
            permit_rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
        )?;

        let mut rules: BTreeMap<libc::c_long, Vec<SeccompRule>> = BTreeMap::new();
        for entry in MEDIATED {
            match entry.disposition {
                Disposition::Deny => {
                    rules.insert(entry.number, Vec::new());
                }
                Disposition::ArgumentScoped => {
                    insert_scoped(&mut rules, entry.number, self.argument_scoped_rules(entry)?);
                }
            }
        }

        let restrictions = compile_filter(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
        )?;

        Ok(SyscallFilters {
            permit,
            restrictions,
        })
    }

    /// The rules for a syscall whose disposition depends on its arguments.
    fn argument_scoped_rules(
        &self,
        entry: &MediatedSyscall,
    ) -> Result<Vec<SeccompRule>, ContainmentError> {
        if entry.number == libc::SYS_socket {
            return self.socket_rules();
        }
        if entry.number == libc::SYS_socketpair {
            return unix_socketpair_rules();
        }
        if entry.number == libc::SYS_execveat {
            return execveat_rules();
        }
        if entry.number == libc::SYS_mmap {
            return write_execute_mmap_rules();
        }
        if entry.number == libc::SYS_mprotect || entry.number == libc::SYS_pkey_mprotect {
            return add_execute_rules();
        }
        if entry.number == libc::SYS_setpgid {
            return setpgid_rules();
        }
        Err(ContainmentError::ApplyFailed {
            backend: MECHANISM.to_string(),
            reason: format!(
                "no argument-scoped rule is defined for the mediated syscall '{}'; \
                 a table entry without a rule would enforce nothing",
                entry.name
            ),
        })
    }

    /// Refuse `socket()` for every family except `AF_UNIX` and `AF_INET`.
    fn socket_rules(&self) -> Result<Vec<SeccompRule>, ContainmentError> {
        Ok(vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AF_UNIX as u64,
                )
                .map_err(filter_error)?,
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AF_INET as u64,
                )
                .map_err(filter_error)?,
            ])
            .map_err(filter_error)?,
        ])
    }
}

fn unix_socketpair_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    Ok(vec![
        SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::AF_UNIX as u64,
            )
            .map_err(filter_error)?,
        ])
        .map_err(filter_error)?,
    ])
}

fn build_permit_rules(
    entries: &[PermittedSyscall],
    arch: &[ArchPermittedSyscall],
    include_installer: bool,
) -> Result<BTreeMap<libc::c_long, Vec<SeccompRule>>, ContainmentError> {
    let mut rules = BTreeMap::new();
    let shared = entries.iter().map(|entry| (entry.name, entry.number));
    let arch_only = arch.iter().map(|entry| (entry.name, entry.number));
    for (name, number) in shared.chain(arch_only) {
        if rules.insert(number, Vec::new()).is_some() {
            return Err(filter_error(format!(
                "duplicate permitted syscall '{name}' ({number})"
            )));
        }
    }
    insert_permitted_scoped(
        &mut rules,
        "setresuid",
        libc::SYS_setresuid,
        setresuid_rules()?,
    )?;
    insert_permitted_scoped(
        &mut rules,
        "setresgid",
        libc::SYS_setresgid,
        setresgid_rules()?,
    )?;
    if include_installer && rules.insert(libc::SYS_seccomp, Vec::new()).is_some() {
        return Err(filter_error(
            "installer-only seccomp duplicates a workload permit",
        ));
    }
    Ok(rules)
}

fn insert_permitted_scoped(
    rules: &mut BTreeMap<libc::c_long, Vec<SeccompRule>>,
    name: &str,
    number: libc::c_long,
    scoped: Vec<SeccompRule>,
) -> Result<(), ContainmentError> {
    if scoped.is_empty() {
        return Err(filter_error(format!(
            "permitted syscall '{name}' has no argument rule"
        )));
    }
    if rules.insert(number, scoped).is_some() {
        return Err(filter_error(format!(
            "duplicate permitted syscall '{name}' ({number})"
        )));
    }
    Ok(())
}

fn setresuid_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    exact_three_argument_rule(0)
}

fn setresgid_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    exact_three_argument_rule(u32::MAX as u64)
}

fn setpgid_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    (0..2)
        .map(|index| {
            SeccompRule::new(vec![
                SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0)
                    .map_err(filter_error)?,
            ])
            .map_err(filter_error)
        })
        .collect()
}

fn exact_three_argument_rule(value: u64) -> Result<Vec<SeccompRule>, ContainmentError> {
    let conditions = (0..3)
        .map(|index| {
            SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
                .map_err(filter_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![SeccompRule::new(conditions).map_err(filter_error)?])
}

fn compile_filter(
    rules: BTreeMap<libc::c_long, Vec<SeccompRule>>,
    mismatch_action: SeccompAction,
    match_action: SeccompAction,
) -> Result<BpfProgram, ContainmentError> {
    let filter = SeccompFilter::new(
        rules,
        mismatch_action,
        match_action,
        TargetArch::try_from(std::env::consts::ARCH).map_err(filter_error)?,
    )
    .map_err(filter_error)?;
    filter.try_into().map_err(filter_error)
}

/// Deny `execveat` only when it execs a descriptor instead of a path.
fn execveat_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    let mask = libc::AT_EMPTY_PATH as u64;
    Ok(vec![
        SeccompRule::new(vec![
            SeccompCondition::new(
                4,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(mask),
                mask,
            )
            .map_err(filter_error)?,
        ])
        .map_err(filter_error)?,
    ])
}

/// Deny `mmap` only when the mapping is writable **and** executable at once.
fn write_execute_mmap_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    let mask = (libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    Ok(vec![
        SeccompRule::new(vec![
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(mask),
                mask,
            )
            .map_err(filter_error)?,
        ])
        .map_err(filter_error)?,
    ])
}

/// Deny `mprotect`/`pkey_mprotect` when the new protection adds `PROT_EXEC`.
fn add_execute_rules() -> Result<Vec<SeccompRule>, ContainmentError> {
    let mask = libc::PROT_EXEC as u64;
    Ok(vec![
        SeccompRule::new(vec![
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(mask),
                mask,
            )
            .map_err(filter_error)?,
        ])
        .map_err(filter_error)?,
    ])
}

/// Insert an argument-scoped rule set, refusing to insert an empty one.
fn insert_scoped(
    rules: &mut BTreeMap<libc::c_long, Vec<SeccompRule>>,
    number: libc::c_long,
    scoped: Vec<SeccompRule>,
) {
    if scoped.is_empty() {
        return;
    }
    rules.insert(number, scoped);
}

/// Map a seccompiler error to this backend's apply failure.
fn filter_error(e: impl std::fmt::Display) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason: format!("compiling the namespace seccomp filter: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localhost() -> Network {
        Network::Localhost {
            connect: vec![8080],
            listen: Vec::new(),
        }
    }

    #[test]
    fn every_mediated_syscall_has_a_rule() {
        let filters = SyscallPolicy::for_config(&localhost())
            .compile()
            .expect("the shipped table must compile");
        for entry in MEDIATED {
            let number = u32::try_from(entry.number).expect("syscall numbers are small");
            assert!(
                filters
                    .restrictions
                    .iter()
                    .any(|instruction| instruction.k == number),
                "mediated syscall '{}' ({}) has no rule in the compiled filter, so it \
                 is unmediated despite being declared -- reason it is listed: {}",
                entry.name,
                entry.number,
                entry.reason,
            );
        }
    }

    #[test]
    fn permit_filter_has_111_workload_entries_and_one_installer_entry() {
        assert_eq!(WORKLOAD_PERMITTED.len(), 111);
        let rules = build_permit_rules(WORKLOAD_PERMITTED, ARCH_PERMITTED, true)
            .expect("the permit table must be unique");
        assert_eq!(rules.len(), 114 + ARCH_PERMITTED.len());
        assert!(rules.contains_key(&libc::SYS_seccomp));
        assert_eq!(rules[&libc::SYS_setresuid].len(), 1);
        assert_eq!(rules[&libc::SYS_setresgid].len(), 1);
        assert!(
            !WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.number == libc::SYS_seccomp)
        );
        assert!(
            !WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.number == libc::SYS_pkey_mprotect)
        );
    }

    #[test]
    fn the_file_mode_calls_and_the_creation_mask_are_permitted() {
        for required in ["fchmod", "fchmodat", "fchmodat2", "umask"] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required),
                "'{required}' must be permitted: a permit table answers an unlisted call with \
                 EPERM, and a caller that tries the newest spelling first would read that as a \
                 real failure instead of falling back"
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn duplicate_permit_numbers_are_refused() {
        let duplicate = [
            PermittedSyscall {
                name: "first",
                number: libc::SYS_read,
            },
            PermittedSyscall {
                name: "second",
                number: libc::SYS_read,
            },
        ];
        build_permit_rules(&duplicate, &[], false).expect_err("a duplicate must fail");
    }

    #[test]
    fn an_arch_permit_that_repeats_a_shared_number_is_refused() {
        let shared = [PermittedSyscall {
            name: "read",
            number: libc::SYS_read,
        }];
        let arch = [ArchPermittedSyscall {
            name: "read-again",
            number: libc::SYS_read,
            basis: ArchBasis::Twin("read"),
        }];
        build_permit_rules(&shared, &arch, false).expect_err("a repeated number must fail");
    }

    #[test]
    fn no_permit_key_carries_the_x32_bit() {
        let rules = build_permit_rules(WORKLOAD_PERMITTED, ARCH_PERMITTED, true)
            .expect("the permit table must be unique");
        assert!(
            rules.keys().all(|number| number & 0x4000_0000 == 0),
            "a permit key with the x32 bit would open the x32 ABI, which shares AUDIT_ARCH_X86_64"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_x86_64_table_has_29_entries_and_the_permit_filter_143() {
        assert_eq!(ARCH_PERMITTED.len(), 29);
        let rules = build_permit_rules(WORKLOAD_PERMITTED, ARCH_PERMITTED, true)
            .expect("the permit table must be unique");
        assert_eq!(rules.len(), 143);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_x86_64_spelling_names_a_permitted_unmediated_twin() {
        for entry in ARCH_PERMITTED {
            let ArchBasis::Twin(twin) = entry.basis else {
                continue;
            };
            assert!(
                WORKLOAD_PERMITTED.iter().any(|shared| shared.name == twin),
                "'{}' is permitted as the twin of '{twin}', which the shared table does not permit",
                entry.name
            );
            assert!(
                !MEDIATED.iter().any(|mediated| mediated.name == twin),
                "'{}' is permitted as the twin of '{twin}', which is mediated",
                entry.name
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn arch_prctl_is_the_only_x86_64_exception() {
        let exceptions: Vec<(&str, &str)> = ARCH_PERMITTED
            .iter()
            .filter_map(|entry| match entry.basis {
                ArchBasis::Exception(reason) => Some((entry.name, reason)),
                ArchBasis::Twin(_) => None,
            })
            .collect();
        assert_eq!(exceptions.len(), 1, "exceptions: {exceptions:?}");
        assert_eq!(exceptions[0].0, "arch_prctl");
        assert!(
            exceptions[0].1.len() > 20,
            "the exception has no substantive reason"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_x86_64_kernel_programming_calls_stay_closed() {
        let rules = build_permit_rules(WORKLOAD_PERMITTED, ARCH_PERMITTED, true)
            .expect("the permit table must be unique");
        for (name, number) in [
            ("modify_ldt", libc::SYS_modify_ldt),
            ("iopl", libc::SYS_iopl),
            ("ioperm", libc::SYS_ioperm),
            ("uselib", libc::SYS_uselib),
        ] {
            assert!(!rules.contains_key(&number), "'{name}' must stay refused");
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn no_x86_64_spelling_collides_with_a_mediated_number() {
        for entry in ARCH_PERMITTED {
            assert!(
                !MEDIATED
                    .iter()
                    .any(|mediated| mediated.number == entry.number),
                "'{}' ({}) shares a number with a mediated syscall",
                entry.name,
                entry.number
            );
        }
    }

    #[test]
    fn every_mediated_syscall_states_its_reason() {
        for entry in MEDIATED {
            assert!(
                !entry.name.is_empty(),
                "a mediated syscall must be named for diagnostics"
            );
            assert!(
                entry.reason.len() > 20,
                "mediated syscall '{}' has no substantive reason",
                entry.name
            );
        }
    }

    #[test]
    fn the_mediated_table_has_no_duplicate_syscalls() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in MEDIATED {
            assert!(
                seen.insert(entry.number),
                "syscall '{}' ({}) is listed twice; the second entry would silently \
                 replace the first",
                entry.name,
                entry.number
            );
        }
    }

    #[test]
    fn the_syscalls_c_headers_omit_are_still_numbered_here() {
        assert_eq!(libc::SYS_io_uring_setup, 425, "ARM64 io_uring_setup");
        assert_eq!(libc::SYS_openat2, 437, "ARM64 openat2");
        assert_eq!(FCHMODAT2, 452, "the generic table numbers fchmodat2 at 452");
        assert!(
            MEDIATED
                .iter()
                .any(|entry| entry.number == libc::SYS_io_uring_setup),
            "io_uring_setup must be mediated: it is the route that issues socket \
             operations without calling socket(2)"
        );
    }

    #[test]
    fn every_network_mode_permits_only_unix_and_inet() {
        for network in [Network::Blocked, localhost(), Network::AllowAll] {
            let policy = SyscallPolicy::for_config(&network);
            let rules = policy.socket_rules().expect("socket rules compile");
            assert_eq!(rules.len(), 1);
            let filters = policy.compile().expect("filters compile");
            for family in [libc::AF_UNIX, libc::AF_INET] {
                let value = u32::try_from(family).expect("families are small");
                assert!(
                    filters
                        .restrictions
                        .iter()
                        .any(|instruction| instruction.k == value)
                );
            }
        }
    }

    #[test]
    fn socketpair_permits_only_unix() {
        let rules = unix_socketpair_rules().expect("socketpair rules compile");
        assert_eq!(rules.len(), 1);
        let filters = SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("filters compile");
        let socketpair_number = u32::try_from(libc::SYS_socketpair).expect("small");
        let unix_family = u32::try_from(libc::AF_UNIX).expect("small");
        assert!(
            filters
                .restrictions
                .iter()
                .any(|instruction| instruction.k == socketpair_number)
        );
        assert!(
            filters
                .restrictions
                .iter()
                .any(|instruction| instruction.k == unix_family)
        );
    }

    #[test]
    fn accepted_namespace_and_root_calls_are_permitted() {
        for required in [
            "clone",
            "clone3",
            "unshare",
            "setns",
            "umount2",
            "pivot_root",
            "chroot",
        ] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required)
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn accepted_signal_identity_and_access_queries_are_permitted() {
        for required in [
            "rt_sigreturn",
            "geteuid",
            "getgid",
            "getegid",
            "getgroups",
            "faccessat2",
        ] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required)
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn accepted_time_calls_are_permitted() {
        for required in ["clock_gettime", "clock_nanosleep"] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required)
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn resource_usage_of_self_is_permitted_and_unmediated() {
        assert!(
            WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.name == "getrusage" && entry.number == libc::SYS_getrusage)
        );
        assert!(!MEDIATED.iter().any(|entry| entry.name == "getrusage"));
        let filters = SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("filters compile");
        let number = u32::try_from(libc::SYS_getrusage).expect("syscall numbers are small");
        assert!(
            filters
                .permit
                .iter()
                .any(|instruction| instruction.k == number),
            "getrusage is absent from the compiled permit filter, so a Bun or Node \
             process asking for its own CPU time gets EPERM and exits at start"
        );
        assert!(
            !filters
                .restrictions
                .iter()
                .any(|instruction| instruction.k == number)
        );
    }

    #[test]
    fn event_loop_timers_are_permitted_and_unmediated() {
        for required in ["timerfd_create", "timerfd_settime", "timerfd_gettime"] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required),
                "'{required}' is absent from the permit table, so uSockets gets EPERM from \
                 timerfd_create, us_create_timer returns null, and Bun panics before the \
                 agent runs -- the same startup refusal getrusage already fixed once"
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
        let filters = SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("filters compile");
        for number in [
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
        ] {
            let number = u32::try_from(number).expect("syscall numbers are small");
            assert!(
                filters
                    .permit
                    .iter()
                    .any(|instruction| instruction.k == number)
            );
            assert!(
                !filters
                    .restrictions
                    .iter()
                    .any(|instruction| instruction.k == number)
            );
        }
    }

    #[test]
    fn descriptor_duplication_is_permitted_and_unmediated() {
        assert!(
            WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.name == "dup" && entry.number == libc::SYS_dup)
        );
        assert!(!MEDIATED.iter().any(|entry| entry.name == "dup"));
        let filters = SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("filters compile");
        let number = u32::try_from(libc::SYS_dup).expect("syscall numbers are small");
        assert!(
            filters
                .permit
                .iter()
                .any(|instruction| instruction.k == number),
            "dup is absent from the compiled permit filter, so CPython's is_valid_fd() gets EPERM \
             on every standard stream and sys.stdin, sys.stdout, and sys.stderr are None"
        );
    }

    #[test]
    fn file_mode_mask_is_permitted_and_unmediated() {
        assert!(
            WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.name == "umask" && entry.number == libc::SYS_umask)
        );
        assert!(!MEDIATED.iter().any(|entry| entry.name == "umask"));
        let filters = SyscallPolicy::for_config(&Network::Blocked)
            .compile()
            .expect("filters compile");
        let number = u32::try_from(libc::SYS_umask).expect("syscall numbers are small");
        assert!(
            filters
                .permit
                .iter()
                .any(|instruction| instruction.k == number),
            "umask is absent from the compiled permit filter, so pip's current_umask() fails and \
             no wheel with an executable entry installs"
        );
    }

    #[test]
    fn accepted_file_mutation_calls_are_permitted() {
        for required in ["pwrite64", "fdatasync", "symlinkat"] {
            assert!(
                WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required)
            );
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn accepted_file_lock_call_is_permitted() {
        assert!(WORKLOAD_PERMITTED.iter().any(|entry| entry.name == "flock"));
        assert!(!MEDIATED.iter().any(|entry| entry.name == "flock"));
    }

    #[test]
    fn accepted_process_group_call_is_argument_scoped() {
        assert!(
            WORKLOAD_PERMITTED
                .iter()
                .any(|entry| entry.name == "setpgid")
        );
        let mediated = MEDIATED
            .iter()
            .find(|entry| entry.name == "setpgid")
            .expect("setpgid must be mediated");
        assert_eq!(mediated.disposition, Disposition::ArgumentScoped);
        assert_eq!(setpgid_rules().expect("setpgid rules compile").len(), 2);
    }

    #[test]
    fn retained_mount_entry_points_are_refused() {
        for required in [
            "mount",
            "fsopen",
            "fsconfig",
            "fsmount",
            "move_mount",
            "open_tree",
            "fspick",
            "mount_setattr",
        ] {
            assert!(MEDIATED.iter().any(|entry| entry.name == required));
            assert!(
                !WORKLOAD_PERMITTED
                    .iter()
                    .any(|entry| entry.name == required)
            );
        }
    }

    #[test]
    fn accepted_namespace_calls_are_not_restricted() {
        for required in [
            "unshare",
            "clone",
            "clone3",
            "setns",
            "umount2",
            "pivot_root",
            "chroot",
        ] {
            assert!(!MEDIATED.iter().any(|entry| entry.name == required));
        }
    }

    #[test]
    fn an_argument_scoped_entry_without_a_rule_is_refused() {
        let policy = SyscallPolicy::for_config(&localhost());
        let bogus = MediatedSyscall {
            name: "fictional",
            number: libc::SYS_getpid,
            disposition: Disposition::ArgumentScoped,
            reason: "a synthetic entry standing in for a future mistake",
        };

        let error = policy
            .argument_scoped_rules(&bogus)
            .expect_err("an argument-scoped entry with no rule must be refused");

        assert!(
            matches!(error, ContainmentError::ApplyFailed { .. }),
            "got {error:?}"
        );
    }
}
