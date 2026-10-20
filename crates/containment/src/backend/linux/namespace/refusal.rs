//! The seccomp notification path: what the workload hands the box, and what the box answers.
//!
//! The box only ever refuses. [`refusal_response`] is the one response builder, and it takes no
//! value a caller could use to continue a call or report a success.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::syscall::{MEDIATED, WORKLOAD_PERMITTED};
use crate::ContainmentError;

/// The tag on the message carrying the listener.
const OBSERVED: u8 = b'O';
/// The tag on the message saying the install fell back, followed by the errno.
const UNOBSERVED: u8 = b'U';

/// One refused call, as the kernel reports it to the listener.
#[derive(Debug, Clone, Copy)]
pub struct Notification {
    /// The kernel's cookie for this notification.
    pub id: u64,
    /// The caller's pid in the reader's PID namespace; 0 when it has none there.
    pub pid: u32,
    /// The syscall number.
    pub syscall: i64,
    /// The six raw argument registers.
    pub args: [u64; 6],
}

/// What [`Listener::next`] found.
#[derive(Debug)]
pub enum Next {
    /// A refused call is waiting for its answer.
    Notification(Notification),
    /// Nothing arrived within the timeout, or the caller went away before it could be read.
    Idle,
    /// No task is left under the filter.
    Ended,
}

/// The receiving end of one observed filter.
#[derive(Debug)]
pub struct Listener(pub(crate) OwnedFd);

impl Listener {
    /// Take ownership of a listener received from the workload.
    #[must_use]
    pub fn from_fd(descriptor: OwnedFd) -> Self {
        Self(descriptor)
    }

    /// Wait up to `timeout` for the next refused call.
    pub fn next(&self, timeout: Duration) -> std::io::Result<Next> {
        let mut poll = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one pollfd on the stack.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(Next::Idle)
            } else {
                Err(error)
            };
        }
        if ready == 0 {
            return Ok(Next::Idle);
        }
        if poll.revents & libc::POLLIN == 0 && poll.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(Next::Ended);
        }
        // SAFETY: the kernel requires a zeroed buffer; `seccomp_notif` is plain data.
        let mut notification: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: the ioctl writes one `seccomp_notif` into the buffer above.
        let received = unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut notification,
            )
        };
        if received < 0 {
            let error = std::io::Error::last_os_error();
            // ENOENT: the caller died between poll and receive. EINTR: retry on the next call.
            return match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::EINTR) => Ok(Next::Idle),
                _ => Err(error),
            };
        }
        let mut args = [0u64; 6];
        args.copy_from_slice(&notification.data.args);
        Ok(Next::Notification(Notification {
            id: notification.id,
            pid: notification.pid,
            syscall: i64::from(notification.data.nr),
            args,
        }))
    }

    /// Whether `id` still names a waiting call, so what was read about its caller is current.
    #[must_use]
    pub fn still_valid(&self, id: u64) -> bool {
        let mut cookie = id;
        // SAFETY: the ioctl reads one u64.
        unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &mut cookie,
            ) == 0
        }
    }

    /// Answer `id` with `EPERM`, the answer the filter gave before notifications existed.
    pub fn refuse(&self, id: u64) -> std::io::Result<()> {
        let mut response = refusal_response(id);
        // SAFETY: the ioctl reads one `seccomp_notif_resp`.
        if unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &mut response,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The one response this crate builds: refuse with `EPERM`, never continue.
pub(crate) fn refusal_response(id: u64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    }
}

/// A refused call in an operator's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The syscall's name, or `syscall_<nr>` when Box's tables do not name it.
    pub syscall: String,
    /// The decoded scalars an argument-scoped rule reads; `None` for any other call.
    pub arguments: Option<String>,
}

/// Describe one refused call from its number and raw arguments, without reading workload memory.
#[must_use]
pub fn describe(syscall: i64, args: &[u64; 6]) -> Description {
    let name = WORKLOAD_PERMITTED
        .iter()
        .map(|e| (e.number, e.name))
        .chain(MEDIATED.iter().map(|e| (e.number, e.name)))
        .find(|(number, _)| *number == syscall)
        .map_or_else(
            || format!("syscall_{syscall}"),
            |(_, name)| name.to_string(),
        );
    Description {
        syscall: name,
        arguments: arguments(syscall, args),
    }
}

fn arguments(syscall: i64, a: &[u64; 6]) -> Option<String> {
    let nr = |n: libc::c_long| n == syscall;
    if nr(libc::SYS_socket) {
        return Some(format!(
            "family={} type={}",
            family(a[0]),
            socket_type(a[1])
        ));
    }
    if nr(libc::SYS_socketpair) {
        return Some(format!("family={}", family(a[0])));
    }
    if nr(libc::SYS_mmap) || nr(libc::SYS_mprotect) || nr(libc::SYS_pkey_mprotect) {
        return Some(format!("prot={}", protection(a[2])));
    }
    if nr(libc::SYS_execveat) {
        return Some(format!("flags={}", at_flags(a[4])));
    }
    if nr(libc::SYS_setpgid) {
        return Some(format!("pid={} pgid={}", a[0] as i32, a[1] as i32));
    }
    if nr(libc::SYS_setresuid) || nr(libc::SYS_setresgid) {
        return Some(format!(
            "ids={},{},{}",
            a[0] as u32, a[1] as u32, a[2] as u32
        ));
    }
    None
}

fn family(value: u64) -> String {
    let name = match value as i32 {
        libc::AF_UNIX => "AF_UNIX",
        libc::AF_INET => "AF_INET",
        libc::AF_INET6 => "AF_INET6",
        libc::AF_NETLINK => "AF_NETLINK",
        libc::AF_PACKET => "AF_PACKET",
        libc::AF_VSOCK => "AF_VSOCK",
        libc::AF_BLUETOOTH => "AF_BLUETOOTH",
        libc::AF_ALG => "AF_ALG",
        libc::AF_KEY => "AF_KEY",
        libc::AF_XDP => "AF_XDP",
        libc::AF_CAN => "AF_CAN",
        libc::AF_TIPC => "AF_TIPC",
        _ => return (value as i32).to_string(),
    };
    name.to_string()
}

fn socket_type(value: u64) -> String {
    // SOCK_NONBLOCK and SOCK_CLOEXEC ride the same word; the type is the low nibble. Any other bit
    // makes the kernel refuse the call itself, so the raw number is the honest spelling.
    let flags = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;
    if value & !(0xf | flags) != 0 {
        return (value as i32).to_string();
    }
    let name = match (value as i32) & 0xf {
        libc::SOCK_STREAM => "SOCK_STREAM",
        libc::SOCK_DGRAM => "SOCK_DGRAM",
        libc::SOCK_RAW => "SOCK_RAW",
        libc::SOCK_SEQPACKET => "SOCK_SEQPACKET",
        libc::SOCK_RDM => "SOCK_RDM",
        _ => return (value as i32).to_string(),
    };
    name.to_string()
}

fn protection(value: u64) -> String {
    let named: Vec<&str> = [
        (libc::PROT_READ, "PROT_READ"),
        (libc::PROT_WRITE, "PROT_WRITE"),
        (libc::PROT_EXEC, "PROT_EXEC"),
    ]
    .iter()
    .filter(|(bit, _)| value & *bit as u64 != 0)
    .map(|(_, name)| *name)
    .collect();
    if named.is_empty() {
        "PROT_NONE".to_string()
    } else {
        named.join("|")
    }
}

fn at_flags(value: u64) -> String {
    let named: Vec<&str> = [
        (libc::AT_EMPTY_PATH, "AT_EMPTY_PATH"),
        (libc::AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"),
    ]
    .iter()
    .filter(|(bit, _)| value & *bit as u64 != 0)
    .map(|(_, name)| *name)
    .collect();
    if named.is_empty() {
        value.to_string()
    } else {
        named.join("|")
    }
}

/// The errno name an install failure carries, for the stderr line. Formats without allocating,
/// so PID 1 can write it after the fork.
pub(crate) struct ErrnoName(pub(crate) i32);

impl std::fmt::Display for ErrnoName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.0 {
            libc::EBUSY => "EBUSY",
            libc::EINVAL => "EINVAL",
            libc::ENOSYS => "ENOSYS",
            libc::EACCES => "EACCES",
            libc::EFAULT => "EFAULT",
            libc::ENOMEM => "ENOMEM",
            libc::EPERM => "EPERM",
            other => return write!(f, "errno_{other}"),
        };
        f.write_str(name)
    }
}

/// Hand the listener to the box. The caller closes its own copy right after.
pub(crate) fn send_observed(
    control: &UnixStream,
    listener: &OwnedFd,
) -> Result<(), ContainmentError> {
    super::netns::send_tagged_descriptor(control, listener, OBSERVED)
}

/// Tell the box this launch fell back, and why.
pub(crate) fn send_unobserved(control: &UnixStream, errno: i32) -> Result<(), ContainmentError> {
    use std::io::Write as _;
    let mut message = [UNOBSERVED, 0, 0, 0, 0];
    message[1..].copy_from_slice(&errno.to_ne_bytes());
    (&*control)
        .write_all(&message)
        .map_err(|source| ContainmentError::ApplyFailed {
            backend: super::MECHANISM.to_string(),
            reason: format!("telling the box seccomp refusals are not observed: {source}"),
        })
}

/// The sync protocol between PID 1 and the workload, five bytes a message (a tag and an `i32`):
///
/// 0. workload → PID 1: `R` (ready: its capabilities are dropped, so PID 1, which holds none,
///    passes the kernel's capability-subset check on it).
/// 1. PID 1 → workload: `G` (go: PID 1 just copied a descriptor out of the workload, so it can copy
///    the listener) or `N errno` (it cannot; install the refusing pair).
/// 2. workload → PID 1, after `G`: `L fd` (the observed filter is installed, listener at `fd`) or
///    `U errno` (the kernel refused the observed install; the refusing pair is installed).
/// 3. PID 1 → workload, after `L`: `Y` (the box has the listener) or `N errno`.
const READY: u8 = b'R';
const GO: u8 = b'G';
const LISTENING: u8 = b'L';
const FORWARDED: u8 = b'Y';
const NOT_FORWARDED: u8 = b'N';

/// The socket pair PID 1 and the workload talk over, `(PID 1's end, the workload's end)`.
/// Created by PID 1 before it forks the workload; both ends are close-on-exec.
pub(crate) fn sync_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut pair = [0 as libc::c_int; 2];
    // SAFETY: socketpair writes two descriptors into `pair`.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

/// Write one five-byte message: a tag and a native-endian `i32`. Uses `write` only, which the
/// workload's filter permits.
fn write_message(socket: &OwnedFd, tag: u8, value: i32) -> bool {
    let mut message = [tag, 0, 0, 0, 0];
    message[1..].copy_from_slice(&value.to_ne_bytes());
    // SAFETY: writing five bytes from the stack.
    let written =
        unsafe { libc::write(socket.as_raw_fd(), message.as_ptr().cast(), message.len()) };
    written == message.len() as isize
}

/// Read one five-byte message, or `None` on EOF or error. Uses `read` only.
fn read_message(socket: &OwnedFd) -> Option<(u8, i32)> {
    let mut message = [0u8; 5];
    let mut filled = 0;
    while filled < message.len() {
        // SAFETY: reading into the unfilled tail of a stack buffer.
        let read = unsafe {
            libc::read(
                socket.as_raw_fd(),
                message[filled..].as_mut_ptr().cast(),
                message.len() - filled,
            )
        };
        if read <= 0 {
            if read < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return None;
        }
        filled += read as usize;
    }
    let mut value = [0u8; 4];
    value.copy_from_slice(&message[1..]);
    Some((message[0], i32::from_ne_bytes(value)))
}

/// What the workload should install, as PID 1 answered step 1.
pub(crate) enum Plan {
    /// Install the observed filter and announce its listener.
    Observe,
    /// Install the refusing pair only; PID 1 has already told the box why.
    Refuse,
    /// PID 1 is gone or broke the protocol: refuse the apply.
    Broken,
}

/// The workload's steps 0 and 1: say it is ready, then wait for PID 1's check. Call it after the
/// workload drops its capabilities.
pub(crate) fn await_plan(sync: &OwnedFd) -> Plan {
    if !write_message(sync, READY, 0) {
        return Plan::Broken;
    }
    match read_message(sync) {
        Some((GO, _)) => Plan::Observe,
        Some((NOT_FORWARDED, _)) => Plan::Refuse,
        _ => Plan::Broken,
    }
}

/// The workload's step 2 with a listener: name it, and wait for PID 1's answer. `true` only when
/// the box now holds the listener.
pub(crate) fn announce_listener(sync: &OwnedFd, listener: &OwnedFd) -> bool {
    if !write_message(sync, LISTENING, listener.as_raw_fd()) {
        return false;
    }
    matches!(read_message(sync), Some((FORWARDED, _)))
}

/// The workload's step 2 when the kernel refused the observed install. Best effort: the refusing
/// filters are already installed.
pub(crate) fn announce_unobserved(sync: &OwnedFd, errno: i32) {
    let _ = write_message(sync, UNOBSERVED, errno);
}

/// PID 1's half. `workload_sync` is the workload's end of `sync` by number, which PID 1 copies out
/// of the workload first: the same operation, on a descriptor that exists now, is the check that
/// it will be able to copy the listener. Never answers a notification.
pub(crate) fn forward_listener(
    workload: libc::pid_t,
    sync: &OwnedFd,
    workload_sync: libc::c_int,
    handoff: libc::c_int,
) {
    // SAFETY: PID 1 owns this descriptor and closes it after this call; ManuallyDrop leaves it open.
    let control = std::mem::ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(handoff) });
    if !matches!(read_message(sync), Some((READY, _))) {
        return;
    }
    if let Err(errno) = copy_descriptor(workload, workload_sync) {
        let _ = write_message(sync, NOT_FORWARDED, errno);
        warn_unobserved(errno);
        let _ = send_unobserved(&control, errno);
        return;
    }
    if !write_message(sync, GO, 0) {
        return;
    }
    match read_message(sync) {
        Some((LISTENING, number)) => match copy_descriptor(workload, number).and_then(|copy| {
            // A copy that cannot reach the box is closed here, unread.
            send_observed(&control, &copy).map_err(|_| libc::EPIPE)
        }) {
            Ok(()) => {
                let _ = write_message(sync, FORWARDED, 0);
            }
            Err(errno) => {
                // The workload refuses its apply on this answer: its filter is installed and can
                // no longer be stacked over.
                eprintln!(
                    "strands-box: namespace reaper could not hand the seccomp listener to the box: {}",
                    ErrnoName(errno)
                );
                let _ = write_message(sync, NOT_FORWARDED, errno);
            }
        },
        Some((UNOBSERVED, errno)) => {
            warn_unobserved(errno);
            let _ = send_unobserved(&control, errno);
        }
        // The workload exited, or wrote something this protocol does not have: nothing to forward.
        _ => {}
    }
}

/// The one stderr line a fallback writes.
fn warn_unobserved(errno: i32) {
    eprintln!(
        "strands-box-contain-trampoline: warning: seccomp refusals are not observed: {}",
        ErrnoName(errno)
    );
}

/// A copy of descriptor `number` in process `pid`, through a pidfd. PID 1 is the workload's parent
/// in the same user namespace, so the kernel's ptrace-access check passes unless the host's
/// policy (Yama scope 2 or higher) refuses it.
fn copy_descriptor(pid: libc::pid_t, number: i32) -> Result<OwnedFd, i32> {
    let errno = || {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    };
    // SAFETY: pidfd_open with a pid and no flags.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        return Err(errno());
    }
    // SAFETY: the kernel returned a new descriptor this process owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    // SAFETY: pidfd_getfd with an owned pidfd, a descriptor number, and no flags.
    let copy = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), number, 0) };
    if copy < 0 {
        return Err(errno());
    }
    // SAFETY: the kernel returned a new close-on-exec descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(copy as i32) })
}

/// What the workload handed over on `control` after the netns listeners: the listener, the
/// fallback's errno, or nothing (it never reached the install, or this launch has no box).
pub fn receive_handoff(control: &UnixStream) -> std::io::Result<Handoff> {
    let mut payload = [0u8; 5];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut space = [0u64; 4];
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut io,
        msg_iovlen: 1,
        msg_control: space.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&space),
        msg_flags: 0,
    };
    // SAFETY: every pointer in `message` refers to a local that outlives the call.
    let received =
        unsafe { libc::recvmsg(control.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if received == 0 {
        return Ok(Handoff::Absent);
    }
    match payload[0] {
        OBSERVED => {
            // SAFETY: reading back the control message the kernel just wrote.
            let descriptor = unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                if header.is_null()
                    || (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    return Err(std::io::Error::other(
                        "the observed handoff carried no descriptor",
                    ));
                }
                std::ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>())
            };
            // SAFETY: SCM_RIGHTS installed a fresh descriptor this process now owns.
            Ok(Handoff::Observed(Listener(unsafe {
                OwnedFd::from_raw_fd(descriptor)
            })))
        }
        UNOBSERVED => {
            use std::io::Read as _;
            let mut errno = [0u8; 4];
            (&*control).read_exact(&mut errno)?;
            Ok(Handoff::Unobserved {
                errno: i32::from_ne_bytes(errno),
            })
        }
        other => Err(std::io::Error::other(format!(
            "unknown handoff tag {other:#x}"
        ))),
    }
}

/// What one launch's workload handed over.
#[derive(Debug)]
pub enum Handoff {
    /// The observed filter is installed; refusals arrive here.
    Observed(Listener),
    /// The install fell back to the refusing filters, for this errno.
    Unobserved {
        /// The errno the observed install failed with.
        errno: i32,
    },
    /// Nothing arrived before the peer closed.
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **P2: the only response this crate can build refuses.** No argument reaches `val`,
    /// `error`, or `flags`, so no caller can continue a call or fake a success.
    #[test]
    fn the_response_always_refuses_with_eperm() {
        for id in [0, 1, u64::MAX] {
            let response = refusal_response(id);
            assert_eq!(response.id, id);
            assert_eq!(response.error, -libc::EPERM);
            assert_eq!(response.val, 0);
            assert_eq!(response.flags, 0);
        }
    }

    #[test]
    fn a_socket_refusal_names_its_family_and_type() {
        let d = describe(
            libc::SYS_socket,
            &[
                libc::AF_PACKET as u64,
                libc::SOCK_RAW as u64 | libc::SOCK_CLOEXEC as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(d.syscall, "socket");
        assert_eq!(
            d.arguments.as_deref(),
            Some("family=AF_PACKET type=SOCK_RAW")
        );
    }

    #[test]
    fn each_argument_scoped_refusal_decodes_its_scalars() {
        let wx = (libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        assert_eq!(
            describe(libc::SYS_mmap, &[0, 4096, wx, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("prot=PROT_WRITE|PROT_EXEC")
        );
        assert_eq!(
            describe(
                libc::SYS_mprotect,
                &[0, 4096, libc::PROT_EXEC as u64, 0, 0, 0]
            )
            .arguments
            .as_deref(),
            Some("prot=PROT_EXEC")
        );
        assert_eq!(
            describe(
                libc::SYS_execveat,
                &[3, 0, 0, 0, libc::AT_EMPTY_PATH as u64, 0]
            )
            .arguments
            .as_deref(),
            Some("flags=AT_EMPTY_PATH")
        );
        assert_eq!(
            describe(libc::SYS_socketpair, &[libc::AF_INET as u64, 1, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("family=AF_INET")
        );
        assert_eq!(
            describe(libc::SYS_setpgid, &[0, 7, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("pid=0 pgid=7")
        );
        assert_eq!(
            describe(libc::SYS_setresuid, &[1000, 0, u32::MAX as u64, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("ids=1000,0,4294967295")
        );
    }

    #[test]
    fn an_unknown_value_is_printed_as_a_number_and_an_unlisted_call_carries_no_arguments() {
        assert_eq!(
            describe(libc::SYS_socket, &[99, 99, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("family=99 type=99")
        );
        let bpf = describe(libc::SYS_bpf, &[0; 6]);
        assert_eq!(bpf.syscall, "bpf");
        assert_eq!(bpf.arguments, None);
        assert_eq!(describe(100_000, &[0; 6]).syscall, "syscall_100000");
    }

    #[test]
    fn the_handoff_round_trips_both_outcomes_and_eof() {
        use std::os::fd::AsRawFd as _;
        let (box_side, child_side) = UnixStream::pair().expect("pair");
        let sample = OwnedFd::from(std::fs::File::open("/dev/null").expect("dev null"));
        send_observed(&child_side, &sample).expect("send observed");
        send_unobserved(&child_side, libc::EBUSY).expect("send unobserved");
        drop(child_side);
        match receive_handoff(&box_side).expect("first") {
            Handoff::Observed(listener) => assert!(listener.0.as_raw_fd() >= 0),
            _ => panic!("first message is the descriptor"),
        }
        assert!(
            matches!(receive_handoff(&box_side).expect("second"), Handoff::Unobserved { errno } if errno == libc::EBUSY)
        );
        assert!(matches!(
            receive_handoff(&box_side).expect("eof"),
            Handoff::Absent
        ));
    }

    #[test]
    fn errno_names_cover_the_install_failures() {
        assert_eq!(ErrnoName(libc::EBUSY).to_string(), "EBUSY");
        assert_eq!(ErrnoName(libc::EINVAL).to_string(), "EINVAL");
        assert_eq!(ErrnoName(libc::ENOSYS).to_string(), "ENOSYS");
        assert_eq!(ErrnoName(libc::EACCES).to_string(), "EACCES");
        assert_eq!(ErrnoName(libc::EFAULT).to_string(), "EFAULT");
        // An unknown errno is written as its number, with nothing allocated after the fork.
        assert_eq!(ErrnoName(12345).to_string(), "errno_12345");
    }
}
