//! Filesystem notifications with sanitized information queries and forwarded native policy requests.

use std::ffi::CString;
use std::io::{self, Read as _, Write as _};
use std::mem::{offset_of, size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const PATH_LIMIT: usize = 4096;
// The supported 64-bit Linux ABIs use the same layout; statfs64 exposes the flags field in libc.
const _: () = assert!(size_of::<libc::statfs>() == size_of::<libc::statfs64>());

/// Pin procfs with the original launcher's process-number view.
pub(super) fn open_proc() -> io::Result<OwnedFd> {
    // SAFETY: the literal is terminated and open returns a new descriptor.
    owned(unsafe {
        libc::open(
            c"/proc".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })
}

/// Install the notification filter and transfer its only listener before workload execution.
pub(super) fn install(program: &seccompiler::BpfProgram, control: &UnixStream) -> io::Result<()> {
    let listener = create_listener(program)?;
    send_listener(control, &listener, false)?;
    drop(listener);
    confirm_handoff(control)
}

pub(super) fn create_listener(program: &seccompiler::BpfProgram) -> io::Result<OwnedFd> {
    // SAFETY: zero initializes the kernel output structure.
    let mut sizes: libc::seccomp_notif_sizes = unsafe { zeroed() };
    // SAFETY: the kernel receives space for the structure selected by this operation.
    checked(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes,
        )
    })?;
    if usize::from(sizes.seccomp_notif) != size_of::<libc::seccomp_notif>()
        || usize::from(sizes.seccomp_notif_resp) != size_of::<libc::seccomp_notif_resp>()
        || usize::from(sizes.seccomp_data) != size_of::<libc::seccomp_data>()
    {
        return Err(io::Error::other(
            "unsupported filesystem notification layout",
        ));
    }
    let filter = libc::sock_fprog {
        len: program
            .len()
            .try_into()
            .map_err(|_| io::Error::other("notification filter length"))?,
        filter: program.as_ptr().cast_mut().cast(),
    };
    // SAFETY: the compiled filter's storage remains live during installation.
    let raw = checked(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &filter,
        )
    })?;
    // SAFETY: seccomp returned a new listener owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

pub(super) fn confirm_handoff(mut control: &UnixStream) -> io::Result<()> {
    control.set_read_timeout(Some(Duration::from_secs(5)))?;
    control.set_write_timeout(Some(Duration::from_secs(5)))?;
    control.write_all(&[1])?;
    let mut acknowledgment = [0];
    control.read_exact(&mut acknowledgment)?;
    if acknowledgment != [1] {
        return Err(io::Error::other("filesystem listener was not accepted"));
    }
    Ok(())
}

/// Serve the workload's filesystem queries while waiting for the existing namespace reaper.
pub(super) fn supervise(reaper: libc::pid_t, proc: OwnedFd, control: UnixStream) -> i32 {
    let registration = register_listener(&control);
    let (listener, native) = match registration {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("strands-box: filesystem query supervisor failed: {error}");
            if error.kind() == io::ErrorKind::UnexpectedEof {
                let code = wait_for_reaper(reaper);
                return if code == 0 { 125 } else { code };
            }
            return 125;
        }
    };
    match serve(reaper, &proc, &listener, native.then_some(&control)) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("strands-box: filesystem query supervisor failed: {error}");
            // The caller exits immediately; the reaper's parent-death signal terminates the namespace.
            125
        }
    }
}

/// Collect the namespace reaper's exit status without signaling a process.
pub(super) fn wait_for_reaper(reaper: libc::pid_t) -> i32 {
    super::reaper_exit_code(|status| {
        // SAFETY: waitpid can collect only this process's child and never sends a signal.
        checked(unsafe { libc::waitpid(reaper, status, 0) } as libc::c_long).map(|_| ())
    })
}

fn register_listener(control: &UnixStream) -> io::Result<(OwnedFd, bool)> {
    let (listener, native) = receive_listener(control)?;
    // A listener accepts ID_VALID and refuses the nonexistent request zero with ENOENT.
    match valid(listener.as_raw_fd(), 0) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        _ => return Err(io::Error::other("invalid filesystem notification listener")),
    }
    let mut peer = control;
    let mut closed = [0];
    peer.read_exact(&mut closed)?;
    if closed != [1] {
        return Err(io::Error::other("filesystem listener remains in workload"));
    }
    peer.write_all(&[1])?;
    Ok((listener, native))
}

fn serve(
    reaper: libc::pid_t,
    proc: &OwnedFd,
    listener: &OwnedFd,
    native: Option<&UnixStream>,
) -> io::Result<i32> {
    let own_pid = unsafe { libc::getpid() };
    let mut pending: Option<(&UnixStream, libc::seccomp_notif)> = None;
    loop {
        let mut status = 0;
        // SAFETY: waitpid observes only this launcher's child.
        let waited = unsafe { libc::waitpid(reaper, &mut status, libc::WNOHANG) };
        if waited == reaper {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                125
            });
        }
        if waited == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        // Keep at most one unsent request; leave further notifications in the kernel.
        // Poll only the blocked socket so queued notifications cannot cause a busy loop.
        let (fd, events) = match pending.as_ref() {
            Some((socket, _)) => (socket.as_raw_fd(), libc::POLLOUT),
            None => (listener.as_raw_fd(), libc::POLLIN),
        };
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll receives one initialized writable pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, 50) };
        if ready == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if poll.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other(
                "filesystem notification descriptor closed unexpectedly",
            ));
        }
        if let Some((socket, request)) = pending.as_ref() {
            if poll.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            if poll.revents & libc::POLLOUT != 0 {
                match forward_request(socket, request) {
                    Ok(()) => pending = None,
                    // Readiness does not reserve capacity; retain the same request on retry.
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            continue;
        }
        if poll.revents & libc::POLLIN == 0 {
            if poll.revents & libc::POLLHUP != 0 {
                // All filtered tasks exited; the reaper still owns the workload's exit status.
                return Ok(wait_for_reaper(reaper));
            }
            continue;
        }
        // SAFETY: the kernel requires the complete notification storage to start at zero.
        let mut request: libc::seccomp_notif = unsafe { zeroed() };
        // SAFETY: the request has the native ioctl layout and remains writable throughout the call.
        if unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut request,
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) {
                continue;
            }
            return Err(error);
        }
        if let Some(native) = native
            && request.pid != 0
            && request.pid != own_pid as u32
            && request.pid != reaper as u32
            && request.flags == 0
            && is_native_operation(request.data.nr)
        {
            match forward_request(native, &request) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    pending = Some((native, request));
                }
                Err(error) => return Err(error),
            }
            continue;
        }
        let result = if request.pid == 0
            || request.pid == own_pid as u32
            || request.pid == reaper as u32
            || request.data.nr != libc::SYS_statfs as i32
            || request.flags != 0
        {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        } else {
            answer(listener.as_raw_fd(), proc.as_raw_fd(), &request)
        };
        let response = libc::seccomp_notif_resp {
            id: request.id,
            val: 0,
            error: match result {
                Ok(()) => 0,
                Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
            },
            flags: 0,
        };
        finish_response(|| {
            // SAFETY: each retry sends the same initialized response; flags never request native continuation.
            checked(unsafe {
                libc::ioctl(
                    listener.as_raw_fd(),
                    libc::SECCOMP_IOCTL_NOTIF_SEND,
                    &response,
                )
            } as libc::c_long)
            .map(|_| ())
        })?;
    }
}

fn is_native_operation(number: i32) -> bool {
    #[cfg(all(feature = "native-filesystem-policy", box_native_adapter_tests))]
    {
        super::native_filesystem::OPERATIONS.contains(&(number as libc::c_long))
    }
    #[cfg(not(all(feature = "native-filesystem-policy", box_native_adapter_tests)))]
    {
        let _ = number;
        false
    }
}

/// Forward one fixed-size, little-endian request without waiting for policy evaluation.
fn forward_request(socket: &UnixStream, request: &libc::seccomp_notif) -> io::Result<()> {
    let mut bytes = [0_u8; 80];
    bytes[0..8].copy_from_slice(&request.id.to_le_bytes());
    bytes[8..12].copy_from_slice(&request.pid.to_le_bytes());
    bytes[12..16].copy_from_slice(&request.flags.to_le_bytes());
    bytes[16..20].copy_from_slice(&request.data.nr.to_le_bytes());
    bytes[20..24].copy_from_slice(&request.data.arch.to_le_bytes());
    bytes[24..32].copy_from_slice(&request.data.instruction_pointer.to_le_bytes());
    for (index, value) in request.data.args.iter().enumerate() {
        bytes[32 + index * 8..40 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    loop {
        // SAFETY: send reads the fixed frame; nonblocking operation bounds supervisor work.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent == bytes.len() as isize {
            return Ok(());
        }
        if sent == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Err(io::Error::other(
            "incomplete native filesystem request forwarding",
        ));
    }
}

fn finish_response(mut send: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    loop {
        match send() {
            Ok(()) => return Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn answer(listener: RawFd, proc: RawFd, request: &libc::seccomp_notif) -> io::Result<()> {
    valid(listener, request.id)?;
    let path = read_path(request)?;
    if path.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    if path[0] != b'/' {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let root_name = CString::new(format!("{}/root", request.pid)).expect("numeric process path");
    // SAFETY: proc is pinned before the PID namespace change; the terminated name contains only a kernel PID.
    let root = owned(unsafe {
        libc::openat(
            proc,
            root_name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    valid(listener, request.id)?;
    let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: zero initializes all open_how fields, including future reserved fields.
    let mut how: libc::open_how = unsafe { zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: openat2 resolves the copied name within the pinned target root, never the supervisor's root.
    let raw = checked(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            size_of::<libc::open_how>(),
        )
    })?;
    // SAFETY: openat2 returned a new descriptor owned here.
    let target = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
    // SAFETY: zero is valid for statfs; fstatfs initializes its public fields on success.
    let mut information: libc::statfs64 = unsafe { zeroed() };
    // SAFETY: target pins the resolved path and information is writable native statfs storage.
    checked(unsafe { libc::fstatfs64(target.as_raw_fd(), &mut information) } as libc::c_long)?;
    let bytes = sanitized(&information);
    valid(listener, request.id)?;
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: request.data.args[1] as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: the kernel validates the target mapping and enforces ptrace access within the private user namespace.
    let written = unsafe { libc::process_vm_writev(request.pid as i32, &local, 1, &remote, 1, 0) };
    if written == -1 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    valid(listener, request.id)
}

fn read_path(request: &libc::seccomp_notif) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; PATH_LIMIT];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: request.data.args[0] as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: the kernel validates the remote address; the local allocation spans the requested bytes.
    let read = unsafe { libc::process_vm_readv(request.pid as i32, &local, 1, &remote, 1, 0) };
    if read == -1 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(read as usize);
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::from_raw_os_error(if bytes.len() == PATH_LIMIT {
            libc::ENAMETOOLONG
        } else {
            libc::EFAULT
        })
    })?;
    bytes.truncate(end);
    Ok(bytes)
}

fn sanitized(information: &libc::statfs64) -> [u8; size_of::<libc::statfs64>()] {
    let mut bytes = [0_u8; size_of::<libc::statfs64>()];
    macro_rules! retain {
        ($field:ident) => {{
            let value = information.$field.to_ne_bytes();
            let start = offset_of!(libc::statfs64, $field);
            bytes[start..start + value.len()].copy_from_slice(&value);
        }};
    }
    retain!(f_type);
    retain!(f_bsize);
    retain!(f_frsize);
    retain!(f_namelen);
    retain!(f_flags);
    bytes
}

fn valid(listener: RawFd, id: u64) -> io::Result<()> {
    // SAFETY: ID_VALID reads one live request identifier.
    checked(
        unsafe { libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &id) } as libc::c_long,
    )
    .map(|_| ())
}

fn checked(result: libc::c_long) -> io::Result<libc::c_long> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn owned(raw: RawFd) -> io::Result<OwnedFd> {
    checked(raw as libc::c_long)?;
    // SAFETY: the successful open call transferred a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

pub(super) fn send_listener(
    control: &UnixStream,
    listener: &OwnedFd,
    native: bool,
) -> io::Result<()> {
    let byte = [if native { 2_u8 } else { 1_u8 }];
    let mut vector = libc::iovec {
        iov_base: byte.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0_usize; 4];
    // SAFETY: zero initializes the optional msghdr fields.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&ancillary);
    // SAFETY: aligned ancillary storage fits exactly one descriptor and its header.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        std::ptr::write(
            libc::CMSG_DATA(header).cast::<RawFd>(),
            listener.as_raw_fd(),
        );
        message.msg_controllen = (*header).cmsg_len;
        if checked(
            libc::sendmsg(control.as_raw_fd(), &message, libc::MSG_NOSIGNAL) as libc::c_long,
        )? != 1
        {
            return Err(io::Error::other("incomplete filesystem listener handoff"));
        }
    }
    Ok(())
}

fn receive_listener(control: &UnixStream) -> io::Result<(OwnedFd, bool)> {
    control.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut byte = [0_u8];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut ancillary = [0_usize; 4];
    // SAFETY: zero initializes optional msghdr fields before the live buffers are assigned.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&ancillary);
    // SAFETY: recvmsg receives initialized writable buffers and close-on-exec descriptor ownership.
    let received =
        checked(
            unsafe { libc::recvmsg(control.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) }
                as libc::c_long,
        )?;
    let mut descriptors = Vec::new();
    let mut headers = 0;
    let mut malformed = false;
    // SAFETY: bounds checks precede every descriptor read from the kernel's control data.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            headers += 1;
            let length = (*header).cmsg_len;
            let minimum = libc::CMSG_LEN(0) as usize;
            let offset = (header as usize).saturating_sub(message.msg_control as usize);
            if length < minimum || offset.saturating_add(length) > message.msg_controllen {
                malformed = true;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = length - minimum;
                malformed |= !bytes.is_multiple_of(size_of::<RawFd>());
                for index in 0..bytes / size_of::<RawFd>() {
                    descriptors.push(OwnedFd::from_raw_fd(
                        *libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    ));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received == 0
        && headers == 0
        && descriptors.is_empty()
        && !malformed
        && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0
    {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    if received != 1
        || !matches!(byte, [1] | [2])
        || malformed
        || headers != 1
        || descriptors.len() != 1
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(io::Error::other("invalid filesystem listener handoff"));
    }
    Ok((
        descriptors.pop().expect("exactly one received descriptor"),
        byte == [2],
    ))
}

#[cfg(all(test, feature = "native-filesystem-policy", box_native_adapter_tests))]
#[path = "filesystem_queries/forwarding_tests.rs"]
mod forwarding_tests;

#[cfg(test)]
mod tests {
    use super::super::failure_tests::in_fresh_process;
    use super::*;

    #[test]
    fn forwarding_fails_without_waiting_when_the_peer_closes_or_stops_reading() {
        in_fresh_process(|| {
            let (sender, receiver) = UnixStream::pair().unwrap();
            // SAFETY: zero initializes every kernel notification field for this transport test.
            let request = unsafe { zeroed() };
            drop(receiver);
            assert_eq!(
                forward_request(&sender, &request).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            let (sender, _receiver) = UnixStream::pair().unwrap();
            let buffer: libc::c_int = 4096;
            // SAFETY: the option pointer covers one live integer of the declared length.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        sender.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&buffer as *const libc::c_int).cast(),
                        size_of_val(&buffer) as libc::socklen_t,
                    )
                },
                0
            );
            let start = std::time::Instant::now();
            let mut refusal = None;
            for _ in 0..1024 {
                if let Err(error) = forward_request(&sender, &request) {
                    refusal = Some(error);
                    break;
                }
            }
            assert_eq!(
                refusal.expect("bounded forwarding buffer must fill").kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "policy backpressure must not block the supervisor"
            );
        });
    }

    #[test]
    fn a_closed_or_malformed_handoff_never_registers() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(register_listener(&receiver).is_err());
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(&[0]).unwrap();
        assert!(register_listener(&receiver).is_err());
        let (sender, receiver) = UnixStream::pair().unwrap();
        let ordinary_file = open_proc().unwrap();
        send_listener(&sender, &ordinary_file, false).unwrap();
        assert!(register_listener(&receiver).is_err());
    }

    #[test]
    fn an_interrupted_response_is_retried_before_retirement() {
        let mut attempts = 0;
        finish_response(|| {
            attempts += 1;
            if attempts < 3 {
                Err(io::Error::from_raw_os_error(libc::EINTR))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 3, "interruptions leave the response pending");
        finish_response(|| Err(io::Error::from_raw_os_error(libc::ENOENT))).unwrap();
        assert_eq!(
            finish_response(|| Err(io::Error::from_raw_os_error(libc::EIO)))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO),
            "other errors terminate supervision"
        );
    }

    #[test]
    fn a_failed_supervisor_never_signals_an_unowned_process() {
        in_fresh_process(|| {
            for malformed in [false, true] {
                let (mut sender, receiver) = UnixStream::pair().unwrap();
                if malformed {
                    sender.write_all(&[0]).unwrap();
                }
                drop(sender);
                // The live test process stands in for a reused, unowned process identifier.
                let unowned = unsafe { libc::getpid() };
                assert_eq!(supervise(unowned, open_proc().unwrap(), receiver), 125);
            }
        });
    }

    #[test]
    fn a_failed_handoff_leaves_statfs_refused() {
        in_fresh_process(|| {
            super::super::authority::set_no_new_privileges().unwrap();
            let filters =
                super::super::syscall::SyscallPolicy::for_config(&crate::Network::Blocked)
                    .compile()
                    .unwrap();
            let (sender, receiver) = UnixStream::pair().unwrap();
            drop(receiver);
            assert!(install(&filters.filesystem_queries, &sender).is_err());
            // SAFETY: zero initializes a native output buffer for the refusal probe.
            let mut result: libc::statfs64 = unsafe { zeroed() };
            // SAFETY: both path and output remain live during the raw syscall.
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_statfs, c"/".as_ptr(), &mut result) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS)
            );
        });
    }

    #[test]
    fn rejected_extra_or_truncated_descriptors_are_closed() {
        in_fresh_process(|| {
            for count in [2, 8] {
                let (sender, receiver) = UnixStream::pair().unwrap();
                let fixture = tempfile::NamedTempFile::new().unwrap();
                let target =
                    std::fs::read_link(format!("/proc/self/fd/{}", fixture.as_raw_fd())).unwrap();
                let references = || {
                    std::fs::read_dir("/proc/self/fd")
                        .unwrap()
                        .filter_map(Result::ok)
                        .filter(|entry| {
                            std::fs::read_link(entry.path()).ok().as_ref() == Some(&target)
                        })
                        .count()
                };
                let before = references();
                let mut byte = [1_u8];
                let mut vector = libc::iovec {
                    iov_base: byte.as_mut_ptr().cast(),
                    iov_len: 1,
                };
                let mut ancillary = [0_usize; 8];
                // SAFETY: the buffers cover the header and up to eight descriptors.
                unsafe {
                    let mut message: libc::msghdr = zeroed();
                    message.msg_iov = &mut vector;
                    message.msg_iovlen = 1;
                    message.msg_control = ancillary.as_mut_ptr().cast();
                    message.msg_controllen =
                        libc::CMSG_SPACE((count * size_of::<RawFd>()) as u32) as usize;
                    assert!(message.msg_controllen <= size_of_val(&ancillary));
                    let header = libc::CMSG_FIRSTHDR(&message);
                    (*header).cmsg_level = libc::SOL_SOCKET;
                    (*header).cmsg_type = libc::SCM_RIGHTS;
                    (*header).cmsg_len =
                        libc::CMSG_LEN((count * size_of::<RawFd>()) as u32) as usize;
                    for index in 0..count {
                        std::ptr::write(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                            fixture.as_raw_fd(),
                        );
                    }
                    assert_eq!(
                        libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                        1
                    );
                }
                assert!(receive_listener(&receiver).is_err());
                assert_eq!(references(), before, "rejected descriptors must close");
            }
        });
    }
}
