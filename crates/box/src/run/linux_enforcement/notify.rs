use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[repr(C)]
#[derive(Default)]
pub(super) struct Data {
    pub number: i32,
    pub arch: u32,
    pub instruction: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
pub(super) struct Request {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: Data,
}

#[repr(C)]
#[derive(Default)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct AddFd {
    id: u64,
    flags: u32,
    source: u32,
    target: u32,
    target_flags: u32,
}

const fn ioctl(direction: u64, number: u64, size: usize) -> libc::c_ulong {
    ((direction << 30) | ((size as u64) << 16) | (33 << 8) | number) as libc::c_ulong
}

pub(super) fn checked(value: i32) -> io::Result<i32> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
pub(super) fn transfer(socket: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    let mut byte = 1_u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: Zero is valid for msghdr; the live buffers and their lengths are assigned before use.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // SAFETY: The test callers supply small descriptor slices; the buffer-size assertion guards the subsequent copy.
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    assert!(message.msg_controllen <= size_of::<[usize; 8]>());
    // SAFETY: Aligned control storage fits the header and descriptors. All buffers remain live through sendmsg.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        checked(libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) as i32)?;
    }
    Ok(())
}

pub(super) fn receive_handles(socket: &UnixStream, count: usize) -> io::Result<Vec<OwnedFd>> {
    let mut byte = 0_u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    // SAFETY: Zero is valid for msghdr; the live buffers and their lengths are assigned before use.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of::<[usize; 8]>();
    // SAFETY: recvmsg receives live, aligned buffers. Header bounds precede descriptor reads.
    // SCM_RIGHTS supplies fresh descriptors, each transferred once into OwnedFd for error-path cleanup.
    unsafe {
        let received = libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC);
        checked(received as i32)?;
        let mut handles = Vec::new();
        let mut headers = 0;
        let mut malformed = false;
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
                    handles.push(OwnedFd::from_raw_fd(
                        *libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    ));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        if received != 1
            || byte != 1
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
            || malformed
            || headers != 1
            || handles.len() != count
        {
            return Err(io::Error::other("invalid descriptor handoff"));
        }
        Ok(handles)
    }
}

pub(super) fn validate_registration(
    header: &[u8; 8],
    handles: &[OwnedFd],
    closed: u8,
) -> io::Result<()> {
    if header != b"BOXFS\0\x01\0" || handles.len() != 2 || closed != 1 {
        return Err(io::Error::other("invalid native filesystem registration"));
    }
    // A notification listener accepts ID_VALID; another descriptor kind does not.
    match valid(handles[0].as_raw_fd(), 0) {
        Ok(_) => {}
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(_) => {
            return Err(io::Error::other(
                "native registration has no notification listener",
            ));
        }
    }
    // SAFETY: Zero initializes every stat field before fstat fills the structure.
    let mut metadata = unsafe { zeroed::<libc::stat>() };
    // SAFETY: The handle count was checked and metadata is writable for the duration of fstat.
    checked(unsafe { libc::fstat(handles[1].as_raw_fd(), &mut metadata) })?;
    // SAFETY: F_GETFL takes no pointer argument and the OwnedFd keeps this descriptor live.
    let flags = checked(unsafe { libc::fcntl(handles[1].as_raw_fd(), libc::F_GETFL) })?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR || flags & libc::O_PATH == 0 {
        return Err(io::Error::other(
            "native registration has no path-only root directory",
        ));
    }
    Ok(())
}

pub(super) fn receive(listener: RawFd) -> io::Result<Request> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "notification wait"));
        }
        let mut poll = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized pollfd and writes only that live structure.
        let polled = unsafe { libc::poll(&mut poll, 1, remaining.as_millis() as i32) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if polled == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "notification wait"));
        }
        if poll.revents & libc::POLLIN == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "listener has no requester",
            ));
        }
        let mut request = Request::default();
        // SAFETY: The ioctl size matches Request, whose initialized storage remains writable throughout the call.
        let received = unsafe {
            checked(libc::ioctl(
                listener,
                ioctl(3, 0, size_of::<Request>()),
                &mut request,
            ))
        };
        match received {
            Ok(_) => return Ok(request),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINTR)) => {
                // The requester can cancel after poll reports a pending request.
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn reply(listener: RawFd, id: u64, error: i32) -> io::Result<()> {
    let response = Response {
        id,
        error: -error,
        ..Response::default()
    };
    // SAFETY: The ioctl size matches the initialized Response, which remains live throughout the call.
    unsafe {
        checked(libc::ioctl(
            listener,
            ioctl(3, 1, size_of::<Response>()),
            &response,
        ))?;
    }
    Ok(())
}

pub(super) fn valid(listener: RawFd, id: u64) -> io::Result<()> {
    // SAFETY: ID_VALID reads one live u64, matching the encoded ioctl size.
    unsafe {
        checked(libc::ioctl(listener, ioctl(1, 2, size_of::<u64>()), &id))?;
    }
    Ok(())
}

pub(super) fn inject(
    listener: RawFd,
    id: u64,
    source: RawFd,
    close_on_exec: bool,
) -> io::Result<i32> {
    let add = AddFd {
        id,
        flags: 2,
        source: source as u32,
        target_flags: if close_on_exec {
            libc::O_CLOEXEC as u32
        } else {
            0
        },
        ..AddFd::default()
    };
    // SAFETY: The initialized AddFd layout and size match the ioctl; the kernel validates descriptor values.
    unsafe { checked(libc::ioctl(listener, ioctl(1, 3, size_of::<AddFd>()), &add)) }
}

pub(super) fn read_path(request: &Request, argument: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; 4096];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: request.data.args[argument] as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: The local vector spans writable bytes. The kernel validates the remote address instead of Rust dereferencing it.
    let length = unsafe { libc::process_vm_readv(request.pid as i32, &local, 1, &remote, 1, 0) };
    if length == -1 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(length as usize);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unterminated pathname"))?;
    bytes.truncate(end);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_handoff_closes_received_descriptors() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let mut pipe = [-1; 2];
        // SAFETY: pipe contains space for both returned descriptors.
        checked(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) })
            .unwrap();
        // SAFETY: Successful pipe2 returned a new reader with no existing Rust owner.
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: Successful pipe2 returned a separate writer with no existing Rust owner.
        let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        transfer(&sender, &[writer.as_raw_fd()]).unwrap();
        drop(writer);
        assert!(receive_handles(&receiver, 2).is_err());
        let mut byte = 0_u8;
        assert_eq!(
            // SAFETY: byte is writable for the one byte requested; the reader remains owned.
            unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );
    }

    #[test]
    fn accepted_handoff_preserves_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        transfer(&sender, &[sender.as_raw_fd()]).unwrap();
        let handles = receive_handles(&receiver, 1).unwrap();
        // SAFETY: F_GETFD takes no pointer argument; receive_handles checked the descriptor count.
        let flags = checked(unsafe { libc::fcntl(handles[0].as_raw_fd(), libc::F_GETFD) }).unwrap();
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    struct Listener {
        descriptor: OwnedFd,
        child: libc::pid_t,
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            // SAFETY: This guard owns the unreaped child; neither call accesses Rust memory.
            unsafe {
                libc::kill(self.child, libc::SIGKILL);
                libc::waitpid(self.child, std::ptr::null_mut(), 0);
            }
        }
    }
    fn listener() -> Listener {
        let (sender, receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // SAFETY: The child follows the syscall-only branch below and exits without running Rust destructors.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // The helper cannot run workload code. It installs a filter on getpid
            // solely to obtain a real listener, sends that descriptor, and waits.
            // SAFETY: Filter and message buffers remain live through their calls; this child uses syscall wrappers and _exit.
            unsafe {
                libc::alarm(10);
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(2);
                }
                let mut instructions = [
                    libc::sock_filter {
                        code: 0x20,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    },
                    libc::sock_filter {
                        code: 0x15,
                        jt: 0,
                        jf: 1,
                        k: libc::SYS_getpid as u32,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: 0x7fc00000,
                    },
                    libc::sock_filter {
                        code: 0x06,
                        jt: 0,
                        jf: 0,
                        k: 0x7fff0000,
                    },
                ];
                let filter = libc::sock_fprog {
                    len: instructions.len() as u16,
                    filter: instructions.as_mut_ptr(),
                };
                let descriptor = libc::syscall(libc::SYS_seccomp, 1, 8, &filter) as i32;
                if descriptor < 0 || transfer(&sender, &[descriptor]).is_err() {
                    libc::_exit(3);
                }
                libc::close(descriptor);
                loop {
                    libc::pause();
                }
            }
        }
        drop(sender);
        let handles = receive_handles(&receiver, 1).expect("helper listener");
        Listener {
            descriptor: handles.into_iter().next().unwrap(),
            child,
        }
    }
    fn root_directory() -> OwnedFd {
        // SAFETY: The path is NUL-terminated and these flags require no mode argument.
        let descriptor = checked(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })
        .unwrap();
        // SAFETY: open returned a new descriptor and checked rejected failure before this ownership transfer.
        unsafe { OwnedFd::from_raw_fd(descriptor) }
    }
    #[test]
    fn registration_accepts_a_kernel_listener_and_path_only_directory() {
        let listener = listener();
        let handles = [listener.descriptor.try_clone().unwrap(), root_directory()];
        validate_registration(b"BOXFS\0\x01\0", &handles, 1).unwrap();
    }
    #[test]
    fn registration_refuses_a_wrong_protocol_or_retained_listener() {
        let listener = listener();
        let handles = [listener.descriptor.try_clone().unwrap(), root_directory()];
        assert!(validate_registration(b"BOXFS\0\x02\0", &handles, 1).is_err());
        assert!(validate_registration(b"BOXFS\0\x01\0", &handles, 0).is_err());
        assert!(validate_registration(b"BOXFS\0\x01\0", &handles[..1], 1).is_err());
    }
    #[test]
    fn registration_refuses_swapped_duplicate_and_wrong_descriptor_kinds() {
        let listener = listener();
        let root = root_directory();
        let header = b"BOXFS\0\x01\0";
        assert!(
            validate_registration(
                header,
                &[
                    root.try_clone().unwrap(),
                    listener.descriptor.try_clone().unwrap()
                ],
                1
            )
            .is_err()
        );
        assert!(
            validate_registration(
                header,
                &[
                    listener.descriptor.try_clone().unwrap(),
                    listener.descriptor.try_clone().unwrap()
                ],
                1
            )
            .is_err()
        );
        assert!(
            validate_registration(
                header,
                &[root.try_clone().unwrap(), root.try_clone().unwrap()],
                1
            )
            .is_err()
        );
        let (socket, _) = UnixStream::pair().unwrap();
        assert!(validate_registration(header, &[socket.into(), root], 1).is_err());
        let content_directory = std::fs::File::open("/").unwrap();
        assert!(
            validate_registration(
                header,
                &[
                    listener.descriptor.try_clone().unwrap(),
                    content_directory.into()
                ],
                1
            )
            .is_err()
        );
    }
}
