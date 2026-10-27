//! Probe path-only descriptor transfer on the running kernel.
use super::notify;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

struct Child(libc::pid_t);
impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            while libc::waitpid(self.0, std::ptr::null_mut(), 0) == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }
    }
}

pub(super) fn path_handles() -> io::Result<bool> {
    super::fault::at("capability-probe")?;
    let (sender, receiver) = UnixStream::pair()?;
    receiver.set_read_timeout(Some(Duration::from_secs(3)))?;
    let readable = unsafe {
        OwnedFd::from_raw_fd(notify::checked(libc::open(
            c"/dev/null".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        ))?)
    };
    let path = unsafe {
        OwnedFd::from_raw_fd(notify::checked(libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ))?)
    };
    let pid = notify::checked(unsafe { libc::fork() })?;
    if pid == 0 {
        unsafe { child(sender.as_raw_fd()) }
    }
    let child = Child(pid);
    drop(sender);
    let handles = notify::receive_handles(&receiver, 1)?;
    let listener = handles[0].as_raw_fd();
    let control = notify::receive(listener)?;
    notify::inject(listener, control.id, readable.as_raw_fd(), true)?;
    let request = notify::receive(listener)?;
    let supported = match notify::inject(listener, request.id, path.as_raw_fd(), true) {
        Ok(_) => true,
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            notify::reply(listener, request.id, libc::EBADF)?;
            false
        }
        Err(error) => return Err(error),
    };
    let mut status = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            break;
        }
        if result == 0 {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "path-only descriptor probe",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
    std::mem::forget(child);
    let expected = if supported { 0 } else { 10 };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != expected {
        return Err(io::Error::other("path-only descriptor probe failed"));
    }
    Ok(supported)
}

unsafe fn child(socket: i32) -> ! {
    unsafe {
        libc::alarm(5);
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
        let listener = libc::syscall(libc::SYS_seccomp, 1, 8, &filter) as i32;
        if listener < 0 {
            libc::_exit(3);
        }
        let mut byte = 1_u8;
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0_usize; 8];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(4) as usize;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
        *libc::CMSG_DATA(header).cast::<i32>() = listener;
        if libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) != 1 {
            libc::_exit(4);
        }
        libc::close(listener);
        let readable = libc::syscall(libc::SYS_getpid) as i32;
        let mut byte = 0_u8;
        if readable < 0
            || libc::read(readable, (&mut byte as *mut u8).cast(), 1) != 0
            || libc::fcntl(readable, libc::F_GETFD) & libc::FD_CLOEXEC == 0
        {
            libc::_exit(5);
        }
        libc::close(readable);
        let path = libc::syscall(libc::SYS_getpid) as i32;
        if path == -1 {
            libc::_exit(if *libc::__errno_location() == libc::EBADF {
                10
            } else {
                6
            });
        }
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fcntl(path, libc::F_GETFL) & libc::O_PATH == 0
            || libc::fcntl(path, libc::F_GETFD) & libc::FD_CLOEXEC == 0
            || libc::fstat(path, &mut stat) != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || libc::read(path, (&mut byte as *mut u8).cast(), 1) != -1
            || *libc::__errno_location() != libc::EBADF
        {
            libc::_exit(7);
        }
        libc::_exit(0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_probe_completes_and_does_not_filter_the_parent() {
        let first = super::path_handles().expect("kernel descriptor probe");
        assert_eq!(super::path_handles().unwrap(), first);
        assert!(unsafe { libc::syscall(libc::SYS_getpid) } > 0);
    }
    #[cfg(box_native_adapter_tests)]
    #[test]
    fn path_only_broker_delivery_preserves_policy_and_handle_restrictions() {
        use super::*;
        use crate::run::native_enforcement::{PATH_HANDLES, broker};
        use crate::run::telemetry::DecisionRecorder;
        use policy::{GovernedBox, PathResolver, Policy};
        let supported = path_handles().unwrap();
        let _ = PATH_HANDLES.set(supported);
        for permitted in [true, false] {
            let fixture = tempfile::tempdir().unwrap();
            let name =
                std::ffi::CString::new(fixture.path().as_os_str().as_encoded_bytes()).unwrap();
            let engine = crate::test_support::open_policy(vec![Policy {
                origin: "native-handle.dw".into(),
                text: if permitted {
                    "permit(principal, action, resource);"
                } else {
                    "forbid(principal, action, resource);"
                }
                .into(),
            }]);
            let (sender, receiver) = UnixStream::pair().unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let readable = std::fs::File::open("/dev/null").unwrap();
            let root = unsafe {
                OwnedFd::from_raw_fd(
                    notify::checked(libc::open(
                        c"/".as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    ))
                    .unwrap(),
                )
            };
            let pid = notify::checked(unsafe { libc::fork() }).unwrap();
            if pid == 0 {
                unsafe { child(sender.as_raw_fd()) }
            }
            let child = Child(pid);
            drop(sender);
            let handles = notify::receive_handles(&receiver, 1).unwrap();
            let listener = handles[0].as_raw_fd();
            let control = notify::receive(listener).unwrap();
            notify::inject(listener, control.id, readable.as_raw_fd(), true).unwrap();
            let mut request = notify::receive(listener).unwrap();
            request.data.number = libc::SYS_openat as i32;
            request.data.args = [
                libc::AT_FDCWD as u64,
                name.as_ptr() as u64,
                (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ];
            let resolver = PathResolver::over([std::path::PathBuf::from("/")]).unwrap();
            let event = broker::file_request(
                &resolver,
                &engine,
                root.as_raw_fd(),
                listener,
                &request,
                &GovernedBox::assigned("native-handle"),
                &DecisionRecorder::discarding(),
            )
            .unwrap();
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            std::mem::forget(child);
            assert!(libc::WIFEXITED(status));
            if !supported {
                assert_eq!(event["refusal"], "kernel cannot transfer path-only handles");
                assert_eq!(libc::WEXITSTATUS(status), 6);
            } else {
                assert_eq!(event["decisions"][0]["operation"], "ReadMetadata");
                assert_eq!(
                    event["outcome"],
                    if permitted {
                        "descriptor_issued"
                    } else {
                        "denied"
                    }
                );
                assert_eq!(libc::WEXITSTATUS(status), if permitted { 0 } else { 6 });
            }
        }
    }
}
