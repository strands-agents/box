//! Real kernel cancellation before and after a brokered truncation.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::run::native_enforcement::fault;
    use policy::Policy;
    use std::cell::{Cell, RefCell};
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    struct Pending {
        pid: Option<libc::pid_t>,
        channel: UnixStream,
        listener: OwnedFd,
    }

    impl Pending {
        fn start(path: &CString) -> (Self, notify::Request) {
            let (sender, receiver) = UnixStream::pair().unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let placeholder = open("/dev/null", libc::O_RDONLY).unwrap();
            // SAFETY: The child runs only the syscall helper and never returns through Rust cleanup.
            let pid = notify::checked(unsafe { libc::fork() }).unwrap();
            if pid == 0 {
                // SAFETY: Both sockets and the pre-fork CString remain live in the child.
                unsafe { request_truncate(sender.as_raw_fd(), receiver.as_raw_fd(), path.as_ptr()) }
            }
            drop(sender);
            let mut pending = Self {
                pid: Some(pid),
                channel: receiver,
                listener: placeholder,
            };
            pending.listener = notify::receive_handles(&pending.channel, 1)
                .unwrap()
                .pop()
                .unwrap();
            let request = notify::receive(pending.listener.as_raw_fd()).unwrap();
            assert_eq!(request.pid, pid as u32);
            assert_eq!(request.data.number, libc::SYS_truncate as i32);
            (pending, request)
        }

        fn running(&mut self) {
            let pid = self.pid.expect("the test owns an unreaped child");
            // SAFETY: pid is still owned, and a null status is permitted for this nonblocking probe.
            let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            if result == pid {
                self.pid = None;
            }
            assert_eq!(result, 0, "requester must still be waiting for its reply");
        }

        fn reap(&mut self, cancel: bool) -> i32 {
            let pid = self.pid.expect("the test owns an unreaped child");
            if cancel {
                // SAFETY: The unreaped child reserves this process ID.
                assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut status = 0;
            loop {
                // SAFETY: pid is owned and status remains writable through the call.
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    self.pid = None;
                    return status;
                }
                if result < 0 {
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
                }
                assert!(
                    Instant::now() < deadline,
                    "truncation requester did not exit"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for Pending {
        fn drop(&mut self) {
            if let Some(pid) = self.pid.take() {
                // SAFETY: This guard owns the unreaped child; it cannot signal a reused process ID.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    while libc::waitpid(pid, std::ptr::null_mut(), 0) == -1
                        && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                    {
                    }
                }
            }
        }
    }

    unsafe fn request_truncate(socket: i32, unused_socket: i32, path: *const libc::c_char) -> ! {
        // SAFETY: All buffers are initialized and live through their syscalls. This forked child
        // uses syscall wrappers and _exit, without allocator or inherited destructor activity.
        unsafe {
            libc::alarm(10);
            libc::close(unused_socket);
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
                    k: libc::SYS_truncate as u32,
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
            let result = libc::syscall(libc::SYS_truncate, path, 3);
            byte = if result == 0 { b'S' } else { b'E' };
            if libc::write(socket, (&byte as *const u8).cast(), 1) != 1 {
                libc::_exit(5);
            }
            libc::_exit(if result == 0 { 0 } else { 6 });
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Cancellation {
        None,
        BeforeEffect,
        AfterEffect,
    }

    fn exercise(cancellation: Cancellation) {
        let fixture = tempfile::tempdir().unwrap();
        let file = fixture.path().join("target");
        std::fs::write(&file, b"original\n").unwrap();
        let history = fixture.path().join("history.redb");
        let resolver = PathResolver::over([fixture.path().to_path_buf()]).unwrap();
        let approved = resolver.approve_host(&file).unwrap();
        let policy_path = approved.reported();
        let sources = vec![Policy {
            origin: "after-effect.dw".into(),
            text: format!(
                r#"permit(principal, action == Box::Action::"fs:write", resource);
    permit(principal, action == Box::Action::"fs:read", resource)
    when temporal {{ formerly within 300s Box::Action::"fs:write"::response{{
        input.path: {path}, input.operation: Box::FsWriteOperation::"write_content",
        output.result: Box::FsResponseResult::"completed"
    }} }};"#,
                path = serde_json::to_string(policy_path.as_ref()).unwrap()
            ),
        }];
        let engine = PolicyEngine::open(sources.clone(), &history).unwrap();
        let governed = GovernedBox::assigned("after-effect");
        let completed = |engine: &PolicyEngine| {
            engine
                .decide(
                    &governed,
                    &Principal::agent(),
                    &Request::Fs {
                        path: &approved,
                        operation: FsOperation::ReadContent,
                    },
                )
                .0
                .is_allow()
        };
        assert!(
            !completed(&engine),
            "unprimed history must not claim a completed write"
        );
        let path = CString::new(file.as_os_str().as_bytes()).unwrap();
        let (pending, request) = Pending::start(&path);
        let listener = pending.listener.as_raw_fd();
        let request_id = request.id;
        let pending = Rc::new(RefCell::new(pending));
        let root = open("/", libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC).unwrap();
        let hook_ran = Rc::new(Cell::new(false));
        let run = || {
            file_request(
                &resolver,
                &engine,
                root.as_raw_fd(),
                listener,
                &request,
                &governed,
                &DecisionRecorder::discarding(),
            )
        };
        let result = if cancellation == Cancellation::AfterEffect {
            let child = Rc::clone(&pending);
            let observed = Rc::clone(&hook_ran);
            let changed = file.clone();
            fault::with_outcome_hook(
                move || {
                    assert_eq!(
                        std::fs::read(changed).unwrap(),
                        b"ori",
                        "hook must run after truncation"
                    );
                    let mut child = child.borrow_mut();
                    child.running();
                    notify::valid(child.listener.as_raw_fd(), request_id).unwrap();
                    let status = child.reap(true);
                    assert!(libc::WIFSIGNALED(status));
                    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                    observed.set(true);
                },
                run,
            )
        } else {
            if cancellation == Cancellation::BeforeEffect {
                let status = pending.borrow_mut().reap(true);
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            }
            run()
        };
        assert_eq!(hook_ran.get(), cancellation == Cancellation::AfterEffect);
        let mut child = pending.borrow_mut();
        if cancellation == Cancellation::None {
            assert_eq!(result.unwrap()["outcome"], "completed");
            let mut delivered = [0_u8];
            child.channel.read_exact(&mut delivered).unwrap();
            assert_eq!(
                delivered,
                [b'S'],
                "the requester must observe successful reply delivery"
            );
            let status = child.reap(false);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                Some(libc::ENOENT)
            );
        }
        let mut extra = [0_u8];
        assert_eq!(
            child.channel.read(&mut extra).unwrap(),
            0,
            "no reply bytes or child may remain"
        );
        assert!(child.pid.is_none(), "requester must be reaped exactly once");
        let expected: &[u8] = if cancellation == Cancellation::BeforeEffect {
            b"original\n"
        } else {
            b"ori"
        };
        assert_eq!(std::fs::read(&file).unwrap(), expected);
        drop(child);
        drop(engine);
        let reopened = PolicyEngine::open(sources, &history).unwrap();
        assert_eq!(
            completed(&reopened),
            cancellation != Cancellation::BeforeEffect,
            "durable completed history must follow the actual effect, not reply delivery"
        );
    }

    #[test]
    fn a_delivered_truncation_records_its_completed_effect() {
        exercise(Cancellation::None);
    }

    #[test]
    fn cancellation_before_truncation_preserves_bytes_and_has_no_completed_outcome() {
        exercise(Cancellation::BeforeEffect);
    }

    #[test]
    fn cancellation_after_truncation_keeps_changed_bytes_and_completed_outcome() {
        exercise(Cancellation::AfterEffect);
    }
}
