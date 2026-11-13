//! Exercise the production supervisor with an unread, saturated forwarding socket.

use super::super::failure_tests::in_fresh_process;
use super::*;
use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Instant;

static PROBE: &std::ffi::CStr = c"/forwarding-test-probe";
const FLAGS: [libc::c_int; 2] = [libc::O_RDONLY, libc::O_RDONLY | libc::O_NONBLOCK];

struct Child {
    pid: libc::pid_t,
    descriptor: OwnedFd,
}

impl Child {
    fn new(pid: libc::pid_t) -> Self {
        // SAFETY: pid identifies our unreaped child; pidfd_open returns a new owned descriptor.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0, "opening a child process handle");
        // SAFETY: a successful pidfd_open returned this new descriptor.
        Self {
            pid,
            descriptor: unsafe { OwnedFd::from_raw_fd(raw as RawFd) },
        }
    }

    fn wait(&mut self) -> i32 {
        let mut status = 0;
        // SAFETY: this guard owns the child and the status output.
        assert_eq!(unsafe { libc::waitpid(self.pid, &mut status, 0) }, self.pid);
        self.pid = 0;
        assert!(libc::WIFEXITED(status), "unexpected child status {status}");
        libc::WEXITSTATUS(status)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.pid == 0 {
            return;
        }
        let mut status = 0;
        // SAFETY: wait only for the owned child. ECHILD means serve already reaped it;
        // never signal that number after ownership has ended.
        if unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) } == 0 {
            // SAFETY: the process handle retains identity even if serve reaps the child concurrently.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.descriptor.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                libc::waitpid(self.pid, &mut status, 0);
            }
        }
    }
}

fn notification_filter() -> seccompiler::BpfProgram {
    let condition = SeccompCondition::new(
        1,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        PROBE.as_ptr() as u64,
    )
    .unwrap();
    let filter = SeccompFilter::new(
        BTreeMap::from([(
            libc::SYS_openat,
            vec![SeccompRule::new(vec![condition]).unwrap()],
        )]),
        SeccompAction::Allow,
        SeccompAction::Trace(0),
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();
    let mut program: seccompiler::BpfProgram = filter.try_into().unwrap();
    // Match production's seccompiler 0.5 notification encoding, retaining its architecture guard.
    for instruction in &mut program {
        if instruction.code == (libc::BPF_RET | libc::BPF_K) as u16
            && instruction.k == libc::SECCOMP_RET_TRACE
        {
            instruction.k = libc::SECCOMP_RET_USER_NOTIF;
        }
    }
    program
}

fn readable(listener: &OwnedFd) -> bool {
    let mut descriptor = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the initialized descriptor remains writable for this nonblocking poll.
    assert!(unsafe { libc::poll(&mut descriptor, 1, 0) } >= 0);
    descriptor.revents & libc::POLLIN != 0
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "notification transition timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct Saturated {
    // Child guards clean up blocked syscalls even when a regression makes an assertion panic.
    workload: Child,
    _reaper: Child,
    reaper_control: UnixStream,
    receiver: Option<UnixStream>,
    listener: OwnedFd,
    sentinels: Vec<u64>,
    result: Receiver<io::Result<i32>>,
    supervisor: Option<JoinHandle<()>>,
}

impl Saturated {
    fn start() -> Self {
        let proc = open_proc().unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (reaper_control, reaper_input) = UnixStream::pair().unwrap();
        let buffer: libc::c_int = 4096;
        // SAFETY: the option points to one live integer of the declared size.
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
        let mut sentinels = Vec::new();
        for id in 1..=1024_u64 {
            // SAFETY: all-zero fields are valid storage for the serialization-only sentinel.
            let mut request: libc::seccomp_notif = unsafe { zeroed() };
            request.id = id;
            match forward_request(&sender, &request) {
                Ok(()) => sentinels.push(id),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("prefilling transport: {error}"),
            }
        }
        assert!(
            !sentinels.is_empty() && sentinels.len() < 1024,
            "socket must reach EAGAIN"
        );
        // SAFETY: this isolated test process permanently gives up privilege acquisition.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        let listener = create_listener(&notification_filter()).unwrap();
        let descriptors = [
            proc.as_raw_fd(),
            sender.as_raw_fd(),
            receiver.as_raw_fd(),
            listener.as_raw_fd(),
            reaper_control.as_raw_fd(),
            reaper_input.as_raw_fd(),
        ];
        // SAFETY: the child performs only raw libc calls and _exit; no Rust teardown runs.
        let reaper = unsafe { libc::fork() };
        assert!(reaper >= 0);
        if reaper == 0 {
            // SAFETY: these are inherited descriptors; retain only the reaper's control input.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                for fd in descriptors {
                    if fd != reaper_input.as_raw_fd() {
                        libc::close(fd);
                    }
                }
                let mut byte = 0_u8;
                let read = libc::read(reaper_input.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                libc::_exit(if read == 1 && byte == 1 { 37 } else { 98 });
            }
        }
        let reaper = Child::new(reaper);
        // SAFETY: the child performs only raw libc calls and _exit, including the filtered probes.
        let workload = unsafe { libc::fork() };
        assert!(workload >= 0);
        if workload == 0 {
            // SAFETY: close all inherited control descriptors, then issue two known-pointer opens.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                for fd in descriptors {
                    libc::close(fd);
                }
                libc::close(reaper.descriptor.as_raw_fd());
                for flags in FLAGS {
                    let result =
                        libc::syscall(libc::SYS_openat, libc::AT_FDCWD, PROBE.as_ptr(), flags, 0);
                    if result != -1 || *libc::__errno_location() != libc::EACCES {
                        libc::_exit(99);
                    }
                }
                libc::_exit(0);
            }
        }
        let workload = Child::new(workload);
        drop(reaper_input);
        // The child is blocked in the kernel before serve starts. No other thread receives it.
        wait_until(|| readable(&listener));
        let serving_listener = listener.try_clone().unwrap();
        let serving_sender = sender.try_clone().unwrap();
        let (report, result) = mpsc::channel();
        let reaper_pid = reaper.pid;
        let supervisor = std::thread::spawn(move || {
            let outcome = serve(reaper_pid, &proc, &serving_listener, Some(&serving_sender));
            let _ = report.send(outcome);
        });
        // POLLIN disappearing proves the production loop dequeued the notification.
        wait_until(|| !readable(&listener));
        // No reader has drained a byte. A further whole frame still cannot fit.
        // SAFETY: zero initializes notification storage used only by the serializer.
        let probe = unsafe { zeroed() };
        assert_eq!(
            forward_request(&sender, &probe).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            matches!(
                result.recv_timeout(Duration::from_millis(100)),
                Err(RecvTimeoutError::Timeout)
            ),
            "serve must remain alive while the dequeued notification cannot be forwarded"
        );
        drop(sender);
        Self {
            workload,
            _reaper: reaper,
            reaper_control,
            receiver: Some(receiver),
            listener,
            sentinels,
            result,
            supervisor: Some(supervisor),
        }
    }

    fn finish(&mut self) -> io::Result<i32> {
        let result = self
            .result
            .recv_timeout(Duration::from_secs(2))
            .expect("supervisor must stop promptly");
        self.supervisor.take().unwrap().join().unwrap();
        result
    }
}

#[test]
fn a_saturated_forwarder_resumes_without_losing_or_repeating_requests() {
    in_fresh_process(|| {
        let mut run = Saturated::start();
        let receiver = run.receiver.as_mut().unwrap();
        for id in &run.sentinels {
            let mut frame = [0; 80];
            receiver.read_exact(&mut frame).unwrap();
            assert_eq!(&frame[..8], &id.to_le_bytes());
            assert_eq!(&frame[8..], &[0; 72]);
        }
        let mut previous = None;
        for flags in FLAGS {
            let mut frame = [0; 80];
            receiver.read_exact(&mut frame).unwrap();
            let id = u64::from_le_bytes(frame[..8].try_into().unwrap());
            assert_ne!(
                previous,
                Some(id),
                "each notification must be forwarded exactly once"
            );
            previous = Some(id);
            assert_eq!(
                u32::from_le_bytes(frame[8..12].try_into().unwrap()),
                run.workload.pid as u32
            );
            assert_eq!(u32::from_le_bytes(frame[12..16].try_into().unwrap()), 0);
            assert_eq!(
                i32::from_le_bytes(frame[16..20].try_into().unwrap()),
                libc::SYS_openat as i32
            );
            assert_eq!(
                u64::from_le_bytes(frame[40..48].try_into().unwrap()),
                PROBE.as_ptr() as u64
            );
            assert_eq!(
                u64::from_le_bytes(frame[48..56].try_into().unwrap()),
                flags as u64
            );
            let response = libc::seccomp_notif_resp {
                id,
                val: 0,
                error: -libc::EACCES,
                flags: 0,
            };
            // SAFETY: the response completes exactly the received request with a denial, never continuation.
            assert_eq!(
                unsafe {
                    libc::ioctl(
                        run.listener.as_raw_fd(),
                        libc::SECCOMP_IOCTL_NOTIF_SEND,
                        &response,
                    )
                },
                0
            );
        }
        assert_eq!(
            run.workload.wait(),
            0,
            "both workload syscalls must observe EACCES"
        );
        receiver
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let error = receiver.read(&mut [0; 1]).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected extra frame: {error}"
        );
        run.reaper_control.write_all(&[1]).unwrap();
        assert_eq!(run.finish().unwrap(), 37);
    });
}

#[test]
fn a_saturated_forwarder_stops_when_the_receiver_closes() {
    in_fresh_process(|| {
        let mut run = Saturated::start();
        drop(run.receiver.take());
        assert!(run.finish().is_err(), "peer closure must fail supervision");
    });
}

#[test]
fn a_saturated_forwarder_preserves_the_reaper_exit_status() {
    in_fresh_process(|| {
        let mut run = Saturated::start();
        run.reaper_control.write_all(&[1]).unwrap();
        assert_eq!(
            run.finish().unwrap(),
            37,
            "a full socket must not hide the workload exit"
        );
    });
}
