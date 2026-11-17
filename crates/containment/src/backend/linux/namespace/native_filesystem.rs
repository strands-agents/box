//! Register filesystem notifications after the workload mount view exists.
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const HANDOFF_HEADER: &[u8; 8] = b"BOXFS\0\x02\0";
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);

fn checked(value: i32) -> io::Result<i32> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

pub(super) const OPERATIONS: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_unlinkat,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_mkdirat,
    libc::SYS_symlinkat,
    libc::SYS_truncate,
];

pub(super) fn handoff(
    program: &seccompiler::BpfProgram,
    supervisor: &UnixStream,
    mut control: &UnixStream,
) -> io::Result<()> {
    control.set_read_timeout(Some(HANDOFF_TIMEOUT))?;
    control.set_write_timeout(Some(HANDOFF_TIMEOUT))?;
    // SAFETY: the process has entered its mount view; this pins that view before openat is intercepted.
    let root = checked(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: open returned a new descriptor owned by this process.
    let root = unsafe { OwnedFd::from_raw_fd(root) };
    control.write_all(HANDOFF_HEADER)?;
    let listener = super::filesystem_queries::create_listener(program)?;
    super::filesystem_queries::send_listener(supervisor, &listener, true)?;
    transfer(
        control,
        [
            listener.as_raw_fd(),
            root.as_raw_fd(),
            supervisor.as_raw_fd(),
        ],
    )?;
    let number = listener.as_raw_fd();
    drop(listener);
    drop(root);
    // SAFETY: no other thread can reuse the descriptor during containment setup.
    let closed = unsafe { libc::fcntl(number, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    // Finish the supervisor handshake before Box starts reading forwarded requests on its copy.
    super::filesystem_queries::confirm_handoff(supervisor)?;
    control.write_all(&[u8::from(closed)])?;
    let mut ready = [0];
    control.read_exact(&mut ready)?;
    if ready != [1] {
        return Err(io::Error::other(
            "Box refused native filesystem registration",
        ));
    }
    Ok(())
}

fn transfer(socket: &UnixStream, descriptors: [RawFd; 3]) -> io::Result<()> {
    let mut byte = 1_u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<[RawFd; 3]>() as u32) } as usize;
    // SAFETY: the aligned control buffer fits one header and the three descriptors.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<[RawFd; 3]>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            descriptors.len(),
        );
    }
    loop {
        let result = checked(unsafe {
            libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) as i32
        });
        match result {
            Ok(1) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "incomplete native filesystem descriptor handoff",
                ));
            }
        }
    }
}
