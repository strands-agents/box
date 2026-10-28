//! Register filesystem notifications after the workload mount view exists.
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const HANDOFF_HEADER: &[u8; 8] = b"BOXFS\0\x01\0";
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);

fn checked(value: i32) -> io::Result<i32> {
    if value == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

pub(super) fn handoff(mut control: &UnixStream) -> io::Result<()> {
    control.set_read_timeout(Some(HANDOFF_TIMEOUT))?;
    control.set_write_timeout(Some(HANDOFF_TIMEOUT))?;
    // SAFETY: the process has entered its mount view; this pins that view's root.
    let root = checked(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    let root = unsafe { OwnedFd::from_raw_fd(root) };
    control.write_all(HANDOFF_HEADER)?;
    let listener = install()?;
    transfer(control, [listener.as_raw_fd(), root.as_raw_fd()])?;
    let number = listener.as_raw_fd();
    drop(listener);
    drop(root);
    // SAFETY: no other thread can reuse the descriptor during containment setup.
    let closed = unsafe { libc::fcntl(number, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
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

const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn install() -> io::Result<OwnedFd> {
    let mut sizes = [0_u16; 3];
    // SAFETY: the kernel writes the three documented notification structure sizes.
    checked(unsafe { libc::syscall(libc::SYS_seccomp, 3, 0, sizes.as_mut_ptr()) as i32 })?;
    if sizes != [80, 24, 64] {
        return Err(io::Error::other(
            "unsupported Linux notification structure sizes",
        ));
    }
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    // Check the architecture before interpreting system-call numbers. Unknown calls
    // reach the existing permit and restriction filters installed after this handoff.
    let mut program = [
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, ARCH),
        instruction(0x06, 0, 0, 0x80000000),
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 1, libc::SYS_openat as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_unlinkat as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_renameat as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_renameat2 as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_mkdirat as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_symlinkat as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x15, 0, 1, libc::SYS_truncate as u32),
        instruction(0x06, 0, 0, 0x7fc00000),
        instruction(0x06, 0, 0, 0x7fff0000),
    ];
    let filter = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: the complete filter lives until the kernel copies it. The caller
    // already dropped capabilities and set no_new_privs.
    let descriptor = checked(unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &filter) as i32 })?;
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn transfer(socket: &UnixStream, descriptors: [RawFd; 2]) -> io::Result<()> {
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
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<[RawFd; 2]>() as u32) } as usize;
    // SAFETY: the aligned control buffer fits one header and the two descriptors.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<[RawFd; 2]>() as u32) as usize;
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
