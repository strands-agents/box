//! Bounded, private controller framing for storage admission.
use super::failure;
use crate::ContainmentError;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;

fn socket_failure(source: std::io::Error) -> ContainmentError {
    ContainmentError::StorageControlIo { source }
}

pub(super) fn send_fd(socket: &UnixStream, fd: &OwnedFd) -> Result<(), ContainmentError> {
    let payload = *b"F";
    let mut io = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    let mut control = [0_u64; 4];
    // SAFETY: zeroed msghdr has null optional fields; required buffers are assigned below.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: aligned control has room for one descriptor, and the payload outlives sendmsg.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            fd.as_raw_fd(),
        );
        message.msg_controllen = (*header).cmsg_len;
        loop {
            let sent = libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
            if sent == 1 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if sent < 0 && error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if sent < 0 {
                socket_failure(error)
            } else {
                failure("descriptor send was incomplete")
            });
        }
    }
}

pub(super) fn receive_fd(socket: &UnixStream) -> Result<OwnedFd, ContainmentError> {
    let mut payload = [0_u8; 1];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_u64; 16];
    // SAFETY: required msghdr buffers are initialized before the syscall.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    let received = loop {
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: all writable buffers remain live; received descriptors are immediately owned.
        let received =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        break received;
    };
    if received < 0 {
        return Err(socket_failure(std::io::Error::last_os_error()));
    }
    if received == 0 {
        return Err(socket_failure(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "storage descriptor socket closed",
        )));
    }
    let mut descriptors = Vec::new();
    let mut malformed = false;
    // SAFETY: iterate only headers whose lengths the kernel supplied within the control buffer.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let minimum = libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_len < minimum {
                malformed = true;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len - minimum;
                malformed |= !bytes.is_multiple_of(std::mem::size_of::<libc::c_int>());
                for index in 0..bytes / std::mem::size_of::<libc::c_int>() {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    );
                    if raw >= 0 {
                        descriptors.push(OwnedFd::from_raw_fd(raw));
                    } else {
                        malformed = true;
                    }
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received != 1
        || payload != *b"F"
        || malformed
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() != 1
    {
        return Err(failure("invalid storage descriptor frame"));
    }
    Ok(descriptors.pop().expect("one descriptor was checked"))
}

pub(super) fn send_text(mut socket: &UnixStream, text: &str) -> Result<(), ContainmentError> {
    if text.len() > super::CONTROL_LIMIT {
        return Err(failure("storage control frame exceeds limit"));
    }
    socket
        .write_all(&(text.len() as u32).to_be_bytes())
        .map_err(socket_failure)?;
    socket.write_all(text.as_bytes()).map_err(socket_failure)
}

pub(super) fn receive_text(
    mut socket: &UnixStream,
    limit: usize,
) -> Result<String, ContainmentError> {
    let mut length = [0_u8; 4];
    socket.read_exact(&mut length).map_err(socket_failure)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > limit {
        return Err(failure("storage control frame exceeds limit"));
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).map_err(socket_failure)?;
    String::from_utf8(bytes).map_err(|_| failure("storage control frame is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_kind(error: ContainmentError) -> std::io::ErrorKind {
        match error {
            ContainmentError::StorageControlIo { source } => source.kind(),
            other => panic!("expected socket I/O error, received {other:?}"),
        }
    }

    #[test]
    fn control_disconnects_preserve_their_io_error_kind() {
        let (socket, peer) = UnixStream::pair().unwrap();
        drop(peer);
        assert_eq!(
            socket_kind(receive_text(&socket, 128).unwrap_err()),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            socket_kind(receive_fd(&socket).unwrap_err()),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            socket_kind(send_text(&socket, "frame").unwrap_err()),
            std::io::ErrorKind::BrokenPipe
        );
        let descriptor: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert_eq!(
            socket_kind(send_fd(&socket, &descriptor).unwrap_err()),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn malformed_frames_are_never_classified_as_cancellation_io() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&129_u32.to_be_bytes()).unwrap();
        assert!(matches!(
            receive_text(&socket, 128),
            Err(ContainmentError::ApplyFailed { .. })
        ));
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&1_u32.to_be_bytes()).unwrap();
        peer.write_all(&[0xff]).unwrap();
        assert!(matches!(
            receive_text(&socket, 128),
            Err(ContainmentError::ApplyFailed { .. })
        ));
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"X").unwrap();
        assert!(matches!(
            receive_fd(&socket),
            Err(ContainmentError::ApplyFailed { .. })
        ));
    }
}
