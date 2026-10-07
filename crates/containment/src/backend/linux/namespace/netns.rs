//! The egress transport across the network namespace.

use std::os::fd::{AsRawFd as _, OwnedFd};

use crate::error::ContainmentError;

use super::MECHANISM;

/// Bring up loopback inside the current (new) network namespace.
pub(crate) fn bring_up_loopback() -> Result<(), ContainmentError> {
    // A datagram socket is just a handle for the ioctl; nothing is sent.
    // SAFETY: a socket call with constant arguments.
    let handle = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if handle < 0 {
        return Err(failure(format!(
            "opening a control socket to configure loopback: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Wrap immediately so every early return below closes it.
    // SAFETY: `handle` is a fresh descriptor this function owns.
    let handle = unsafe { OwnedFd::from_raw_fd(handle) };

    let mut request = InterfaceRequest::for_loopback();

    // Read the current flags before writing them: the kernel reads the whole `ifreq`, so the flags
    // field must start from what is already there.
    if unsafe { libc::ioctl(handle.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) } < 0 {
        return Err(failure(format!(
            "reading loopback's interface flags: {}",
            std::io::Error::last_os_error()
        )));
    }

    request.flags |= libc::IFF_UP as libc::c_short;

    // SAFETY: same structure, now with IFF_UP set.
    if unsafe { libc::ioctl(handle.as_raw_fd(), libc::SIOCSIFFLAGS, &request) } < 0 {
        return Err(failure(format!(
            "bringing loopback up: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Bind and listen on `127.0.0.1:port` in the current network namespace.
pub(crate) fn listen_on_loopback(port: u16) -> Result<OwnedFd, ContainmentError> {
    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).map_err(|source| {
            failure(format!(
                "binding 127.0.0.1:{port} inside the network namespace: {source}"
            ))
        })?;

    // Deliberately *not* `SO_REUSEADDR`: the namespace's port space is empty, so a conflict would
    // mean something unexpected already holds the port, and that should fail loudly rather than be
    // shared.
    Ok(OwnedFd::from(listener))
}

/// Send one descriptor over a Unix socket with `SCM_RIGHTS`.
pub(crate) fn send_descriptor(
    socket: &std::os::unix::net::UnixStream,
    descriptor: &OwnedFd,
) -> Result<(), ContainmentError> {
    let payload = *b"L";
    let mut io = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };

    // The control buffer must be large enough for one descriptor, and aligned for
    // `cmsghdr`. A `u64` array gives both without an explicit alignment attribute.
    let mut control = [0u64; 4];
    let control_bytes = std::mem::size_of_val(&control);

    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut io,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control_bytes,
        msg_flags: 0,
    };

    // SAFETY: `message.msg_control` points at `control`, which is large enough for
    // one `cmsghdr` plus one `c_int` and outlives this block.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(failure(
                "building the SCM_RIGHTS control message: no header space".to_string(),
            ));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            descriptor.as_raw_fd(),
        );
        message.msg_controllen = (*header).cmsg_len;

        let sent = libc::sendmsg(socket.as_raw_fd(), &message, 0);
        if sent < 0 {
            return Err(failure(format!(
                "passing the listening descriptor to the box: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Receive one descriptor sent with [`send_descriptor`].
#[cfg(test)]
pub(crate) fn receive_descriptor(
    socket: &std::os::unix::net::UnixStream,
) -> Result<OwnedFd, ContainmentError> {
    let mut payload = [0u8; 1];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = [0u64; 4];

    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut io,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&control),
        msg_flags: 0,
    };

    // SAFETY: every pointer in `message` refers to a local that outlives the call.
    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(failure(format!(
            "receiving the listening descriptor: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: reading back the control message the kernel just wrote.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(failure(
                "the peer sent no descriptor; without it there is no egress route \
                 and the workload would fail every request"
                    .to_string(),
            ));
        }
        let raw = std::ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>());
        if raw < 0 {
            return Err(failure("received an invalid descriptor".to_string()));
        }
        Ok(OwnedFd::from_raw_fd(raw))
    }
}

/// `struct ifreq`, with only the two fields this module uses.
#[repr(C)]
struct InterfaceRequest {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    /// `struct ifreq`'s union is 24 bytes; `flags` uses 2, so 22 remain.
    padding: [u8; 22],
}

impl InterfaceRequest {
    fn for_loopback() -> Self {
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        // "lo", NUL-terminated by the zero initialization above.
        name[0] = b'l' as libc::c_char;
        name[1] = b'o' as libc::c_char;
        Self {
            name,
            flags: 0,
            padding: [0; 22],
        }
    }
}

use std::os::fd::FromRawFd as _;

/// A failure in the egress transport, carrying this backend's mechanism name.
fn failure(reason: String) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: MECHANISM.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    /// The whole transport claim, in one test: a listener created inside a fresh network namespace
    /// is accepted on from *outside* that namespace, while the namespace itself has no other route.
    #[test]
    fn a_listener_made_inside_a_netns_is_accepted_from_outside_it() {
        if !super::super::probe::user_namespace_is_permitted() {
            println!("skipping: this host forbids user namespaces");
            return;
        }

        let (box_side, child_side) =
            std::os::unix::net::UnixStream::pair().expect("control socketpair");

        // SAFETY: the child enters new namespaces and exits; it never returns into
        // test-harness code.
        let child = unsafe { libc::fork() };
        assert_ne!(child, -1, "fork failed");

        if child == 0 {
            drop(box_side);
            // Read the ids BEFORE the unshare: inside a fresh user namespace with no map yet,
            // `getuid()` returns the overflow uid (65534) and mapping that is refused with EPERM.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            // SAFETY: irreversible for this child only.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(10) };
            }
            let _ = std::fs::write("/proc/self/setgroups", "deny");
            let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
            let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));
            // SAFETY: irreversible for this child only.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                // SAFETY: terminating the child.
                unsafe { libc::_exit(11) };
            }

            let outcome = (|| -> Result<u8, ContainmentError> {
                bring_up_loopback()?;
                // Port 0 lets the kernel choose, then the child reports it: a
                // fixed port would make concurrent test runs collide.
                let listener = listen_on_loopback(0)?;
                let bound = {
                    let borrowed = std::net::TcpListener::from(
                        listener.try_clone().expect("clone the listener"),
                    );
                    let port = borrowed.local_addr().expect("bound address").port();
                    std::mem::forget(borrowed);
                    port
                };

                send_descriptor(&child_side, &listener)?;
                drop(listener);

                let mut control = child_side.try_clone().expect("clone control");
                control.write_all(&bound.to_be_bytes()).expect("send port");

                let mut ready = [0u8; 1];
                control.read_exact(&mut ready).expect("await ready");

                // The workload's connect: this is what Codex does to reach the proxy.
                let mut upstream =
                    std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, bound))
                        .expect("connect to the relay endpoint");
                upstream.write_all(b"PING").expect("write ping");
                let mut reply = [0u8; 4];
                upstream.read_exact(&mut reply).expect("read pong");
                if &reply != b"PONG" {
                    return Ok(12);
                }

                // And nothing else is reachable: no route exists at all.
                let elsewhere = std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([169, 254, 169, 254], 80)),
                    std::time::Duration::from_secs(2),
                );
                if elsewhere.is_ok() {
                    return Ok(13);
                }

                Ok(0)
            })()
            .unwrap_or(14);

            // SAFETY: terminating the child with a status the parent reads.
            unsafe { libc::_exit(i32::from(outcome)) };
        }

        drop(child_side);

        let listener = receive_descriptor(&box_side).expect("receive the listening descriptor");

        let mut control = box_side.try_clone().expect("clone control");
        let mut port_bytes = [0u8; 2];
        control.read_exact(&mut port_bytes).expect("read the port");
        let _port = u16::from_be_bytes(port_bytes);

        let listener = std::net::TcpListener::from(listener);
        control.write_all(b"R").expect("signal ready");

        let (mut connection, _peer) = listener.accept().expect(
            "accepting from the host namespace on a socket created inside the child's \
             namespace is the whole transport claim",
        );
        let mut request = [0u8; 4];
        connection.read_exact(&mut request).expect("read ping");
        assert_eq!(&request, b"PING");
        connection.write_all(b"PONG").expect("write pong");

        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(libc::WIFEXITED(status), "the child must exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "transport failed (10=no userns, 11=no netns, 12=wrong reply, \
             13=another address was reachable so the namespace did not isolate, \
             14=a transport call errored)"
        );
    }
}
