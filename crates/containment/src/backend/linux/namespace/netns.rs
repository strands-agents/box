//! The transport across the network namespace: egress listeners out, and sockets for inbound connections.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

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

/// Send one listening descriptor over a Unix socket with `SCM_RIGHTS`.
pub(crate) fn send_descriptor(
    socket: &std::os::unix::net::UnixStream,
    descriptor: &OwnedFd,
) -> Result<(), ContainmentError> {
    send_tagged_descriptor(socket, descriptor, LISTENER_TAG)
}

/// The payload byte beside an egress listener.
const LISTENER_TAG: u8 = b'L';
/// The payload byte beside a new, unconnected socket for an inbound connection.
const SOCKET_TAG: u8 = b'S';
/// The payload byte that answers a socket request with no descriptor.
const REFUSED_TAG: u8 = b'E';
/// The request byte for an IPv4 socket.
const IPV4_REQUEST: u8 = b'4';
/// The byte PID 1 sends once, when it starts answering socket requests.
const READY_TAG: u8 = b'R';

/// Send one descriptor over a Unix socket with `SCM_RIGHTS`, beside `tag`.
fn send_tagged_descriptor(
    socket: &std::os::unix::net::UnixStream,
    descriptor: &OwnedFd,
    tag: u8,
) -> Result<(), ContainmentError> {
    let payload = [tag];
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

/// Mark `descriptor` close-on-exec, so the workload's `exec` closes the copy it inherits.
pub(crate) fn close_on_exec(descriptor: std::os::fd::RawFd) -> Result<(), ContainmentError> {
    // SAFETY: `fcntl` on a descriptor number, with scalar arguments.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags == -1
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1
    {
        return Err(failure(format!(
            "marking the handoff socket close-on-exec: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Answer each socket request on `handoff` until the box closes it.
///
/// [`READY_TAG`] goes first, so the box starts no relay before this loop answers. A request is
/// [`IPV4_REQUEST`]. The answer is a new, unconnected IPv4 TCP socket created in this
/// namespace, or [`REFUSED_TAG`] alone when no socket can be created. Any other byte ends the loop. Creating a
/// socket does not block, so a workload that accepts nothing cannot stall this loop.
pub(crate) fn serve_inbound(handoff: std::os::unix::net::UnixStream) {
    use std::io::{Read as _, Write as _};
    let mut handoff = handoff;
    if handoff.write_all(&[READY_TAG]).is_err() {
        return;
    }
    loop {
        let mut request = [0u8; 1];
        if handoff.read_exact(&mut request).is_err() {
            return;
        }
        if request[0] != IPV4_REQUEST {
            return;
        }
        // SAFETY: `socket` with scalar arguments; a non-negative result is a new descriptor.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let answered = if raw < 0 {
            handoff.write_all(&[REFUSED_TAG]).is_ok()
        } else {
            // SAFETY: `raw` is a descriptor this process just opened and owns.
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };
            send_tagged_descriptor(&handoff, &socket, SOCKET_TAG).is_ok()
        };
        if !answered {
            return;
        }
    }
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

    /// A caller that arrives before PID 1's connector starts waits in the listen queue, and it and
    /// the next caller are served once the connector answers, even when the connector starts later
    /// than one answer may take.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connector_that_starts_late_serves_the_caller_that_arrived_first() {
        let workload = std::net::TcpListener::bind("127.0.0.1:0").expect("bind workload");
        let workload_port = workload.local_addr().expect("address").port();
        std::thread::spawn(move || {
            for incoming in workload.incoming() {
                let Ok(mut stream) = incoming else { continue };
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 16];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    let _ = stream.write_all(&buffer[..read].to_ascii_uppercase());
                });
            }
        });
        let public = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let public_port = public.local_addr().expect("address").port();

        let (box_side, pid_one) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(6));
            serve_inbound(pid_one);
        });

        let call = move |request: &'static [u8]| {
            std::thread::spawn(move || {
                let mut caller =
                    std::net::TcpStream::connect(("127.0.0.1", public_port)).expect("connect");
                caller.write_all(request).expect("write");
                let mut reply = Vec::new();
                let _ = caller.read_to_end(&mut reply);
                reply
            })
        };
        let first = call(b"early");

        let workloads = tokio::task::spawn_blocking(move || {
            ingress::Workload::in_namespace_ports(box_side, &[workload_port])
        })
        .await
        .expect("join")
        .expect("PID 1 reports ready");
        let workload = workloads.into_iter().next().expect("one workload");
        let _relay = ingress::Ingress::start(ingress::IngressConfig::new(
            ingress::Source::tcp(public),
            workload,
        ))
        .expect("start the relay");

        let joined = |caller: std::thread::JoinHandle<Vec<u8>>| async move {
            tokio::task::spawn_blocking(move || caller.join().expect("caller"))
                .await
                .expect("join")
        };
        assert_eq!(joined(first).await, b"EARLY");
        assert_eq!(joined(call(b"later")).await, b"LATER");
    }

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
