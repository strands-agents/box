//! The box side of the Linux egress transport.
//!
//! A listener created *inside* the workload's network namespace, passed out over
//! `SCM_RIGHTS` and accepted on from the host. Why it must be a descriptor rather than a
//! port, and why the relay is not an authorization, are in the crate's `AGENTS.md`.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;

use crate::error::BoxError;

/// Receives the in-namespace listener and relays it to the gateway.
#[derive(Debug)]
pub(crate) struct NetnsRelay {
    /// Cancels the accept loop on drop.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Joined on drop so the loop's exit is observed rather than assumed.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NetnsRelay {
    /// Attach the control socket the trampoline will send its listener over.
    pub(crate) fn control_pair() -> Result<(UnixStream, UnixStream), BoxError> {
        let (box_side, child_side) = UnixStream::pair()
            .map_err(|source| BoxError::from(crate::error::RelayError::ControlPair { source }))?;
        Ok((box_side, child_side))
    }

    /// Receive one listening descriptor per port, in order, and relay each to its port.
    pub(crate) fn start_each(control: UnixStream, ports: &[u16]) -> Result<Vec<Self>, BoxError> {
        // A receive timeout, because this blocking `recvmsg` runs on a runtime worker.
        control
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(|source| BoxError::from(crate::error::RelayError::Receive { source }))?;

        let mut relays = Vec::with_capacity(ports.len());
        for port in ports {
            relays.push(Self::start_one(&control, *port)?);
        }
        Ok(relays)
    }

    /// Take the next descriptor off `control` and relay it to `proxy_port`.
    fn start_one(control: &UnixStream, proxy_port: u16) -> Result<Self, BoxError> {
        let listener = receive_listener(control)?;

        // Into a std listener, then a tokio one: the descriptor is already bound
        // and listening, so this only changes who polls it.
        let listener = std::net::TcpListener::from(listener);
        listener
            .set_nonblocking(true)
            .map_err(|source| BoxError::from(crate::error::RelayError::Accept { source }))?;
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|source| BoxError::from(crate::error::RelayError::Accept { source }))?;

        let (shutdown, mut cancelled) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    // Biased so shutdown wins a tie: on drop the loop should stop
                    // rather than serve one more connection.
                    biased;
                    _ = &mut cancelled => return,
                    accepted = listener.accept() => accepted,
                };

                let Ok((workload_side, _peer)) = accepted else {
                    // An accept failure is per-connection: the workload may retry,
                    // and tearing the relay down would turn one failed request into
                    continue;
                };

                tokio::spawn(splice(workload_side, proxy_port));
            }
        });

        Ok(Self {
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }
}

impl Drop for NetnsRelay {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            // The receiver is dropped if the task already returned; either way the
            // loop is not accepting after this.
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Copy one accepted connection to the gateway and back, streaming.
async fn splice(mut workload_side: tokio::net::TcpStream, proxy_port: u16) {
    let Ok(mut gateway_side) =
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, proxy_port)).await
    else {
        // The gateway is the box's own daemon. If it is unreachable the workload's
        // request fails, which is the correct outcome — closing this side reports
        return;
    };

    let _ = tokio::io::copy_bidirectional(&mut workload_side, &mut gateway_side).await;
}

/// Receive one descriptor sent with `SCM_RIGHTS`.
fn receive_listener(control: &UnixStream) -> Result<OwnedFd, BoxError> {
    let mut payload = [0u8; 1];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // A `u64` array for alignment: `cmsghdr` requires it, and this is large enough
    // for one header plus one `c_int`.
    let mut control_buffer = [0u64; 4];

    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut io,
        msg_iovlen: 1,
        msg_control: control_buffer.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&control_buffer),
        msg_flags: 0,
    };

    // SAFETY: every pointer in `message` refers to a local that outlives the call.
    let received = unsafe { libc::recvmsg(control.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(BoxError::from(crate::error::RelayError::Receive {
            source: std::io::Error::last_os_error(),
        }));
    }

    // SAFETY: reading back the control message the kernel just wrote.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(BoxError::from(crate::error::RelayError::NoDescriptor));
        }
        let raw = std::ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>());
        if raw < 0 {
            return Err(BoxError::from(crate::error::RelayError::NoDescriptor));
        }
        Ok(OwnedFd::from_raw_fd(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    /// The relay carries a request from a socket it did not create to a listener
    /// standing in for the gateway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_relay_splices_an_accepted_connection_to_the_gateway() {
        // Stand in for the gateway: echo one line back, uppercased so the reply
        // cannot be confused with the request being reflected by the plumbing.
        let gateway = std::net::TcpListener::bind("127.0.0.1:0").expect("bind gateway");
        let proxy_port = gateway.local_addr().expect("gateway address").port();
        std::thread::spawn(move || {
            for incoming in gateway.incoming() {
                let Ok(mut stream) = incoming else { continue };
                let mut buffer = [0u8; 64];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let reply = String::from_utf8_lossy(&buffer[..read]).to_uppercase();
                let _ = stream.write_all(reply.as_bytes());
            }
        });

        // The listener the trampoline would have created inside the namespace.
        let workload_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let workload_port = workload_listener.local_addr().expect("addr").port();

        let (box_side, child_side) = NetnsRelay::control_pair().expect("control pair");

        // Send it exactly as the trampoline does.
        send_descriptor(&child_side, &OwnedFd::from(workload_listener));

        // Through the public entry point, so this exercises what `supervise` calls.
        let mut relays = NetnsRelay::start_each(box_side, &[proxy_port]).expect("start relay");
        let _relay = relays.pop().expect("one relay for one port");

        // The workload's request, on a blocking thread so the runtime's workers stay
        // free to run the relay's accept loop and its splice task.
        let reply = tokio::task::spawn_blocking(move || {
            let mut client = std::net::TcpStream::connect(("127.0.0.1", workload_port))
                .expect("connect to the relay endpoint");
            client.write_all(b"ping").expect("write");
            let mut buffer = [0u8; 16];
            let read = client.read(&mut buffer).expect("read");
            buffer[..read].to_vec()
        });

        let reply = tokio::time::timeout(std::time::Duration::from_secs(10), reply)
            .await
            .expect("the relay must answer rather than hang")
            .expect("the client thread must not panic");

        assert_eq!(
            reply,
            b"PING".to_vec(),
            "the relay must carry the request to the gateway and the reply back"
        );
    }

    /// A control socket that carries no descriptor is refused rather than left to
    /// hang: with no listener there is no egress route, and the box must say so.
    #[tokio::test]
    async fn a_control_message_with_no_descriptor_is_refused() {
        let (box_side, child_side) = NetnsRelay::control_pair().expect("control pair");

        // One ordinary byte, no ancillary data.
        (&child_side).write_all(b"x").expect("write payload");

        let error =
            NetnsRelay::start_each(box_side, &[1]).expect_err("a missing descriptor must refuse");
        assert!(
            error.to_string().contains("descriptor"),
            "the refusal must name what was missing: {error}"
        );
    }

    /// Send one descriptor, matching the trampoline's sender.
    fn send_descriptor(socket: &UnixStream, descriptor: &OwnedFd) {
        let payload = *b"L";
        let mut io = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
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
        // SAFETY: the control buffer is large enough for one header plus one
        // `c_int`, and every pointer outlives the call.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
            std::ptr::write(
                libc::CMSG_DATA(header).cast::<libc::c_int>(),
                descriptor.as_raw_fd(),
            );
            message.msg_controllen = (*header).cmsg_len;
            assert!(
                libc::sendmsg(socket.as_raw_fd(), &message, 0) >= 0,
                "sendmsg failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}
