use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use super::{ConnectError, connect_loopback};
use crate::{IngressError, Workload};

/// The request byte for an IPv4 socket.
const IPV4_REQUEST: u8 = b'4';
/// The answer byte beside a new, unconnected socket.
const SOCKET_TAG: u8 = b'S';
/// The answer byte when PID 1 has no socket.
const REFUSED_TAG: u8 = b'E';
/// The byte PID 1 sends once, when it starts answering.
const READY_TAG: u8 = b'R';

/// How long PID 1 may take to answer, which it does without blocking.
const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long the namespace setup may take before PID 1 starts answering.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Asks the namespace's PID 1 for a socket in that namespace for each connection, over the channel
/// the trampoline carried in, and connects it to the workload.
///
/// The channel is `None` once an exchange on it fails, because a reply that arrives after a
/// timeout would answer the next request.
#[derive(Debug)]
pub(super) struct InNamespace {
    channel: Arc<Mutex<Option<UnixStream>>>,
    pub(super) port: u16,
}

impl Workload {
    /// The workload's `port` in its own network namespace, reached through sockets that PID 1 on
    /// `channel` creates there.
    pub fn in_namespace(channel: UnixStream, port: u16) -> Result<Self, IngressError> {
        let mut workloads = Self::in_namespace_ports(channel, &[port])?;
        Ok(workloads.remove(0))
    }

    /// One workload for each of `ports` in one network namespace, all reached through sockets
    /// that PID 1 on the one `channel` creates there. Blocks until PID 1 is ready.
    pub fn in_namespace_ports(
        channel: UnixStream,
        ports: &[u16],
    ) -> Result<Vec<Self>, IngressError> {
        channel.set_read_timeout(Some(READY_TIMEOUT))?;
        match receive_tagged(&channel) {
            Ok((READY_TAG, None)) => {}
            _ => return Err(IngressError::NotReady),
        }
        channel.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        let channel = Arc::new(Mutex::new(Some(channel)));
        Ok(ports
            .iter()
            .map(|&port| {
                Self(InNamespace {
                    channel: Arc::clone(&channel),
                    port,
                })
            })
            .collect())
    }
}

impl InNamespace {
    pub(super) async fn connect(&self) -> Result<tokio::net::TcpStream, ConnectError> {
        let channel = Arc::clone(&self.channel);
        let socket = tokio::task::spawn_blocking(move || ask(&channel))
            .await
            .map_err(|_| ConnectError::Fatal)??;
        socket
            .set_nonblocking(true)
            .map_err(|_| ConnectError::Fatal)?;
        connect_loopback(tokio::net::TcpSocket::from_std_stream(socket), self.port).await
    }
}

/// Ask PID 1 for an unconnected IPv4 stream socket, and check what comes back.
fn ask(channel: &Mutex<Option<UnixStream>>) -> Result<std::net::TcpStream, ConnectError> {
    let mut guard = channel.lock().map_err(|_| ConnectError::Fatal)?;
    let Some(socket) = guard.as_ref() else {
        return Err(ConnectError::Fatal);
    };
    let answered = (|| {
        let mut writer = socket;
        writer
            .write_all(&[IPV4_REQUEST])
            .map_err(|_| ConnectError::Fatal)?;
        receive_tagged(socket)
    })();
    let (tag, descriptor) = match answered {
        Ok(answer) => answer,
        Err(error) => {
            *guard = None;
            return Err(error);
        }
    };
    match (tag, descriptor) {
        (REFUSED_TAG, None) => Err(ConnectError::NotReady),
        (SOCKET_TAG, Some(descriptor)) if is_ipv4_stream_socket(&descriptor) => {
            Ok(std::net::TcpStream::from(descriptor))
        }
        (SOCKET_TAG, Some(_)) => Err(ConnectError::Fatal),
        _ => {
            *guard = None;
            Err(ConnectError::Fatal)
        }
    }
}

/// Whether `descriptor` is an `AF_INET` `SOCK_STREAM` socket.
fn is_ipv4_stream_socket(descriptor: &OwnedFd) -> bool {
    let option = |name: libc::c_int| {
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes one `c_int` into `value`, whose size is `length`.
        let read = unsafe {
            libc::getsockopt(
                descriptor.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        (read == 0).then_some(value)
    };
    option(libc::SO_TYPE) == Some(libc::SOCK_STREAM)
        && option(libc::SO_DOMAIN) == Some(libc::AF_INET)
}

/// Receive one tag byte, and the descriptor sent beside it with `SCM_RIGHTS`, if any.
fn receive_tagged(channel: &UnixStream) -> Result<(u8, Option<OwnedFd>), ConnectError> {
    let mut payload = [0u8; 1];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // A `u64` array for alignment: `cmsghdr` requires it, and this is large enough for one header
    // plus one `c_int`.
    let mut control_buffer = [0u64; 4];
    // SAFETY: an all-zero `msghdr` is valid; the fields this call reads are set below.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io;
    message.msg_iovlen = 1;
    message.msg_control = control_buffer.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control_buffer) as _;

    // SAFETY: every pointer in `message` refers to a local that outlives the call.
    let received =
        unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received <= 0 {
        return Err(ConnectError::Fatal);
    }

    // SAFETY: reading back the control message the kernel just wrote.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Ok((payload[0], None));
        }
        if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
            return Err(ConnectError::Fatal);
        }
        let raw = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>());
        if raw < 0 {
            return Err(ConnectError::Fatal);
        }
        Ok((payload[0], Some(OwnedFd::from_raw_fd(raw))))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Read as _;

    use super::*;

    /// One answer the fake PID 1 gives to one request.
    #[derive(Clone, Copy)]
    pub(crate) enum Answer {
        /// Create an IPv4 stream socket and send it.
        Socket,
        /// Answer that there is no socket.
        Refuse,
        /// Send a datagram socket instead.
        Datagram,
        /// Send an IPv6 stream socket instead.
        Ipv6,
        /// Send a tag the protocol does not define.
        Garbage,
        /// Close the channel.
        Close,
    }

    /// A channel whose far end is a thread answering as PID 1 does, one answer per request.
    pub(crate) fn fake_pid_one(answers: Vec<Answer>) -> UnixStream {
        fake_pid_one_after(std::time::Duration::ZERO, Some(READY_TAG), answers)
    }

    /// As [`fake_pid_one`], with `first` sent after `delay` in place of the ready byte, or
    /// nothing sent at all.
    pub(crate) fn fake_pid_one_after(
        delay: std::time::Duration,
        first: Option<u8>,
        answers: Vec<Answer>,
    ) -> UnixStream {
        let (box_side, pid_one) = UnixStream::pair().expect("socket pair");
        std::thread::spawn(move || {
            let mut pid_one = pid_one;
            std::thread::sleep(delay);
            match first {
                Some(byte) => pid_one.write_all(&[byte]).expect("first byte"),
                None => return,
            }
            for answer in answers {
                let mut request = [0u8; 1];
                if pid_one.read_exact(&mut request).is_err() {
                    return;
                }
                match answer {
                    Answer::Socket => send_tagged(
                        &pid_one,
                        SOCKET_TAG,
                        &socket(libc::AF_INET, libc::SOCK_STREAM),
                    ),
                    Answer::Datagram => send_tagged(
                        &pid_one,
                        SOCKET_TAG,
                        &socket(libc::AF_INET, libc::SOCK_DGRAM),
                    ),
                    Answer::Ipv6 => send_tagged(
                        &pid_one,
                        SOCKET_TAG,
                        &socket(libc::AF_INET6, libc::SOCK_STREAM),
                    ),
                    Answer::Refuse => pid_one.write_all(&[REFUSED_TAG]).expect("refuse"),
                    Answer::Garbage => pid_one.write_all(b"?").expect("garbage"),
                    Answer::Close => return,
                }
            }
        });
        box_side
    }

    fn socket(domain: libc::c_int, kind: libc::c_int) -> OwnedFd {
        // SAFETY: `socket` with scalar arguments; a non-negative result is a new descriptor.
        let raw = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
        assert!(
            raw >= 0,
            "socket failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: `raw` is a descriptor this process just opened and owns.
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    /// Send one tag byte and one descriptor, matching PID 1's sender.
    fn send_tagged(socket: &UnixStream, tag: u8, descriptor: &OwnedFd) {
        let payload = [tag];
        let mut io = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0u64; 4];
        // SAFETY: an all-zero `msghdr` is valid; the fields `sendmsg` reads are set below, and the
        // control buffer holds one header plus one `c_int`.
        unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut io;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = std::mem::size_of_val(&control) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(
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

    fn listener(address: &str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind(address).expect("bind");
        let port = listener.local_addr().expect("address").port();
        (listener, port)
    }

    #[tokio::test]
    async fn the_relay_connects_the_socket_pid_one_sends() {
        let (_workload, port) = listener("127.0.0.1:0");
        let workload = Workload::in_namespace(fake_pid_one(vec![Answer::Socket]), port).unwrap();
        let stream = workload
            .connect()
            .await
            .expect("the connection is accepted");
        assert_eq!(stream.peer_addr().unwrap(), super::super::loopback(port));
    }

    #[tokio::test]
    async fn workloads_on_one_channel_each_reach_their_own_port() {
        let (_first, first_port) = listener("127.0.0.1:0");
        let (_second, second_port) = listener("127.0.0.1:0");
        let channel = fake_pid_one(vec![Answer::Socket, Answer::Socket]);
        let workloads = Workload::in_namespace_ports(channel, &[first_port, second_port]).unwrap();
        let first = workloads[0]
            .connect()
            .await
            .expect("the first port answers");
        let second = workloads[1]
            .connect()
            .await
            .expect("the second port answers");
        assert_eq!(
            first.peer_addr().unwrap(),
            super::super::loopback(first_port)
        );
        assert_eq!(
            second.peer_addr().unwrap(),
            super::super::loopback(second_port)
        );
    }

    #[tokio::test]
    async fn nothing_listening_is_not_ready_and_the_channel_stays_open() {
        let (held, port) = crate::workload::refusing_port();
        let answers = vec![Answer::Socket, Answer::Socket, Answer::Socket];
        let workload = Workload::in_namespace(fake_pid_one(answers), port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::NotReady));

        drop(held);
        let _workload = std::net::TcpListener::bind(("127.0.0.1", port)).expect("rebind");
        assert!(
            workload.connect().await.is_ok(),
            "the next caller is served once the workload listens"
        );
    }

    #[tokio::test]
    async fn no_socket_is_not_ready() {
        let channel = fake_pid_one(vec![Answer::Refuse]);
        let (_held, port) = crate::workload::refusing_port();
        let workload = Workload::in_namespace(channel, port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::NotReady));
    }

    #[tokio::test]
    async fn a_socket_that_is_not_a_stream_is_refused() {
        let (_workload, port) = listener("127.0.0.1:0");
        let workload = Workload::in_namespace(fake_pid_one(vec![Answer::Datagram]), port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::Fatal));
    }

    #[tokio::test]
    async fn an_ipv6_socket_is_refused() {
        let (_workload, port) = listener("127.0.0.1:0");
        let workload = Workload::in_namespace(fake_pid_one(vec![Answer::Ipv6]), port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::Fatal));
    }

    #[tokio::test]
    async fn an_undefined_answer_closes_the_channel() {
        let (_workload, port) = listener("127.0.0.1:0");
        let channel = fake_pid_one(vec![Answer::Garbage, Answer::Socket]);
        let workload = Workload::in_namespace(channel, port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::Fatal));
        assert_eq!(
            workload.connect().await.err(),
            Some(ConnectError::Fatal),
            "a channel that sent an undefined answer is not asked again"
        );
    }

    #[tokio::test]
    async fn the_workloads_wait_until_pid_one_is_ready() {
        let (_workload, port) = listener("127.0.0.1:0");
        let delay = std::time::Duration::from_millis(300);
        let channel = fake_pid_one_after(delay, Some(READY_TAG), vec![Answer::Socket]);
        let started = std::time::Instant::now();
        let workloads = Workload::in_namespace_ports(channel, &[port]).unwrap();
        assert!(
            started.elapsed() >= delay,
            "no workload exists before PID 1 is ready"
        );
        assert!(workloads[0].connect().await.is_ok());
    }

    #[test]
    fn a_channel_that_closes_before_ready_is_refused() {
        let channel = fake_pid_one_after(std::time::Duration::ZERO, None, Vec::new());
        assert!(matches!(
            Workload::in_namespace_ports(channel, &[1]),
            Err(IngressError::NotReady)
        ));
    }

    #[test]
    fn a_first_byte_that_is_not_ready_is_refused() {
        let channel = fake_pid_one_after(std::time::Duration::ZERO, Some(SOCKET_TAG), Vec::new());
        assert!(matches!(
            Workload::in_namespace_ports(channel, &[1]),
            Err(IngressError::NotReady)
        ));
    }

    #[tokio::test]
    async fn a_closed_channel_is_fatal() {
        let (_workload, port) = listener("127.0.0.1:0");
        let workload = Workload::in_namespace(fake_pid_one(vec![Answer::Close]), port).unwrap();
        assert_eq!(workload.connect().await.err(), Some(ConnectError::Fatal));
    }
}
