//! One-shot descriptor handoff into a dedicated container PID namespace.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 65536;
const MAX_FDS: usize = 8;
const FD_FLAGS: &[&str] = &["--config-fd", "--setup-status-fd", "--relay-control-fd"];
static SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    version: u8,
    arguments: Vec<String>,
    working_directory: std::path::PathBuf,
    descriptors: Vec<i32>,
}

pub(super) fn dispatch(args: &[String]) -> Option<io::Result<u8>> {
    match args.first().map(String::as_str) {
        Some("--connect-container") if args.len() > 2 => {
            Some(connect(Path::new(&args[1]), &args[2..]))
        }
        Some("--receive-container") if args.len() == 2 => Some(receive(Path::new(&args[1]))),
        _ => None,
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

fn peer(stream: &UnixStream) -> io::Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: getsockopt receives the initialized credential buffer and its length.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&credentials)
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err(invalid("container peer has a different identity"));
    }
    Ok(())
}

fn connect(path: &Path, arguments: &[String]) -> io::Result<u8> {
    let parsed = super::Args::parse(arguments.iter().cloned())
        .map_err(|_| invalid("invalid container launch arguments"))?;
    if parsed.launch_gate_fd.is_some()
        || parsed.container_lifetime_fd.is_some()
        || parsed.config_fd.is_none()
    {
        return Err(invalid(
            "container launch requires an opened config and no pre-existing control channel",
        ));
    }
    let mut descriptors = vec![0, 1, 2];
    descriptors.extend(
        [
            parsed.config_fd,
            parsed.setup_status_fd,
            parsed.relay_control_fd,
        ]
        .into_iter()
        .flatten(),
    );
    let image = std::fs::File::open("/proc/self/exe")?;
    let mut sending = descriptors.clone();
    sending.push(image.as_raw_fd());
    let payload = Launch {
        version: 1,
        arguments: arguments.to_vec(),
        working_directory: std::env::current_dir()?,
        descriptors,
    };
    let bytes = serde_json::to_vec(&payload)?;
    if bytes.len() > MAX_FRAME {
        return Err(invalid("container launch exceeds the frame limit"));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match UnixStream::connect(path) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error),
        }
    };
    peer(&stream)?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    send_descriptors(&stream, &sending)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    drop(image);
    for descriptor in sending
        .into_iter()
        .skip(3)
        .take(payload.descriptors.len() - 3)
    {
        // SAFETY: the receiver owns duplicates of these launch descriptors.
        unsafe { libc::close(descriptor) };
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler only stores an atomic integer.
        unsafe { libc::signal(signal, remember_signal as *const () as libc::sighandler_t) };
    }
    let mut bytes = [0_u8; 4];
    let mut read = 0;
    loop {
        let signal = SIGNAL.swap(0, Ordering::Relaxed);
        if signal != 0 {
            stream.write_all(&[signal as u8])?;
        }
        let mut poll = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized pollfd.
        let result = unsafe { libc::poll(&mut poll, 1, 50) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if result > 0 {
            let n = stream.read(&mut bytes[read..])?;
            if n == 0 {
                return Err(invalid("container exited without a workload result"));
            }
            read += n;
            if read == bytes.len() {
                return u8::try_from(i32::from_be_bytes(bytes))
                    .map_err(|_| invalid("invalid container exit status"));
            }
        }
    }
}

extern "C" fn remember_signal(signal: i32) {
    SIGNAL.store(signal, Ordering::Relaxed);
}

fn receive(path: &Path) -> io::Result<u8> {
    if unsafe { libc::getpid() } != 1 || unsafe { libc::getppid() } != 0 {
        return Err(invalid("container receiver must be private PID 1"));
    }
    if !path.is_absolute() {
        return Err(invalid("container socket must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("container socket has no parent"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !parent.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "container socket directory must be private and owned by the launcher",
        ));
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "existing container socket is not owned by the launcher",
            ));
        }
        match UnixStream::connect(path) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)?
            }
            _ => return Err(invalid("container socket is already active")),
        }
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    };
    peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let descriptors = receive_descriptors(&stream)?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(invalid("container launch exceeds the frame limit"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    let mut launch: Launch = serde_json::from_slice(&bytes)?;
    if launch.version != 1
        || launch.descriptors.len() + 1 != descriptors.len()
        || launch.descriptors.get(..3) != Some(&[0, 1, 2])
    {
        return Err(invalid("invalid container launch descriptor map"));
    }
    let parsed = super::Args::parse(launch.arguments.iter().cloned())
        .map_err(|_| invalid("invalid container launch arguments"))?;
    let mut expected = vec![0, 1, 2];
    expected.extend(
        [
            parsed.config_fd,
            parsed.setup_status_fd,
            parsed.relay_control_fd,
        ]
        .into_iter()
        .flatten(),
    );
    if expected != launch.descriptors
        || parsed.config_fd.is_none()
        || parsed.container_lifetime_fd.is_some()
        || parsed.launch_gate_fd.is_some()
    {
        return Err(invalid(
            "container launch descriptors do not match arguments",
        ));
    }
    std::fs::remove_file(path)?;
    drop(listener);
    for (index, descriptor) in descriptors.iter().take(3).enumerate() {
        // SAFETY: all received descriptors are owned and above the standard streams.
        if unsafe { libc::dup2(descriptor.as_raw_fd(), index as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let delimiter = launch
        .arguments
        .iter()
        .position(|value| value == "--")
        .ok_or_else(|| invalid("missing workload delimiter"))?;
    for index in 0..delimiter {
        if FD_FLAGS.contains(&launch.arguments[index].as_str()) {
            let old: i32 = launch.arguments[index + 1]
                .parse()
                .map_err(|_| invalid("invalid descriptor argument"))?;
            let position = launch
                .descriptors
                .iter()
                .position(|candidate| *candidate == old)
                .ok_or_else(|| invalid("unmapped descriptor"))?;
            launch.arguments[index + 1] = descriptors[position].as_raw_fd().to_string();
            inherit(descriptors[position].as_raw_fd())?;
        }
    }
    stream.set_read_timeout(None)?;
    inherit(stream.as_raw_fd())?;
    launch.arguments.splice(
        0..0,
        [
            "--container-lifetime-fd".to_string(),
            stream.as_raw_fd().to_string(),
        ],
    );
    let image = descriptors
        .last()
        .ok_or_else(|| invalid("missing trampoline image"))?;
    let error = std::process::Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
        .args(&launch.arguments)
        .env_clear()
        .current_dir(&launch.working_directory)
        .exec();
    Err(error)
}

fn inherit(descriptor: i32) -> io::Result<()> {
    // SAFETY: the descriptor is owned by this launcher.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_descriptors(stream: &UnixStream, descriptors: &[i32]) -> io::Result<()> {
    if descriptors.len() > MAX_FDS {
        return Err(invalid("too many launch descriptors"));
    }
    let mut byte = 1_u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 32];
    let bytes = std::mem::size_of_val(descriptors);
    // SAFETY: the control buffer is aligned and larger than CMSG_SPACE for MAX_FDS.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(bytes as u32) as usize;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(bytes as u32) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            bytes,
        );
        if libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn receive_descriptors(stream: &UnixStream) -> io::Result<Vec<OwnedFd>> {
    let mut byte = 0_u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 32];
    // SAFETY: every buffer is aligned, writable, and sized for the declared receive length.
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        if libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) != 1 {
            return Err(io::Error::last_os_error());
        }
        let mut result = Vec::new();
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
                return Err(invalid("unexpected container ancillary message"));
            }
            let bytes = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
            for index in 0..bytes / std::mem::size_of::<i32>() {
                let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index));
                result.push(OwnedFd::from_raw_fd(fd));
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        if byte != 1 || message.msg_flags & libc::MSG_CTRUNC != 0 || result.len() > MAX_FDS {
            return Err(invalid("invalid container descriptor message"));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_handoff_preserves_the_opened_file_and_cloexec() {
        let (sender, receiver) = UnixStream::pair().expect("transport");
        let mut file = tempfile::tempfile().expect("file");
        file.write_all(b"opened identity").expect("write");
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).expect("rewind");
        send_descriptors(&sender, &[file.as_raw_fd()]).expect("send");
        let mut descriptors = receive_descriptors(&receiver).expect("receive");
        assert_eq!(descriptors.len(), 1);
        let flags = unsafe { libc::fcntl(descriptors[0].as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop(file);
        let mut received = std::fs::File::from(descriptors.remove(0));
        let mut bytes = String::new();
        received.read_to_string(&mut bytes).expect("read identity");
        assert_eq!(bytes, "opened identity");
    }

    #[test]
    fn unframed_transport_data_is_refused() {
        let (mut sender, receiver) = UnixStream::pair().expect("transport");
        sender.write_all(b"X").expect("invalid frame");
        assert!(receive_descriptors(&receiver).is_err());
    }

    #[test]
    fn ordinary_process_cannot_be_a_container_receiver() {
        assert!(receive(Path::new("/no-socket-created")).is_err());
    }
}
