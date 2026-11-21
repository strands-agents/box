//! One Box's distinct source caches and recipient subscriptions.

use super::protocol::{SourceIdentity, VERSION};
use super::worker::Worker;
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(not(test))]
use std::io::{Read as _, Write as _};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Initialization {
    version: u16,
    roots: Vec<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subscription {
    roots: Vec<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Status {
    Ready { version: u16 },
    Failed { message: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Event {
    Initialized {
        required: Vec<u32>,
    },
    Captured {
        root: u32,
        identity: SourceIdentity,
        filesystem: String,
    },
    Cloned {
        root: u32,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloneRequest {
    roots: Vec<u32>,
}

fn send<T: Serialize>(control: &UnixStream, value: &T) -> Result<(), ContainmentError> {
    transport::send_text(
        control,
        &serde_json::to_string(value).map_err(|error| failure(error.to_string()))?,
    )
}

fn receive<T: serde::de::DeserializeOwned>(control: &UnixStream) -> Result<T, ContainmentError> {
    serde_json::from_str(&transport::receive_text(control, CONTROL_LIMIT)?)
        .map_err(|error| failure(format!("invalid source-helper frame: {error}")))
}

/// Initialize the private source helper before registering recipients.
pub fn initialize(control: &UnixStream, roots: &[PathBuf]) -> Result<(), ContainmentError> {
    send(
        control,
        &Initialization {
            version: VERSION,
            roots: roots.to_vec(),
        },
    )?;
    match receive(control)? {
        Status::Ready { version: VERSION } => Ok(()),
        Status::Failed { message } => Err(failure(message)),
        _ => Err(failure("source helper has an incompatible protocol")),
    }
}

/// Give one recipient its own source subscription without granting filesystem access.
pub fn subscribe(control: &UnixStream, roots: &[PathBuf]) -> Result<UnixStream, ContainmentError> {
    let (recipient, helper) = UnixStream::pair().map_err(io_failure)?;
    send(
        control,
        &Subscription {
            roots: roots.to_vec(),
        },
    )?;
    transport::send_fd(control, &helper.into())?;
    Ok(recipient)
}

/// Monitor the Box-owned source helper until it fails or its owner closes the channel.
pub fn monitor(control: &UnixStream) -> Result<(), ContainmentError> {
    match receive(control)? {
        Status::Failed { message } => Err(failure(message)),
        Status::Ready { .. } => Err(failure("source helper initialized twice")),
    }
}

pub(super) fn receive_event(control: &UnixStream) -> Result<Event, ContainmentError> {
    receive(control)
}

pub(super) fn request_clones(control: &UnixStream, roots: &[u32]) -> Result<(), ContainmentError> {
    send(
        control,
        &CloneRequest {
            roots: roots.to_vec(),
        },
    )
}

struct Source {
    worker: Worker,
    waiting: VecDeque<(u64, u32)>,
}

enum Output {
    Bytes { bytes: Vec<u8>, written: usize },
    Descriptor { root: u32, descriptor: OwnedFd },
}

struct Recipient {
    control: UnixStream,
    roots: Vec<usize>,
    pending: BTreeSet<u32>,
    input: Vec<u8>,
    output: VecDeque<Output>,
}

impl Recipient {
    fn new(control: UnixStream, roots: Vec<usize>) -> Result<Self, ContainmentError> {
        control.set_nonblocking(true).map_err(io_failure)?;
        Ok(Self {
            control,
            roots,
            pending: BTreeSet::new(),
            input: Vec::new(),
            output: VecDeque::new(),
        })
    }

    fn event(&mut self, event: &Event) -> Result<(), ContainmentError> {
        let json = serde_json::to_vec(event).map_err(|error| failure(error.to_string()))?;
        if json.len() > CONTROL_LIMIT {
            return Err(failure("source event exceeds frame limit"));
        }
        let mut bytes = (json.len() as u32).to_be_bytes().to_vec();
        bytes.extend(json);
        self.output.push_back(Output::Bytes { bytes, written: 0 });
        Ok(())
    }

    fn captured(&mut self, index: u32, source: &Source) -> Result<(), ContainmentError> {
        let (identity, filesystem) = source.worker.source.as_ref().expect("captured source");
        self.event(&Event::Captured {
            root: index,
            identity: identity.clone(),
            filesystem: filesystem.clone(),
        })
    }

    fn flush(&mut self) -> Result<(), ContainmentError> {
        while let Some(frame) = self.output.front_mut() {
            match frame {
                Output::Bytes { bytes, written } => match (&self.control).write(&bytes[*written..])
                {
                    Ok(0) => {
                        return Err(ContainmentError::StorageControlIo {
                            source: std::io::ErrorKind::BrokenPipe.into(),
                        });
                    }
                    Ok(count) => {
                        *written += count;
                        if *written < bytes.len() {
                            continue;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(source) => return Err(ContainmentError::StorageControlIo { source }),
                },
                Output::Descriptor { root, descriptor } => {
                    match transport::send_fd(&self.control, descriptor) {
                        Ok(()) => {
                            self.pending.remove(root);
                        }
                        Err(ContainmentError::StorageControlIo { source })
                            if source.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            self.output.pop_front();
        }
        Ok(())
    }

    fn requests(&mut self) -> Result<Vec<CloneRequest>, ContainmentError> {
        let mut requests = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            match (&self.control).read(&mut buffer) {
                Ok(0) => {
                    return Err(ContainmentError::StorageControlIo {
                        source: std::io::ErrorKind::UnexpectedEof.into(),
                    });
                }
                Ok(count) => self.input.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(ContainmentError::StorageControlIo { source }),
            }
            while self.input.len() >= 4 {
                let length =
                    u32::from_be_bytes(self.input[..4].try_into().expect("four bytes")) as usize;
                if length > CONTROL_LIMIT {
                    return Err(failure("source request exceeds frame limit"));
                }
                if self.input.len() < length + 4 {
                    break;
                }
                requests.push(
                    serde_json::from_slice(&self.input[4..length + 4])
                        .map_err(|error| failure(format!("invalid source request: {error}")))?,
                );
                self.input.drain(..length + 4);
            }
            if !requests.is_empty() {
                break;
            }
        }
        Ok(requests)
    }
}

fn logical_root(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && !path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
}

fn validate_roots(roots: &[PathBuf]) -> Result<(), ContainmentError> {
    if roots.is_empty()
        || roots.iter().any(|root| !logical_root(root))
        || roots.iter().collect::<BTreeSet<_>>().len() != roots.len()
    {
        return Err(failure(
            "source helper requires distinct absolute storage roots",
        ));
    }
    Ok(())
}

fn disconnected(error: &ContainmentError) -> bool {
    matches!(error, ContainmentError::StorageControlIo { source }
        if matches!(source.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof))
}

/// Run only in the fresh private executable owned by one Box.
pub fn serve(control: &UnixStream) -> Result<(), ContainmentError> {
    let result = serve_inner(control);
    if let Err(error) = &result {
        let _ = send(
            control,
            &Status::Failed {
                message: error.to_string(),
            },
        );
    }
    result
}

fn serve_inner(control: &UnixStream) -> Result<(), ContainmentError> {
    if std::fs::read_dir("/proc/self/task")
        .map_err(io_failure)?
        .count()
        != 1
    {
        return Err(failure(
            "source helper requires a fresh single-threaded executable",
        ));
    }
    let initialization: Initialization = receive(control)?;
    if initialization.version != VERSION {
        return Err(failure("source helper has an incompatible protocol"));
    }
    validate_roots(&initialization.roots)?;
    super::super::enter_namespaces(true)?;
    // The new user namespace needs this process to own its UID/GID mapping files. Marking it
    // non-dumpable before namespace creation makes those proc files root-owned on non-root hosts.
    authority::refuse_process_memory_access()?;
    propagation(libc::MS_SLAVE)?;
    authority::retain_storage_mount_access()?;
    authority::set_no_new_privileges()?;
    let roots = initialization.roots;
    let mut sources = roots
        .iter()
        .map(|root| {
            Ok(Source {
                worker: Worker::spawn(root)?,
                waiting: VecDeque::new(),
            })
        })
        .collect::<Result<Vec<_>, ContainmentError>>()?;
    send(control, &Status::Ready { version: VERSION })?;
    control.set_read_timeout(None).map_err(io_failure)?;
    let mut recipients = BTreeMap::<u64, Recipient>::new();
    let mut next_recipient = 0_u64;
    loop {
        let keys: Vec<_> = recipients.keys().copied().collect();
        let mut descriptors = vec![libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        }];
        descriptors.extend(sources.iter().map(|source| libc::pollfd {
            fd: source.worker.control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        }));
        descriptors.extend(keys.iter().map(|key| libc::pollfd {
            fd: recipients[key].control.as_raw_fd(),
            events: libc::POLLIN
                | libc::POLLRDHUP
                | if recipients[key].output.is_empty() {
                    0
                } else {
                    libc::POLLOUT
                },
            revents: 0,
        }));
        // SAFETY: the helper owns every descriptor during this single-threaded poll.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                -1,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io_failure(std::io::Error::last_os_error()));
        }
        if descriptors[0].revents != 0 {
            if descriptors[0].revents & (libc::POLLHUP | libc::POLLRDHUP) != 0 {
                return Ok(());
            }
            let subscription: Subscription = receive(control)?;
            let socket = UnixStream::from(transport::receive_fd(control)?);
            validate_roots(&subscription.roots)?;
            let indices = subscription
                .roots
                .iter()
                .map(|root| {
                    roots
                        .iter()
                        .position(|candidate| candidate == root)
                        .ok_or_else(|| failure("recipient requested an undeclared source"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let table = mountinfo::MountTable::read(
                std::fs::File::open("/proc/self/mountinfo").map_err(io_failure)?,
            )
            .map_err(|error| failure(error.to_string()))?;
            let mut required = Vec::new();
            for (local, global) in indices.iter().copied().enumerate() {
                if sources[global].worker.source.is_some()
                    || table
                        .has_storage_at(&roots[global])
                        .map_err(|error| failure(error.to_string()))?
                {
                    required.push(local as u32);
                }
            }
            let mut recipient = Recipient::new(socket, indices)?;
            recipient.event(&Event::Initialized { required })?;
            for local in 0..recipient.roots.len() {
                let global = recipient.roots[local];
                if sources[global].worker.source.is_some() {
                    recipient.captured(local as u32, &sources[global])?;
                }
            }
            next_recipient = next_recipient
                .checked_add(1)
                .ok_or_else(|| failure("source subscriber count overflow"))?;
            recipients.insert(next_recipient, recipient);
        }
        for (index, source) in sources.iter_mut().enumerate() {
            if descriptors[1 + index].revents == 0 {
                continue;
            }
            if source.worker.source.is_none() {
                source.worker.capture()?;
                for recipient in recipients.values_mut() {
                    if let Some(local) = recipient.roots.iter().position(|global| *global == index)
                    {
                        recipient.captured(local as u32, source)?;
                    }
                }
            } else {
                let clone = transport::receive_fd(&source.worker.control)?;
                if complete_clone(&mut source.waiting, &mut recipients, clone)? {
                    source.worker.request_clone()?;
                }
            }
        }
        for (offset, key) in keys.into_iter().enumerate() {
            let events = descriptors[1 + sources.len() + offset].revents;
            if events == 0 || !recipients.contains_key(&key) {
                continue;
            }
            if events & (libc::POLLHUP | libc::POLLRDHUP) != 0 {
                recipients.remove(&key);
                continue;
            }
            let recipient = recipients.get_mut(&key).expect("recipient exists");
            let result = (|| {
                if events & libc::POLLOUT != 0 {
                    recipient.flush()?;
                }
                if events & libc::POLLIN == 0 {
                    return Ok(());
                }
                for request in recipient.requests()? {
                    if request.roots.is_empty()
                        || request.roots.iter().collect::<BTreeSet<_>>().len()
                            != request.roots.len()
                    {
                        return Err(failure(
                            "source clone request needs distinct captured roots",
                        ));
                    }
                    for local in &request.roots {
                        let global = recipient
                            .roots
                            .get(*local as usize)
                            .ok_or_else(|| failure("source clone request has an unknown root"))?;
                        if sources[*global].worker.source.is_none()
                            || recipient.pending.contains(local)
                        {
                            return Err(failure(
                                "source clone request is pending or has no capture",
                            ));
                        }
                    }
                    for local in request.roots {
                        let global = recipient.roots[local as usize];
                        recipient.pending.insert(local);
                        sources[global].waiting.push_back((key, local));
                        if sources[global].waiting.len() == 1 {
                            sources[global].worker.request_clone()?;
                        }
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => {}
                Err(error) if disconnected(&error) => {
                    recipients.remove(&key);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Consume exactly the in-flight completion before advancing past canceled queued recipients.
fn complete_clone(
    waiting: &mut VecDeque<(u64, u32)>,
    recipients: &mut BTreeMap<u64, Recipient>,
    clone: OwnedFd,
) -> Result<bool, ContainmentError> {
    let (key, local) = waiting
        .pop_front()
        .ok_or_else(|| failure("source cache sent an unrequested clone"))?;
    if let Some(recipient) = recipients.get_mut(&key) {
        if !recipient.pending.contains(&local) {
            return Err(failure("source clone has no recipient request"));
        }
        recipient.event(&Event::Cloned { root: local })?;
        recipient.output.push_back(Output::Descriptor {
            root: local,
            descriptor: clone,
        });
    }
    while waiting
        .front()
        .is_some_and(|(recipient, _)| !recipients.contains_key(recipient))
    {
        waiting.pop_front();
    }
    Ok(!waiting.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt as _;

    #[test]
    fn source_roots_deduplicate_without_imposing_cross_recipient_overlap_rules() {
        assert!(validate_roots(&["/incoming".into(), "/incoming/nested".into()]).is_ok());
        assert!(validate_roots(&["/incoming".into(), "/incoming".into()]).is_err());
        for invalid in ["/", "relative", "/incoming/../other", "/incoming/./other"] {
            assert!(validate_roots(&[invalid.into()]).is_err(), "{invalid}");
        }
    }

    #[test]
    fn slow_recipient_output_does_not_block_other_recipients() {
        let (slow, _unread) = UnixStream::pair().unwrap();
        let mut slow = Recipient::new(slow, vec![0]).unwrap();
        // Check the production socket before filling it. A test-only write timeout would mask a
        // regression to blocking I/O by returning WouldBlock after the timeout instead.
        // SAFETY: F_GETFL reads flags from the live socket owned by this recipient.
        let flags = unsafe { libc::fcntl(slow.control.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "recipient output must never block"
        );
        assert_eq!(slow.control.write_timeout().unwrap(), None);
        for _ in 0..256 {
            slow.event(&Event::Captured {
                root: 0,
                identity: SourceIdentity {
                    device: 1,
                    inode: 2,
                    mount_id: 3,
                },
                filesystem: "fuse.".to_owned() + &"x".repeat(4096),
            })
            .unwrap();
        }
        slow.flush().unwrap();
        assert!(
            !slow.output.is_empty(),
            "control must actually fill the socket"
        );
        let (fast, reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut fast = Recipient::new(fast, vec![0]).unwrap();
        fast.event(&Event::Initialized { required: vec![0] })
            .unwrap();
        fast.flush().unwrap();
        assert!(fast.output.is_empty());
        assert!(
            matches!(receive_event(&reader).unwrap(), Event::Initialized { required } if required == vec![0])
        );
    }

    #[test]
    fn recipient_requests_preserve_partial_frames_and_reject_oversize_frames() {
        let (writer, socket) = UnixStream::pair().unwrap();
        let mut recipient = Recipient::new(socket, vec![0]).unwrap();
        let json = serde_json::to_vec(&CloneRequest { roots: vec![0] }).unwrap();
        let mut frame = (json.len() as u32).to_be_bytes().to_vec();
        frame.extend(json);
        let last = frame.len() - 1;
        for (index, byte) in frame.into_iter().enumerate() {
            (&writer).write_all(&[byte]).unwrap();
            let requests = recipient.requests().unwrap();
            if index == last {
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].roots, vec![0]);
            } else {
                assert!(requests.is_empty());
            }
        }
        (&writer)
            .write_all(&((CONTROL_LIMIT + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(recipient.requests().is_err());
    }

    #[test]
    fn canceled_clone_completion_preserves_the_next_recipients_queued_clone() {
        let (socket, reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut live = Recipient::new(socket, vec![1, 0]).unwrap();
        live.pending.insert(1);
        let mut recipients = BTreeMap::from([(2, live)]);
        // Recipient 1 disconnected while its clone was in flight. Recipient 3 disconnected while
        // queued. The next live recipient maps this source to its own local root index 1.
        let mut waiting = VecDeque::from([(1, 0), (3, 0), (2, 1)]);
        let first: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(complete_clone(&mut waiting, &mut recipients, first).unwrap());
        assert_eq!(waiting, VecDeque::from([(2, 1)]));
        assert!(
            recipients[&2].output.is_empty(),
            "canceled completion reached another recipient"
        );
        assert_eq!(recipients[&2].pending, BTreeSet::from([1]));

        let mut expected = tempfile::tempfile().unwrap();
        expected.write_all(b"the second recipient's clone").unwrap();
        std::io::Seek::rewind(&mut expected).unwrap();
        assert!(!complete_clone(&mut waiting, &mut recipients, expected.into()).unwrap());
        let live = recipients.get_mut(&2).unwrap();
        live.flush().unwrap();
        assert!(matches!(
            receive_event(&reader).unwrap(),
            Event::Cloned { root: 1 }
        ));
        let mut received = std::fs::File::from(transport::receive_fd(&reader).unwrap());
        let mut contents = String::new();
        received.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "the second recipient's clone");
        assert!(live.pending.is_empty());
        assert!(waiting.is_empty());
    }

    #[test]
    fn clone_frames_transfer_one_descriptor_and_complete_the_pending_request() {
        let (socket, reader) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut recipient = Recipient::new(socket, vec![0]).unwrap();
        recipient.pending.insert(0);
        recipient.event(&Event::Cloned { root: 0 }).unwrap();
        recipient.output.push_back(Output::Descriptor {
            root: 0,
            descriptor: std::fs::File::open("/dev/null").unwrap().into(),
        });
        recipient.flush().unwrap();
        assert!(recipient.pending.is_empty());
        assert!(matches!(
            receive_event(&reader).unwrap(),
            Event::Cloned { root: 0 }
        ));
        let descriptor = transport::receive_fd(&reader).unwrap();
        assert!(
            std::fs::File::from(descriptor)
                .metadata()
                .unwrap()
                .file_type()
                .is_char_device()
        );
    }
}
