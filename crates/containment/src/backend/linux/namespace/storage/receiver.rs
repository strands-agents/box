//! Persistent source observation and explicitly authorized protected publication.

use super::protocol::{ControllerCommand, GenerationRequest, HelperEvent, StorageLayout};
use super::target::PinnedTarget;
use super::worker::Child;
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(test))]
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    CloningSnapshot,
    Compiling,
    CloningStage,
    Staging,
    Prepared,
    Committing,
}

struct Snapshot {
    generation: u64,
    roots: Vec<u32>,
    phase: Phase,
}

#[derive(Default)]
struct State {
    last_generation: u64,
    snapshot: Option<Snapshot>,
    published: BTreeSet<u32>,
    published_dependencies: BTreeSet<u32>,
    completed_roots: BTreeSet<u32>,
    launch_released: bool,
}

impl State {
    fn snapshot(&mut self, generation: u64, roots: Vec<u32>) -> Result<(), ContainmentError> {
        if self.snapshot.is_some()
            || generation == 0
            || generation <= self.last_generation
            || roots.is_empty()
        {
            return Err(failure(
                "snapshot needs a new transaction and at least one captured root",
            ));
        }
        if !self
            .published_dependencies
            .iter()
            .all(|root| roots.contains(root))
        {
            return Err(failure("snapshot forgot a published source dependency"));
        }
        self.last_generation = generation;
        self.snapshot = Some(Snapshot {
            generation,
            roots,
            phase: Phase::CloningSnapshot,
        });
        Ok(())
    }
    fn require(&self, generation: u64, phase: Phase) -> Result<&Snapshot, ContainmentError> {
        self.snapshot
            .as_ref()
            .filter(|snapshot| snapshot.generation == generation && snapshot.phase == phase)
            .ok_or_else(|| failure("storage command does not match the active transaction phase"))
    }
    fn prepare(
        &mut self,
        request: &GenerationRequest,
        targets: usize,
    ) -> Result<(), ContainmentError> {
        request.validate()?;
        let snapshot = self.require(request.generation, Phase::Compiling)?;
        if request.captured_roots != snapshot.roots {
            return Err(failure(
                "generation must use the complete frozen compiler snapshot",
            ));
        }
        if request
            .targets
            .iter()
            .any(|index| *index as usize >= targets || self.published.contains(index))
        {
            return Err(failure(
                "generation names an unknown or already published target",
            ));
        }
        self.snapshot.as_mut().expect("snapshot was checked").phase = Phase::CloningStage;
        Ok(())
    }
    fn release(&mut self, generation: u64) -> Result<(), ContainmentError> {
        let roots = self.require(generation, Phase::Compiling)?.roots.clone();
        self.completed_roots.extend(roots);
        self.snapshot = None;
        Ok(())
    }
    fn release_launch(&mut self, required: &BTreeSet<u32>) -> Result<(), ContainmentError> {
        if self.launch_released
            || self.snapshot.is_some()
            || !required.is_subset(&self.completed_roots)
        {
            return Err(failure(
                "workload startup needs every required source protected exactly once",
            ));
        }
        self.launch_released = true;
        Ok(())
    }
    fn commit(&mut self, generation: u64) -> Result<(), ContainmentError> {
        self.require(generation, Phase::Prepared)?;
        self.snapshot.as_mut().expect("snapshot was checked").phase = Phase::Committing;
        Ok(())
    }
    fn published(&mut self, generation: u64, targets: &[u32]) -> Result<(), ContainmentError> {
        let roots = self.require(generation, Phase::Committing)?.roots.clone();
        self.published.extend(targets.iter().copied());
        self.completed_roots.extend(roots.iter().copied());
        self.published_dependencies.extend(roots);
        self.snapshot = None;
        Ok(())
    }
}

enum ClonePurpose {
    Snapshot,
    Stage(GenerationRequest),
}
struct CloneJob {
    purpose: ClonePurpose,
    roots: Vec<u32>,
    clones: BTreeMap<u32, OwnedFd>,
}

impl CloneJob {
    fn start(
        purpose: ClonePurpose,
        roots: Vec<u32>,
        sources: &UnixStream,
    ) -> Result<Self, ContainmentError> {
        sources::request_clones(sources, &roots)?;
        Ok(Self {
            purpose,
            roots,
            clones: BTreeMap::new(),
        })
    }
    fn waiting_for(&self, root: u32) -> bool {
        self.roots.contains(&root) && !self.clones.contains_key(&root)
    }
    fn complete(&self) -> bool {
        self.clones.len() == self.roots.len()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum StageEvent {
    Prepared,
    Published,
    Failed { message: String },
}

struct Stage {
    child: Child,
    control: UnixStream,
    generation: u64,
    targets: Vec<u32>,
}

fn send_stage(control: &UnixStream, event: &StageEvent) -> Result<(), ContainmentError> {
    let json = serde_json::to_string(event).map_err(|error| failure(error.to_string()))?;
    transport::send_text(control, &json)
}

impl Stage {
    fn start(
        layout: &StorageLayout,
        request: GenerationRequest,
        clones: BTreeMap<u32, OwnedFd>,
        namespace: &OwnedFd,
        targets: &mut [Option<PinnedTarget>],
        published: &BTreeSet<u32>,
    ) -> Result<Self, ContainmentError> {
        let (control, worker_control) = UnixStream::pair().map_err(io_failure)?;
        // SAFETY: the receiver is single-threaded; this child never returns to its event loop.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io_failure(std::io::Error::last_os_error()));
        }
        if pid == 0 {
            drop(control);
            let result = (|| {
                let mut keep = vec![0, 1, 2, worker_control.as_raw_fd(), namespace.as_raw_fd()];
                keep.extend(clones.values().map(AsRawFd::as_raw_fd));
                for index in &request.targets {
                    keep.extend(
                        targets[*index as usize]
                            .as_ref()
                            .ok_or_else(|| failure("publication target is unavailable"))?
                            .descriptors(),
                    );
                }
                authority::close_inherited_descriptors(&keep)?;
                if !reaper::arm_parent_death(&worker_control) {
                    return Err(failure("staging worker parent-death handshake failed"));
                }
                let sources = request
                    .captured_roots
                    .iter()
                    .map(|index| {
                        (
                            layout.roots[*index as usize].as_path(),
                            clones[index].as_raw_fd(),
                        )
                    })
                    .collect::<Vec<_>>();
                production::install_sources(&sources)?;
                // Every captured source is installed before deserialization can resolve a path.
                let config = ContainmentConfig::from_json(&request.config_json)?;
                crate::floors::require_all(&config)?;
                config.require_live_path_identities()?;
                let remaining = layout
                    .masks
                    .iter()
                    .filter(|mask| {
                        !layout.targets.iter().enumerate().any(|(index, target)| {
                            target == *mask
                                && (published.contains(&(index as u32))
                                    || request.targets.contains(&(index as u32)))
                        })
                    })
                    .map(|mask| (mask.path.clone(), mask.scope))
                    .collect::<Vec<_>>();
                let view = MountView::plan(&config)?.with_pending_masks(&remaining)?;
                let paths = request
                    .targets
                    .iter()
                    .map(|index| layout.targets[*index as usize].path.clone())
                    .collect::<Vec<_>>();
                let protected = view.stage_projections(&paths)?;
                send_stage(&worker_control, &StageEvent::Prepared)?;
                let mut command = [0];
                (&worker_control)
                    .read_exact(&mut command)
                    .map_err(io_failure)?;
                if command != *b"C" {
                    return Err(failure(
                        "publication needs an explicit commit authorization",
                    ));
                }
                // SAFETY: namespace and root are the launch-time descriptors in this same owning user namespace.
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
                    return Err(io_failure(std::io::Error::last_os_error()));
                }
                targets[request.targets[0] as usize]
                    .as_ref()
                    .expect("validated target")
                    .adopt_root()?;
                for (index, projection) in request.targets.iter().zip(&protected) {
                    targets[*index as usize]
                        .take()
                        .ok_or_else(|| failure("target was already consumed"))?
                        .publish(projection)?;
                }
                send_stage(&worker_control, &StageEvent::Published)
            })();
            if let Err(error) = &result {
                let _ = send_stage(
                    &worker_control,
                    &StageEvent::Failed {
                        message: error.to_string(),
                    },
                );
            }
            // SAFETY: this disposable publisher never returns to receiver code.
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
        }
        drop(worker_control);
        let stage = Self {
            child: Child::new(pid),
            control,
            generation: request.generation,
            targets: request.targets,
        };
        if !reaper::confirm_parent_death(&stage.control) {
            return Err(failure(
                "staging worker did not acknowledge parent-death protection",
            ));
        }
        Ok(stage)
    }
}

#[derive(Default)]
struct Capture {
    source: Option<(protocol::SourceIdentity, String)>,
    reported: bool,
}

fn report_captures(workers: &mut [Capture], control: &UnixStream) -> Result<(), ContainmentError> {
    for (index, worker) in workers.iter_mut().enumerate() {
        if !worker.reported
            && let Some((identity, filesystem)) = &worker.source
        {
            protocol::send_event(
                control,
                &HelperEvent::Captured {
                    root: index as u32,
                    identity: identity.clone(),
                    filesystem: filesystem.clone(),
                },
            )?;
            worker.reported = true;
        }
    }
    Ok(())
}

pub(super) fn run(
    layout: &StorageLayout,
    control: &UnixStream,
    registration: &UnixStream,
    lifetime: &UnixStream,
    sources: &UnixStream,
) -> Result<bool, ContainmentError> {
    let sources::Event::Initialized { required } = sources::receive_event(sources)? else {
        return Err(failure(
            "source subscription did not establish its launch cutoff",
        ));
    };
    let initial: BTreeSet<_> = required.iter().copied().collect();
    if initial.len() != required.len()
        || required
            .iter()
            .any(|index| *index as usize >= layout.roots.len())
    {
        return Err(failure("source subscription has invalid initial roots"));
    }
    let namespace = transport::receive_fd(registration)?;
    let view = transport::receive_fd(registration)?;
    let mut targets = layout
        .targets
        .iter()
        .map(|target| PinnedTarget::receive(registration, &target.path, target.scope).map(Some))
        .collect::<Result<Vec<_>, _>>()?;
    protocol::send_event(control, &HelperEvent::ViewReady { required })?;
    transport::send_fd(control, &view)?;
    drop(view);
    let mut workers: Vec<_> = layout.roots.iter().map(|_| Capture::default()).collect();
    let mut state = State::default();
    let mut job: Option<CloneJob> = None;
    let mut stage: Option<Stage> = None;
    loop {
        if state.snapshot.is_none() {
            report_captures(&mut workers, control)?;
        }
        let mut descriptors = vec![
            libc::pollfd {
                fd: lifetime.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
        ];
        descriptors.push(libc::pollfd {
            fd: sources.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        });
        if let Some(stage) = &stage {
            descriptors.push(libc::pollfd {
                fd: stage.control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            });
        }
        // SAFETY: every descriptor stays owned throughout this single-threaded poll.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                -1,
            )
        };
        if result < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(io_failure(std::io::Error::last_os_error()));
        }
        // Workload completion outranks a concurrently closed controller socket.
        if descriptors[0].revents != 0 {
            let mut signal = [0];
            (&*lifetime).read_exact(&mut signal).map_err(io_failure)?;
            if signal == *b"D" {
                return Ok(true);
            }
            return Err(failure("invalid launcher lifetime signal"));
        }
        if descriptors[2].revents != 0 {
            match sources::receive_event(sources)? {
                sources::Event::Captured {
                    root,
                    identity,
                    filesystem,
                } => {
                    let capture = workers
                        .get_mut(root as usize)
                        .ok_or_else(|| failure("source event has an unknown root"))?;
                    if capture.source.is_some() {
                        return Err(failure("source root was captured twice"));
                    }
                    capture.source = Some((identity, filesystem));
                }
                sources::Event::Cloned { root } => {
                    let job = job
                        .as_mut()
                        .filter(|job| job.waiting_for(root))
                        .ok_or_else(|| failure("source cache sent an unrequested clone"))?;
                    job.clones.insert(root, transport::receive_fd(sources)?);
                }
                sources::Event::Initialized { .. } => {
                    return Err(failure("source subscription initialized twice"));
                }
            }
        }
        if job.as_ref().is_some_and(CloneJob::complete) {
            let finished = job.take().expect("completed clone job");
            match finished.purpose {
                ClonePurpose::Snapshot => {
                    let snapshot = state.snapshot.as_mut().expect("clone job owns a snapshot");
                    protocol::send_event(
                        control,
                        &HelperEvent::Snapshot {
                            generation: snapshot.generation,
                            captured_roots: snapshot.roots.clone(),
                        },
                    )?;
                    for index in &snapshot.roots {
                        transport::send_fd(control, &finished.clones[index])?;
                    }
                    snapshot.phase = Phase::Compiling;
                }
                ClonePurpose::Stage(request) => {
                    state
                        .snapshot
                        .as_mut()
                        .expect("staging owns a snapshot")
                        .phase = Phase::Staging;
                    stage = Some(Stage::start(
                        layout,
                        request,
                        finished.clones,
                        &namespace,
                        &mut targets,
                        &state.published,
                    )?);
                }
            }
        }
        if let Some(active) = stage.as_mut()
            && descriptors.get(3).is_some_and(|event| event.revents != 0)
        {
            let event: StageEvent =
                serde_json::from_str(&transport::receive_text(&active.control, CONTROL_LIMIT)?)
                    .map_err(|error| failure(format!("invalid staging event: {error}")))?;
            match event {
                StageEvent::Prepared => {
                    state.require(active.generation, Phase::Staging)?;
                    state
                        .snapshot
                        .as_mut()
                        .expect("staging owns a snapshot")
                        .phase = Phase::Prepared;
                    protocol::send_event(
                        control,
                        &HelperEvent::Prepared {
                            generation: active.generation,
                            targets: active.targets.clone(),
                        },
                    )?;
                }
                StageEvent::Published => {
                    state.published(active.generation, &active.targets)?;
                    protocol::send_event(
                        control,
                        &HelperEvent::Published {
                            generation: active.generation,
                            targets: active.targets.clone(),
                        },
                    )?;
                    active.child.wait()?;
                    stage = None;
                }
                StageEvent::Failed { message } => return Err(failure(message)),
            }
        }
        if descriptors[1].revents != 0 {
            match protocol::receive_command(control)? {
                ControllerCommand::Initialize(_) => {
                    return Err(failure("storage layout cannot change after launch"));
                }
                ControllerCommand::Snapshot { generation } => {
                    // Include captures already reported to this controller, in permanent index order.
                    let roots = workers
                        .iter()
                        .enumerate()
                        .filter(|(_, worker)| worker.reported)
                        .map(|(index, _)| index as u32)
                        .collect();
                    state.snapshot(generation, roots)?;
                    job = Some(CloneJob::start(
                        ClonePurpose::Snapshot,
                        state
                            .snapshot
                            .as_ref()
                            .expect("snapshot created")
                            .roots
                            .clone(),
                        sources,
                    )?);
                }
                ControllerCommand::Release { generation } => {
                    state.release(generation)?;
                }
                ControllerCommand::Prepare(request) => {
                    state.prepare(&request, targets.len())?;
                    for index in &request.targets {
                        if layout.roots.iter().enumerate().any(|(root_index, root)| {
                            layout.targets[*index as usize].path.starts_with(root)
                                && !request.captured_roots.contains(&(root_index as u32))
                        }) {
                            return Err(failure(
                                "publication target belongs to an uncaptured source",
                            ));
                        }
                    }
                    job = Some(CloneJob::start(
                        ClonePurpose::Stage(request),
                        state
                            .snapshot
                            .as_ref()
                            .expect("snapshot exists")
                            .roots
                            .clone(),
                        sources,
                    )?);
                }
                ControllerCommand::Commit { generation } => {
                    state.commit(generation)?;
                    let active = stage
                        .as_ref()
                        .ok_or_else(|| failure("commit has no staging worker"))?;
                    (&active.control).write_all(b"C").map_err(io_failure)?;
                }
                ControllerCommand::ReleaseLaunch => {
                    state.release_launch(&initial)?;
                    (&*registration).write_all(b"R").map_err(io_failure)?;
                }
                ControllerCommand::Abort => return Ok(false),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn launch_release_waits_for_initial_sources_but_not_absent_sources() {
        let mut state = State::default();
        assert!(state.release_launch(&BTreeSet::from([0])).is_err());
        state.snapshot(1, vec![0]).unwrap();
        assert!(state.release_launch(&BTreeSet::from([0])).is_err());
        state.snapshot.as_mut().unwrap().phase = Phase::Compiling;
        state.release(1).unwrap();
        state.release_launch(&BTreeSet::from([0])).unwrap();
        assert!(state.release_launch(&BTreeSet::from([0])).is_err());
        assert!(!state.completed_roots.contains(&1));
        let mut absent = State::default();
        absent.release_launch(&BTreeSet::new()).unwrap();
    }

    #[test]
    fn prepared_sources_do_not_release_launch_until_publication_completes() {
        let mut state = State::default();
        state.snapshot(1, vec![0]).unwrap();
        state.snapshot.as_mut().unwrap().phase = Phase::Prepared;
        assert!(state.release_launch(&BTreeSet::from([0])).is_err());
        state.commit(1).unwrap();
        assert!(state.release_launch(&BTreeSet::from([0])).is_err());
        state.published(1, &[0]).unwrap();
        state.release_launch(&BTreeSet::from([0])).unwrap();
    }
    use super::*;
    fn request(generation: u64, roots: Vec<u32>, targets: Vec<u32>) -> GenerationRequest {
        GenerationRequest {
            generation,
            captured_roots: roots,
            targets,
            config_json: "{}".into(),
        }
    }
    #[test]
    fn snapshot_requires_complete_sources_and_commit_requires_preparation() {
        let mut state = State::default();
        state.snapshot(1, vec![0, 2]).unwrap();
        assert!(state.commit(1).is_err());
        state.snapshot.as_mut().unwrap().phase = Phase::Compiling;
        assert!(state.prepare(&request(1, vec![0], vec![0]), 3).is_err());
        state.prepare(&request(1, vec![0, 2], vec![0]), 3).unwrap();
        assert!(state.commit(1).is_err());
        assert!(state.release(1).is_err());
        state.snapshot.as_mut().unwrap().phase = Phase::Prepared;
        state.commit(1).unwrap();
        state.published(1, &[0]).unwrap();
        assert!(state.snapshot(2, vec![2]).is_err());
        state.snapshot(2, vec![0, 1, 2]).unwrap();
        state.snapshot.as_mut().unwrap().phase = Phase::Compiling;
        assert!(
            state
                .prepare(&request(2, vec![0, 1, 2], vec![0]), 3)
                .is_err()
        );
        state
            .prepare(&request(2, vec![0, 1, 2], vec![1]), 3)
            .unwrap();
    }
    #[test]
    fn no_target_snapshot_releases_without_forgetting_generation_order() {
        let mut state = State::default();
        state.snapshot(3, vec![1]).unwrap();
        state.snapshot.as_mut().unwrap().phase = Phase::Compiling;
        state.release(3).unwrap();
        assert!(state.snapshot(3, vec![1]).is_err());
        state.snapshot(4, vec![0, 1]).unwrap();
    }
}
