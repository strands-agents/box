//! One normal launch's receiver, with whole-Box failure and cancellation ownership.

use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use super::{LaunchPlan, StorageLayout as CompiledLayout};
use crate::error::{BoxError, SuperviseError};
use crate::record::config::filesystem::FilesystemTargetKind;
use crate::run::hosted::storage::{Cancellation, StorageOwner};
use containment::Scope;
use containment::storage::{
    self as wire, ControllerCommand, GenerationRequest, HelperEvent, StorageLayout, StorageTarget,
};

/// A socket handed to the private launcher and an owned controller started after spawn.
pub(crate) struct Receiver {
    child: Option<UnixStream>,
    parent: Option<UnixStream>,
    plan: Arc<LaunchPlan>,
    owner: StorageOwner,
    cancel: Arc<Cancellation>,
    sources: Option<UnixStream>,
}

impl Receiver {
    pub(crate) fn prepare(plan: Arc<LaunchPlan>, owner: StorageOwner) -> Result<Self, BoxError> {
        owner.check()?;
        let (parent, child) = UnixStream::pair().map_err(io_error)?;
        let cancel = Arc::new(Cancellation::default());
        cancel.track(&parent).map_err(io_error)?;
        let sources = owner.subscribe_sources(&plan.policy.roots)?;
        Ok(Self {
            child: Some(child),
            parent: Some(parent),
            plan,
            owner,
            cancel,
            sources: Some(sources),
        })
    }

    pub(crate) fn child(&self) -> &UnixStream {
        self.child
            .as_ref()
            .expect("child socket retained until spawn")
    }

    pub(crate) fn start(&mut self) -> Result<(), BoxError> {
        drop(self.child.take());
        let control = self
            .parent
            .take()
            .ok_or_else(|| failure("storage receiver started twice"))?;
        let plan = Arc::clone(&self.plan);
        let owner = self.owner.clone();
        let cancel = Arc::clone(&self.cancel);
        let sources = self
            .sources
            .take()
            .ok_or_else(|| failure("storage source subscription already transferred"))?;
        self.owner.spawn_worker(Arc::clone(&cancel), move || {
            run(control, plan, owner, cancel, sources)
        })
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn scope(kind: FilesystemTargetKind) -> Scope {
    match kind {
        FilesystemTargetKind::File => Scope::File,
        FilesystemTargetKind::Directory => Scope::Root,
    }
}

fn initial_layout(plan: &LaunchPlan) -> Result<StorageLayout, BoxError> {
    let mut targets = Vec::new();
    let mut add = |target: StorageTarget| -> Result<(), BoxError> {
        if let Some(previous) = targets
            .iter()
            .find(|previous: &&StorageTarget| previous.path == target.path)
        {
            if previous.scope != target.scope {
                return Err(failure("storage destination has conflicting kinds"));
            }
        } else {
            targets.push(target);
        }
        Ok(())
    };
    for root in &plan.policy.roots {
        add(StorageTarget {
            path: root.clone(),
            scope: Scope::Root,
        })?;
    }
    let masks: Vec<_> = plan
        .policy
        .layout
        .pending_masks
        .iter()
        .map(|mask| StorageTarget {
            path: mask.path.clone(),
            scope: scope(mask.kind),
        })
        .collect();
    for target in &masks {
        add(target.clone())?;
    }
    for target in &plan.policy.layout.publication_targets {
        add(StorageTarget {
            path: target.path.clone(),
            scope: scope(target.kind),
        })?;
    }
    Ok(StorageLayout {
        version: wire::VERSION,
        roots: plan.policy.roots.clone(),
        masks,
        targets,
    })
}

fn target_indices(layout: &StorageLayout, compiled: &CompiledLayout) -> Result<Vec<u32>, BoxError> {
    for mask in &compiled.pending_masks {
        if !layout.masks.contains(&StorageTarget {
            path: mask.path.clone(),
            scope: scope(mask.kind),
        }) {
            return Err(failure(
                "compiler introduced a pending mask after workload startup",
            ));
        }
    }
    let mut targets = Vec::new();
    for target in &compiled.publication_targets {
        let expected = StorageTarget {
            path: target.path.clone(),
            scope: scope(target.kind),
        };
        let index = layout
            .targets
            .iter()
            .position(|candidate| *candidate == expected)
            .ok_or_else(|| failure("compiler introduced an unregistered storage destination"))?;
        let index = u32::try_from(index).map_err(|_| failure("too many storage destinations"))?;
        if !targets.contains(&index) {
            targets.push(index);
        }
    }
    Ok(targets)
}

fn note_capture(
    event: HelperEvent,
    roots: usize,
    observed: &mut BTreeSet<u32>,
) -> Result<bool, BoxError> {
    match event {
        HelperEvent::Captured { root, .. } if (root as usize) < roots && observed.insert(root) => {
            Ok(true)
        }
        HelperEvent::Complete => Ok(false),
        HelperEvent::Failed { stage, message } => Err(failure(format!("{stage}: {message}"))),
        _ => Err(failure("unexpected storage receiver event")),
    }
}

fn run(
    control: UnixStream,
    plan: Arc<LaunchPlan>,
    owner: StorageOwner,
    cancel: Arc<Cancellation>,
    sources: UnixStream,
) -> Result<(), BoxError> {
    let layout = initial_layout(&plan)?;
    if !send_or_complete(
        &control,
        &ControllerCommand::Initialize(layout.clone()),
        &cancel,
    )? {
        return Ok(());
    }
    control_result(wire::send_fd(&control, &sources.into()), &cancel)?;
    let user_namespace = File::from(control_result(wire::receive_owner(&control), &cancel)?);
    let required = match control_result(wire::receive_event(&control), &cancel)? {
        HelperEvent::ViewReady { required } => required,
        HelperEvent::Complete => return Ok(()),
        HelperEvent::Failed { stage, message } => {
            return Err(failure(format!("{stage}: {message}")));
        }
        _ => {
            return Err(failure(
                "receiver did not register its protected workload view",
            ));
        }
    };
    let required_set: BTreeSet<_> = required.iter().copied().collect();
    if required_set.len() != required.len()
        || required
            .iter()
            .any(|root| *root as usize >= layout.roots.len())
    {
        return Err(failure("receiver has invalid initial storage roots"));
    }
    let view = File::from(control_result(wire::receive_fd(&control), &cancel)?);
    if plan.input.table == "[agent]" {
        owner.install_hosted(view)?;
    }
    let mut observed = BTreeSet::new();
    let mut published = BTreeSet::new();
    let mut input = plan.input.clone();
    let mut generation = 0_u64;
    let mut launch_released = false;
    release_launch(
        &control,
        &owner,
        &cancel,
        &required_set,
        &BTreeSet::new(),
        &mut launch_released,
    )?;
    loop {
        let event = control_result(wire::receive_event(&control), &cancel)?;
        if !note_capture(event, layout.roots.len(), &mut observed)? {
            return Ok(());
        }
        owner.check()?;
        generation = generation
            .checked_add(1)
            .ok_or_else(|| failure("storage generation counter overflow"))?;
        if !command_result_or_complete(
            &control,
            wire::send_command(&control, &ControllerCommand::Snapshot { generation }),
            &cancel,
            Some((layout.roots.len(), &mut observed)),
        )? {
            return Ok(());
        }
        let captured_roots = loop {
            match control_result(wire::receive_event(&control), &cancel)? {
                HelperEvent::Snapshot {
                    generation: received,
                    captured_roots,
                } if received == generation => break captured_roots,
                event => {
                    if !note_capture(event, layout.roots.len(), &mut observed)? {
                        return Ok(());
                    }
                }
            }
        };
        let captured: BTreeSet<_> = captured_roots.iter().copied().collect();
        if captured_roots.is_empty()
            || captured.len() != captured_roots.len()
            || captured != observed
        {
            return Err(failure(
                "receiver snapshot does not match its reported captures",
            ));
        }
        let trees = captured_roots
            .iter()
            .map(|_| control_result(wire::receive_fd(&control), &cancel).map(File::from))
            .collect::<Result<Vec<_>, _>>()?;
        input.admitted = captured_roots
            .iter()
            .map(|index| layout.roots[*index as usize].clone())
            .collect();
        let output = super::compiler::execute(
            input.clone(),
            &user_namespace,
            trees,
            &plan.policy.commands,
            &plan.policy.installation,
            &cancel,
        )?;
        let targets = target_indices(&layout, &output.layout)?;
        if !published.iter().all(|target| targets.contains(target)) {
            return Err(failure("compiler withdrew a published storage destination"));
        }
        let targets: Vec<_> = targets
            .into_iter()
            .filter(|target| !published.contains(target))
            .collect();
        if targets.is_empty() {
            input.previous = output.checkpoint;
            if !send_or_complete(
                &control,
                &ControllerCommand::Release { generation },
                &cancel,
            )? {
                return Ok(());
            }
            release_launch(
                &control,
                &owner,
                &cancel,
                &required_set,
                &captured,
                &mut launch_released,
            )?;
            continue;
        }
        if !send_or_complete(
            &control,
            &ControllerCommand::Prepare(GenerationRequest {
                generation,
                captured_roots,
                targets: targets.clone(),
                config_json: output.config_json,
            }),
            &cancel,
        )? {
            return Ok(());
        }
        match control_result(wire::receive_event(&control), &cancel)? {
            HelperEvent::Prepared {
                generation: received,
                targets: prepared,
            } if received == generation && prepared == targets => {}
            HelperEvent::Complete => return Ok(()),
            HelperEvent::Failed { stage, message } => {
                return Err(failure(format!("{stage}: {message}")));
            }
            _ => {
                return Err(failure(
                    "receiver did not prepare the requested storage transaction",
                ));
            }
        }
        let sent = owner.admit(|| {
            Ok(wire::send_command(
                &control,
                &ControllerCommand::Commit { generation },
            ))
        })?;
        if !command_result_or_complete(&control, sent, &cancel, None)? {
            return Ok(());
        }
        match control_result(wire::receive_event(&control), &cancel)? {
            HelperEvent::Published {
                generation: received,
                targets: attached,
            } if received == generation && attached == targets => {}
            HelperEvent::Complete => return Ok(()),
            HelperEvent::Failed { stage, message } => {
                return Err(failure(format!("{stage}: {message}")));
            }
            _ => {
                return Err(failure(
                    "receiver did not publish the authorized storage transaction",
                ));
            }
        }
        published.extend(targets);
        input.previous = output.checkpoint;
        release_launch(
            &control,
            &owner,
            &cancel,
            &required_set,
            &captured,
            &mut launch_released,
        )?;
    }
}

fn release_launch(
    control: &UnixStream,
    owner: &StorageOwner,
    cancel: &Cancellation,
    required: &BTreeSet<u32>,
    completed: &BTreeSet<u32>,
    released: &mut bool,
) -> Result<(), BoxError> {
    if !*released && required.is_subset(completed) {
        let sent = owner.admit(|| {
            Ok(wire::send_command(
                control,
                &ControllerCommand::ReleaseLaunch,
            ))
        })?;
        command_result_or_complete(control, sent, cancel, None)?;
        *released = true;
    }
    Ok(())
}

fn control_result<T>(
    result: Result<T, containment::ContainmentError>,
    cancel: &Cancellation,
) -> Result<T, BoxError> {
    match result {
        Err(containment::ContainmentError::StorageControlIo { source })
            if cancel.is_cancelled()
                && matches!(
                    source.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                ) =>
        {
            Err(SuperviseError::StorageCancelled.into())
        }
        result => result.map_err(BoxError::from),
    }
}

/// A workload may finish while its compiler runs. An already queued Complete frame is the
/// authority for treating a failed command send as normal completion; other errors stay fatal.
fn send_or_complete(
    control: &UnixStream,
    command: &ControllerCommand,
    cancel: &Cancellation,
) -> Result<bool, BoxError> {
    command_result_or_complete(control, wire::send_command(control, command), cancel, None)
}

fn command_result_or_complete(
    control: &UnixStream,
    result: Result<(), containment::ContainmentError>,
    cancel: &Cancellation,
    mut pending_captures: Option<(usize, &mut BTreeSet<u32>)>,
) -> Result<bool, BoxError> {
    let disconnected = matches!(
        &result,
        Err(containment::ContainmentError::StorageControlIo { source })
            if matches!(
                source.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            )
    );
    match control_result(result, cancel) {
        Ok(()) => Ok(true),
        Err(error) if error.is_storage_cancelled() || !disconnected => Err(error),
        Err(error) => {
            // Only a Snapshot send can race with unreported captures. An active snapshot
            // holds new notices until Release or Published, so all other phases reject them.
            let remaining = pending_captures
                .as_ref()
                .map_or(0, |(roots, observed)| roots.saturating_sub(observed.len()));
            // At most one notice per remaining root, followed by one terminal event.
            for _ in 0..=remaining {
                let mut poll = libc::pollfd {
                    fd: control.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll inspects the live private socket and does not wait.
                if unsafe { libc::poll(&mut poll, 1, 0) } <= 0 || poll.revents & libc::POLLIN == 0 {
                    return Err(error);
                }
                match control_result(wire::receive_event(control), cancel)? {
                    HelperEvent::Complete => return Ok(false),
                    HelperEvent::Failed { stage, message } => {
                        return Err(failure(format!("{stage}: {message}")));
                    }
                    event @ HelperEvent::Captured { .. } => {
                        let Some((roots, observed)) = pending_captures.as_mut() else {
                            return Err(failure(
                                "unexpected storage receiver event after command failure",
                            ));
                        };
                        note_capture(event, *roots, observed)?;
                    }
                    _ => {
                        return Err(failure(
                            "unexpected storage receiver event after command failure",
                        ));
                    }
                }
            }
            Err(failure(
                "storage receiver exceeded its remaining capture count",
            ))
        }
    }
}

fn failure(reason: impl Into<String>) -> BoxError {
    SuperviseError::Control {
        reason: reason.into(),
    }
    .into()
}
fn io_error(source: std::io::Error) -> BoxError {
    SuperviseError::Spawn { source }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::config::filesystem::{PendingMask, PublicationTarget};

    fn layout() -> StorageLayout {
        StorageLayout {
            version: wire::VERSION,
            roots: vec!["/storage".into()],
            masks: vec![StorageTarget {
                path: "/storage".into(),
                scope: Scope::Root,
            }],
            targets: vec![StorageTarget {
                path: "/storage".into(),
                scope: Scope::Root,
            }],
        }
    }

    #[test]
    fn a_compiler_cannot_publish_an_unregistered_path_or_change_its_kind() {
        for (path, kind) in [
            ("/ordinary", FilesystemTargetKind::Directory),
            ("/storage", FilesystemTargetKind::File),
        ] {
            let compiled = CompiledLayout {
                pending_masks: vec![],
                publication_targets: vec![PublicationTarget {
                    path: path.into(),
                    kind,
                    roots: vec!["/storage".into()],
                }],
            };
            assert!(target_indices(&layout(), &compiled).is_err());
        }
    }

    #[test]
    fn a_compiler_cannot_add_a_mask_after_startup() {
        let compiled = CompiledLayout {
            publication_targets: vec![],
            pending_masks: vec![PendingMask {
                path: "/ordinary".into(),
                kind: FilesystemTargetKind::Directory,
                roots: vec!["/storage".into()],
            }],
        };
        assert!(target_indices(&layout(), &compiled).is_err());
    }

    #[test]
    fn the_original_destination_maps_to_its_permanent_index() {
        let compiled = CompiledLayout {
            pending_masks: vec![],
            publication_targets: vec![PublicationTarget {
                path: "/storage".into(),
                kind: FilesystemTargetKind::Directory,
                roots: vec!["/storage".into()],
            }],
        };
        assert_eq!(target_indices(&layout(), &compiled).unwrap(), vec![0]);
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::io::Write as _;

    fn queued_event(json: &[u8]) -> UnixStream {
        queued_events(&[json])
    }

    fn queued_events(events: &[&[u8]]) -> UnixStream {
        let (parent, mut helper) = UnixStream::pair().unwrap();
        for json in events {
            helper
                .write_all(&(json.len() as u32).to_be_bytes())
                .unwrap();
            helper.write_all(json).unwrap();
        }
        drop(helper);
        parent
    }

    fn captured(root: u32) -> Vec<u8> {
        serde_json::to_vec(&HelperEvent::Captured {
            root,
            identity: wire::SourceIdentity {
                device: 1,
                inode: 2,
                mount_id: 3,
            },
            filesystem: "fuse".into(),
        })
        .unwrap()
    }

    fn send_snapshot_with_captures(
        parent: &UnixStream,
        roots: usize,
        observed: &mut BTreeSet<u32>,
    ) -> Result<bool, BoxError> {
        command_result_or_complete(
            parent,
            wire::send_command(parent, &ControllerCommand::Snapshot { generation: 1 }),
            &Cancellation::default(),
            Some((roots, observed)),
        )
    }

    #[test]
    fn queued_complete_allows_workload_exit_during_compilation() {
        let parent = queued_event(br#"{"status":"complete"}"#);
        assert!(
            !send_or_complete(
                &parent,
                &ControllerCommand::Release { generation: 1 },
                &Cancellation::default()
            )
            .unwrap()
        );
    }

    #[test]
    fn queued_failure_is_not_hidden_by_a_send_error() {
        let parent =
            queued_event(br#"{"status":"failed","stage":"protect","message":"denial missing"}"#);
        let error = send_or_complete(
            &parent,
            &ControllerCommand::Release { generation: 1 },
            &Cancellation::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("denial missing"));
    }

    #[test]
    fn queued_captures_then_complete_allow_workload_exit_before_snapshot() {
        let second = captured(1);
        let third = captured(2);
        let parent = queued_events(&[&second, &third, br#"{"status":"complete"}"#]);
        let mut observed = BTreeSet::from([0]);
        assert!(!send_snapshot_with_captures(&parent, 3, &mut observed).unwrap());
        assert_eq!(observed, BTreeSet::from([0, 1, 2]));
    }

    #[test]
    fn queued_capture_does_not_hide_a_later_failure() {
        let capture = captured(1);
        let parent = queued_events(&[
            &capture,
            br#"{"status":"failed","stage":"protect","message":"denial missing"}"#,
            br#"{"status":"complete"}"#,
        ]);
        let error = send_snapshot_with_captures(&parent, 2, &mut BTreeSet::from([0])).unwrap_err();
        assert!(error.to_string().contains("denial missing"));
    }

    #[test]
    fn queued_capture_does_not_hide_a_malformed_event() {
        let capture = captured(1);
        let parent = queued_events(&[&capture, b"{", br#"{"status":"complete"}"#]);
        let error = send_snapshot_with_captures(&parent, 2, &mut BTreeSet::from([0])).unwrap_err();
        assert!(error.to_string().contains("invalid storage event"));
        assert!(!error.is_storage_cancelled());
    }

    #[test]
    fn queued_capture_followed_only_by_eof_is_not_completion() {
        let capture = captured(1);
        let parent = queued_event(&capture);
        let error = send_snapshot_with_captures(&parent, 2, &mut BTreeSet::from([0])).unwrap_err();
        assert!(!error.is_storage_cancelled());
    }

    #[test]
    fn duplicate_and_unknown_capture_indices_cannot_be_drained_to_completion() {
        for root in [0, 2] {
            let capture = captured(root);
            let parent = queued_events(&[&capture, br#"{"status":"complete"}"#]);
            let error =
                send_snapshot_with_captures(&parent, 2, &mut BTreeSet::from([0])).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unexpected storage receiver event")
            );
        }
    }

    #[test]
    fn capture_in_a_frozen_transaction_cannot_be_drained_to_completion() {
        let capture = captured(1);
        let parent = queued_events(&[&capture, br#"{"status":"complete"}"#]);
        let error = send_or_complete(
            &parent,
            &ControllerCommand::Release { generation: 1 },
            &Cancellation::default(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected storage receiver event")
        );
    }

    #[test]
    fn unexpected_phase_event_cannot_be_drained_to_completion() {
        let parent = queued_events(&[
            br#"{"status":"prepared","generation":1,"targets":[0]}"#,
            br#"{"status":"complete"}"#,
        ]);
        let error = send_snapshot_with_captures(&parent, 2, &mut BTreeSet::from([0])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected storage receiver event")
        );
    }

    #[test]
    fn queued_complete_cannot_hide_a_command_validation_error() {
        let parent = queued_event(br#"{"status":"complete"}"#);
        let error = command_result_or_complete(
            &parent,
            Err(containment::ContainmentError::ConfigValidation(
                "bad command".into(),
            )),
            &Cancellation::default(),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("bad command"));
    }

    #[test]
    fn explicit_cancellation_cannot_be_recovered_as_queued_completion() {
        let parent = queued_event(br#"{"status":"complete"}"#);
        let cancel = Cancellation::default();
        cancel.cancel();
        let error = send_or_complete(
            &parent,
            &ControllerCommand::Release { generation: 1 },
            &cancel,
        )
        .unwrap_err();
        assert!(error.is_storage_cancelled());
    }

    #[test]
    fn cancellation_does_not_convert_invalid_protocol_into_expected_shutdown() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let invalid = containment::ContainmentError::ConfigValidation("bad frame".into());
        assert!(
            !control_result::<()>(Err(invalid), &cancel)
                .unwrap_err()
                .is_storage_cancelled()
        );
        let disconnected = containment::ContainmentError::StorageControlIo {
            source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
        };
        assert!(
            control_result::<()>(Err(disconnected), &cancel)
                .unwrap_err()
                .is_storage_cancelled()
        );
    }
}
