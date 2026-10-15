use super::*;

#[test]
fn child_check_reads_process_ids_instead_of_a_buffer_estimate() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    // SAFETY: these live process IDs belong to this test and its child.
    let parent_has_child = unsafe { box_es_has_children(std::process::id() as i32) };
    let child_has_child = unsafe { box_es_has_children(child.id() as i32) };
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(parent_has_child);
    assert!(!child_has_child);
}

fn event(kind: u32, source: &str) -> RawEvent {
    // Every field accepts zero as a representation. Decoding validates its meaning.
    let mut event: RawEvent = unsafe { std::mem::zeroed() };
    event.kind = kind;
    event.phase = AUTH;
    event.valid = 1;
    event.source_identity = FILE_IDENTITY;
    event.path[..source.len()].copy_from_slice(source.as_bytes());
    event
}

#[test]
fn bridge_layout_matches_rust() {
    assert_eq!(std::mem::size_of::<RawEvent>(), unsafe {
        box_es_event_size()
    });
}

#[test]
fn open_flags_use_kernel_access_bits_and_preserve_append() {
    let mut raw = event(OPEN, "/file");
    raw.flags = FREAD | FWRITE | libc::O_APPEND as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 2);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    assert_eq!(plan.checks[1].operation, FsOperation::WriteContent);
    raw.flags = FREAD | libc::O_TRUNC as u32;
    assert_eq!(Plan::decode(&raw).unwrap().checks.len(), 2);
    raw.flags = 0;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn create_and_unlink_preserve_object_types() {
    for (mode, create, remove) in [
        (
            libc::S_IFREG,
            FsOperation::WriteContent,
            FsOperation::RemoveFile,
        ),
        (
            libc::S_IFDIR,
            FsOperation::CreateDir,
            FsOperation::RemoveDir,
        ),
        (libc::S_IFLNK, FsOperation::Symlink, FsOperation::RemoveFile),
    ] {
        let mut raw = event(CREATE, "/new");
        raw.source_identity = PARENT_IDENTITY;
        raw.mode = mode as u32 | 0o600;
        assert_eq!(Plan::decode(&raw).unwrap().checks[0].operation, create);
        raw.kind = UNLINK;
        raw.source_identity = FILE_IDENTITY;
        assert_eq!(Plan::decode(&raw).unwrap().checks[0].operation, remove);
    }
    let mut raw = event(CREATE, "/device");
    raw.source_identity = PARENT_IDENTITY;
    raw.mode = libc::S_IFCHR as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn rename_checks_read_and_both_move_targets_and_authorizes_replacement() {
    let mut raw = event(RENAME, "/source");
    raw.destination[..12].copy_from_slice(b"/destination");
    raw.destination_identity = PARENT_IDENTITY;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 3);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    assert_eq!(plan.checks[1].path, Path::new("/source"));
    assert_eq!(plan.checks[2].path, Path::new("/destination"));
    raw.destination_exists = 1;
    // An existing destination must carry its own kernel identity.
    assert!(Plan::decode(&raw).is_err());
    raw.destination_identity = FILE_IDENTITY;
    raw.destination_mode = libc::S_IFREG as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 5);
    assert_eq!(plan.checks[3].operation, FsOperation::RemoveFile);
    assert_eq!(plan.checks[4].operation, FsOperation::WriteContent);
    assert_eq!(plan.identities[1].path, Path::new("/destination"));
    raw.destination_mode = libc::S_IFDIR as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn event_only_open_checks_content_and_unknown_flags_stay_refused() {
    let mut raw = event(OPEN, "/file");
    raw.flags = (libc::O_EVTONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u32;
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 1);
    assert_eq!(plan.checks[0].operation, FsOperation::ReadContent);
    for flags in [
        0,
        libc::O_EVTONLY as u32 | 0x80000000,
        libc::O_EVTONLY as u32 | libc::O_TRUNC as u32,
    ] {
        raw.flags = flags;
        assert!(Plan::decode(&raw).is_err(), "{flags:#x}");
    }
}

#[test]
fn execute_only_open_uses_the_existing_exec_operation() {
    let mut raw = event(OPEN, "/program");
    raw.flags = (libc::O_EXEC | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK) as u32;
    assert_eq!(raw.flags, 0x41020004);
    let plan = Plan::decode(&raw).unwrap();
    assert_eq!(plan.checks.len(), 1);
    assert_eq!(plan.checks[0].operation, FsOperation::ExecFile);
    raw.flags |= libc::O_EVTONLY as u32;
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn replacement_rechecks_the_kernel_destination_identity() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let destination = directory.path().join("destination");
    std::fs::write(&source, "source").unwrap();
    std::fs::write(&destination, "old").unwrap();
    let mut raw = event(RENAME, source.to_str().unwrap());
    let name = destination.to_str().unwrap().as_bytes();
    raw.destination[..name.len()].copy_from_slice(name);
    raw.source_dev = source.metadata().unwrap().dev();
    raw.source_ino = source.metadata().unwrap().ino();
    raw.destination_exists = 1;
    raw.destination_identity = FILE_IDENTITY;
    raw.destination_mode = libc::S_IFREG as u32;
    raw.destination_dev = destination.metadata().unwrap().dev();
    raw.destination_ino = destination.metadata().unwrap().ino();
    let plan = Plan::decode(&raw).unwrap();
    plan.verify().unwrap();
    std::fs::rename(&destination, directory.path().join("old")).unwrap();
    std::fs::write(&destination, "replacement").unwrap();
    assert!(plan.verify().is_err());
}

#[test]
fn malformed_paths_and_notifications_cannot_authorize() {
    let mut raw = event(TRUNCATE, "/file");
    raw.phase = NOTIFY;
    assert!(Plan::decode(&raw).is_err());
    raw.phase = AUTH;
    raw.valid = 0;
    assert!(Plan::decode(&raw).is_err());
    raw.valid = 1;
    raw.path.fill(b'a');
    assert!(Plan::decode(&raw).is_err());
    raw.path.fill(0);
    raw.path[..5].copy_from_slice(b"/x/\xffy");
    assert!(Plan::decode(&raw).is_err());
}

#[test]
fn replaced_file_identity_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    std::fs::write(&path, "original").unwrap();
    let metadata = path.metadata().unwrap();
    let plan = Plan {
        checks: vec![],
        identities: vec![Identity {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }],
    };
    plan.verify().unwrap();
    std::fs::rename(&path, directory.path().join("original")).unwrap();
    std::fs::write(&path, "replacement").unwrap();
    assert!(plan.verify().is_err());
}

#[test]
fn sequence_gaps_and_duplicates_fail() {
    let mut tracker = Tracker::default();
    assert!(tracker.sequence(0));
    assert!(tracker.sequence(1));
    assert!(!tracker.sequence(3));
    assert!(!tracker.sequence(3));
}

#[test]
fn bridge_fields_have_the_same_offsets_as_rust() {
    let offsets = [
        std::mem::offset_of!(RawEvent, kind),
        std::mem::offset_of!(RawEvent, phase),
        std::mem::offset_of!(RawEvent, flags),
        std::mem::offset_of!(RawEvent, mode),
        std::mem::offset_of!(RawEvent, sequence),
        std::mem::offset_of!(RawEvent, deadline),
        std::mem::offset_of!(RawEvent, pid),
        std::mem::offset_of!(RawEvent, valid),
        std::mem::offset_of!(RawEvent, source_dev),
        std::mem::offset_of!(RawEvent, source_ino),
        std::mem::offset_of!(RawEvent, destination_dev),
        std::mem::offset_of!(RawEvent, destination_ino),
        std::mem::offset_of!(RawEvent, source_identity),
        std::mem::offset_of!(RawEvent, destination_identity),
        std::mem::offset_of!(RawEvent, destination_exists),
        std::mem::offset_of!(RawEvent, destination_mode),
        std::mem::offset_of!(RawEvent, result),
        std::mem::offset_of!(RawEvent, path),
        std::mem::offset_of!(RawEvent, destination),
    ];
    for (field, offset) in offsets.into_iter().enumerate() {
        assert_eq!(
            offset,
            unsafe { box_es_event_offset(field) },
            "field {field}"
        );
    }
}

fn context(root: &Path) -> Context {
    Context {
        engine: Arc::new(crate::test_support::open_policy(vec![policy::Policy {
            origin: root.join("policy.dw"),
            text: "permit(principal, action, resource);".into(),
        }])),
        recorder: DecisionRecorder::discarding(),
        governed: GovernedBox::assigned("native-test"),
        resolver: PathResolver::over([root.to_path_buf()]).unwrap(),
        fatal: tokio::sync::mpsc::unbounded_channel().0,
        tracker: Mutex::new(Tracker::default()),
    }
}

fn readable(root: &Path) -> RawEvent {
    let file = root.join("readable");
    std::fs::write(&file, "content").unwrap();
    let mut raw = event(OPEN, file.to_str().unwrap());
    raw.flags = FREAD;
    raw.source_dev = file.metadata().unwrap().dev();
    raw.source_ino = file.metadata().unwrap().ino();
    raw
}

#[test]
fn the_kernel_denial_replaces_a_provisional_policy_permit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let context = context(&root);
    let mut raw = readable(&root);
    assert!(context.receive(&raw, 0));
    assert!(context.recorder.recorded().is_empty());
    raw.phase = REPLY;
    raw.result = 0;
    context.receive(&raw, 0);
    let records = context.recorder.recorded();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].parts().3,
        super::super::telemetry::EffectiveVerdict::Deny
    );
    assert_eq!(records[0].cause(), ::telemetry::DecisionCause::Enforcement);
}

#[test]
fn a_malformed_event_records_an_adapter_denial() {
    let directory = tempfile::tempdir().unwrap();
    let context = context(directory.path());
    let mut raw = event(OPEN, "relative");
    assert!(!context.receive(&raw, 0));
    raw.phase = REPLY;
    context.receive(&raw, 0);
    assert_eq!(
        context.recorder.recorded()[0].parts().3,
        super::super::telemetry::EffectiveVerdict::Deny
    );
}

#[test]
fn reply_failure_keeps_later_authorizations_denied() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let context = context(&root);
    let mut raw = readable(&root);
    assert!(context.receive(&raw, 0));
    raw.phase = REPLY;
    raw.result = 1;
    context.receive(&raw, 1);
    raw.phase = AUTH;
    raw.sequence = 1;
    assert!(!context.receive(&raw, 0));
    assert!(context.tracker.lock().unwrap().failed);
}

#[test]
fn sequence_loss_keeps_later_authorizations_denied() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let context = context(&root);
    let mut raw = readable(&root);
    assert!(context.receive(&raw, 0));
    raw.phase = REPLY;
    raw.result = 1;
    context.receive(&raw, 0);
    raw.phase = AUTH;
    raw.sequence = 2;
    assert!(!context.receive(&raw, 0));
    raw.sequence = 3;
    assert!(!context.receive(&raw, 0));
}
