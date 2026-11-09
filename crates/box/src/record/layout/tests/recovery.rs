use super::*;

#[cfg(unix)]
#[test]
fn an_interrupted_first_record_write_leaves_the_directory_recoverable() {
    use std::os::unix::fs::PermissionsExt as _;

    for partial in [false, true] {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let root = parent.path().join("box");
        std::fs::create_dir(&root).expect("caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let private = root.join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private).expect("interrupted private directory");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("private state mode");
        if partial {
            write_partial_record(&private, "version =");
        }

        let mut opened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("interrupted first use recovers")
        });
        assert_eq!(
            children(&root),
            ["private"],
            "opening an interrupted first use must not mutate it"
        );
        assert_eq!(
            children(&private),
            if partial {
                vec![RECORD_FILE.to_string()]
            } else {
                Vec::new()
            },
            "opening must retain the exact interrupted record state"
        );
        opened
            .settle_identity()
            .expect("the recovered directory receives an identity");
        let record = record_for(&opened);
        opened
            .initialize_first_use(&record)
            .expect("the retry commits a record and initializes the layout");
        assert_eq!(
            private.metadata().unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            Record::parse(
                &std::fs::read_to_string(private.join(RECORD_FILE)).expect("completed record"),
                &private.join(RECORD_FILE)
            )
            .expect("record parses")
            .box_id,
            opened.box_id()
        );

        let reopened = with_operator_home(operator_home.path(), || {
            BoxRoot::open_directory(&root).expect("the completed retry reopens")
        });
        assert_eq!(reopened.box_id(), opened.box_id());
    }
}

#[cfg(unix)]
#[test]
fn an_interrupted_record_does_not_commit_its_identity() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let root = parent.path().join("box");
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    let private = root.join(PRIVATE_DIRECTORY);
    std::fs::create_dir(&private).expect("interrupted private directory");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
        .expect("interrupted private mode");
    let expected = "box-1111111111111111";
    write_partial_record(
        &private,
        &valid_record_at(&root, operator_home.path(), expected),
    );

    let mut opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("completed first record opens")
    });
    assert!(!opened.is_configured());
    opened
        .settle_identity()
        .expect("the retry receives an uncommitted identity");
    assert_ne!(opened.box_id(), expected);
    let retried = opened.box_id().to_string();
    let record = record_for(&opened);
    opened
        .initialize_first_use(&record)
        .expect("first-use completion succeeds");

    assert!(opened.is_configured());
    assert_eq!(children(&root), ["bin", "private", "run", "trust"]);
    let reopened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("completed box reopens")
    });
    assert_eq!(reopened.box_id(), retried);
}

#[cfg(unix)]
#[test]
fn a_crash_after_mode_change_does_not_commit_the_record() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let root = parent.path().join("box");
    let private = root.join(PRIVATE_DIRECTORY);
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    std::fs::create_dir(&private).expect("private directory");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("configured-looking mode");
    let uncommitted = "box-2222222222222222";
    write_partial_record(
        &private,
        &valid_record_at(&root, operator_home.path(), uncommitted),
    );

    let mut opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("the uncommitted state reopens")
    });
    assert!(!opened.is_configured());
    opened
        .settle_identity()
        .expect("the retry receives a new identity");
    assert_ne!(opened.box_id(), uncommitted);
}

#[cfg(unix)]
#[test]
fn a_crash_during_commit_staging_leaves_first_use_recoverable() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let root = parent.path().join("box");
    let private = root.join(PRIVATE_DIRECTORY);
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    std::fs::create_dir(&private).expect("private directory");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("configured-looking mode");
    write_partial_record(
        &private,
        &valid_record_at(&root, operator_home.path(), "box-2222222222222222"),
    );
    std::fs::write(private.join(".configured.123.0.tmp"), "partial")
        .expect("partial commit staging");

    let mut opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("the staged commit reopens")
    });
    assert!(!opened.is_configured());
    opened
        .settle_identity()
        .expect("the retry receives a new identity");
    let record = record_for(&opened);
    opened
        .initialize_first_use(&record)
        .expect("the retry commits the record");

    let reopened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("the completed retry reopens")
    });
    assert_eq!(reopened.box_id(), opened.box_id());
}

#[cfg(unix)]
#[test]
fn a_record_replaced_during_commit_is_refused_when_reopened() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let root = parent.path().join("box");
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");

    let mut opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("empty first use opens")
    });
    opened.settle_identity().expect("box identity");
    let record = record_for(&opened);
    let private = opened
        .create_first_use_private()
        .expect("first-use private directory");
    opened.private_handle = Some(Arc::clone(&private.handle));
    let written = private
        .write_record(&opened, &record.to_toml().expect("record text"))
        .expect("record write");
    let record_path = opened.record();
    let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
    private
        .finish_with(&opened, &written, || {
            std::fs::remove_file(&record_path).expect("unlink opened record");
            write_partial_record(&opened.private_directory(), &replacement);
        })
        .expect_err("the replacement record must not be sealed");

    assert_eq!(
        opened
            .private_directory()
            .metadata()
            .expect("private metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    let mut retained = written.as_ref();
    retained
        .seek(std::io::SeekFrom::Start(0))
        .expect("retained record seeks");
    let mut retained_text = String::new();
    retained
        .read_to_string(&mut retained_text)
        .expect("retained record reads");
    assert_eq!(retained_text, record.to_toml().expect("record text"));
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("replacement remains"),
        replacement
    );
    let box_id = opened.box_id().to_string();
    drop(opened);
    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a record swapped under the marker must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "its record identity is {box_id} sha256:{}, but the committed record has \
             identity box-ffffffffffffffff sha256:{}.",
            sha256_hex(retained_text.as_bytes()),
            sha256_hex(replacement.as_bytes())
        )),
        "the refusal must name the sealed identity and the replacement: {message}"
    );
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("the replacement remains"),
        replacement,
        "the refusal must not re-initialize the replacement"
    );
}

#[cfg(unix)]
#[test]
fn a_crash_after_refresh_commit_completes_the_record_install_on_open() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let root = parent.path().join("box");
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");

    let mut opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("empty box opens")
    });
    opened.settle_identity().expect("box identity");
    let initial = record_for(&opened);
    opened
        .initialize_first_use(&initial)
        .expect("first use completes");
    let mut updated = initial;
    updated.agent = Some(crate::record::config::process::ProcessSpec {
        native_filesystem_policy: None,
        command: vec!["/bin/sh".to_string()],
        workspace: None,
        env: std::collections::BTreeMap::from([("REFRESHED".to_string(), "yes".to_string())]),
        filesystem: Default::default(),
        network: None,
        grammar: None,
    });
    let updated_text = updated.to_toml().expect("updated record");

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        opened
            .write_committed_record_with(&updated_text, || panic!("simulated crash"))
            .expect("the simulated crash interrupts the write");
    }));
    assert!(interrupted.is_err());
    assert!(
        opened
            .private_directory()
            .join(PENDING_RECORD_FILE)
            .is_file()
    );
    drop(opened);

    let reopened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("the committed refresh recovers")
    });
    assert!(reopened.is_configured());
    assert_eq!(
        reopened
            .read_record()
            .expect("the recovered record reads")
            .agent
            .expect("the refreshed agent")
            .env
            .get("REFRESHED")
            .map(String::as_str),
        Some("yes")
    );
    assert!(
        !reopened
            .private_directory()
            .join(PENDING_RECORD_FILE)
            .exists()
    );
}
