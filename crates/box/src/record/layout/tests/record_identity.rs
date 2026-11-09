use super::*;

/// A box whose first use completed, closed, so a later open reads only what is on disk.
#[cfg(unix)]
fn configured_box(operator_home: &Path, parent: &Path) -> (PathBuf, String) {
    use std::os::unix::fs::PermissionsExt as _;

    let root = parent.join("box");
    std::fs::create_dir(&root).expect("caller-owned box directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private root mode");
    let mut opened = with_operator_home(operator_home, || {
        BoxRoot::open_directory(&root).expect("empty box opens")
    });
    opened.settle_identity().expect("box identity");
    let record = record_for(&opened);
    opened
        .initialize_first_use(&record)
        .expect("first use completes");
    let box_id = opened.box_id().to_string();
    drop(opened);
    (root, box_id)
}

/// Copy `source` to `destination` with every mode kept, so the copy differs only in identity.
#[cfg(unix)]
fn copy_tree(source: &Path, destination: &Path) {
    let metadata = std::fs::symlink_metadata(source).expect("source metadata");
    if metadata.is_dir() {
        std::fs::create_dir(destination).expect("copied directory");
        for entry in std::fs::read_dir(source).expect("source entries") {
            let entry = entry.expect("source entry");
            copy_tree(&entry.path(), &destination.join(entry.file_name()));
        }
        std::fs::set_permissions(destination, metadata.permissions()).expect("directory mode");
    } else if metadata.is_file() {
        std::fs::copy(source, destination).expect("copied file");
    } else if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(source).expect("link target");
        std::os::unix::fs::symlink(target, destination).expect("copied link");
    }
}

#[cfg(unix)]
#[test]
fn a_configured_box_whose_marker_holds_its_id_and_digest_reopens() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);

    let record = std::fs::read(private.join(RECORD_FILE)).expect("the committed record");
    assert_eq!(
        std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("the marker"),
        format!("{box_id} sha256:{}\n", sha256_hex(&record)),
        "the marker must hold the box id and the digest of the committed record"
    );

    let reopened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("a configured box reopens")
    });
    assert!(reopened.is_configured());
    assert_eq!(reopened.box_id(), box_id);
}

#[cfg(unix)]
#[test]
fn a_record_whose_content_changed_in_place_refuses_and_names_both_identities() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    let record_path = private.join(RECORD_FILE);
    let inode_before = record_path.metadata().expect("record metadata").ino();
    let stored = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

    let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&record_path)
        .and_then(|mut file| file.write_all(replacement.as_bytes()))
        .expect("rewrite the record in place");
    assert_eq!(
        record_path.metadata().expect("record metadata").ino(),
        inode_before,
        "the rewrite must keep the record's inode"
    );

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a record with other content must be refused");
    let message = error.to_string();
    assert!(message.starts_with("unsafe box directory "), "{message}");
    assert!(
        message.contains(&format!(
            ": its record identity is {}, but the committed record has identity \
             box-ffffffffffffffff sha256:{}. Delete the box directory to start again.",
            stored.trim_end(),
            sha256_hex(replacement.as_bytes())
        )),
        "{message}"
    );
    assert!(message.contains(&box_id), "{message}");
}

#[cfg(unix)]
#[test]
fn a_marker_in_the_device_and_inode_form_refuses_with_the_identity_text() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    let record = std::fs::read(private.join(RECORD_FILE)).expect("the committed record");
    let metadata = private
        .join(RECORD_FILE)
        .metadata()
        .expect("record metadata");
    let legacy = format!("{}:{}\n", metadata.dev(), metadata.ino());
    std::fs::write(private.join(PRIVATE_COMMIT_FILE), &legacy).expect("legacy marker");

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a marker in the device and inode form must be refused");
    let message = error.to_string();
    assert!(message.starts_with("unsafe box directory "), "{message}");
    assert!(
        message.contains(&format!(
            ": its record identity is {}, but the committed record has identity {box_id} \
             sha256:{}. Delete the box directory to start again.",
            legacy.trim_end(),
            sha256_hex(&record)
        )),
        "{message}"
    );
}

#[cfg(unix)]
#[test]
fn the_record_identity_holds_no_device_or_inode() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    let metadata = private
        .join(RECORD_FILE)
        .metadata()
        .expect("record metadata");
    let text = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

    let line = text
        .strip_suffix('\n')
        .expect("one line ending in a newline");
    let (id, digest) = line
        .split_once(' ')
        .expect("two fields separated by one space");
    assert_eq!(id, box_id, "the first field must be the box id");
    assert_eq!(id.len(), "box-".len() + 16);
    assert!(id.starts_with("box-") && id[4..].bytes().all(|byte| byte.is_ascii_hexdigit()));
    let digest = digest
        .strip_prefix("sha256:")
        .expect("the second field names its algorithm");
    assert_eq!(digest.len(), 64, "the digest must be a SHA-256 in hex");
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(line.matches(':').count(), 1);
    assert_ne!(text, format!("{}:{}\n", metadata.dev(), metadata.ino()));
}

#[cfg(unix)]
#[test]
fn a_copied_box_directory_with_the_same_bytes_opens_as_the_same_box() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let copy = parent.path().join("copy");
    copy_tree(&root, &copy);
    let original = root.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
    let copied = copy.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
    assert_ne!(
        original.metadata().expect("original record").ino(),
        copied.metadata().expect("copied record").ino(),
        "the copy must hold a different record inode"
    );
    assert_eq!(
        std::fs::read(&original).expect("original bytes"),
        std::fs::read(&copied).expect("copied bytes")
    );

    let opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&copy).expect("a copy with the same bytes opens")
    });
    assert!(opened.is_configured());
    assert_eq!(opened.box_id(), box_id);
}

#[cfg(unix)]
#[test]
fn a_committed_record_that_no_longer_parses_refuses_with_its_own_parse_error() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let record_path = root.join(PRIVATE_DIRECTORY).join(RECORD_FILE);
    let stale = valid_record_at(&root, operator_home.path(), &box_id).replacen(
        &format!("version = {}", crate::record::config::RECORD_VERSION),
        "version = 999",
        1,
    );
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&record_path)
        .and_then(|mut file| file.write_all(stale.as_bytes()))
        .expect("rewrite the record in place");

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a record this build cannot read must be refused");
    let message = error.to_string();
    assert!(
        message.contains("box record is version 999, but this build understands"),
        "the refusal must be the record's own: {message}"
    );
    assert!(!message.contains("no valid private record"), "{message}");
}

#[cfg(unix)]
#[test]
fn a_pending_record_that_does_not_match_the_marker_is_not_installed() {
    use std::os::unix::fs::PermissionsExt as _;

    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, _) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    let record_path = private.join(RECORD_FILE);
    let pending_path = private.join(PENDING_RECORD_FILE);
    let stored = std::fs::read_to_string(private.join(PRIVATE_COMMIT_FILE)).expect("marker");

    let replaced = valid_record_at(&root, operator_home.path(), "box-eeeeeeeeeeeeeeee");
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&record_path)
        .and_then(|mut file| file.write_all(replaced.as_bytes()))
        .expect("rewrite the record in place");
    let stray = valid_record_at(&root, operator_home.path(), "box-dddddddddddddddd");
    std::fs::write(&pending_path, &stray).expect("stray pending record");
    std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o600))
        .expect("pending mode");

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("neither the record nor the pending record matches the marker");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "its record identity is {}, but the committed record has identity \
             box-eeeeeeeeeeeeeeee sha256:{}.",
            stored.trim_end(),
            sha256_hex(replaced.as_bytes())
        )),
        "{message}"
    );
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("the record remains"),
        replaced,
        "the stray pending record must not be installed over the record"
    );
    assert_eq!(
        std::fs::read_to_string(&pending_path).expect("the pending record remains"),
        stray
    );
}

/// Reduce a configured box's private directory to its record and its marker alone.
#[cfg(unix)]
fn keep_only_record_and_marker(private: &Path) {
    for entry in std::fs::read_dir(private).expect("private entries") {
        let entry = entry.expect("private entry");
        let name = entry.file_name();
        if name == RECORD_FILE || name == PRIVATE_COMMIT_FILE {
            continue;
        }
        if entry.file_type().expect("entry type").is_dir() {
            std::fs::remove_dir_all(entry.path()).expect("remove a generated directory");
        } else {
            std::fs::remove_file(entry.path()).expect("remove a generated file");
        }
    }
    assert_eq!(children(private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
}

#[cfg(unix)]
fn rewrite_in_place(path: &Path, contents: &str) {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .expect("rewrite the record in place");
}

#[cfg(unix)]
#[test]
fn a_marker_beside_an_edited_record_refuses_without_sibling_directories() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, _) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    keep_only_record_and_marker(&private);
    let record_path = private.join(RECORD_FILE);
    let marker_path = private.join(PRIVATE_COMMIT_FILE);
    let stored = std::fs::read_to_string(&marker_path).expect("marker");
    let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
    rewrite_in_place(&record_path, &replacement);

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a marker beside a record it does not describe must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "its record identity is {}, but the committed record has identity \
             box-ffffffffffffffff sha256:{}.",
            stored.trim_end(),
            sha256_hex(replacement.as_bytes())
        )),
        "the refusal must name both identities: {message}"
    );
    assert_eq!(
        std::fs::read_to_string(&marker_path).expect("the marker remains"),
        stored,
        "the open must not rewrite the marker"
    );
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("the record remains"),
        replacement,
        "the open must not rewrite the record"
    );
    assert_eq!(
        children(&private),
        [RECORD_FILE, PRIVATE_COMMIT_FILE],
        "the open must not re-initialize the private directory"
    );
}

#[cfg(unix)]
#[test]
fn a_marker_beside_an_unreadable_record_refuses_without_sibling_directories() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, box_id) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    keep_only_record_and_marker(&private);
    let record_path = private.join(RECORD_FILE);
    let marker_path = private.join(PRIVATE_COMMIT_FILE);
    let stored = std::fs::read_to_string(&marker_path).expect("marker");
    let stale = valid_record_at(&root, operator_home.path(), &box_id).replacen(
        &format!("version = {}", crate::record::config::RECORD_VERSION),
        "version = 999",
        1,
    );
    rewrite_in_place(&record_path, &stale);

    let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
        .expect_err("a marker beside a record this build cannot read must be refused");
    let message = error.to_string();
    assert!(
        message.contains("box record is version 999, but this build understands"),
        "the refusal must be the record's own: {message}"
    );
    assert!(!message.contains("no valid private record"), "{message}");
    assert_eq!(
        std::fs::read_to_string(&marker_path).expect("the marker remains"),
        stored
    );
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("the record remains"),
        stale
    );
    assert_eq!(children(&private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
}

#[cfg(unix)]
#[test]
fn a_record_without_a_marker_still_recovers_as_an_interrupted_first_use() {
    let operator_home = tempfile::tempdir().expect("operator home");
    let parent = tempfile::tempdir().expect("box parent");
    let (root, _) = configured_box(operator_home.path(), parent.path());
    let private = root.join(PRIVATE_DIRECTORY);
    keep_only_record_and_marker(&private);
    std::fs::remove_file(private.join(PRIVATE_COMMIT_FILE)).expect("remove the marker");
    let record_path = private.join(RECORD_FILE);
    let before = std::fs::read_to_string(&record_path).expect("record");

    let opened = with_operator_home(operator_home.path(), || {
        BoxRoot::open_directory(&root).expect("a record without a marker is recoverable")
    });
    assert!(
        !opened.is_configured(),
        "a record without a marker must not open as configured"
    );
    assert_eq!(children(&private), [RECORD_FILE]);
    assert_eq!(
        std::fs::read_to_string(&record_path).expect("the record remains"),
        before
    );
}

#[cfg(unix)]
#[test]
fn a_marker_under_the_first_use_mode_refuses_and_is_not_re_initialized() {
    use std::os::unix::fs::PermissionsExt as _;

    for edited in [true, false] {
        let operator_home = tempfile::tempdir().expect("operator home");
        let parent = tempfile::tempdir().expect("box parent");
        let (root, _) = configured_box(operator_home.path(), parent.path());
        let private = root.join(PRIVATE_DIRECTORY);
        keep_only_record_and_marker(&private);
        for name in ["bin", "run", "trust"] {
            std::fs::remove_dir_all(root.join(name)).expect("remove a layout directory");
        }
        assert_eq!(children(&root), [PRIVATE_DIRECTORY]);
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o1700))
            .expect("first-use private mode");
        let record_path = private.join(RECORD_FILE);
        let marker_path = private.join(PRIVATE_COMMIT_FILE);
        let stored = std::fs::read_to_string(&marker_path).expect("marker");
        let record = if edited {
            let replacement = valid_record_at(&root, operator_home.path(), "box-ffffffffffffffff");
            rewrite_in_place(&record_path, &replacement);
            replacement
        } else {
            std::fs::read_to_string(&record_path).expect("record")
        };

        let error = with_operator_home(operator_home.path(), || BoxRoot::open_directory(&root))
            .expect_err("a marker under the first-use mode must be refused");
        let message = error.to_string();
        if edited {
            assert!(
                message.contains(&format!(
                    "its record identity is {}, but the committed record has identity \
                     box-ffffffffffffffff sha256:{}.",
                    stored.trim_end(),
                    sha256_hex(record.as_bytes())
                )),
                "the refusal must name both identities: {message}"
            );
        } else {
            assert!(
                message.contains("contains no valid private record"),
                "a marker that matches its record is not a first-use state: {message}"
            );
        }
        assert_eq!(
            private
                .metadata()
                .expect("private metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o1700,
            "the open must not change the private directory mode"
        );
        assert_eq!(
            std::fs::read_to_string(&marker_path).expect("the marker remains"),
            stored
        );
        assert_eq!(
            std::fs::read_to_string(&record_path).expect("the record remains"),
            record
        );
        assert_eq!(children(&private), [RECORD_FILE, PRIVATE_COMMIT_FILE]);
        assert_eq!(children(&root), [PRIVATE_DIRECTORY]);
    }
}
