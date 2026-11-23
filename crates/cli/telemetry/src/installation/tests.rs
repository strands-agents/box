use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use serde_json::json;

use super::{InstallationId, save_telemetry_choice, saved_choice};

const ID: &str = "12345678-90ab-4cde-8f01-234567890abc";

#[test]
fn creates_a_schema_uuid_and_reuses_it_until_removed() {
    let root = tempfile::tempdir().unwrap();
    let box_dir = root.path().join(".strands/box");
    let path = box_dir.join("installation.toml");
    let first = InstallationId::load_or_create(&box_dir).unwrap();
    let value = serde_json::to_value(first).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/box.schema.json")).unwrap();
    assert!(jsonschema::is_valid(
        &schema["definitions"]["installation_id"],
        &value
    ));
    let contents = fs::read_to_string(&path).unwrap();
    let stored: toml::Table = toml::from_str(&contents).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored["installation_id"].as_str(), value.as_str());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for directory in [root.path().join(".strands"), box_dir.clone()] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert_eq!(InstallationId::load_or_create(&box_dir).unwrap(), first);
    assert_eq!(fs::read_to_string(&path).unwrap(), contents);

    fs::remove_file(&path).unwrap();
    let next = InstallationId::load_or_create(&box_dir).unwrap();
    assert_ne!(next, first);
}

#[test]
fn preserves_existing_installation_metadata_verbatim() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation.toml");
    let contents =
        format!("# installed by the operator\ninstallation_id = '{ID}'\nchannel = 'preview'\n");
    fs::write(&path, &contents).unwrap();
    let id = InstallationId::load_or_create(root.path()).unwrap();
    assert_eq!(serde_json::to_value(id).unwrap(), json!(ID));
    assert_eq!(fs::read_to_string(&path).unwrap(), contents);
}

#[test]
fn adds_a_missing_id_and_preserves_existing_metadata() {
    for original in [
        "",
        "# installation\nchannel = 'preview'\n",
        "# installation\n[installer]\nmethod = 'script'\n",
        "\u{feff}# installation\nchannel = 'preview'\n",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("installation.toml");
        fs::write(&path, original).unwrap();
        let id = InstallationId::load_or_create(root.path()).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        let value = serde_json::to_value(id).unwrap();
        let (bom, original) = original
            .strip_prefix('\u{feff}')
            .map_or(("", original), |original| ("\u{feff}", original));
        assert_eq!(
            contents,
            format!("{bom}installation_id = {value}\n{original}")
        );
        let stored: toml::Table = toml::from_str(&contents).unwrap();
        assert_eq!(stored["installation_id"].as_str(), value.as_str());
        assert_eq!(InstallationId::load_or_create(root.path()).unwrap(), id);
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);
    }
}

#[test]
fn concurrent_creators_agree_on_the_published_identity() {
    for original in [None, Some("# existing metadata\nchannel = 'preview'\n")] {
        let root = tempfile::tempdir().unwrap();
        let box_dir = root.path().join(".strands/box");
        if let Some(original) = original {
            fs::create_dir_all(&box_dir).unwrap();
            fs::write(box_dir.join("installation.toml"), original).unwrap();
        }
        let barrier = Arc::new(Barrier::new(8));
        let (sender, receiver) = mpsc::channel();
        for _ in 0..8 {
            let box_dir = box_dir.clone();
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            let _ = std::thread::spawn(move || {
                barrier.wait();
                let _ = sender.send(InstallationId::load_or_create(&box_dir));
            });
        }
        drop(sender);
        let ids = (0..8)
            .map(|_| {
                receiver
                    .recv_timeout(Duration::from_secs(10))
                    .expect("installation creation did not complete")
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(
            fs::read_dir(&box_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            ["installation.toml"]
        );
        let contents = fs::read_to_string(box_dir.join("installation.toml")).unwrap();
        let stored: toml::Table = toml::from_str(&contents).unwrap();
        assert_eq!(
            stored["installation_id"].as_str(),
            serde_json::to_value(ids[0]).unwrap().as_str()
        );
        if let Some(original) = original {
            assert!(contents.ends_with(original));
        }
    }
}

#[test]
fn invalid_installations_are_left_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation.toml");
    for contents in [
        b"[".as_slice(),
        b"\xff",
        b"installation_id = 12",
        b"installation_id = 'not-a-uuid'",
        b"installation_id = '12345678-90AB-4CDE-8F01-234567890ABC'",
        b"installation_id = '12345678-90ab-1cde-8f01-234567890abc'",
        b"installation_id = '12345678-90ab-4cde-0f01-234567890abc'",
    ] {
        fs::write(&path, contents).unwrap();
        assert!(InstallationId::load_or_create(root.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), contents);
    }
}

#[test]
fn refuses_links_and_special_files() {
    let root = tempfile::tempdir().unwrap();
    let box_dir = root.path().join(".strands/box");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::create_dir(box_dir.parent().unwrap()).unwrap();
    symlink(&elsewhere, &box_dir).unwrap();
    assert!(InstallationId::load_or_create(&box_dir).is_err());
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    fs::remove_file(&box_dir).unwrap();
    fs::create_dir(&box_dir).unwrap();

    let path = box_dir.join("installation.toml");
    let outside = elsewhere.join("installation.toml");
    let contents = format!("installation_id = '{ID}'\n");
    fs::write(&outside, &contents).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(InstallationId::load_or_create(&box_dir).is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), contents);
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(InstallationId::load_or_create(&box_dir).is_err());
    fs::remove_dir(&path).unwrap();
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
    let (sender, receiver) = mpsc::channel();
    let _ = std::thread::spawn(move || {
        let _ = sender.send(InstallationId::load_or_create(&box_dir));
    });
    assert!(
        receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("installation read blocked on a FIFO")
            .is_err()
    );
}

#[test]
fn saving_a_choice_keeps_the_id_and_other_metadata() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation.toml");
    fs::write(
        &path,
        format!("# kept\ninstallation_id = \"{ID}\"\nother = 1\n"),
    )
    .unwrap();
    save_telemetry_choice(root.path(), false).unwrap();
    let contents = fs::read_to_string(&path).unwrap();
    assert!(contents.starts_with("# kept\n"), "{contents}");
    let stored: toml::Table = toml::from_str(&contents).unwrap();
    assert_eq!(stored["installation_id"].as_str(), Some(ID));
    assert_eq!(stored["other"].as_integer(), Some(1));
    assert_eq!(stored["telemetry"].as_bool(), Some(false));
    assert_eq!(
        InstallationId::load_or_create(root.path()).unwrap(),
        InstallationId::load_or_create(root.path()).unwrap()
    );
    assert!(fs::read_to_string(&path).unwrap().contains(ID));
}

#[test]
fn saving_a_choice_before_any_run_creates_no_id() {
    let root = tempfile::tempdir().unwrap();
    let box_dir = root.path().join(".strands/box");
    save_telemetry_choice(&box_dir, false).unwrap();
    let path = box_dir.join("installation.toml");
    let stored: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored["telemetry"].as_bool(), Some(false));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let id = serde_json::to_value(InstallationId::load_or_create(&box_dir).unwrap()).unwrap();
    let stored: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored["installation_id"].as_str(), id.as_str());
    assert_eq!(stored["telemetry"].as_bool(), Some(false));
}

#[test]
fn installation_metadata_refuses_a_linked_parent() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, root.path().join(".strands")).unwrap();
    let box_dir = root.path().join(".strands/box");
    assert!(InstallationId::load_or_create(&box_dir).is_err());
    assert!(save_telemetry_choice(&box_dir, false).is_err());
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);

    fs::create_dir(elsewhere.join("box")).unwrap();
    let path = elsewhere.join("box/installation.toml");
    let contents = format!("installation_id = '{ID}'\ntelemetry = true\n");
    fs::write(&path, &contents).unwrap();
    assert!(saved_choice(&box_dir).is_err());
    assert!(InstallationId::load_or_create(&box_dir).is_err());
    assert!(save_telemetry_choice(&box_dir, false).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), contents);
}

#[test]
fn saving_a_choice_refuses_invalid_metadata_and_links() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation.toml");
    fs::write(&path, "not toml = = =\n").unwrap();
    assert!(save_telemetry_choice(root.path(), false).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "not toml = = =\n");
    fs::remove_file(&path).unwrap();
    let target = root.path().join("elsewhere.toml");
    fs::write(&target, "").unwrap();
    symlink(&target, &path).unwrap();
    assert!(save_telemetry_choice(root.path(), false).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "");
}

#[test]
fn concurrent_choice_saves_and_id_creation_keep_both() {
    for _ in 0..50 {
        let root = tempfile::tempdir().unwrap();
        let box_dir = root.path().join(".strands/box");
        let barrier = Arc::new(Barrier::new(8));
        let (ids, created) = mpsc::channel();
        let (saves, saved) = mpsc::channel();
        for creator in [true, false].repeat(4) {
            let box_dir = box_dir.clone();
            let barrier = Arc::clone(&barrier);
            let ids = ids.clone();
            let saves = saves.clone();
            let _ = std::thread::spawn(move || {
                barrier.wait();
                if creator {
                    let _ = ids.send(InstallationId::load_or_create(&box_dir));
                } else {
                    let _ = saves.send(save_telemetry_choice(&box_dir, false));
                }
            });
        }
        drop((ids, saves));
        let ids = (0..4)
            .map(|_| {
                created
                    .recv_timeout(Duration::from_secs(10))
                    .expect("installation creation did not complete")
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for _ in 0..4 {
            saved
                .recv_timeout(Duration::from_secs(10))
                .expect("saving the choice did not complete")
                .unwrap();
        }
        assert!(ids.iter().all(|id| *id == ids[0]));
        let contents = fs::read_to_string(box_dir.join("installation.toml")).unwrap();
        let stored: toml::Table = toml::from_str(&contents).unwrap();
        assert_eq!(
            stored["installation_id"].as_str(),
            serde_json::to_value(ids[0]).unwrap().as_str(),
            "{contents}"
        );
        assert_eq!(stored["telemetry"].as_bool(), Some(false), "{contents}");
    }
}
