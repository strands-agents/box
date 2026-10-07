//! The config model and its one serialized boundary.
//!
//! There is no wire twin to test: each value carries its own wire form, and each type that holds an
//! invariant validates itself on load. These assert that loading is not a second, weaker path.

use std::path::PathBuf;

use containment::{
    BackendOverride, ContainmentConfig, IpcMode, Network, Operation, ProcessInfoMode, Scope,
    SignalMode,
};

const CROSS_CWD_CONFIG_ENV: &str = "STRANDS_BOX_CONTAINMENT_CROSS_CWD_CONFIG_48A46E9E6D4F4C3A";
const CROSS_CWD_TARGET_ENV: &str = "STRANDS_BOX_CONTAINMENT_CROSS_CWD_TARGET_48A46E9E6D4F4C3A";

#[test]
fn defaults_are_deny_first_and_isolated() {
    let config = ContainmentConfig::new();
    let config_json: serde_json::Value =
        serde_json::from_str(&config.to_json().expect("serialize default config"))
            .expect("parse default config JSON");
    assert_eq!(config_json["paths"], serde_json::json!([]));
    assert_eq!(config_json["identity_requirements"], serde_json::json!([]));
    assert_eq!(config_json["write_protections"], serde_json::json!([]));
    assert_eq!(config.network(), &Network::Blocked);
    assert_eq!(config.signal_mode(), SignalMode::Isolated);
    assert_eq!(config.process_info_mode(), ProcessInfoMode::Isolated);
    assert_eq!(config.ipc_mode(), IpcMode::SharedMemoryOnly);
    assert!(matches!(config.backend_override(), BackendOverride::None));
}

/// **Every legal cell survives the wire, and none folds into another.**
///
/// Exec at file scope in particular must not arrive carrying read: that is the whole reason the
/// two are separate operations, and the macOS profile's exec literal grants no read.
#[test]
fn every_legal_cell_survives_the_wire_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let directory = dir.path().canonicalize().expect("canonical dir");
    let file = directory.join("file");
    std::fs::write(&file, "data").expect("fixture");

    let cells = [
        (file.as_path(), Operation::Exec, Scope::File),
        (directory.as_path(), Operation::Exec, Scope::Root),
        (file.as_path(), Operation::Read, Scope::File),
        (file.as_path(), Operation::Write, Scope::File),
        (file.as_path(), Operation::Connect, Scope::File),
        (directory.as_path(), Operation::Read, Scope::Dir),
        (directory.as_path(), Operation::Read, Scope::Root),
        (directory.as_path(), Operation::List, Scope::Root),
        (directory.as_path(), Operation::Write, Scope::Root),
        (directory.as_path(), Operation::Metadata, Scope::Dir),
        (directory.as_path(), Operation::Metadata, Scope::Root),
    ];

    for (path, operation, scope) in cells {
        let config = ContainmentConfig::new()
            .allow(path, operation, scope)
            .unwrap_or_else(|e| panic!("{operation:?} at {scope:?} is legal: {e:?}"));
        let json = config.to_json().expect("serialize");
        let wire: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(wire["paths"].as_array().expect("paths").len(), 1);

        let restored = ContainmentConfig::from_json(&json).expect("round trip");
        let restored_json = restored.to_json().expect("re-serialize");
        assert_eq!(
            restored_json, json,
            "{operation:?} at {scope:?} did not survive the wire unchanged"
        );
    }

    // **The two denial cells, which `allow` cannot state.** A denial has its own verb, and its wire
    // reload takes the lexical route rather than the authorizing constructor — so these are the cells
    // whose round trip exercises the second branch of `TryFrom`. The file denial is stated on a path
    // that does not exist, because that is the case the lexical route exists for.
    let future = directory.join("not-yet-written");
    for (path, scope) in [
        (directory.as_path(), Scope::Root),
        (future.as_path(), Scope::File),
    ] {
        let denial = ContainmentConfig::new()
            .refuse(path, scope)
            .expect("a denial at this scope is legal");
        let json = denial.to_json().expect("serialize");
        assert_eq!(json.matches("\"deny\"").count(), 1, "{json}");
        let restored = ContainmentConfig::from_json(&json).expect("a denial round trips");
        assert_eq!(
            restored.to_json().expect("re-serialize"),
            json,
            "a denial at {scope:?} scope did not survive the wire unchanged"
        );
    }
}

#[test]
fn path_grants_fail_closed_for_wrong_or_missing_path_kinds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file");
    std::fs::write(&file, "data").expect("fixture");

    assert!(
        ContainmentConfig::new()
            .allow(&file, Operation::Read, Scope::Root)
            .is_err()
    );
    assert!(
        ContainmentConfig::new()
            .allow(dir.path(), Operation::Read, Scope::File)
            .is_err()
    );
    assert!(
        ContainmentConfig::new()
            .allow(dir.path().join("missing"), Operation::Read, Scope::Root)
            .is_err()
    );
}

/// **A file grant never becomes a directory grant.** Reloading revalidates the kind, so replacing
/// the granted file with a directory is refused rather than widened.
#[test]
fn a_file_grant_does_not_survive_replacement_by_a_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file");
    std::fs::write(&file, "data").expect("fixture");

    let json = ContainmentConfig::new()
        .allow(&file, Operation::Read, Scope::File)
        .expect("grant existing file")
        .to_json()
        .expect("serialize");

    std::fs::remove_file(&file).expect("remove granted file");
    std::fs::create_dir(&file).expect("replace file with directory");
    std::fs::write(file.join("child"), "replacement").expect("replacement child");

    assert!(
        ContainmentConfig::from_json(&json).is_err(),
        "a file grant must not reload as a directory grant after path replacement"
    );
}

#[test]
fn a_write_protection_round_trip_retains_the_opened_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("authority");
    std::fs::write(&file, "authority").expect("fixture");
    let opened = std::fs::File::open(&file).expect("open authority");

    let config = ContainmentConfig::new()
        .protect_write(&file, &opened)
        .expect("protect opened authority");
    let json = config.to_json().expect("serialize");
    let wire: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(
        wire["write_protections"][0]["path"]
            .as_str()
            .map(std::path::Path::new),
        Some(file.canonicalize().expect("canonical authority").as_path())
    );

    let restored = ContainmentConfig::from_json(&json).expect("restore live identity");
    assert_eq!(restored.to_json().expect("re-serialize"), json);
}

#[test]
fn a_write_protection_refuses_a_replaced_or_different_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let authority = dir.path().join("authority");
    let different = dir.path().join("different");
    std::fs::write(&authority, "authority").expect("authority fixture");
    std::fs::write(&different, "different").expect("different fixture");
    let opened = std::fs::File::open(&authority).expect("open authority");
    let wrong = std::fs::File::open(&different).expect("open different object");

    assert!(
        ContainmentConfig::new()
            .protect_write(&authority, &wrong)
            .is_err(),
        "a pathname cannot protect a different opened object"
    );

    let json = ContainmentConfig::new()
        .protect_write(&authority, &opened)
        .expect("protect authority")
        .to_json()
        .expect("serialize");
    std::fs::remove_file(&authority).expect("remove authority");
    std::fs::write(&authority, "replacement").expect("replace authority");

    assert!(
        ContainmentConfig::from_json(&json).is_err(),
        "a replacement at the same path must not inherit the opened identity"
    );
}

#[cfg(unix)]
#[test]
fn a_write_protection_refuses_an_object_with_another_hard_link() {
    let dir = tempfile::tempdir().expect("tempdir");
    let authority = dir.path().join("authority");
    let alias = dir.path().join("alias");
    std::fs::write(&authority, "authority").expect("authority fixture");
    let opened = std::fs::File::open(&authority).expect("open authority");
    std::fs::hard_link(&authority, &alias).expect("hard-link alias");

    let error = ContainmentConfig::new()
        .protect_write(&authority, &opened)
        .expect_err("one protected pathname cannot cover a hard-link alias")
        .to_string();
    assert!(error.contains("hard links"), "{error}");
}

#[cfg(unix)]
#[test]
fn an_identity_requirement_refuses_a_hard_link_added_before_apply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let authority = dir.path().join("authority");
    let alias = dir.path().join("alias");
    std::fs::write(&authority, "authority").expect("authority fixture");
    let opened = std::fs::File::open(&authority).expect("open authority");
    let json = ContainmentConfig::new()
        .require_file_identity(&authority, &opened)
        .expect("require authority identity")
        .to_json()
        .expect("serialize");

    std::fs::hard_link(&authority, &alias).expect("hard-link alias");

    let error = ContainmentConfig::from_json(&json)
        .expect_err("apply-time loading must refuse the new alias")
        .to_string();
    assert!(error.contains("identity changed before apply"), "{error}");
}

#[cfg(unix)]
#[test]
fn a_write_protection_refuses_a_new_symlink_spelling_for_the_same_object() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let original = dir.path().join("original");
    let moved = dir.path().join("moved");
    std::fs::create_dir(&original).expect("authority directory");
    let authority = original.join("authority");
    std::fs::write(&authority, "authority").expect("authority fixture");
    let opened = std::fs::File::open(&authority).expect("open authority");
    let json = ContainmentConfig::new()
        .protect_write(&authority, &opened)
        .expect("protect authority")
        .to_json()
        .expect("serialize");

    std::fs::rename(&original, &moved).expect("move authority directory");
    symlink(&moved, &original).expect("replace original directory with a symlink");

    let error = ContainmentConfig::from_json(&json)
        .expect_err("a new spelling must not inherit protection")
        .to_string();
    assert!(error.contains("canonical path changed"), "{error}");
}

#[test]
fn relative_grant_round_trip_is_independent_of_exec_cwd() {
    if let Some(json) = std::env::var_os(CROSS_CWD_CONFIG_ENV) {
        let target = std::env::var_os(CROSS_CWD_TARGET_ENV)
            .map(std::path::PathBuf::from)
            .expect("cross-cwd target");
        let config = ContainmentConfig::from_json(
            json.to_str().expect("cross-cwd config JSON must be UTF-8"),
        )
        .expect("absolute caller spelling must reload under a different cwd");
        let wire: serde_json::Value =
            serde_json::from_str(&config.to_json().expect("re-serialize")).expect("parse");
        assert_eq!(
            wire["paths"][0]["resolved"]
                .as_str()
                .map(std::path::Path::new),
            Some(target.canonicalize().expect("canonical target").as_path()),
        );
        return;
    }

    let authoring_cwd = std::env::current_dir().expect("authoring cwd");
    let grant = tempfile::Builder::new()
        .prefix("containment-relative-grant-")
        .tempdir_in(&authoring_cwd)
        .expect("relative grant directory");
    let relative = grant
        .path()
        .strip_prefix(&authoring_cwd)
        .expect("grant must be below authoring cwd");
    let config = ContainmentConfig::new()
        .allow(relative, Operation::Read, Scope::Root)
        .expect("relative grant");
    let json = config.to_json().expect("serialize relative grant");
    let wire: serde_json::Value = serde_json::from_str(&json).expect("parse config JSON");
    let serialized_original = wire["paths"][0]["original"]
        .as_str()
        .map(std::path::Path::new)
        .expect("serialized original path");
    assert!(
        serialized_original.is_absolute(),
        "the authoring process must freeze a relative spelling as absolute"
    );

    let other_cwd = tempfile::tempdir().expect("different exec cwd");
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("relative_grant_round_trip_is_independent_of_exec_cwd")
        .arg("--nocapture")
        .current_dir(other_cwd.path())
        .env(CROSS_CWD_CONFIG_ENV, &json)
        .env(CROSS_CWD_TARGET_ENV, grant.path())
        .output()
        .expect("run cross-cwd child");

    assert!(
        output.status.success(),
        "cross-cwd reload failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn round_trip_preserves_every_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let canonical_dir = dir.path().canonicalize().expect("canonical dir");
    let file = canonical_dir.join("input.txt");
    std::fs::write(&file, "input").expect("write fixture");
    let program = canonical_dir.join("program");
    std::fs::write(&program, "program").expect("write program fixture");
    let socket = canonical_dir.join("proxy.sock");
    std::fs::write(&socket, "").expect("create socket-path fixture");

    let config = ContainmentConfig::new()
        .allow(&canonical_dir, Operation::Read, Scope::Root)
        .expect("read tree")
        .allow(&canonical_dir, Operation::Write, Scope::Root)
        .expect("write tree")
        .allow(&file, Operation::Read, Scope::File)
        .expect("read file")
        .allow(&program, Operation::Exec, Scope::File)
        .expect("exec file")
        .allow(&socket, Operation::Connect, Scope::File)
        .expect("connect socket")
        .allow(&canonical_dir, Operation::Read, Scope::Dir)
        .expect("read dir")
        .set_network(
            Network::localhost()
                .connect(8443)
                .connect(4319)
                .listen(3000)
                .listen(3001),
        )
        .expect("network")
        .set_signal_mode(SignalMode::AllowAll)
        .set_process_info_mode(ProcessInfoMode::AllowAll)
        .set_ipc_mode(IpcMode::Full)
        .with_backend_override(BackendOverride::Seatbelt {
            extensions_enabled: true,
        });

    let json = config.to_json().expect("serialize");
    let restored = ContainmentConfig::from_json(&json).expect("round trip");

    // Read through the wire, because the grant's fields are the crate's own. Exec without read
    // must survive in particular: collapsing the pair would silently add a read of the program's
    // bytes.
    let wire: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let grants: Vec<(String, String, String)> = wire["paths"]
        .as_array()
        .expect("paths")
        .iter()
        .map(|entry| {
            (
                entry["resolved"].as_str().expect("resolved").to_string(),
                entry["operation"].as_str().expect("operation").to_string(),
                entry["scope"].as_str().expect("scope").to_string(),
            )
        })
        .collect();
    let text = |path: &std::path::Path| path.display().to_string();
    assert_eq!(
        grants,
        vec![
            (text(&canonical_dir), "read".into(), "root".into()),
            (text(&canonical_dir), "write".into(), "root".into()),
            (text(&file), "read".into(), "file".into()),
            (text(&program), "exec".into(), "file".into()),
            (text(&socket), "connect".into(), "file".into()),
            (text(&canonical_dir), "read".into(), "dir".into()),
        ]
    );

    assert_eq!(restored.network(), config.network());
    assert_eq!(restored.signal_mode(), SignalMode::AllowAll);
    assert_eq!(restored.process_info_mode(), ProcessInfoMode::AllowAll);
    assert_eq!(restored.ipc_mode(), IpcMode::Full);
    assert!(matches!(
        restored.backend_override(),
        BackendOverride::Seatbelt {
            extensions_enabled: true
        }
    ));

    // Re-serializing is byte-identical, so nothing folded or reordered on the way through.
    assert_eq!(restored.to_json().expect("re-serialize"), json);
}

/// The leaf-only fields survive the wire, so a leaf restored by the trampoline keeps discovery,
/// its box-state exclusion, broad exec, and runtime services.
#[test]
fn a_leaf_config_round_trips_every_leaf_field() {
    let home = tempfile::tempdir().expect("an operator home");
    let home_path = home.path().canonicalize().expect("canonical home");
    let box_state = home_path.join("box");
    std::fs::create_dir(&box_state).expect("a box directory");

    let config = ContainmentConfig::new()
        .anchored_at(&home_path)
        .allow_discovery(&home_path)
        .deny_discovery(&box_state)
        .allow_broad_exec()
        .allow_runtime_services();
    let json = config.to_json().expect("serialize");
    let restored = ContainmentConfig::from_json(&json).expect("round trip");

    let wire: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let text = |path: &std::path::Path| serde_json::json!([path.display().to_string()]);
    assert_eq!(wire["discovery_roots"], text(&home_path));
    assert_eq!(wire["discovery_denies"], text(&box_state));
    assert_eq!(wire["broad_exec"], serde_json::json!(true));
    assert_eq!(wire["runtime_services"], serde_json::json!(true));
    assert_eq!(restored.to_json().expect("re-serialize"), json);

    let agent: serde_json::Value = serde_json::from_str(
        &ContainmentConfig::new()
            .to_json()
            .expect("serialize the agent"),
    )
    .expect("parse the agent");
    assert_eq!(agent["discovery_roots"], serde_json::json!([]));
    assert_eq!(agent["discovery_denies"], serde_json::json!([]));
    assert_eq!(agent["broad_exec"], serde_json::json!(false));
    assert_eq!(agent["runtime_services"], serde_json::json!(false));
}

/// A crafted payload meets every refusal a builder call does, because loading rebuilds.
///
/// Four crafted shapes, one per refusal: a path that does not exist, a relative path, a
/// `resolved` that drifted, and a cell the vocabulary refuses.
#[test]
fn loading_refuses_what_a_builder_call_refuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let canonical = dir.path().canonicalize().expect("canonical dir");

    for (crafted, expected) in [
        (
            grant_payload(
                "/nonexistent/crafted/path",
                "/nonexistent/crafted/path",
                "write",
                "root",
            ),
            "does not exist",
        ),
        (
            grant_payload(
                "relative/path",
                &canonical.display().to_string(),
                "read",
                "root",
            ),
            "must be absolute",
        ),
        (
            grant_payload(&canonical.display().to_string(), "/etc", "read", "root"),
            "drifted",
        ),
        (
            grant_payload(
                &canonical.display().to_string(),
                &canonical.display().to_string(),
                "exec",
                "dir",
            ),
            "no bytes to execute",
        ),
        (
            grant_payload(
                &canonical.display().to_string(),
                &canonical.display().to_string(),
                "list",
                "dir",
            ),
            "read at dir scope",
        ),
    ] {
        let error = ContainmentConfig::from_json(&crafted)
            .expect_err("a crafted payload must meet the builder's refusal")
            .to_string()
            .to_ascii_lowercase();
        assert!(
            error.contains(&expected.to_ascii_lowercase()),
            "expected {expected:?} in: {error}"
        );
    }
}

/// **A zero port is refused on the wire**, so a payload cannot name what a builder rejects.
#[test]
fn loading_refuses_a_zero_connect_or_listen_port() {
    for network in [
        r#"{"localhost":{"connect":[0],"listen":[]}}"#,
        r#"{"localhost":{"connect":[8080,0],"listen":[]}}"#,
        r#"{"localhost":{"connect":[8080],"listen":[0]}}"#,
    ] {
        let json = format!(
            r#"{{"paths":[],"write_protections":[],"network":{network},"process":{{"signals":"isolated","info":"isolated","ipc":"shared_memory_only"}},"backend_override":"none","operator_home":null}}"#
        );
        let error = ContainmentConfig::from_json(&json)
            .expect_err("port 0 is never a port")
            .to_string();
        assert!(error.contains("port"), "{error}");
    }
}

/// An unknown key is a load error rather than a silently dropped field, at every level.
#[test]
fn unknown_fields_are_rejected() {
    let config = ContainmentConfig::new()
        .set_network(Network::localhost().connect(8080))
        .expect("localhost");
    let json = config.to_json().expect("serialize");

    for (find, replace) in [
        (r#""paths""#, r#""unknown":true,"paths""#),
        (r#""connect""#, r#""unknown":true,"connect""#),
        (r#""signals""#, r#""unknown":true,"signals""#),
    ] {
        let crafted = json.replacen(find, replace, 1);
        assert_ne!(crafted, json, "the probe must have changed the payload");
        assert!(
            ContainmentConfig::from_json(&crafted).is_err(),
            "an unknown key beside {find} must be refused: {crafted}"
        );
    }
}

/// An absent key is a load error too, so a payload cannot leave a mode to a default.
#[test]
fn absent_fields_are_rejected() {
    let json = ContainmentConfig::new().to_json().expect("serialize");
    for key in [
        "network",
        "process",
        "backend_override",
        "paths",
        "write_protections",
        "operator_home",
    ] {
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        value.as_object_mut().expect("object").remove(key);
        let crafted = serde_json::to_string(&value).expect("json");
        assert!(
            ContainmentConfig::from_json(&crafted).is_err(),
            "an absent {key} must be refused"
        );
    }
}

/// A stated home that is not an absolute path is refused on load.
///
/// **The floor's anchors may not depend on a working directory.** A relative spelling would be
/// canonicalized against the applying process's cwd, so the same config would anchor differently
/// depending on where the trampoline was started. The field must refuse this itself, the way a
/// `PathGrant` refuses its own illegal cell, rather than leaving it to a caller
/// (docs/design/decisions.md#the-configuration-is-its-own-wire-format).
#[test]
fn a_stated_home_that_is_not_absolute_is_rejected() {
    let json = ContainmentConfig::new().to_json().expect("serialize");
    for spelling in ["relative/not/absolute", "", "..", "~", "~/.aws"] {
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        value
            .as_object_mut()
            .expect("object")
            .insert("operator_home".to_string(), spelling.into());
        let crafted = serde_json::to_string(&value).expect("json");
        let error = ContainmentConfig::from_json(&crafted)
            .expect_err(&format!(
                "{spelling:?} is not an absolute home and must be refused"
            ))
            .to_string();
        assert!(
            error.contains("absolute"),
            "the refusal must say what is wrong with it: {error}"
        );
    }

    // The shape that must still load, so the check above is not refusing everything.
    let mut value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    value
        .as_object_mut()
        .expect("object")
        .insert("operator_home".to_string(), "/Users/operator".into());
    let crafted = serde_json::to_string(&value).expect("json");
    ContainmentConfig::from_json(&crafted).expect("an absolute home loads");
}

/// One grant's payload, so a crafted case reads as the one field it varies.
fn grant_payload(original: &str, resolved: &str, operation: &str, scope: &str) -> String {
    let original = PathBuf::from(original);
    let resolved = PathBuf::from(resolved);
    format!(
        r#"{{"paths":[{{"original":{original:?},"resolved":{resolved:?},"operation":"{operation}","scope":"{scope}"}}],"write_protections":[],"network":"blocked","process":{{"signals":"isolated","info":"isolated","ipc":"shared_memory_only"}},"backend_override":"none","operator_home":null}}"#
    )
}
