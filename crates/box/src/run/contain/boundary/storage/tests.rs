use super::*;
use crate::record::config::process::Filesystem;
use std::process::Command;

const CHILD_ROLE: &str = "BOX_FROZEN_CONTEXT_TEST_ROLE";
const CHILD_ROOT: &str = "BOX_FROZEN_CONTEXT_TEST_ROOT";
const TEST_NAME: &str =
    "run::contain::boundary::storage::tests::frozen_context_survives_fresh_worker_environment";

fn compile(
    frozen: &FrozenFilesystemContext,
    lists: &Filesystem,
) -> Result<FilesystemGeneration, BoxError> {
    frozen.with_context("[agent]", |context| {
        Ok(FilesystemPlan::new(lists, &[], context)?.compile_generation(&[], context)?)
    })
}

fn assert_refused(frozen: &FrozenFilesystemContext, lists: &Filesystem, reason: &str) {
    let error = compile(frozen, lists).expect_err("the captured guard must refuse this grant");
    assert!(error.to_string().contains(reason), "{error}");
}

fn capture(root: &Path) {
    let source = AuthoritySource::read(&root.join("home/project/authority/source.dw"), "policy")
        .unwrap()
        .0;
    let mut tables = ProcessTables {
        tables: Vec::new(),
        policy: Some(root.join("policy-link/policy.dw")),
        declares_stdio_mcp: true,
        source_paths: vec![
            ProtectedPath {
                scheme: "fixture".to_string(),
                list: "reads",
                entry: "~/secret-read".to_string(),
            },
            ProtectedPath {
                scheme: "fixture".to_string(),
                list: "deny",
                entry: "~/secret-deny".to_string(),
            },
        ],
    };
    let frozen =
        FrozenFilesystemContext::capture("[agent]", &tables, &[source.clone(), source]).unwrap();
    assert_eq!(frozen.operator_home, root.join("home"));
    assert_eq!(frozen.policy, Some(root.join("policy/policy.dw")));
    assert_eq!(
        frozen.authority_directories,
        vec![root.join("home/project/authority")]
    );
    assert_eq!(
        frozen.program_search_directories,
        vec![root.join("search-bin")]
    );
    assert_eq!(frozen.source_paths.len(), 2);
    std::fs::write(root.join("seed.json"), serde_json::to_vec(&frozen).unwrap()).unwrap();

    // The existing constructor protects PATH only when a local MCP server is declared.
    tables.declares_stdio_mcp = false;
    assert!(
        FrozenFilesystemContext::capture("[agent]", &tables, &[])
            .unwrap()
            .program_search_directories
            .is_empty()
    );
}

fn imported_controls(root: &Path) {
    let frozen: FrozenFilesystemContext =
        serde_json::from_slice(&std::fs::read(root.join("seed.json")).unwrap()).unwrap();
    assert_ne!(
        std::env::var_os("HOME"),
        Some(root.join("home").into_os_string())
    );
    assert_ne!(
        std::env::var_os("PATH"),
        Some(root.join("search-bin").into_os_string())
    );

    let read = Filesystem {
        read_file: vec![PathBuf::from("~/project/data")],
        ..Filesystem::default()
    };
    let generation = compile(&frozen, &read).unwrap();
    generation.with_policy(|reach, _, _| {
        assert_eq!(reach.grants.len(), 1);
        assert_eq!(reach.grants[0].resolved, root.join("home/project/data"));
    });
    let mut changed_home = frozen.clone();
    changed_home.operator_home = root.join("other-home");
    compile(&changed_home, &read)
        .unwrap()
        .with_policy(|reach, _, _| {
            assert_eq!(
                reach.grants[0].resolved,
                root.join("other-home/project/data")
            );
        });

    let write_search = Filesystem {
        read: vec![root.join("search-bin")],
        write: vec![root.join("search-bin")],
        ..Filesystem::default()
    };
    assert_refused(&frozen, &write_search, "search path");
    let mut missing_search_guard = frozen.clone();
    missing_search_guard.program_search_directories.clear();
    compile(&missing_search_guard, &write_search).unwrap();

    let write_policy = Filesystem {
        read_file: vec![root.join("policy/policy.dw")],
        write_file: vec![root.join("policy/policy.dw")],
        ..Filesystem::default()
    };
    assert_refused(&frozen, &write_policy, "policy file");
    let mut missing_policy_guard = frozen.clone();
    missing_policy_guard.policy = None;
    compile(&missing_policy_guard, &write_policy).unwrap();

    let read_project = Filesystem {
        read: vec![root.join("home/project")],
        ..Filesystem::default()
    };
    let authority = root.join("home/project/authority");
    compile(&frozen, &read_project)
        .unwrap()
        .with_policy(|reach, _, _| {
            assert!(
                reach
                    .refusals
                    .iter()
                    .any(|refusal| refusal.path == authority)
            );
        });
    let mut missing_authority_guard = frozen.clone();
    missing_authority_guard.authority_directories.clear();
    compile(&missing_authority_guard, &read_project)
        .unwrap()
        .with_policy(|reach, _, _| {
            assert!(
                !reach
                    .refusals
                    .iter()
                    .any(|refusal| refusal.path == authority)
            );
        });

    for entry in ["~/secret-read", "~/secret-deny"] {
        let read_secret = Filesystem {
            read_file: vec![PathBuf::from(entry)],
            ..Filesystem::default()
        };
        assert_refused(&frozen, &read_secret, "fixture");
        let mut missing_source_guard = frozen.clone();
        missing_source_guard.source_paths.clear();
        compile(&missing_source_guard, &read_secret).unwrap();
    }
}

fn child(root: &Path, role: &str, ambient: bool) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env(CHILD_ROLE, role)
        .env(CHILD_ROOT, root)
        .current_dir("/");
    if role == "capture" {
        command.env("HOME", root.join("home-link"));
        command.env("PATH", root.join("search-link"));
    } else if ambient {
        command.env("HOME", root.join("other-home"));
        command.env("PATH", root.join("other-search"));
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{role} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn frozen_context_survives_fresh_worker_environment() {
    if let Some(role) = std::env::var_os(CHILD_ROLE) {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).unwrap());
        match role.to_str().unwrap() {
            "capture" => capture(&root),
            "import" => imported_controls(&root),
            other => panic!("unknown test role: {other}"),
        }
        return;
    }

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    for directory in [
        "home/project/authority",
        "other-home/project",
        "search-bin",
        "other-search",
        "policy",
    ] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (path, contents) in [
        ("home/project/data", "original home"),
        ("other-home/project/data", "different home"),
        ("home/project/authority/source.dw", "authority fixture"),
        ("policy/policy.dw", "policy fixture"),
        ("home/secret-read", "source reads fixture"),
        ("home/secret-deny", "source deny fixture"),
    ] {
        std::fs::write(root.join(path), contents).unwrap();
    }
    for (target, link) in [
        ("home", "home-link"),
        ("search-bin", "search-link"),
        ("policy", "policy-link"),
    ] {
        std::os::unix::fs::symlink(root.join(target), root.join(link)).unwrap();
    }
    child(&root, "capture", true);
    child(&root, "import", true);
    child(&root, "import", false);
}

fn seed() -> FrozenFilesystemContext {
    FrozenFilesystemContext {
        table: "[agent]".to_string(),
        operator_home: PathBuf::from("/original/home"),
        policy: None,
        authority_directories: Vec::new(),
        program_search_directories: Vec::new(),
        upstream_trust: Vec::new(),
        source_paths: vec![FrozenSourcePath {
            scheme: "fixture".to_string(),
            list: SourceList::Deny,
            entry: "~/private".to_string(),
        }],
    }
}

#[test]
fn frozen_context_preserves_upstream_trust_write_protection() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let trust = root.join("roots.pem");
    std::fs::write(&trust, "trust fixture").unwrap();
    let mut original = seed();
    original.operator_home = root;
    original.source_paths.clear();
    original.upstream_trust = vec![trust.clone()];
    let frozen: FrozenFilesystemContext =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(frozen.upstream_trust, original.upstream_trust);

    let mut access = Filesystem {
        read_file: vec![trust.clone()],
        ..Filesystem::default()
    };
    compile(&frozen, &access).unwrap();
    access.write_file.push(trust);
    assert_refused(&frozen, &access, "SSL_CERT_FILE");

    let mut without_guard = frozen;
    without_guard.upstream_trust.clear();
    compile(&without_guard, &access).unwrap();
}

#[test]
fn frozen_context_refuses_other_process_table_before_compilation() {
    let error = seed()
        .with_context("[tool.reader]", |_| -> Result<(), BoxError> {
            panic!("a different process's context must never reach the compiler")
        })
        .unwrap_err();
    assert!(error.to_string().contains("different process table"));
}

#[test]
fn frozen_context_import_refuses_unknown_or_missing_fields_and_source_lists() {
    let original = serde_json::to_value(seed()).unwrap();
    let mut unknown = original.clone();
    unknown["ambient_home"] = serde_json::json!("/replacement");
    assert!(serde_json::from_value::<FrozenFilesystemContext>(unknown).is_err());
    for field in [
        "operator_home",
        "policy",
        "source_paths",
        "program_search_directories",
        "upstream_trust",
    ] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<FrozenFilesystemContext>(missing).is_err());
    }
    let mut nested = original.clone();
    nested["source_paths"][0]["ambient_entry"] = serde_json::json!("/replacement");
    assert!(serde_json::from_value::<FrozenFilesystemContext>(nested).is_err());
    let mut source_list = original;
    source_list["source_paths"][0]["list"] = serde_json::json!("write");
    assert!(serde_json::from_value::<FrozenFilesystemContext>(source_list).is_err());
}
