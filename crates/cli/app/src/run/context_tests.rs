use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

const PROFILE: &[u8] = b"[agent]\ncommand = [\"/usr/bin/true\"]\n";
const PROFILE_HASH: &str = "8dbd425d78fbd2346b8263ba59f6447690fe9db9133aab6228f83d1fc8b28acf";

fn expected(
    profile: &[u8],
    packs: Option<&[&str]>,
    custom: Option<bool>,
    policy: Option<bool>,
    mcp: Option<bool>,
) -> Value {
    json!({
        "box_version": crate::telemetry::VERSION,
        "os_family": match std::env::consts::OS {
            "macos" | "linux" | "windows" => std::env::consts::OS,
            _ => "other",
        },
        "os_version": sysinfo::System::os_version().ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()),
        "build_arch": match std::env::consts::ARCH {
            "aarch64" | "x86_64" => std::env::consts::ARCH,
            _ => "other",
        },
        "profile_hash": format!("{:x}", Sha256::digest(profile)),
        "builtin_packs": packs,
        "has_custom_packs": custom,
        "profile_policy_present": policy,
        "mcp_configured": mcp,
    })
}

struct Fixture {
    _root: tempfile::TempDir,
    folder: PathBuf,
    workspace: PathBuf,
    launcher: Launcher,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("bx")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        let workspace = home.join("project");
        let folder = home.join(".strands/box/profiles/test");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&folder).unwrap();
        let launcher = Launcher::from_host()
            .home(&home)
            .search_path("/usr/bin:/bin")
            .environment(&[]);
        Self {
            _root: root,
            folder,
            workspace,
            launcher,
        }
    }

    fn write(&self, bytes: &[u8]) {
        std::fs::write(self.folder.join("profile.toml"), bytes).unwrap();
    }

    fn prepare(&self) -> Preparation {
        self.launcher
            .prepare_with_context("test", &self.workspace, None)
    }
}

#[test]
fn installation_id_survives_box_home_changes_and_cleanup() {
    let mut fixture = Fixture::new();
    let installed = fixture.launcher.host.home.join(".strands/box");
    let tries = fixture._root.path().canonicalize().unwrap().join("tries");
    let first = tries.join("first");
    std::fs::create_dir_all(&first).unwrap();
    fixture.folder = first.join("profiles/test");
    fixture.launcher = fixture.launcher.box_home(&first);
    let failed = fixture.prepare();
    assert!(matches!(failed.result, Err(Error::ProfileMissing { .. })));
    let id = failed
        .installation_id
        .expect("identity before profile loading");
    let installation = installed.join("installation.toml");
    assert!(installation.is_file());
    let saved = std::fs::read_to_string(&installation).unwrap();
    let document: toml::Table = toml::from_str(&saved).unwrap();
    assert_eq!(
        document["installation_id"].as_str().unwrap(),
        serde_json::to_value(id).unwrap().as_str().unwrap()
    );

    for box_home in [
        installed.clone(),
        first.clone(),
        tries.join("second"),
        first,
    ] {
        fixture.folder = box_home.join("profiles/test");
        fixture.launcher = fixture.launcher.box_home(&box_home);
        std::fs::create_dir_all(&fixture.folder).unwrap();
        fixture.write(PROFILE);
        let prepared = fixture.prepare();
        assert!(prepared.result.is_ok(), "{:?}", prepared.result);
        assert_eq!(prepared.installation_id, Some(id));
        drop(prepared);
        if box_home != installed {
            assert!(!box_home.join("installation.toml").exists());
            std::fs::remove_dir_all(&box_home).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&installation).unwrap(), saved);
    }
}

#[test]
fn unavailable_installation_id_does_not_fail_preparation() {
    let mut fixture = Fixture::new();
    let box_home = fixture
        ._root
        .path()
        .canonicalize()
        .unwrap()
        .join("selected");
    fixture.folder = box_home.join("profiles/test");
    fixture.launcher = fixture.launcher.box_home(&box_home);
    std::fs::create_dir_all(&fixture.folder).unwrap();
    fixture.write(PROFILE);
    let installation = fixture
        .launcher
        .host
        .home
        .join(".strands/box/installation.toml");
    std::fs::create_dir(&installation).unwrap();
    let prepared = fixture.prepare();
    assert!(prepared.result.is_ok(), "{:?}", prepared.result);
    assert_eq!(prepared.installation_id, None);
    assert!(installation.is_dir());
    assert!(!box_home.join("installation.toml").exists());
}

#[test]
fn ordinary_preparation_does_not_create_installation_metadata() {
    let fixture = Fixture::new();
    fixture.write(PROFILE);
    fixture
        .launcher
        .prepare("test", &fixture.workspace, None)
        .unwrap();
    assert!(
        !fixture
            .launcher
            .host
            .home
            .join(".strands/box/installation.toml")
            .exists()
    );
}

#[test]
fn a_nonabsolute_home_creates_no_installation_metadata() {
    let root = tempfile::Builder::new()
        .prefix(".box-installation-test-")
        .tempdir_in(".")
        .unwrap();
    let home = PathBuf::from(root.path().file_name().unwrap());
    let box_home = root.path().canonicalize().unwrap().join("box");
    let mut launcher = Launcher::from_host().box_home(&box_home);
    launcher.host.home = home;
    let prepared = launcher.prepare_with_context("missing", root.path(), None);
    assert!(prepared.result.is_err());
    assert_eq!(prepared.installation_id, None);
    assert!(!root.path().join(".strands/box").exists());
    assert!(!box_home.exists());
}

#[test]
fn preparation_errors_preserve_the_original_profile_bytes() {
    let fixture = Fixture::new();
    for (bytes, hash, policy_present) in [
        (
            b"[".as_slice(),
            "245843abef9e72e7efac30138a994bf6301e7e1d7d7042a33d42e863d2638811",
            None,
        ),
        (
            b"\xff".as_slice(),
            "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
            None,
        ),
        (
            b"policies = [\"missing.dw\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n".as_slice(),
            "00692bc09b6ddbbd869aea9f32b202c52c3d66f35f076e9bcb582bfac628b739",
            Some(true),
        ),
    ] {
        fixture.write(bytes);
        let prepared = fixture.prepare();
        assert!(prepared.result.is_err());
        let context = serde_json::to_value(prepared.context).unwrap();
        assert_eq!(context["profile_hash"], hash);
        assert_eq!(context["profile_policy_present"], json!(policy_present));
        assert_eq!(context["builtin_packs"], Value::Null);
        assert_eq!(context["has_custom_packs"], Value::Null);
        assert_eq!(context["mcp_configured"], Value::Null);
    }
}

#[test]
fn policy_presence_follows_the_list_and_ignores_unlisted_files() {
    for (policies, leftover, expected) in [
        ("policies = ['rules.dw']\n", false, true),
        ("", true, false),
        ("policies = []\n", true, false),
        ("policies = ['policy.dw']\n", true, true),
    ] {
        let fixture = Fixture::new();
        fixture.write(format!("{policies}[agent]\ncommand = ['/usr/bin/true']\n").as_bytes());
        std::fs::write(fixture.folder.join("rules.dw"), "").unwrap();
        if leftover {
            std::fs::write(fixture.folder.join("policy.dw"), "").unwrap();
        }
        let prepared = fixture.prepare();
        assert!(prepared.result.is_ok(), "{policies}: {:?}", prepared.result);
        assert_eq!(
            serde_json::to_value(prepared.context).unwrap()["profile_policy_present"],
            expected,
            "{policies}"
        );
    }
}

#[test]
fn completed_graph_survives_resolution_failure_and_failed_graph_stays_unknown() {
    let fixture = Fixture::new();
    fixture.write(b"packs = [\"@box/base\"]\n[agent]\ncommand = [\"${{ no.such.reference }}\"]\n");
    let prepared = fixture.prepare();
    assert!(prepared.result.is_err());
    let context = serde_json::to_value(prepared.context).unwrap();
    assert_eq!(context["builtin_packs"], json!(["base"]));
    assert_eq!(context["has_custom_packs"], false);
    assert!(fixture.launcher.runs().unwrap().is_empty());

    fixture.write(b"packs = [\"private-missing-pack\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n");
    let prepared = fixture.prepare();
    assert!(prepared.result.is_err());
    let context = serde_json::to_value(prepared.context).unwrap();
    assert_eq!(context["builtin_packs"], Value::Null);
    assert_eq!(context["has_custom_packs"], Value::Null);
    assert!(!context.to_string().contains("private-missing-pack"));
    assert!(fixture.launcher.runs().unwrap().is_empty());
}

#[test]
fn successful_context_is_frozen_before_the_workload_runs() {
    let fixture = Fixture::new();
    fixture.write(PROFILE);
    let prepared = fixture.prepare();
    let launch = prepared.result.unwrap();
    let context = serde_json::to_value(&prepared.context).unwrap();
    assert_eq!(context["profile_hash"], PROFILE_HASH);
    assert_eq!(context["builtin_packs"], json!([]));
    assert_eq!(context["has_custom_packs"], false);
    assert_eq!(context["profile_policy_present"], false);
    assert_eq!(context["mcp_configured"], false);

    fixture.write(
        b"policies = ['policy.dw']\n# a changed profile\n[agent]\ncommand = [\"/usr/bin/true\"]\n",
    );
    std::fs::write(fixture.folder.join("policy.dw"), "").unwrap();
    let next =
        fixture
            .launcher
            .prepare_with_context("test", &fixture.workspace, Some(launch.name()));
    assert!(matches!(next.result, Err(Error::BoxIdRunning { .. })));
    let next_context = serde_json::to_value(next.context).unwrap();
    assert_ne!(next_context["profile_hash"], context["profile_hash"]);
    assert_eq!(next_context["profile_policy_present"], true);
    assert_eq!(serde_json::to_value(&prepared.context).unwrap(), context);
    assert!(launch.config().is_file());
}

#[test]
fn missing_profiles_and_invalid_names_leave_observations_unknown() {
    let fixture = Fixture::new();
    for name in ["test", "../outside"] {
        let prepared = fixture
            .launcher
            .prepare_with_context(name, &fixture.workspace, None);
        assert!(prepared.result.is_err());
        let context = serde_json::to_value(prepared.context).unwrap();
        for field in [
            "profile_hash",
            "profile_policy_present",
            "builtin_packs",
            "has_custom_packs",
            "mcp_configured",
        ] {
            assert_eq!(context[field], Value::Null, "{name}: {field}");
        }
        assert_eq!(context["box_version"], crate::telemetry::VERSION);
        assert_eq!(
            context["os_family"],
            match std::env::consts::OS {
                "macos" | "linux" | "windows" => std::env::consts::OS,
                _ => "other",
            }
        );
        assert_eq!(
            context["build_arch"],
            match std::env::consts::ARCH {
                "aarch64" | "x86_64" => std::env::consts::ARCH,
                _ => "other",
            }
        );
    }
}

fn claude_profile(host: &crate::FakeHost, box_home: &Path, import: bool) {
    host.profile()
        .box_home(box_home)
        .profiles(box_home.join("profiles"))
        .with("claude")
        .option("claude.import-mcp", if import { "true" } else { "false" })
        .with("bedrock")
        .tools(std::iter::empty::<&str>())
        .create()
        .unwrap()
        .write(true)
        .unwrap();
}

#[test]
fn mcp_context_reads_imported_and_preserved_settings() {
    let host = crate::FakeHost::new();
    let directory = tempfile::Builder::new()
        .prefix("bx")
        .tempdir_in("/tmp")
        .unwrap();
    let box_home = directory.path().canonicalize().unwrap();
    std::fs::write(
        host.home().join(".claude.json"),
        r#"{"mcpServers":{"docs":{"url":"https://docs.example.com/mcp"}}}"#,
    )
    .unwrap();
    claude_profile(&host, &box_home, true);
    let launcher = host.launcher().box_home(&box_home);
    let path = box_home.join("profiles/claude/profile.toml");
    let prepared = launcher.prepare_with_context("claude", &host.project(), None);
    assert!(prepared.result.is_ok(), "{:?}", prepared.result);
    let captured = serde_json::to_value(&prepared.context).unwrap();
    assert_eq!(
        captured,
        expected(
            &std::fs::read(&path).unwrap(),
            Some(&["base", "bedrock", "claude"]),
            Some(false),
            Some(false),
            Some(true),
        )
    );

    std::fs::write(host.home().join(".claude.json"), "{}").unwrap();
    let target = lang::storage_root(&box_home, "claude").join("agent/config/.claude.json");
    for import in [true, false] {
        claude_profile(&host, &box_home, import);
        for (stored, configured) in [
            (
                r#"{"mcpServers":{"saved":{"url":"https://private.example.com"}}}"#,
                true,
            ),
            (r#"{"mcpServers":{}}"#, false),
            ("{}", false),
        ] {
            std::fs::write(&target, stored).unwrap();
            let next = launcher.prepare_with_context("claude", &host.project(), None);
            assert!(next.result.is_ok(), "{:?}", next.result);
            let context = serde_json::to_value(next.context).unwrap();
            assert_eq!(
                context,
                expected(
                    &std::fs::read(&path).unwrap(),
                    Some(&["base", "bedrock", "claude"]),
                    Some(false),
                    Some(false),
                    Some(configured),
                ),
                "import={import}"
            );
        }
    }
    assert_eq!(serde_json::to_value(prepared.context).unwrap(), captured);
}

#[test]
fn accepted_mcp_launcher_chains_reach_the_context() {
    let host = crate::FakeHost::new();
    let keg = host.brew().join("Cellar/npx/1.0.0");
    crate::test_support::script(&keg.join("bin/npx"), "exit 0");
    std::fs::write(keg.join("bin/npx"), "#!/usr/bin/env node\n").unwrap();
    std::fs::write(
        keg.join("INSTALL_RECEIPT.json"),
        r#"{"runtime_dependencies":[]}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(keg.join("bin/npx"), host.brew().join("bin/npx")).unwrap();
    std::fs::write(
        host.home().join(".claude.json"),
        serde_json::json!({"mcpServers": {
            "memory": {"command": "npx", "args": ["memory-server"]},
            "skipped": {"command": host.home().join("missing/uvx")}
        }})
        .to_string(),
    )
    .unwrap();
    let box_home = host.home().join(".strands/box");
    claude_profile(&host, &box_home, true);
    let path = box_home.join("profiles/claude/profile.toml");
    let prepared = host
        .launcher()
        .prepare_with_context("claude", &host.project(), None);
    assert!(prepared.result.is_ok(), "{:?}", prepared.result);
    let context = serde_json::to_value(prepared.context).unwrap();
    assert_eq!(
        context,
        expected(
            &std::fs::read(&path).unwrap(),
            Some(&["base", "bedrock", "claude", "node", "npx"]),
            Some(false),
            Some(false),
            Some(true),
        )
    );

    let mut profile: toml::Table =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    profile.insert(
        "agent".into(),
        toml::toml! { command = ["${{ unavailable.reference }}"] }.into(),
    );
    std::fs::write(&path, toml::to_string(&profile).unwrap()).unwrap();
    let failed = host
        .launcher()
        .prepare_with_context("claude", &host.project(), None);
    assert!(failed.result.is_err());
    let context = serde_json::to_value(failed.context).unwrap();
    assert_eq!(
        context,
        expected(
            &std::fs::read(&path).unwrap(),
            None,
            None,
            Some(false),
            None,
        )
    );
}
