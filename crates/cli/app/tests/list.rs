#![cfg(unix)]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use serde_json::{Value, json};

const HEADER: &str = "PROFILE\tUPDATED (UTC)\tBOX ID";
const DATE_SECONDS: u64 = 946_782_245;

struct Scene {
    _root: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&project).unwrap();
        Self {
            _root: root,
            home,
            project,
        }
    }

    fn runs(&self) -> PathBuf {
        self.home.join(".strands/box/r")
    }

    fn saved(&self, id: &str, profile: Option<&[u8]>) -> PathBuf {
        let run = self.runs().join(id);
        std::fs::create_dir_all(&run).unwrap();
        if let Some(profile) = profile {
            std::fs::write(run.join("profile-name"), profile).unwrap();
        }
        run
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_box"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "")
            .env("BOX_RESOURCES", self.home.join("absent-resources"))
            .current_dir(&self.project)
            .stdin(Stdio::null());
        command
    }

    fn command(&self, format: Option<&str>) -> Command {
        let mut command = self.base_command();
        command.args(["runs", "list"]);
        if let Some(format) = format {
            command.args(["--format", format]);
        }
        command
    }

    fn list(&self, format: Option<&str>) -> Output {
        self.command(format).output().unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        text(&output.stdout),
        text(&output.stderr)
    );
}

fn decoded_rows(output: &Output) -> Vec<Value> {
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "list must emit one JSON value: {error}\nstdout: {}\nstderr: {}",
            text(&output.stdout),
            text(&output.stderr)
        )
    });
    value.as_array().expect("list emits a JSON array").clone()
}

fn json_rows(output: &Output) -> Vec<Value> {
    let rows = decoded_rows(output);
    for row in &rows {
        let mut keys: Vec<_> = row
            .as_object()
            .expect("each saved run is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["id", "profile", "updated"]);
    }
    rows
}

fn text_rows(output: &Output) -> Vec<Vec<String>> {
    let stdout = text(&output.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some(HEADER), "{stdout}");
    lines
        .map(|line| {
            let fields: Vec<String> = line.split('\t').map(str::to_owned).collect();
            assert_eq!(fields.len(), 3, "one run occupies one three-column row");
            fields
        })
        .collect()
}

fn snapshot(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>, std::time::SystemTime)> {
    let mut entries = vec![(
        root.to_path_buf(),
        None,
        std::fs::symlink_metadata(root).unwrap().modified().unwrap(),
    )];
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            entries.extend(snapshot(&path));
        } else {
            entries.push((
                path.clone(),
                metadata.is_file().then(|| std::fs::read(&path).unwrap()),
                metadata.modified().unwrap(),
            ));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn wait_bounded(child: &mut Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("list did not exit within five seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn bounded_output(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_bounded(&mut child);
    child.wait_with_output().unwrap()
}

fn fifo(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a valid C string, and the test owns its parent directory.
    assert_eq!(unsafe { nix::libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[test]
fn list_keeps_locked_completed_and_orphaned_runs_without_loading_profiles() {
    let scene = Scene::new();
    let active = scene.saved("b-000000000000000f", Some(b"live-profile\n"));
    let lock = std::fs::File::open(&active).unwrap();
    lock.try_lock().unwrap();
    scene.saved("b-0000000000000004", Some(b"unknown\n"));
    scene.saved("b-0000000000000002", None);
    let completed = scene.saved(
        "b-0000000000000001",
        Some(b"full-profile-name-that-is-longer-than-the-id\n"),
    );
    std::fs::write(completed.join("records.jsonl"), "saved telemetry\n").unwrap();
    let cwd_run = scene.project.join(".strands/box/r/cwd-only-00000005");
    std::fs::create_dir_all(&cwd_run).unwrap();
    std::fs::write(cwd_run.join("profile-name"), "wrong-home\n").unwrap();
    assert!(!scene.home.join(".strands/box/profiles").exists());
    let before = snapshot(&scene.home);
    let default = bounded_output(scene.command(None));
    success(&default);
    assert!(default.stderr.is_empty());
    assert_eq!(
        text(&default.stdout),
        concat!(
            "PROFILE\tUPDATED (UTC)\tBOX ID\n",
            "full-profile-name-that-is-longer-than-the-id\tunknown\tb-0000000000000001\n",
            "unknown\tunknown\tb-0000000000000002\n",
            "unknown\tunknown\tb-0000000000000004\n",
            "live-profile\tunknown\tb-000000000000000f\n"
        )
    );
    let explicit = bounded_output(scene.command(Some("text")));
    success(&explicit);
    assert_eq!(explicit.stdout, default.stdout);
    let json = bounded_output(scene.command(Some("json")));
    success(&json);
    assert!(json.stderr.is_empty());
    assert_eq!(
        json_rows(&json),
        [
            json!({"updated": null, "id": "b-0000000000000001", "profile": "full-profile-name-that-is-longer-than-the-id"}),
            json!({"updated": null, "id": "b-0000000000000002", "profile": null}),
            json!({"updated": null, "id": "b-0000000000000004", "profile": "unknown"}),
            json!({"updated": null, "id": "b-000000000000000f", "profile": "live-profile"})
        ]
    );
    let mut empty_box_home_command = scene.command(Some("json"));
    empty_box_home_command.env("BOX_HOME", "");
    let empty_box_home = bounded_output(empty_box_home_command);
    success(&empty_box_home);
    assert!(empty_box_home.stderr.is_empty());
    assert_eq!(empty_box_home.stdout, json.stdout);
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn list_uses_configured_box_home_with_or_without_home() {
    let scene = Scene::new();
    scene.saved("default-only", Some(b"default-profile\n"));
    let box_home = scene._root.path().join("configured-box-home");
    let run = box_home.join("r/custom-only");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("profile-name"), "custom-profile\n").unwrap();
    let before = snapshot(scene._root.path());
    for has_home in [true, false] {
        for format in [None, Some("json")] {
            let mut command = scene.command(format);
            command.env("BOX_HOME", &box_home);
            if !has_home {
                command.env_remove("HOME");
            }
            let output = bounded_output(command);
            success(&output);
            assert!(output.stderr.is_empty());
            if format == Some("json") {
                assert_eq!(
                    json_rows(&output),
                    [json!({"profile": "custom-profile", "updated": null, "id": "custom-only"})]
                );
            } else {
                assert_eq!(
                    text(&output.stdout),
                    "PROFILE\tUPDATED (UTC)\tBOX ID\ncustom-profile\tunknown\tcustom-only\n"
                );
            }
            assert_eq!(
                snapshot(scene._root.path()),
                before,
                "HOME set: {has_home}, {format:?}"
            );
        }
    }
}

#[test]
fn list_missing_configured_box_home_does_not_fall_back_or_create_files() {
    for layout in ["missing-box-home", "box-home-only", "empty-runs"] {
        let scene = Scene::new();
        scene.saved("default-only", Some(b"default-profile\n"));
        let box_home = scene._root.path().join("configured-box-home");
        match layout {
            "box-home-only" => std::fs::create_dir(&box_home).unwrap(),
            "empty-runs" => std::fs::create_dir_all(box_home.join("r")).unwrap(),
            _ => {}
        }
        let before = snapshot(scene._root.path());
        for format in [None, Some("json")] {
            let mut command = scene.command(format);
            command.env("BOX_HOME", &box_home);
            let output = bounded_output(command);
            success(&output);
            assert!(output.stderr.is_empty());
            if format == Some("json") {
                assert!(json_rows(&output).is_empty());
            } else {
                assert_eq!(text(&output.stdout), "No saved runs.\n");
            }
            assert_eq!(snapshot(scene._root.path()), before, "{layout}, {format:?}");
        }
    }
}

#[test]
fn list_missing_and_empty_run_roots_succeed_without_creating_anything() {
    for layout in ["home-only", "strands-only", "box-only", "empty-runs"] {
        let scene = Scene::new();
        match layout {
            "strands-only" => std::fs::create_dir(scene.home.join(".strands")).unwrap(),
            "box-only" => std::fs::create_dir_all(scene.home.join(".strands/box")).unwrap(),
            "empty-runs" => std::fs::create_dir_all(scene.runs()).unwrap(),
            _ => {}
        }
        let before = snapshot(&scene.home);
        for format in [None, Some("text"), Some("json")] {
            let output = scene.list(format);
            success(&output);
            assert!(
                output.stderr.is_empty(),
                "{layout}: {}",
                text(&output.stderr)
            );
            if format == Some("json") {
                assert!(json_rows(&output).is_empty());
            } else {
                assert_eq!(text(&output.stdout), "No saved runs.\n");
            }
            assert_eq!(snapshot(&scene.home), before, "{layout}, {format:?}");
        }
    }
}

#[test]
fn list_ignores_files_fifos_and_symlink_run_entries() {
    let scene = Scene::new();
    scene.saved("real-00000001", Some(b"real-profile\n"));
    std::fs::write(scene.runs().join("plain-file"), "not a run").unwrap();
    fifo(&scene.runs().join("fifo-entry"));
    let outside = scene.project.join("outside-run");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("profile-name"), "must-not-read\n").unwrap();
    symlink(&outside, scene.runs().join("linked-run")).unwrap();
    symlink(
        scene.project.join("missing"),
        scene.runs().join("dangling-run"),
    )
    .unwrap();
    let before = snapshot(&scene.home);
    let output = bounded_output(scene.command(Some("json")));
    success(&output);
    assert_eq!(
        json_rows(&output),
        [json!({"updated": null, "id": "real-00000001", "profile": "real-profile"})]
    );
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn list_rejects_linked_box_and_runs_ancestors() {
    for component in [".strands", ".strands/box", ".strands/box/r"] {
        let scene = Scene::new();
        scene.saved("secret-00000001", Some(b"must-not-read\n"));
        success(&scene.list(None));
        let linked = scene.home.join(component);
        let outside = scene.project.join("moved");
        std::fs::rename(&linked, &outside).unwrap();
        symlink(&outside, &linked).unwrap();
        let before = snapshot(&scene.home);
        for format in [None, Some("json")] {
            let output = bounded_output(scene.command(format));
            assert_eq!(output.status.code(), Some(1), "followed {component}");
            assert!(!output.stderr.is_empty());
            assert!(!text(&output.stdout).contains("secret-00000001"));
            assert!(!text(&output.stdout).contains("must-not-read"));
        }
        assert_eq!(snapshot(&scene.home), before);
    }
}

#[test]
fn list_keeps_ids_when_profile_metadata_is_unavailable_without_following_or_blocking() {
    let scene = Scene::new();
    let ids = [
        "directory",
        "empty",
        "fifo",
        "invalid-utf8",
        "missing",
        "newline-only",
        "symlink",
    ];
    for id in ids {
        scene.saved(id, None);
    }
    std::fs::create_dir(scene.runs().join("directory/profile-name")).unwrap();
    std::fs::write(scene.runs().join("empty/profile-name"), "").unwrap();
    fifo(&scene.runs().join("fifo/profile-name"));
    std::fs::write(scene.runs().join("invalid-utf8/profile-name"), [0xff, 0xfe]).unwrap();
    std::fs::write(scene.runs().join("newline-only/profile-name"), "\n").unwrap();
    let secret = scene.project.join("private-profile-name");
    std::fs::write(&secret, "must-not-read\n").unwrap();
    symlink(&secret, scene.runs().join("symlink/profile-name")).unwrap();
    let before = snapshot(&scene.home);
    let json = bounded_output(scene.command(Some("json")));
    success(&json);
    assert_eq!(
        json_rows(&json),
        ids.map(|id| json!({"updated": null, "id": id, "profile": null}))
    );
    let text = bounded_output(scene.command(None));
    success(&text);
    assert_eq!(
        text_rows(&text),
        ids.map(|id| vec!["unknown".to_owned(), "unknown".to_owned(), id.to_owned()])
    );
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn list_bounds_profile_metadata_by_bytes_and_strips_only_one_final_newline() {
    let scene = Scene::new();
    let limit = 64 * 1024;
    let exact_profile = "p".repeat(limit - 1);
    let exact = format!("{exact_profile}\n");
    let oversized = format!("{}\n", "p".repeat(limit));
    assert_eq!(exact.len(), limit);
    assert_eq!(oversized.len(), limit + 1);
    scene.saved("at-limit", Some(exact.as_bytes()));
    scene.saved("no-final-newline", Some(b"whole-profile-name"));
    scene.saved("one-byte-over", Some(oversized.as_bytes()));
    scene.saved("two-final-newlines", Some(b"kept-newline\n\n"));
    let unicode = "é".repeat(limit / 2 + 1);
    assert!(unicode.len() > limit && unicode.chars().count() < limit);
    scene.saved("unicode-over-limit", Some(unicode.as_bytes()));
    let before = snapshot(&scene.home);
    let output = scene.list(Some("json"));
    success(&output);
    let rows = json_rows(&output);
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0]["id"], "at-limit");
    assert!(
        rows[0]["profile"] == exact_profile,
        "the exact 64 KiB file must retain its whole profile"
    );
    assert_eq!(
        rows[1],
        json!({"updated": null, "id": "no-final-newline", "profile": null}),
        "box writes every record with a final newline; one without it names no profile"
    );
    assert_eq!(
        rows[2],
        json!({"updated": null, "id": "one-byte-over", "profile": null})
    );
    assert_eq!(
        rows[3],
        json!({"updated": null, "id": "two-final-newlines", "profile": "kept-newline\n"})
    );
    assert_eq!(
        rows[4],
        json!({"updated": null, "id": "unicode-over-limit", "profile": null})
    );
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn list_preserves_controls_and_unicode_in_json_and_escapes_terminal_fields() {
    let scene = Scene::new();
    let id = "run\tline\n日本語\u{1b}[31m😀";
    let profile = "profile\tline\nnext\r\0\u{1b}[31m雪😀\\literal";
    scene.saved(id, Some(format!("{profile}\n").as_bytes()));
    let json = scene.list(Some("json"));
    success(&json);
    assert_eq!(
        json_rows(&json),
        [json!({"updated": null, "id": id, "profile": profile})]
    );
    let output = scene.list(None);
    success(&output);
    let stdout = text(&output.stdout);
    assert!(
        !stdout
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    );
    let rows = text_rows(&output);
    assert_eq!(rows.len(), 1);
    assert!(rows[0][2].contains("日本語"));
    assert!(rows[0][2].ends_with("😀"));
    assert!(rows[0][0].contains("雪😀"));
    assert_eq!(rows[0][1], "unknown");
    for field in [&rows[0][0], &rows[0][2]] {
        assert!(field.contains("\\t") && field.contains("\\n"), "{field:?}");
    }
}

#[test]
fn list_reports_invalid_roots_and_requires_home() {
    for component in [".strands", ".strands/box", ".strands/box/r"] {
        let scene = Scene::new();
        let path = scene.home.join(component);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not a directory").unwrap();
        let before = snapshot(&scene.home);
        for format in [None, Some("json")] {
            let output = scene.list(format);
            assert_eq!(output.status.code(), Some(1), "{component}, {format:?}");
            assert!(!output.stderr.is_empty());
        }
        assert_eq!(snapshot(&scene.home), before);
    }
    let scene = Scene::new();
    let output = scene.command(None).env_remove("HOME").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).to_lowercase().contains("home"));
}

#[test]
fn list_exits_successfully_when_stdout_closes_in_text_and_json() {
    let scene = Scene::new();
    let profile = format!("{}\n", "p".repeat(4096));
    for n in 0..1024 {
        scene.saved(&format!("run-{n:08x}"), Some(profile.as_bytes()));
    }
    for format in [None, Some("json")] {
        let mut child = scene
            .command(format)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        assert!(
            wait_bounded(&mut child).success(),
            "closed stdout in {format:?} format"
        );
    }
}

#[test]
fn list_rejects_invalid_formats_as_usage_errors() {
    let scene = Scene::new();
    success(&scene.list(Some("text")));
    success(&scene.list(Some("json")));
    for format in ["yaml", "JSON", ""] {
        let output = scene.list(Some(format));
        assert_eq!(output.status.code(), Some(2), "{format:?}");
        assert!(output.stdout.is_empty());
        assert!(text(&output.stderr).contains("error:"));
    }
}

fn set_modified(path: &Path, seconds: u64, nanos: u32) {
    let modified = std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanos);
    let file = std::fs::File::open(path).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(file.metadata().unwrap().modified().unwrap(), modified);
}

fn configuration_at(run: &Path, seconds: u64, nanos: u32) {
    let path = run.join("box.toml");
    std::fs::write(&path, b"\xffnot a parsed configuration\n").unwrap();
    set_modified(&path, seconds, nanos);
}

fn ids(rows: &[Value]) -> Vec<&str> {
    rows.iter().map(|row| row["id"].as_str().unwrap()).collect()
}

#[test]
fn runs_list_orders_one_profiles_runs_by_configuration_time_and_shows_profile_first() {
    let scene = Scene::new();
    for (id, offset) in [("z-newest", 2), ("a-oldest", 0), ("m-middle", 1)] {
        let run = scene.saved(id, Some(b"same-profile\n"));
        configuration_at(&run, DATE_SECONDS + offset, 0);
    }
    let before = snapshot(&scene.home);
    let output = bounded_output(scene.command(Some("json")));
    success(&output);
    let rows = decoded_rows(&output);
    assert_eq!(
        ids(&rows),
        ["z-newest", "m-middle", "a-oldest"],
        "configuration time must take priority over the random ID suffix"
    );
    assert_eq!(
        json_rows(&output),
        [
            json!({"profile": "same-profile", "updated": "2000-01-02T03:04:07Z", "id": "z-newest"}),
            json!({"profile": "same-profile", "updated": "2000-01-02T03:04:06Z", "id": "m-middle"}),
            json!({"profile": "same-profile", "updated": "2000-01-02T03:04:05Z", "id": "a-oldest"})
        ]
    );
    let default = bounded_output(scene.command(None));
    success(&default);
    assert_eq!(
        text(&default.stdout),
        concat!(
            "PROFILE\tUPDATED (UTC)\tBOX ID\n",
            "same-profile\t2000-01-02T03:04:07Z\tz-newest\n",
            "same-profile\t2000-01-02T03:04:06Z\tm-middle\n",
            "same-profile\t2000-01-02T03:04:05Z\ta-oldest\n"
        )
    );
    let explicit = bounded_output(scene.command(Some("text")));
    success(&explicit);
    assert_eq!(explicit.stdout, default.stdout);
    assert!(output.stderr.is_empty() && default.stderr.is_empty() && explicit.stderr.is_empty());
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn runs_list_orders_nanoseconds_then_ids_and_places_missing_times_last() {
    let scene = Scene::new();
    for (id, nanos) in [("z-newer", 9), ("a-older", 1), ("m-tie", 9), ("b-tie", 9)] {
        let run = scene.saved(id, Some(b"same-profile\n"));
        configuration_at(&run, DATE_SECONDS, nanos);
    }
    scene.saved("z-missing", Some(b"same-profile\n"));
    scene.saved("a-missing", Some(b"same-profile\n"));
    let before = snapshot(&scene.home);
    let output = bounded_output(scene.command(Some("json")));
    success(&output);
    let rows = decoded_rows(&output);
    assert_eq!(
        ids(&rows),
        [
            "b-tie",
            "m-tie",
            "z-newer",
            "a-older",
            "a-missing",
            "z-missing"
        ],
        "nanoseconds decide newest first, IDs break exact ties, and missing times follow dated runs"
    );
    assert_eq!(rows[0]["updated"], "2000-01-02T03:04:05.000000009Z");
    assert_eq!(rows[3]["updated"], "2000-01-02T03:04:05.000000001Z");
    assert_eq!(rows[4]["updated"], Value::Null);
    assert_eq!(rows[5]["updated"], Value::Null);
    let _ = json_rows(&output);
    let text = bounded_output(scene.command(None));
    success(&text);
    let text = text_rows(&text);
    assert_eq!(
        text.iter().map(|row| row[2].as_str()).collect::<Vec<_>>(),
        ids(&rows)
    );
    assert_eq!(text[0][1], "2000-01-02T03:04:05.000000009Z");
    assert_eq!(text[4][1], "unknown");
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn runs_list_uses_only_regular_configuration_metadata_without_following_or_blocking() {
    let scene = Scene::new();
    for id in [
        "directory",
        "fifo",
        "linked",
        "missing",
        "unknown-profile",
        "wrong-timestamps",
    ] {
        scene.saved(
            id,
            (id != "unknown-profile").then_some(b"saved-profile\n".as_slice()),
        );
    }
    std::fs::create_dir(scene.runs().join("directory/box.toml")).unwrap();
    fifo(&scene.runs().join("fifo/box.toml"));
    let outside = scene.project.join("private-config.toml");
    std::fs::write(&outside, "must-not-read\n").unwrap();
    set_modified(&outside, DATE_SECONDS + 3600, 0);
    symlink(&outside, scene.runs().join("linked/box.toml")).unwrap();
    configuration_at(&scene.runs().join("unknown-profile"), DATE_SECONDS + 1, 0);
    let run = scene.runs().join("wrong-timestamps");
    configuration_at(&run, DATE_SECONDS, 0);
    std::fs::write(run.join("records.jsonl"), "not a timestamp source\n").unwrap();
    set_modified(&run.join("profile-name"), DATE_SECONDS + 3600, 0);
    set_modified(&run.join("records.jsonl"), DATE_SECONDS + 3600, 0);
    set_modified(&run, DATE_SECONDS + 3600, 0);
    let before = snapshot(&scene.home);
    let outside_before = std::fs::read(&outside).unwrap();
    let output = bounded_output(scene.command(Some("json")));
    success(&output);
    let rows = decoded_rows(&output);
    let unknown_profile = rows
        .iter()
        .find(|row| row["id"] == "unknown-profile")
        .unwrap();
    assert_eq!(unknown_profile["profile"], Value::Null);
    assert_eq!(unknown_profile["updated"], "2000-01-02T03:04:06Z");
    let regular = rows
        .iter()
        .find(|row| row["id"] == "wrong-timestamps")
        .unwrap();
    assert_eq!(regular["updated"], "2000-01-02T03:04:05Z");
    assert_eq!(
        ids(&rows),
        [
            "unknown-profile",
            "wrong-timestamps",
            "directory",
            "fifo",
            "linked",
            "missing"
        ]
    );
    for id in ["directory", "fifo", "linked", "missing"] {
        assert_eq!(
            rows.iter().find(|row| row["id"] == id).unwrap(),
            &json!({"profile": "saved-profile", "updated": null, "id": id}),
            "only a regular box.toml supplies a timestamp: {id}"
        );
    }
    let _ = json_rows(&output);
    let output = bounded_output(scene.command(None));
    success(&output);
    let text = text_rows(&output);
    assert_eq!(
        text[0],
        ["unknown", "2000-01-02T03:04:06Z", "unknown-profile"]
    );
    assert_eq!(
        text[1],
        ["saved-profile", "2000-01-02T03:04:05Z", "wrong-timestamps"]
    );
    assert!(text[2..].iter().all(|row| row[1] == "unknown"));
    assert_eq!(snapshot(&scene.home), before);
    assert_eq!(std::fs::read(&outside).unwrap(), outside_before);
}

#[test]
fn runs_list_refreshes_time_when_an_existing_ids_configuration_is_replaced() {
    let scene = Scene::new();
    let first = scene.saved("a-first", Some(b"same-profile\n"));
    let reused = scene.saved("z-reused", Some(b"same-profile\n"));
    configuration_at(&first, DATE_SECONDS + 1, 0);
    configuration_at(&reused, DATE_SECONDS, 0);
    let before = snapshot(&scene.home);
    let initial = bounded_output(scene.command(Some("json")));
    success(&initial);
    assert_eq!(ids(&decoded_rows(&initial)), ["a-first", "z-reused"]);
    assert_eq!(snapshot(&scene.home), before);
    let replacement = reused.join("replacement.toml");
    std::fs::write(&replacement, "replacement configuration\n").unwrap();
    set_modified(&replacement, DATE_SECONDS + 2, 0);
    std::fs::rename(&replacement, reused.join("box.toml")).unwrap();
    let replaced = snapshot(&scene.home);
    let output = bounded_output(scene.command(Some("json")));
    success(&output);
    let rows = decoded_rows(&output);
    assert_eq!(
        ids(&rows),
        ["z-reused", "a-first"],
        "replacing an existing run configuration must update its displayed order"
    );
    assert_eq!(rows[0]["updated"], "2000-01-02T03:04:07Z");
    assert_eq!(rows[0]["profile"], "same-profile");
    let _ = json_rows(&output);
    let again = bounded_output(scene.command(Some("json")));
    success(&again);
    assert_eq!(again.stdout, output.stdout);
    assert_eq!(snapshot(&scene.home), replaced);
}

#[test]
fn runs_list_is_namespaced_without_a_top_level_list_alias() {
    let scene = Scene::new();
    let before = snapshot(&scene.home);
    let help = scene.command(None).arg("--help").output().unwrap();
    success(&help);
    assert!(text(&help.stdout).contains("box runs list"));
    let old = scene.base_command().arg("list").output().unwrap();
    assert_eq!(old.status.code(), Some(2));
    assert!(old.stdout.is_empty());
    assert!(text(&old.stderr).contains("unrecognized subcommand 'list'"));
    let records = scene
        .base_command()
        .args(["runs", "history", "--help"])
        .output()
        .unwrap();
    success(&records);
    assert!(text(&records.stdout).contains("box runs history"));
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn runs_list_with_a_profile_keeps_only_runs_that_record_that_profile() {
    let scene = Scene::new();
    for (id, profile, offset) in [
        ("b-000000000000000a", Some(&b"claude\n"[..]), 3),
        ("b-000000000000000b", Some(&b"other\n"[..]), 2),
        ("b-000000000000000c", Some(&b"claude\n"[..]), 1),
        ("b-000000000000000d", None, 4),
        ("b-000000000000000e", Some(&b"claudette\n"[..]), 5),
        ("b-000000000000000f", Some(&b"Claude\n"[..]), 6),
        ("b-0000000000000010", Some(&b"clau\n"[..]), 7),
    ] {
        let run = scene.saved(id, profile);
        configuration_at(&run, DATE_SECONDS + offset, 0);
    }
    let before = snapshot(&scene.home);
    let filtered = |format: Option<&str>| {
        let mut command = scene.command(format);
        command.arg("claude");
        bounded_output(command)
    };

    let json_output = filtered(Some("json"));
    success(&json_output);
    assert_eq!(
        ids(&json_rows(&json_output)),
        ["b-000000000000000a", "b-000000000000000c"]
    );

    let text_output = filtered(None);
    success(&text_output);
    assert_eq!(
        text(&text_output.stdout),
        concat!(
            "PROFILE\tUPDATED (UTC)\tBOX ID\n",
            "claude\t2000-01-02T03:04:08Z\tb-000000000000000a\n",
            "claude\t2000-01-02T03:04:06Z\tb-000000000000000c\n"
        )
    );

    let every = bounded_output(scene.command(Some("json")));
    success(&every);
    assert_eq!(
        json_rows(&every).len(),
        7,
        "without a profile every run is listed"
    );

    assert!(json_output.stderr.is_empty() && text_output.stderr.is_empty());
    assert_eq!(snapshot(&scene.home), before);
}

#[test]
fn runs_list_with_a_profile_that_has_no_runs_succeeds_with_an_empty_result() {
    let scene = Scene::new();
    scene.saved("claude-a", Some(b"claude\n"));
    let mut text_command = scene.command(None);
    text_command.arg("nosuch");
    let text_output = bounded_output(text_command);
    success(&text_output);
    assert_eq!(
        text(&text_output.stdout),
        "No saved runs for profile nosuch.\n"
    );

    let mut json_command = scene.command(Some("json"));
    json_command.arg("nosuch");
    let json_output = bounded_output(json_command);
    success(&json_output);
    assert!(json_rows(&json_output).is_empty());

    let mut empty_command = scene.command(None);
    empty_command.arg("");
    let empty = bounded_output(empty_command);
    assert_eq!(
        empty.status.code(),
        Some(2),
        "an empty profile name is a usage error"
    );
    for (argument, message) in [
        (
            "../box/profile.toml",
            "pass the `[profile] name` in that file",
        ),
        (
            "weather-agent.toml",
            "pass the `[profile] name` in that file",
        ),
        ("base", "reserved"),
        ("box", "reserved"),
        (".hidden", "cannot start with"),
    ] {
        let mut command = scene.command(None);
        command.arg(argument);
        let refused = bounded_output(command);
        assert_eq!(refused.status.code(), Some(2), "{argument}");
        assert!(
            text(&refused.stderr).contains(message),
            "{argument}: {}",
            text(&refused.stderr)
        );
        assert!(refused.stdout.is_empty(), "{argument}");
    }
    assert!(
        !scene.home.join(".strands/box/profiles").exists(),
        "the filter needs no profile folder"
    );
}

#[test]
fn runs_list_with_a_profile_lists_exactly_what_profile_clean_removes() {
    let scene = Scene::new();
    for (id, profile) in [
        ("b-0000000000000001", Some(&b"claude\n"[..])),
        ("b-0000000000000002", Some(&b"codex\n"[..])),
        ("b-0000000000000003", Some(&b"claude"[..])),
        ("claude-0000000000000004", Some(&b"claude\n"[..])),
    ] {
        scene.saved(id, profile);
        std::fs::create_dir_all(scene.runs().join(id).join("box")).unwrap();
    }
    let all = bounded_output(scene.command(Some("json")));
    success(&all);
    let rows = json_rows(&all);
    let mut shown: Vec<(&str, Option<&str>)> = rows
        .iter()
        .map(|row| (row["id"].as_str().unwrap(), row["profile"].as_str()))
        .collect();
    shown.sort_unstable();
    assert_eq!(
        shown,
        [
            ("b-0000000000000001", Some("claude")),
            ("b-0000000000000002", Some("codex")),
            ("b-0000000000000003", None),
            ("claude-0000000000000004", Some("claude")),
        ],
        "the PROFILE column reads a record the way the ownership check does"
    );

    let mut listed = scene.command(Some("json"));
    listed.arg("claude");
    let listed = bounded_output(listed);
    success(&listed);
    assert_eq!(
        ids(&json_rows(&listed)),
        ["b-0000000000000001"],
        "a record without its newline, and an ID that is not a run ID, belong to no profile"
    );

    let clean = scene
        .base_command()
        .args(["profile", "clean", "claude", "--no-ask"])
        .output()
        .unwrap();
    success(&clean);
    let mut left: Vec<String> = std::fs::read_dir(scene.runs())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort_unstable();
    assert_eq!(
        left,
        [
            "b-0000000000000002",
            "b-0000000000000003",
            "claude-0000000000000004",
        ],
        "clean removes exactly what list showed for the profile"
    );
}
