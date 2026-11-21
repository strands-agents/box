//! `resources/packs/pi/box-shell.ts` against a real pi, outside a box. A faux model makes pi call
//! its bash tool, and an RPC `bash` command runs a `!` command, so both reach the extension. The
//! test skips when `PI_BINARY` names no pi and `pi` is not on `PATH`, unless `BOX_REQUIRE_PI` is set.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PROBE_PROVIDER: &str = r#"
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
export default function (pi: any) {
	const faux = fauxProvider({ provider: "box-probe", api: "box-probe-api" });
	faux.setResponses([
		fauxAssistantMessage([fauxToolCall("bash", { command: "echo tool-ran-$PI_PROVIDER" })], { stopReason: "toolUse" }),
		fauxAssistantMessage("done"),
	]);
	pi.registerProvider(faux.provider.id, {
		api: faux.api,
		baseUrl: faux.getModel().baseUrl,
		apiKey: "probe",
		models: faux.models,
		streamSimple: faux.provider.streamSimple,
	});
}
"#;

fn pi() -> Option<PathBuf> {
    if let Some(pi) = std::env::var_os("PI_BINARY") {
        return Some(PathBuf::from(pi));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|folder| folder.join("pi"))
        .find(|candidate| candidate.is_file())
}

fn extension() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../resources/packs/pi/box-shell.ts")
}

struct Scene {
    _directory: tempfile::TempDir,
    root: PathBuf,
    pi: PathBuf,
}

impl Scene {
    fn new(pi: PathBuf) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().to_path_buf();
        std::fs::create_dir_all(root.join("agent")).expect("an agent folder");
        std::fs::create_dir_all(root.join("project/.pi")).expect("a project");
        std::fs::write(
            root.join("project/.pi/settings.json"),
            r#"{"shellPath": "/no/such/shell", "shellCommandPrefix": "echo prefix-ran"}"#,
        )
        .expect("project settings");
        let probe = root.join("box-bash");
        std::fs::write(
            &probe,
            "#!/bin/bash\necho via-box-shell >&2\nexec /bin/bash \"$@\"\n",
        )
        .expect("a probe shell");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).expect("0755");
        std::fs::write(root.join("probe.ts"), PROBE_PROVIDER).expect("a probe provider");
        Self {
            _directory: directory,
            root,
            pi,
        }
    }

    fn command(&self, with_extension: bool) -> Command {
        let mut command = Command::new(&self.pi);
        command
            .current_dir(self.root.join("project"))
            .env_clear()
            .env("HOME", &self.root)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("PI_CODING_AGENT_DIR", self.root.join("agent"))
            .env("PI_OFFLINE", "1")
            .env("BOX_SHELL_PATH", self.root.join("box-bash"))
            .args(["--approve", "--no-session"]);
        if with_extension {
            command.arg("-e").arg(extension());
        }
        command
    }

    /// What pi prints when its model calls the bash tool once.
    fn tool(&self, with_extension: bool, flags: &[&str]) -> String {
        let output = self
            .command(with_extension)
            .args(flags)
            .arg("-e")
            .arg(self.root.join("probe.ts"))
            .args(["--provider", "box-probe", "--model", "faux-1"])
            .args(["--mode", "json", "-p", "go"])
            .stdin(Stdio::null())
            .output()
            .expect("pi runs");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// What pi answers to one RPC `bash` command, which runs as a `!` command.
    fn user_bash(&self, with_extension: bool) -> String {
        let mut child = self
            .command(with_extension)
            .args(["--mode", "rpc"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("pi runs");
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(
            stdin,
            r#"{{"id":"1","type":"bash","command":"echo user-ran"}}"#
        )
        .expect("a command");
        let stdout = child.stdout.take().expect("stdout");
        let mut answer = String::new();
        for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
            let line = line.expect("a line");
            if line.contains(r#""type":"response""#) && line.contains(r#""command":"bash""#) {
                answer = line;
                break;
            }
        }
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        answer
    }
}

#[test]
fn the_box_shell_runs_the_bash_tool_and_bang_commands_in_box_shell_path_whatever_settings_say() {
    let Some(pi) = pi() else {
        assert!(
            std::env::var_os("BOX_REQUIRE_PI").is_none(),
            "no pi, and BOX_REQUIRE_PI is set; the CI macOS job installs it"
        );
        eprintln!("skipped: no pi; set PI_BINARY or put pi on PATH");
        return;
    };
    let scene = Scene::new(pi);

    let tool = scene.tool(true, &[]);
    assert!(tool.contains("via-box-shell"), "{tool}");
    assert!(
        tool.contains("prefix-ran"),
        "the project's shellCommandPrefix runs in the box's shell: {tool}"
    );
    assert!(
        tool.contains("tool-ran-box-probe"),
        "the tool keeps pi's session variables, such as PI_PROVIDER: {tool}"
    );
    let user = scene.user_bash(true);
    assert!(
        user.contains("via-box-shell") && user.contains("user-ran"),
        "{user}"
    );
    assert!(
        user.contains(r#""exitCode":0"#) && user.contains("prefix-ran"),
        "{user}"
    );
    for flags in [&["--no-builtin-tools"][..], &["--tools", "read"]] {
        let off = scene.tool(true, flags);
        assert!(
            off.contains("Tool bash not found") && !off.contains("via-box-shell"),
            "{flags:?} turns the box's bash off, as it does pi's: {off}"
        );
    }
    assert!(
        scene
            .tool(true, &["--tools", "read,bash"])
            .contains("via-box-shell"),
        "--tools names bash, so it is on"
    );

    let tool = scene.tool(false, &[]);
    assert!(
        !tool.contains("via-box-shell") && tool.contains("Custom shell path not found"),
        "without the extension, the project's shellPath applies: {tool}"
    );
    let user = scene.user_bash(false);
    assert!(
        !user.contains("via-box-shell") && user.contains("Custom shell path not found"),
        "{user}"
    );
}
