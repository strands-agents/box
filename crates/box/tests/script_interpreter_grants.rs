//! Linux script edits cannot add filesystem grants across declared launches.

#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;

#[path = "support/bounded_output.rs"]
mod bounded_output;
#[path = "support/fixture.rs"]
mod fixture;

use bounded_output::bounded_output;
use fixture::{Configured, Request};

const MARKER: &str = "SCRIPT_INTERPRETER_SYNTHETIC_MARKER";
const TOOL_POLICY: &str = r#"
permit(principal, action == Box::Action::"shell:exec", resource);
permit(principal, action == Box::Action::"shell:spawn", resource);
permit(principal, action == Box::Action::"fs:read", resource);
"#;

fn original_script(bash: &Path, marker: &Path) -> String {
    format!(
        "#!{}\nprintf 'ORIGINAL_SCRIPT_RAN\\n'\n\
         if IFS= read -r fixture_value < {}; then\n\
             [[ \"$fixture_value\" == {} ]] || exit 92\n\
             printf 'DIRECT_READ_ALLOWED\\n'\n\
         else\n\
             printf 'DIRECT_READ_REFUSED\\n'\n\
         fi\n",
        bash.display(),
        quoted(marker.to_str().unwrap()),
        quoted(MARKER)
    )
}

fn assert_direct_read(output: &Output, granted: bool) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = if granted {
        "DIRECT_READ_ALLOWED"
    } else {
        "DIRECT_READ_REFUSED"
    };
    assert!(
        stdout.lines().any(|line| line == expected),
        "the original script must observe {expected}: {}",
        text(output)
    );
}

fn executable(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write the fixture script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("make the fixture script executable");
}

fn outside_fixtures(request: &Request) -> (PathBuf, PathBuf) {
    let env = request.operator_home().join("fixture-env/env");
    let marker = request.operator_home().join("unlisted/marker");
    std::fs::create_dir_all(env.parent().unwrap()).expect("create the interpreter directory");
    std::fs::create_dir_all(marker.parent().unwrap()).expect("create the marker directory");
    std::fs::copy("/usr/bin/cat", &env).expect("copy the fixture interpreter");
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o755))
        .expect("make the fixture interpreter executable");
    std::fs::write(&marker, format!("{MARKER}\n")).expect("write the synthetic marker");
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))
        .expect("keep the marker non-executable");
    (env, marker)
}

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn run(box_: &Configured, program: &Path, arguments: &[&str]) -> Output {
    let mut command = box_.command_for(program.to_str().expect("fixture path"));
    command.args(arguments);
    bounded_output(command)
}

fn text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_read_result(output: &Output, marker: &Path, granted: bool) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let observed = text(output);
    if granted {
        assert!(
            output.status.success(),
            "explicit grant control: {observed}"
        );
        assert!(
            stdout.contains(MARKER),
            "the declared grant must read the marker: {observed}"
        );
    } else {
        assert!(
            !output.status.success(),
            "an unlisted interpreter was admitted: {observed}"
        );
        assert!(
            !stdout.contains(MARKER),
            "the unlisted marker reached stdout: {observed}"
        );
        assert!(
            observed.contains(marker.to_str().unwrap()),
            "the refusal must name the marker: {observed}"
        );
        assert!(
            observed.contains("names the interpreter") && observed.contains("authorizes"),
            "the interpreter grant check must refuse: {observed}"
        );
    }
}

#[test]
fn a_script_changed_by_an_earlier_workload_cannot_add_an_interpreter_grant() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for granted in [false, true] {
        let request = Request::with_nothing("script-cross-run");
        let (env, marker) = outside_fixtures(&request);
        let bash = Path::new("/bin/bash").canonicalize().expect("resolve Bash");
        let mut grants = vec![env.to_str().unwrap(), bash.to_str().unwrap()];
        if granted {
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o755))
                .expect("make the explicit exec control executable");
            grants.push(marker.to_str().unwrap());
        }
        let box_ = request.agent_list("exec", &grants).expect();
        let script = box_.box_home().join("mutable-script");
        let changed = format!("#!{} {}\n", env.display(), marker.display());
        let original_body = format!(
            "{}printf '%s' {} > \"$0\" && printf 'SCRIPT_CHANGED\\n'\n",
            original_script(&bash, &marker),
            quoted(&changed)
        );
        executable(&script, &original_body);
        box_.write_command(script.to_str().unwrap());
        let config_before =
            std::fs::read(box_.config()).expect("read the declared script configuration");

        let original = run(&box_, &script, &[]);
        assert!(
            original.status.success(),
            "original script: {}",
            text(&original)
        );
        let stdout = String::from_utf8_lossy(&original.stdout);
        assert!(stdout.contains("ORIGINAL_SCRIPT_RAN"));
        assert!(stdout.contains("SCRIPT_CHANGED"));
        assert_direct_read(&original, granted);
        assert_eq!(std::fs::read_to_string(&script).unwrap(), changed);
        assert_eq!(std::fs::read(box_.config()).unwrap(), config_before);

        let next_run = run(&box_, &script, &[]);
        assert_eq!(std::fs::read(box_.config()).unwrap(), config_before);
        assert_read_result(&next_run, &marker, granted);
    }
}

#[test]
fn a_tool_changed_during_a_run_cannot_add_an_interpreter_grant() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    for granted in [false, true] {
        let bash = Path::new("/bin/bash").canonicalize().expect("resolve Bash");
        let extra = if granted {
            ", \"~/unlisted/marker\""
        } else {
            ""
        };
        let tool = format!(
            r#"
[tool.mutable]
command = ["{{box_home}}/mutable-script"]
[tool.mutable.filesystem]
read_file = [{bash:?}, "~/fixture-env/env"{extra}]
"#
        );
        let request = Request::with_config("script-same-run-tool", TOOL_POLICY, &tool);
        let (env, marker) = outside_fixtures(&request);
        let script = request.operator_home().join("agent-home/mutable-script");
        std::fs::create_dir_all(script.parent().unwrap())
            .expect("create the writable script directory");
        executable(&script, &original_script(&bash, &marker));
        let box_ = request.expect();
        let changed = format!("#!{} {}\n", env.display(), marker.display());
        let invocation = quoted(script.to_str().unwrap());
        let workload = format!(
            "zsh -c {invocation} || exit 90\nprintf '%s' {} > {invocation} || exit 91\nprintf 'SCRIPT_CHANGED\\n'\nzsh -c {invocation}",
            quoted(&changed)
        );

        let output = run(&box_, &bash, &["-c", &workload]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("ORIGINAL_SCRIPT_RAN"),
            "the first declared tool must run: {}",
            text(&output)
        );
        assert!(
            stdout.contains("SCRIPT_CHANGED"),
            "the contained writer must run: {}",
            text(&output)
        );
        assert_direct_read(&output, granted);
        assert_eq!(std::fs::read_to_string(&script).unwrap(), changed);
        assert_read_result(&output, &marker, granted);
    }
}
