//! `monty = false` through a real `run`: a bare `python3` or `python` runs the declared Python
//! tool, is refused with a reason when there is none, is denied without a `shell:spawn` permit, and
//! runs Monty with the table unused when Monty is on.

mod support {
    pub mod fixture;
}

use std::path::Path;
use std::process::Output;

use support::fixture::{Configured, Request, namespace_launcher_is_usable};

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run `command` in the hosted Shell, and print its status after it.
fn in_the_shell(box_: &Configured, command: &str) -> Output {
    box_.bash(&format!(r#"zsh -c '{command}; printf "|status=%s" "$?"'"#))
}

/// A policy that lets the Shell run commands and read files, and spawns nothing.
const SHELL_ONLY: &str = r#"
permit (principal, action == Box::Action::"shell:exec", resource);
permit (principal, action == Box::Action::"fs:read", resource);
"#;

/// A stand-in Python install laid out the standard way: `<home>/py/bin/python3`, a `#!/bin/sh`
/// script that prints its arguments, and `<home>/py/lib/python3.12/os.py`, the file install
/// detection looks for. Answers with the script's canonical path.
fn fake_python_install(home: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let prefix = home.join("py");
    std::fs::create_dir_all(prefix.join("bin")).expect("the install's bin directory");
    std::fs::create_dir_all(prefix.join("lib/python3.12")).expect("the standard library");
    std::fs::write(prefix.join("lib/python3.12/os.py"), "").expect("the standard library's os.py");
    let program = prefix.join("bin/python3");
    std::fs::write(&program, "#!/bin/sh\nprintf 'FAKE_PYTHON:%s\\n' \"$*\"\n")
        .expect("the stand-in python3");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("an executable stand-in");
    program.canonicalize().expect("the stand-in resolves")
}

/// A `[tool.python3]` whose command is the stand-in install, with read access to the install
/// and, on Linux, to the script's interpreter.
fn python_tool(home: &Path, program: &Path) -> String {
    let interpreter = if cfg!(target_os = "linux") {
        let sh = Path::new("/bin/sh")
            .canonicalize()
            .expect("resolve the script interpreter");
        format!("\nread_file = [{:?}]", sh.display().to_string())
    } else {
        String::new()
    };
    format!(
        "[tool.python3]\ncommand = [{:?}]\n[tool.python3.filesystem]\nread = [{:?}]{interpreter}\n",
        program.display().to_string(),
        home.join("py").display().to_string()
    )
}

/// `SHELL_ONLY` plus a `shell:spawn` permit for `program`.
fn spawn_permit(program: &Path) -> String {
    format!(
        r#"{SHELL_ONLY}
permit (principal, action == Box::Action::"shell:spawn", resource)
when {{ context.input.program_path == "{}" }};"#,
        program.display()
    )
}

#[test]
fn with_monty_off_and_no_python_tool_python3_exits_126_with_the_reason() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let (box_, started) = Request::with_config("monty-off-alone", SHELL_ONLY, "")
        .top_level("monty = false")
        .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    assert!(
        stderr(&started).contains(
            "strands-box: Monty is off (monty = false) and no [tool.python3] or [tool.python] is \
             declared, so python3 and python exit 126\n"
        ),
        "startup says python3 exits 126: {}",
        stderr(&started)
    );

    for command in ["python3 -c 1", "python -c 1"] {
        let output = in_the_shell(&box_, command);
        let name = command.split(' ').next().expect("a name");
        assert!(
            stdout(&output).contains("|status=126"),
            "{command}: {output:?}"
        );
        assert!(
            stderr(&output).contains(&format!(
                "strands-shell: {name}: Monty is off (monty = false) and no [tool.python3] or \
                 [tool.python] is declared"
            )),
            "{command} names the reason: {output:?}"
        );
        assert!(
            !stdout(&output).contains("Monty (Strands-Box Python subset)"),
            "{command} never falls back to Monty: {output:?}"
        );
    }
}

#[test]
fn with_monty_off_python3_and_python_run_the_python_tool() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let program = fake_python_install(home.path());
    let (box_, started) = Request::with_config(
        "monty-off-tool",
        &spawn_permit(&program),
        &python_tool(home.path(), &program),
    )
    .top_level("monty = false")
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    assert!(
        stderr(&started).contains(&format!(
            "strands-box: [tool.python3]: a bare `python3` in the Shell runs {}, in place of Monty\n",
            program.display()
        )),
        "startup names the file python3 runs: {}",
        stderr(&started)
    );

    for command in ["python3 a b", "python a b"] {
        let output = in_the_shell(&box_, command);
        assert!(
            stdout(&output).contains("|status=0"),
            "{command}: {output:?}"
        );
        assert!(
            stdout(&output).contains("FAKE_PYTHON:a b\n"),
            "{command} runs the tool's file with its arguments: {output:?}"
        );
    }
    let version = in_the_shell(&box_, "python3 --version");
    assert!(
        !stdout(&version).contains("Monty (Strands-Box Python subset)"),
        "Monty no longer answers to python3: {version:?}"
    );
}

#[test]
fn with_monty_off_a_python_tool_without_a_permit_is_denied_and_never_runs_monty() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let program = fake_python_install(home.path());
    let box_ = Request::with_config(
        "monty-off-no-permit",
        SHELL_ONLY,
        &python_tool(home.path(), &program),
    )
    .top_level("monty = false")
    .expect();

    for command in ["python3 --version", "python a b"] {
        let output = in_the_shell(&box_, command);
        assert!(
            stdout(&output).contains("|status=126"),
            "{command}: {output:?}"
        );
        assert!(
            stderr(&output).contains("default-deny"),
            "{command} is refused by the default deny: {output:?}"
        );
        assert!(
            !stdout(&output).contains("Monty (Strands-Box Python subset)")
                && !stdout(&output).contains("FAKE_PYTHON:"),
            "{command} runs neither Monty nor the tool: {output:?}"
        );
    }
}

#[test]
fn with_monty_on_a_python_tool_is_unused_and_python3_is_monty() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let home = support::fixture::short_temporary_home();
    let program = fake_python_install(home.path());
    let (box_, started) = Request::with_config(
        "monty-on-tool",
        &spawn_permit(&program),
        &python_tool(home.path(), &program),
    )
    .attempt();
    assert!(started.status.success(), "{}", stderr(&started));
    assert!(
        stderr(&started).contains(
            "strands-box: a bare python3 or python in the Shell runs Monty, Box's Python subset\n"
        ) && stderr(&started).contains(
            "strands-box: [tool.python3]: not used for a bare python3 or python, because Monty is \
             on. Set monty = false at the top of box.toml to use it\n"
        ),
        "startup says Monty answers and names the unused table: {}",
        stderr(&started)
    );

    let version = in_the_shell(&box_, "python3 --version");
    assert!(stdout(&version).contains("|status=0"), "{version:?}");
    assert!(
        stdout(&version).contains("Monty (Strands-Box Python subset)"),
        "python3 is Monty: {version:?}"
    );
    assert!(
        !stdout(&version).contains("FAKE_PYTHON:"),
        "the unused table does not run: {version:?}"
    );
}

/// The host's Homebrew `python3`, if there is one. Homebrew names every library its extension
/// modules load through `<prefix>/opt/<formula>` links, which is the case this test needs. The
/// macOS runner has one; the Linux runner has no Homebrew, and Linux CI fails on a skip it doesn't
/// expect, so the test is macOS-only.
#[cfg(target_os = "macos")]
fn homebrew_python() -> Option<std::path::PathBuf> {
    ["/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        .into_iter()
        .map(Path::new)
        .find(|candidate| {
            candidate
                .canonicalize()
                .is_ok_and(|real| real.components().any(|part| part.as_os_str() == "Cellar"))
        })
        .map(Path::to_path_buf)
}

/// With no `[tool.python3.filesystem]`, Box grants a real Homebrew Python the libraries its
/// extension modules load. Homebrew names each one through links, such as
/// `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib`, and Box's own lists refuse a link, so the
/// grant names the real file and containment also grants the name the load requests. Before that,
/// the box refused to start.
#[cfg(target_os = "macos")]
#[test]
fn with_monty_off_a_homebrew_python_loads_the_libraries_its_modules_name_through_links() {
    if !namespace_launcher_is_usable() {
        eprintln!("skipping: the namespace launcher is not usable on this host");
        return;
    }
    let Some(python) = homebrew_python() else {
        eprintln!("skipping: no Homebrew python3 on this host");
        return;
    };
    let home = support::fixture::short_temporary_home();
    let venv = home.path().join("venv");
    let made = std::process::Command::new(&python)
        .args(["-m", "venv", "--without-pip"])
        .arg(&venv)
        .output()
        .expect("run python3 -m venv");
    assert!(made.status.success(), "make the venv: {made:?}");
    let command = venv.join("bin/python3");
    let program = command.canonicalize().expect("the venv's python3 resolves");
    let (box_, started) = Request::with_config(
        "monty-off-homebrew",
        &spawn_permit(&program),
        &format!(
            "[tool.python3]\ncommand = [{:?}]\n",
            command.display().to_string()
        ),
    )
    .top_level("monty = false")
    .attempt();
    assert!(
        started.status.success(),
        "the box starts: {}",
        stderr(&started)
    );
    assert!(
        stderr(&started).contains("(added for [tool.python3]: libraries)  (loaded as "),
        "startup lists a library with the name its load requests: {}",
        stderr(&started)
    );

    let output = in_the_shell(
        &box_,
        r#"python3 -c "import ssl, lzma, sqlite3, decimal; print(ssl.OPENSSL_VERSION.split()[0], decimal.Decimal(1) / 4)""#,
    );
    assert!(
        stdout(&output).contains("OpenSSL 0.25\n|status=0"),
        "the modules load their libraries: {output:?}"
    );
}
