use std::path::{Path, PathBuf};
use std::process::Command;

use strands_det_harness::mcp_fixture::{box_sibling, place_server, server_dir};
use strands_det_harness::{BoxFixture, Platform, RunResult, det_case, sh_quote};

// A leaf holds no route back to its own box's broker (issue #255). Only the agent gets the
// interpreter aliases in `<box_dir>/bin`, that directory on its PATH, and a connect grant on
// `<box_dir>/run/box.sock`. A `[tool.<name>]` leaf, a stdio `[mcp.<name>]` leaf behind the gateway,
// and a stdio `[mcp.<name>]` leaf with `contain_egress = false` each declare a PATH that names
// `<box_dir>/bin` in four spellings, and each must answer a PATH without it, fail to run every
// alias in `<box_dir>/bin`, and fail to connect to `box.sock`. The controls: the same probe run by
// the agent sees the alias directory first on its PATH, runs the `zsh` alias, and connects to the
// socket; the agent's own `zsh -lc` reaches the Strands Shell; and each leaf answers its PATH.
const PROBE: &str = include_str!("../probes/leaf_probe.rs");

#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-t03-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-t03-macos";

include!("../probes/fetch_server.rs");

/// What an alias prints when it reaches the broker; no argument spells it whole.
const RAN: &str = "DET_T03_ALIAS_RAN";

const SHELL_ALIASES: [&str; 3] = ["zsh", "bash", "sh"];
const PYTHON_ALIASES: [&str; 2] = ["python3", "python"];

/// The arguments that make one alias print [`RAN`]: a command for an interpreter, none for an MCP alias.
fn alias_arguments(name: &str) -> Vec<String> {
    if SHELL_ALIASES.contains(&name) {
        vec!["-c".into(), "printf '%s_%s\\n' DET_T03 ALIAS_RAN".into()]
    } else if PYTHON_ALIASES.contains(&name) {
        vec!["-c".into(), "print('DET_T03' + '_ALIAS_RAN')".into()]
    } else {
        Vec::new()
    }
}

/// Every alias the box placed in `<box_dir>/bin`, by name; the five interpreter aliases must be there.
fn aliases(b: &BoxFixture) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(b.alias_dir())
        .expect("DET_ERROR: list the alias directory")
        .map(|entry| entry.expect("DET_ERROR: an alias entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in SHELL_ALIASES.iter().chain(&PYTHON_ALIASES) {
        assert!(names.iter().any(|n| n == name), "DET_ERROR: the alias directory lacks {name}: {names:?}");
    }
    names
}

/// A symbolic link to `box_dir`, so one PATH spelling of `<box_dir>/bin` differs from it textually.
fn linked_box_dir(b: &BoxFixture) -> PathBuf {
    let link = b.workspace().parent().unwrap().join("t03-box-link");
    if !link.exists() {
        std::os::unix::fs::symlink(b.box_dir(), &link).expect("DET_ERROR: link to the box directory");
    }
    link
}

/// Four spellings of `<box_dir>/bin`, joined as PATH entries.
fn alias_spellings(b: &BoxFixture) -> String {
    let bin = b.alias_dir();
    let state = b.box_dir().display().to_string();
    [
        bin.display().to_string(),
        format!("{}/", bin.display()),
        format!("{state}/./bin"),
        linked_box_dir(b).join("bin").display().to_string(),
    ]
    .join(":")
}

/// Panic if one entry of `path` names anything under `box_dir`, in any spelling.
fn assert_no_box_entry(b: &BoxFixture, leaf: &str, path: &str) {
    let state = b.box_dir().canonicalize().expect("DET_ERROR: resolve the box directory");
    let link = linked_box_dir(b);
    for entry in std::env::split_paths(path) {
        let resolved = entry.canonicalize().unwrap_or_else(|_| entry.clone());
        assert!(
            !resolved.starts_with(&state) && !entry.starts_with(b.box_dir()) && !entry.starts_with(&link),
            "the {leaf} leaf holds {} on its PATH, which is under the box directory; PATH={path}",
            entry.display()
        );
    }
    assert!(!path.contains(RAN), "DET_ERROR: the PATH line holds the alias marker");
}

/// One `tools/call` of the fetch server's `tool` with `arguments`, from the host.
fn call(b: &BoxFixture, tool: &str, arguments: serde_json::Value) -> String {
    let output = Command::new(box_sibling("box-mcp-call-probe"))
        .arg(b.box_dir().join("run").join("box.sock"))
        .arg(FETCH_PROGRAM)
        .arg(tool)
        .arg(arguments.to_string())
        .output()
        .expect("run box-mcp-call-probe");
    String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr)
}

fn with_fetch_server(config: String, b: &BoxFixture, native: bool, control: &Path) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let path = format!("{}:{}:/usr/bin:/bin", server_dir().display(), alias_spellings(b));
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.env]\nPATH = {}\n",
        quote(FETCH_PROGRAM),
        quote(&path)
    );
    if native {
        tables.push_str("[mcp.fetch.network]\ncontain_egress = false\n");
    }
    let control = quote(&control.display().to_string());
    tables.push_str(&format!("[mcp.fetch.filesystem]\nwrite = [{control}]\n"));
    if Platform::current() == Platform::Macos {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("read = [{dir}]\n"));
    }
    config + &tables
}

/// The MCP leaf arm: its PATH, a connect to `box.sock`, and an exec of every alias, from inside it.
fn mcp_leaf(b: &BoxFixture, native: bool) {
    let leaf = if native { "native-egress MCP" } else { "gateway MCP" };
    let socket = b.box_dir().join("run").join("box.sock");
    place_server(FETCH_PROGRAM);
    // A socket under the leaf's own write grant, so the fixture's connect tool has a target it reaches.
    let control = b.workspace().parent().unwrap().join(if native { "t03-ctl-n" } else { "t03-ctl-g" });
    std::fs::create_dir_all(&control).expect("DET_ERROR: the control socket directory");
    let control_socket = control.join("ctl.sock");
    let _control_listener = std::os::unix::net::UnixListener::bind(&control_socket)
        .expect("DET_ERROR: bind the control socket");
    let mut path = String::new();
    let mut connect = String::new();
    let mut control_connect = String::new();
    let mut control_exec = String::new();
    let mut execs = Vec::new();
    let meanwhile = || {
        assert!(socket.exists(), "DET_ERROR: the broker socket is absent while the box runs");
        path = call(b, "env", serde_json::json!({ "name": "PATH" }));
        connect = call(b, "unix-connect", serde_json::json!({ "path": socket.to_string_lossy() }));
        control_connect =
            call(b, "unix-connect", serde_json::json!({ "path": control_socket.to_string_lossy() }));
        let server = server_dir().join(FETCH_PROGRAM);
        control_exec =
            call(b, "exec", serde_json::json!({ "path": server.to_string_lossy(), "args": [] }));
        for name in aliases(b) {
            let alias = b.alias_dir().join(&name);
            let arguments = serde_json::json!({ "path": alias.to_string_lossy(), "args": alias_arguments(&name) });
            execs.push((name, call(b, "exec", arguments)));
        }
    };
    let host_path = format!("{}:{}", server_dir().display(), std::env::var("PATH").unwrap_or_default());
    let run = b.run_sh_with_config_meanwhile_env(
        |config| with_fetch_server(config, b, native, &control),
        BLOCK,
        &[("PATH", host_path.as_str())],
        meanwhile,
    );
    let all = execs.iter().map(|(name, out)| format!("{name}: {out}")).collect::<Vec<_>>().join("\n");
    let report = format!(
        "PATH: {path}\nconnect: {connect}\ncontrol connect: {control_connect}\ncontrol exec: {control_exec}\n{all}\n[box output]\n{}",
        run.out
    );
    let combined = RunResult::bare(report.clone(), 0);

    // The control: the leaf started and answered, so a refusal below is the leaf's own.
    run.assert_mediated_permitted("shell:spawn", FETCH_PROGRAM);
    run.assert_mediated_permitted("mcp:call", "fetch/env");
    if native {
        run.assert_mediated_permitted("egress:native", "fetch");
    }
    let value = path
        .lines()
        .find_map(|line| line.strip_prefix("env:"))
        .unwrap_or_else(|| panic!("DET_ERROR: the {leaf} leaf answered no PATH; {report}"));
    assert!(value.contains("/usr/bin"), "DET_ERROR: the {leaf} leaf PATH is not its declared one; {report}");
    // 1. No spelling of `<box_dir>/bin` survives on the leaf's PATH.
    assert_no_box_entry(b, leaf, value);
    // The fixture's exec and connect tools work inside this leaf, so a refusal below is containment.
    assert!(
        control_exec.contains("exec-ok:"),
        "DET_ERROR: the {leaf} leaf could not exec its own granted program; {report}"
    );
    assert!(
        control_connect.contains("connect-ok"),
        "DET_ERROR: the {leaf} leaf could not connect to a socket under its own write grant; {report}"
    );
    // 2. No alias runs.
    for (name, out) in &execs {
        assert!(
            out.contains("exec-failed:") && !out.contains("exec-ok"),
            "the {leaf} leaf ran the {name} alias; {report}"
        );
    }
    combined.assert_absent(RAN);
    // 3. The connect to this box's own broker socket fails with an errno.
    assert!(
        connect.contains("connect-failed:errno=") && !connect.contains("connect-ok"),
        "the {leaf} leaf connected to its own box.sock; {report}"
    );
}

det_case! {
    name: cn_t_03,
    id:   "CN-T-03",
    platforms: [Linux, Macos],
    desc: "Leaf has no route to the broker: a [tool.x] leaf, a gateway [mcp.x] leaf, and a contain_egress=false [mcp.x] leaf hold no <box_dir>/bin on PATH in any spelling, run no alias, and fail to connect to box.sock; the agent holds all three",
    run: |b| {
        let probe = b.compile_probe("leafprobe-t03", PROBE);
        let quoted = |s: &str| serde_json::to_string(s).unwrap();
        let exec_tree = b.with_exec_tree();
        let tool_path = format!("{}:/usr/bin:/bin", alias_spellings(b));
        let edit = |text: String| format!(
            "{}\n[tool.t03]\ncommand = [{}]\n\n[tool.t03.env]\nPATH = {}\n",
            exec_tree(text), quoted(&probe.to_string_lossy()), quoted(&tool_path)
        );
        b.apply_policy(&format!("{SERVER_PERMIT}\n"));
        let socket = b.box_dir().join("run").join("box.sock");
        let names = aliases(b);
        let p = sh_quote(&probe.to_string_lossy());
        let s = sh_quote(&socket.to_string_lossy());
        let execs = |prefix: &str| names.iter().map(|name| {
            let arguments: Vec<String> = alias_arguments(name).iter().map(|a| sh_quote(a)).collect();
            format!("{prefix}{p} exec {} {}", sh_quote(&b.alias_dir().join(name).to_string_lossy()), arguments.join(" "))
        }).collect::<Vec<_>>().join("; ");

        // The control: the agent runs the same probe and holds all three routes.
        let agent = b.run_sh_with_config(edit, &format!(
            "{p} path; {p} unix-connect {s}; {p} exec {} {}",
            sh_quote(&b.alias_dir().join("zsh").to_string_lossy()),
            alias_arguments("zsh").iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" "),
        ));
        let agent_path = agent.out.lines().find_map(|l| l.strip_prefix("PATH_SET value=")).unwrap_or_else(|| {
            panic!("DET_ERROR: the agent probe answered no PATH; out=[{}]", agent.snippet())
        });
        assert_eq!(
            std::env::split_paths(agent_path).next().map(|first| first.canonicalize().unwrap_or(first)),
            b.alias_dir().canonicalize().ok(),
            "DET_ERROR: the agent's PATH does not begin with the alias directory; PATH={agent_path}"
        );
        agent.assert_contains(&format!("CONNECT_OK {:?}", socket.to_string_lossy()));
        agent.assert_contains(&format!("EXEC_OK {:?} :: {RAN}", b.alias_dir().join("zsh").to_string_lossy()));

        // The tool leaf: spawned by the agent's Strands Shell, which proves the mediated route.
        let r = b.run_mediated_with_config(edit, &format!(
            "{p} path; {p} unix-connect {s}; {}", execs("")
        ));
        r.assert_mediated_permitted("shell:spawn", "leafprobe-t03");
        let tool_value = r.out.lines().find_map(|l| l.strip_prefix("PATH_SET value=")).unwrap_or_else(|| {
            panic!("DET_ERROR: the tool leaf answered no PATH; out=[{}]", r.snippet())
        });
        assert!(tool_value.contains("/usr/bin"), "DET_ERROR: the tool leaf PATH is not its declared one; PATH={tool_value}");
        assert_no_box_entry(b, "tool", tool_value);
        for name in &names {
            let line = format!("{:?}", b.alias_dir().join(name).to_string_lossy());
            assert!(
                r.out.lines().any(|l| l.starts_with(&format!("EXEC_FAILED {line}")) || l.starts_with(&format!("EXEC_REFUSED {line}"))),
                "the tool leaf did not fail to run the {name} alias; out=[{}]", r.snippet()
            );
            r.assert_absent(&format!("EXEC_OK {line}"));
        }
        r.assert_absent(RAN);
        r.assert_contains(&format!("CONNECT_REFUSED {:?} errno=", socket.to_string_lossy()));
        r.assert_absent("CONNECT_OK");

        mcp_leaf(b, false);
        mcp_leaf(b, true);
    }
}
