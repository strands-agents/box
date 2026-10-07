#![allow(dead_code)] // Each suite uses a different part of this.

use std::ffi::CString;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::FromRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::fixture;

mod captured_output;
use captured_output::CapturedOutput;

const CONTROL_DIRECTORY: &str = ".runtime-mcp-test";

/// The agent home the fixture declares, under the operator home.
const AGENT_HOME: &str = "agent-home";
const UNRELATED_SENTINEL: &str = "STRANDS_BOX_DISCOVERY_SENTINEL";
const POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy)]
pub enum DiscoveryBehavior {
    Ready,
    WaitForRelease,
    FailAfterRelease,
    Hang,
    MultipageExchange,
    Pages(usize),
    RepeatedCursor,
    RepeatedTool,
    ConflictingDefinitions,
    InvalidResponse,
    ErrorResponse,
    ExitAfterReady,
}

impl DiscoveryBehavior {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::WaitForRelease => "wait",
            Self::FailAfterRelease => "fail",
            Self::Hang => "hang",
            Self::MultipageExchange => "exchange",
            Self::Pages(_) => "pages",
            Self::RepeatedCursor => "repeated-cursor",
            Self::RepeatedTool => "repeated-tool",
            Self::ConflictingDefinitions => "conflicting-definitions",
            Self::InvalidResponse => "invalid-response",
            Self::ErrorResponse => "error-response",
            Self::ExitAfterReady => "exit-after-ready",
        }
    }

    fn uses_release_fifo(self) -> bool {
        matches!(
            self,
            Self::WaitForRelease | Self::FailAfterRelease | Self::ExitAfterReady
        )
    }

    fn page_count(self) -> usize {
        match self {
            Self::MultipageExchange
            | Self::RepeatedCursor
            | Self::RepeatedTool
            | Self::ConflictingDefinitions => 2,
            Self::Pages(count) => count,
            _ => 1,
        }
    }
}

pub struct Server<'a> {
    pub name: &'a str,
    pub program: &'a str,
    pub tool: &'a str,
    pub behavior: DiscoveryBehavior,
    executable: &'a str,
    arguments: Vec<String>,
    /// `Some(false)` emits `[mcp.<name>.network] contain_egress = false` (native egress); `None`
    /// leaves the default gateway-routed posture.
    contain_egress: Option<bool>,
    /// Extra `[mcp.<name>.env]` entries; the fetch tool reads `FIXTURE_FETCH_TARGET` from here.
    env: Vec<(String, String)>,
}

impl<'a> Server<'a> {
    pub fn new(
        name: &'a str,
        program: &'a str,
        tool: &'a str,
        behavior: DiscoveryBehavior,
    ) -> Self {
        Self {
            name,
            program,
            tool,
            behavior,
            executable: program,
            arguments: vec!["--declared".to_string(), name.to_string()],
            contain_egress: None,
            env: Vec::new(),
        }
    }

    pub fn launched_through(mut self, executable: &'a str, arguments: Vec<String>) -> Self {
        self.executable = executable;
        self.arguments = arguments;
        self
    }

    /// Declare `[mcp.<name>.network] contain_egress = false` — the native-egress trust grant.
    pub fn native_egress(mut self) -> Self {
        self.contain_egress = Some(false);
        self
    }

    /// Add one `[mcp.<name>.env]` entry.
    pub fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_string(), value.to_string()));
        self
    }
}

pub struct RuntimeMcpBox {
    home: tempfile::TempDir,
    workspace: PathBuf,
    bin: PathBuf,
    control: PathBuf,
    name: String,
    /// `[tool.<label>]` tables the box declares, as `(label, table)`.
    tools: Vec<(String, String)>,
}

impl RuntimeMcpBox {
    pub fn new(name: &str) -> Self {
        let home = fixture::short_temporary_home();
        let workspace = home.path().join("workspace");
        let bin = home.path().join("operator-bin");
        let control = home.path().join(CONTROL_DIRECTORY);
        std::fs::create_dir_all(workspace.join(".strands-box")).expect("create the Box workspace");
        std::fs::create_dir_all(&bin).expect("create the operator bin directory");
        std::fs::create_dir_all(&control).expect("create the MCP control directory");
        // A directory this fixture owns, never `~/.strands-box/b/`: Box sites no box and creates no
        // ancestor, so the caller names the path and creates its parent.
        let root = home.path().join("boxes").join(name);
        std::fs::create_dir_all(root.parent().expect("the box root has a parent"))
            .expect("create the box directory's parent");
        std::fs::create_dir(&root).expect("create the caller-owned box directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("make the box directory private");
        std::fs::create_dir(home.path().join(AGENT_HOME)).expect("create the agent home");
        Self {
            home,
            workspace,
            bin,
            control,
            name: name.to_string(),
            tools: Vec::new(),
        }
    }

    /// Place an executable `script` named `name` on the operator's `PATH`, beside the servers.
    pub fn install_program(&self, name: &str, script: &str) -> PathBuf {
        let path = self.bin.join(name);
        std::fs::write(&path, script).expect("write the operator program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make the operator program executable");
        path
    }

    /// Declare one `[tool.<label>]` table.
    pub fn declare_tool(&mut self, label: &str, table: &str) {
        self.tools.push((label.to_string(), table.to_string()));
    }

    pub fn install_server(&self, server: &Server<'_>) {
        if server.behavior.uses_release_fifo() {
            make_fifo(&self.release_path(server.program));
        }
        let script = format!(
            r#"#!/usr/bin/python3
import json
import os
import pathlib
import subprocess
import sys

control = pathlib.Path({control:?})
program = {program:?}
server = {server:?}
tool = {tool:?}
behavior = {behavior:?}
page_count = {page_count}

def path(kind):
    return control / (program + "." + kind)

def write(kind, value):
    path(kind).write_text(str(value) + "\n")

def append(kind, value):
    with path(kind).open("a") as output:
        output.write(str(value) + "\n")
        output.flush()

def mark(kind):
    path(kind).touch()

def respond(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)

def page_number(frame):
    cursor = frame.get("params", {{}}).get("cursor")
    if cursor is None:
        return 0
    if cursor == "repeat":
        return 1
    prefix = "cursor-"
    if not isinstance(cursor, str) or not cursor.startswith(prefix):
        raise ValueError("unexpected fixture cursor " + repr(cursor))
    return int(cursor[len(prefix):])

append("invocations", os.getpid())
append("pids", os.getpid())
write("pid", os.getpid())
write("home", os.environ.get("HOME", "<absent>"))
write("path", os.environ.get("PATH", "<absent>"))
write("cwd", pathlib.Path.cwd().resolve())
write("sentinel", "present" if {sentinel:?} in os.environ else "absent")
write("argv", json.dumps(sys.argv[1:], separators=(",", ":")))
write("environment", json.dumps(dict(sorted(os.environ.items())), separators=(",", ":")))
if behavior in ("fail", "hang"):
    descendant = subprocess.Popen(
        ["/bin/sleep", "3600"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    write("descendant.pid", descendant.pid)
    append("descendant.pids", descendant.pid)
mark("started")

while True:
    raw = sys.stdin.readline()
    if not raw:
        break
    frame = json.loads(raw)
    method = frame.get("method")
    if method == "initialize":
        append("initialize.frames", json.dumps(frame, separators=(",", ":")))
        respond({{
            "jsonrpc": "2.0",
            "id": frame["id"],
            "result": {{
                "protocolVersion": "2024-11-05",
                "capabilities": {{"tools": {{"listChanged": True}}}},
                "serverInfo": {{"name": server, "version": "fixture-1"}},
                "fixtureExtension": {{"preserved": True}}
            }},
            "fixtureTopLevel": "preserved"
        }})
    elif method == "notifications/initialized":
        append("initialized.frames", json.dumps(frame, separators=(",", ":")))
        mark("initialized")
    elif method == "tools/list":
        append("list.frames", json.dumps(frame, separators=(",", ":")))
        mark("list.started")
        page = page_number(frame)
        if behavior in ("wait", "fail"):
            with path("release").open("r") as release:
                release.readline()
        elif behavior == "hang":
            while True:
                subprocess.run(["/bin/sleep", "3600"], check=False)
        if behavior == "fail":
            sys.exit(17)
        if behavior == "exchange":
            respond({{
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {{"phase": "pagination", "page": page}}
            }})
            if page == 0:
                respond({{
                    "jsonrpc": "2.0",
                    "id": "fixture-ping",
                    "method": "ping",
                    "params": {{"during": "pagination"}}
                }})
                respond({{
                    "jsonrpc": "2.0",
                    "id": 701,
                    "method": "fixture/unsupported",
                    "params": {{"during": "pagination"}}
                }})
                for expected in ("fixture-ping", 701):
                    local_raw = sys.stdin.readline()
                    if not local_raw:
                        sys.exit(18)
                    local = json.loads(local_raw)
                    append("broker.frames", json.dumps(local, separators=(",", ":")))
                    if local.get("id") != expected:
                        sys.exit(19)
        if behavior == "invalid-response":
            respond({{
                "jsonrpc": "1.0",
                "id": frame["id"],
                "result": {{"tools": []}}
            }})
            continue
        if behavior == "error-response":
            respond({{
                "jsonrpc": "2.0",
                "id": frame["id"],
                "error": {{"code": -32603, "message": "fixture list error"}}
            }})
            continue

        tool_name = tool if behavior == "repeated-tool" or page == 0 else tool + "-" + str(page)
        result = {{
            "tools": [{{
                "name": tool_name,
                "description": "Runtime policy staging test tool",
                "inputSchema": {{
                    "type": "object",
                    "properties": {{"value": {{"type": "string"}}}},
                    "required": ["value"]
                }},
                "fixtureField": "tool-" + str(page)
            }}],
            "fixturePageField": "page-" + str(page)
        }}
        if behavior in ("exchange", "conflicting-definitions"):
            result["$defs"] = {{
                "Shared": {{
                    "type": "number" if behavior == "conflicting-definitions" and page == 1 else "string"
                }}
            }}
        if behavior == "repeated-cursor":
            result["nextCursor"] = "repeat"
        elif page + 1 < page_count:
            result["nextCursor"] = "cursor-" + str(page + 1)
        respond({{
            "jsonrpc": "2.0",
            "id": frame["id"],
            "result": result,
            "fixtureResponseField": "response-" + str(page)
        }})
        if behavior == "exchange" and page + 1 == page_count:
            respond({{
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
                "params": {{"phase": "finalization"}}
            }})
            mark("finalization.notification")
        if behavior == "exit-after-ready" and page + 1 == page_count:
            mark("exit.waiting")
            with path("release").open("r") as release:
                release.readline()
            sys.exit(0)
    elif method == "tools/call":
        append("call.frames", json.dumps(frame, separators=(",", ":")))
        mark("call.received")
        fetch_target = os.environ.get("FIXTURE_FETCH_TARGET")
        connect_targets = os.environ.get("FIXTURE_CONNECT_UNIX")
        resolve_target = os.environ.get("FIXTURE_RESOLVE")
        if connect_targets:
            # One `connect()` per `|`-separated pathname socket, each reported on its own line.
            import errno
            import socket
            lines = []
            for target in connect_targets.split("|"):
                try:
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        probe.connect(target)
                    finally:
                        probe.close()
                    lines.append("connected:" + target)
                except OSError as error:
                    name = errno.errorcode.get(error.errno, str(error.errno))
                    lines.append("refused:" + target + ":" + name)
            text = "\n".join(lines)
        elif resolve_target:
            import socket
            try:
                socket.getaddrinfo(resolve_target, 80)
                text = "resolved:" + resolve_target
            except OSError as error:
                text = "resolve-failed:" + repr(error)
        elif fetch_target:
            # Native-egress proof: reach a host endpoint the box did not proxy. Under
            # contain_egress = false the leaf has the host network and this succeeds; under the
            # gateway default the direct connect is refused and the tool reports the failure.
            # `urllib.request` is imported HERE, not at module top: importing it eagerly pulls in
            # `ssl`/`socket` and can fault at leaf startup under a restrictive containment profile,
            # which would kill the leaf before it signals `started` (breaks every runtime_mcp test).
            try:
                import urllib.request
                with urllib.request.urlopen(fetch_target, timeout=5) as response:
                    body = response.read().decode("utf-8", "replace")
                text = "fetched:" + body
            except Exception as error:
                text = "fetch-failed:" + repr(error)
        else:
            text = "called " + tool
        respond({{
            "jsonrpc": "2.0",
            "id": frame["id"],
            "result": {{
                "content": [{{"type": "text", "text": text}}],
                "isError": False
            }}
        }})
    elif "id" in frame:
        respond({{
            "jsonrpc": "2.0",
            "id": frame["id"],
            "error": {{"code": -32601, "message": "Method not found"}}
        }})
"#,
            control = self.control.to_string_lossy(),
            program = server.program,
            server = server.name,
            tool = server.tool,
            behavior = server.behavior.as_str(),
            page_count = server.behavior.page_count(),
            sentinel = UNRELATED_SENTINEL,
        );
        let path = self.bin.join(server.executable);
        std::fs::write(&path, script).expect("write the fake MCP server");
        let mut permissions = std::fs::metadata(&path)
            .expect("read fake MCP server metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make the fake MCP server executable");
    }

    /// Write the workspace with `policy` plus a permit that starts every declared server.
    pub fn write_workspace(&self, policy: &str, servers: &[Server<'_>], workload: &str) {
        let policy = format!(
            "permit (principal, action == Box::Action::\"shell:spawn\", resource);\n{policy}"
        );
        self.write_workspace_as_authored(&policy, servers, workload);
    }

    /// Write the workspace with `policy` exactly as given.
    pub fn write_workspace_as_authored(
        &self,
        policy: &str,
        servers: &[Server<'_>],
        workload: &str,
    ) {
        let dot = self.workspace.join(".strands-box");
        std::fs::write(dot.join("policy.dw"), policy).expect("write the workspace policy");
        let workload = toml::Value::String(workload.to_string());
        // The agent reaches every declared server, so each one's alias is on its PATH; its home is
        // a directory of the fixture's, granted read and write, where the workload leaves its
        // markers.
        let agent_home = self.box_home().display().to_string();
        // The contained MCP leaf must READ its own server script (it lives in operator-bin, which the
        // shebang's python opens) and WRITE its lifecycle markers into the control dir. Without these
        // grants the leaf dies at startup under macOS Seatbelt ("Operation not permitted" opening the
        // script) before it can signal `started`. Canonicalized so the paths match how the box
        // resolves them (/var/tmp -> /private/var/tmp on macOS).
        let operator_bin = self
            .bin
            .canonicalize()
            .expect("operator-bin resolves")
            .display()
            .to_string();
        let control = self
            .control
            .canonicalize()
            .expect("control dir resolves")
            .display()
            .to_string();
        // The leaf's cwd (the workspace) must be listable, or getcwd()/uv_cwd fails EPERM at startup.
        let workspace_path = self
            .workspace
            .canonicalize()
            .expect("workspace resolves")
            .display()
            .to_string();
        let mut config = format!(
            "name = {:?}\nbox_dir = {:?}\npolicy = \"policy.dw\"\n\n\
             [agent]\ncommand = [\"/bin/bash\", \"-c\", {workload}]\nworkspace = {:?}\n\
             env = {{ HOME = {agent_home:?} }}\n\
             [agent.filesystem]\nread = [{agent_home:?}]\nwrite = [{agent_home:?}]\n",
            self.name,
            self.root().display().to_string(),
            self.workspace
                .canonicalize()
                .expect("the workspace resolves")
                .display()
                .to_string()
        );
        for (_, table) in &self.tools {
            config.push('\n');
            config.push_str(table);
        }
        for server in servers {
            let command = std::iter::once(server.program.to_string())
                .chain(server.arguments.iter().cloned())
                .collect::<Vec<_>>();
            config.push_str(&format!(
                "\n[mcp.{}]\ntype = \"stdio\"\ncommand = {command:?}\n",
                server.name
            ));
            if let Some(contain_egress) = server.contain_egress {
                config.push_str(&format!(
                    "[mcp.{}.network]\ncontain_egress = {contain_egress}\n",
                    server.name
                ));
            }
            let toolchain = python_toolchain();
            let env = server
                .env
                .iter()
                .cloned()
                .chain(
                    toolchain
                        .developer_dir
                        .map(|directory| ("DEVELOPER_DIR".to_string(), directory)),
                )
                .collect::<Vec<_>>();
            if !env.is_empty() {
                config.push_str(&format!("[mcp.{}.env]\n", server.name));
                for (key, value) in &env {
                    config.push_str(&format!("{key} = {value:?}\n"));
                }
            }
            // Grant the leaf read of its script's dir (operator-bin), the toolchain behind the
            // `#!/usr/bin/python3` stub, and write+list of the control dir for its markers.
            let read = std::iter::once(operator_bin.clone())
                .chain(std::iter::once(control.clone()))
                .chain(toolchain.read)
                .collect::<Vec<_>>();
            config.push_str(&format!(
                "[mcp.{}.filesystem]\nread = {read:?}\nwrite = [{control:?}]\nlist = [{control:?}, {workspace_path:?}]\n",
                server.name,
            ));
        }
        std::fs::write(dot.join("box.toml"), config).expect("write box.toml");
    }

    pub fn plant_generated_schema_artifacts(&self, schema: &str) -> (PathBuf, PathBuf, PathBuf) {
        let workspace_directory = self.workspace.join(".strands-box");
        let workspace_actions = workspace_directory.join("actions.cedarschema");
        let workspace_events = workspace_directory.join("events.dwschema");
        std::fs::write(&workspace_actions, schema)
            .expect("write the stale workspace action schema");
        std::fs::write(&workspace_events, "stale event schema\n")
            .expect("write the stale workspace event schema");

        let private_directory = self.root().join("private");
        std::fs::create_dir_all(&private_directory)
            .expect("create the stale private authority directory");
        let private_schemas = private_directory.join("mcp-schemas.json");
        let serialized =
            serde_json::to_vec(&[schema]).expect("serialize the stale private schema set");
        std::fs::write(&private_schemas, serialized).expect("write the stale private schema set");

        (workspace_actions, workspace_events, private_schemas)
    }

    pub fn spawn(&self) -> RunningBox {
        let child = self.command().spawn().expect("spawn strands-box run");
        RunningBox::new(child, self.home.path().to_path_buf(), self.name.clone())
    }

    pub fn spawn_from_operator_home(&self) -> RunningBox {
        let mut command = self.command();
        command.current_dir(self.home.path());
        let child = command
            .spawn()
            .expect("spawn strands-box run outside the workspace");
        RunningBox::new(child, self.home.path().to_path_buf(), self.name.clone())
    }

    pub fn spawn_attempt(&self) -> RunningBox {
        self.spawn()
    }

    pub fn spawn_without_trusted_path(&self) -> RunningBox {
        let mut command = self.command();
        command.env_remove("PATH");
        let child = command.spawn().expect("spawn strands-box run without PATH");
        RunningBox::new(child, self.home.path().to_path_buf(), self.name.clone())
    }

    pub fn open_client(&self, program: &str) -> RunningMcpClient {
        let mut command = self.alias_command(program);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the MCP alias");
        let stdin = child.stdin.take().expect("the MCP alias stdin is piped");
        let stdout = child.stdout.take().expect("the MCP alias stdout is piped");
        let stderr = child.stderr.take().expect("the MCP alias stderr is piped");
        let (output, received) = mpsc::channel();
        let output_thread = std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let result = stdout
                    .read_line(&mut line)
                    .map_err(|error| format!("read MCP client output: {error}"))
                    .and_then(|read| {
                        if read == 0 {
                            return Err("the MCP alias closed its output".to_string());
                        }
                        serde_json::from_str(&line)
                            .map_err(|error| format!("parse MCP client output {line:?}: {error}"))
                    });
                let stop = result.is_err();
                if output.send(result).is_err() || stop {
                    return;
                }
            }
        });
        let stderr_bytes = Arc::new(Mutex::new(Vec::new()));
        let captured_stderr = Arc::clone(&stderr_bytes);
        let stderr_thread = std::thread::spawn(move || {
            let mut stderr = stderr;
            let _ = stderr.read_to_end(
                &mut captured_stderr
                    .lock()
                    .expect("the MCP stderr capture is not poisoned"),
            );
        });
        RunningMcpClient {
            child: Some(child),
            stdin: Some(stdin),
            received,
            output_thread: Some(output_thread),
            stderr_thread: Some(stderr_thread),
            stderr: stderr_bytes,
        }
    }

    pub fn invoke_refused_open(&self, program: &str, timeout: Duration) -> ClientExit {
        self.open_client(program).wait(timeout)
    }

    pub fn release_server(&self, program: &str) {
        write_fifo_before(&self.release_path(program), Duration::from_secs(3));
    }

    pub fn release_workload(&self) {
        std::fs::write(self.box_home().join("release"), b"release\n")
            .expect("release the workload");
    }

    pub fn server_started(&self, program: &str) -> PathBuf {
        self.event_path(program, "started")
    }

    pub fn server_initialized(&self, program: &str) -> PathBuf {
        self.event_path(program, "initialized")
    }

    pub fn list_started(&self, program: &str) -> PathBuf {
        self.event_path(program, "list.started")
    }

    pub fn call_received(&self, program: &str) -> PathBuf {
        self.event_path(program, "call.received")
    }

    pub fn server_pid(&self, program: &str) -> u32 {
        read_pid(&self.event_path(program, "pid"))
    }

    pub fn descendant_pid(&self, program: &str) -> u32 {
        read_pid(&self.event_path(program, "descendant.pid"))
    }

    pub fn trace(&self, program: &str, field: &str) -> String {
        std::fs::read_to_string(self.event_path(program, field))
            .unwrap_or_else(|error| panic!("read {program} {field}: {error}"))
            .trim_end()
            .to_string()
    }

    pub fn received_frames(&self, program: &str, kind: &str) -> Vec<Value> {
        std::fs::read_to_string(self.event_path(program, &format!("{kind}.frames")))
            .map(|text| {
                text.lines()
                    .map(|line| {
                        serde_json::from_str(line)
                            .unwrap_or_else(|error| panic!("parse {program} {kind} frame: {error}"))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn invocation_count(&self, program: &str) -> usize {
        self.event_line_count(program, "invocations")
    }

    pub fn list_count(&self, program: &str) -> usize {
        self.event_line_count(program, "list.frames")
    }

    pub fn call_count(&self, program: &str) -> usize {
        self.event_line_count(program, "call.frames")
    }

    pub fn process_groups(
        &self,
        program: &str,
        count: usize,
        timeout: Duration,
    ) -> Vec<(u32, u32)> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let leaders = self.event_process_ids(program, "pids");
            let descendants = self.event_process_ids(program, "descendant.pids");
            if leaders.len() == count && descendants.len() == count {
                return leaders.into_iter().zip(descendants).collect();
            }
            std::thread::sleep(POLL);
        }
        panic!(
            "{program} did not expose {count} process groups within {timeout:?}; leaders={:?}, \
             descendants={:?}",
            self.event_process_ids(program, "pids"),
            self.event_process_ids(program, "descendant.pids")
        );
    }

    pub fn event(&self, program: &str, kind: &str) -> PathBuf {
        self.event_path(program, kind)
    }

    pub fn operator_home(&self) -> &Path {
        self.home.path()
    }

    pub fn trusted_path(&self) -> std::ffi::OsString {
        std::env::join_paths([self.bin.as_path(), Path::new("/usr/bin"), Path::new("/bin")])
            .expect("join the operator PATH")
    }

    pub fn server_executable(&self, executable: &str) -> PathBuf {
        self.bin.join(executable)
    }

    pub fn mcp_working_directory(&self) -> PathBuf {
        self.root().join("private").join("mcp")
    }

    /// The agent's `HOME`: a directory of the fixture's, declared through `[agent] env`.
    pub fn box_home(&self) -> PathBuf {
        self.home.path().join(AGENT_HOME)
    }

    pub fn root(&self) -> PathBuf {
        self.home.path().join("boxes").join(&self.name)
    }

    pub fn live_record(&self) -> PathBuf {
        self.root().join("private").join("live.json")
    }

    pub fn stored_record(&self) -> PathBuf {
        self.root().join("private").join("box.toml")
    }

    pub fn stored_policy(&self) -> PathBuf {
        self.root().join("private").join("policy.dw")
    }

    pub fn workload_path(&self, name: &str) -> PathBuf {
        self.box_home().join(name)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(fixture::box_binary());
        command
            .arg("run")
            .arg("--config")
            .arg(self.workspace.join(".strands-box/box.toml"))
            .current_dir(&self.workspace)
            .env("HOME", self.home.path())
            .env("PATH", self.trusted_path())
            .env(UNRELATED_SENTINEL, "must-not-cross")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn alias_command(&self, program: &str) -> Command {
        let mut command = Command::new(self.root().join("bin").join(program));
        // SAFETY: setrlimit is async-signal-safe and the closure accesses no shared memory.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 256,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }

    fn release_path(&self, program: &str) -> PathBuf {
        self.event_path(program, "release")
    }

    fn event_path(&self, program: &str, kind: &str) -> PathBuf {
        self.control.join(format!("{program}.{kind}"))
    }

    fn event_line_count(&self, program: &str, kind: &str) -> usize {
        std::fs::read_to_string(self.event_path(program, kind))
            .map(|text| text.lines().count())
            .unwrap_or_default()
    }

    fn event_process_ids(&self, program: &str, kind: &str) -> Vec<u32> {
        std::fs::read_to_string(self.event_path(program, kind))
            .map(|text| {
                text.lines()
                    .map(|line| {
                        line.parse().unwrap_or_else(|error| {
                            panic!("parse {program} {kind} process id: {error}")
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct RunningMcpClient {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    received: mpsc::Receiver<Result<Value, String>>,
    output_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

/// One paged `tools/list`, as the client saw it.
#[derive(Debug, Default)]
pub struct ListExchange {
    /// Each page's response, in order; the last may be an error.
    pub pages: Vec<Value>,
    /// Notifications that arrived while paging.
    pub notifications: Vec<Value>,
    /// Server requests that arrived while paging, each answered.
    pub requests: Vec<Value>,
}

impl ListExchange {
    /// The last page's response.
    pub fn last(&self) -> &Value {
        self.pages.last().expect("a list exchange has a page")
    }
}

impl RunningMcpClient {
    pub fn initialize(&mut self, id: Value, timeout: Duration) -> (Value, Value) {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"fixtureClient": true},
                "clientInfo": {"name": "runtime-fixture", "version": "1"},
                "fixtureParameter": "preserved"
            },
            "fixtureTopLevel": "preserved"
        });
        self.send(&request);
        let response = self.receive(timeout);
        (request, response)
    }

    pub fn initialized(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {"fixtureNotification": true}
        }));
    }

    pub fn initialize_and_activate(&mut self, id: Value, timeout: Duration) -> (Value, Value) {
        let exchange = self.initialize(id, timeout);
        self.initialized();
        exchange
    }

    pub fn request_root_list(&mut self, id: Value) {
        self.request_list(id, json!({}));
    }

    pub fn request_list(&mut self, id: Value, params: Value) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": params
        }));
    }

    pub fn list_root(&mut self, id: Value, timeout: Duration) -> Value {
        self.request_root_list(id);
        self.receive(timeout)
    }

    /// Page through one `tools/list` from its first page, answering each server request on the way.
    pub fn list_all(&mut self, first_id: u64, params: Value, timeout: Duration) -> ListExchange {
        let mut exchange = ListExchange::default();
        let mut cursor: Option<String> = None;
        let mut id = first_id;
        loop {
            let mut page_params = params.clone();
            if let Some(cursor) = &cursor {
                page_params
                    .as_object_mut()
                    .expect("list params are an object")
                    .insert("cursor".to_string(), json!(cursor));
            }
            self.request_list(json!(id), page_params);
            let page = loop {
                let frame = self.receive(timeout);
                match (frame.get("method"), frame.get("id")) {
                    (Some(method), Some(request_id)) => {
                        let answer = if method == "ping" {
                            json!({"jsonrpc": "2.0", "id": request_id, "result": {}})
                        } else {
                            json!({
                                "jsonrpc": "2.0",
                                "id": request_id,
                                "error": {"code": -32601, "message": "Method not found"}
                            })
                        };
                        self.send(&answer);
                        exchange.requests.push(frame);
                    }
                    (Some(_), None) => exchange.notifications.push(frame),
                    _ if frame.get("id") == Some(&json!(id)) => break frame,
                    _ => exchange.notifications.push(frame),
                }
            };
            cursor = page
                .pointer("/result/nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            exchange.pages.push(page);
            match cursor {
                Some(_) => id += 1,
                None => return exchange,
            }
        }
    }

    pub fn request_call(&mut self, id: Value, tool: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {"value": "fixture"}
            }
        }));
    }

    pub fn call(&mut self, id: Value, tool: &str, timeout: Duration) -> Value {
        self.request_call(id, tool);
        self.receive(timeout)
    }

    pub fn receive(&mut self, timeout: Duration) -> Value {
        self.receive_result(timeout)
            .unwrap_or_else(|error| panic!("receive an MCP response: {error}"))
    }

    pub fn receive_result(&mut self, timeout: Duration) -> Result<Value, String> {
        self.received
            .recv_timeout(timeout)
            .map_err(|error| format!("wait for MCP client output: {error}"))?
    }

    pub fn assert_running(&mut self) {
        let status = self
            .child
            .as_mut()
            .expect("the MCP alias is present")
            .try_wait()
            .expect("inspect the MCP alias");
        assert!(
            status.is_none(),
            "the MCP alias exited unexpectedly: {status:?}"
        );
    }

    pub fn wait(mut self, timeout: Duration) -> ClientExit {
        self.stdin.take();
        self.wait_for_broker_exit(timeout)
    }

    fn wait_for_broker_exit(mut self, timeout: Duration) -> ClientExit {
        let mut child = self.child.take().expect("the MCP alias is present");
        let status = wait_status_before(&mut child, timeout);
        self.stdin.take();
        self.join_readers();
        ClientExit {
            status,
            stderr: self.stderr_text(),
        }
    }

    pub fn send(&mut self, value: &Value) {
        let stdin = self.stdin.as_mut().expect("the MCP alias stdin is open");
        serde_json::to_writer(&mut *stdin, value).expect("write one MCP frame");
        stdin.write_all(b"\n").expect("terminate one MCP frame");
        stdin.flush().expect("flush one MCP frame");
    }

    fn join_readers(&mut self) {
        if let Some(thread) = self.output_thread.take() {
            thread.join().expect("join the MCP output reader");
        }
        if let Some(thread) = self.stderr_thread.take() {
            thread.join().expect("join the MCP stderr reader");
        }
    }

    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .stderr
                .lock()
                .expect("the MCP stderr capture is not poisoned"),
        )
        .into_owned()
    }
}

impl Drop for RunningMcpClient {
    fn drop(&mut self) {
        self.stdin.take();
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
        self.join_readers();
    }
}

pub struct ClientExit {
    pub status: ExitStatus,
    pub stderr: String,
}

pub struct RunningBox {
    child: Option<Child>,
    home: PathBuf,
    name: String,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
}

impl RunningBox {
    fn new(mut child: Child, home: PathBuf, name: String) -> Self {
        let stdout = CapturedOutput::start(child.stdout.take().expect("the box stdout is piped"));
        let stderr = CapturedOutput::start(child.stderr.take().expect("the box stderr is piped"));
        Self {
            child: Some(child),
            home,
            name,
            stdout,
            stderr,
        }
    }

    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .expect("the run is present")
            .try_wait()
            .expect("inspect strands-box run")
            .is_none()
    }

    pub fn wait_for(&mut self, path: impl AsRef<Path>, timeout: Duration) {
        let path = path.as_ref();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            if self
                .child
                .as_mut()
                .expect("the run is present")
                .try_wait()
                .expect("inspect strands-box run")
                .is_some()
            {
                let child = self.child.take().expect("the run is present");
                let output = output_before(child, timeout, &mut self.stdout, &mut self.stderr);
                panic!(
                    "{} did not appear before strands-box exited; stdout={:?}, stderr={:?}",
                    path.display(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(POLL);
        }
        panic!("{} did not appear within {timeout:?}", path.display());
    }

    pub fn wait(mut self, timeout: Duration) -> Output {
        let child = self.child.take().expect("the run is present");
        output_before(child, timeout, &mut self.stdout, &mut self.stderr)
    }
}

impl Drop for RunningBox {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            // `SIGTERM` lets the box end its workload group; only a box that does not leave in
            // time is killed outright.
            // SAFETY: signalling the child this harness spawned.
            let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && child.try_wait().ok().flatten().is_none() {
                std::thread::sleep(POLL);
            }
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

pub fn wait_for_process_exit(pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_exists(pid) {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("process {pid} remained alive after {timeout:?}");
}

pub fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 checks one numeric process id and sends no signal.
    (unsafe { libc::kill(pid, 0) == 0 })
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn read_pid(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("parse {} as a process id: {error}", path.display()))
}

fn output_before(
    mut child: Child,
    timeout: Duration,
    stdout: &mut CapturedOutput,
    stderr: &mut CapturedOutput,
) -> Output {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child
            .try_wait()
            .expect("inspect the child process")
            .is_some()
        {
            return Output {
                status: child.wait().expect("collect child status"),
                stdout: stdout.finish(),
                stderr: stderr.finish(),
            };
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let output = Output {
        status: child.wait().expect("collect timed-out status"),
        stdout: stdout.finish(),
        stderr: stderr.finish(),
    };
    panic!(
        "process did not exit within {timeout:?}; stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn wait_status_before(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("inspect the MCP alias") {
            return status;
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let status = child.wait().expect("collect the timed-out MCP alias");
    panic!("the MCP alias did not exit within {timeout:?}; status={status}");
}

fn make_fifo(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).expect("FIFO path contains no NUL");
    // SAFETY: `path` is a NUL-terminated string and mode has no invalid bits.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "create the discovery FIFO: {}",
        std::io::Error::last_os_error()
    );
}

fn write_fifo_before(path: &Path, timeout: Duration) {
    let path_bytes = CString::new(path.as_os_str().as_bytes()).expect("FIFO path contains no NUL");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // SAFETY: `path_bytes` is a NUL-terminated string. The returned descriptor is owned here.
        let descriptor =
            unsafe { libc::open(path_bytes.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
        if descriptor >= 0 {
            // SAFETY: `descriptor` is open and becomes owned by this File.
            let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
            file.write_all(b"release\n")
                .expect("write the discovery release");
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENXIO) {
            panic!("open {} for release: {error}", path.display());
        }
        std::thread::sleep(POLL);
    }
    panic!(
        "{} had no discovery reader within {timeout:?}",
        path.display()
    );
}

/// What a tool table grants so the `/usr/bin/python3` stub runs on this Mac.
#[derive(Default)]
struct Toolchain {
    read: Vec<String>,
    developer_dir: Option<String>,
}

/// The selected Command Line Tools, or the installed Command Line Tools with `DEVELOPER_DIR` when a
/// full Xcode is selected.
fn python_toolchain() -> Toolchain {
    if !cfg!(target_os = "macos") {
        return Toolchain::default();
    }
    let Some(selected) = std::process::Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
                .canonicalize()
                .ok()
        })
        .filter(|directory| directory.is_dir())
    else {
        return Toolchain::default();
    };
    let xcode = selected.ancestors().any(|ancestor| {
        ancestor
            .extension()
            .is_some_and(|extension| extension == "app")
    });
    let command_line_tools = Path::new("/Library/Developer/CommandLineTools");
    if xcode && command_line_tools.is_dir() {
        let directory = command_line_tools.display().to_string();
        return Toolchain {
            read: vec![directory.clone()],
            developer_dir: Some(directory),
        };
    }
    Toolchain {
        read: vec![selected.display().to_string()],
        developer_dir: None,
    }
}
