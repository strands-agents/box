//! A created box to run tests against, and the constraints that shape it.
//!
//! Included by each integration suite with `#[path]` rather than shared through a
//! crate, because these are separate test binaries.
//!
//! # Authority is loaded from one explicit configuration
//!
//! Each run receives the same explicit configuration path. [`Request::expect`] requires
//! the preparation run to succeed, and [`Request::attempt`] returns its refusal.
//!
//! # The agent's `command` is a prefix, so a run rewrites it
//!
//! `run -- args` appends to `[agent] command`. A suite that runs `bash` here and `env` there
//! therefore rewrites the `command` line before each run, atomically, and the box re-reads the
//! configuration it names. [`Configured::run`] does the rewrite; [`Configured::command_for`] hands
//! back a prepared `Command` for a suite that spawns several runs of one program at once.
//!
//! # The agent's home is a directory the fixture declares
//!
//! There is no box home: `HOME` is the operator's unless `[agent] env.HOME` says otherwise. The
//! fixture declares one under the operator home, `agent-home`, grants it read and write, and puts
//! `TMPDIR` inside it. A policy body writes `{box_home}` for it, and [`Configured::box_home`]
//! answers with the same path.
//!
//! # The operator home must be short, and `tempfile` is not
//!
//! macOS caps `sun_path` at 103 usable bytes, and a box's socket sits under the operator's home.
//! So the fixture homes live under `/var/tmp`, named by pid and a per-process counter.

#![allow(dead_code)] // Each suite uses a different part of this.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// What a policy body writes where the agent home's host path belongs.
///
/// Substituted by [`Request::with_policy`] and [`Request::with_config`]. A rule that must
/// cover the whole home writes `{box_home}*`, exactly as it would spell any other prefix.
pub const BOX_HOME: &str = "{box_home}";

/// The token an authored policy or script uses for the **workspace** directory.
///
/// The workspace is the interpreters' working directory, so this is what a relative path through an
/// alias resolves against. Named rather than spelled, for the same reason as [`BOX_HOME`]: the
/// path carries the fixture's pid.
pub const PROJECT: &str = "{workspace}";

/// The token a config body uses for this box's own `box_dir`.
///
/// Named rather than spelled for the same reason as [`BOX_HOME`], and here it is not optional: the
/// name carries the fixture's pid, so a hand-spelled path names a **sibling** directory. A telemetry
/// case that did exactly that stopped testing anything once the refusal became per-`box_dir`.
pub const BOX_DIR: &str = "{box_dir}";

/// The directory under the operator home the fixture declares as the agent's `HOME`.
const AGENT_HOME: &str = "agent-home";

/// Where this fixture sites one box's `box_dir`: a directory the fixture owns, under the operator
/// home but **not** under `.strands-box`.
///
/// Box creates no directory above the one `box_dir` names and sites no box itself, so a caller picks
/// the path. Keeping the fixture off the product directory is what lets a suite assert that Box
/// created no `~/.strands-box` at all.
fn box_directory_for(operator_home: &Path, name: &str) -> PathBuf {
    operator_home.join("boxes").join(name)
}

/// The box binary under test.
pub fn box_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_strands-box"))
}

/// `true(1)`, the workload a fixture runs when the test is about something else.
///
/// **The path is not the same on every platform.** macOS ships it only at `/usr/bin/true`, so a
/// hardcoded `/bin/true` made every box refuse with `containment config failed: path does not
/// exist` and every fixture-built suite fail before its own assertions ran.
pub fn no_op_program() -> &'static str {
    ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|candidate| std::path::Path::new(candidate).is_file())
        .expect("this platform ships `true` at neither /usr/bin/true nor /bin/true")
}

/// Where a fixture operator home is created.
///
/// **`/var/tmp`, and deliberately NOT `/tmp`.** Short, because a box's broker socket sits under
/// the home and must fit the platform's `AF_UNIX` path limit. And off `/tmp`, because the Linux view
/// mounts a fresh writable tmpfs at `/tmp`: with the fixture home under it, the whole box root fell
/// inside that tmpfs and `bin/`, `run/`, and `trust/` were writable. The view mounts fresh
/// filesystems at `/`, `/proc`, and `/tmp` only, so `/var/tmp` is not shadowed.
pub const FIXTURE_HOME_PARENT_TEXT: &str = "/var/tmp";

/// A short operator home that cleans itself up, for a suite that wants a `TempDir`'s Drop.
pub fn short_temporary_home() -> tempfile::TempDir {
    let parent = Path::new(FIXTURE_HOME_PARENT_TEXT)
        .canonicalize()
        .expect("the fixture home parent resolves");
    tempfile::Builder::new()
        .prefix("sb")
        .tempdir_in(parent)
        .expect("create a short fixture operator home")
}

fn short_operator_home() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);

    let path = PathBuf::from(FIXTURE_HOME_PARENT_TEXT).join(format!(
        "sb{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create the fixture operator home");
    // Canonical, because the box canonicalizes every root it stores and a suite must name a path in
    // the spelling the box actually granted. On macOS `/var/tmp` reaches `/private/var/tmp` through
    // a symlink.
    path.canonicalize()
        .expect("the fixture operator home resolves")
}

/// The eight `filesystem` lists plus `env` the fixture writes into `[agent]`.
#[derive(Default, Clone)]
struct AgentTable {
    read: Vec<String>,
    write: Vec<String>,
    read_file: Vec<String>,
    write_file: Vec<String>,
    list: Vec<String>,
    metadata: Vec<String>,
    exec: Vec<String>,
    deny: Vec<String>,
    env: Vec<(String, String)>,
}

/// What `run` is about to be asked for, before it is asked.
///
/// Split from [`Configured`] so a suite can assert on a *refusal*: a box the first run
/// rejected stores nothing and runs nothing, so there is no created box to hand back.
pub struct Request {
    operator_home: PathBuf,
    name: String,
    /// The policy text, or empty for a box created with no authority.
    policy: PathBuf,
    /// Extra tables appended after `[agent]`: `[egress.*]`, `[mcp.*]`, `[tool.*]`, `[telemetry.*]`.
    config_body: Option<String>,
    /// What the creating run should see in its environment.
    ///
    /// Carried rather than set on this process: an `env://` locator dereferences in
    /// the *box's* environment, and mutating the harness's own would both leak the
    /// value to every parallel test and make this fixture order-dependent.
    environment: Vec<(String, String)>,
    agent: AgentTable,
    /// Whether the fixture declares an agent home at all.
    with_agent_home: bool,
}

/// A host path as a rule reads it: `~/<relative>` when it is under `home`.
///
/// **A string mapping, deliberately, and it must agree with `ApprovedPath::reported`.**
/// `reported_spelling.rs` compares this against `policy`'s own spelling, so the agreement is
/// checked rather than assumed.
pub fn reported_under_home(path: &str, home: &Path) -> String {
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    match Path::new(path).strip_prefix(&home) {
        Ok(relative) if relative.as_os_str().is_empty() => "~".to_string(),
        Ok(relative) => format!("~/{}", relative.display()),
        Err(_) => path.to_string(),
    }
}

impl Request {
    /// A box whose authority is one policy file.
    ///
    /// Every [`BOX_HOME`] token in `policy_text` becomes the agent home's reported spelling.
    pub fn with_policy(name: &str, policy_text: &str) -> Self {
        let mut request = Self::with_nothing(name);
        let policy = request.operator_home.join("policy.dw");
        std::fs::write(&policy, request.resolve_tokens(policy_text)).expect("write the policy");
        request.policy = policy;
        request
    }

    /// The agent home's host path.
    fn agent_home_text(&self) -> String {
        self.operator_home.join(AGENT_HOME).display().to_string()
    }

    /// The workspace this fixture writes `.strands-box/` into, as `attempt` sites it.
    fn project_text(&self) -> String {
        let workspace = self.operator_home.join("workspace");
        workspace
            .canonicalize()
            .unwrap_or(workspace)
            .display()
            .to_string()
    }

    /// Substitute every fixture token in an authored **policy** body.
    ///
    /// **A policy reads the REPORTED spelling, which is `~/<relative>`.** The interpreters abbreviate
    /// every path under the operator home before the decision, so a rule checked into a repository
    /// holds in every clone.
    fn resolve_tokens(&self, text: &str) -> String {
        text.replace(BOX_HOME, &self.reported(&self.agent_home_text()))
            .replace(PROJECT, &self.reported(&self.project_text()))
    }

    /// A host path as a rule reads it, against this fixture's operator home.
    fn reported(&self, path: &str) -> String {
        reported_under_home(path, &self.operator_home)
    }

    /// A box whose authority is a config file, with `config_body` appended after the `[agent]`
    /// table. The body holds whole tables: `[egress.<name>]`, `[mcp.<name>]`, `[tool.<name>]`,
    /// `[telemetry.<name>]`. The agent reaches every table it declares.
    ///
    /// The config's `policy` key is deliberately **relative**, so a passing test
    /// proves the box resolves it beside the config file rather than against whatever
    /// directory the harness happened to run from.
    pub fn with_config(name: &str, policy_text: &str, config_body: &str) -> Self {
        let mut request = Self::with_policy(name, policy_text);
        request.config_body = Some(request.resolve_host_tokens(config_body));
        request
    }

    /// A box created with a config file that names no policy at all.
    pub fn with_config_only(name: &str, config_body: &str) -> Self {
        let mut request = Self::with_nothing(name);
        request.config_body = Some(request.resolve_host_tokens(config_body));
        request
    }

    /// Substitute the fixture tokens in a **config** body with host paths, which is what a
    /// `filesystem` entry or a telemetry destination names.
    fn resolve_host_tokens(&self, text: &str) -> String {
        text.replace(BOX_HOME, &self.agent_home_text())
            .replace(PROJECT, &self.project_text())
            .replace(BOX_DIR, &self.box_directory_text())
    }

    /// This box's own `box_dir`, as `attempt` sites it.
    fn box_directory_text(&self) -> String {
        box_directory_for(&self.operator_home, &self.name)
            .display()
            .to_string()
    }

    /// A box with no authored authority at all: default-deny, nothing declared.
    pub fn with_nothing(name: &str) -> Self {
        Self {
            operator_home: short_operator_home(),
            // Suffixed with the pid because a box persists by design: a fixed name
            // would carry state between runs of a suite, so a test asserting some
            // file is *absent* would fail on what a previous run left behind.
            name: format!("{name}-{}", std::process::id()),
            policy: PathBuf::new(),
            config_body: None,
            environment: Vec::new(),
            agent: AgentTable::default(),
            with_agent_home: true,
        }
    }

    /// Add `[agent.filesystem] read` trees, as host paths.
    pub fn agent_read(mut self, paths: &[&Path]) -> Self {
        self.agent
            .read
            .extend(paths.iter().map(|path| path.display().to_string()));
        self
    }

    /// Add `[agent.filesystem] write` trees, as host paths.
    pub fn agent_write(mut self, paths: &[&Path]) -> Self {
        self.agent
            .write
            .extend(paths.iter().map(|path| path.display().to_string()));
        self
    }

    /// Add one `[agent.filesystem]` list by key, with the fixture tokens resolved to host paths.
    pub fn agent_list(mut self, key: &str, entries: &[&str]) -> Self {
        let entries: Vec<String> = entries
            .iter()
            .map(|entry| self.resolve_host_tokens(entry))
            .collect();
        match key {
            "read" => self.agent.read.extend(entries),
            "write" => self.agent.write.extend(entries),
            "read_file" => self.agent.read_file.extend(entries),
            "write_file" => self.agent.write_file.extend(entries),
            "list" => self.agent.list.extend(entries),
            "metadata" => self.agent.metadata.extend(entries),
            "exec" => self.agent.exec.extend(entries),
            "deny" => self.agent.deny.extend(entries),
            other => panic!("{other} is not a filesystem list"),
        }
        self
    }

    /// Add one `[agent] env` variable.
    pub fn agent_env(mut self, name: &str, value: &str) -> Self {
        self.agent
            .env
            .push((name.to_string(), self.resolve_host_tokens(value)));
        self
    }

    /// Declare no agent home: `HOME` is the operator's, and nothing under it is granted.
    pub fn without_agent_home(mut self) -> Self {
        self.with_agent_home = false;
        self
    }

    /// The operator home, so a test can plant a file the run will read.
    pub fn operator_home(&self) -> &Path {
        &self.operator_home
    }

    /// Set a variable in the environment the creating run runs with.
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.environment.push((name.to_string(), value.to_string()));
        self
    }

    /// The configuration text with `{command}` where the `command` array belongs.
    fn template(&self, root: &Path, workspace: &Path) -> String {
        let quoted = |value: &str| toml::Value::String(value.to_string()).to_string();
        let mut toml = format!(
            "name = {}\nbox_dir = {}\n",
            quoted(&self.name),
            quoted(&root.display().to_string())
        );
        if !self.policy.as_os_str().is_empty() {
            toml.push_str("policy = \"policy.dw\"\n");
        }
        toml.push_str(&format!(
            "\n[agent]\ncommand = {{command}}\nworkspace = {}\n",
            quoted(&workspace.display().to_string())
        ));

        let mut env: Vec<(String, String)> = Vec::new();
        let mut table = self.agent.clone();
        if self.with_agent_home {
            let home = self.agent_home_text();
            env.push(("HOME".to_string(), home.clone()));
            env.push(("TMPDIR".to_string(), format!("{home}/.tmp")));
            table.read.insert(0, home.clone());
            table.write.insert(0, home);
        }
        env.extend(table.env.iter().cloned());
        if !env.is_empty() {
            let pairs: Vec<String> = env
                .iter()
                .map(|(name, value)| format!("{name} = {}", quoted(value)))
                .collect();
            toml.push_str(&format!("env = {{ {} }}\n", pairs.join(", ")));
        }
        let lists: [(&str, &[String]); 8] = [
            ("read", &table.read),
            ("write", &table.write),
            ("read_file", &table.read_file),
            ("write_file", &table.write_file),
            ("list", &table.list),
            ("metadata", &table.metadata),
            ("exec", &table.exec),
            ("deny", &table.deny),
        ];
        if lists.iter().any(|(_, entries)| !entries.is_empty()) {
            toml.push_str("\n[agent.filesystem]\n");
            for (key, entries) in lists {
                if entries.is_empty() {
                    continue;
                }
                let items: Vec<String> = entries.iter().map(|entry| quoted(entry)).collect();
                toml.push_str(&format!("{key} = [{}]\n", items.join(", ")));
            }
        }
        if let Some(body) = &self.config_body {
            toml.push('\n');
            toml.push_str(body);
        }
        toml
    }

    /// Create the box the way an operator does, a first `run` in a workspace, and answer with that
    /// run's output whether it succeeded or not.
    ///
    /// This writes `<workspace>/.strands-box/box.toml` and `policy.dw`, then runs `strands-box run`
    /// from the workspace with a no-op workload. A refusal an invalid configuration earns surfaces
    /// on this run.
    pub fn attempt(self) -> (Configured, Output) {
        let workspace = self.operator_home.join("workspace");
        let dot = workspace.join(".strands-box");
        std::fs::create_dir_all(&dot).expect("the workspace's .strands-box directory");
        if self.with_agent_home {
            let home = self.operator_home.join(AGENT_HOME);
            std::fs::create_dir_all(home.join(".tmp")).expect("the agent home and its scratch");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
                    .expect("make the agent home private");
            }
        }

        // The policy the operator authored, beside the config, exactly as `run` expects.
        if !self.policy.as_os_str().is_empty() {
            let text = std::fs::read_to_string(&self.policy).unwrap_or_default();
            std::fs::write(dot.join("policy.dw"), text).expect("write the workspace policy");
        }

        let root = box_directory_for(&self.operator_home, &self.name);
        std::fs::create_dir_all(
            root.parent()
                .expect("the fixture box directory has a parent"),
        )
        .expect("create the box directory's parent");
        std::fs::create_dir(&root).expect("create the empty caller-owned box directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("make the box directory private");
        }

        let config = dot.join("box.toml");
        let canonical_workspace = workspace
            .canonicalize()
            .expect("the fixture workspace resolves");
        let template = self.template(&root, &canonical_workspace);
        let configured = Configured {
            operator_home: self.operator_home,
            name: self.name,
            config,
            template,
            environment: self.environment,
        };
        configured.write_command(no_op_program());

        let mut command = configured.run_command();
        command.current_dir(&workspace);
        let output = command.output().expect("spawn strands-box run");

        // Leave the box created-but-UNLOADED. The creating run loaded it (it ran `true(1)`); a
        // test that then asserts `rm`/`reset`/`ls` behaviour expects an unloaded box, and a test
        // that runs a workload reloads on demand.
        if output.status.success() {
            let _ = Command::new(box_binary())
                .args(["stop", "--name", &configured.name])
                .env("HOME", &configured.operator_home)
                .output();
        }
        (configured, output)
    }

    /// Create the box and require the creating run to have succeeded.
    pub fn expect(self) -> Configured {
        let (configured, output) = self.attempt();
        assert!(
            output.status.success(),
            "the creating run must succeed for this test to mean anything: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        configured
    }
}

/// A created box.
pub struct Configured {
    operator_home: PathBuf,
    name: String,
    config: PathBuf,
    /// The configuration with `{command}` where the `command` array belongs.
    template: String,
    environment: Vec<(String, String)>,
}

impl Configured {
    /// The box's name, as the fixture chose it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The operator's home for this fixture.
    pub fn operator_home(&self) -> &Path {
        &self.operator_home
    }

    /// The complete configuration that every run of this fixture receives.
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// The box root, for asserting on what a run left on the host.
    pub fn root(&self) -> PathBuf {
        let root = box_directory_for(&self.operator_home, &self.name);
        root.canonicalize().unwrap_or(root)
    }

    /// The agent's declared `HOME`, canonical because the agent's own `HOME` is.
    pub fn box_home(&self) -> PathBuf {
        let home = self.operator_home.join(AGENT_HOME);
        home.canonicalize().unwrap_or(home)
    }

    /// The workspace directory, which is the **interpreters'** working directory.
    pub fn workspace(&self) -> PathBuf {
        let workspace = self.operator_home.join("workspace");
        workspace.canonicalize().unwrap_or(workspace)
    }

    /// Rewrite the configuration so `[agent] command` names `program`, atomically.
    pub fn write_command(&self, program: &str) {
        let command = toml::Value::Array(vec![toml::Value::String(program.to_string())]);
        let text = self.template.replace("{command}", &command.to_string());
        if std::fs::read_to_string(&self.config).ok().as_deref() == Some(text.as_str()) {
            return;
        }
        let staged = self.config.with_extension("toml.staged");
        std::fs::write(&staged, text).expect("stage the configuration");
        std::fs::rename(&staged, &self.config).expect("install the configuration");
    }

    /// A `strands-box run --config <this box> --` command with the fixture's environment, ready for
    /// the arguments that follow `[agent] command`.
    fn run_command(&self) -> Command {
        let mut command = Command::new(box_binary());
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            .arg("--");
        // The same environment the creating run saw, so a test cannot accidentally pass
        // because a secret was present at create time and absent at run time.
        for (name, value) in &self.environment {
            command.env(name, value);
        }
        command.env("HOME", &self.operator_home);
        command
    }

    /// A prepared `run` of `program`, for a suite that appends its own arguments or spawns several
    /// runs of one program at once.
    pub fn command_for(&self, program: &str) -> Command {
        self.write_command(program);
        self.run_command()
    }

    /// Run one workload: element 0 becomes `[agent] command`, and the rest follow `--`.
    pub fn run<S: AsRef<std::ffi::OsStr>>(&self, argv: &[S]) -> Output {
        let (program, arguments) = argv.split_first().expect("a workload names a program");
        let program = program
            .as_ref()
            .to_str()
            .expect("the fixture's programs are UTF-8");
        let mut command = self.command_for(program);
        for argument in arguments {
            command.arg(argument);
        }
        command.output().expect("spawn strands-box run")
    }

    /// Run `script` as the contained workload, through the host's real `bash`.
    ///
    /// Not `/bin/sh`: on macOS that is a multiplexer which consults
    /// `/private/var/select/sh` to pick its variant, and the profile grants exec on
    /// exactly the literals the box named, so it cannot start at all.
    ///
    /// Every [`BOX_HOME`] token in `script` becomes the agent home's host path, and `$BOX_HOME`
    /// is exported for scripts built with `format!`.
    pub fn bash(&self, script: &str) -> Output {
        let script = script
            .replace(BOX_HOME, &self.box_home().display().to_string())
            .replace(PROJECT, &self.workspace().display().to_string());
        let script = format!(
            "BOX_HOME={}; export BOX_HOME; {script}",
            self.box_home().display()
        );
        self.run(&["/bin/bash", "-c", &script])
    }
}

/// Remove the fixture, which is the whole teardown now.
///
/// This called `stop` first, because a box outlived its runs and removing the tree under a live one
/// would leave it running with no filesystem to serve from. There is no `stop` verb, and none is
/// needed: every run this fixture starts is waited to completion, so no run is live here, and the
/// kernel has already released the ownership lock. A suite that spawns runs through
/// [`Configured::command_for`] waits for them itself.
impl Drop for Configured {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.operator_home);
    }
}

/// Whether the backend this box actually runs on can express **execute without read**.
///
/// On Linux the answer is `false` for every host that can run a box: the namespace launcher cannot
/// subtract read from a bind, and the workload runs as the same uid as the box. Off Linux the
/// answer is `true`: Seatbelt renders one `process-exec` literal and its paired
/// `file-read-metadata`, never `file-read*`.
pub fn execute_without_read_is_expressible() -> bool {
    if cfg!(target_os = "linux") {
        return false;
    }
    true
}

/// Whether this host can run the Linux namespace launcher. Always `true` off Linux.
#[cfg(not(target_os = "linux"))]
pub fn namespace_launcher_is_usable() -> bool {
    true
}

/// Whether this host can run the Linux namespace launcher.
///
/// A build host can permit user namespaces and still refuse a nested procfs, which failed every
/// box-spawning test on such a host. A test that cannot construct a box measures nothing, so it
/// **skips loudly** rather than failing. It probes the exact operation that fails, in a forked
/// reaper the way the real launcher does.
#[cfg(target_os = "linux")]
pub fn namespace_launcher_is_usable() -> bool {
    // The box selects the namespace backend only on aarch64 and refuses every other Linux
    // architecture by name, so no box runs on x86_64 whatever the kernel permits.
    if !cfg!(target_arch = "aarch64") {
        return false;
    }
    use std::sync::OnceLock;
    static USABLE: OnceLock<bool> = OnceLock::new();
    *USABLE.get_or_init(|| {
        // SAFETY: the child only makes syscalls and `_exit`s.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return true; // cannot probe; let the test run and report its own failure
        }
        if child == 0 {
            // SAFETY: syscall-only child.
            unsafe {
                let namespaces = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
                if libc::unshare(namespaces) != 0 {
                    libc::_exit(10);
                }
                let inner = libc::fork();
                if inner < 0 {
                    libc::_exit(12);
                }
                if inner == 0 {
                    let fstype = c"proc".as_ptr();
                    let target = c"/proc".as_ptr();
                    if libc::mount(fstype, target, fstype, 0, std::ptr::null()) != 0 {
                        libc::_exit(11);
                    }
                    libc::_exit(0);
                }
                let mut inner_status = 0;
                libc::waitpid(inner, &mut inner_status, 0);
                let ok = libc::WIFEXITED(inner_status) && libc::WEXITSTATUS(inner_status) == 0;
                libc::_exit(if ok { 0 } else { 11 });
            }
        }
        let mut status = 0;
        // SAFETY: waiting on this process's own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        let usable = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        if !usable {
            println!(
                "skipping: this host cannot run the namespace launcher (unshare or a nested \
                 procfs mount is refused); a box cannot be constructed here"
            );
        }
        usable
    })
}
