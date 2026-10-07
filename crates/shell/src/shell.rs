// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

//! Builder-based API for creating and running sandboxed shells.
//!
//! This is the primary public interface for the crate. Start with
//! [`Shell::builder()`] to configure a shell, then call [`Shell::run()`]
//! or [`Shell::execute()`] to run commands.
//!
//! See the [crate-level documentation](crate) for a full overview.

use std::io;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::effect::EffectInterceptor;
use crate::exec;
#[cfg(not(target_arch = "wasm32"))]
use crate::mcp_client::{McpConfigEntry, NamedMcpClient};
use crate::mediate::Mediated;
use crate::os::{Kernel, OpenFlags, Process};
use crate::vfs_config::{BindEntry, BindMode, VfsConfig, build_vfs};
use crate::vfs_kernel::{EgressProxy, VfsKernel};

// The `shell:run` denial and interceptor-failure statuses moved to `exec.rs` with the
// admission point. They are not duplicated here: two spellings of "denied"
// would drift, and this module no longer produces either.

/// Structured output from a shell command execution.
///
/// Returned by [`Shell::run()`], which captures both stdout and stderr.
///
/// ```rust,no_run
/// # async fn example() -> std::io::Result<()> {
/// # let mut shell = strands_shell::Shell::builder().build()?;
/// let output = shell.run("echo hello && echo oops >&2").await;
/// assert_eq!(output.status, 0);
/// assert_eq!(output.stdout.trim(), "hello");
/// assert_eq!(output.stderr.trim(), "oops");
/// # Ok(())
/// # }
/// ```
pub struct Output {
    /// Exit code of the command (0 = success).
    pub status: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// Metadata about a single VFS entry returned by [`Shell::list_files()`].
///
/// Mirrors the `FileInfo` shape used by the Strands `Sandbox` ABC and by
/// the `strands_shell` Python and `@strands-agents/shell` Node bindings, so adapter
/// code at the binding layer is a `From` conversion away.
///
/// `FileInfo` is `#[non_exhaustive]` so future kernels can carry richer
/// metadata (e.g. `mtime`) without breaking external callers' pattern
/// matches or struct literals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FileInfo {
    /// Basename of the entry — no leading path.
    pub name: String,
    /// `Some(true)` for directories, `Some(false)` for files. `None` is
    /// part of the type because the bindings expose it as optional — Python
    /// (`is_dir: bool | None`) and JS (`isDir?: boolean`, i.e. `undefined`
    /// when unknown, matching the sandbox-provider contract). In practice
    /// today it is always `Some(_)`.
    pub is_dir: Option<bool>,
    /// Size in bytes for files, `None` for directories.
    pub size: Option<u64>,
}

/// A read-only snapshot of how a [`Shell`] was configured.
///
/// Captured at [`build()`](ShellBuilder::build) time and returned by
/// [`Shell::config()`]. This exists so an embedder (for example a sandbox
/// adapter in another SDK) can introspect a constructed `Shell` after the
/// fact — to build tool descriptions or report the active resource caps —
/// without having held onto the builder.
///
/// `#[non_exhaustive]` so future fields can be added without breaking callers
/// who construct or pattern-match exhaustively.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ShellConfig {
    /// Bind mounts mapping host paths into the VFS, in declaration order.
    pub binds: Vec<BindInfo>,
    /// Whether the kernel may dispatch network requests.
    pub network_enabled: bool,
    /// Environment variables seeded into the shell, in declaration order.
    pub env: Vec<(String, String)>,
    /// File-creation umask.
    pub umask: u32,
    /// Per-command wall-clock timeout in seconds, or `None` for no timeout.
    pub timeout_secs: Option<f64>,
    /// Active resource caps.
    pub limits: LimitsInfo,
}

/// A single bind mount in a [`ShellConfig`] snapshot.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BindInfo {
    /// Host path that was mounted.
    pub source: String,
    /// Destination path inside the VFS.
    pub destination: String,
    /// `"copy"` (build-time snapshot) or `"direct"` (host passthrough).
    pub mode: &'static str,
    /// Whether writes through this mount are rejected.
    pub readonly: bool,
}

/// The resource caps active on a [`Shell`], as reported in a
/// [`ShellConfig`] snapshot.
///
/// Unlike [`crate::os::ProcessLimits`] (process-only), this view also carries
/// the two VFS-level caps (`max_file_size`, `max_inodes`) so the snapshot
/// reflects every limit the builder applied in one place.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct LimitsInfo {
    /// Max recursion depth for functions/subshells.
    pub max_depth: u32,
    /// Max size in bytes for any single output accumulation.
    pub max_output: usize,
    /// Max open file descriptors per process.
    pub max_fds: usize,
    /// Max concurrent background jobs.
    pub max_bg_jobs: usize,
    /// Max stages in a single pipeline.
    pub max_pipeline: usize,
    /// Max input size in bytes the parser will accept.
    pub max_input: usize,
    /// Max size in bytes for any single file in the VFS.
    pub max_file_size: usize,
    /// Max inodes (files + directories) in the VFS.
    pub max_inodes: usize,
}

impl Default for LimitsInfo {
    /// Matches [`ShellBuilder::default`]'s caps, so a [`Shell`] built without
    /// touching the limit setters reports these values.
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_output: 1024 * 1024,
            max_fds: 128,
            max_bg_jobs: 8,
            max_pipeline: 16,
            max_input: 1024 * 1024,
            max_file_size: 10 * 1024 * 1024,
            max_inodes: 10_000,
        }
    }
}

impl Default for ShellConfig {
    /// An empty snapshot with default umask, no timeout, and default caps.
    fn default() -> Self {
        Self {
            binds: Vec::new(),
            network_enabled: true,
            env: Vec::new(),
            umask: 0o022,
            timeout_secs: None,
            limits: LimitsInfo::default(),
        }
    }
}

/// Classification of a file-op `io::Error` into the categories the language
/// bindings surface as typed errors.
///
/// The kernel reports failures as [`io::Error`] values: most carry a precise
/// [`io::ErrorKind`] (`NotFound`, `PermissionDenied`), but the size/inode caps
/// use `ErrorKind::Other` with a diagnostic message. This enum is the single
/// place that classification logic lives, so the Python and JS bindings stay
/// in lockstep (`FileNotFoundError` / `NotFoundError`, `PermissionDeniedError`,
/// `FileTooLargeError`, and a generic base for everything else).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOpErrorKind {
    /// Path missing — `io::ErrorKind::NotFound`.
    NotFound,
    /// Read-only mount or otherwise blocked — `io::ErrorKind::PermissionDenied`.
    PermissionDenied,
    /// `max_file_size` / `max_inodes` cap (on write or read), or a write that
    /// did not commit its full length.
    TooLarge,
    /// Anything else (not-a-directory, parent-is-a-file, host I/O, …).
    Other,
}

impl FileOpErrorKind {
    /// Classify a file-op `io::Error`. Pure and side-effect free so both
    /// bindings can call it on the error the core returns.
    pub fn classify(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => {
                // Size/inode caps surface as ErrorKind::Other with a known
                // message; match on the substrings the kernel emits.
                let msg = err.to_string();
                if msg.contains("file size limit")
                    || msg.contains("inode limit")
                    || msg.contains("write did not commit")
                {
                    Self::TooLarge
                } else {
                    Self::Other
                }
            }
        }
    }
}

/// A sandboxed shell environment.
///
/// `Shell` is the main entry point for running commands. Create one with
/// [`Shell::builder()`], then use [`run()`](Shell::run) to capture output
/// or [`execute()`](Shell::execute) for pass-through execution.
///
/// The shell maintains persistent state between commands — environment
/// variables, the current directory, and shell functions all carry over,
/// just like an interactive session.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust,no_run
/// # async fn example() -> std::io::Result<()> {
/// use strands_shell::Shell;
///
/// let mut shell = Shell::builder().build()?;
///
/// // Commands share state
/// shell.run("cd /tmp").await;
/// shell.run("X=42").await;
/// let output = shell.run("echo $X from $PWD").await;
/// assert_eq!(output.stdout.trim(), "42 from /tmp");
/// # Ok(())
/// # }
/// ```
///
/// Sandboxed with bind mounts and limits:
///
/// ```rust,no_run
/// # async fn example() -> std::io::Result<()> {
/// use std::time::Duration;
/// use strands_shell::Shell;
///
/// let mut shell = Shell::builder()
///     .bind("/home/user/project", "/workspace")
///     .timeout(Duration::from_secs(30))
///     .max_depth(64)
///     .build()?;
///
/// let output = shell.run("grep -rn TODO /workspace").await;
/// println!("{}", output.stdout);
/// # Ok(())
/// # }
/// ```
pub struct Shell {
    // The interceptor is NOT stored here. `Mediated` owns it — `build` hands
    // it over — and `exec::execute` reaches it through `kernel`. A second copy on `Shell`
    // was what let this type admit commands on a path four other routes did not take; one
    // owner means one admission point.
    kernel: Arc<Mediated>,
    /// The shell process state.
    ///
    /// Exposed for advanced use cases that need direct access to the
    /// process, such as interactive REPLs using
    /// [`exec::execute_with_reader()`](crate::exec::execute_with_reader).
    /// Most users should use [`run()`](Shell::run) or
    /// [`execute()`](Shell::execute) instead.
    pub proc: Process,
    /// Configured per-command timeout. Used to refresh `proc.deadline`
    /// on every `run()` / `execute()` call so that idle time between
    /// commands does not eat into the per-command budget.
    timeout: Option<Duration>,
    /// `max_file_size` cap (bytes) applied to `read_file`, so a read can
    /// never pull more into memory than a write is allowed to commit.
    /// `0` means no cap. Mirrors the kernel's write-side `max_file_size`.
    max_file_size: usize,
    /// Read-only snapshot of the configuration this shell was built with.
    /// Captured at build time so embedders can introspect a constructed
    /// shell (see [`Shell::config`]). Never carries secret values.
    config: ShellConfig,
    #[cfg(not(target_arch = "wasm32"))]
    mcp_clients: Rc<Vec<NamedMcpClient>>,
    #[cfg(not(target_arch = "wasm32"))]
    mcp_config: Vec<McpConfigEntry>,
}

impl Shell {
    /// Create a new [`ShellBuilder`] for configuring a shell.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> std::io::Result<()> {
    /// let mut shell = strands_shell::Shell::builder()
    ///     .bind("/host/path", "/vfs/path")
    ///     .env("MY_VAR", "my_value")
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> ShellBuilder {
        ShellBuilder::default()
    }

    /// Refresh `proc.deadline` to `now + timeout` so the per-command
    /// budget starts fresh on each `run()` / `execute()`.
    fn refresh_deadline(&mut self) {
        if let Some(dur) = self.timeout {
            #[cfg(not(target_arch = "wasm32"))]
            {
                self.proc.deadline = Some(tokio::time::Instant::now() + dur);
            }
            #[cfg(target_arch = "wasm32")]
            {
                self.proc.deadline = Some(std::time::Instant::now() + dur);
            }
        }
    }

    // `intercept_shell_command` and `finish_shell_command` were deleted here, not moved.
    // They admitted only the two entry points a caller reaches from outside
    // the crate, which is why Lua's `io.popen`, `os.execute`, `find -exec`, and `xargs`
    // — all of which re-enter `exec::execute` from *inside* — ran unjudged. The equivalents
    // now live beside the funnel as `Mediated::admit_command` and `CommandPermit::record`.
    //
    // Do not reintroduce an admission call in this module. It would double-count every
    // submission, and a policy counting `shell:run` would see two events for one command.

    /// Run a command and capture its output.
    ///
    /// Both stdout and stderr are captured into the returned [`Output`].
    /// Nothing is printed to the real terminal. The shell's state
    /// (environment, cwd, functions) persists after the call.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> std::io::Result<()> {
    /// # let mut shell = strands_shell::Shell::builder().build()?;
    /// let output = shell.run("echo hello | tr a-z A-Z").await;
    /// assert_eq!(output.status, 0);
    /// assert_eq!(output.stdout.trim(), "HELLO");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(&mut self, input: &str) -> Output {
        // Admission is NOT here. `exec::execute` — which `execute_capture`
        // delegates to — is the one function every command-text route reaches, so judging
        // there covers Lua's `io.popen`/`os.execute`, `find -exec`, and `xargs`, which
        // bypassed this method entirely. Re-adding a check here would emit two
        // `shell:run` events for one submission, which is worse than none for a policy
        // that counts them.
        self.refresh_deadline();
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start_mcp().await;
            crate::io::set_mcp_clients(self.mcp_clients.clone());
        }
        let (status, stdout, stderr) =
            exec::execute_capture(self.kernel.clone(), &mut self.proc, input).await;
        Output {
            status,
            stdout,
            stderr,
        }
    }

    /// Execute a command, returning just the exit code.
    ///
    /// Unlike [`run()`](Shell::run), stdout and stderr are **not**
    /// captured — they flow to the real file descriptors. Use this for
    /// interactive or streaming output.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> std::io::Result<()> {
    /// # let mut shell = strands_shell::Shell::builder().build()?;
    /// let status = shell.execute("ls -la /").await;
    /// // Output was printed directly to the terminal
    /// assert_eq!(status, 0);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn execute(&mut self, input: &str) -> i32 {
        // Admission is in `exec::execute` — see the note on `run`.
        self.refresh_deadline();
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start_mcp().await;
            crate::io::set_mcp_clients(self.mcp_clients.clone());
        }
        let (code, _) = exec::execute(self.kernel.clone(), &mut self.proc, input).await;
        code
    }

    /// Set an environment variable in the shell.
    ///
    /// This is equivalent to running `export KEY=VALUE` inside the shell.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.proc.set_env(key, value);
    }

    /// Get an environment variable from the shell.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.proc.get_env(key)
    }

    /// The mediating kernel handle.
    ///
    /// Yields [`Mediated`], never a bare `Arc<dyn Kernel>`: an accessor returning the
    /// raw trait would be a route around admission, which is the hole this seam
    /// closes. Consumers that need a kernel — the MCP server, the REPL — get the
    /// mediated handle and are governed by the configured interceptor.
    pub fn kernel(&self) -> &Arc<Mediated> {
        &self.kernel
    }

    /// Get the configured resource limits for this shell.
    ///
    /// Useful for passing limits to [`mcp::serve()`](crate::mcp::serve)
    /// so per-request processes inherit the same limits.
    pub fn limits(&self) -> crate::os::ProcessLimits {
        self.proc.limits()
    }

    /// Get a read-only snapshot of the configuration this shell was built
    /// with.
    ///
    /// The snapshot is captured at [`build()`](ShellBuilder::build) time and
    /// reports bind mounts, seeded environment variables, umask, timeout, and
    /// resource caps. It exists so an embedder (e.g. a sandbox adapter in
    /// another SDK) can introspect a constructed `Shell` without having held
    /// onto the builder — to build tool descriptions or report active limits.
    pub fn config(&self) -> &ShellConfig {
        &self.config
    }

    /// Read a file from the virtual filesystem as raw bytes.
    ///
    /// Subject to the per-`Shell` `max_file_size` limit set on the builder,
    /// so a read can never pull more into memory than a write may commit.
    ///
    /// # Errors
    ///
    /// Returns `Err(io::Error)` if the path is missing, points to a
    /// directory, or the read exceeds `max_file_size`. The error message
    /// is prefixed with the path: `"{path}: {kernel diagnostic}"`.
    ///
    /// # Panics
    ///
    /// Must be called inside `LocalSet::run_until(...)` on a current-thread
    /// Tokio runtime; the underlying VFS uses `tokio::task::spawn_local`
    /// for its drain task and panics outside that context.
    pub async fn read_file(&mut self, path: &str) -> io::Result<Vec<u8>> {
        async fn inner(
            kernel: &Arc<Mediated>,
            proc: &mut Process,
            path: &str,
            limit: usize,
        ) -> io::Result<Vec<u8>> {
            let fd = kernel.open(proc, path, OpenFlags::read()).await?;
            let mut reader = proc.take_reader(fd)?;
            // Bound the read by max_file_size so a read can never pull more
            // into memory than a write is allowed to commit — and so a
            // direct-passthrough mount can't surface an arbitrarily large
            // host file. A limit of 0 means "no cap" (see read_to_end_limited).
            // The limit-exceeded message classifies as TooLarge.
            crate::os::read_to_end_limited(&mut reader, limit)
                .await
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::Other
                        && e.to_string().contains("output size limit")
                    {
                        io::Error::other("file size limit exceeded")
                    } else {
                        e
                    }
                })
        }
        let limit = self.max_file_size;
        inner(&self.kernel, &mut self.proc, path, limit)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))
    }

    /// Write raw bytes to a file in the virtual filesystem.
    ///
    /// Creates missing parent directories (mkdir -p semantics) and
    /// truncates any existing file. Empty payloads (`b""`) produce a
    /// zero-byte file. Waits for the kernel's drain task to commit the
    /// write before returning.
    ///
    /// # Errors
    ///
    /// Returns `Err(io::Error)` if the parent path is a file, the mount
    /// is read-only, the write exceeds `max_file_size`, the VFS exceeds
    /// `max_inodes`, or the write did not commit its full length. The error message is
    /// prefixed with the path: `"{path}: {kernel diagnostic}"`.
    ///
    /// # Panics
    ///
    /// Must be called inside `LocalSet::run_until(...)` on a current-thread
    /// Tokio runtime.
    pub async fn write_file(&mut self, path: &str, content: &[u8]) -> io::Result<()> {
        let kernel = &self.kernel;
        let proc = &mut self.proc;
        let expected = content.len() as u64;
        let result: io::Result<()> = async {
            if let Some(parent) = parent_dir(path) {
                create_dir_recursive(kernel.as_ref(), proc, &parent).await?;
            }
            let fd = kernel.open(proc, path, OpenFlags::write()).await?;
            {
                // Scope the writer so it is dropped (closing the channel)
                // before we wait for the kernel's background drain task.
                let mut writer = proc.take_writer(fd)?;
                writer.write_all(content).await?;
                writer.shutdown().await?;
            }
            if let Some(failure) = kernel.settle_writes().await.into_iter().next() {
                return Err(failure.error);
            }
            let s = kernel.stat(proc, path).await;
            if s.exists && s.len == expected {
                Ok(())
            } else {
                Err(io::Error::other(
                    "write did not commit (file size limit exceeded?)",
                ))
            }
        }
        .await;
        result.map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))
    }

    /// Remove a file from the virtual filesystem.
    ///
    /// Errors if the path is a directory or does not exist. Use
    /// `shell.run("rm -rf ...")` for recursive directory removal.
    ///
    /// # Errors
    ///
    /// Returns `Err(io::Error)` prefixed with `"{path}: ..."`.
    pub async fn remove_file(&mut self, path: &str) -> io::Result<()> {
        self.kernel
            .remove_file(&self.proc, path)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))
    }

    /// List the entries in a directory.
    ///
    /// `FileInfo.name` is the basename only — `"x.txt"`, never
    /// `"/work/x.txt"`. `FileInfo.size` is `None` for directories,
    /// `Some(bytes)` for files.
    ///
    /// # Errors
    ///
    /// Returns `Err(io::Error)` prefixed with `"{path}: ..."` if the
    /// path is missing or not a directory.
    pub async fn list_files(&mut self, path: &str) -> io::Result<Vec<FileInfo>> {
        let entries = self
            .kernel
            .list_dir(&self.proc, path)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;

        let base = if path.ends_with('/') {
            path.trim_end_matches('/').to_string()
        } else {
            path.to_string()
        };

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let child = if base.is_empty() || base == "/" {
                format!("/{}", e.name)
            } else {
                format!("{}/{}", base, e.name)
            };
            let stat = self.kernel.stat(&self.proc, &child).await;
            let size = if stat.exists && !e.is_dir {
                Some(stat.len)
            } else {
                None
            };
            out.push(FileInfo {
                name: e.name,
                is_dir: Some(e.is_dir),
                size,
            });
        }
        Ok(out)
    }

    /// Start any configured MCP servers that haven't been started yet.
    ///
    /// This is called automatically by [`run()`](Shell::run) and
    /// [`execute()`](Shell::execute), but can be called explicitly
    /// to start servers eagerly (e.g. before an interactive REPL).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn start_mcp(&mut self) {
        if self.mcp_config.is_empty() {
            return;
        }
        let entries = std::mem::take(&mut self.mcp_config);
        match crate::mcp_client::start_clients(&entries).await {
            Ok(clients) => {
                self.mcp_clients = Rc::new(clients);
                crate::io::set_mcp_clients(self.mcp_clients.clone());
            }
            Err(e) => eprintln!("strands-shell: mcp: {e}"),
        }
    }
}

/// Builder for configuring and constructing a [`Shell`].
///
/// The builder configures three aspects of the shell:
///
/// 1. **Filesystem** — bind mounts that expose host paths into the
///    virtual filesystem
/// 2. **Network** — whether the kernel dispatches requests, and the transport
///    that carries them
/// 3. **Limits** — resource constraints to prevent runaway execution
///
/// # Bind Mount Modes
///
/// | Method | Behavior |
/// |--------|----------|
/// | [`bind()`](Self::bind) | Copies files into the VFS at build time (isolated snapshot) |
/// | [`bind_direct()`](Self::bind_direct) | Passes reads/writes through to the host filesystem |
/// | [`bind_readonly()`](Self::bind_readonly) | Copy mode, read-only in the VFS |
/// | [`bind_direct_readonly()`](Self::bind_direct_readonly) | Direct passthrough, read-only |
///
/// Copy mode is safer (the agent can't modify host files) but uses
/// memory proportional to file size. Direct mode is zero-copy but
/// gives the agent real filesystem access to that path.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> std::io::Result<()> {
/// use std::time::Duration;
/// use strands_shell::Shell;
///
/// let mut shell = Shell::builder()
///     // Filesystem
///     .bind("/home/user/project/src", "/workspace/src")
///     .bind_direct("/tmp/output", "/output")
///     // Limits
///     .timeout(Duration::from_secs(30))
///     .max_depth(64)
///     .max_output(1024 * 1024)
///     // Environment
///     .env("PROJECT", "my-project")
///     .umask(0o022)
///     .build()?;
///
/// let output = shell.run("ls /workspace/src").await;
/// # Ok(())
/// # }
/// ```
pub struct ShellBuilder {
    config: VfsConfig,
    env: Vec<(String, String)>,
    #[cfg(not(target_arch = "wasm32"))]
    mcp: Vec<McpConfigEntry>,
    max_depth: u32,
    max_output: usize,
    max_fds: usize,
    max_bg_jobs: usize,
    max_pipeline: usize,
    max_input: usize,
    max_file_size: usize,
    max_inodes: usize,
    timeout: Option<Duration>,
    network_enabled: bool,
    egress_proxy: Option<EgressProxy>,
    script_interpreter: Option<crate::os::ScriptInterpreter>,
    host_spawner: Option<crate::os::HostSpawner>,
    egress_refusal_header: Option<String>,
    effect_interceptor: Option<Arc<dyn EffectInterceptor>>,
    kernel: Option<Arc<dyn Kernel>>,
}

impl Default for ShellBuilder {
    fn default() -> Self {
        Self {
            config: VfsConfig::default(),
            env: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            mcp: Vec::new(),
            max_depth: 64,
            max_output: 1024 * 1024,
            max_fds: 128,
            max_bg_jobs: 8,
            max_pipeline: 16,
            max_input: 1024 * 1024,
            max_file_size: 10 * 1024 * 1024,
            max_inodes: 10_000,
            timeout: Some(std::time::Duration::from_secs(30)),
            network_enabled: true,
            egress_proxy: None,
            script_interpreter: None,
            host_spawner: None,
            egress_refusal_header: None,
            effect_interceptor: None,
            kernel: None,
        }
    }
}

impl ShellBuilder {
    /// Intercept **every** route that evaluates command text.
    ///
    /// The interceptor receives the exact command string and returns an opaque permit; the
    /// Shell reports the invocation's status through that permit.
    ///
    /// Coverage is the whole point, so it is spelled out. Admission lives in
    /// [`exec::execute_sourced`](crate::exec::execute_sourced) and
    /// [`exec::execute_with_reader`](crate::exec::execute_with_reader) — the narrowest pair every
    /// route reaches — so all of these are judged: [`Shell::run`], [`Shell::execute`], the
    /// capturing and direct `exec::` entry points, Lua's `io.popen` and `os.execute`,
    /// `find -exec`, `xargs`, `sh <file>` and `source`, an `EXIT` trap body, the MCP
    /// `exec_shell` tool, and the REPL. A nested command is admitted in its own right rather
    /// than folded into the command that spawned it.
    ///
    /// **This doc said the opposite until 2026-08-09** — "public direct executor and MCP entry
    /// points do not use this builder seam" — which was true when admission sat in `Shell::run`,
    /// and is the sentence an embedder would have read to conclude a route was unmediated.
    ///
    /// Not covered: [`crate::mcp_client`] spawns a host process outside this seam entirely.
    pub fn effect_interceptor(mut self, interceptor: Arc<dyn EffectInterceptor>) -> Self {
        self.effect_interceptor = Some(interceptor);
        self
    }

    /// Use `kernel` as the backend instead of the built-in VFS kernel.
    ///
    /// Use this when you need a backend other than the built-in VFS — for
    /// example, one backed by S3, a database, or a remote API. Going through the
    /// builder is what makes the custom kernel inherit the process limits and
    /// umask [`build`](Self::build) applies: `max_depth`, `max_output`,
    /// `max_fds`, `max_bg_jobs`, `max_pipeline`, `max_input`, `umask`, and the
    /// per-command [`timeout`](Self::timeout) all land on the shell process
    /// either way.
    ///
    /// [`effect_interceptor`](Self::effect_interceptor) **does** apply: admission
    /// sits above the `Kernel` trait, so a supplied kernel is mediated identically to
    /// the bundled one and cannot opt out.
    ///
    /// **The remaining kernel-side settings do not transfer, and the supplied kernel
    /// is responsible for the guarantees they would have provided.** These builder
    /// calls configure the built-in VFS kernel's internals and cannot be injected into
    /// an arbitrary implementation, so they are ignored here:
    ///
    /// - [`bind`](Self::bind) and the other bind modes — no VFS is built
    /// - [`disable_network`](Self::disable_network) — the custom kernel's
    ///   `http_request` decides whether it dispatches
    /// - [`max_file_size`](Self::max_file_size) and
    ///   [`max_inodes`](Self::max_inodes) — the custom kernel owns its storage.
    ///   `max_file_size` still bounds [`Shell::read_file`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use strands_shell::Shell;
    /// use strands_shell::os::Kernel;
    ///
    /// fn create_shell(kernel: Arc<dyn Kernel>) -> std::io::Result<Shell> {
    ///     Shell::builder().kernel(kernel).build()
    /// }
    /// ```
    pub fn kernel(mut self, kernel: Arc<dyn Kernel>) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Bind a host path into the virtual filesystem using copy mode.
    ///
    /// The contents of `source` are copied into the VFS at `destination`
    /// when [`build()`](Self::build) is called. Changes inside the shell
    /// do not affect the host.
    ///
    /// `source` can be a file or directory. Directories are copied
    /// recursively.
    pub fn bind(mut self, source: impl Into<String>, destination: impl Into<String>) -> Self {
        self.config.bind.push(BindEntry {
            mode: BindMode::Copy,
            source: source.into(),
            destination: destination.into(),
            readonly: false,
        });
        self
    }

    /// Bind a host path as read-only using copy mode.
    ///
    /// Like [`bind()`](Self::bind), but the files cannot be modified
    /// inside the shell.
    pub fn bind_readonly(
        mut self,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        self.config.bind.push(BindEntry {
            mode: BindMode::Copy,
            source: source.into(),
            destination: destination.into(),
            readonly: true,
        });
        self
    }

    /// Bind a host path with direct passthrough.
    ///
    /// Reads and writes inside the shell go directly to the host
    /// filesystem. No data is copied into the VFS. This is useful for
    /// large directories or when you want the agent to produce output
    /// files on the host.
    pub fn bind_direct(
        mut self,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        self.config.bind.push(BindEntry {
            mode: BindMode::Direct,
            source: source.into(),
            destination: destination.into(),
            readonly: false,
        });
        self
    }

    /// Bind a host path as read-only with direct passthrough.
    ///
    /// Like [`bind_direct()`](Self::bind_direct), but writes are
    /// rejected.
    pub fn bind_direct_readonly(
        mut self,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        self.config.bind.push(BindEntry {
            mode: BindMode::Direct,
            source: source.into(),
            destination: destination.into(),
            readonly: true,
        });
        self
    }

    /// Set the umask for file creation (default: `0o022`).
    pub fn umask(mut self, umask: u32) -> Self {
        self.config.umask = umask;
        self
    }

    /// Set an environment variable that will be available in the shell.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set the maximum recursion depth for shell functions, subshells,
    /// and command substitutions (default: unlimited).
    pub fn max_depth(mut self, n: u32) -> Self {
        self.max_depth = n;
        self
    }

    /// Set the maximum size in bytes for any single output
    /// accumulation (default: unlimited).
    pub fn max_output(mut self, n: usize) -> Self {
        self.max_output = n;
        self
    }

    /// Set the maximum number of open file descriptors per process
    /// (default: unlimited).
    pub fn max_fds(mut self, n: usize) -> Self {
        self.max_fds = n;
        self
    }

    /// Set the maximum number of concurrent background jobs
    /// (default: unlimited).
    pub fn max_bg_jobs(mut self, n: usize) -> Self {
        self.max_bg_jobs = n;
        self
    }

    /// Set the maximum number of stages in a single pipeline
    /// (default: unlimited).
    pub fn max_pipeline(mut self, n: usize) -> Self {
        self.max_pipeline = n;
        self
    }

    /// Set the maximum input size in bytes that the parser will accept
    /// (default: unlimited).
    pub fn max_input(mut self, n: usize) -> Self {
        self.max_input = n;
        self
    }

    /// Set the maximum size in bytes for any single file in the VFS
    /// (default: unlimited).
    pub fn max_file_size(mut self, n: usize) -> Self {
        self.max_file_size = n;
        self
    }

    /// Set the maximum number of inodes (files + directories) in the
    /// VFS (default: unlimited).
    pub fn max_inodes(mut self, n: usize) -> Self {
        self.max_inodes = n;
        self
    }

    /// Set a per-command wall-clock timeout for this shell.
    ///
    /// The deadline is reset on every [`run()`](Shell::run) /
    /// [`execute()`](Shell::execute) call, so idle time between
    /// commands does not consume the budget. A command that runs longer
    /// than `duration` is terminated and its `Output` carries
    /// `status = 1` with `strands-shell: execution timeout exceeded` in stderr.
    ///
    /// A zero `duration` is rejected by [`build`](Self::build): there is no
    /// "unlimited" sentinel, so omit the timeout entirely for no limit.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Disable all network requests dispatched by this Shell's kernel.
    pub fn disable_network(mut self) -> Self {
        self.network_enabled = false;
        self
    }

    /// Route this Shell's outbound HTTP through an egress proxy instead of dialing
    /// origins directly.
    ///
    /// `target` is the proxy URL (for example `http://127.0.0.1:8080`), and `ca_path`
    /// points at the PEM certificate the proxy signs its intercepted leaves with, read
    /// once here. This is a *stated position*, the counterpart of
    /// [`disable_network`](Self::disable_network): an embedder that wants the Shell's
    /// egress to meet a governed boundary configures it here rather than relying on a
    /// default. It enables the network, so it and `disable_network` are opposites — the
    /// last call wins, and the SSRF floor still runs before any request either way.
    ///
    /// This applies only to the bundled kernel. A kernel supplied through
    /// [`kernel`](Self::kernel) owns its own transport and ignores this setting.
    ///
    /// # Errors
    ///
    /// Returns an error if the CA certificate at `ca_path` cannot be read, or if its
    /// contents are not a valid PEM certificate. The parse happens here so a bad CA is
    /// a configuration-time error, matching this method's stated-position intent, rather
    /// than a failure on every later request.
    ///
    /// On `wasm32` this refuses unconditionally: the bundled kernel's wasm request path
    /// dials the host directly and does not honor a proxy, so enabling the network there
    /// would route around the gateway. Refusing keeps the fail-closed invariant — the
    /// network is never enabled unless the route can be honored.
    pub fn egress_proxy(
        self,
        target: impl Into<String>,
        ca_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        // On wasm the kernel's `http_request_effect` reaches the host directly and never
        // reads `egress_proxy`, so turning the network on here would be a silent bypass of
        // the gateway. Refuse before touching `network_enabled`, so the network cannot be
        // enabled without a route that honors it.
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (target, ca_path);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "egress_proxy is not supported on wasm: the kernel cannot route through the \
                 gateway on this target",
            ));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let ca_pem = std::fs::read(ca_path.as_ref())?;
            self.egress_proxy_pem(target, ca_pem)
        }
    }

    /// Route outbound HTTP through an egress proxy with already-loaded CA bytes.
    pub fn egress_proxy_pem(
        mut self,
        target: impl Into<String>,
        ca_pem: Vec<u8>,
    ) -> io::Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (target, ca_pem);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "egress_proxy is not supported on wasm: the kernel cannot route through the \
                 gateway on this target",
            ));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            // Validate the CA now, not per-request. `Certificate::from_pem` is lazy — it does
            // not parse the DER — so a malformed certificate is only rejected when a client is
            // *built* with it.
            let cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            reqwest::Client::builder()
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert)
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.egress_proxy = Some(EgressProxy {
                target: target.into(),
                ca_pem,
                refusal_header: self.egress_refusal_header.take(),
            });
            self.network_enabled = true;
            Ok(self)
        }
    }

    /// Install the interpreter that backs [`Kernel::run_script`](crate::os::Kernel::run_script).
    ///
    /// A stated position, the counterpart of the built-in commands: an embedder that
    /// wants the Shell's `python`/`python3` command to reach an out-of-Shell interpreter
    /// installs the hook here. Without it, `run_script` is `Unsupported` and a `python`
    /// command refuses. Applies only to the bundled kernel; a kernel supplied through
    /// [`kernel`](Self::kernel) owns its own `run_script`.
    pub fn script_interpreter(mut self, hook: crate::os::ScriptInterpreter) -> Self {
        self.script_interpreter = Some(hook);
        self
    }

    /// Install the hook that backs [`Kernel::spawn_host`](crate::os::Kernel::spawn_host).
    ///
    /// A stated position, the counterpart of [`script_interpreter`](Self::script_interpreter): an
    /// embedder that wants a host binary the Shell does not implement to run somewhere other than a
    /// plain child process installs the hook here. Without it, `spawn_host` uses the built-in
    /// `fork`+`exec`. Applies only to the bundled kernel; a kernel supplied through
    /// [`kernel`](Self::kernel) owns its own `spawn_host`.
    pub fn host_spawner(mut self, hook: crate::os::HostSpawner) -> Self {
        self.host_spawner = Some(hook);
        self
    }

    /// Name the response header the egress proxy sets on a refusal it originates itself.
    ///
    /// State it before [`egress_proxy`](Self::egress_proxy), which reads it. Without it a refusal the
    /// proxy synthesises inside its own tunnel is indistinguishable from the origin answering with
    /// the same status, so a command reports a refused request as a server response and exits `0`.
    /// With it, such a response becomes `PermissionDenied` and never reaches a command as a response.
    pub fn egress_refusal_header(mut self, header: impl Into<String>) -> Self {
        self.egress_refusal_header = Some(header.into());
        self
    }

    /// Load additional configuration from a TOML file.
    ///
    /// Bind mounts from the file are appended to whatever is already
    /// configured on the builder. The umask
    /// is overwritten. Resource caps under `[limits]` overwrite the
    /// corresponding builder values (an omitted key keeps the builder
    /// default). Environment variables follow a "code wins" rule: a key set
    /// explicitly via [`env`](Self::env) takes precedence over the same key
    /// in the file's `[env]` table, regardless of call order.
    ///
    /// See [`vfs_config::VfsConfig`](crate::vfs_config::VfsConfig) for
    /// the TOML format.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, contains invalid TOML,
    /// or contains an unknown key (typos fail the parse rather than being
    /// silently ignored).
    pub fn config_file(mut self, path: impl AsRef<Path>) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: VfsConfig = crate::vfs_config::parse_config(&content)?;
        self.config.bind.extend(config.bind);
        #[cfg(not(target_arch = "wasm32"))]
        self.mcp.extend(config.mcp);
        self.config.umask = config.umask;
        // Env: an explicitly-passed `.env()` value always wins over the file,
        // regardless of whether `.env()` or `.config_file()` was called first
        // (matches the "code wins" rule for umask/timeout). Only take a TOML
        // entry whose key the builder doesn't already carry.
        for (k, v) in config.env {
            if !self.env.iter().any(|(existing, _)| existing == &k) {
                self.env.push((k, v));
            }
        }
        if let Some(limits) = config.limits {
            // Each cap is optional — an omitted TOML key leaves the builder
            // default untouched. config_file() routes process-level caps and
            // VFS-level caps (max_file_size / max_inodes) to their respective
            // builder fields; they're grouped under one [limits] table for the
            // user but applied to different subsystems at build time.
            if let Some(n) = limits.max_depth {
                self.max_depth = n;
            }
            if let Some(n) = limits.max_output {
                self.max_output = n;
            }
            if let Some(n) = limits.max_fds {
                self.max_fds = n;
            }
            if let Some(n) = limits.max_bg_jobs {
                self.max_bg_jobs = n;
            }
            if let Some(n) = limits.max_pipeline {
                self.max_pipeline = n;
            }
            if let Some(n) = limits.max_input {
                self.max_input = n;
            }
            if let Some(dur) = limits.timeout {
                self.timeout = Some(dur);
            }
            if let Some(n) = limits.max_file_size {
                self.max_file_size = n;
            }
            if let Some(n) = limits.max_inodes {
                self.max_inodes = n;
            }
        }
        Ok(self)
    }

    /// Build the [`Shell`].
    ///
    /// This constructs the virtual filesystem with bind mounts and creates the
    /// initial shell process. When a custom [`kernel`](Self::kernel) was
    /// supplied, no VFS is built and that kernel is used instead — the process
    /// limits and umask still apply, but the kernel-side settings listed on
    /// [`kernel`](Self::kernel) do not.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A bind mount source path does not exist
    /// - The configured timeout is zero (a zero timeout would expire every
    ///   command immediately; there is no "unlimited" sentinel — simply omit
    ///   the timeout for no limit)
    pub fn build(self) -> io::Result<Shell> {
        if self.timeout == Some(Duration::ZERO) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be greater than zero (omit it for no timeout)",
            ));
        }

        // Capture a read-only config snapshot before the builder's fields are
        // moved into the kernel/process below. This is what `Shell::config()`
        // returns.
        let config_snapshot = ShellConfig {
            binds: self
                .config
                .bind
                .iter()
                .map(|b| BindInfo {
                    source: b.source.clone(),
                    destination: b.destination.clone(),
                    mode: b.mode.as_str(),
                    readonly: b.readonly,
                })
                .collect(),
            network_enabled: self.network_enabled,
            env: self.env.clone(),
            umask: self.config.umask,
            timeout_secs: self.timeout.map(|d| d.as_secs_f64()),
            limits: LimitsInfo {
                max_depth: self.max_depth,
                max_output: self.max_output,
                max_fds: self.max_fds,
                max_bg_jobs: self.max_bg_jobs,
                max_pipeline: self.max_pipeline,
                max_input: self.max_input,
                max_file_size: self.max_file_size,
                max_inodes: self.max_inodes,
            },
        };

        let kernel: Arc<dyn Kernel> = match self.kernel {
            Some(kernel) => kernel,
            None => {
                let mut vfs = build_vfs(&self.config)?;
                vfs.max_file_size = self.max_file_size;
                vfs.max_inodes = self.max_inodes;
                let mut kernel = VfsKernel::new(vfs);
                kernel.network_enabled = self.network_enabled;
                kernel.egress_proxy = self.egress_proxy;
                kernel.script_interpreter = self.script_interpreter;
                kernel.host_spawner = self.host_spawner;
                Arc::new(kernel)
            }
        };
        // Wrapped once, here. `Mediated` is the only route to the kernel, so a
        // supplied kernel is admitted exactly as the bundled one is — mediation does
        // not depend on which backend the embedder chose.
        let kernel = Arc::new(Mediated::new(kernel, self.effect_interceptor.clone()));
        let mut proc = kernel.new_process();

        proc.max_depth = self.max_depth;
        proc.max_output = self.max_output;
        proc.max_fds = self.max_fds;
        proc.max_bg_jobs = self.max_bg_jobs;
        proc.max_pipeline = self.max_pipeline;
        proc.max_input = self.max_input;
        proc.umask = self.config.umask;
        if let Some(dur) = self.timeout {
            #[cfg(not(target_arch = "wasm32"))]
            {
                proc.deadline = Some(tokio::time::Instant::now() + dur);
            }
            #[cfg(target_arch = "wasm32")]
            {
                proc.deadline = Some(std::time::Instant::now() + dur);
            }
        }

        for (k, v) in self.env {
            proc.set_env(k, v);
        }

        Ok(Shell {
            kernel,

            proc,
            timeout: self.timeout,
            max_file_size: self.max_file_size,
            config: config_snapshot,
            #[cfg(not(target_arch = "wasm32"))]
            mcp_clients: Rc::new(Vec::new()),
            #[cfg(not(target_arch = "wasm32"))]
            mcp_config: self.mcp,
        })
    }
}

// `EffectStartFailure` and `EffectPermitGuard` were deleted with the admission calls above.
// `mediate::CommandPermit` is their replacement, and it keeps the property
// that mattered: dropping without recording marks the effect **indeterminate**, never
// successful, so a command killed by its deadline or abandoned on a client disconnect cannot
// enter history as though it completed.

/// Compute the parent directory of a path, or `None` if there is none
/// (root, empty, or no `/`).
fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    if idx == 0 {
        None
    } else {
        Some(trimmed[..idx].to_string())
    }
}

/// Create a directory and all missing ancestors via the Kernel trait.
async fn create_dir_recursive(kernel: &Mediated, proc: &Process, path: &str) -> io::Result<()> {
    let stat = kernel.stat(proc, path).await;
    if stat.exists && stat.is_dir {
        return Ok(());
    }
    if stat.exists {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{path}: not a directory"),
        ));
    }
    if let Some(parent) = parent_dir(path) {
        Box::pin(create_dir_recursive(kernel, proc, &parent)).await?;
    }
    kernel.create_dir(proc, path).await
}

#[cfg(test)]
mod tests {
    use super::parent_dir;

    #[test]
    fn parent_dir_of_root_is_none() {
        assert_eq!(parent_dir("/"), None);
    }

    #[test]
    fn parent_dir_of_empty_is_none() {
        assert_eq!(parent_dir(""), None);
    }

    #[test]
    fn parent_dir_of_top_level_is_none() {
        // "/foo" — parent is root, treated as None ("nothing to create").
        assert_eq!(parent_dir("/foo"), None);
    }

    #[test]
    fn parent_dir_of_nested_absolute_is_parent() {
        assert_eq!(parent_dir("/a/b/c"), Some("/a/b".to_string()));
    }

    #[test]
    fn parent_dir_strips_trailing_slash() {
        assert_eq!(parent_dir("/a/b/"), Some("/a".to_string()));
    }

    #[test]
    fn parent_dir_relative_path_is_supported() {
        assert_eq!(parent_dir("a/b/c"), Some("a/b".to_string()));
    }

    #[test]
    fn parent_dir_no_slash_is_none() {
        assert_eq!(parent_dir("foo"), None);
    }
}
