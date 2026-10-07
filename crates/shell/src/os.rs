// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Monotonic counter for virtual PIDs.
static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// Metadata about a directory entry.
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// File metadata returned by Kernel::stat().
#[derive(Default)]
pub struct FileStat {
    pub exists: bool,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub len: u64,
    pub is_socket: bool,
    pub is_fifo: bool,
    pub is_block_device: bool,
    pub is_char_device: bool,
    /// Unix mode bits (permissions + setuid/setgid/sticky).
    pub mode: u32,
    /// Device ID (for -ef same-file check).
    pub dev: u64,
    /// Inode number (for -ef same-file check).
    pub ino: u64,
    /// Modification time as duration since epoch.
    pub modified: Option<std::time::SystemTime>,
}

/// Access permission modes for Kernel::access().
pub const ACCESS_R: i32 = 4;
pub const ACCESS_W: i32 = 2;
pub const ACCESS_X: i32 = 1;

/// File descriptor index.
pub type Fd = u32;

pub const STDIN: Fd = 0;
pub const STDOUT: Fd = 1;
pub const STDERR: Fd = 2;

/// Open flags for the open() syscall.
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub append: bool,
    pub truncate: bool,
}

impl OpenFlags {
    pub fn read() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            append: false,
            truncate: false,
        }
    }
    pub fn write() -> Self {
        Self {
            read: false,
            write: true,
            create: true,
            append: false,
            truncate: true,
        }
    }
    pub fn append() -> Self {
        Self {
            read: false,
            write: true,
            create: true,
            append: true,
            truncate: false,
        }
    }
}

/// The backing storage for a file descriptor.
pub enum FdKind {
    ChannelReader {
        rx: mpsc::Receiver<Bytes>,
        buf: Vec<u8>,
    },
    ChannelWriter {
        tx: mpsc::Sender<Bytes>,
        limit: Option<Arc<WriteLimit>>,
    },
    #[cfg(not(target_arch = "wasm32"))]
    File(tokio::fs::File),
}

/// The byte budget of one open file, shared by every descriptor that writes it.
///
/// `admit` and `record` are one read-modify-write split in two, correct because every
/// `poll_write` runs them on the single-threaded `LocalSet` with no await between them, which is
/// also why `Relaxed` ordering is enough.
pub struct WriteLimit {
    cap: usize,
    written: std::sync::atomic::AtomicUsize,
    state: std::sync::atomic::AtomicU8,
}

const LIMIT_OPEN: u8 = 0;
const LIMIT_EXCEEDED: u8 = 1;
const LIMIT_FAILED: u8 = 2;

impl WriteLimit {
    /// A budget of `cap` bytes, of which `written` are already in the file; `0` is unbounded.
    pub fn new(cap: usize, written: usize) -> Arc<Self> {
        Arc::new(Self {
            cap,
            written: std::sync::atomic::AtomicUsize::new(written),
            state: std::sync::atomic::AtomicU8::new(LIMIT_OPEN),
        })
    }

    /// Records that the backing store refused the bytes, so the next write reports it.
    pub fn fail(&self) {
        self.state
            .store(LIMIT_FAILED, std::sync::atomic::Ordering::Relaxed);
    }

    /// The refusal a write over the budget reports.
    pub fn exceeded(&self) -> io::Error {
        io::Error::other(format!("file size limit exceeded ({} bytes)", self.cap))
    }

    /// How many of `len` bytes still fit, or the refusal when none do.
    fn admit(&self, len: usize) -> io::Result<usize> {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            LIMIT_EXCEEDED => return Err(self.exceeded()),
            LIMIT_FAILED => return Err(io::Error::other("write failed")),
            _ => {}
        }
        if self.cap == 0 {
            return Ok(len);
        }
        let room = self
            .cap
            .saturating_sub(self.written.load(std::sync::atomic::Ordering::Relaxed));
        if len > 0 && room == 0 {
            self.state
                .store(LIMIT_EXCEEDED, std::sync::atomic::Ordering::Relaxed);
            return Err(self.exceeded());
        }
        Ok(len.min(room))
    }

    fn record(&self, len: usize) {
        self.written
            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
    }
}

impl FdKind {
    async fn try_clone(&self) -> io::Result<FdKind> {
        match self {
            FdKind::ChannelWriter { tx, limit } => Ok(FdKind::ChannelWriter {
                tx: tx.clone(),
                limit: limit.clone(),
            }),
            #[cfg(not(target_arch = "wasm32"))]
            FdKind::File(f) => Ok(FdKind::File(f.try_clone().await?)),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cannot duplicate this fd",
            )),
        }
    }
}

/// Per-process state. Each shell/subshell gets its own.
pub struct Process {
    /// Virtual PID (not the real OS PID).
    pub pid: u32,
    pub cwd: PathBuf,
    pub env: Arc<HashMap<String, String>>,
    pub functions: Arc<HashMap<String, crate::parser::CommandLine>>,
    pub last_exit: i32,
    pub arg0: String,
    pub args: Vec<String>,
    /// Shell option flags.
    pub opt_errexit: bool,
    pub opt_nounset: bool,
    pub opt_xtrace: bool,
    /// Set when a nounset error occurs during expansion.
    pub nounset_error: bool,
    /// PID of last background job (for $!).
    pub last_bg_pid: Option<u32>,
    /// Background job handles.
    pub bg_jobs: Vec<tokio::task::JoinHandle<(i32, String, String)>>,
    /// Stack of local variable scopes (for shell functions).
    /// Each entry maps variable names to their previous value (None = was unset).
    local_scopes: Vec<HashMap<String, Option<String>>>,
    fds: HashMap<Fd, FdKind>,
    next_fd: Fd,
    pub bg_counter: u32,
    /// Offset within current arg for getopts combined flags (e.g. -abc).
    pub optoff: i32,
    /// Set of readonly variable names.
    pub readonly_vars: Arc<std::collections::HashSet<String>>,
    /// Shell aliases.
    pub aliases: Arc<HashMap<String, String>>,
    /// Command hash table (name → full path).
    pub hash_table: Arc<HashMap<String, String>>,
    /// Optional stderr channel for sandboxed error output.
    err_tx: Option<mpsc::Sender<Bytes>>,
    /// Current recursion depth (incremented on function calls, subshells, eval, source, command substitution).
    pub depth: u32,
    /// Maximum allowed recursion depth (0 = unlimited).
    pub max_depth: u32,
    /// Deadline for script execution (None = no timeout).
    #[cfg(not(target_arch = "wasm32"))]
    pub deadline: Option<tokio::time::Instant>,
    #[cfg(target_arch = "wasm32")]
    pub deadline: Option<std::time::Instant>,
    /// Maximum bytes for any single string accumulation (0 = unlimited).
    pub max_output: usize,
    /// Maximum number of open file descriptors (0 = unlimited).
    pub max_fds: usize,
    /// Maximum number of background jobs (0 = unlimited).
    pub max_bg_jobs: usize,
    /// Maximum number of pipeline stages (0 = unlimited).
    pub max_pipeline: usize,
    /// Maximum input size for the parser in bytes (0 = unlimited).
    pub max_input: usize,
    /// When true, pipelines capture stdout instead of copying to real stdout.
    pub capture: bool,
    /// Captured stdout output (populated when capture=true).
    pub captured_output: String,
    /// Captured stderr output (populated when capture=true).
    pub captured_stderr: String,
    /// Trap handlers (signal name → command string).
    pub traps: HashMap<String, String>,
    /// File creation mask.
    pub umask: u32,
    /// `shopt` option names currently set; recorded, with no effect on execution.
    pub shopts: std::collections::BTreeSet<String>,
}

/// Resource limits that can be extracted from a configured Process
/// and applied to fresh processes (e.g., MCP per-request processes).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ProcessLimits {
    pub max_depth: u32,
    pub max_output: usize,
    pub max_fds: usize,
    pub max_bg_jobs: usize,
    pub max_pipeline: usize,
    pub max_input: usize,
    #[serde(default, deserialize_with = "deserialize_timeout")]
    pub timeout: Option<std::time::Duration>,
}

fn deserialize_timeout<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<std::time::Duration>, D::Error> {
    let secs: Option<u64> = Option::deserialize(d)?;
    Ok(secs.map(std::time::Duration::from_secs))
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_output: 1024 * 1024,
            max_fds: 128,
            max_bg_jobs: 8,
            max_pipeline: 16,
            max_input: 1024 * 1024,
            timeout: Some(std::time::Duration::from_secs(30)),
        }
    }
}

impl Process {
    /// Extract the configured resource limits from this process.
    pub fn limits(&self) -> ProcessLimits {
        ProcessLimits {
            max_depth: self.max_depth,
            max_output: self.max_output,
            max_fds: self.max_fds,
            max_bg_jobs: self.max_bg_jobs,
            max_pipeline: self.max_pipeline,
            max_input: self.max_input,
            timeout: {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.deadline
                        .map(|dl| dl.duration_since(tokio::time::Instant::now()))
                }
                #[cfg(target_arch = "wasm32")]
                {
                    self.deadline
                        .and_then(|dl| dl.checked_duration_since(std::time::Instant::now()))
                }
            },
        }
    }

    /// Apply resource limits to this process.
    pub fn apply_limits(&mut self, limits: &ProcessLimits) {
        self.max_depth = limits.max_depth;
        self.max_output = limits.max_output;
        self.max_fds = limits.max_fds;
        self.max_bg_jobs = limits.max_bg_jobs;
        self.max_pipeline = limits.max_pipeline;
        self.max_input = limits.max_input;
        if let Some(dur) = limits.timeout {
            #[cfg(not(target_arch = "wasm32"))]
            {
                self.deadline = Some(tokio::time::Instant::now() + dur);
            }
            #[cfg(target_arch = "wasm32")]
            {
                self.deadline = Some(std::time::Instant::now() + dur);
            }
        }
    }
    pub fn new(cwd: PathBuf, env: HashMap<String, String>) -> Self {
        Self {
            pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
            cwd,
            env: Arc::new(env),
            functions: Arc::new(HashMap::new()),
            last_exit: 0,
            arg0: "lash".into(),
            args: Vec::new(),
            opt_errexit: false,
            opt_nounset: false,
            opt_xtrace: false,
            nounset_error: false,
            last_bg_pid: None,
            bg_jobs: Vec::new(),
            local_scopes: Vec::new(),
            fds: HashMap::new(),
            next_fd: 3,
            bg_counter: 0,
            optoff: -1,
            readonly_vars: Arc::new(std::collections::HashSet::new()),
            aliases: Arc::new(HashMap::new()),
            hash_table: Arc::new(HashMap::new()),
            err_tx: None,
            depth: 0,
            max_depth: 0,
            deadline: None,
            max_output: 0,
            max_fds: 0,
            max_bg_jobs: 0,
            max_pipeline: 0,
            max_input: 0,
            capture: false,
            captured_output: String::new(),
            captured_stderr: String::new(),
            traps: HashMap::new(),
            umask: 0o022,
            shopts: std::collections::BTreeSet::new(),
        }
    }

    /// Create a placeholder empty process (used for temporary swaps).
    pub fn empty() -> Self {
        Self {
            pid: 0,
            cwd: PathBuf::new(),
            env: Arc::new(HashMap::new()),
            functions: Arc::new(HashMap::new()),
            last_exit: 0,
            arg0: String::new(),
            args: Vec::new(),
            opt_errexit: false,
            opt_nounset: false,
            opt_xtrace: false,
            nounset_error: false,
            last_bg_pid: None,
            bg_jobs: Vec::new(),
            local_scopes: Vec::new(),
            fds: HashMap::new(),
            next_fd: 3,
            bg_counter: 0,
            optoff: -1,
            readonly_vars: Arc::new(std::collections::HashSet::new()),
            aliases: Arc::new(HashMap::new()),
            hash_table: Arc::new(HashMap::new()),
            err_tx: None,
            depth: 0,
            max_depth: 0,
            deadline: None,
            max_output: 0,
            max_fds: 0,
            max_bg_jobs: 0,
            max_pipeline: 0,
            max_input: 0,
            capture: false,
            captured_output: String::new(),
            captured_stderr: String::new(),
            traps: HashMap::new(),
            umask: 0o022,
            shopts: std::collections::BTreeSet::new(),
        }
    }

    pub fn alloc_fd(&mut self, kind: FdKind) -> io::Result<Fd> {
        if self.max_fds > 0 && self.fds.len() >= self.max_fds {
            return Err(io::Error::other("too many open file descriptors"));
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, kind);
        Ok(fd)
    }

    /// Fork this process — child inherits cwd and env but gets empty fd table.
    pub fn fork(&self) -> Process {
        Process {
            pid: self.pid,
            cwd: self.cwd.clone(),
            env: self.env.clone(),
            functions: self.functions.clone(),
            last_exit: self.last_exit,
            arg0: self.arg0.clone(),
            args: self.args.clone(),
            opt_errexit: self.opt_errexit,
            opt_nounset: self.opt_nounset,
            opt_xtrace: self.opt_xtrace,
            nounset_error: false,
            last_bg_pid: None,
            bg_jobs: Vec::new(),
            local_scopes: Vec::new(),
            fds: HashMap::new(),
            next_fd: 3,
            bg_counter: 0,
            optoff: self.optoff,
            readonly_vars: self.readonly_vars.clone(),
            aliases: self.aliases.clone(),
            hash_table: self.hash_table.clone(),
            err_tx: self.err_tx.clone(),
            depth: self.depth,
            max_depth: self.max_depth,
            deadline: self.deadline,
            max_output: self.max_output,
            max_fds: self.max_fds,
            max_bg_jobs: self.max_bg_jobs,
            max_pipeline: self.max_pipeline,
            max_input: self.max_input,
            capture: self.capture,
            captured_output: String::new(),
            captured_stderr: String::new(),
            traps: self.traps.clone(),
            umask: self.umask,
            shopts: self.shopts.clone(),
        }
    }

    /// Install a pipe: writer on `self[writer_fd]`, reader on returned Process-less FdReader.
    /// Use `set_channel_writer` / `set_channel_reader` for cross-process pipes.
    pub fn set_channel_reader(&mut self, fd: Fd, rx: mpsc::Receiver<Bytes>) {
        self.fds.insert(
            fd,
            FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            },
        );
    }

    pub fn set_channel_writer(&mut self, fd: Fd, tx: mpsc::Sender<Bytes>) {
        self.fds
            .insert(fd, FdKind::ChannelWriter { tx, limit: None });
    }

    /// Give `target` a clone of the channel writer on `fd` with its budget, or `false` when there is none.
    pub fn inherit_channel_writer(&self, fd: Fd, target: &mut Process) -> bool {
        match self.fds.get(&fd) {
            Some(FdKind::ChannelWriter { tx, limit }) => {
                target.fds.insert(
                    fd,
                    FdKind::ChannelWriter {
                        tx: tx.clone(),
                        limit: limit.clone(),
                    },
                );
                true
            }
            _ => false,
        }
    }

    /// The sender of a channel writer installed on `fd`, if there is one.
    ///
    /// Lets a fork inherit an embedder's output sink instead of replacing it. `fork` starts with an
    /// empty descriptor table, so a caller who installed a writer on this process — the documented
    /// way to receive output as it is produced — would otherwise have it discarded by the forked
    /// process's own pipes. `transfer_fd` is the equivalent for stdin, which moves rather than
    /// clones because only one reader may hold it.
    pub fn channel_writer(&self, fd: Fd) -> Option<mpsc::Sender<Bytes>> {
        match self.fds.get(&fd) {
            Some(FdKind::ChannelWriter { tx, .. }) => Some(tx.clone()),
            _ => None,
        }
    }

    /// Remove an fd from this process and install it in another.
    /// Used to pass stdin across fork boundaries (e.g. CompoundPipeline).
    pub fn transfer_fd(&mut self, fd: Fd, target: &mut Process) {
        if let Some(kind) = self.fds.remove(&fd) {
            target.fds.insert(fd, kind);
        }
    }

    pub fn dup2(&mut self, from: Fd, to: Fd) -> io::Result<()> {
        let kind = self
            .fds
            .remove(&from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("bad fd {from}")))?;
        self.fds.insert(to, kind);
        Ok(())
    }

    /// Duplicate an fd (keeping the source open) by cloning its channel.
    pub async fn dup_fd(&mut self, src: Fd, dst: Fd) -> io::Result<()> {
        let kind = self
            .fds
            .get(&src)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("bad fd {src}")))?
            .try_clone()
            .await?;
        self.fds.insert(dst, kind);
        Ok(())
    }

    /// Take the reader half out of an fd, removing it from the table.
    pub fn take_reader(&mut self, fd: Fd) -> io::Result<FdReader> {
        match self.fds.remove(&fd) {
            Some(kind) => Ok(FdReader { kind, done: false }),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("bad fd {fd}"),
            )),
        }
    }

    /// Take the writer half out of an fd, removing it from the table.
    pub fn take_writer(&mut self, fd: Fd) -> io::Result<FdWriter> {
        match self.fds.remove(&fd) {
            Some(kind) => Ok(FdWriter { kind }),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("bad fd {fd}"),
            )),
        }
    }

    pub fn close(&mut self, fd: Fd) {
        self.fds.remove(&fd);
    }

    /// Check whether an fd exists in this process.
    pub fn has_fd(&self, fd: Fd) -> bool {
        self.fds.contains_key(&fd)
    }

    /// Restore a previously taken fd (e.g. after `take_reader`).
    pub fn restore_fd(&mut self, fd: Fd, kind: FdKind) {
        self.fds.insert(fd, kind);
    }

    /// Set the stderr channel for sandboxed error output.
    pub fn set_err_tx(&mut self, tx: mpsc::Sender<Bytes>) {
        self.err_tx = Some(tx);
    }

    /// Check execution limits (deadline and recursion depth).
    /// Returns an error message if a limit is exceeded.
    pub fn check_limits(&self) -> Option<&'static str> {
        if let Some(dl) = self.deadline {
            #[cfg(not(target_arch = "wasm32"))]
            let expired = tokio::time::Instant::now() >= dl;
            #[cfg(target_arch = "wasm32")]
            let expired = std::time::Instant::now() >= dl;
            if expired {
                return Some("strands-shell: execution timeout exceeded");
            }
        }
        if self.max_depth > 0 && self.depth >= self.max_depth {
            return Some("strands-shell: maximum recursion depth exceeded");
        }
        None
    }

    /// Clear the stderr channel (allows the channel to close).
    pub fn clear_err_tx(&mut self) {
        self.err_tx = None;
    }

    /// Remove and return the stderr channel, if one is set.
    pub fn take_err_tx(&mut self) -> Option<mpsc::Sender<Bytes>> {
        self.err_tx.take()
    }

    /// Send `text` to the channel writer on `fd` within its budget, or `None` when `fd` has no channel writer.
    fn send_to_channel(&mut self, fd: Fd, text: String) -> Option<io::Result<()>> {
        let Some(FdKind::ChannelWriter { tx, limit }) = self.fds.get(&fd) else {
            return None;
        };
        let bytes = Bytes::from(text);
        let Some(limit) = limit else {
            let _ = tx.try_send(bytes);
            return Some(Ok(()));
        };
        let fit = match limit.admit(bytes.len()) {
            Ok(fit) => fit,
            Err(e) => return Some(Err(e)),
        };
        if tx.try_send(bytes.slice(..fit)).is_ok() {
            limit.record(fit);
        }
        Some(match bytes.len() - fit {
            0 => Ok(()),
            rest => limit.admit(rest).map(|_| ()),
        })
    }

    /// Write text to stderr by the same route as [`Self::err_msg`], without a trailing newline.
    pub fn err_raw(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Some(tx) = &self.err_tx {
            let _ = tx.try_send(Bytes::from(text.to_string()));
        } else if let Some(sent) = self.send_to_channel(STDERR, text.to_string()) {
            if sent.is_err() {
                self.last_exit = 1;
            }
        } else if self.capture {
            if !self.append_captured_stderr(text) {
                self.last_exit = 1;
            }
        } else {
            eprint!("{text}");
        }
    }

    /// Write text to stdout by the same route as [`Self::out_msg`], without a trailing newline.
    pub fn out_raw(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Some(sent) = self.send_to_channel(STDOUT, text.to_string()) {
            if let Err(e) = sent {
                self.err_msg(&format!("strands-shell: {e}"));
                self.last_exit = 1;
            }
        } else if self.capture {
            if !self.append_captured_output(text) {
                self.append_captured_stderr("strands-shell: output size limit exceeded\n");
                self.last_exit = 1;
            }
        } else {
            print!("{text}");
        }
    }

    /// A writer on a duplicate of `fd`, leaving the descriptor in place.
    pub async fn clone_writer(&self, fd: Fd) -> io::Result<FdWriter> {
        let kind = self
            .fds
            .get(&fd)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("bad fd {fd}")))?
            .try_clone()
            .await?;
        Ok(FdWriter { kind })
    }

    /// Write an error message to the process stderr channel, or real stderr as fallback.
    ///
    /// Checks a `ChannelWriter` on fd 2 after `err_tx`, mirroring [`Self::out_msg`]'s check on
    /// fd 1: without it an embedder's stderr sink never sees a message reported this way.
    pub fn err_msg(&mut self, msg: &str) {
        if let Some(tx) = &self.err_tx {
            let _ = tx.try_send(Bytes::from(format!("{msg}\n")));
        } else if let Some(sent) = self.send_to_channel(STDERR, format!("{msg}\n")) {
            if sent.is_err() {
                self.last_exit = 1;
            }
        } else if self.capture {
            let complete = self.append_captured_stderr(msg) && self.append_captured_stderr("\n");
            if !complete {
                self.last_exit = 1;
            }
        } else {
            eprintln!("{msg}");
        }
    }

    pub(crate) fn append_captured_output(&mut self, output: &str) -> bool {
        append_limited(&mut self.captured_output, output, self.max_output)
    }

    pub(crate) fn append_captured_stderr(&mut self, output: &str) -> bool {
        append_limited(&mut self.captured_stderr, output, self.max_output)
    }

    /// Write a message to stdout (fd 1 channel if available, else real stdout).
    pub fn out_msg(&mut self, msg: &str) {
        if let Some(sent) = self.send_to_channel(STDOUT, format!("{msg}\n")) {
            if let Err(e) = sent {
                self.err_msg(&format!("strands-shell: {e}"));
                self.last_exit = 1;
            }
        } else if self.capture {
            let complete = self.append_captured_output(msg) && self.append_captured_output("\n");
            if !complete {
                self.append_captured_stderr("strands-shell: output size limit exceeded\n");
                self.last_exit = 1;
            }
        } else {
            println!("{msg}");
        }
    }

    /// Set an environment variable (COW — clones map on first write if shared).
    /// Returns false if the variable is readonly.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) -> bool {
        let key = key.into();
        if self.readonly_vars.contains(&key) {
            self.err_msg(&format!("strands-shell: {key}: readonly variable"));
            return false;
        }
        Arc::make_mut(&mut self.env).insert(key, value.into());
        true
    }

    /// Remove an environment variable. Returns false if readonly.
    pub fn unset_env(&mut self, key: &str) -> bool {
        if self.readonly_vars.contains(key) {
            self.err_msg(&format!("strands-shell: {key}: readonly variable"));
            return false;
        }
        Arc::make_mut(&mut self.env).remove(key);
        true
    }

    /// Mark a variable as readonly.
    pub fn mark_readonly(&mut self, key: impl Into<String>) {
        Arc::make_mut(&mut self.readonly_vars).insert(key.into());
    }

    /// Define a shell function.
    pub fn set_function(&mut self, name: impl Into<String>, body: crate::parser::CommandLine) {
        Arc::make_mut(&mut self.functions).insert(name.into(), body);
    }

    /// Look up a shell function.
    pub fn get_function(&self, name: &str) -> Option<&crate::parser::CommandLine> {
        self.functions.get(name)
    }

    /// Remove a shell function.
    pub fn unset_function(&mut self, name: &str) {
        Arc::make_mut(&mut self.functions).remove(name);
    }

    /// Set a shell alias.
    pub fn set_alias(&mut self, name: impl Into<String>, value: impl Into<String>) {
        Arc::make_mut(&mut self.aliases).insert(name.into(), value.into());
    }

    /// Remove a shell alias.
    pub fn unset_alias(&mut self, name: &str) -> bool {
        let map = Arc::make_mut(&mut self.aliases);
        map.remove(name).is_some()
    }

    /// Remove all aliases.
    pub fn clear_aliases(&mut self) {
        Arc::make_mut(&mut self.aliases).clear();
    }

    /// Look up an environment variable.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(|s| s.as_str())
    }

    /// Push a new local variable scope (called when entering a function).
    pub fn push_local_scope(&mut self) {
        self.local_scopes.push(HashMap::new());
    }

    /// Pop the top local scope, restoring all localized variables.
    pub fn pop_local_scope(&mut self) {
        if let Some(scope) = self.local_scopes.pop() {
            for (name, prev) in scope {
                match prev {
                    Some(val) => {
                        self.set_env(&name, &val);
                    }
                    None => {
                        self.unset_env(&name);
                    }
                }
            }
        }
    }

    /// Declare a variable as local: save its current value in the top scope,
    /// then set the new value. If already saved in this scope, just set.
    pub fn set_local(&mut self, name: &str, value: &str) {
        if let Some(scope) = self.local_scopes.last_mut() {
            scope
                .entry(name.to_string())
                .or_insert_with(|| self.env.get(name).cloned());
        }
        self.set_env(name, value);
    }

    /// Declare a variable as local without assigning (preserve or set empty).
    pub fn declare_local(&mut self, name: &str) {
        if let Some(scope) = self.local_scopes.last_mut() {
            scope
                .entry(name.to_string())
                .or_insert_with(|| self.env.get(name).cloned());
        }
    }
}

pub(crate) fn append_limited(target: &mut String, value: &str, limit: usize) -> bool {
    if limit == 0 {
        target.push_str(value);
        return true;
    }

    let remaining = limit.saturating_sub(target.len());
    if value.len() <= remaining {
        target.push_str(value);
        return true;
    }

    let mut end = remaining.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&value[..end]);
    false
}

/// Read from an async reader into a String, enforcing an optional size limit.
/// Returns Err if the limit is exceeded.
pub async fn read_to_string_limited<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<String> {
    let buf = read_to_end_limited(reader, limit).await?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read from an async reader into a byte vector, enforcing an optional size
/// limit. Returns Err if the limit is exceeded. A `limit` of 0 means no cap.
pub async fn read_to_end_limited<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    if limit == 0 {
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(reader, &mut buf).await?;
        return Ok(buf);
    }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = tokio::io::AsyncReadExt::read(reader, &mut tmp).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > limit {
            return Err(io::Error::other("output size limit exceeded"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(buf)
}

/// Standard base64 encoder (RFC 4648). Self-contained — no external dep.
pub fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// One file write that did not reach its place after its descriptors closed.
#[derive(Debug)]
pub struct WriteFailure {
    /// The path the descriptor was opened on.
    pub path: String,
    /// The error the write met.
    pub error: io::Error,
}

/// Create a bounded channel pair for use as a pipe.
pub fn pipe(buffer: usize) -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    mpsc::channel(buffer)
}

/// Owned async reader extracted from a Process fd.
pub struct FdReader {
    kind: FdKind,
    done: bool,
}

impl FdReader {
    /// Create an FdReader directly from a channel receiver.
    pub fn from_receiver(rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            kind: FdKind::ChannelReader {
                rx,
                buf: Vec::new(),
            },
            done: false,
        }
    }

    /// Consume this reader and return the underlying FdKind.
    pub fn into_fd_kind(self) -> FdKind {
        self.kind
    }
}

impl AsyncRead for FdReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Ok(()));
        }
        match &mut this.kind {
            FdKind::ChannelReader { rx, buf: remainder } => {
                if !remainder.is_empty() {
                    let n = remainder.len().min(buf.remaining());
                    buf.put_slice(&remainder[..n]);
                    remainder.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(bytes)) => {
                        let n = bytes.len().min(buf.remaining());
                        buf.put_slice(&bytes[..n]);
                        if n < bytes.len() {
                            remainder.extend_from_slice(&bytes[n..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(None) => {
                        this.done = true;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            FdKind::File(f) => Pin::new(f).poll_read(cx, buf),
            FdKind::ChannelWriter { .. } => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd not readable",
            ))),
        }
    }
}

/// Owned async writer extracted from a Process fd.
pub struct FdWriter {
    kind: FdKind,
}

impl AsyncWrite for FdWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.kind {
            FdKind::ChannelWriter { tx, limit } => {
                let len = match limit {
                    Some(limit) => match limit.admit(buf.len()) {
                        Ok(len) => len,
                        Err(e) => return Poll::Ready(Err(e)),
                    },
                    None => buf.len(),
                };
                let bytes = Bytes::copy_from_slice(&buf[..len]);
                match tx.try_send(bytes) {
                    Ok(()) => {
                        if let Some(limit) = limit {
                            limit.record(len);
                        }
                        Poll::Ready(Ok(len))
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Channel full — we need to wait. Store bytes and poll again.
                        // For simplicity, use a waker-based approach via try_send retry.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "pipe closed",
                    ))),
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            FdKind::File(f) => Pin::new(f).poll_write(cx, buf),
            FdKind::ChannelReader { .. } => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd not writable",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            #[cfg(not(target_arch = "wasm32"))]
            FdKind::File(f) => Pin::new(f).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().kind {
            #[cfg(not(target_arch = "wasm32"))]
            FdKind::File(f) => Pin::new(f).poll_shutdown(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}

/// HTTP request passed to [`Kernel::http_request`].
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Allow invalid TLS certificates (curl -k).
    pub insecure: bool,
    /// Maximum response body size in bytes (0 = unlimited).
    pub max_response: usize,
}

/// HTTP response returned by [`Kernel::http_request`].
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// HTTP version string (e.g. "1.1", "2").
    pub version: String,
    /// Canonical reason phrase (e.g. "OK", "Not Found").
    pub reason: String,
}

/// The outcome of running a script through [`Kernel::run_script`].
///
/// The mirror of [`HttpResponse`] for the script seam: a process-style status and the
/// captured streams. Buffered, not streamed — the interpreter behind the seam runs to
/// completion and hands back what it produced.
pub struct ScriptOutcome {
    /// The script's process-style exit status.
    pub status: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// A hook that runs a script for [`Kernel::run_script`].
///
/// The embedder installs one through [`crate::ShellBuilder::script_interpreter`]. It
/// takes the script source and returns its outcome. Boxed and shared so the kernel can
/// hold it behind `&self`, and `Send + Sync` so a per-request Shell can carry it across
/// threads. It is the script counterpart of [`EgressProxy`](crate::EgressProxy): a
/// stated destination for a capability the Shell forwards rather than owns.
///
/// [`EgressProxy`]: crate::vfs_kernel::EgressProxy
pub type ScriptInterpreter = std::sync::Arc<dyn Fn(String) -> ScriptFuture + Send + Sync>;

/// The future a [`ScriptInterpreter`] hook returns: the pending [`ScriptOutcome`].
pub type ScriptFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<ScriptOutcome>> + Send>>;

/// The outcome of running a host binary through [`Kernel::spawn_host`].
///
/// The mirror of [`ScriptOutcome`] for the host-binary seam: a process-style status and the
/// captured streams. Buffered, not streamed — the hook runs the binary to completion and hands
/// back what it produced.
pub struct HostSpawnOutcome {
    /// The binary's process-style exit status.
    pub status: i32,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

/// A hook that runs a host binary for [`Kernel::spawn_host`].
///
/// The embedder installs one through [`crate::ShellBuilder::host_spawner`]. It takes the resolved
/// program, its arguments, and the working directory, and returns the outcome. The host-binary
/// counterpart of [`ScriptInterpreter`]: a stated destination for execution the Shell forwards
/// rather than owns, so an embedder can run the binary somewhere the Shell cannot — for
/// `strands-box`, inside a contained leaf box.
pub type HostSpawner = std::sync::Arc<dyn Fn(HostSpawn) -> HostSpawnFuture + Send + Sync>;

/// The future a [`HostSpawner`] hook returns: the pending [`HostSpawnOutcome`].
pub type HostSpawnFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<HostSpawnOutcome>> + Send>>;

/// One resolved host-binary spawn request handed to a [`HostSpawner`].
pub struct HostSpawn {
    /// The resolved absolute path of the program to run.
    pub program: std::path::PathBuf,
    /// The spelling the caller invoked the program by, made absolute, which the program reads as
    /// `argv[0]`.
    pub invoked: std::path::PathBuf,
    /// The program's arguments, in order.
    pub args: Vec<String>,
    /// The working directory the binary runs in.
    pub cwd: std::path::PathBuf,
    /// The composed environment the binary runs with. The built-in spawn applies exactly this,
    /// never the process's inherited environment; an embedder's hook may compose its own instead.
    pub env: Vec<(String, String)>,
}

// No `HttpTransport` seam. Routing the Shell's egress through a boundary is not a
// mechanism the Shell should own: a trait every embedding must wire up correctly is
// weaker than a proxy destination an operator can inspect, and it can route anywhere —
// including around the boundary it exists to enforce.
//
// It would also not be a forcing control where it matters. The Shell shim runs
// outside the Agent's containment domain, so a trusted process that can construct a
// direct client is not confined by configuration. So the box sets its egress gateway as
// the proxy destination, and calls `disable_network()` when it has no gateway.

/// Whether an operation acts on a symlink's target or on the link itself.
///
/// This is a property of the *operation*, not of the path, and getting it wrong is
/// exploitable in both directions: resolving a no-follow operation would authorize a
/// file the caller never touches, and failing to resolve a following one lets a
/// symlink launder a denied path.
///
/// | Disposition | Operations |
/// |---|---|
/// | [`Follow::Yes`] | `open`, `list_dir`, `change_dir`, `stat`, `access`, `canonicalize`, `is_executable`, `remove_dir`, `set_permissions` |
/// | [`Follow::No`] | `lstat`, `read_link`, `remove_file`, `create_dir`, the `rename` source and destination, the link side of `symlink` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    /// Act on what the link points at.
    Yes,
    /// Act on the link itself.
    No,
}

/// A filesystem identity produced by the kernel that owns it.
///
/// Constructible only by [`Kernel::resolve`], so a method accepting one has evidence
/// that resolution happened. That is the point: a `&str` parameter carries no such
/// evidence, which is why each method had to remember to resolve, and why one of them
/// did not.
///
/// The contained path is absolute and normalized. Whether a final symlink was
/// followed is recorded in [`Self::follow`], and must match the semantics of the
/// operation the token is passed to.
///
/// This is **not** a capability in the object-capability sense: it proves resolution,
/// not authorization. Admission is a separate step and the token records no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    path: String,
    follow: Follow,
    generation: u64,
    host_identity: Option<HostIdentity>,
}

/// The host object identity recorded by an earlier Shell release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectIdentity {
    /// The device number.
    pub dev: u64,
    /// The inode number.
    pub ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostIdentity {
    Present {
        path: PathBuf,
        parent: PathBuf,
        #[cfg(unix)]
        device: u64,
        #[cfg(unix)]
        inode: u64,
        #[cfg(unix)]
        parent_device: u64,
        #[cfg(unix)]
        parent_inode: u64,
    },
    Missing {
        path: PathBuf,
        parent: PathBuf,
        #[cfg(unix)]
        parent_device: u64,
        #[cfg(unix)]
        parent_inode: u64,
    },
    Unavailable {
        path: PathBuf,
    },
}

impl Resolved {
    /// Mint a token. Callable only inside this crate, by a [`Kernel::resolve`] impl.
    pub(crate) fn new(
        path: String,
        follow: Follow,
        generation: u64,
        host_identity: Option<HostIdentity>,
    ) -> Self {
        Self {
            path,
            follow,
            generation,
            host_identity,
        }
    }

    /// The resolved absolute path, for admission and diagnostics.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The symlink disposition this token was minted with.
    pub fn follow(&self) -> Follow {
        self.follow
    }

    /// The earlier host identity view, when this token is host-backed.
    pub fn binding(&self) -> Option<ObjectIdentity> {
        #[cfg(unix)]
        {
            match &self.host_identity {
                Some(HostIdentity::Present { device, inode, .. }) => Some(ObjectIdentity {
                    dev: *device,
                    ino: *inode,
                }),
                Some(HostIdentity::Missing {
                    parent_device,
                    parent_inode,
                    ..
                }) => Some(ObjectIdentity {
                    dev: *parent_device,
                    ino: *parent_inode,
                }),
                Some(HostIdentity::Unavailable { .. }) | None => None,
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn host_identity(&self) -> Option<&HostIdentity> {
        self.host_identity.as_ref()
    }
}

/// The core kernel abstraction. All methods take &self — the kernel is shared.
#[async_trait]
pub trait Kernel: Send + Sync {
    /// Resolve a caller-supplied path into the identity an operation will act on.
    ///
    /// The only constructor of [`Resolved`]. Applies the process working directory,
    /// normalizes `.` and `..`, and resolves every intermediate symlink. The final component is
    /// resolved only when `follow` is [`Follow::Yes`]. A dangling symlink that is resolved resolves to
    /// the path it names, and a path with too many symlinks keeps its spelling.
    ///
    /// A path whose leaf does not exist yet still resolves: existing ancestors are
    /// canonicalized and the missing remainder appended to that base. This is what
    /// makes a create authorize under its real parent, so
    /// `ln -s /secrets /alias; touch /alias/new` is judged as `/secrets/new`.
    ///
    /// Resolution answers *which object*, never *whether permitted* — admission is a
    /// separate step above this trait.
    async fn resolve(&self, proc: &Process, path: &str, follow: Follow) -> Resolved;

    fn new_process(&self) -> Process;
    async fn open(&self, proc: &mut Process, path: Resolved, flags: OpenFlags) -> io::Result<Fd>;
    async fn list_dir(&self, proc: &Process, path: Resolved) -> io::Result<Vec<DirEntry>>;
    async fn change_dir(&self, proc: &mut Process, path: Resolved) -> io::Result<()>;
    /// Stat a file (follows symlinks). Returns default (exists=false) on error.
    async fn stat(&self, proc: &Process, path: Resolved) -> FileStat;
    /// Stat a file (does not follow symlinks).
    async fn lstat(&self, proc: &Process, path: Resolved) -> FileStat;
    /// Check access permissions (ACCESS_R, ACCESS_W, ACCESS_X).
    async fn access(&self, proc: &Process, path: Resolved, mode: i32) -> bool;
    /// Canonicalize a path (resolve symlinks).
    async fn canonicalize(&self, proc: &Process, path: Resolved) -> io::Result<PathBuf>;
    /// Check if a path is an executable file.
    async fn is_executable(&self, proc: &Process, path: Resolved) -> bool;
    /// Expand a glob pattern relative to the process cwd. Returns sorted matches.
    async fn glob(&self, proc: &Process, pattern: &str) -> Vec<String>;
    /// Check if a file descriptor refers to a terminal.
    fn isatty(&self, fd: i32) -> bool;
    /// Remove a file.
    async fn remove_file(&self, proc: &Process, path: Resolved) -> io::Result<()>;
    /// Remove an empty directory.
    async fn remove_dir(&self, proc: &Process, path: Resolved) -> io::Result<()>;
    /// Create a directory.
    async fn create_dir(&self, proc: &Process, path: Resolved) -> io::Result<()>;
    /// Rename (move) a file or directory.
    async fn rename(&self, proc: &Process, from: Resolved, to: Resolved) -> io::Result<()>;
    /// Create a symbolic link at `link` pointing to `target`.
    /// Create the symlink `link` holding the literal text `target`.
    ///
    /// `target` is a `&str`, not a [`Resolved`]: it is *stored data*, not a path this
    /// call acts on. A relative link (`ln -s d /tmp/link`) must keep the spelling `d`
    /// so it resolves against the link's own directory later — absolutizing or
    /// resolving it here would silently rewrite the user's link. What a later read
    /// through the link authorizes is decided then, by `open`, on the resolved target.
    async fn symlink(&self, proc: &Process, target: &str, link: Resolved) -> io::Result<()>;
    /// Read the target of a symbolic link.
    async fn read_link(&self, proc: &Process, path: Resolved) -> io::Result<String>;
    /// Set Unix permission mode bits on a path.
    async fn set_permissions(&self, proc: &Process, path: Resolved, mode: u32) -> io::Result<()>;
    /// Return the current wall-clock time.
    fn now(&self) -> std::time::SystemTime;
    /// Wait until every write whose descriptors are all closed is visible, and report each that failed.
    async fn settle_writes(&self) -> Vec<WriteFailure>;
    /// Check whether a URL is allowed for network access.
    /// Returns Ok(()) if allowed, Err with a message if blocked.
    /// The SSRF floor: refuse a destination no policy may open.
    ///
    /// Deny-only, and **required** — it has no default body on purpose. A default of
    /// `Ok(())` would mean an implementer opts out of the floor by writing no code,
    /// which is the wrong direction for the one control that must hold
    /// unconditionally. Refuse link-local, loopback, RFC1918, and instance-metadata
    /// destinations; return `Ok(())` for anything else.
    ///
    /// This is not authorization. Reachability is decided above this trait.
    fn check_url(&self, url: &str) -> io::Result<()>;
    /// Send an HTTP request. The kernel handles SSRF protection and the actual
    /// network transport.
    async fn http_request(&self, _req: HttpRequest) -> io::Result<HttpResponse> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP not available",
        ))
    }

    /// Run a script through the embedder's out-of-Shell interpreter.
    ///
    /// The counterpart of [`http_request`](Self::http_request) for a scripted
    /// interpreter. The Shell does not interpret the source itself; it forwards it to a
    /// hook the embedder installs (for `strands-box`, the Python interpreter Monty). The
    /// default is `Unsupported`, so a Shell with no hook refuses rather than pretends —
    /// a `python` command over such a Shell reports that no interpreter is available.
    ///
    /// Raises no admission here: the command-level `shell:exec` already fired when the
    /// command resolved, and the script's own effects are judged by the interpreter the
    /// hook drives.
    async fn run_script(&self, _source: String) -> io::Result<ScriptOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "script interpreter not available",
        ))
    }

    /// Run a host binary the Shell does not implement.
    ///
    /// The counterpart of [`run_script`](Self::run_script) for a host binary. The default is
    /// `Unsupported`, so a Shell with no [`HostSpawner`] hook **refuses** rather than running the
    /// binary uncontained — mirroring `run_script`. An embedder installs a hook through
    /// [`crate::ShellBuilder::host_spawner`] to run it (for `strands-box`, inside a contained leaf
    /// box), or explicitly opts into the crate's built-in `fork`+`exec` with [`builtin_spawn_host`].
    /// Raises no admission here: the command-level `shell:spawn` already fired when the command
    /// resolved.
    async fn spawn_host(&self, _spawn: HostSpawn) -> io::Result<HostSpawnOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host-binary spawner not available",
        ))
    }
}

/// Run a host binary with the crate's built-in `fork`+`exec`, capturing its output.
///
/// The default behind [`Kernel::spawn_host`], and what a [`crate::vfs_kernel::VfsKernel`] with no
/// [`HostSpawner`] installed falls back to. The environment is exactly [`HostSpawn::env`] — cleared
/// first, never inherited — the working directory is [`HostSpawn::cwd`], `stdin` is null, and the
/// child is detached into a new session so it cannot suspend the caller by opening `/dev/tty`.
pub async fn builtin_spawn_host(spawn: HostSpawn) -> io::Result<HostSpawnOutcome> {
    let mut command = tokio::process::Command::new(&spawn.program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().arg0(&spawn.invoked);
    }
    command.args(&spawn.args);
    command.current_dir(&spawn.cwd);
    command.env_clear();
    for (key, value) in &spawn.env {
        command.env(key, value);
    }
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    // SAFETY: `setsid` is async-signal-safe, takes no arguments, and is the only action in the
    // child between fork and exec.
    unsafe {
        command.pre_exec(|| match libc::setsid() {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    let output = command.output().await?;
    Ok(HostSpawnOutcome {
        status: output.status.code().unwrap_or_else(|| {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                output.status.signal().map_or(128, |signal| 128 + signal)
            }
            #[cfg(not(unix))]
            {
                128
            }
        }),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
