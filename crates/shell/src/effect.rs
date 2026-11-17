use std::io;

use async_trait::async_trait;

/// One filesystem operation, at the granularity a decision names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsOperation {
    /// Open to read file content.
    ReadContent,
    /// Open to write file content.
    WriteContent {
        /// Whether a missing file is created by this open.
        create: bool,
        /// Whether existing content is discarded by this open.
        truncate: bool,
    },
    /// Read attributes without reading content.
    ReadMetadata {
        /// Whether a final symlink is followed to its target.
        follow_symlinks: bool,
    },
    /// List a directory or expand a pattern within it.
    Enumerate,
    /// Test whether a path may be executed.
    Exec,
    /// Ask whether a `PATH` candidate is an executable file.
    Locate,
    /// Remove a file.
    RemoveFile,
    /// Remove an empty directory.
    RemoveDir,
    /// Create a directory.
    CreateDir,
    /// Replace Unix permission bits.
    SetPermissions {
        /// The requested mode bits.
        mode: u32,
    },
    /// Make a directory the process working directory.
    ChangeDir,
    /// Read a symlink's target without following it.
    ReadLink,
}

/// One filesystem operation over two paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsPairOperation {
    /// Move or rename `from` onto `to`.
    Rename {
        /// Whether a name is bound at `to`, so this rename replaces it.
        destination_exists: bool,
        /// Whether the object bound at `to` is a directory.
        destination_is_dir: bool,
    },
    /// Create the symlink `to` pointing at `from`.
    Symlink,
}

/// One effect presented for a decision, on resolved absolute paths.
#[derive(Debug)]
#[non_exhaustive]
pub enum EffectAttempt<'a> {
    /// One resolved command whose program the Shell implements.
    ShellRun {
        /// The program and its expanded arguments as one line.
        command: &'a str,
        /// The program the first word resolved to.
        program: &'a str,
        /// The expanded arguments, without the program.
        args: &'a [String],
        /// Whether each argument was literal in the script, aligned with `args`.
        literal: &'a [bool],
        /// The working directory the command runs in.
        cwd: &'a str,
    },
    /// One resolved command that a host binary runs.
    ShellSpawn {
        /// The program and its expanded arguments as one line.
        command: &'a str,
        /// The program name as resolved.
        program: &'a str,
        /// The absolute path of the binary that runs.
        program_path: &'a str,
        /// The expanded arguments, without the program.
        args: &'a [String],
        /// Whether each argument was literal in the script, aligned with `args`.
        literal: &'a [bool],
        /// The working directory the command runs in.
        cwd: &'a str,
    },
    /// One filesystem operation on one resolved path.
    Filesystem {
        /// The resolved absolute path.
        path: &'a str,
        /// The operation.
        operation: FsOperation,
    },
    /// One filesystem operation relating two resolved paths.
    FilesystemPair {
        /// The resolved absolute source path, or a symlink's target text.
        from: &'a str,
        /// The resolved absolute target path.
        to: &'a str,
        /// The operation.
        operation: FsPairOperation,
    },
}

/// How an admitted effect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectOutcome {
    /// The status of one command.
    ShellCommand {
        /// The command's reported status.
        reported_status: i32,
    },
    /// How one filesystem effect ended.
    Kernel(EffectResult),
}

/// How one admitted filesystem effect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectResult {
    /// The whole effect happened.
    Completed,
    /// A descriptor was issued; no transfer has happened yet.
    DescriptorIssued,
    /// The effect was attempted and did not happen.
    Failed(io::ErrorKind),
    /// The effect ended with no recorded outcome.
    Indeterminate,
}

/// Decides an attempt before the Shell performs it.
#[async_trait]
pub trait EffectInterceptor: Send + Sync {
    /// The permit an admitted attempt owes, or the refusal; `PermissionDenied` is a denial.
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>>;
}

/// Correlates one admitted effect with its outcome.
#[async_trait]
pub trait EffectPermit: Send {
    /// The absolute directory a spawn's decision checked, or `None` to keep the caller's.
    fn spawn_working_directory(&self) -> Option<&std::path::Path> {
        None
    }

    /// Record how the effect ended.
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()>;

    /// Record an effect that ended with no outcome. It must not block.
    fn mark_indeterminate(self: Box<Self>);
}
