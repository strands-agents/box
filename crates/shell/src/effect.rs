//! Policy-neutral interception of submitted Shell effects.

use std::io;

use async_trait::async_trait;

/// One filesystem operation, at the granularity policy authorizes it.
///
/// The distinctions here are load-bearing rather than cosmetic. Reading content is
/// separate from reading metadata because metadata is the enumeration channel;
/// following symlinks is recorded because a no-follow probe before a delete is a
/// symlink-escape defense; creation and truncation are called out because they
/// mutate at open time rather than when bytes are written.
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
///
/// Both identities are authorized together: a policy that permits reading `from`
/// does not thereby permit creating `to`.
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

/// A submitted Shell operation presented for admission.
///
/// Filesystem paths are the **resolved absolute virtual path**, produced after the
/// kernel applied the process working directory and normalization. They are not the
/// caller's spelling: authorizing a caller-supplied string and letting the kernel
/// resolve it separately would leave a window between the decision and the effect.
#[derive(Debug)]
#[non_exhaustive]
pub enum EffectAttempt<'a> {
    /// One **resolved** command, whose program this Shell implements.
    ///
    /// Raised once per pipeline stage, from the single resolution point every command
    /// reaches: after parsing, after expansion, and after the first word has been looked
    /// up in the builtin, function, and command registries. Admission for every stage of a
    /// pipeline happens before any stage runs, so a refusal in one stage stops the whole
    /// pipeline rather than letting an earlier stage's effect land first.
    ///
    /// This replaces an earlier attempt that carried the submitted command *text* before
    /// parsing. That text was the only fact available at that point, and one effect has
    /// many spellings, so a rule could only pattern-match a string. The two facts a rule
    /// needs — which program will run, and from which directory — exist only here.
    ShellRun {
        /// The canonical command line, reconstructed from the expanded words.
        ///
        /// **Not the submitted spelling.** `X=rm; $X -rf /data` arrives here as
        /// `rm -rf /data`, which is the point: a decision is about what runs, not about how
        /// it was written. Quoting, an alias, and a variable all collapse into this form.
        command: &'a str,
        /// The program the first word resolved to, after any alias and any multicall or
        /// shebang rewrite. Carries the first word unchanged when nothing resolved.
        program: &'a str,
        /// The expanded arguments, without the program.
        args: &'a [String],
        /// Whether each argument's word was literal in the script, aligned with `args` by index.
        ///
        /// An interceptor that reports a command needs this: a literal word is already in a file the
        /// operator can read, and an expanded one carries a value that arrived at runtime.
        literal: &'a [bool],
        /// The working directory the command will run in.
        cwd: &'a str,
    },
    /// One resolved command handed to a **host binary** — a program this Shell does not
    /// implement, executed inside the containment domain.
    ///
    /// Raised when a host binary runs through the passthrough path. A `permit` naming it
    /// grants more than it appears to: the binary reaches the kernel rather than this Shell's
    /// VFS, so no filesystem attempt is raised for anything it does, and its children inherit
    /// containment while raising no attempt of their own.
    ShellSpawn {
        /// The canonical command line, reconstructed from the expanded words.
        command: &'a str,
        /// The program name as resolved.
        program: &'a str,
        /// The absolute path of the binary that will execute.
        ///
        /// The exec must use **this** value rather than re-resolving through `PATH`.
        /// Resolving twice reopens the gap between the decision and the effect.
        program_path: &'a str,
        /// The expanded arguments, without the program.
        args: &'a [String],
        /// Whether each argument's word was literal in the script, aligned with `args` by index.
        literal: &'a [bool],
        /// The working directory the command will run in.
        cwd: &'a str,
    },
    /// One filesystem operation on one resolved path.
    Filesystem {
        /// The resolved absolute virtual path this operation acts on.
        path: &'a str,
        /// The operation being attempted.
        operation: FsOperation,
    },
    /// One filesystem operation relating two resolved paths.
    FilesystemPair {
        /// The resolved absolute source path.
        from: &'a str,
        /// The resolved absolute target path.
        to: &'a str,
        /// The operation being attempted.
        operation: FsPairOperation,
    },
}

// No network variant. The Shell does not authorize egress.
//
// An outbound request is authorized at the egress boundary the workload is confined
// to — the proxy — with the host/port/method/path/body vocabulary such a decision
// needs.
// A second admission here would be a second network authority: two decisions, two
// audit streams, and a coarser one (method plus URL string) able to permit what the
// finer one refused.
//
// What remains in the kernel are the two non-authorization controls: the embedder's
// blanket `network_enabled` switch and the SSRF floor, both deny-only and both
// unconditional. Credentials are likewise absent — the Shell holds none.

/// The result of an effect that received a permit and was executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectOutcome {
    /// Reported status of one top-level Shell command invocation.
    ///
    /// A command that uses the background connector (`&`) reports launch
    /// status before its child job completes.
    ShellCommand {
        /// The command invocation's reported status.
        reported_status: i32,
    },
    /// How one admitted kernel effect ended.
    Kernel(EffectResult),
}

/// How one admitted kernel effect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EffectResult {
    /// The operation completed and its whole effect has happened.
    Completed,
    /// A descriptor was issued; the transfer it enables has not happened yet.
    ///
    /// This is the honest outcome for an open. The caller may then read or write
    /// any number of bytes — including none — outside the admitted call, so a
    /// consumer must not read this as bytes transferred or a write committed.
    DescriptorIssued,
    /// The operation was attempted and failed without its effect happening.
    ///
    /// This covers a refusal by a control *below* policy as well as an ordinary
    /// failure: a read-only bind mount, a permission check, a size or inode cap, and
    /// the SSRF floor all report [`io::ErrorKind::PermissionDenied`] here. Those floors
    /// hold regardless of any policy allow, but the seam does not currently distinguish
    /// them from other failures — a consumer that needs that distinction cannot get it
    /// from this value alone.
    Failed(io::ErrorKind),
    /// An admitted effect ended without any terminal outcome being recorded.
    ///
    /// Produced when a permit is dropped rather than reported — a cancelled future, or
    /// a path out that did not reach its reporting point. It means "unknown", not
    /// "did not happen".
    Indeterminate,
}

/// Intercepts a submitted effect before the Shell executes it.
///
/// Returning an error prevents the effect. Use
/// [`io::ErrorKind::PermissionDenied`] for an authorization denial; other error
/// kinds identify an interceptor failure and also fail closed.
#[async_trait]
pub trait EffectInterceptor: Send + Sync {
    /// Obtain the permit that must be consumed after this invocation reports.
    ///
    /// If this future is cancelled after the implementation reserves state but
    /// before it returns a permit, the implementation is responsible for
    /// reconciling that reservation.
    async fn intercept(&self, effect: &EffectAttempt<'_>) -> io::Result<Box<dyn EffectPermit>>;
}

/// Correlates one admitted effect with its eventual outcome.
#[async_trait]
pub trait EffectPermit: Send {
    /// Record the outcome after the admitted effect has executed.
    ///
    /// An error cannot undo an already-completed effect. The Shell reports it
    /// as an outcome-recording failure rather than as an authorization denial.
    ///
    /// This method consumes the permit. Once it is called, the Shell will not
    /// call [`Self::mark_indeterminate`], even if this future is cancelled.
    /// Implementations must arrange cancellation-safe delivery before their
    /// first suspension point or reconcile a cancelled recording themselves.
    async fn record_outcome(self: Box<Self>, outcome: EffectOutcome) -> io::Result<()>;

    /// Mark an admitted effect whose execution future ended without an outcome.
    ///
    /// This method consumes the permit and must not block. A remote
    /// implementation can enqueue an indeterminate outcome for its coordinator.
    fn mark_indeterminate(self: Box<Self>);
}

/// Holds one claimed kernel permit so every early exit marks it indeterminate.
///
/// The kernel's mediated methods have many `?` returns between admission and the
/// effect. Carrying the permit in this guard makes "reported exactly once" the
/// default: recording consumes it, and any other path out — including a cancelled
/// future — marks it indeterminate on drop.
pub(crate) struct KernelPermit {
    permit: Option<Box<dyn EffectPermit>>,
}

impl KernelPermit {
    /// Wrap a permit obtained from an interceptor.
    pub(crate) fn new(permit: Box<dyn EffectPermit>) -> Self {
        Self {
            permit: Some(permit),
        }
    }

    /// A guard for an unmediated call, which reports nothing.
    pub(crate) fn absent() -> Self {
        Self { permit: None }
    }

    /// Report how the admitted effect ended.
    ///
    /// An outcome-recording failure cannot undo an effect that already happened,
    /// so it is surfaced to the caller rather than converted into a denial.
    pub(crate) async fn record(mut self, result: EffectResult) -> io::Result<()> {
        match self.permit.take() {
            Some(permit) => permit.record_outcome(EffectOutcome::Kernel(result)).await,
            None => Ok(()),
        }
    }
}

impl Drop for KernelPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            permit.mark_indeterminate();
        }
    }
}
