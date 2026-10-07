//! The [`Request`] enum — the single value a PEP hands the PDP.

use std::net::IpAddr;

use crate::path::ApprovedPath;

pub(crate) const DEFAULT_PRINCIPAL_ID: &str = "self";

/// Integration metadata for the fixed `Box::Agent::"self"` policy principal.
///
/// Every value maps to the same policy identity. The action identifies the boundary operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    id: String,
}

impl Principal {
    /// Construct the default `Box::Agent::"self"` principal.
    pub fn agent() -> Self {
        Self {
            id: DEFAULT_PRINCIPAL_ID.to_string(),
        }
    }

    /// Set the integration identifier.
    ///
    /// Policy evaluation still uses `Box::Agent::"self"`.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Return the integration identifier.
    pub fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The customer-altitude filesystem verb an operation authorizes — the Cedar actions
/// `fs:read`, `fs:write`, `fs:delete`, and `fs:move`
/// (docs/design/decisions.md#filesystem-authorization-uses-four-verbs-and-a-catch-all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAccess {
    /// Reads: content, metadata, enumeration, link targets, working directory, and the
    /// executability probe.
    Read,
    /// Mutations that are not a removal or a move: content writes, directory creation,
    /// permission changes, and symlink creation.
    Write,
    /// Removal of a file or directory.
    Delete,
    /// Rename or move of a path.
    Move,
}

/// The exact filesystem operation a PEP is attempting — and the action it authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsOperation {
    /// Open to read file content.
    ReadContent,
    /// Open to write file content, including an open that creates or truncates.
    WriteContent,
    /// Read attributes without reading content, following a final symlink or not.
    ReadMetadata,
    /// List a directory or expand a pattern within it.
    Enumerate,
    /// Test whether a path may be executed.
    ExecFile,
    /// Remove a file.
    RemoveFile,
    /// Remove an empty directory.
    RemoveDir,
    /// Create a directory.
    CreateDir,
    /// Replace Unix permission bits.
    SetPermissions,
    /// Make a directory the process working directory.
    ChangeDir,
    /// Read a symlink's target without following it.
    ReadLink,
    /// Rename or move a path.
    Rename,
    /// Create a symlink.
    Symlink,
    /// An operation this vocabulary does not name.
    Other,
}

impl FsOperation {
    /// The stable string a rule matches on `context.input.operation`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FsOperation::ReadContent => "read_content",
            FsOperation::WriteContent => "write_content",
            FsOperation::ReadMetadata => "read_metadata",
            FsOperation::Enumerate => "enumerate",
            FsOperation::ExecFile => "exec",
            FsOperation::RemoveFile => "remove_file",
            FsOperation::RemoveDir => "remove_dir",
            FsOperation::CreateDir => "create_dir",
            FsOperation::SetPermissions => "set_permissions",
            FsOperation::ChangeDir => "change_dir",
            FsOperation::ReadLink => "read_link",
            FsOperation::Rename => "rename",
            FsOperation::Symlink => "symlink",
            FsOperation::Other => "other",
        }
    }

    /// The customer-altitude verb this operation authorizes.
    ///
    /// This mirrors the action mapping in `schema::fs_action_id`. [`FsAccess`] names only
    /// the four verbs, so an operation the four do not name — `Other`, which authorizes
    /// `fs:other` — has no verb here and is reported as the most conservative mutation,
    /// [`FsAccess::Write`]. The authoritative action mapping is `schema::fs_action_id`,
    /// which keeps `fs:other` distinct.
    #[must_use]
    pub fn access(self) -> FsAccess {
        match self {
            FsOperation::ReadContent
            | FsOperation::ReadMetadata
            | FsOperation::Enumerate
            | FsOperation::ReadLink
            | FsOperation::ChangeDir
            | FsOperation::ExecFile => FsAccess::Read,
            FsOperation::WriteContent
            | FsOperation::CreateDir
            | FsOperation::Symlink
            | FsOperation::SetPermissions => FsAccess::Write,
            FsOperation::RemoveFile | FsOperation::RemoveDir => FsAccess::Delete,
            FsOperation::Rename => FsAccess::Move,
            // `fs:other` has no customer verb; report the conservative mutation.
            FsOperation::Other => FsAccess::Write,
        }
    }
}

/// The single value a PEP hands the PDP for one authorization question.
#[derive(Debug)]
pub enum Request<'a> {
    /// Filesystem access. The `operation` selects the coarse action a rule names
    /// (`fs:read`, `fs:write`, `fs:delete`, `fs:move`, or `fs:other`) and rides
    /// `context.input.operation` so a rule can narrow within an action.
    Fs {
        /// The canonical target path, as a resolver approved it.
        ///
        /// The type carries the claim. This field once took a `&Path` and stated
        /// the same thing in prose, and the prose was false for one of its two callers:
        /// the Shell adapter built the request from a raw string and canonicalized
        /// nothing. An [`ApprovedPath`] has no public constructor, so a raw spelling now
        /// fails to compile instead of passing a check that was never run.
        path: &'a ApprovedPath,
        /// The exact operation being attempted. Selects the action, and is reported on
        /// `context.input.operation`.
        operation: FsOperation,
    },
    /// L4 TCP connect (`net:connect`) — the durable floor that holds even against an
    /// agent that links its own TLS. Distinct from [`Request::Http`].
    Connect {
        /// Destination host as resolved/observed by the PEP.
        host: &'a str,
        /// Destination IP when the PEP has pinned one (DNS-rebind defense lives below
        /// the PDP as a compiled floor).
        ip: Option<IpAddr>,
        /// Destination port.
        port: u16,
    },
    /// L7 HTTP request (`http:request`) — a cooperating-agent control on top of the L4
    /// floor.
    ///
    /// The reply raises no request: it rides the same action's one `::response` as
    /// `output.status`, so there is no `ResponseRelease` variant.
    Http {
        /// Destination host.
        host: &'a str,
        /// Destination port.
        port: u16,
        /// HTTP method (`GET`, `POST`, …).
        method: &'a str,
        /// Request path.
        path: &'a str,
        /// Request body length without body content.
        body_bytes: usize,
        /// Whether the request was seen through TLS interception (vs. tunneled).
        intercepted: bool,
    },
    /// One MCP request, with per-tool actions for `tools/call` and `mcp:call` for other methods.
    McpCall {
        /// Trusted server name from operator configuration.
        server: &'a str,
        /// The JSON-RPC method (`tools/call`, `prompts/get`, `resources/read`, `tools/list`, …).
        method: &'a str,
        /// The tool the call names, for `tools/call`.
        tool: Option<&'a str>,
        /// The prompt the call names, for `prompts/get`.
        prompt: Option<&'a str>,
        /// The resource URI the call names, for `resources/read`.
        uri: Option<&'a str>,
        /// Raw `tools/call` arguments that select and type the per-tool action.
        arguments: Option<&'a serde_json::Value>,
    },

    /// One resolved command line whose program the Shell implements (`shell:exec`).
    ShellExec {
        /// The submitted text, carried through so one rule can read both.
        command: &'a str,
        /// The program the first word **resolved** to, not how it was spelled. An alias
        /// makes the two differ, and `alias` raises no decision of its own.
        program: &'a str,
        /// The command's arguments, after expansion, without the program.
        ///
        /// `arg1`/`arg2` and `arg_count` are derived from this. The slice is not itself
        /// reported, because Cedar's only collection is an unordered `Set` with no index
        /// operator, so a rule could not read a position out of it.
        args: &'a [String],
        /// The working directory the line runs in. Required, because most arguments are
        /// relative and identical arguments name different files from different
        /// directories.
        cwd: &'a str,
    },
    /// One resolved command line handed to a host binary (`shell:spawn`).
    ///
    /// **Permitting this grants more than it appears to.** The binary runs against the
    /// kernel rather than the Shell's VFS, so no `fs:*` decision fires for anything it
    /// does, and its children inherit containment while raising no decision of their own.
    ShellSpawn {
        /// The submitted text.
        command: &'a str,
        /// The program name as resolved.
        program: &'a str,
        /// The spelling a rule reads for the binary that will execute: home-relative under the
        /// operator's home, canonical elsewhere. The effect runs against the identity the Shell
        /// decided, never against this value and never against a re-resolution through `PATH`.
        program_path: &'a str,
        /// Exact credential path spellings this leaf receives.
        credential_reads: &'a [String],
        /// The command's arguments, after expansion, without the program.
        args: &'a [String],
        /// The working directory the line runs in.
        cwd: &'a str,
    },
}

impl Request<'_> {
    /// What the action named, as a raw observer spells it.
    ///
    /// A reported path for `fs:*`, a host and port for a destination, `server/tool` for a tool
    /// call, and the resolved program for a command. **A path is the `reported()` spelling**, so
    /// a record from one machine reads the same as the rule that decided it.
    ///
    /// This is a label, never an authority. Nothing may resolve it back into a path and act on
    /// it: the value an effect acts on is [`ApprovedPath::as_path`].
    #[must_use]
    pub(crate) fn resource(&self) -> String {
        match self {
            Request::Fs { path, .. } => path.reported().into_owned(),
            Request::Connect { host, port, .. } => format!("{host}:{port}"),
            Request::Http {
                host, port, path, ..
            } => format!("{host}:{port}{path}"),
            Request::McpCall {
                server,
                method,
                tool,
                prompt,
                uri,
                ..
            } => {
                let item = tool.or(*prompt).or(*uri).unwrap_or(method);
                format!("{server}/{item}")
            }
            Request::ShellExec { program, .. } => (*program).to_string(),
            // The reported spelling of the decided binary, as `context.input.program_path` reads it.
            Request::ShellSpawn { program_path, .. } => (*program_path).to_string(),
        }
    }
}

/// How many arguments a resolved command line carries, clamped for the engine's `Long`.
///
/// Saturating rather than wrapping, and in the direction that can only make a rule more
/// likely to deny: a wrapped count could turn a very long line into a short one and slip
/// under a rule that refuses an unexpected shape.
pub(crate) fn arg_count(args: &[String]) -> i64 {
    i64::try_from(args.len()).unwrap_or(i64::MAX)
}
