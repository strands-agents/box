// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

pub use strands_shell_macros::command;
pub use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub use crate::commands::CommandResult;
pub use crate::io;
pub use crate::mediate::Mediated;
pub use crate::os::OpenFlags;
pub use crate::{wprint, wprintln};

/// Re-export lexopt for argument parsing in commands.
pub use lexopt;
pub use lexopt::prelude::*;
