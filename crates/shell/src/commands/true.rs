// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

#[command("true")]
async fn cmd_true(_os: &Mediated, _args: &[String]) -> CommandResult {
    Ok(0)
}
