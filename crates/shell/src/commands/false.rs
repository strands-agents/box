// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

#[command("false")]
async fn cmd_false(_os: &Mediated, _args: &[String]) -> CommandResult {
    Ok(1)
}
