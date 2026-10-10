// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: dirname NAME
Strip last component from NAME.";

#[command("dirname")]
async fn cmd_dirname(_os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut name = None;
    while let Some(arg) = parser.next()? {
        match arg {
            Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Value(val) if name.is_none() => name = Some(val.string()?),
            _ => return Err(arg.unexpected().into()),
        }
    }
    let name = name.ok_or("dirname: missing operand")?;
    let trimmed = name.trim_end_matches('/');
    let dir = if trimmed.is_empty() && !name.is_empty() {
        "/"
    } else {
        match trimmed.rfind('/') {
            Some(i) => {
                let prefix = trimmed[..i].trim_end_matches('/');
                if prefix.is_empty() { "/" } else { prefix }
            }
            None => ".",
        }
    };
    let mut w = io::stdout()?;
    wprintln!(w, "{}", dir)?;
    Ok(0)
}
