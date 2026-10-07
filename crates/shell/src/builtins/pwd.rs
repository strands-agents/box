// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::os::Process;
use crate::prelude::*;

pub fn builtin_pwd<'a>(
    os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        let mut physical = false;
        for arg in args {
            match arg.as_str() {
                "-L" => physical = false,
                "-P" => physical = true,
                _ => {
                    proc.err_msg(&format!("strands-shell: pwd: bad option: {arg}"));
                    return Ok(2);
                }
            }
        }
        let mut w = io::stdout()?;
        if physical {
            match os.canonicalize(proc, ".").await {
                Ok(p) => wprintln!(w, "{}", p.display())?,
                Err(_) => wprintln!(w, "{}", proc.cwd.display())?,
            }
        } else {
            wprintln!(w, "{}", proc.cwd.display())?;
        }
        Ok(0)
    })
}
