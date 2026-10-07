// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::os::Process;
use crate::prelude::*;

pub fn builtin_umask<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        if args.is_empty() {
            let mut w = io::stdout()?;
            wprintln!(w, "{:04o}", proc.umask)?;
        } else {
            let val = u32::from_str_radix(&args[0], 8).map_err(
                |_| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("umask: '{}': invalid octal number", args[0]).into()
                },
            )?;
            proc.umask = val & 0o777;
        }
        Ok(0)
    })
}
