// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_shift<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        let n: usize = if args.is_empty() {
            1
        } else {
            args[0].parse().unwrap_or(1)
        };
        if n > proc.args.len() {
            return Ok(1);
        }
        proc.args.drain(..n);
        Ok(0)
    })
}
