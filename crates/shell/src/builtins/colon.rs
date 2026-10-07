// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_colon<'a>(
    _os: &'a Mediated,
    _proc: &'a mut Process,
    _args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move { Ok(0) })
}

pub fn builtin_false<'a>(
    _os: &'a Mediated,
    _proc: &'a mut Process,
    _args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move { Ok(1) })
}
