// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_local<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        for arg in args {
            if let Some(eq) = arg.find('=') {
                proc.set_local(&arg[..eq], &arg[eq + 1..]);
            } else {
                proc.declare_local(arg);
            }
        }
        Ok(0)
    })
}
