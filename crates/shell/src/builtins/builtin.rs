use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

/// Run the named builtin, bypassing any function or alias of the same name.
pub fn builtin_builtin<'a>(
    os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        let Some(name) = args.first() else {
            return Ok(0);
        };
        match super::lookup(name) {
            Some(f) => f(os, proc, &args[1..]).await,
            None => {
                proc.err_msg(&format!(
                    "strands-shell: builtin: {name}: not a shell builtin"
                ));
                Ok(1)
            }
        }
    })
}
