// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_trap<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        if args.len() < 2 {
            return Ok(0);
        }
        let action = &args[0];
        for sig in &args[1..] {
            if action == "-" {
                proc.traps.remove(sig.as_str());
            } else {
                proc.traps.insert(sig.to_uppercase(), action.clone());
            }
        }
        Ok(0)
    })
}
