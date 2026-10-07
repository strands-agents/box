// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_unset<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        let mut func_mode = false;
        let mut names = Vec::new();
        let mut options_ended = false;
        for a in args {
            match a.as_str() {
                "--" if !options_ended => options_ended = true,
                "-f" if !options_ended => func_mode = true,
                "-v" if !options_ended => func_mode = false,
                _ => names.push(a.as_str()),
            }
        }
        for name in names {
            if func_mode {
                proc.unset_function(name);
            } else {
                proc.unset_env(name);
            }
        }
        Ok(0)
    })
}
