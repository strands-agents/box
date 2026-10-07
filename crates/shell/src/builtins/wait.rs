// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;

use crate::commands::CommandResult;
use crate::mediate::Mediated;
use crate::os::Process;

pub fn builtin_wait<'a>(
    _os: &'a Mediated,
    proc: &'a mut Process,
    _args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        let mut last = 0;
        let jobs = std::mem::take(&mut proc.bg_jobs);
        for handle in jobs {
            let (code, stdout, stderr) = handle.await.unwrap_or((1, String::new(), String::new()));
            last = code;
            if proc.capture
                && (!proc.append_captured_output(&stdout) || !proc.append_captured_stderr(&stderr))
            {
                last = 1;
            }
        }
        proc.last_exit = last;
        Ok(last)
    })
}
