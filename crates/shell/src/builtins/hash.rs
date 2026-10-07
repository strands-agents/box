// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::commands::CommandResult;
use crate::os::Process;
use crate::prelude::*;

pub fn builtin_hash<'a>(
    os: &'a Mediated,
    proc: &'a mut Process,
    args: &'a [String],
) -> Pin<Box<dyn Future<Output = CommandResult> + 'a>> {
    Box::pin(async move {
        if args.is_empty() {
            // List all hashed commands
            let mut w = io::stdout()?;
            let table = proc.hash_table.clone();
            if table.is_empty() {
                return Ok(0);
            }
            let mut entries: Vec<_> = table.iter().collect();
            entries.sort_by_key(|(k, _)| (*k).clone());
            for (name, path) in entries {
                wprintln!(w, "{name}={path}")?;
            }
            return Ok(0);
        }

        // Check for -r flag
        let mut names = Vec::new();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-r" => {
                    Arc::make_mut(&mut proc.hash_table).clear();
                }
                _ => names.push(&args[i]),
            }
            i += 1;
        }

        let mut status = 0;
        for name in names {
            match os.find_in_path(proc, name).await {
                Some(path) => {
                    Arc::make_mut(&mut proc.hash_table).insert(name.clone(), path);
                }
                None => {
                    proc.err_msg(&format!("strands-shell: hash: {name}: not found"));
                    status = 1;
                }
            }
        }
        Ok(status)
    })
}
