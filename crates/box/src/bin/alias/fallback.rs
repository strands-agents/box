//! Ordinary program execution after an MCP non-match.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

pub(super) fn execute(program: &str, arguments: &[String]) -> io::Result<u8> {
    let image = std::env::current_exe()?;
    let image_identity = identity(&image)?;
    let alias_directory = image
        .parent()
        .ok_or_else(|| io::Error::other("alias has no directory"))?;
    let directory_identity = identity(alias_directory)?;
    let arguments = std::iter::once(program)
        .chain(arguments.iter().map(String::as_str))
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()?;
    let environment = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            CString::new(entry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let argv = pointers(&arguments);
    let envp = pointers(&environment);
    let mut refused = false;
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &directory
        };
        if identity(directory).ok() == Some(directory_identity) {
            continue;
        }
        let candidate = directory.join(program);
        match std::fs::metadata(&candidate) {
            Ok(metadata) => {
                if (metadata.dev(), metadata.ino()) == image_identity {
                    continue;
                }
                if !metadata.is_file() {
                    refused = true;
                    continue;
                }
            }
            Err(error) if missing(&error) => continue,
            Err(error) if denied(&error) => {
                refused = true;
                continue;
            }
            Err(error) => return execution_error(program, &error),
        }
        let candidate = CString::new(candidate.as_os_str().as_bytes())?;
        // Scripts require a shebang; no implicit shell runs.
        // SAFETY: the signal disposition is process-local and exec receives live, terminated arrays.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::execve(candidate.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        let error = io::Error::last_os_error();
        if missing(&error) {
            continue;
        }
        if denied(&error) {
            refused = true;
            continue;
        }
        // Unexpected execution errors stop the search.
        return execution_error(program, &error);
    }
    if refused {
        execution_error(program, &io::Error::from(io::ErrorKind::PermissionDenied))
    } else {
        eprintln!("strands-box: no ordinary executable for {program:?} on the agent's PATH");
        Ok(127)
    }
}

fn execution_error(program: &str, error: &io::Error) -> io::Result<u8> {
    eprintln!("strands-box: cannot execute ordinary program {program:?}: {error}");
    Ok(126)
}

fn identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn pointers(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

fn missing(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
}

fn denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}
