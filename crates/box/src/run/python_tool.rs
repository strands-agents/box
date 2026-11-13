//! The checks Box makes on a call to the Python tool, the `[tool.python3]` or `[tool.python]` table
//! a bare `python3` or `python` runs when `monty = false`.
//!
//! A program the Shell starts can't read its input yet. So Box refuses a call that would read its
//! program from stdin, and says so when a call whose stdin carried data fails.

use std::io;

/// The reason a call that would read its program from stdin is refused. The Shell prints it and
/// exits 126.
pub(crate) const PROGRAM_FROM_STDIN: &str =
    "python3 would read its program from stdin, which a program the Shell starts can't receive yet";

/// Whether `table` is one of the two Python tool tables.
pub(crate) fn is_python_table(table: &str) -> bool {
    crate::record::config::PYTHON_TABLES.iter().any(|name| {
        table
            .strip_prefix("[tool.")
            .and_then(|rest| rest.strip_suffix(']'))
            == Some(*name)
    })
}

/// The line Box adds to stderr when a call whose stdin carried data exits non-zero.
pub(crate) fn no_stdin_line(name: &str) -> String {
    format!(
        "strands-box: {name} got no stdin: a program the Shell starts can't read its input yet\n"
    )
}

/// Refuse a call whose arguments make Python read its program from stdin.
pub(crate) fn refuse_program_from_stdin(args: &[String]) -> io::Result<()> {
    if reads_program_from_stdin(args) {
        return Err(io::Error::other(PROGRAM_FROM_STDIN));
    }
    Ok(())
}

/// Short options whose value is the rest of the word or the next argument.
const SHORT_WITH_VALUE: &[char] = &['c', 'm', 'W', 'X'];
/// Short options that take no value. `-OO` is two `O`s.
const SHORT_FLAGS: &[char] = &[
    'b', 'B', 'd', 'E', 'h', 'i', 'I', 'O', 'P', 'q', 'R', 's', 'S', 'u', 'v', 'V', 'x',
];
/// Long options that print and exit without running a program.
const LONG_INFO: &[&str] = &[
    "--version",
    "--help",
    "--help-env",
    "--help-xoptions",
    "--help-all",
];

/// What the arguments make Python run.
#[derive(Debug, PartialEq, Eq)]
enum Program {
    /// `-c`, `-m`, or a script file.
    Named,
    /// `-` as the first operand, or no program at all.
    Stdin,
    /// An option Python prints and exits on, or one it rejects. Either way it reads no program.
    None,
}

/// Whether Python would read its program from stdin.
fn reads_program_from_stdin(args: &[String]) -> bool {
    let mut info = false;
    let program = scan(args, &mut info);
    // `-V` and `-h` print and exit before Python reads any program.
    !info && program == Program::Stdin
}

fn scan(args: &[String], info: &mut bool) -> Program {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            return match args.next() {
                Some(operand) if operand == "-" => Program::Stdin,
                Some(_) => Program::Named,
                None => Program::Stdin,
            };
        }
        if arg == "-" {
            return Program::Stdin;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            if LONG_INFO.contains(&arg.as_str()) {
                *info = true;
            } else if name == "check-hash-based-pycs" {
                if value.is_none() && args.next().is_none() {
                    return Program::None;
                }
            } else {
                // Python rejects an option it doesn't know, before it reads a program.
                return Program::None;
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-') else {
            return Program::Named;
        };
        for (at, option) in cluster.char_indices() {
            if SHORT_WITH_VALUE.contains(&option) {
                let rest = &cluster[at + option.len_utf8()..];
                if rest.is_empty() && args.next().is_none() {
                    // `Argument expected for the -c option`: Python exits 2.
                    return Program::None;
                }
                if matches!(option, 'c' | 'm') {
                    return Program::Named;
                }
                break;
            }
            if !SHORT_FLAGS.contains(&option) {
                return Program::None;
            }
            if matches!(option, 'h' | 'V') {
                *info = true;
            }
        }
    }
    Program::Stdin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(args: &[&str]) -> bool {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        refuse_program_from_stdin(&args).is_err()
    }

    #[test]
    fn python_tool_refuses_no_program() {
        assert!(refused(&[]));
        assert!(refused(&["-u"]));
        assert!(refused(&["-I", "-B", "-OO"]));
        assert!(refused(&["-i"]));
        assert!(refused(&["-W", "ignore"]));
        assert!(refused(&["-Wignore", "-X", "utf8"]));
        assert!(refused(&["--check-hash-based-pycs", "never"]));
        assert!(refused(&["--check-hash-based-pycs=always"]));
        assert!(refused(&["-E", "--"]));
    }

    #[test]
    fn python_tool_refuses_a_dash_program() {
        assert!(refused(&["-"]));
        assert!(refused(&["-", "arg"]));
        assert!(refused(&["-u", "-"]));
        assert!(refused(&["-X", "dev", "-"]));
        assert!(refused(&["--", "-"]));
        assert!(refused(&["-IsB", "-"]));
    }

    #[test]
    fn python_tool_passes_a_named_program() {
        assert!(!refused(&["script.py"]));
        assert!(!refused(&["script.py", "-"]));
        assert!(!refused(&["-u", "script.py"]));
        assert!(!refused(&["-c", "print(1)"]));
        assert!(!refused(&["-cprint(1)"]));
        assert!(!refused(&["-Ic", "print(1)"]));
        assert!(!refused(&["-m", "pytest", "-"]));
        assert!(!refused(&["-mpytest"]));
        assert!(!refused(&["-W", "-", "x.py"]));
        assert!(!refused(&["-X", "-", "-c", "pass"]));
        assert!(!refused(&["--", "x.py"]));
        assert!(!refused(&["--check-hash-based-pycs", "-", "x.py"]));
    }

    #[test]
    fn python_tool_passes_version_and_help() {
        for args in [
            &["--version"][..],
            &["-V"],
            &["-VV"],
            &["-h"],
            &["--help"],
            &["--help-all"],
            &["-I", "-V"],
            &["-V", "-"],
        ] {
            assert!(!refused(args), "{args:?}");
        }
    }

    #[test]
    fn python_tool_passes_what_python_rejects_itself() {
        assert!(!refused(&["-c"]));
        assert!(!refused(&["-m"]));
        assert!(!refused(&["-W"]));
        assert!(!refused(&["-Z"]));
        assert!(!refused(&["--no-such-option"]));
        assert!(!refused(&["--check-hash-based-pycs"]));
    }

    #[test]
    fn python_tool_refusal_names_the_reason() {
        let error = refuse_program_from_stdin(&[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "python3 would read its program from stdin, which a program the Shell starts can't receive yet"
        );
    }

    #[test]
    fn python_tool_tables_are_python3_and_python() {
        assert!(is_python_table("[tool.python3]"));
        assert!(is_python_table("[tool.python]"));
        assert!(!is_python_table("[tool.python3.14]"));
        assert!(!is_python_table("[tool.native-python]"));
        assert!(!is_python_table("python3"));
    }

    #[test]
    fn python_tool_no_stdin_line_uses_the_name() {
        assert_eq!(
            no_stdin_line("python"),
            "strands-box: python got no stdin: a program the Shell starts can't read its input yet\n"
        );
    }
}
