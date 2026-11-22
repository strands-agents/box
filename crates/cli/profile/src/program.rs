//! A program on the host that a tool, an agent, or an MCP server runs: the checks that refuse a
//! program a box could have planted, and the interpreter that its `#!` line names.

use std::path::{Path, PathBuf};

use crate::host::{canonical, is_executable_file};
use crate::lang::lies_under;

/// The places a box can write on every run, where `box` takes no program from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Writable<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) storage: &'a Path,
    pub(crate) home: &'a Path,
    pub(crate) box_home: &'a Path,
}

impl Writable<'_> {
    /// The place that `path` lies in, as `box` names it in a refusal, if a box can write it.
    pub(crate) fn root(&self, path: &Path) -> Option<&'static str> {
        let box_homes = crate::host::box_homes(self.home, self.box_home);
        [
            (self.workspace, "the workspace"),
            (self.storage, "the run's storage"),
        ]
        .into_iter()
        .chain(
            box_homes
                .iter()
                .map(|box_home| (box_home.as_path(), "the box home")),
        )
        .find(|(root, _)| lies_under(path, root))
        .map(|(_, what)| what)
    }
}

/// A program that passed the checks: where it was found, and the real file it runs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Checked {
    pub(crate) spelling: PathBuf,
    pub(crate) real: PathBuf,
}

/// Why `box` refuses a program.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Refused {
    /// The path, as written or real, lies where a box can write.
    Planted { path: PathBuf, what: &'static str },
    /// The path is a link that leads to no file.
    Dangling,
    /// The real file is not an executable file.
    NotExecutable,
}

/// `<folder>/<name>` for each folder in order, where that path exists, as a file or a link.
pub(crate) fn candidates<'a>(
    folders: impl IntoIterator<Item = PathBuf> + 'a,
    name: &'a str,
) -> impl Iterator<Item = PathBuf> + 'a {
    folders
        .into_iter()
        .map(move |folder| folder.join(name))
        .filter(|candidate| std::fs::symlink_metadata(candidate).is_ok())
}

/// Check `spelling` and the real file it leads to, in this order: the spelling lies where a box
/// can write, the link leads to no file, the real file lies where a box can write, the real file is
/// not executable. The first that holds is the reason.
pub(crate) fn check(spelling: &Path, writable: &Writable<'_>) -> Result<Checked, Refused> {
    let planted = |path: &Path| {
        writable.root(path).map(|what| Refused::Planted {
            path: path.to_path_buf(),
            what,
        })
    };
    if let Some(refused) = planted(spelling) {
        return Err(refused);
    }
    let real = canonical(spelling).ok_or(Refused::Dangling)?;
    if let Some(refused) = planted(&real) {
        return Err(refused);
    }
    if !is_executable_file(&real) {
        return Err(Refused::NotExecutable);
    }
    Ok(Checked {
        spelling: spelling.to_path_buf(),
        real,
    })
}

/// The interpreter that a `#!` line names.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Interpreter {
    /// `#!/usr/bin/env <program>`: the `env` path as written, and the program by name.
    Named(PathBuf, String),
    /// `#!<path>`, as written.
    Path(PathBuf),
}

impl Interpreter {
    /// Whether the interpreter is node, such as `node-20` or `ts-node`, by its name or its file name.
    pub(crate) fn is_node(&self) -> bool {
        match self {
            Self::Named(_, name) => names_node(name),
            Self::Path(path) => names_node(&path.display().to_string()),
        }
    }
}

/// Whether the `#!` line of `path` runs node: its interpreter is node, or the line names no
/// interpreter that box can follow and one of its words after the first names node.
pub(crate) fn runs_node(path: &Path) -> bool {
    match interpreter(path) {
        Ok(interpreter) => interpreter.is_some_and(|interpreter| interpreter.is_node()),
        Err(words) => words.iter().skip(1).any(|word| names_node(word)),
    }
}

/// Whether the file name of `word` names node.
fn names_node(word: &str) -> bool {
    Path::new(word)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("node"))
}

/// The words of the `#!` line of `path`, without the `#!`, or none when it has no such line.
pub(crate) fn shebang(path: &Path) -> Vec<String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut first = Vec::new();
    let _ = std::io::Read::read_to_end(&mut std::io::Read::take(file, 256), &mut first);
    let line = first
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    match line.strip_prefix(b"#!") {
        Some(line) => String::from_utf8_lossy(line)
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    }
}

/// The program that the `#!` line of `path` runs when the line is `env <program>` or
/// `env -S <program>`, with only the program's own arguments after it. Any other `env` line, such
/// as one with a flag or an assignment before the program, or a program name with a character
/// other than a letter, a digit, `.`, `_`, `+`, or `-`, such as a quote or `$`, gives `None`,
/// because `env` could then find another program than the one on its search path.
pub(crate) fn plain_env(path: &Path) -> Option<String> {
    let words = shebang(path);
    let (first, rest) = words.split_first()?;
    if Path::new(first).file_name()? != "env" {
        return None;
    }
    let name = match rest {
        [flag, name, ..] if flag == "-S" => name,
        [name, ..] => name,
        [] => return None,
    };
    (!name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')))
    .then(|| name.clone())
}

/// The interpreter that the `#!` line of `path` names, if it has a `#!` line. `env` is followed to
/// the first word that is not a flag, the value of a flag, or an assignment. An `env` line that
/// names nothing, or that sets the search path with `-P`, is an error, with the line's words.
pub(crate) fn interpreter(path: &Path) -> Result<Option<Interpreter>, Vec<String>> {
    let words = shebang(path);
    let Some(first) = words.first() else {
        return Ok(None);
    };
    if Path::new(first)
        .file_name()
        .is_some_and(|name| name == "env")
    {
        let mut rest = words[1..].iter();
        while let Some(word) = rest.next() {
            match flag(word) {
                Flag::Path => break,
                Flag::Value => {
                    rest.next();
                }
                Flag::Alone if !word.starts_with('-') && !word.contains('=') => {
                    return Ok(Some(Interpreter::Named(PathBuf::from(first), word.clone())));
                }
                Flag::Alone => {}
            }
        }
        return Err(words.clone());
    }
    Ok(Some(Interpreter::Path(PathBuf::from(first))))
}

/// What an `env` word does to the words after it.
enum Flag {
    /// It is a program, an assignment, or a flag that takes no next word.
    Alone,
    /// It takes the next word as its value: `--unset`, `--chdir`, `--argv0`, or a run of short
    /// flags that ends with `-u`, `-C`, `-L`, or `-a`.
    Value,
    /// It is `-P`, which makes `env` find the program in other folders than `PATH`.
    Path,
}

fn flag(word: &str) -> Flag {
    if let Some(long) = word.strip_prefix("--") {
        return match long {
            "unset" | "chdir" | "argv0" => Flag::Value,
            _ => Flag::Alone,
        };
    }
    let Some(short) = word.strip_prefix('-') else {
        return Flag::Alone;
    };
    match short
        .char_indices()
        .find(|(_, flag)| matches!(flag, 'u' | 'C' | 'L' | 'a' | 'P'))
    {
        Some((_, 'P')) => Flag::Path,
        Some((at, _)) if at + 1 == short.len() => Flag::Value,
        _ => Flag::Alone,
    }
}

/// The OS and CPU architecture that the executable header of `path` names, as
/// `std::env::consts` names them, or none for a file that is not ELF or Mach-O, or that is too
/// short to tell. A universal Mach-O file names no architecture.
pub(crate) fn platform(path: &Path) -> Option<(&'static str, Option<&'static str>)> {
    let mut header = [0u8; 20];
    let file = std::fs::File::open(path).ok()?;
    let mut read = Vec::with_capacity(header.len());
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 20), &mut read).ok()?;
    header[..read.len()].copy_from_slice(&read);
    let header = &header[..read.len()];
    match header {
        [0x7f, b'E', b'L', b'F', _, data, ..] if header.len() >= 20 => {
            let machine = [header[18], header[19]];
            let machine = match data {
                1 => u16::from_le_bytes(machine),
                2 => u16::from_be_bytes(machine),
                _ => return None,
            };
            Some(("linux", elf_arch(machine)))
        }
        [0xcf, 0xfa, 0xed, 0xfe, a, b, c, d, ..] => {
            Some(("macos", macho_arch(u32::from_le_bytes([*a, *b, *c, *d]))))
        }
        [0xca, 0xfe, 0xba, 0xbe, ..] => Some(("macos", None)),
        _ => None,
    }
}

fn elf_arch(machine: u16) -> Option<&'static str> {
    match machine {
        62 => Some("x86_64"),
        183 => Some("aarch64"),
        _ => None,
    }
}

fn macho_arch(cpu: u32) -> Option<&'static str> {
    match cpu {
        0x0100_0007 => Some("x86_64"),
        0x0100_000c => Some("aarch64"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{executable, link, script, write};

    struct Scene {
        _root: tempfile::TempDir,
        root: PathBuf,
    }

    impl Scene {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("a temporary root");
            let root = directory.path().canonicalize().expect("a canonical root");
            Self {
                _root: directory,
                root,
            }
        }

        fn at(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        fn writable(&self) -> (PathBuf, PathBuf, PathBuf) {
            (
                self.at("home/work"),
                self.at("home/.strands/box/storage/x"),
                self.at("home"),
            )
        }
    }

    fn checked(scene: &Scene, path: &Path) -> Result<Checked, Refused> {
        let (workspace, storage, home) = scene.writable();
        check(
            path,
            &Writable {
                workspace: &workspace,
                storage: &storage,
                home: &home,
                box_home: &home.join(".strands/box"),
            },
        )
    }

    #[test]
    fn a_program_and_its_real_file_pass_outside_every_writable_place() {
        let scene = Scene::new();
        let real = scene.at("opt/tool/1.0/bin/tool");
        script(&real, "true");
        link(&real.display().to_string(), &scene.at("bin/tool"));
        assert_eq!(
            checked(&scene, &scene.at("bin/tool")),
            Ok(Checked {
                spelling: scene.at("bin/tool"),
                real,
            })
        );
    }

    #[test]
    fn a_program_is_refused_where_a_box_writes_as_written_or_real() {
        let scene = Scene::new();
        for (relative, what) in [
            ("home/work/bin/tool", "the workspace"),
            ("home/.strands/box/storage/x/tool", "the run's storage"),
            ("home/.strands/box/bin/tool", "the box home"),
        ] {
            let path = scene.at(relative);
            script(&path, "true");
            assert_eq!(
                checked(&scene, &path),
                Err(Refused::Planted {
                    path: path.clone(),
                    what
                }),
                "{relative}"
            );
            let outside = scene.at(&format!("links/{what}"));
            link(&path.display().to_string(), &outside);
            assert_eq!(
                checked(&scene, &outside),
                Err(Refused::Planted {
                    path: outside.clone(),
                    what
                }),
                "a link to {relative} is refused under its own spelling"
            );
        }
    }

    #[test]
    fn a_writable_place_is_the_reason_before_any_other() {
        let scene = Scene::new();
        let plain = scene.at("home/work/plain");
        write(&plain, "not a program");
        let dangling = scene.at("home/work/gone");
        link(&scene.at("nowhere").display().to_string(), &dangling);
        for path in [plain, dangling] {
            assert_eq!(
                checked(&scene, &path),
                Err(Refused::Planted {
                    path: path.clone(),
                    what: "the workspace"
                }),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn candidates_are_each_folder_that_holds_the_name_in_order() {
        let scene = Scene::new();
        script(&scene.at("b/tool"), "true");
        write(&scene.at("c/tool"), "not a program");
        link(
            &scene.at("nowhere").display().to_string(),
            &scene.at("d/tool"),
        );
        let folders = ["a", "b", "c", "d"].map(|folder| scene.at(folder));
        assert_eq!(
            candidates(folders, "tool").collect::<Vec<_>>(),
            ["b/tool", "c/tool", "d/tool"].map(|path| scene.at(path))
        );
    }

    #[test]
    fn a_dangling_link_and_a_plain_file_are_refused() {
        let scene = Scene::new();
        link(
            &scene.at("nowhere").display().to_string(),
            &scene.at("bin/gone"),
        );
        assert_eq!(
            checked(&scene, &scene.at("bin/gone")),
            Err(Refused::Dangling)
        );
        write(&scene.at("bin/plain"), "not a program");
        assert_eq!(
            checked(&scene, &scene.at("bin/plain")),
            Err(Refused::NotExecutable)
        );
    }

    #[test]
    fn the_interpreter_is_the_first_word_or_what_env_names() {
        let scene = Scene::new();
        for (line, expected) in [
            ("#!/bin/sh\n", Ok(Some(Interpreter::Path("/bin/sh".into())))),
            (
                "#!/usr/bin/node-20 --x\n",
                Ok(Some(Interpreter::Path("/usr/bin/node-20".into()))),
            ),
            (
                "#!/usr/bin/env node\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "node".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -S node --flag\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "node".into(),
                ))),
            ),
            (
                "#!/usr/bin/env A=1 python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -u NODE_OPTIONS node\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "node".into(),
                ))),
            ),
            (
                "#!/usr/bin/env --unset NODE_OPTIONS -C /srv python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -iu X python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -uX python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -a myname python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env --argv0 myname python3\n",
                Ok(Some(Interpreter::Named(
                    "/usr/bin/env".into(),
                    "python3".into(),
                ))),
            ),
            (
                "#!/usr/bin/env -P /opt/bin node\n",
                Err(vec![
                    "/usr/bin/env".to_string(),
                    "-P".to_string(),
                    "/opt/bin".to_string(),
                    "node".to_string(),
                ]),
            ),
            (
                "#!/usr/bin/env -iP/opt/bin node\n",
                Err(vec![
                    "/usr/bin/env".to_string(),
                    "-iP/opt/bin".to_string(),
                    "node".to_string(),
                ]),
            ),
            ("echo no line\n", Ok(None)),
            (
                "#!/usr/bin/env -S\n",
                Err(vec!["/usr/bin/env".to_string(), "-S".to_string()]),
            ),
            (
                "#!/usr/bin/env -u X\n",
                Err(vec![
                    "/usr/bin/env".to_string(),
                    "-u".to_string(),
                    "X".to_string(),
                ]),
            ),
        ] {
            let path = scene.at("script");
            write(&path, line);
            executable(&path);
            assert_eq!(interpreter(&path), expected, "{line:?}");
        }
    }

    #[test]
    fn node_is_named_by_its_program_or_its_file_name() {
        for (interpreter, node) in [
            (
                Interpreter::Named("/usr/bin/env".into(), "node".into()),
                true,
            ),
            (
                Interpreter::Named("/usr/bin/env".into(), "/usr/bin/node".into()),
                true,
            ),
            (Interpreter::Path("/usr/bin/node-20".into()), true),
            (Interpreter::Path("/opt/homebrew/bin/node".into()), true),
            (
                Interpreter::Named("/usr/bin/env".into(), "ts-node".into()),
                true,
            ),
            (Interpreter::Path("/usr/local/bin/ts-node".into()), true),
            (
                Interpreter::Named("/usr/bin/env".into(), "python3".into()),
                false,
            ),
            (Interpreter::Path("/bin/sh".into()), false),
        ] {
            assert_eq!(interpreter.is_node(), node, "{interpreter:?}");
        }
    }

    #[test]
    fn platform_reads_the_os_and_cpu_of_an_executable_header() {
        let scene = Scene::new();
        let elf = |data: u8, machine: [u8; 2]| {
            let mut header = vec![0x7f, b'E', b'L', b'F', 2, data];
            header.resize(18, 0);
            header.extend(machine);
            header
        };
        for (name, header, expected) in [
            ("elf-x86", elf(1, [62, 0]), Some(("linux", Some("x86_64")))),
            (
                "elf-arm-be",
                elf(2, [0, 183]),
                Some(("linux", Some("aarch64"))),
            ),
            ("elf-other", elf(1, [243, 0]), Some(("linux", None))),
            ("elf-short", b"\x7fELF".to_vec(), None),
            (
                "macho-arm",
                vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 0x01],
                Some(("macos", Some("aarch64"))),
            ),
            (
                "macho-x86",
                vec![0xcf, 0xfa, 0xed, 0xfe, 0x07, 0, 0, 0x01],
                Some(("macos", Some("x86_64"))),
            ),
            (
                "universal",
                vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2],
                Some(("macos", None)),
            ),
            ("script", b"#!/bin/sh\necho hi\n".to_vec(), None),
        ] {
            let path = scene.at(name);
            std::fs::write(&path, header).expect("a file");
            assert_eq!(platform(&path), expected, "{name}");
        }
    }
}
