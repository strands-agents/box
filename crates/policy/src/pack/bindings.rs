//! The installed tool packs, each bound to a program file's identity and the name it is called by
//! (docs/design/decisions.md#a-tool-pack-binds-on-the-program-file-and-the-called-name).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::Pack;

/// One resolved program file, compared by its device and inode.
#[derive(Debug, Clone)]
pub(crate) struct ProgramFile {
    identity: FileIdentity,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

/// A program file whose identity Box cannot read.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the program file {}: {reason}", .path.display())]
pub(crate) struct UnreadableProgramFile {
    path: PathBuf,
    reason: std::io::Error,
}

impl ProgramFile {
    /// Read the identity of the file at `path`, after the host resolves each link in it.
    pub(crate) fn read(path: impl Into<PathBuf>) -> Result<Self, UnreadableProgramFile> {
        let path = path.into();
        match std::fs::metadata(&path) {
            Ok(metadata) => Ok(Self {
                identity: FileIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
                path,
            }),
            Err(reason) => Err(UnreadableProgramFile { path, reason }),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// The installed packs, and the (program file, called name) pairs each one covers.
#[derive(Debug, Default)]
pub(crate) struct PackBindings {
    packs: Vec<Pack>,
    by_file: BTreeMap<FileIdentity, usize>,
    bound: BTreeSet<(FileIdentity, String)>,
    declared: BTreeSet<(FileIdentity, String)>,
}

/// How a pack covers one spawn.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PackCoverage<'a> {
    /// The file and the name are bound to this pack, so the command parses with its grammar.
    Parsed(&'a Pack),
    /// The file is bound to this pack, and no `[tool]` declares the name it was called by.
    Unmodeled(&'a Pack),
}

/// Why Box refuses the installed packs or one binding.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindingRefusal {
    #[error("two installed tool packs are named {pack:?}")]
    NamedTwice { pack: String },
    #[error("no installed tool pack is named {pack:?}")]
    UnknownPack { pack: String },
    #[error(
        "{} is bound to tool pack {bound:?}, so it cannot also bind {pack:?}",
        .program_path.display()
    )]
    BoundToAnotherPack {
        program_path: PathBuf,
        bound: String,
        pack: String,
    },
}

impl PackBindings {
    pub(crate) fn new(packs: Vec<Pack>) -> Result<Self, BindingRefusal> {
        let mut seen = BTreeMap::<&str, usize>::new();
        for pack in &packs {
            *seen.entry(pack.name.as_str()).or_default() += 1;
        }
        if let Some((pack, _)) = seen.into_iter().find(|&(_, count)| count > 1) {
            return Err(BindingRefusal::NamedTwice {
                pack: pack.to_string(),
            });
        }
        Ok(Self {
            packs,
            ..Self::default()
        })
    }

    /// Declare that a `[tool]` runs `program` under the name `name`.
    pub(crate) fn declare(&mut self, program: &ProgramFile, name: impl Into<String>) {
        self.declared.insert((program.identity, name.into()));
    }

    /// Bind the pack named `pack` to `program` called by `name`.
    pub(crate) fn bind(
        &mut self,
        program: &ProgramFile,
        name: impl Into<String>,
        pack: &str,
    ) -> Result<(), BindingRefusal> {
        let index = self
            .packs
            .iter()
            .position(|installed| installed.name == pack)
            .ok_or_else(|| BindingRefusal::UnknownPack {
                pack: pack.to_string(),
            })?;
        if let Some(&bound) = self.by_file.get(&program.identity)
            && bound != index
        {
            return Err(BindingRefusal::BoundToAnotherPack {
                program_path: program.path.clone(),
                bound: self.packs[bound].name.clone(),
                pack: pack.to_string(),
            });
        }
        self.by_file.insert(program.identity, index);
        self.bound.insert((program.identity, name.into()));
        Ok(())
    }

    /// The pack that covers a spawn of `program` called by `name`, if any.
    pub(crate) fn coverage(&self, program: &ProgramFile, name: &str) -> Option<PackCoverage<'_>> {
        let pack = &self.packs[*self.by_file.get(&program.identity)?];
        let pair = (program.identity, name.to_string());
        if self.bound.contains(&pair) {
            Some(PackCoverage::Parsed(pack))
        } else if self.declared.contains(&pair) {
            None
        } else {
            Some(PackCoverage::Unmodeled(pack))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT: &str = "usr/bin/git";
    const CARGO: &str = "home/operator/.cargo/bin/cargo";
    const MISE: &str = "home/operator/.local/bin/mise";

    /// A temporary host directory that holds real program files.
    struct Host(tempfile::TempDir);

    impl Host {
        fn new() -> Self {
            Self(tempfile::tempdir().expect("a temporary directory"))
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.0.path().join(relative)
        }

        fn parent_of(&self, relative: &str) {
            let path = self.path(relative);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        }

        fn program(&self, relative: &str) -> ProgramFile {
            let path = self.path(relative);
            if !path.exists() {
                self.parent_of(relative);
                std::fs::write(&path, relative).expect("a program file");
            }
            ProgramFile::read(path).expect("a readable program file")
        }

        fn hard_link(&self, original: &str, link: &str) -> ProgramFile {
            self.program(original);
            self.parent_of(link);
            std::fs::hard_link(self.path(original), self.path(link)).expect("a hard link");
            self.program(link)
        }

        fn symlink(&self, original: &str, link: &str) -> ProgramFile {
            self.program(original);
            self.parent_of(link);
            std::os::unix::fs::symlink(self.path(original), self.path(link)).expect("a symlink");
            self.program(link)
        }
    }

    fn installed(names: &[&str]) -> Vec<Pack> {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/packs/valid");
        names
            .iter()
            .map(|name| Pack::load(&corpus.join(format!("{name}.pack.toml"))).expect("a pack"))
            .collect()
    }

    fn version(pack: &str, version: u32) -> Pack {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/packs/valid");
        let text =
            std::fs::read_to_string(corpus.join(format!("{pack}.pack.toml"))).expect("a pack");
        let text = text.replacen("version = 1", &format!("version = {version}"), 1);
        let pack = Pack::parse(&text).expect("a pack");
        assert_eq!(pack.version, version, "{pack:?} carries the version");
        pack
    }

    fn answer(coverage: Option<PackCoverage<'_>>) -> Option<(&'static str, String)> {
        coverage.map(|coverage| match coverage {
            PackCoverage::Parsed(pack) => ("parsed", pack.name.clone()),
            PackCoverage::Unmodeled(pack) => ("unmodeled", pack.name.clone()),
        })
    }

    fn parsed(pack: &str) -> Option<(&'static str, String)> {
        Some(("parsed", pack.to_string()))
    }

    fn unmodeled(pack: &str) -> Option<(&'static str, String)> {
        Some(("unmodeled", pack.to_string()))
    }

    #[test]
    fn each_spawn_resolves_by_its_program_file_and_its_called_name() {
        let host = Host::new();
        let mut bindings = PackBindings::new(installed(&["git", "cargo"])).expect("distinct packs");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings.declare(&host.program(CARGO), "rustc");
        bindings
            .bind(&host.program(CARGO), "cargo", "cargo")
            .expect("cargo binds");
        bindings
            .bind(&host.program(MISE), "git", "git")
            .expect("the mise shim binary binds");
        bindings.declare(&host.program(MISE), "node");
        bindings.declare(&host.program(MISE), "npm");

        for (case, program, name, expected) in [
            ("a bound pair parses", GIT, "git", parsed("git")),
            (
                "a second pack on a second file",
                CARGO,
                "cargo",
                parsed("cargo"),
            ),
            (
                "a declared, unbound name on a bound file",
                CARGO,
                "rustc",
                None,
            ),
            (
                "an undeclared name on a bound file",
                CARGO,
                "cargo-clippy",
                unmodeled("cargo"),
            ),
            ("an unbound file", "usr/bin/ls", "ls", None),
            (
                "an unbound file called by a bound name",
                "opt/git/bin/git",
                "git",
                None,
            ),
            (
                "the mise shim binary, by its bound name",
                MISE,
                "git",
                parsed("git"),
            ),
            (
                "the mise shim binary, by a declared name",
                MISE,
                "node",
                None,
            ),
            (
                "the mise shim binary, by another declared name",
                MISE,
                "npm",
                None,
            ),
            (
                "the mise shim binary, by an undeclared name",
                MISE,
                "python",
                unmodeled("git"),
            ),
        ] {
            assert_eq!(
                answer(bindings.coverage(&host.program(program), name)),
                expected,
                "{case}: {program} called as {name}"
            );
        }
    }

    #[test]
    fn an_undeclared_name_on_a_file_that_no_pack_binds_stays_a_spawn() {
        let host = Host::new();
        let mut bindings = PackBindings::new(installed(&["git"])).expect("distinct packs");
        bindings.declare(&host.program(MISE), "node");

        for (case, name) in [
            ("a declared name", "node"),
            ("an undeclared name", "python"),
        ] {
            assert!(
                bindings.coverage(&host.program(MISE), name).is_none(),
                "{case}: {MISE} called as {name}"
            );
        }
    }

    #[test]
    fn a_link_to_a_bound_file_is_that_file() {
        let host = Host::new();
        let mut bindings = PackBindings::new(installed(&["git", "cargo"])).expect("distinct packs");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings.declare(&host.program(GIT), "git-lfs");

        for (case, program) in [
            ("the original path", host.program(GIT)),
            ("a hard link", host.hard_link(GIT, "opt/git-hard")),
            ("a symlink", host.symlink(GIT, "opt/git-symbolic")),
        ] {
            let at = program.path().display().to_string();
            for (name, expected) in [
                ("git", parsed("git")),
                ("git-lfs", None),
                ("gitk", unmodeled("git")),
            ] {
                assert_eq!(
                    answer(bindings.coverage(&program, name)),
                    expected,
                    "{case}: {at} called as {name}"
                );
            }
            assert_eq!(
                bindings.bind(&program, "cargo", "cargo"),
                Err(BindingRefusal::BoundToAnotherPack {
                    program_path: program.path().to_path_buf(),
                    bound: "git".to_string(),
                    pack: "cargo".to_string(),
                }),
                "{case}: a second pack through {at}"
            );
        }
    }

    #[test]
    fn a_program_file_that_cannot_be_read_is_refused() {
        let host = Host::new();

        let refused = ProgramFile::read(host.path("absent")).expect_err("the file is refused");

        assert_eq!(refused.path, host.path("absent"));
        assert_eq!(refused.reason.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn a_binding_that_names_no_installed_pack_or_a_second_pack_on_one_file_is_refused() {
        let host = Host::new();
        let mut bindings = PackBindings::new(installed(&["git", "cargo"])).expect("distinct packs");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings
            .bind(&host.program(CARGO), "cargo", "cargo")
            .expect("cargo binds");
        bindings
            .bind(&host.program(MISE), "git", "git")
            .expect("the mise shim binary binds");

        let another_pack = |program: &str| {
            Err(BindingRefusal::BoundToAnotherPack {
                program_path: host.path(program),
                bound: "git".to_string(),
                pack: "cargo".to_string(),
            })
        };
        for (case, program, name, pack, expected) in [
            (
                "an unknown pack",
                CARGO,
                "rustc",
                "kubectl",
                Err(BindingRefusal::UnknownPack {
                    pack: "kubectl".to_string(),
                }),
            ),
            (
                "a bound pair, to another pack",
                GIT,
                "git",
                "cargo",
                another_pack(GIT),
            ),
            (
                "another name, to another pack",
                MISE,
                "cargo",
                "cargo",
                another_pack(MISE),
            ),
            (
                "a bound pair, to the same pack again",
                GIT,
                "git",
                "git",
                Ok(()),
            ),
            (
                "another name, to the same pack",
                GIT,
                "git-upload-pack",
                "git",
                Ok(()),
            ),
        ] {
            assert_eq!(
                bindings.bind(&host.program(program), name, pack),
                expected,
                "{case}: {program} called as {name}, to {pack}"
            );
        }

        for (case, program, name, expected) in [
            (
                "the refused unknown pack",
                CARGO,
                "rustc",
                unmodeled("cargo"),
            ),
            ("the refused pair", GIT, "git", parsed("git")),
            ("the refused name", MISE, "cargo", unmodeled("git")),
            ("the accepted name", GIT, "git-upload-pack", parsed("git")),
        ] {
            assert_eq!(
                answer(bindings.coverage(&host.program(program), name)),
                expected,
                "{case}: {program} called as {name}"
            );
        }
    }

    #[test]
    fn two_installed_packs_with_one_name_are_refused_in_any_order() {
        let (git, cargo) = (|v| version("git", v), |v| version("cargo", v));
        for (case, packs, named) in [
            ("one version twice", vec![git(1), git(1)], "git"),
            ("v1, then v2", vec![git(1), git(2)], "git"),
            ("v2, then v1", vec![git(2), git(1)], "git"),
            ("around another pack", vec![git(2), cargo(1), git(1)], "git"),
            ("before another pack", vec![git(1), git(2), cargo(1)], "git"),
            ("after another pack", vec![cargo(1), git(1), git(2)], "git"),
            (
                "two names, cargo first",
                vec![cargo(1), git(1), git(2), cargo(2)],
                "cargo",
            ),
            (
                "two names, git first",
                vec![git(1), git(2), cargo(1), cargo(2)],
                "cargo",
            ),
        ] {
            assert_eq!(
                PackBindings::new(packs).map(|_| ()),
                Err(BindingRefusal::NamedTwice {
                    pack: named.to_string()
                }),
                "{case}"
            );
        }
    }
}
