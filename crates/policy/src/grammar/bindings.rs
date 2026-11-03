//! The installed tool grammars, each bound to a program file's identity and the name it is called
//! by (docs/design/decisions.md#a-tool-grammar-binds-on-the-program-file-and-the-called-name).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::Grammar;

/// The most links Box records from one spelling.
const MAXIMUM_LINKS: usize = 40;

/// One resolved program file: the device and inode found there, and each spelling that led to it.
#[derive(Debug, Clone)]
pub(crate) struct ProgramFile {
    identity: FileIdentity,
    path: PathBuf,
    spellings: Vec<PathBuf>,
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
        let read = std::fs::canonicalize(&path)
            .and_then(|canonical| std::fs::metadata(&canonical).map(|found| (canonical, found)));
        match read {
            Ok((canonical, metadata)) => {
                let mut spellings = links_from(&path);
                if !spellings.contains(&canonical) {
                    spellings.push(canonical.clone());
                }
                Ok(Self {
                    identity: FileIdentity {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    },
                    path: canonical,
                    spellings,
                })
            }
            Err(reason) => Err(UnreadableProgramFile { path, reason }),
        }
    }

    /// A program file at `path` with a fixed identity, for a test that runs no host file.
    #[cfg(test)]
    pub(crate) fn fixed(path: &str, inode: u64) -> Self {
        Self {
            identity: FileIdentity { device: 0, inode },
            path: PathBuf::from(path),
            spellings: vec![PathBuf::from(path)],
        }
    }

    /// The canonical path the identity was read at.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// `path`, then the path each link on the way names, as the host follows them.
fn links_from(path: &Path) -> Vec<PathBuf> {
    let mut spellings = vec![path.to_path_buf()];
    let mut current = path.to_path_buf();
    while spellings.len() <= MAXIMUM_LINKS {
        let Ok(target) = std::fs::read_link(&current) else {
            break;
        };
        current = match current.parent() {
            Some(parent) if target.is_relative() => parent.join(target),
            _ => target,
        };
        spellings.push(current.clone());
    }
    spellings
}

/// The installed tool grammars, the (program file, called name) pairs each one covers, and the file
/// identity that each bound spelling led to when it was bound.
#[derive(Debug, Default)]
pub(crate) struct GrammarBindings {
    grammars: Vec<Grammar>,
    bound: BTreeMap<(FileIdentity, String), usize>,
    spellings: BTreeMap<PathBuf, FileIdentity>,
    declared: BTreeSet<(FileIdentity, String)>,
}

/// How the installed grammars cover one spawn.
#[derive(Debug)]
pub(crate) enum GrammarCoverage<'a> {
    /// The file and the name are bound to this grammar, so the command parses with it.
    Parsed {
        grammar: &'a Grammar,
        file: ProgramFile,
    },
    /// A grammar binds the file or a spelling of it, and Box refuses the spawn before any policy
    /// decides it.
    Refused(CoverageRefusal),
}

/// Why Box refuses a spawn of a file that a grammar binds, whatever the policy permits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CoverageRefusal {
    #[error(
        "`{name}` runs `{}`, which a tool grammar covers, but no `[tool]` declares the name `{name}`",
        .program_path.display()
    )]
    UndeclaredName { name: String, program_path: PathBuf },
    #[error(
        "`{name}` runs `{}`, which a tool grammar bound, but the file at that path is no longer the file it bound",
        .program_path.display()
    )]
    ReplacedFile { name: String, program_path: PathBuf },
}

/// Why Box refuses the installed grammars or one binding.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindingRefusal {
    /// Two installed grammars have one name.
    #[error("two installed tool grammars are named {grammar:?}")]
    NamedTwice {
        /// The name that two grammars have.
        grammar: String,
    },
    /// A binding names a grammar that is not installed.
    #[error("no installed tool grammar is named {grammar:?}")]
    UnknownGrammar {
        /// The name that no installed grammar has.
        grammar: String,
    },
    /// A binding reuses a (program file, called name) pair that another grammar binds.
    #[error(
        "{} called as {name:?} is bound to tool grammar {bound:?}, so it cannot also bind {grammar:?}",
        .program_path.display()
    )]
    BoundToAnotherGrammar {
        /// The canonical path of the program file.
        program_path: PathBuf,
        /// The called name.
        name: String,
        /// The grammar that binds the pair.
        bound: String,
        /// The grammar that the refused binding names.
        grammar: String,
    },
}

/// The name a program was called by: the last component of its spelling.
pub(crate) fn called_name(spelling: &str) -> &str {
    Path::new(spelling)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(spelling)
}

impl GrammarBindings {
    /// Hold the installed `grammars`, each with a distinct name, and no binding yet.
    pub(crate) fn new(grammars: Vec<Grammar>) -> Result<Self, BindingRefusal> {
        let mut seen = BTreeMap::<&str, usize>::new();
        for grammar in &grammars {
            *seen.entry(grammar.name.as_str()).or_default() += 1;
        }
        if let Some((grammar, _)) = seen.into_iter().find(|&(_, count)| count > 1) {
            return Err(BindingRefusal::NamedTwice {
                grammar: grammar.to_string(),
            });
        }
        Ok(Self {
            grammars,
            ..Self::default()
        })
    }

    /// Declare that a `[tool]` runs `program` under the name `name`.
    pub(crate) fn declare(&mut self, program: &ProgramFile, name: impl Into<String>) {
        self.declared.insert((program.identity, name.into()));
    }

    /// Bind the grammar named `grammar` to `program` called by `name`.
    pub(crate) fn bind(
        &mut self,
        program: &ProgramFile,
        name: impl Into<String>,
        grammar: &str,
    ) -> Result<(), BindingRefusal> {
        let index = self
            .grammars
            .iter()
            .position(|installed| installed.name == grammar)
            .ok_or_else(|| BindingRefusal::UnknownGrammar {
                grammar: grammar.to_string(),
            })?;
        let pair = (program.identity, name.into());
        if let Some(&bound) = self.bound.get(&pair)
            && bound != index
        {
            return Err(BindingRefusal::BoundToAnotherGrammar {
                program_path: program.path.clone(),
                name: pair.1,
                bound: self.grammars[bound].name.clone(),
                grammar: grammar.to_string(),
            });
        }
        for spelling in &program.spellings {
            self.spellings
                .entry(spelling.clone())
                .or_insert(program.identity);
        }
        self.bound.insert(pair, index);
        Ok(())
    }

    /// Whether no grammar binds any file.
    pub(crate) fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }

    fn binds_file(&self, identity: FileIdentity) -> bool {
        self.bound
            .range((identity, String::new())..)
            .next()
            .is_some_and(|((bound, _), _)| *bound == identity)
    }

    /// Whether a bound spelling now leads somewhere other than a file it was bound to that covered
    /// `name`: a spelling of `program` itself, or a bound spelling that now resolves to `program`.
    fn replaced(&self, program: &ProgramFile, name: &str) -> bool {
        let moved = |identity: &FileIdentity| *identity != program.identity;
        let covered = |identity: FileIdentity| {
            let pair = (identity, name.to_string());
            self.bound.contains_key(&pair)
                || (!self.declared.contains(&pair) && !self.binds_file(program.identity))
        };
        program.spellings.iter().any(|spelling| {
            self.spellings
                .get(spelling)
                .is_some_and(|identity| moved(identity) && covered(*identity))
        }) || self.spellings.iter().any(|(spelling, identity)| {
            moved(identity)
                && covered(*identity)
                && std::fs::canonicalize(spelling).is_ok_and(|now| now == program.path)
        })
    }

    /// How the grammars cover a spawn spelled `spelling` of the program file that `read` found, or
    /// `None` when no grammar does.
    pub(crate) fn coverage(
        &self,
        read: Result<ProgramFile, UnreadableProgramFile>,
        spelling: &str,
    ) -> Option<GrammarCoverage<'_>> {
        let name = called_name(spelling);
        let refused = |refusal: fn(String, PathBuf) -> CoverageRefusal, path: &Path| {
            Some(GrammarCoverage::Refused(refusal(
                name.to_string(),
                path.to_path_buf(),
            )))
        };
        let replaced = |name, program_path| CoverageRefusal::ReplacedFile { name, program_path };
        let undeclared =
            |name, program_path| CoverageRefusal::UndeclaredName { name, program_path };
        let program = match read {
            Ok(program) => program,
            Err(unreadable) if self.spellings.contains_key(&unreadable.path) => {
                return refused(replaced, &unreadable.path);
            }
            Err(_) => return None,
        };
        if self.replaced(&program, name) {
            return refused(replaced, &program.path);
        }
        let pair = (program.identity, name.to_string());
        if let Some(&index) = self.bound.get(&pair) {
            return Some(GrammarCoverage::Parsed {
                grammar: &self.grammars[index],
                file: program,
            });
        }
        if self.binds_file(program.identity) && !self.declared.contains(&pair) {
            return refused(undeclared, &program.path);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT: &str = "usr/bin/git";
    const CARGO: &str = "home/operator/.cargo/bin/cargo";
    const MISE: &str = "home/operator/.local/bin/mise";
    const RENAMED_MISE: &str = "opt/renamed/bin/mise";
    const LINKED_MISE: &str = "opt/linked/bin/mise";
    const FIRST_MISE: &str = "opt/linked/mise-1/mise";
    const SECOND_MISE: &str = "opt/linked/mise-2/mise";

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
            ProgramFile::read(self.path(link)).expect("a readable link")
        }

        /// Put a new file at `relative`, as an update does: a rename over the old name.
        fn replace(&self, relative: &str) -> ProgramFile {
            let staged = self.path(&format!("{relative}.new"));
            std::fs::write(&staged, "a new build").expect("a new program file");
            std::fs::rename(&staged, self.path(relative)).expect("the rename");
            self.program(relative)
        }
    }

    fn installed(names: &[&str]) -> Vec<Grammar> {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/grammars/valid");
        names
            .iter()
            .map(|name| {
                Grammar::load(&corpus.join(format!("{name}.grammar.toml"))).expect("a grammar")
            })
            .collect()
    }

    fn version(grammar: &str, version: u32) -> Grammar {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/grammars/valid");
        let text = std::fs::read_to_string(corpus.join(format!("{grammar}.grammar.toml")))
            .expect("a grammar");
        let text = text.replacen("version = 1", &format!("version = {version}"), 1);
        let grammar = Grammar::parse(&text).expect("a grammar");
        assert_eq!(grammar.version, version, "{grammar:?} carries the version");
        grammar
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Answer {
        Parsed(String),
        Undeclared,
        Replaced,
    }

    fn answer(coverage: Option<GrammarCoverage<'_>>) -> Option<Answer> {
        coverage.map(|coverage| match coverage {
            GrammarCoverage::Parsed { grammar, .. } => Answer::Parsed(grammar.name.clone()),
            GrammarCoverage::Refused(CoverageRefusal::UndeclaredName { .. }) => Answer::Undeclared,
            GrammarCoverage::Refused(CoverageRefusal::ReplacedFile { .. }) => Answer::Replaced,
        })
    }

    fn parsed(grammar: &str) -> Option<Answer> {
        Some(Answer::Parsed(grammar.to_string()))
    }

    const REFUSED: Option<Answer> = Some(Answer::Undeclared);

    #[test]
    fn each_spawn_resolves_by_its_program_file_and_its_called_name() {
        let host = Host::new();
        let mut bindings =
            GrammarBindings::new(installed(&["git", "cargo"])).expect("distinct grammars");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings.declare(&host.program(CARGO), "rustc");
        bindings
            .bind(&host.program(CARGO), "cargo", "cargo")
            .expect("cargo binds");
        bindings.declare(&host.program(MISE), "node");
        bindings.declare(&host.program(MISE), "npm");
        bindings
            .bind(&host.program(MISE), "git", "git")
            .expect("the mise shim binary binds");
        for shim in [
            host.program(RENAMED_MISE),
            host.symlink(FIRST_MISE, LINKED_MISE),
        ] {
            bindings.declare(&shim, "node");
            bindings
                .bind(&shim, "cargo", "cargo")
                .expect("cargo binds the shim binary");
        }
        host.replace(RENAMED_MISE);
        host.program(SECOND_MISE);
        std::fs::remove_file(host.path(LINKED_MISE)).expect("the old link is removed");
        std::os::unix::fs::symlink(host.path(SECOND_MISE), host.path(LINKED_MISE))
            .expect("a new link");

        for (case, program, name, expected) in [
            ("a bound pair parses", GIT, "git", parsed("git")),
            (
                "a second grammar on a second file",
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
                REFUSED,
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
                REFUSED,
            ),
            (
                "a shim binary replaced in place, by its bound name",
                RENAMED_MISE,
                "cargo",
                Some(Answer::Replaced),
            ),
            (
                "a shim binary replaced in place, by a declared name",
                RENAMED_MISE,
                "node",
                None,
            ),
            (
                "a shim binary behind a retargeted link, by its bound name",
                SECOND_MISE,
                "cargo",
                Some(Answer::Replaced),
            ),
            (
                "a shim binary behind a retargeted link, by a declared name",
                SECOND_MISE,
                "node",
                None,
            ),
        ] {
            assert_eq!(
                answer(bindings.coverage(Ok(host.program(program)), name)),
                expected,
                "{case}: {program} called as {name}"
            );
        }
    }

    #[test]
    fn two_grammars_bind_one_shim_binary_by_two_names() {
        let host = Host::new();
        let mut bindings =
            GrammarBindings::new(installed(&["cargo", "aws"])).expect("distinct grammars");
        let mise = host.program(MISE);
        bindings
            .bind(&mise, "cargo", "cargo")
            .expect("cargo binds the shim binary");
        bindings
            .bind(&mise, "aws", "aws")
            .expect("aws binds the same shim binary by another name");
        bindings.declare(&mise, "node");

        for (case, name, expected) in [
            ("the first grammar's name", "cargo", parsed("cargo")),
            ("the second grammar's name", "aws", parsed("aws")),
            ("a declared name with no grammar", "node", None),
            ("an undeclared name", "python", REFUSED),
        ] {
            assert_eq!(
                answer(bindings.coverage(Ok(mise.clone()), name)),
                expected,
                "{case}: {MISE} called as {name}"
            );
        }
    }

    #[test]
    fn an_undeclared_name_on_a_file_that_no_grammar_binds_stays_a_spawn() {
        let host = Host::new();
        let mut bindings = GrammarBindings::new(installed(&["git"])).expect("distinct grammars");
        bindings.declare(&host.program(MISE), "node");

        for (case, name) in [
            ("a declared name", "node"),
            ("an undeclared name", "python"),
        ] {
            assert!(
                bindings.coverage(Ok(host.program(MISE)), name).is_none(),
                "{case}: {MISE} called as {name}"
            );
        }
    }

    #[test]
    fn a_link_to_a_bound_file_is_that_file() {
        let host = Host::new();
        let mut bindings =
            GrammarBindings::new(installed(&["git", "cargo"])).expect("distinct grammars");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings.declare(&host.program(GIT), "git-lfs");

        for (case, program) in [
            ("the original path", host.program(GIT)),
            ("a hard link", host.hard_link(GIT, "opt/git-hard")),
            ("a symlink", host.symlink(GIT, "opt/git-symbolic")),
            ("a short symlink", host.symlink(GIT, "opt/g")),
        ] {
            let at = program.path().display().to_string();
            for (name, expected) in [
                ("git", parsed("git")),
                ("git-lfs", None),
                ("gitk", REFUSED),
                ("g", REFUSED),
                ("git-hard", REFUSED),
            ] {
                assert_eq!(
                    answer(bindings.coverage(Ok(program.clone()), name)),
                    expected,
                    "{case}: {at} called as {name}"
                );
            }
            assert_eq!(
                bindings.bind(&program, "git", "cargo"),
                Err(BindingRefusal::BoundToAnotherGrammar {
                    program_path: program.path().to_path_buf(),
                    name: "git".to_string(),
                    bound: "git".to_string(),
                    grammar: "cargo".to_string(),
                }),
                "{case}: a second grammar on the bound pair through {at}"
            );
        }
    }

    #[test]
    fn a_replaced_file_at_a_bound_path_is_refused() {
        let host = Host::new();
        let mut bindings = GrammarBindings::new(installed(&["git"])).expect("distinct grammars");
        let original = host.program(GIT);
        bindings.bind(&original, "git", "git").expect("git binds");
        bindings.declare(&original, "git-lfs");

        let replaced = host.replace(GIT);

        assert_eq!(replaced.path(), original.path());
        assert!(
            bindings.coverage(Ok(replaced.clone()), "git-lfs").is_none(),
            "a declared name with no grammar stays a spawn"
        );
        for name in ["git", "gitk"] {
            assert_eq!(
                bindings
                    .coverage(Ok(replaced.clone()), name)
                    .map(|coverage| match coverage {
                        GrammarCoverage::Refused(refusal) => Some(refusal),
                        GrammarCoverage::Parsed { .. } => None,
                    }),
                Some(Some(CoverageRefusal::ReplacedFile {
                    name: name.to_string(),
                    program_path: original.path().to_path_buf(),
                })),
                "the new file at {} called as {name}",
                replaced.path().display()
            );
        }
    }

    #[test]
    fn a_new_file_behind_a_bound_link_is_refused() {
        let host = Host::new();
        let mut bindings = GrammarBindings::new(installed(&["git"])).expect("distinct grammars");
        let linked = host.symlink("opt/cellar/git/1/bin/git", "opt/bin/git");
        bindings
            .bind(&linked, "git", "git")
            .expect("git binds through the link");

        let upgraded = host.program("opt/cellar/git/2/bin/git");
        std::fs::remove_file(host.path("opt/bin/git")).expect("the old link is removed");
        std::os::unix::fs::symlink(upgraded.path(), host.path("opt/bin/git")).expect("a new link");

        assert_eq!(
            answer(bindings.coverage(Ok(upgraded.clone()), "git")),
            Some(Answer::Replaced),
            "the file that the bound link leads to now"
        );
        assert_eq!(
            answer(bindings.coverage(Ok(host.program("opt/cellar/git/3/bin/git")), "git")),
            None,
            "a file that no bound path leads to"
        );
    }

    #[test]
    fn a_refusal_names_the_called_name_and_the_program_file() {
        for (refusal, message) in [
            (
                CoverageRefusal::UndeclaredName {
                    name: "python".to_string(),
                    program_path: PathBuf::from("/usr/local/bin/mise"),
                },
                "`python` runs `/usr/local/bin/mise`, which a tool grammar covers, but no `[tool]` \
                 declares the name `python`",
            ),
            (
                CoverageRefusal::ReplacedFile {
                    name: "git".to_string(),
                    program_path: PathBuf::from("/usr/bin/git"),
                },
                "`git` runs `/usr/bin/git`, which a tool grammar bound, but the file at that path \
                 is no longer the file it bound",
            ),
        ] {
            assert_eq!(refusal.to_string(), message);
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
    fn a_program_file_is_read_at_its_canonical_path() {
        let host = Host::new();
        let original = host.program(GIT);

        let link = host.symlink(GIT, "opt/git-symbolic");

        assert_eq!(link.path(), original.path());
        assert_eq!(link.identity, original.identity);
    }

    #[test]
    fn a_second_grammar_is_refused_only_on_a_bound_pair() {
        let host = Host::new();
        let mut bindings =
            GrammarBindings::new(installed(&["git", "cargo"])).expect("distinct grammars");
        bindings
            .bind(&host.program(GIT), "git", "git")
            .expect("git binds");
        bindings
            .bind(&host.program(CARGO), "cargo", "cargo")
            .expect("cargo binds");
        bindings
            .bind(&host.program(MISE), "git", "git")
            .expect("the mise shim binary binds");

        let another_grammar = |program: &str, name: &str| {
            Err(BindingRefusal::BoundToAnotherGrammar {
                program_path: host.program(program).path().to_path_buf(),
                name: name.to_string(),
                bound: "git".to_string(),
                grammar: "cargo".to_string(),
            })
        };
        for (case, program, name, grammar, expected) in [
            (
                "an unknown grammar",
                CARGO,
                "rustc",
                "kubectl",
                Err(BindingRefusal::UnknownGrammar {
                    grammar: "kubectl".to_string(),
                }),
            ),
            (
                "a bound pair, to another grammar",
                GIT,
                "git",
                "cargo",
                another_grammar(GIT, "git"),
            ),
            (
                "a bound pair on the shim binary, to another grammar",
                MISE,
                "git",
                "cargo",
                another_grammar(MISE, "git"),
            ),
            (
                "another name on the shim binary, to another grammar",
                MISE,
                "cargo",
                "cargo",
                Ok(()),
            ),
            (
                "a bound pair, to the same grammar again",
                GIT,
                "git",
                "git",
                Ok(()),
            ),
            (
                "another name, to the same grammar",
                GIT,
                "git-upload-pack",
                "git",
                Ok(()),
            ),
        ] {
            assert_eq!(
                bindings.bind(&host.program(program), name, grammar),
                expected,
                "{case}: {program} called as {name}, to {grammar}"
            );
        }

        for (case, program, name, expected) in [
            ("the refused unknown grammar", CARGO, "rustc", REFUSED),
            ("the refused pair", GIT, "git", parsed("git")),
            ("the refused pair on the shim", MISE, "git", parsed("git")),
            (
                "the accepted name on the shim",
                MISE,
                "cargo",
                parsed("cargo"),
            ),
            ("the accepted name", GIT, "git-upload-pack", parsed("git")),
        ] {
            assert_eq!(
                answer(bindings.coverage(Ok(host.program(program)), name)),
                expected,
                "{case}: {program} called as {name}"
            );
        }
    }

    #[test]
    fn two_installed_grammars_with_one_name_are_refused_in_any_order() {
        let (git, cargo) = (|v| version("git", v), |v| version("cargo", v));
        for (case, grammars, named) in [
            ("one version twice", vec![git(1), git(1)], "git"),
            ("v1, then v2", vec![git(1), git(2)], "git"),
            ("v2, then v1", vec![git(2), git(1)], "git"),
            (
                "around another grammar",
                vec![git(2), cargo(1), git(1)],
                "git",
            ),
            (
                "before another grammar",
                vec![git(1), git(2), cargo(1)],
                "git",
            ),
            (
                "after another grammar",
                vec![cargo(1), git(1), git(2)],
                "git",
            ),
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
                GrammarBindings::new(grammars).map(|_| ()),
                Err(BindingRefusal::NamedTwice {
                    grammar: named.to_string()
                }),
                "{case}"
            );
        }
    }
}
