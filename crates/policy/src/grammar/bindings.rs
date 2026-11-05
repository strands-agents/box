//! The installed tool grammars, each bound to a program file's identity and the name it is called
//! by (docs/design/decisions.md#a-tool-grammar-binds-on-the-program-file-and-the-called-name).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{Grammar, ToolGrammars};

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

/// The tool grammars an engine installs, the (program file, called name) pairs each one covers, and
/// the file identity that each bound spelling led to when it was bound.
#[derive(Debug)]
pub struct GrammarBindings {
    issuer: u64,
    grammars: Vec<Arc<Grammar>>,
    bound: BTreeMap<(FileIdentity, String), usize>,
    spellings: BTreeMap<PathBuf, FileIdentity>,
    named: BTreeMap<String, BTreeMap<PathBuf, FileIdentity>>,
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
        "`{name}` runs `{}`, which a tool grammar covers, but no `[tool]` or `[mcp]` declares the name `{name}`",
        .program_path.display()
    )]
    UndeclaredName { name: String, program_path: PathBuf },
    #[error(
        "`{name}` runs `{}`, which a tool grammar bound, but the file at that path is no longer the file it bound",
        .program_path.display()
    )]
    ReplacedFile { name: String, program_path: PathBuf },
}

/// Why Box refuses to declare a tool, or to install bindings.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BindingRefusal {
    /// Box cannot read the identity of a declared program file.
    #[error("cannot read the program file {}: {reason}", .program_path.display())]
    UnreadableProgram {
        /// The path the `[tool]` command resolved to.
        program_path: PathBuf,
        /// What the host reported.
        reason: String,
    },
    /// The bindings came from another engine.
    #[error("the tool grammar bindings came from another policy engine")]
    AnotherEngine,
}

/// The name a program was called by: the last component of its spelling.
pub(crate) fn called_name(spelling: &str) -> &str {
    Path::new(spelling)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(spelling)
}

impl GrammarBindings {
    /// Hold the grammars that the engine `issuer` installs, and no binding yet.
    pub(crate) fn installed(grammars: &ToolGrammars, issuer: u64) -> Self {
        Self {
            issuer,
            grammars: grammars
                .iter()
                .map(|tool| Arc::clone(tool.grammar()))
                .collect(),
            bound: BTreeMap::new(),
            spellings: BTreeMap::new(),
            named: BTreeMap::new(),
            declared: BTreeSet::new(),
        }
    }

    /// The engine that issued these bindings.
    pub(crate) fn issuer(&self) -> u64 {
        self.issuer
    }

    /// Declare that a `[tool]` runs the program file `opened`, which sits at the canonical `path`
    /// and is called through `invoked`, under the name `called`, and bind the grammar whose
    /// `program` is `called`, when one is installed
    /// (docs/design/decisions.md#a-tool-grammar-binds-on-the-program-file-and-the-called-name).
    pub fn declare_tool(
        &mut self,
        opened: &std::fs::File,
        path: &Path,
        invoked: &Path,
        called: &str,
    ) -> Result<(), BindingRefusal> {
        let metadata = opened
            .metadata()
            .map_err(|reason| BindingRefusal::UnreadableProgram {
                program_path: path.to_path_buf(),
                reason: reason.to_string(),
            })?;
        let mut spellings = links_from(invoked);
        if !spellings.iter().any(|spelling| spelling == path) {
            spellings.push(path.to_path_buf());
        }
        let program = ProgramFile {
            identity: FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            path: path.to_path_buf(),
            spellings,
        };
        self.declare(&program, called);
        Ok(())
    }

    /// Declare that a `[tool]` runs `program` under the name `called`, and bind the grammar whose
    /// `program` is `called`, when one is installed.
    pub(crate) fn declare(&mut self, program: &ProgramFile, called: &str) {
        let pair = (program.identity, called.to_string());
        self.declared.insert(pair.clone());
        let Some(index) = self
            .grammars
            .iter()
            .position(|grammar| grammar.program == called)
        else {
            return;
        };
        for spelling in &program.spellings {
            self.spellings
                .entry(spelling.clone())
                .or_insert(program.identity);
            self.named
                .entry(called.to_string())
                .or_default()
                .entry(spelling.clone())
                .or_insert(program.identity);
        }
        self.bound.insert(pair, index);
    }

    /// Whether no grammar binds any file.
    pub(crate) fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }

    /// The first spelling bound under `name` that no longer leads to the file it was bound to.
    fn gone_under(&self, name: &str) -> Option<&Path> {
        self.named.get(name)?.iter().find_map(|(spelling, bound)| {
            let now = std::fs::metadata(spelling).ok().map(|found| FileIdentity {
                device: found.dev(),
                inode: found.ino(),
            });
            (now != Some(*bound)).then_some(spelling.as_path())
        })
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
        if !spelling.contains('/')
            && let Some(gone) = self.gone_under(name)
        {
            return refused(replaced, gone);
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
            // Keep the old inode allocated, as a running process does, so no later file reuses it.
            std::fs::hard_link(self.path(relative), self.path(&format!("{relative}.old")))
                .expect("the old build stays allocated");
            std::fs::write(&staged, "a new build").expect("a new program file");
            std::fs::rename(&staged, self.path(relative)).expect("the rename");
            self.program(relative)
        }
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
    fn a_grammar_binds_every_declared_tool_that_runs_its_program() {
        let host = Host::new();
        let system = host.program(GIT);
        let homebrew = host.program("opt/homebrew/bin/git");
        let cli = host.program("usr/bin/gh");
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);

        for (program, called) in [(&system, "git"), (&homebrew, "git"), (&cli, "gh")] {
            let opened = std::fs::File::open(program.path()).expect("the program opens");
            bindings
                .declare_tool(&opened, program.path(), program.path(), called)
                .expect("the tool declares");
        }

        assert_eq!(answer(bindings.coverage(Ok(system), "git")), parsed("git"));
        assert_eq!(
            answer(bindings.coverage(Ok(homebrew), "git")),
            parsed("git")
        );
        assert_eq!(answer(bindings.coverage(Ok(cli), "gh")), None);
    }

    #[test]
    fn a_tool_is_bound_to_the_file_it_was_opened_as_and_not_to_what_its_path_holds_now() {
        let host = Host::new();
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);
        let original = host.program(GIT);
        let opened = std::fs::File::open(original.path()).expect("the program opens");
        host.replace(GIT);

        bindings
            .declare_tool(&opened, original.path(), original.path(), "git")
            .expect("the tool declares");

        assert_eq!(
            answer(bindings.coverage(Ok(host.program(GIT)), "git")),
            Some(Answer::Replaced),
            "the file at the path now is not the file that was approved"
        );
    }

    #[test]
    fn a_bare_name_whose_bound_file_is_gone_is_refused_and_does_not_fall_through_the_search_path() {
        let host = Host::new();
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);
        bindings.declare(&host.program(GIT), "git");
        let later = host.program("usr/local/bin/git");
        std::fs::remove_file(host.path(GIT)).expect("the bound file is removed");

        assert_eq!(
            answer(bindings.coverage(Ok(later.clone()), "git")),
            Some(Answer::Replaced),
            "a bare name found further along the search path"
        );
        assert_eq!(
            answer(bindings.coverage(Ok(later.clone()), &later.path().display().to_string())),
            None,
            "a path that names another file"
        );
    }

    #[test]
    fn each_spawn_resolves_by_its_program_file_and_its_called_name() {
        let host = Host::new();
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git", "cargo"]), 0);
        bindings.declare(&host.program(GIT), "git");
        bindings.declare(&host.program(CARGO), "rustc");
        bindings.declare(&host.program(CARGO), "cargo");
        bindings.declare(&host.program(MISE), "node");
        bindings.declare(&host.program(MISE), "npm");
        bindings.declare(&host.program(MISE), "git");
        for shim in [
            host.program(RENAMED_MISE),
            host.symlink(FIRST_MISE, LINKED_MISE),
        ] {
            bindings.declare(&shim, "node");
            bindings.declare(&shim, "cargo");
        }
        let _original_shim = std::fs::File::open(host.path(RENAMED_MISE))
            .expect("the replaced shim stays open so its file identity cannot be reused");
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
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["cargo", "aws"]), 0);
        let mise = host.program(MISE);
        bindings.declare(&mise, "cargo");
        bindings.declare(&mise, "aws");
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
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);
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
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git", "cargo"]), 0);
        bindings.declare(&host.program(GIT), "git");
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
        }
    }

    #[test]
    fn a_replaced_file_at_a_bound_path_is_refused() {
        let host = Host::new();
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);
        let original = host.program(GIT);
        bindings.declare(&original, "git");
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
        let mut bindings = GrammarBindings::installed(&ToolGrammars::corpus(&["git"]), 0);
        let linked = host.symlink("opt/cellar/git/1/bin/git", "opt/bin/git");
        bindings.declare(&linked, "git");

        let upgraded = host.program("opt/cellar/git/2/bin/git");
        std::fs::remove_file(host.path("opt/bin/git")).expect("the old link is removed");
        std::os::unix::fs::symlink(upgraded.path(), host.path("opt/bin/git")).expect("a new link");

        assert_eq!(
            answer(bindings.coverage(Ok(upgraded.clone()), "git")),
            Some(Answer::Replaced),
            "the file that the bound link leads to now"
        );
        let elsewhere = host.program("opt/cellar/git/3/bin/git");
        assert_eq!(
            answer(bindings.coverage(Ok(elsewhere.clone()), "git")),
            Some(Answer::Replaced),
            "a file that no bound path leads to, called by the bare name"
        );
        assert_eq!(
            answer(bindings.coverage(
                Ok(elsewhere.clone()),
                &elsewhere.path().display().to_string()
            )),
            None,
            "a file that no bound path leads to, called by its own path"
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
                "`python` runs `/usr/local/bin/mise`, which a tool grammar covers, but no `[tool]` or \
                 `[mcp]` declares the name `python`",
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
}
