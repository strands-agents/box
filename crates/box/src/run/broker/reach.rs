//! The reachable set: what the interpreters may name, and the one resolver over it.
//!
//! One directory has one name for every participant. The agent's home keeps its host path,
//! because an environment variable must be true for the process that reads it: the workload's
//! own syscalls resolve these strings directly, so the Shell must report the same one or the agent
//! reads two names for one directory.
//!
//! **`HOME` and the working directory are two questions.** `HOME` is the agent's home, which is the
//! operator's own unless `[agent] env.HOME` names another directory, and every participant reads the
//! same string for it. `PWD` is the workspace, because that is where the operator's policy names
//! paths — so [`Reach::working_directory`] answers `PWD` and relative-path rooting, and
//! [`Reach::home_variable`] answers `HOME`.
//!
//! The accessors stay separate because the agent's home and the operator home answer different
//! questions. The interpreters report paths under the operator home relative to that home, so
//! checked-in policy remains portable.
//!
//! [`Reach`] holds that set once and both interpreters share it, so the two cannot
//! drift. It also holds the one [`PathResolver`], which is the floor **beneath** policy:
//! it translates the visible home prefix into its canonical host identity, refuses
//! other non-canonical spellings, and refuses an identity outside every
//! declared root. Policy decides first; this cannot widen what policy allowed,
//! and no `permit` can open it.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use policy::{PathRefusal, PathResolver};

use crate::record::config::AuthoritySource;
use crate::run::broker::invalid_input;

/// The set of paths the interpreters may name, and the resolver that admits one.
#[derive(Debug)]
pub(super) struct Reach {
    /// The agent's home, at its host path. One string for the workload, the Shell, and Monty.
    home: String,

    /// The canonical host identity that backs the home's visible spelling.
    home_source: String,

    /// The one resolver over the agent's home, the operator home, and the workspace.
    resolver: PathResolver,

    /// The deny floor: roots no path may resolve into, whatever policy says.
    forbidden: Vec<PathBuf>,

    /// The exact authority-source identities that this run loaded.
    forbidden_exactly: Vec<AuthoritySource>,

    /// The operator home both interpreters may name under policy.
    shared: Option<String>,

    /// The directory a relative path means: the workspace, when the box has one.
    working: Option<String>,
}

impl Reach {
    /// Declare the reachable set from the agent's home, the operator home, and the workspace.
    #[cfg(test)]
    pub(super) fn over(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
    ) -> io::Result<Self> {
        Self::over_with_floor(home, operator_home, working, None, &[])
    }

    pub(super) fn over_box(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
        box_root: &Path,
        protected_sources: &[AuthoritySource],
    ) -> io::Result<Self> {
        Self::over_with_floor(
            home,
            operator_home,
            working,
            Some(box_root),
            protected_sources,
        )
    }

    fn over_with_floor(
        home: &Path,
        operator_home: Option<&Path>,
        working: Option<&Path>,
        box_root: Option<&Path>,
        protected_sources: &[AuthoritySource],
    ) -> io::Result<Self> {
        let home_text = utf8(home, "the agent's home")?;

        let canonical_home = home.canonicalize().map_err(|source| {
            invalid_input(format!(
                "the agent's home {home_text} could not be resolved: {source}"
            ))
        })?;
        let home_source = utf8(&canonical_home, "the resolved home")?;

        let mut forbidden = forbidden_roots();
        if let Some(box_root) = box_root {
            let canonical = box_root.canonicalize().map_err(|source| {
                invalid_input(format!(
                    "the box directory {} could not be resolved: {source}",
                    box_root.display()
                ))
            })?;
            if !forbidden.contains(&canonical) {
                forbidden.push(canonical);
            }
        }
        // The operator home first, so the resolver's own roots read widest-first. The order does
        // not decide anything: `PathResolver` admits a path under any root.
        let shared = match operator_home {
            Some(shared) => {
                let canonical = shared.canonicalize().map_err(|source| {
                    invalid_input(format!(
                        "the operator home {} could not be resolved: {source}",
                        shared.display()
                    ))
                })?;
                Some(canonical)
            }
            None => None,
        };
        let mut roots = Vec::new();
        if let Some(shared) = &shared {
            roots.push(shared.clone());
        }
        if !roots.iter().any(|root| canonical_home.starts_with(root)) {
            roots.push(canonical_home.clone());
        }
        if let Some(working) = working {
            let canonical = working.canonicalize().map_err(|source| {
                invalid_input(format!(
                    "the workspace directory {} could not be resolved: {source}",
                    working.display()
                ))
            })?;
            if !roots.iter().any(|root| canonical.starts_with(root)) {
                roots.push(canonical);
            }
        }
        let mut resolver = PathResolver::over(roots).map_err(|refusal| {
            invalid_input(format!("the reachable set is unusable: {refusal}"))
        })?;
        // **A rule reads `~/<relative>`, so a checked-in policy holds in every clone.**
        //
        if let Some(shared) = &shared {
            resolver = resolver.reporting_under(shared.clone());
        }

        // **Refused rather than corrected, on two counts.**
        //
        let working_text = match working {
            Some(workspace) => {
                let text = utf8(workspace, "the workspace directory")?;
                let canonical = workspace.canonicalize().map_err(|source| {
                    invalid_input(format!(
                        "the workspace directory {text} could not be resolved: {source}"
                    ))
                })?;
                if canonical != workspace {
                    return Err(invalid_input(format!(
                        "the workspace directory is {text} but resolves to {}; the interpreters \
                         would name one directory with two strings",
                        canonical.display()
                    )));
                }
                if resolver.approve_host(&canonical).is_err() {
                    return Err(invalid_input(format!(
                        "the workspace directory {text} is outside this box's reachable set, so \
                         every relative path through an interpreter would be refused"
                    )));
                }
                Some(text)
            }
            None => None,
        };

        Ok(Self {
            home: home_text,
            home_source,
            resolver,
            forbidden,
            forbidden_exactly: protected_sources.to_vec(),
            shared: shared
                .map(|home| utf8(&home, "the operator home"))
                .transpose()?,
            working: working_text,
        })
    }

    /// The directory a relative path means, and what the interpreters report as `PWD`.
    pub(super) fn working_directory(&self) -> &str {
        self.working.as_deref().unwrap_or(&self.home)
    }

    /// The agent's home, at its host path.
    #[cfg(test)]
    pub(super) fn home(&self) -> &str {
        &self.home
    }

    /// The home a reported path is abbreviated against, when this box shares one.
    pub(super) fn reported_home(&self) -> Option<&str> {
        self.shared.as_deref()
    }

    /// The string every participant must read from `HOME`.
    pub(super) fn home_variable(&self) -> &str {
        &self.home
    }

    /// The absolute name a relative spelling means, resolved against the working
    /// directory.
    pub(super) fn absolute(&self, spelled: &str) -> PathBuf {
        let named = Path::new(spelled);
        if named.is_absolute() {
            named.to_path_buf()
        } else {
            // The working directory, not the home, so a relative path means the same file for
            // the script interpreter as it does for the Shell.
            Path::new(self.working_directory()).join(named)
        }
    }

    /// Every root the hosted Shell must bind to the same host path.
    pub(super) fn shell_binds(&self) -> Vec<(&str, &str)> {
        let mut roots = Vec::new();
        for candidate in [
            self.shared.as_deref().map(|path| (path, path)),
            Some((self.home_source.as_str(), self.home.as_str())),
            self.working.as_deref().map(|path| (path, path)),
        ]
        .into_iter()
        .flatten()
        {
            if roots
                .iter()
                .any(|(_, destination)| Path::new(candidate.1).starts_with(destination))
            {
                continue;
            }
            roots.push(candidate);
        }
        roots
    }

    /// Whether this name is backed by a host object at all.
    pub(super) fn names_a_host_path(&self, named: &Path) -> bool {
        self.is_inside_the_set(named)
    }

    /// Approve one interpreter path, returning the host path an effect may act on.
    pub(super) fn approve(&self, named: &Path, reported_as: &str) -> Result<PathBuf, Refused> {
        self.approve_with_source_access(named, reported_as, false)
    }

    /// Approve a path for an operation that can change its bytes or identity.
    pub(super) fn approve_mutation(
        &self,
        named: &Path,
        reported_as: &str,
    ) -> Result<PathBuf, Refused> {
        self.approve_with_source_access(named, reported_as, true)
    }

    fn approve_with_source_access(
        &self,
        named: &Path,
        reported_as: &str,
        mutates: bool,
    ) -> Result<PathBuf, Refused> {
        if !self.is_inside_the_set(named) {
            return Err(Refused::new(reported_as, OUTSIDE_THE_SET));
        }
        let identity = named
            .strip_prefix(&self.home)
            .map(|relative| Path::new(&self.home_source).join(relative))
            .unwrap_or_else(|_| named.to_path_buf());
        let approved = self
            .resolver
            .approve_host(&identity)
            .map(|approved| approved.as_path().to_path_buf())
            .map_err(|refusal| Refused::new(reported_as, reason(&refusal)))?;
        // **The deny floor, applied last and on the canonical identity.**
        //
        self.refuse_forbidden(&approved, reported_as, mutates)?;
        Ok(approved)
    }

    /// Refuse a canonical path that resolves into a root no policy may open.
    fn refuse_forbidden(
        &self,
        approved: &Path,
        reported_as: &str,
        mutates: bool,
    ) -> Result<(), Refused> {
        // The authority this run loaded is trusted Box state wherever it sits, so no operation
        // reaches it; changing its enclosing directory is refused too. It keeps its own reason, so
        // the operator learns which file the run loaded rather than which root refused it.
        if self
            .forbidden_exactly
            .iter()
            .any(|forbidden| forbidden.path() == approved || forbidden.matches(approved))
        {
            return Err(Refused::new(reported_as, AUTHORITY_SOURCE));
        }
        if mutates
            && self
                .forbidden_exactly
                .iter()
                .any(|forbidden| forbidden.path().starts_with(approved))
        {
            return Err(Refused::new(reported_as, AUTHORITY_SOURCE));
        }

        // No exception for a home: `layout::refuse_home_in_box_state` refuses one here first.
        if self.forbidden.iter().any(|root| approved.starts_with(root)) {
            return Err(Refused::new(reported_as, BENEATH_THE_FLOOR));
        }
        Ok(())
    }

    /// Whether `named` lies under a root of this box's reachable set.
    fn is_inside_the_set(&self, named: &Path) -> bool {
        [
            Some(self.home.as_str()),
            self.shared.as_deref(),
            self.working.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|root| named.starts_with(root))
    }
}

/// The one refusal every path outside the set gets, spelled once.
const OUTSIDE_THE_SET: &str = "outside this box's home and every declared bind";

/// The one refusal a path beneath the deny floor gets.
const BENEATH_THE_FLOOR: &str = "resolves into trusted Box state, which no policy may open";

const AUTHORITY_SOURCE: &str =
    "resolves to an authority source that this run loaded, which no policy may open or change";

/// The roots no interpreter path may resolve into, whatever policy permits.
fn forbidden_roots() -> Vec<PathBuf> {
    crate::record::layout::reserved_host_roots()
}

/// Why the reachable set refused a path, named in the caller's own spelling.
#[derive(Debug)]
pub(super) struct Refused {
    /// The spelling the caller used.
    requested: String,

    /// What is wrong with it, in the operator's and the agent's terms.
    reason: &'static str,
}

impl Refused {
    fn new(requested: &str, reason: &'static str) -> Self {
        Self {
            requested: requested.to_string(),
            reason,
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.requested, self.reason)
    }
}

/// Carry a resolver refusal into the words a caller reads.
fn reason(refusal: &PathRefusal) -> &'static str {
    match refusal {
        PathRefusal::NotAbsolute(_) => "is not an absolute path",
        PathRefusal::NotCanonical { .. } => {
            "resolves to a different path, so it is not the identity policy judged"
        }
        PathRefusal::Unreachable(_) => OUTSIDE_THE_SET,
        PathRefusal::Unresolvable { .. } => "cannot be resolved to a path this box acts on",
        // Neither can arise once `Reach::over` has built the resolver, and both are
        // reported there instead. Answered rather than ignored, because a silent
        PathRefusal::NoRoot | PathRefusal::RootNotAbsolute(_) => {
            "cannot be judged, because this box declares no reachable root"
        }
    }
}

fn utf8(path: &Path, description: &str) -> io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        invalid_input(format!(
            "{description} is not valid UTF-8: {}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent home, the whole reachable set for a box with no workspace.
    fn fixture() -> (tempfile::TempDir, Reach) {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        let home = resolved.join("home");
        std::fs::create_dir(&home).expect("the agent's home");

        let reach = Reach::over(&home, None, None).expect("the reachable set is usable");
        (root, reach)
    }

    /// **The home is named by its own host path, and it is the only entry.** The second half of
    /// this asserted a bind at `/workspace`.
    #[test]
    fn the_home_keeps_its_host_path_and_is_the_only_bind() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");

        assert_eq!(
            reach.home(),
            resolved.join("home").to_str().expect("UTF-8"),
            "the home must be named by its host path for every participant"
        );
        assert_eq!(
            reach.shell_binds(),
            [(reach.home(), reach.home())],
            "one entry, the home at its own path: a renamed mount point cannot exist"
        );
    }

    #[test]
    fn a_path_outside_the_reachable_set_is_refused_in_the_callers_spelling() {
        let (_root, reach) = fixture();

        let refused = reach
            .approve(Path::new("/etc/passwd"), "/etc/passwd")
            .expect_err("outside the set");
        assert_eq!(
            refused.to_string(),
            format!("/etc/passwd: {OUTSIDE_THE_SET}")
        );
        assert!(
            !reach.names_a_host_path(Path::new("/etc/passwd")),
            "a path outside the set is backed by no host object"
        );
    }

    /// The refusal must name what the caller wrote, not a path derived from it.
    #[test]
    fn a_refusal_names_the_spelling_the_caller_used() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");

        let refused = reach
            .approve(&reach.absolute("absent/f.txt"), "absent/f.txt")
            .expect_err("a missing parent cannot be resolved");
        assert!(
            refused.to_string().starts_with("absent/f.txt: "),
            "the caller's spelling must lead the refusal: {refused}"
        );
        assert!(
            !refused
                .to_string()
                .contains(resolved.to_str().expect("UTF-8")),
            "the resolved host path must not leak into the refusal: {refused}"
        );
    }

    /// A symlink is refused, because the path policy judged is not the path the effect would
    /// touch.
    #[cfg(unix)]
    #[test]
    fn a_symlink_whose_spelling_is_not_its_identity_is_refused() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/secret"), "s").expect("a secret in the home");
        std::os::unix::fs::symlink(resolved.join("home/secret"), resolved.join("home/link"))
            .expect("a link beside the secret it names");

        let named = resolved.join("home/link");
        let refused = reach
            .approve(&named, named.to_str().expect("UTF-8"))
            .expect_err("a link is not its own identity, however reachable both ends are");
        assert!(
            refused
                .to_string()
                .contains("not the identity policy judged"),
            "the refusal must say the spelling is not the identity: {refused}"
        );
    }

    /// A relative spelling means the same file it means in the Shell, because both
    /// resolve it against the working directory.
    #[test]
    fn a_relative_spelling_resolves_against_the_working_directory() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::write(resolved.join("home/notes.txt"), "n").expect("a file in the home");

        assert_eq!(
            reach.absolute("notes.txt"),
            resolved.join("home/notes.txt"),
            "a relative path must resolve against the working directory, not the root"
        );
        let approved = reach
            .approve(&reach.absolute("notes.txt"), "notes.txt")
            .expect("a relative path inside the home is reachable");
        assert_eq!(approved, resolved.join("home/notes.txt"));
        let already_absolute = resolved.join("home/notes.txt");
        assert_eq!(
            reach.absolute(already_absolute.to_str().expect("UTF-8")),
            already_absolute,
            "an absolute spelling is already what it means"
        );
    }

    /// A new leaf is approved, because a create names a path that does not exist yet.
    #[test]
    fn a_new_leaf_inside_the_home_is_approved() {
        let (root, reach) = fixture();
        let resolved = root.path().canonicalize().expect("the root resolves");
        let requested = resolved.join("home/new.txt");

        let approved = reach
            .approve(&requested, requested.to_str().expect("UTF-8"))
            .expect("a create inside the home is reachable");
        assert_eq!(approved, requested);
    }

    /// An ancestor symlink may spell the visible home, while effects use its canonical identity.
    #[cfg(unix)]
    #[test]
    fn an_ancestor_symlink_spelling_binds_to_the_canonical_home_identity() {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        std::fs::create_dir(resolved.join("real")).expect("real parent");
        std::fs::create_dir(resolved.join("real/home")).expect("the agent's home");
        std::os::unix::fs::symlink(resolved.join("real"), resolved.join("visible"))
            .expect("visible parent");
        let visible = resolved.join("visible/home");
        let canonical = resolved.join("real/home");

        let reach = Reach::over(&visible, None, None).expect("the visible home is reachable");
        assert_eq!(reach.home(), visible.to_str().expect("UTF-8"));
        assert_eq!(
            reach.shell_binds(),
            [(
                canonical.to_str().expect("UTF-8"),
                visible.to_str().expect("UTF-8")
            )]
        );
        assert_eq!(
            reach
                .approve(
                    &visible.join("new.txt"),
                    visible.join("new.txt").to_str().expect("UTF-8"),
                )
                .expect("the visible spelling resolves"),
            canonical.join("new.txt")
        );
    }

    /// A non-canonical spelling of the box home, offered as the workspace, is
    /// refused rather than silently corrected, so the interpreters cannot name one directory two
    /// ways.
    #[cfg(unix)]
    #[test]
    fn a_non_canonical_workspace_spelling_of_the_home_is_refused() {
        let root = tempfile::tempdir().expect("a fixture root");
        let resolved = root.path().canonicalize().expect("the root resolves");
        let home = resolved.join("home");
        std::fs::create_dir(&home).expect("the box home");
        // A second spelling of the home, through a symlink beside it.
        std::os::unix::fs::symlink(&home, resolved.join("visible")).expect("a link to the home");
        let visible = resolved.join("visible");

        let refusal = Reach::over(&home, None, Some(&visible))
            .expect_err("a workspace that resolves to a different string is refused");
        let message = refusal.to_string();
        assert!(
            message.contains("resolves to") && message.contains("two strings"),
            "the refusal must say the spelling resolves to another, not silently accept it: \
             {message}"
        );
    }

    // ── The deny floor ─────────────────────────────────────────────────────────

    /// A `Reach` whose home is the operator home itself, over a caller-selected box directory that
    /// holds this box's stored policy.
    fn operator_home_fixture() -> (tempfile::TempDir, Reach) {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let private = resolved.join("boxes/codex/private");
        std::fs::create_dir_all(&private).expect("this box's private tree");
        std::fs::write(private.join("policy.dw"), "// the stored rules\n").expect("its policy");
        std::fs::create_dir_all(resolved.join("workspace/service")).expect("a workspace");

        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                None,
                &resolved.join("boxes/codex"),
                &[],
            )
            .expect("the reachable set is usable")
        });
        (operator, reach)
    }

    /// **A path inside the box directory is refused, and no policy is consulted.**
    ///
    /// This is the sharpest hazard of interpreter reach: the interpreters see the whole
    #[test]
    fn a_path_inside_the_box_directory_is_beneath_the_floor() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("boxes/codex/private/policy.dw");

        let refusal = crate::test_support::with_operator_home(&resolved, || {
            reach
                .approve(&target, target.to_str().expect("UTF-8"))
                .expect_err("this box's stored policy must be unreachable")
        })
        .to_string();
        assert!(
            refusal.contains(BENEATH_THE_FLOOR),
            "the refusal must say the floor refused it, not that policy did: {refusal}"
        );
    }

    /// The box directory itself is refused, not merely its contents, whether the caller reads it
    /// or changes it.
    #[test]
    fn the_box_directory_itself_is_beneath_the_floor_for_every_operation() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("boxes/codex");
        let spelled = target.to_str().expect("UTF-8");

        crate::test_support::with_operator_home(&resolved, || {
            assert!(
                reach.approve(&target, spelled).is_err(),
                "the box directory holds this box's state, so reading it must be refused"
            );
            assert!(
                reach.approve_mutation(&target, spelled).is_err(),
                "the box directory holds this box's state, so changing it must be refused"
            );
        });
    }

    /// **The floor makes no exception for a home**: a home declared inside the box directory
    /// reaches nothing there.
    #[test]
    fn a_home_inside_trusted_box_state_reaches_nothing_there() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let box_root = resolved.join("boxes/codex");
        let home = box_root.join("home");
        std::fs::create_dir_all(&home).expect("a home inside the box directory");

        for target in [home.clone(), home.join("note.txt")] {
            let reach = crate::test_support::with_operator_home(&resolved, || {
                Reach::over_box(&home, Some(&resolved), None, &box_root, &[])
                    .expect("the reachable set is declarable")
            });
            let spelled = target.to_str().expect("UTF-8");
            let refusal = crate::test_support::with_operator_home(&resolved, || {
                reach.approve(&target, spelled)
            })
            .err()
            .unwrap_or_else(|| panic!("{spelled} must be beneath the floor"))
            .to_string();
            assert!(refusal.contains(BENEATH_THE_FLOOR), "{spelled}: {refusal}");
        }
    }

    /// A symlink into the box directory is refused — **by the resolver, not by the floor.**
    ///
    /// Measured 2026-08-18 by deleting the floor: this test still passed, because
    #[test]
    fn a_symlink_into_the_box_directory_is_refused() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let link = resolved.join("workspace/service/shortcut");
        std::os::unix::fs::symlink(resolved.join("boxes/codex/private"), &link)
            .expect("plant the link");

        let target = link.join("policy.dw");
        assert!(
            crate::test_support::with_operator_home(&resolved, || reach
                .approve(&target, target.to_str().expect("UTF-8"),))
            .is_err(),
            "a link into the box directory must be refused on its canonical identity"
        );
    }

    /// **A sibling box's authority under the reachable set passes the floor**, so policy decides:
    /// only this run's own sources and trusted Box state sit beneath it, whatever a directory is
    /// called.
    #[test]
    fn a_sibling_boxs_authority_passes_the_floor_and_policy_decides() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let sibling = resolved.join("workspace/service/.strands-box");
        std::fs::create_dir_all(&sibling).expect("a sibling box's directory");
        std::fs::write(sibling.join("policy.dw"), "permit(...)").expect("its policy");

        for target in [sibling.clone(), sibling.join("policy.dw")] {
            let spelled = target.to_str().expect("UTF-8");
            reach
                .approve(&target, spelled)
                .unwrap_or_else(|error| panic!("{spelled} is policy's to decide: {error}"));
            reach
                .approve_mutation(&target, spelled)
                .unwrap_or_else(|error| panic!("{spelled} is policy's to decide: {error}"));
        }
    }

    /// **A loaded authority source is beneath the floor wherever it sits**, so a policy read from
    /// beside the project is no more readable than one under it.
    #[test]
    fn a_loaded_authority_source_is_beneath_the_floor_wherever_it_sits() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let policy = resolved.join("workspace/policy.dw");
        std::fs::create_dir_all(resolved.join("workspace")).expect("a workspace");
        std::fs::write(&policy, "permit(...)").expect("a policy beside the project");
        let (source, _text) =
            AuthoritySource::read(&policy, "policy").expect("the authority loads");
        std::fs::create_dir(resolved.join("box")).expect("a box directory");
        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                None,
                &resolved.join("box"),
                &[source],
            )
            .expect("the reachable set is usable")
        });

        let refusal = reach
            .approve(&policy, policy.to_str().expect("UTF-8"))
            .expect_err("the loaded policy must be unreadable through the interpreters")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
        assert!(
            !refusal.contains(BENEATH_THE_FLOOR),
            "a source outside any product directory does not borrow that reason: {refusal}"
        );
        // The enclosing directory keeps its own refusal, and keeps its own reason: a read is fine,
        // and only an operation that could change the source's identity is refused.
        let enclosing = resolved.join("workspace");
        reach
            .approve(&enclosing, enclosing.to_str().expect("UTF-8"))
            .expect("the directory beside the policy stays reachable");
        let refusal = reach
            .approve_mutation(&enclosing, enclosing.to_str().expect("UTF-8"))
            .expect_err("the directory holding a loaded source may not be changed")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
    }

    /// **A configuration `--config` named outside the workspace is protected identically**: the
    /// source is refused for every operation, and the directory holding it may not be changed.
    #[test]
    fn a_config_loaded_from_outside_the_workspace_is_beneath_the_floor() {
        let operator = tempfile::tempdir().expect("an operator home");
        let resolved = operator.path().canonicalize().expect("the home resolves");
        let authority = resolved.join("elsewhere/authority");
        std::fs::create_dir_all(&authority).expect("the authority directory");
        std::fs::create_dir_all(resolved.join("workspace")).expect("a workspace");
        let config = authority.join("control.toml");
        std::fs::write(&config, "name = \"elsewhere\"\n").expect("a configuration");
        let (source, _text) = AuthoritySource::read(&config, "config").expect("the config loads");
        std::fs::create_dir(resolved.join("box")).expect("a box directory");
        let reach = crate::test_support::with_operator_home(&resolved, || {
            Reach::over_box(
                &resolved,
                Some(&resolved),
                Some(&resolved.join("workspace")),
                &resolved.join("box"),
                &[source],
            )
            .expect("the reachable set is usable")
        });

        let spelled = config.to_str().expect("UTF-8");
        for outcome in [
            reach.approve(&config, spelled),
            reach.approve_mutation(&config, spelled),
        ] {
            let refusal = outcome
                .expect_err("the loaded configuration is beneath the floor")
                .to_string();
            assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
        }
        let spelled = authority.to_str().expect("UTF-8");
        reach
            .approve(&authority, spelled)
            .expect("the directory holding the configuration stays readable");
        let refusal = reach
            .approve_mutation(&authority, spelled)
            .expect_err("the directory holding the configuration may not be changed")
            .to_string();
        assert!(refusal.contains(AUTHORITY_SOURCE), "{refusal}");
    }

    /// An ordinary workspace path is still reachable, so the floor is a floor and not a wall.
    #[test]
    fn an_ordinary_project_path_is_still_reachable() {
        let (operator, reach) = operator_home_fixture();
        let resolved = operator.path().canonicalize().expect("resolves");
        let target = resolved.join("workspace/service");

        assert!(
            crate::test_support::with_operator_home(&resolved, || reach
                .approve(&target, target.to_str().expect("UTF-8"),))
            .is_ok(),
            "the floor must refuse only trusted Box state and the sources this run loaded"
        );
    }
}
