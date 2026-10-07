//! The approved-path type, and the only resolver that mints one.
//!
//! [`Request::Fs`] documented its path as canonicalized and typed it `&Path`, so the
//! claim rested on every call site staying correct. It did not: the Shell adapter built
//! the request from a raw string. [`ApprovedPath`] moves the claim into the type, so a
//! raw spelling no longer compiles.
//!
//! [`Request::Fs`]: crate::Request::Fs

use std::path::{Path, PathBuf};

/// A filesystem path a resolver approved.
///
/// [`Request::Fs`] accepts nothing else, so an unresolved path cannot reach `decide`.
/// There is no public constructor and no `From` conversion. A caller outside
/// this crate obtains one only from [`PathResolver`], which resolves the path in a
/// stated namespace and refuses one outside the declared reachable set.
///
/// The value is the canonical identity the resolver approved, not the caller's
/// spelling. A refusal message still names the caller's spelling, because the
/// refusal carries it.
///
/// [`Request::Fs`]: crate::Request::Fs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPath {
    path: PathBuf,
    /// The spelling a RULE reads, when it differs from the canonical one.
    ///
    /// `None` means a rule reads [`ApprovedPath::as_path`] verbatim.
    reported: Option<String>,
}

impl ApprovedPath {
    /// The canonical path this approval covers, and the one every effect must act on.
    ///
    /// **This is the value the kernel gets. It is never the value a rule reads.** The two are
    /// separate because this crate has been bitten twice by "validate one spelling, act on another"
    /// — both Python-boundary escapes were exactly that shape. Keeping the effect on this accessor
    /// and the decision on [`ApprovedPath::reported`] is what makes the split visible at every call
    /// site rather than incidental.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// The spelling a rule reads as `context.input.path`.
    ///
    /// **Home-relative when the path is under the operator's home, and canonical otherwise.** A
    /// policy is checked into the operator's repository and has to hold in every clone, and a host
    /// path holds only on the machine that wrote it — `/home/alex/service` means nothing on a
    /// teammate's laptop. `~/service` means the same thing on both.
    ///
    /// It is safe to abbreviate here precisely because the Shell's reachable root *is* the operator
    /// home: every path an interpreter can resolve already sits under it, so `~` names the root the
    /// mount table already uses rather than inventing a second namespace.
    ///
    /// **Only the decision reads this.** `to_cedar_request` and the temporal event take it; every
    /// effect takes [`ApprovedPath::as_path`]. A caller that acted on this value would be acting on
    /// a path the kernel does not know.
    #[must_use]
    pub fn reported(&self) -> std::borrow::Cow<'_, str> {
        match &self.reported {
            Some(reported) => std::borrow::Cow::Borrowed(reported),
            None => self.path.to_string_lossy(),
        }
    }

    /// Mint an approval with no reported spelling, for a test that does not exercise reporting.
    ///
    /// **Test-only, and that is the honest marker.** Both adapters mint through
    /// [`ApprovedPath::under_home`] now, so production never reaches this — and a `pub(crate)` mint
    /// with no caller outside tests is dead code the compiler reports. It stays because four
    /// decision tests care about the path and not about how it is spelled.
    #[cfg(test)]
    pub(crate) fn interpreter_resolved(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            reported: None,
        }
    }

    /// Mint an approval whose reported spelling is relative to `home`.
    ///
    /// Crate-private for the same reason [`ApprovedPath::interpreter_resolved`] is: a public mint
    /// would let a caller choose what a rule sees, which is the whole authority this type carries.
    pub(crate) fn under_home(path: impl Into<PathBuf>, home: Option<&Path>) -> Self {
        let path = path.into();
        let reported = home.and_then(|home| {
            let relative = path.strip_prefix(home).ok()?;
            // The home itself reports as `~`, and anything under it as `~/<relative>`. An empty
            // relative component would render `~/`, which is the same directory spelled worse.
            Some(if relative.as_os_str().is_empty() {
                "~".to_string()
            } else {
                format!("~/{}", relative.to_string_lossy())
            })
        });
        Self { path, reported }
    }
}

/// Why a [`PathResolver`] refused a path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathRefusal {
    /// A declared root is not absolute, so no path can be tested against it.
    #[error("declared root is not absolute: {0}")]
    RootNotAbsolute(PathBuf),

    /// The resolver holds no root, so nothing is reachable.
    #[error("the resolver declares no reachable root")]
    NoRoot,

    /// The requested path is relative. The resolver has no working directory of its
    /// own, so a caller resolves a relative path before asking.
    #[error("path is not absolute: {0}")]
    NotAbsolute(PathBuf),

    /// The requested spelling differs from the canonical identity it resolves to.
    /// Judging the spelling and acting on the canonical form is how a symlink
    /// or a `..` segment evades the rule that guarded the path.
    #[error("path {requested} resolves to {canonical}, so the requested spelling is not canonical")]
    NotCanonical {
        /// The spelling the caller used.
        requested: PathBuf,
        /// The identity it resolves to.
        canonical: PathBuf,
    },

    /// The path resolves outside every declared root.
    #[error("path {0} is outside every declared root")]
    Unreachable(PathBuf),

    /// The namespace could not resolve the path at all.
    #[error("path {path} could not be resolved: {reason}")]
    Unresolvable {
        /// The spelling the caller used.
        path: PathBuf,
        /// What the namespace reported.
        reason: String,
    },
}

/// The reachable set a path must resolve inside, and the only public minter of an
/// [`ApprovedPath`].
///
/// One resolver serves both interpreters. The box home and every declared bind
/// destination are its roots, and a path under none of them is refused before any rule
/// is consulted. The resolver holds no policy authority: it decides reachability, and
/// policy decides permission.
///
/// The two `approve_*` methods differ only in the namespace they resolve in, because
/// the two interpreters do not share one. `std::fs::canonicalize` answers in the
/// **host** namespace, which is the wrong one for a script path.
#[derive(Debug, Clone)]
pub struct PathResolver {
    roots: Vec<PathBuf>,
    /// The operator home a reported path is abbreviated against, when there is one.
    ///
    /// Held here rather than passed per call, so every path this resolver mints reports the same
    /// way. A per-call home is how two paths for one directory end up spelled differently.
    home: Option<PathBuf>,
}

impl PathResolver {
    /// Declare the reachable set: the box home first, then each bind destination.
    ///
    /// Every root must be absolute. A relative root would make `starts_with` compare
    /// two things that are not comparable, and every path would then be refused — a
    /// misconfiguration that is better reported here than diagnosed later.
    pub fn over(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self, PathRefusal> {
        let roots: Vec<PathBuf> = roots.into_iter().collect();
        if roots.is_empty() {
            return Err(PathRefusal::NoRoot);
        }
        for root in &roots {
            if !root.is_absolute() {
                return Err(PathRefusal::RootNotAbsolute(root.clone()));
            }
        }
        Ok(Self { roots, home: None })
    }

    /// Report every approved path relative to `home`.
    ///
    /// **Consuming, and it changes what rules read rather than what effects do.** A path under
    /// `home` is reported as `~/<relative>`, so a `policy.dw` checked into a repository holds in
    /// every clone. `ApprovedPath::as_path` is unaffected, which is what keeps the effect acting on
    /// the identity the kernel checks.
    #[must_use]
    pub fn reporting_under(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Approve a path in the **host** namespace, following symlinks.
    ///
    /// This is the box's seam. It resolves with the filesystem, refuses a spelling that
    /// differs from the canonical identity, and refuses an identity outside every
    /// declared root.
    ///
    /// A path that does not exist yet is a legitimate target of a create, so the parent
    /// is canonicalized and the leaf name is rejoined. Anything already present at that
    /// leaf name is refused: `symlink_metadata` does not follow, so a dangling link
    /// shows as a link rather than as absent, and a create has nothing there.
    pub fn approve_host(&self, requested: &Path) -> Result<ApprovedPath, PathRefusal> {
        if !requested.is_absolute() {
            return Err(PathRefusal::NotAbsolute(requested.to_path_buf()));
        }
        let canonical = match std::fs::canonicalize(requested) {
            Ok(canonical) => canonical,
            Err(error) => {
                let parent = requested
                    .parent()
                    .ok_or_else(|| PathRefusal::Unresolvable {
                        path: requested.to_path_buf(),
                        reason: error.to_string(),
                    })?;
                let name = requested
                    .file_name()
                    .ok_or_else(|| PathRefusal::Unresolvable {
                        path: requested.to_path_buf(),
                        reason: error.to_string(),
                    })?;
                let leaf = std::fs::canonicalize(parent)
                    .map_err(|error| PathRefusal::Unresolvable {
                        path: requested.to_path_buf(),
                        reason: error.to_string(),
                    })?
                    .join(name);
                if leaf.symlink_metadata().is_ok() {
                    return Err(PathRefusal::Unresolvable {
                        path: requested.to_path_buf(),
                        reason: "the leaf name is already taken by an object this \
                                 resolver will not write through"
                            .to_string(),
                    });
                }
                leaf
            }
        };
        self.admit(requested, canonical)
    }

    /// Approve a path in an interpreter's **virtual** namespace, with no I/O.
    ///
    /// A script path lives in the interpreter's own namespace, and a host
    /// canonicalization answers about a different one. So this method closes `.` and
    /// `..` lexically and treats the result as the canonical identity. It follows no
    /// symlink, because the virtual namespace declares none.
    ///
    /// The identity it returns is what the caller must act on, and the box compares its
    /// own host-canonical result against it. That comparison is the symlink defence for
    /// this path, not this method.
    pub fn approve_virtual(&self, requested: &Path) -> Result<ApprovedPath, PathRefusal> {
        if !requested.is_absolute() {
            return Err(PathRefusal::NotAbsolute(requested.to_path_buf()));
        }
        let canonical = normalize_virtual(&requested.to_string_lossy());
        self.admit_resolved(requested, canonical)
    }

    /// Refuse a non-canonical spelling, then refuse an unreachable identity.
    fn admit(&self, requested: &Path, canonical: PathBuf) -> Result<ApprovedPath, PathRefusal> {
        if canonical != requested {
            return Err(PathRefusal::NotCanonical {
                requested: requested.to_path_buf(),
                canonical,
            });
        }
        self.admit_resolved(requested, canonical)
    }

    /// Refuse an identity outside every declared root.
    fn admit_resolved(
        &self,
        requested: &Path,
        canonical: PathBuf,
    ) -> Result<ApprovedPath, PathRefusal> {
        if self.roots.iter().any(|root| canonical.starts_with(root)) {
            Ok(ApprovedPath::under_home(canonical, self.home.as_deref()))
        } else {
            // The caller's spelling is what the refusal names.
            Err(PathRefusal::Unreachable(requested.to_path_buf()))
        }
    }
}

/// Close `.` and `..` in a virtual path, so neither can alias the identity policy judges.
///
/// One implementation serves [`PathResolver::approve_virtual`] and the script adapter,
/// so the two cannot drift.
pub(crate) fn normalize_virtual(path: &str) -> PathBuf {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            // An empty span comes from a leading, trailing, or doubled separator; `.`
            // names the directory it sits in. Neither changes which object is meant.
            "" | "." => {}
            // Pop, but never past the root: `/..` is `/`, so stacking `..` cannot climb
            // out of the namespace.
            ".." => {
                parts.pop();
            }
            named => parts.push(named),
        }
    }
    if parts.is_empty() {
        return PathBuf::from("/");
    }
    let mut normalized = String::with_capacity(path.len() + 1);
    for part in &parts {
        normalized.push('/');
        normalized.push_str(part);
    }
    PathBuf::from(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(root: &str) -> PathResolver {
        PathResolver::over([PathBuf::from(root)]).expect("an absolute root is accepted")
    }

    #[test]
    fn a_resolver_needs_at_least_one_absolute_root() {
        assert_eq!(
            PathResolver::over(Vec::new()).unwrap_err(),
            PathRefusal::NoRoot
        );
        assert_eq!(
            PathResolver::over([PathBuf::from("work")]).unwrap_err(),
            PathRefusal::RootNotAbsolute(PathBuf::from("work"))
        );
    }

    #[test]
    fn a_relative_path_is_refused_rather_than_guessed() {
        // The resolver holds no working directory, so it cannot resolve `file.txt`.
        // Guessing a root would make the same spelling mean a different file per root.
        let resolver = resolver("/workspace");
        assert_eq!(
            resolver.approve_virtual(Path::new("file.txt")).unwrap_err(),
            PathRefusal::NotAbsolute(PathBuf::from("file.txt"))
        );
    }

    #[test]
    fn a_path_outside_every_root_is_refused() {
        let resolver = resolver("/workspace");
        assert_eq!(
            resolver
                .approve_virtual(Path::new("/etc/passwd"))
                .unwrap_err(),
            PathRefusal::Unreachable(PathBuf::from("/etc/passwd"))
        );
    }

    /// `starts_with` compares whole components, so a sibling whose name merely begins
    /// with the root's name is outside it. A `str::starts_with` here would admit
    /// `/workspace-evil`.
    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_inside_the_root() {
        let resolver = resolver("/workspace");
        assert!(
            resolver
                .approve_virtual(Path::new("/workspace-evil/key.pem"))
                .is_err()
        );
        assert!(resolver.approve_virtual(Path::new("/workspace/a")).is_ok());
    }

    #[test]
    fn a_virtual_path_is_approved_at_its_normalized_identity() {
        let resolver = resolver("/workspace");
        let approved = resolver
            .approve_virtual(Path::new("/workspace/./sub/../main.py"))
            .expect("the normalized identity is inside the root");
        assert_eq!(approved.as_path(), Path::new("/workspace/main.py"));
    }

    /// The escape the normalizer closes: `..` climbing out of the root is judged at the
    /// identity it reaches, so it is refused rather than judged as the spelling.
    #[test]
    fn a_dot_dot_escape_is_judged_at_the_identity_it_reaches() {
        let resolver = resolver("/workspace");
        assert!(
            resolver
                .approve_virtual(Path::new("/workspace/../etc/passwd"))
                .is_err()
        );
    }

    #[test]
    fn the_host_resolver_refuses_a_non_canonical_spelling() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(home.path()).expect("the root canonicalizes");
        std::fs::create_dir(root.join("sub")).expect("a subdirectory");
        std::fs::write(root.join("sub/main.py"), "x").expect("a file");

        let resolver = PathResolver::over([root.clone()]).expect("an absolute root");
        assert!(resolver.approve_host(&root.join("sub/main.py")).is_ok());

        let spelled = root.join("sub/../sub/main.py");
        let refusal = resolver.approve_host(&spelled).unwrap_err();
        assert!(
            matches!(refusal, PathRefusal::NotCanonical { .. }),
            "a non-canonical spelling must refuse, got {refusal:?}"
        );
    }

    /// A symlink pointing out of the root is refused at its target, which is the escape
    /// the crate's `AGENTS.md` records as undefended on the script side.
    #[cfg(unix)]
    #[test]
    fn the_host_resolver_refuses_a_symlink_leading_out_of_the_root() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let outside = tempfile::tempdir().expect("a second temporary directory");
        let root = std::fs::canonicalize(home.path()).expect("the root canonicalizes");
        let secret = std::fs::canonicalize(outside.path())
            .expect("the outside canonicalizes")
            .join("key.pem");
        std::fs::write(&secret, "secret").expect("a file outside the root");
        std::os::unix::fs::symlink(&secret, root.join("link")).expect("a symlink");

        let resolver = PathResolver::over([root.clone()]).expect("an absolute root");
        let refusal = resolver.approve_host(&root.join("link")).unwrap_err();
        assert!(
            matches!(
                refusal,
                PathRefusal::NotCanonical { .. } | PathRefusal::Unreachable(_)
            ),
            "a link out of the root must refuse, got {refusal:?}"
        );
    }

    /// A create names a path that does not exist yet, so the resolver must approve it.
    #[test]
    fn the_host_resolver_approves_a_new_leaf_inside_the_root() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let root = std::fs::canonicalize(home.path()).expect("the root canonicalizes");
        let resolver = PathResolver::over([root.clone()]).expect("an absolute root");

        let approved = resolver
            .approve_host(&root.join("new.txt"))
            .expect("a new leaf inside the root is approved");
        assert_eq!(approved.as_path(), root.join("new.txt"));
    }
}
