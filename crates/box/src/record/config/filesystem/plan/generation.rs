//! Compound policy generations for protected storage publication.
//!
//! A generation is useful before every source arrives, but its reach is inseparable from the
//! masks that keep unresolved rules from exposing placeholder contents or alias destinations.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use containment::Scope;
use serde::{Deserialize, Serialize};

use super::super::{DirectReach, FileIdentity, FilesystemContext, refuse};
use super::{FilesystemCompilation, FilesystemPlan};
use crate::error::ConfigError;
use crate::record::config::process::Grant;
use crate::record::layout::{resolved_through_links, resolved_to_its_deepest_existing_ancestor};
use crate::run::commands::ConfiguredCommand;
use crate::run::installation::TrustedInstallation;

/// The object a private target placeholder must be able to receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FilesystemTargetKind {
    File,
    Directory,
}

/// A logical path that must stay unavailable while its source rules are unresolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingMask {
    pub(crate) path: PathBuf,
    pub(crate) kind: FilesystemTargetKind,
    /// Related sources whose policy must be ready before this target can be compiled.
    pub(crate) roots: Vec<PathBuf>,
}

/// One independently publishable projection from a fully protected private view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationTarget {
    pub(crate) path: PathBuf,
    pub(crate) kind: FilesystemTargetKind,
    /// Captured sources needed to construct this projection at its original logical path.
    pub(crate) roots: Vec<PathBuf>,
}

/// Authored rules and the identities already judged, suitable for a fresh compiler subprocess.
///
/// This is an internal trusted-channel value, not a second configuration format. Captured mount
/// descriptors and command/installation descriptors travel separately; path text grants no trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesystemCheckpoint {
    table: String,
    plan: FilesystemPlan,
    /// Captured descriptors the next worker must still receive, including dependency-blocked roots.
    admitted: Vec<PathBuf>,
    /// Targets this policy can construct. Publication acknowledgments belong to each receiver,
    /// so every generation retains the full set for both existing and newly created sandboxes.
    compiled_targets: Vec<PublicationTarget>,
    /// Restrictions required on exposed paths, including both spellings of a denial.
    restrictions: Vec<CompiledRestriction>,
    /// Only these logical targets may acquire new restrictions in a later generation.
    pending_masks: Vec<PendingMask>,
    judged: Vec<JudgedPath>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestrictionKind {
    Deny,
    DenyWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledRestriction {
    path: PathBuf,
    /// The normal canonical destination also protects an authored alias through a pending mask.
    resolved: PathBuf,
    kind: RestrictionKind,
    scope: Scope,
}

impl CompiledRestriction {
    fn covers(&self, other: &Self) -> bool {
        (self.kind == RestrictionKind::Deny || self.kind == other.kind)
            && match self.scope {
                Scope::Root => other.path.starts_with(&self.path),
                Scope::File | Scope::Dir => self.path == other.path && self.scope == other.scope,
            }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgedPath {
    path: PathBuf,
    identity: FileIdentity,
}

/// The rules that can be applied now, together with every required unavailable target.
#[derive(Debug)]
pub(crate) struct FilesystemGeneration {
    checkpoint: FilesystemCheckpoint,
    reach: DirectReach,
    masks: Vec<PendingMask>,
    targets: Vec<PublicationTarget>,
}

impl FilesystemPlan {
    /// Compile one captured-source view without waiting for unrelated declared roots.
    pub(crate) fn compile_generation(
        self,
        admitted: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<FilesystemGeneration, ConfigError> {
        for (index, root) in admitted.iter().enumerate() {
            if admitted[..index].contains(root) {
                return Err(refuse(
                    context,
                    &root.display().to_string(),
                    "a captured root was repeated",
                ));
            }
        }
        // First discover routes in all captures. A root whose authored rule reaches a pending
        // source waits with that source; unrelated roots remain independently publishable.
        let (plan, reach, pending) = evaluate(self, admitted, context)?;
        let blocked = dependency_blocked_roots(&plan, pending.clone());
        let ready: Vec<_> = admitted
            .iter()
            .filter(|root| !blocked.contains(root))
            .cloned()
            .collect();
        let (plan, reach) = if blocked == pending {
            (plan, reach)
        } else {
            let (plan, reach, _) = evaluate(plan, &ready, context)?;
            (plan, reach)
        };
        let masks = pending_masks(&plan, &blocked);
        let targets = publication_targets(&plan, &reach, &ready);
        let compiled_targets = targets.clone();
        let judged = judged_paths(&plan, &reach, &blocked, context)?;
        let restrictions = compiled_restrictions(&reach);
        Ok(FilesystemGeneration {
            checkpoint: FilesystemCheckpoint {
                table: context.table.to_string(),
                plan,
                admitted: admitted.to_vec(),
                compiled_targets,
                restrictions,
                pending_masks: masks.clone(),
                judged,
            },
            reach,
            masks,
            targets,
        })
    }
}

fn evaluate(
    plan: FilesystemPlan,
    admitted: &[PathBuf],
    context: &FilesystemContext<'_>,
) -> Result<(FilesystemPlan, DirectReach, Vec<PathBuf>), ConfigError> {
    let retained = plan.clone();
    let (mut plan, reach, pending) = match plan.judge_current_view(admitted, context)? {
        FilesystemCompilation::Complete(reach) => (retained, reach, Vec::new()),
        FilesystemCompilation::Pending(pending) => (pending.plan, pending.available, pending.roots),
    };
    retain_compiled_dependencies(&mut plan, &pending, context)?;
    Ok((plan, reach, pending))
}

/// Keep every source used by a successfully compiled rule, including denial routes and sources
/// already captured before the first generation. This examines authored paths, never a tree.
fn retain_compiled_dependencies(
    plan: &mut FilesystemPlan,
    pending: &[PathBuf],
    context: &FilesystemContext<'_>,
) -> Result<(), ConfigError> {
    for entry in &mut plan.entries {
        if entry.roots.iter().any(|root| pending.contains(root)) {
            continue;
        }
        let (resolved, links) = resolved_through_links(&entry.lexical).map_err(|error| {
            refuse(
                context,
                &entry.authored.display().to_string(),
                &format!("cannot retain the compiled rule's source dependencies: {error}"),
            )
        })?;
        for root in &plan.roots {
            if (resolved.starts_with(root) || links.iter().any(|link| link.starts_with(root)))
                && !entry.roots.contains(root)
            {
                entry.roots.push(root.clone());
            }
        }
    }
    Ok(())
}

fn dependency_blocked_roots(plan: &FilesystemPlan, mut blocked: Vec<PathBuf>) -> Vec<PathBuf> {
    loop {
        let before = blocked.len();
        for entry in &plan.entries {
            if entry.roots.iter().any(|root| blocked.contains(root)) {
                for root in &entry.roots {
                    if !blocked.contains(root) {
                        blocked.push(root.clone());
                    }
                }
            }
        }
        if blocked.len() == before {
            return blocked;
        }
    }
}

impl FilesystemCheckpoint {
    /// Refuse accidental reuse of another process table or a different authored declaration.
    pub(crate) fn matches(
        &self,
        lists: &crate::record::config::process::Filesystem,
        roots: &[PathBuf],
    ) -> bool {
        self.plan.original == *lists && self.plan.roots == roots
    }

    /// Continue with the same objects and original alias bindings in a captured-source view.
    pub(crate) fn compile(
        self,
        admitted: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<FilesystemGeneration, ConfigError> {
        if self.table != context.table {
            return Err(refuse(
                context,
                "filesystem",
                "a retained filesystem generation belongs to a different process table",
            ));
        }
        for root in &self.admitted {
            if !admitted.contains(root) {
                return Err(refuse(
                    context,
                    &root.display().to_string(),
                    "a captured source cannot be forgotten by a later generation",
                ));
            }
        }
        for judged in &self.judged {
            let unchanged = std::fs::symlink_metadata(&judged.path)
                .is_ok_and(|metadata| FileIdentity::of(&metadata) == judged.identity);
            if !unchanged {
                return Err(refuse(
                    context,
                    &judged.path.display().to_string(),
                    "a previously judged filesystem object was replaced or became unavailable",
                ));
            }
        }
        let next = self.plan.clone().compile_generation(admitted, context)?;
        self.require_monotonic_protection(&next.checkpoint, context)?;
        for target in &self.compiled_targets {
            let preserved = next.checkpoint.compiled_targets.iter().any(|candidate| {
                candidate.path == target.path
                    && candidate.kind == target.kind
                    && target
                        .roots
                        .iter()
                        .all(|root| candidate.roots.contains(root))
            });
            if !preserved {
                return Err(refuse(
                    context,
                    &target.path.display().to_string(),
                    "a previously compiled storage target lost its policy dependencies",
                ));
            }
        }
        Ok(next)
    }

    /// A late rule can protect a still-masked target, but cannot silently revise protection on
    /// a path earlier generations could expose. In particular, a denial spelled under a newly
    /// captured root must not resolve into an already visible root or ordinary host path.
    fn require_monotonic_protection(
        &self,
        next: &Self,
        context: &FilesystemContext<'_>,
    ) -> Result<(), ConfigError> {
        for previous in &self.restrictions {
            if !next
                .restrictions
                .iter()
                .any(|candidate| candidate.covers(previous))
            {
                return Err(refuse(
                    context,
                    &previous.path.display().to_string(),
                    "a previously compiled filesystem restriction was lost",
                ));
            }
        }
        for restriction in &next.restrictions {
            let unchanged = self
                .restrictions
                .iter()
                .any(|previous| previous.covers(restriction));
            let masked = self.pending_masks.iter().any(|mask| {
                [&restriction.path, &restriction.resolved]
                    .iter()
                    .any(|path| match mask.kind {
                        FilesystemTargetKind::Directory => path.starts_with(&mask.path),
                        FilesystemTargetKind::File => *path == &mask.path,
                    })
            });
            if !unchanged && !masked {
                return Err(refuse(
                    context,
                    &restriction.path.display().to_string(),
                    "a newly resolved filesystem restriction would change an already exposed path; \
                     its source must be available before that path is exposed",
                ));
            }
        }
        Ok(())
    }
}

impl FilesystemGeneration {
    /// Bind mandatory storage masks to the reach consumed by the normal launcher.
    pub(crate) fn into_initial_reach(
        mut self,
        policy: Arc<crate::run::contain::boundary::storage::Policy>,
    ) -> DirectReach {
        self.reach.storage = Some(policy);
        self.reach
    }

    /// The caller must carry the masks into both initial startup and protected staging.
    /// There is deliberately no getter for the partial reach alone.
    pub(crate) fn with_policy<T>(
        &self,
        use_policy: impl FnOnce(&DirectReach, &[PendingMask], &[PublicationTarget]) -> T,
    ) -> T {
        use_policy(&self.reach, &self.masks, &self.targets)
    }

    /// Retain a successfully compiled policy independently of each sandbox's publication state.
    pub(crate) fn checkpoint(&self) -> FilesystemCheckpoint {
        self.checkpoint.clone()
    }

    /// Add already-opened runtime bindings after the normal command/installation guards pass.
    pub(crate) fn with_runtime_bindings(
        mut self,
        command: Option<Arc<ConfiguredCommand>>,
        installation: Arc<TrustedInstallation>,
    ) -> Self {
        self.reach.command = command;
        self.reach.installation = Some(installation);
        self
    }

    /// Recompile in a view containing every admitted capture, preserving prior identities.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Normal storage compiler handoff is not connected yet"
        )
    )]
    pub(crate) fn recompile(
        self,
        admitted: &[PathBuf],
        context: &FilesystemContext<'_>,
    ) -> Result<Self, ConfigError> {
        super::super::require_judged_identities(&self.reach, context.table)?;
        let mut next = self.checkpoint.compile(admitted, context)?;
        next.reach.command = self.reach.command;
        next.reach.installation = self.reach.installation;
        Ok(next)
    }
}

fn pending_masks(plan: &FilesystemPlan, pending: &[PathBuf]) -> Vec<PendingMask> {
    let mut masks: Vec<_> = pending
        .iter()
        .map(|root| PendingMask {
            path: root.clone(),
            kind: FilesystemTargetKind::Directory,
            roots: dependency_blocked_roots(plan, vec![root.clone()]),
        })
        .collect();
    for entry in &plan.entries {
        let roots: Vec<_> = entry
            .roots
            .iter()
            .filter(|root| pending.contains(root))
            .cloned()
            .collect();
        if roots.is_empty() || pending.iter().any(|root| entry.lexical.starts_with(root)) {
            continue;
        }
        // The existing compiler supports only final read aliases to regular files. A future
        // directory target still fails its normal rule check rather than extending that contract.
        if matches!(entry.kind, Grant::Read | Grant::ReadFile)
            && entry.alias_root.is_some()
            && !masks.iter().any(|mask| mask.path == entry.lexical)
        {
            masks.push(PendingMask {
                path: entry.lexical.clone(),
                kind: FilesystemTargetKind::File,
                roots: dependency_blocked_roots(plan, roots),
            });
        }
    }
    masks
}

fn publication_targets(
    plan: &FilesystemPlan,
    reach: &DirectReach,
    admitted: &[PathBuf],
) -> Vec<PublicationTarget> {
    let mut targets = Vec::new();
    for root in admitted {
        let mut roots = vec![root.clone()];
        let mut reached = false;
        for grant in &reach.grants {
            if grant.names().iter().any(|name| {
                name.starts_with(root) || (grant.scope == Scope::Root && root.starts_with(name))
            }) {
                reached = true;
                add_dependencies(&mut roots, plan, grant, admitted);
            }
        }
        if reached {
            targets.push(PublicationTarget {
                path: root.clone(),
                kind: FilesystemTargetKind::Directory,
                roots: dependency_blocked_roots(plan, roots),
            });
        }
    }
    for grant in &reach.grants {
        if !grant.is_link()
            || plan
                .roots
                .iter()
                .any(|root| grant.lexical.starts_with(root))
        {
            continue;
        }
        let mut roots = Vec::new();
        add_dependencies(&mut roots, plan, grant, admitted);
        if roots.is_empty() || targets.iter().any(|target| target.path == grant.lexical) {
            continue;
        }
        targets.push(PublicationTarget {
            path: grant.lexical.clone(),
            kind: FilesystemTargetKind::File,
            roots: dependency_blocked_roots(plan, roots),
        });
    }
    targets
}

fn add_dependencies(
    roots: &mut Vec<PathBuf>,
    plan: &FilesystemPlan,
    grant: &super::super::DirectGrant,
    admitted: &[PathBuf],
) {
    for root in admitted {
        let authored_dependency = plan.entries.iter().any(|entry| {
            entry.kind == grant.kind && entry.lexical == grant.lexical && entry.roots.contains(root)
        });
        if (authored_dependency || grant.resolved.starts_with(root)) && !roots.contains(root) {
            roots.push(root.clone());
        }
    }
}

/// Match normal containment lowering: a refusal protects both its authored spelling and its
/// canonical destination; a write-protected tree already has a canonical directory path.
fn compiled_restrictions(reach: &DirectReach) -> Vec<CompiledRestriction> {
    let mut restrictions = Vec::new();
    let mut add = |restriction| {
        if !restrictions.contains(&restriction) {
            restrictions.push(restriction);
        }
    };
    for refusal in &reach.refusals {
        let resolved = resolved_to_its_deepest_existing_ancestor(&refusal.path);
        for path in [refusal.path.clone(), resolved.clone()] {
            add(CompiledRestriction {
                path,
                resolved: resolved.clone(),
                kind: RestrictionKind::Deny,
                scope: refusal.scope,
            });
        }
    }
    for path in &reach.write_protections {
        add(CompiledRestriction {
            path: path.clone(),
            resolved: path.clone(),
            kind: RestrictionKind::DenyWrite,
            scope: Scope::Root,
        });
    }
    restrictions
}

fn judged_paths(
    plan: &FilesystemPlan,
    reach: &DirectReach,
    pending: &[PathBuf],
    context: &FilesystemContext<'_>,
) -> Result<Vec<JudgedPath>, ConfigError> {
    super::super::require_judged_identities(reach, context.table)?;
    let mut paths = Vec::new();
    let mut add = |path: &Path| -> Result<(), ConfigError> {
        if paths.iter().any(|judged: &JudgedPath| judged.path == path) {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            refuse(
                context,
                &path.display().to_string(),
                &format!("cannot retain the judged filesystem identity: {error}"),
            )
        })?;
        paths.push(JudgedPath {
            path: path.to_path_buf(),
            identity: FileIdentity::of(&metadata),
        });
        Ok(())
    };
    for grant in &reach.grants {
        for name in grant.names() {
            add(name)?;
        }
    }
    for refusal in &reach.refusals {
        if refusal.judged.is_some() {
            add(&refusal.path)?;
        }
    }
    for path in &reach.write_protections {
        add(path)?;
    }
    // The link itself is observable even if its target source is absent. Retain that object
    // without following the link or inventing an identity for its future target.
    for entry in &plan.entries {
        if matches!(entry.kind, Grant::Read | Grant::ReadFile)
            && entry.alias_root.is_some()
            && !pending.iter().any(|root| entry.lexical.starts_with(root))
        {
            add(&entry.lexical)?;
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests;
