//! Every kernel filesystem verb the vendored Shell declares today rides one of the four named
//! actions or, for `Locate` alone, decides nothing, and `fs:other` has no producer.
//!
//! `strands_shell::FsOperation` and `FsPairOperation` are `#[non_exhaustive]`, so a `match` in
//! this crate cannot be exhaustive and the two lists below are the pin. The vendored source is
//! read beside them, so a variant upstream adds fails this file and is named in the failure.

#![cfg(feature = "shell-adapter")]

mod support;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use policy::{Decision, DecisionObserver, GovernedBox, Policy, Principal, ShellPolicyInterceptor};
use strands_shell::{EffectAttempt, EffectInterceptor, FsOperation, FsPairOperation};

const EFFECT_SOURCE: &str = include_str!("../../shell/src/effect.rs");

const FS_OTHER: &str = r#"Box::Action::"fs:other""#;

/// What the adapter is expected to decide for one kernel verb.
#[derive(Clone, Copy, Debug)]
enum Expected {
    /// One decision on the named action.
    Action(&'static str),
    /// No decision at all: nothing reaches the engine and nothing is recorded.
    NoDecision,
}

/// Every single-path verb the vendored Shell declares, and what the adapter decides for each.
const SINGLE: &[(FsOperation, Expected)] = &[
    (FsOperation::ReadContent, Expected::Action("fs:read")),
    (
        FsOperation::WriteContent {
            create: true,
            truncate: true,
        },
        Expected::Action("fs:write"),
    ),
    (
        FsOperation::ReadMetadata {
            follow_symlinks: true,
        },
        Expected::Action("fs:read"),
    ),
    (FsOperation::Enumerate, Expected::Action("fs:read")),
    (FsOperation::Exec, Expected::Action("fs:read")),
    (FsOperation::Locate, Expected::NoDecision),
    (FsOperation::RemoveFile, Expected::Action("fs:delete")),
    (FsOperation::RemoveDir, Expected::Action("fs:delete")),
    (FsOperation::CreateDir, Expected::Action("fs:write")),
    (
        FsOperation::SetPermissions { mode: 0o644 },
        Expected::Action("fs:write"),
    ),
    (FsOperation::ChangeDir, Expected::Action("fs:read")),
    (FsOperation::ReadLink, Expected::Action("fs:read")),
];

/// Every two-path verb the vendored Shell declares, and the actions its legs ride, in order:
/// the pair action on the source, a content read of the source, and the pair action on the
/// target; a rename onto a bound destination adds `fs:delete` on the target before it.
const PAIR: &[(FsPairOperation, &[&str])] = &[
    (
        FsPairOperation::Rename {
            destination_exists: false,
            destination_is_dir: false,
        },
        &["fs:move", "fs:read", "fs:move"],
    ),
    (
        FsPairOperation::Rename {
            destination_exists: true,
            destination_is_dir: false,
        },
        &["fs:move", "fs:read", "fs:delete", "fs:move"],
    ),
    (
        FsPairOperation::Rename {
            destination_exists: true,
            destination_is_dir: true,
        },
        &["fs:move", "fs:read", "fs:delete", "fs:move"],
    ),
    (
        FsPairOperation::Symlink,
        &["fs:write", "fs:read", "fs:write"],
    ),
];

const SOURCE: &str = "/home/strands-box/a.txt";
const TARGET: &str = "/home/strands-box/b.txt";

/// Collects the action of every verdict the engine reaches.
#[derive(Default)]
struct Actions(Mutex<Vec<String>>);

impl Actions {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().expect("observer lock"))
    }
}

impl DecisionObserver for Actions {
    fn observed(&self, action: &str, _resource: &str, _decision: &Decision) {
        self.0
            .lock()
            .expect("observer lock")
            .push(action.to_string());
    }
}

fn action(id: &str) -> String {
    format!(r#"Box::Action::"{id}""#)
}

fn interceptor() -> (Arc<dyn EffectInterceptor>, Arc<Actions>) {
    let actions = Arc::new(Actions::default());
    let policy = support::open_policy(vec![Policy {
        origin: PathBuf::from("shell-fs-vocabulary.dw"),
        text: "permit(principal, action, resource);".to_string(),
    }])
    .expect("policy loads")
    .observed_by(Arc::clone(&actions) as Arc<dyn DecisionObserver>);
    let handle = ShellPolicyInterceptor::into_handle(
        Arc::new(policy),
        Principal::agent(),
        GovernedBox::assigned("test-box"),
    );
    (handle, actions)
}

#[tokio::test]
async fn every_declared_kernel_verb_rides_a_named_action_and_none_rides_fs_other() {
    let (interceptor, actions) = interceptor();

    for (operation, expected) in SINGLE {
        let permit = interceptor
            .intercept(&EffectAttempt::Filesystem {
                path: SOURCE,
                operation: *operation,
            })
            .await
            .unwrap_or_else(|error| panic!("the catch-all permit admits {operation:?}: {error}"));
        drop(permit);
        let observed = actions.take();
        assert!(
            !observed.iter().any(|decided| decided == FS_OTHER),
            "{operation:?} must not ride fs:other; observed {observed:?}"
        );
        match expected {
            Expected::Action(expected) => {
                assert_eq!(observed, vec![action(expected)], "{operation:?}")
            }
            Expected::NoDecision => assert!(
                observed.is_empty(),
                "{operation:?} must decide nothing; observed {observed:?}"
            ),
        }
    }

    for (operation, expected) in PAIR {
        let permit = interceptor
            .intercept(&EffectAttempt::FilesystemPair {
                from: SOURCE,
                to: TARGET,
                operation: *operation,
            })
            .await
            .unwrap_or_else(|error| panic!("the catch-all permit admits {operation:?}: {error}"));
        drop(permit);
        let observed = actions.take();
        assert!(
            !observed.iter().any(|decided| decided == FS_OTHER),
            "{operation:?} must not ride fs:other; observed {observed:?}"
        );
        let expected: Vec<String> = expected.iter().map(|id| action(id)).collect();
        assert_eq!(observed, expected, "{operation:?}");
    }
}

#[test]
fn the_pinned_lists_name_every_variant_the_vendored_shell_declares() {
    let pinned_single: BTreeSet<String> = SINGLE
        .iter()
        .map(|(operation, _)| variant_name(&format!("{operation:?}")))
        .collect();
    let pinned_pair: BTreeSet<String> = PAIR
        .iter()
        .map(|(operation, _)| variant_name(&format!("{operation:?}")))
        .collect();

    assert_same_variants("FsOperation", &pinned_single);
    assert_same_variants("FsPairOperation", &pinned_pair);
}

fn assert_same_variants(enum_name: &str, pinned: &BTreeSet<String>) {
    let declared = declared_variants(EFFECT_SOURCE, enum_name);
    let added: Vec<&String> = declared.difference(pinned).collect();
    let removed: Vec<&String> = pinned.difference(&declared).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the vendored `{enum_name}` changed: added {added:?}, removed {removed:?}; \
         extend this list and the one in the box crate's `run/broker/shell.rs` test \
         `every_kernel_verb_labels_the_action_the_policy_adapter_decides`, and map each new \
         variant to a named action or to no decision"
    );
}

fn variant_name(debug: &str) -> String {
    debug
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric())
        .collect()
}

/// The variant names of `pub enum <enum_name>` in the vendored `effect.rs`.
fn declared_variants(source: &str, enum_name: &str) -> BTreeSet<String> {
    let header = format!("pub enum {enum_name} {{\n");
    let start = source
        .find(&header)
        .unwrap_or_else(|| panic!("`{header}` is declared in the vendored effect.rs"))
        + header.len();
    let body = &source[start..];
    let end = body.find("\n}").expect("the enum closes");
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.strip_prefix("    ")?;
            let name = variant_name(line);
            (!name.is_empty() && line.starts_with(|c: char| c.is_ascii_uppercase())).then_some(name)
        })
        .collect()
}

/// The delete leg of a replacing rename carries `remove_dir` for a directory destination and
/// `remove_file` otherwise, so a rule narrowed on either operation reaches the rename it names.
#[tokio::test]
async fn a_replaced_directory_is_deleted_as_remove_dir_and_a_file_as_remove_file() {
    let onto_directory = FsPairOperation::Rename {
        destination_exists: true,
        destination_is_dir: true,
    };
    let onto_file = FsPairOperation::Rename {
        destination_exists: true,
        destination_is_dir: false,
    };
    for (forbidden, refused, admitted) in [
        ("remove_dir", onto_directory, onto_file),
        ("remove_file", onto_file, onto_directory),
    ] {
        let policy = support::open_policy(vec![Policy {
            origin: PathBuf::from("shell-fs-vocabulary-operation.dw"),
            text: format!(
                r#"permit(principal, action, resource);
                   @id("no-{forbidden}")
                   forbid(principal, action == Box::Action::"fs:delete", resource)
                   when {{ context.input.operation == Box::FsDeleteOperation::"{forbidden}" }};"#
            ),
        }])
        .expect("policy loads");
        let interceptor = ShellPolicyInterceptor::into_handle(
            Arc::new(policy),
            Principal::agent(),
            GovernedBox::assigned("test-box"),
        );
        let error = interceptor
            .intercept(&EffectAttempt::FilesystemPair {
                from: SOURCE,
                to: TARGET,
                operation: refused,
            })
            .await
            .err()
            .unwrap_or_else(|| panic!("{refused:?} is refused by a forbid on {forbidden}"));
        assert!(
            error
                .to_string()
                .contains(&format!("'{TARGET}' [policy: no-{forbidden}]")),
            "{error}"
        );
        drop(
            interceptor
                .intercept(&EffectAttempt::FilesystemPair {
                    from: SOURCE,
                    to: TARGET,
                    operation: admitted,
                })
                .await
                .unwrap_or_else(|error| {
                    panic!("{admitted:?} is not reached by {forbidden}: {error}")
                }),
        );
    }
}
