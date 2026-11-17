//! Explicit compatibility records for the Dogwood 1.0.0 to 1.1.2 upgrade.
//!
//! Normal opens never derive a legacy match. They consume only the identities
//! recorded by a completed explicit migration, after checking the format.

mod capture;
mod legacy;
mod preparation;
mod storage;
mod transition;
mod validator;

pub use preparation::{MigrationInput, MigrationSummary, MigrationTarget, PolicyMigration};

use std::collections::{BTreeMap, BTreeSet};

use dogwood_local_engine::{DurableError, DurableLog, PolicyEntry, Write};
use serde::{Deserialize, Serialize};

pub(crate) const PROVENANCE_KEY: &str = "box.dogwood.migration.v1";
const FORMAT_VERSION: u32 = 1;
const ENGINE_VERSION: &str = "1.1.2";
const LEGACY_VERSION: &str = "1.0.0";
const SERVICE_SCHEMA_KEY: &str = "dogwood_server_service_schema";

/// The original authored input, recorded before compatibility is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalSource {
    pub(crate) origin: String,
    pub(crate) text: String,
}

/// One approved current spelling and the exact stored rule it may retain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleBinding {
    pub(crate) current_statement: String,
    pub(crate) retained: PolicyEntry,
}

/// A frozen, versioned format. Unknown versions or fields require review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationRecord {
    pub(crate) format_version: u32,
    pub(crate) engine_version: String,
    pub(crate) migrated_from: Option<String>,
    pub(crate) original_sources: Vec<OriginalSource>,
    pub(crate) grammar_schemas: Vec<String>,
    pub(crate) mcp_schemas: Vec<String>,
    pub(crate) bindings: Vec<RuleBinding>,
}

impl MigrationRecord {
    fn fresh() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            engine_version: ENGINE_VERSION.to_owned(),
            migrated_from: None,
            original_sources: Vec::new(),
            grammar_schemas: Vec::new(),
            mcp_schemas: Vec::new(),
            bindings: Vec::new(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DurableError> {
        if self.format_version != FORMAT_VERSION || self.engine_version != ENGINE_VERSION {
            return Err(refused(
                "unsupported saved migration format or Dogwood version",
            ));
        }
        match self.migrated_from.as_deref() {
            None if self.bindings.is_empty()
                && self.original_sources.is_empty()
                && self.grammar_schemas.is_empty()
                && self.mcp_schemas.is_empty() => {}
            Some(LEGACY_VERSION) => {}
            _ => return Err(refused("invalid saved migration provenance")),
        }
        let mut ids = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        let mut statements = BTreeMap::new();
        for binding in &self.bindings {
            if binding.current_statement.trim().is_empty()
                || binding.retained.statement.trim().is_empty()
                || !ids.insert(binding.retained.id)
                || !tokens.insert(&binding.retained.token)
            {
                return Err(refused("invalid or duplicate saved rule identity"));
            }
            if let Some(previous) =
                statements.insert(&binding.retained.statement, &binding.current_statement)
                && previous != &binding.current_statement
            {
                return Err(refused(
                    "one retained rule spelling has conflicting current spellings",
                ));
            }
        }
        Ok(())
    }
}

/// Active aliases are qualified by the whole entry, not only its text or token.
#[derive(Debug, Clone, Default)]
pub(crate) struct MigrationBindings(Vec<RuleBinding>);

impl MigrationBindings {
    pub(crate) fn read_or_mark_fresh(log: &DurableLog) -> Result<Self, DurableError> {
        if let Some(record) = transition::runtime_record(log).map_err(log_error)? {
            return Ok(Self(record.bindings));
        }
        let bytes = match log.get_meta(PROVENANCE_KEY).map_err(log_error)? {
            Some(bytes) => bytes,
            None => {
                if log.next_offset() != 0
                    || log.base_offset() != 0
                    || log.get_snapshot().map_err(log_error)?.is_some()
                    || log
                        .get_meta(SERVICE_SCHEMA_KEY)
                        .map_err(log_error)?
                        .is_some()
                {
                    return Err(refused(
                        "this history has no recorded Dogwood version; stop Box and run the explicit 1.0.0-to-1.1.2 migration before opening it",
                    ));
                }
                let bytes = serde_json::to_vec(&MigrationRecord::fresh())
                    .map_err(|error| refused(format!("encode fresh history version: {error}")))?;
                log.commit(&[Write::Meta {
                    key: PROVENANCE_KEY,
                    value: &bytes,
                }])
                .map_err(log_error)?;
                bytes
            }
        };
        let record: MigrationRecord = serde_json::from_slice(&bytes)
            .map_err(|error| refused(format!("invalid saved migration record: {error}")))?;
        record.validate()?;
        if record.migrated_from.is_some() {
            storage::verify_application_receipt(log, PROVENANCE_KEY, &bytes).map_err(log_error)?;
        }
        Ok(Self(record.bindings))
    }

    /// A deleted or replaced entry never reactivates an earlier binding.
    /// An explicit history reset keeps the entry and its approved spelling.
    pub(crate) fn current_statement<'a>(&'a self, entry: &'a PolicyEntry) -> &'a str {
        self.0
            .iter()
            .find(|binding| binding.retained == *entry)
            .map_or(&entry.statement, |binding| &binding.current_statement)
    }

    /// Compare each entry's one approved current spelling, in installed order.
    pub(crate) fn retained_indices(
        &self,
        current: &[String],
        existing: &[PolicyEntry],
    ) -> Vec<Option<usize>> {
        let mut used = vec![false; existing.len()];
        current
            .iter()
            .map(|policy| {
                let index = existing.iter().enumerate().find_map(|(index, entry)| {
                    (!used[index] && self.current_statement(entry) == policy).then_some(index)
                });
                if let Some(index) = index {
                    used[index] = true;
                }
                index
            })
            .collect()
    }

    #[cfg(test)]
    fn matches(&self, current: &str, entry: &PolicyEntry) -> bool {
        self.0
            .iter()
            .any(|binding| binding.current_statement == current && binding.retained == *entry)
    }
}

fn refused(message: impl Into<String>) -> DurableError {
    DurableError::Log(format!("Dogwood migration required: {}", message.into()))
}

fn log_error(error: impl std::fmt::Display) -> DurableError {
    DurableError::Log(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dogwood_local_engine::{PolicyId, PolicyToken};

    fn entry(id: u64, statement: &str) -> PolicyEntry {
        PolicyEntry {
            id: PolicyId(id),
            token: PolicyToken(format!("test-{id}")),
            statement: statement.to_owned(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn used_unmarked_history_is_refused_without_writing_provenance() {
        let log = DurableLog::ephemeral().unwrap();
        log.append(b"record that must remain untouched").unwrap();
        assert!(MigrationBindings::read_or_mark_fresh(&log).is_err());
        assert_eq!(log.next_offset(), 1);
        assert!(log.get_meta(PROVENANCE_KEY).unwrap().is_none());
        let mut records = Vec::new();
        log.scan_from(0, |offset, bytes| records.push((offset, bytes.to_vec())))
            .unwrap();
        assert_eq!(
            records,
            vec![(0, b"record that must remain untouched".to_vec())]
        );
    }

    #[test]
    fn only_an_empty_store_can_receive_fresh_provenance() {
        let log = DurableLog::ephemeral().unwrap();
        assert!(
            MigrationBindings::read_or_mark_fresh(&log)
                .unwrap()
                .0
                .is_empty()
        );
        let bytes = log.get_meta(PROVENANCE_KEY).unwrap().unwrap();
        log.append(b"later record").unwrap();
        assert!(
            MigrationBindings::read_or_mark_fresh(&log)
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(log.get_meta(PROVENANCE_KEY).unwrap().unwrap(), bytes);
    }

    #[test]
    fn corrupt_or_future_provenance_is_refused_instead_of_treated_as_empty() {
        for bytes in [b"broken".to_vec(), {
            let mut record = MigrationRecord::fresh();
            record.format_version += 1;
            serde_json::to_vec(&record).unwrap()
        }] {
            let log = DurableLog::ephemeral().unwrap();
            log.commit(&[Write::Meta {
                key: PROVENANCE_KEY,
                value: &bytes,
            }])
            .unwrap();
            assert!(MigrationBindings::read_or_mark_fresh(&log).is_err());
            assert_eq!(log.get_meta(PROVENANCE_KEY).unwrap().unwrap(), bytes);
        }
    }

    #[test]
    fn deletion_replacement_and_edit_back_do_not_reuse_an_old_binding() {
        let old = entry(7, "old spelling");
        let bindings = MigrationBindings(vec![RuleBinding {
            current_statement: "current spelling".into(),
            retained: old.clone(),
        }]);
        assert!(bindings.matches("current spelling", &old));
        assert!(!bindings.matches("edited spelling", &old));
        let mut changed = old.clone();
        changed.updated += 1;
        assert!(!bindings.matches("current spelling", &changed));
        let new_identity = entry(8, "old spelling");
        assert!(!bindings.matches("current spelling", &new_identity));
        assert_eq!(bindings.current_statement(&new_identity), "old spelling");
    }

    #[test]
    fn duplicate_rules_keep_distinct_identities_but_conflicting_aliases_are_refused() {
        let a = RuleBinding {
            current_statement: "current".into(),
            retained: entry(1, "old"),
        };
        let mut record = MigrationRecord {
            migrated_from: Some(LEGACY_VERSION.into()),
            bindings: vec![
                a.clone(),
                RuleBinding {
                    retained: entry(2, "old"),
                    ..a.clone()
                },
            ],
            ..MigrationRecord::fresh()
        };
        assert!(record.validate().is_ok());
        record.bindings[1].current_statement = "different".into();
        assert!(record.validate().is_err());
        record.bindings = vec![a.clone(), a];
        assert!(record.validate().is_err());
    }

    #[test]
    fn only_the_approved_current_spelling_retains_history_in_either_source_order() {
        let old = entry(1, "literal");
        let bindings = MigrationBindings(vec![RuleBinding {
            current_statement: "macro expansion".into(),
            retained: old.clone(),
        }]);
        assert_eq!(
            bindings.retained_indices(
                &["macro expansion".into(), "literal".into()],
                std::slice::from_ref(&old)
            ),
            vec![Some(0), None]
        );
        assert_eq!(
            bindings.retained_indices(
                &["literal".into(), "macro expansion".into()],
                std::slice::from_ref(&old)
            ),
            vec![None, Some(0)]
        );
        assert_eq!(
            bindings.retained_indices(
                &["macro expansion".into(), "macro expansion".into()],
                &[old]
            ),
            vec![Some(0), None]
        );
    }

    #[test]
    fn duplicate_logical_rules_retain_in_installed_order() {
        let old = entry(1, "old");
        let native = entry(2, "current");
        let bindings = MigrationBindings(vec![RuleBinding {
            current_statement: "current".into(),
            retained: old.clone(),
        }]);
        assert_eq!(
            bindings.retained_indices(&["current".into()], &[old.clone(), native.clone()]),
            vec![Some(0)]
        );
        assert_eq!(
            bindings.retained_indices(&["current".into(), "current".into()], &[old, native]),
            vec![Some(0), Some(1)]
        );
    }
}
