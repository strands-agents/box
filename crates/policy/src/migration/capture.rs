//! Fold only the stored rule identities needed to review an explicit migration.
//! Engine recovery independently validates the full history on a private copy.

use dogwood_local_engine::{Installed, PolicySet, Record, SnapshotPayload};

use super::storage::CapturedStore;
use crate::PolicyError;

pub(super) fn installed(capture: &CapturedStore) -> Result<Installed, PolicyError> {
    let (mut bundle, start) = match &capture.snapshot {
        Some(snapshot) => {
            let payload = SnapshotPayload::decode(&snapshot.payload).map_err(fail)?;
            (payload.bundle, snapshot.up_to)
        }
        None if capture.base == 0 => (
            Installed {
                policies: PolicySet::new(),
                action_schema: String::new(),
            },
            0,
        ),
        None => return Err(fail("pruned history has no saved engine state")),
    };
    for (offset, bytes) in capture
        .records
        .iter()
        .filter(|(offset, _)| *offset >= start)
    {
        let record =
            Record::decode(bytes).map_err(|error| fail(format!("record {offset}: {error}")))?;
        fold(&mut bundle, record).map_err(|error| fail(format!("record {offset}: {error}")))?;
    }
    Ok(bundle)
}

fn fold(bundle: &mut Installed, record: Record) -> Result<(), String> {
    match record {
        Record::Event(_) => (),
        Record::Add {
            ts,
            id,
            token,
            statement,
        } => {
            if bundle.policies.next_id() == u64::MAX
                || id.0 != bundle.policies.next_id()
                || bundle.policies.contains_token(&token)
            {
                return Err("invalid or reused policy identity".into());
            }
            bundle.policies.insert_recorded(id, token, statement, ts);
        }
        Record::Update { ts, id, statement } => {
            if !bundle.policies.update_statement(id, statement, ts) {
                return Err("update names a missing policy".into());
            }
        }
        Record::Delete { id, .. } => {
            if !bundle.policies.remove(id) {
                return Err("delete names a missing policy".into());
            }
        }
        Record::Reset { id, .. } => {
            if !bundle.policies.contains(id) {
                return Err("reset names a missing policy".into());
            }
        }
        Record::DeleteAll { .. } => bundle.policies.clear(),
        Record::ResetAll { .. } => (),
        Record::SetActionSchema { action_schema, .. } => bundle.action_schema = action_schema,
        Record::AppendActionSchema { fragment, .. } => {
            let base = bundle.action_schema.trim_end();
            bundle.action_schema = if base.is_empty() {
                fragment
            } else {
                format!("{base}\n{fragment}")
            };
        }
    }
    Ok(())
}

fn fail(message: impl Into<String>) -> PolicyError {
    PolicyError::Evaluation(format!(
        "cannot prepare Dogwood migration: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dogwood_local_engine::{PolicyId, PolicyToken};

    #[test]
    fn folding_retains_recorded_identity_and_does_not_reuse_a_deleted_ordinal() {
        let mut bundle = Installed {
            policies: PolicySet::new(),
            action_schema: String::new(),
        };
        fold(
            &mut bundle,
            Record::Add {
                ts: 5,
                id: PolicyId(0),
                token: PolicyToken("first".into()),
                statement: "old".into(),
            },
        )
        .unwrap();
        fold(
            &mut bundle,
            Record::Update {
                ts: 6,
                id: PolicyId(0),
                statement: "new".into(),
            },
        )
        .unwrap();
        let before = bundle.policies.get(PolicyId(0)).unwrap().clone();
        fold(
            &mut bundle,
            Record::Reset {
                ts: 7,
                id: PolicyId(0),
            },
        )
        .unwrap();
        assert_eq!(bundle.policies.get(PolicyId(0)).unwrap(), &before);
        fold(&mut bundle, Record::DeleteAll { ts: 8 }).unwrap();
        assert!(
            fold(
                &mut bundle,
                Record::Add {
                    ts: 9,
                    id: PolicyId(0),
                    token: PolicyToken("second".into()),
                    statement: "new".into()
                }
            )
            .is_err()
        );
        assert!(
            fold(
                &mut bundle,
                Record::Add {
                    ts: 9,
                    id: PolicyId(1),
                    token: PolicyToken("second".into()),
                    statement: "new".into()
                }
            )
            .is_ok()
        );
        assert_eq!(bundle.policies.next_id(), 2);
    }
}
