//! Supported-subset translation for an explicitly approved history migration.
//!
//! These helpers do not select installed rules, prove input provenance, change a
//! database, or authorize work. The coordinator must validate trusted captured
//! inputs, unique stored identities, monitor compatibility, and activation.
//! Normal policy edits must never invoke legacy matching.

mod source;
mod temporal;

pub(crate) use source::convert_saved_statement;
pub(crate) use temporal::legacy_form;

/// Predict a stored statement from the original policy and optional old compiler output.
pub(crate) fn original_statement(
    policy: &dogwood_language::ParsedPolicy<'_>,
    current: &str,
    old_compiled: Option<&str>,
    service: &dogwood_language::ServiceSchema,
) -> Result<String, MigrationError> {
    // Compiler output no longer distinguishes authored names from generated names.
    // Check the original bindings even when the old compiler supplies the spelling.
    let projected = legacy_form(policy)?;
    if let Some(old) = old_compiled {
        Ok(convert_saved_statement(old, service)?.statement)
    } else {
        Ok(projected.map_or_else(|| current.to_owned(), |form| form.statement))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationErrorKind {
    Lexical,
    UnsupportedSyntax,
    BindingCapture,
    InvalidPolicy,
    PolicyCount,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}{location}", location = display_location(*.byte_offset))]
pub(crate) struct MigrationError {
    pub(crate) kind: MigrationErrorKind,
    pub(crate) byte_offset: Option<usize>,
    pub(crate) detail: String,
}

impl MigrationError {
    fn capture(detail: impl Into<String>) -> Self {
        Self {
            kind: MigrationErrorKind::BindingCapture,
            byte_offset: None,
            detail: detail.into(),
        }
    }

    fn unsupported(detail: impl Into<String>) -> Self {
        Self {
            kind: MigrationErrorKind::UnsupportedSyntax,
            byte_offset: None,
            detail: detail.into(),
        }
    }
}

fn display_location(offset: Option<usize>) -> String {
    offset.map_or_else(String::new, |offset| format!(" at byte {offset}"))
}

#[cfg(test)]
mod tests;
