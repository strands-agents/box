//! The Strands box's stderr messages: one line format, the message codes, and a parser.
//!
//! | Part | Role |
//! |---|---|
//! | [`diag!`] | writes one message in the format |
//! | [`Code`] | every message code, with its severity and meaning |
//! | [`parse`] | reads one line back |

#![warn(missing_docs, unreachable_pub)]

mod format;
mod parse;
mod registry;

pub use format::{Kind, Severity, Source, emit, stderr, write};
pub use parse::{Line, Message, parse};
pub use registry::Code;

/// Write one message to stderr, or with `into`, to a writer.
///
/// The first argument is a code (`P0201`), a severity for an uncoded message (`error`, `warning`,
/// `note`), or a braced expression that yields a [`Kind`]. The rest is a `format!` string. The
/// calling crate names its voice with `const DIAGNOSTIC_SOURCE: diagnostics::Source` at its root.
// `crate::DIAGNOSTIC_SOURCE` names the calling crate's voice on purpose.
#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! diag {
    (into $writer:expr, $kind:tt, $($format:tt)+) => {
        $crate::write(
            &mut $writer,
            crate::DIAGNOSTIC_SOURCE,
            $crate::kind!($kind),
            ::std::format_args!($($format)+),
        )
    };
    ($kind:tt, $($format:tt)+) => {
        $crate::emit(
            crate::DIAGNOSTIC_SOURCE,
            $crate::kind!($kind),
            ::std::format_args!($($format)+),
        )
    };
}

/// The [`Kind`] that a [`diag!`] call's first argument names.
#[doc(hidden)]
#[macro_export]
macro_rules! kind {
    (error) => {
        $crate::Kind::Uncoded($crate::Severity::Error)
    };
    (warning) => {
        $crate::Kind::Uncoded($crate::Severity::Warning)
    };
    (note) => {
        $crate::Kind::Uncoded($crate::Severity::Note)
    };
    ({ $kind:expr }) => {
        $crate::Kind::from($kind)
    };
    ($code:ident) => {
        $crate::Kind::Coded($crate::Code::$code)
    };
}
