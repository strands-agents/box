//! The stored box: what a box *is*, before anything is running.
//!
//! | Module | Answers |
//! |---|---|
//! | [`config`] | `box.toml`: the two wire records, and one module per key |
//! | [`layout`] | where this box's files live |
//! | [`workspace`] | refusing the operator's home as a workspace |

pub(crate) mod config;
pub(crate) mod layout;
pub(crate) mod workspace;
