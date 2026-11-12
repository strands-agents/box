//! The kernel the hosted Shell runs on.
//!
//! | Part | What it is |
//! |---|---|
//! | [`EffectAttempt`], [`EffectInterceptor`], [`EffectPermit`] | the checkpoint each effect meets |
//! | [`Filesystem`] | one Program's filesystem: the Shell's own, and the host folders it serves |
//! | [`ShellKernel`] | one Call's kernel over a [`Filesystem`] |
//! | [`Network`], [`HostSpawner`], [`ScriptRunner`] | what the embedder runs after a decision |

#![warn(missing_docs, unreachable_pub)]

mod effect;
mod fallback;
mod floor;
mod host;
mod kernel;
mod memory;
mod network;
mod program;
mod resolve;

pub use effect::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, EffectResult, FsOperation,
    FsPairOperation,
};
pub use fallback::{ScriptFuture, ScriptOutcome, ScriptRunner};
pub use floor::check_url_safe;
pub use kernel::{Filesystem, ShellKernel};
pub use network::Network;
pub use program::{
    HostPrograms, HostSpawn, HostSpawnFuture, HostSpawnOutcome, HostSpawner, implements_program,
};
