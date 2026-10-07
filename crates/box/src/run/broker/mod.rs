//! The broker: one socket, one protocol, one interpreter per Program.
//!
//! | | Lifetime | Runs in |
//! |---|---|---|
//! | [`aliases`] | box — placed by `configure` | — (files on disk) |
//! | [`host`] | daemon — [`BrokerHost`] | the daemon, own thread |
//! | [`program`] | per Program | a Call's own task |
//! | [`reach`] | daemon — one per box | both interpreters, per effect |
//! | [`shell`] | per Program | a Call's own task; built per Program |
//! | [`python`] | per Call | inline; the interpreter is stateless |
//! | [`protocol`] | — | both ends |
//!
//! The split is by *lifetime and trust*, not by topic. An alias is an execute-only file the
//! **contained workload** runs; the host is trusted code holding the box's one `PolicyEngine`. They share
//! only [`protocol`], which is why that module carries the framing rules rather than either side.
//!
//! There were two of these — `shell/` and `script/`, each with its own socket, host, and wire
//! format. What differed was never the boundary, only the interpreter, so `Open` names one and the
//! rest is shared. See [`host`] for why the interpreters run in the daemon and what bounds
//! them there.
//!
//! [`shell`] and [`python`] are siblings holding what each interpreter needs, so a third costs an
//! `Interpreter` variant and a constructor. Their confinement is checked at different moments and
//! that is deliberate — the Shell's bind is verified once at construction, Python's path floor per
//! effect, because a Monty VM is built per Call and has no standing configuration to verify.

pub(crate) mod aliases;
pub(crate) mod complete;
mod held;
pub(crate) mod host;
mod kernel;
pub(crate) mod mcp;
pub(crate) mod mcp_remote;
pub(crate) mod program;
pub(crate) mod protocol;
pub(crate) mod python;
pub(crate) mod reach;
pub(crate) mod shell;

/// A refusal an operator reads, for input a broker module will not serve.
fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

pub(crate) use host::BrokerHost;
