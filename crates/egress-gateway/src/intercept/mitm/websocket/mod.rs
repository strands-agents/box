//! WebSocket (RFC 6455) through an intercepted TLS connection.
//!
//! | Part | Does |
//! |---|---|
//! | [`classify`] | Find a WebSocket handshake in a request head, or the reason that it is malformed |
//! | [`Expected`], [`check_switching_protocols`] | Accept a `101` only when it answers the forwarded handshake |
//! | [`run`] | Read, check, and frame again every frame in both directions after the `101` |
//!
//! The handshake is an ordinary `http:request` `GET` on its path. There is no other policy action.
//! The release of the `101` admits the messages of its session.

mod frame;
mod handshake;
mod relay;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OwnedSemaphorePermit;

use crate::audit::RequestId;

pub(super) use handshake::{Expected, Handshake, check_switching_protocols, classify};
pub(super) use relay::run;

/// The share of the connection slots that open WebSockets may hold, in quarters. The rest stay free
/// for ordinary requests and the hosted Shell.
const SESSION_QUARTERS: usize = 3;

/// How many WebSockets may be open at one time, for `slots` connection slots: three quarters,
/// rounded down.
pub(super) fn session_slots(slots: usize) -> usize {
    slots.saturating_mul(SESSION_QUARTERS) / 4
}

/// A stream that the relay reads and writes.
pub(super) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Duplex for S {}

/// What the connection task needs to relay one WebSocket once hyper has written its `101`. No
/// `Debug`.
pub(super) struct Pending {
    pub(super) host: String,
    pub(super) port: u16,
    /// The path as the workload sent it, before any credential mutation.
    pub(super) path: String,
    pub(super) correlation: RequestId,
    /// The upstream after its `101`, with the bytes that the server sent after its head first.
    pub(super) upstream: Box<dyn Duplex>,
    /// One of the session slots, held until the relay ends.
    pub(super) slot: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_websockets_take_at_most_three_quarters_of_the_slots() {
        assert_eq!(session_slots(256), 192);
        assert_eq!(session_slots(4), 3);
        assert_eq!(session_slots(2), 1);
        assert_eq!(session_slots(1), 0);
        assert_eq!(session_slots(usize::MAX), usize::MAX / 4);
    }
}
