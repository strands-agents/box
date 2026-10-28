//! WebSocket (RFC 6455) through an intercepted TLS connection.
//!
//! | Part | Does |
//! |---|---|
//! | [`classify`] | Find a WebSocket handshake in a request head, or the reason that it is malformed |
//!
//! The handshake is an ordinary `http:request` `GET` on its path. There is no other policy action.

mod handshake;

pub(super) use handshake::{Handshake, classify};
