//! The vault's data vocabulary — the shapes passed across the open/attach/redact steps.

mod destination;
mod inject;
mod material;
mod reference;
mod route;
mod secret;

pub use destination::{Destination, DestinationPattern};
pub use inject::InjectMode;
pub use reference::Locator;
pub use route::{PhantomCheck, RouteSpec};

// Crate-internal: a resolved secret's shape and the phantom that stands in for it are reached
// only through the vault's own verbs. `PhantomToken` surfaces to callers as the non-secret string on
// `Phantom::token`, and `AwsSessionCredentials` only ever travels from the AWS source to the signer.
pub(crate) use inject::{DEFAULT_PHANTOM_PREFIX, PhantomToken, check_phantom_prefix};
pub(crate) use material::AwsSessionCredentials;
pub(crate) use secret::Secret;
// The route's private kind enum, for the store's dispatch. Re-exported crate-internally rather than
// making the module public, so the variant set stays the crate's.
pub(crate) use route::RouteKind;
