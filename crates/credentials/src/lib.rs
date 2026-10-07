//! Credential materialization for trusted Strands box boundaries.

#![warn(missing_docs, unreachable_pub)]

mod attach;
mod audit;
mod backend;
mod config;
mod diagnostic;
mod error;
mod legs;
mod model;
mod opened;
mod preflight;
mod sources;
mod vault;

pub use attach::{Attachment, Inbound, Outbound, Redactions};
pub use backend::Backend;
pub use config::VaultConfig;
pub use error::{CredentialError, Result};
pub use model::{Destination, DestinationPattern, InjectMode, Locator, PhantomCheck, RouteSpec};
pub use opened::{Opened, Phantom, Skipped};
pub use preflight::credsd_preflight;
pub use vault::Vault;

// Crate-internal. Each of these was public until 2026-08-07 and is now reached only from inside:
//
// - `Emitter` / `audit_resolve` / `RequestId` — the acquisition audit. It is emitted on the load path
//   and no longer crosses the façade, which also resolves the `Emitter` name collision with
//   `egress-proxy`'s own (live, unrelated) emitter seam.
// - `CredentialDiagnostic` / `redact_credential_ref` — redaction happens inside the diagnostic and
//   audit constructors; callers see a `Skipped`.
// - `AwsSessionCredentials` / `PhantomToken` / `Secret` — resolved-material shapes that exist only
//   between a source and the vault's own load path. `Secret` is the opaque one, and its constructor
//   is where the content rule lives
//   (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
// - `sign_request` — reached through `attach_for`, never called directly by the proxy.
pub(crate) use audit::{Emitter, RequestId, audit_resolve};
pub(crate) use diagnostic::{CredentialDiagnostic, redact_credential_ref};
pub(crate) use model::{
    AwsSessionCredentials, DEFAULT_PHANTOM_PREFIX, PhantomToken, Secret, check_phantom_prefix,
};
pub(crate) use sources::sign_request;
