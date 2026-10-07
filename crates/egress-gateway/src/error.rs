//! Fail-closed, typed error model for the proxy — [`ProxyError`].

/// Fail-closed, typed error model for the proxy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// A config-load failure, fail closed: a malformed route, a `Control` needing more visibility
    /// than the interceptor can ever provide, or a route requiring interception while
    /// `tls-intercept` is off. Wraps the vault's [`CredentialError`](credentials::CredentialError)
    /// when a credential route cannot be built.
    #[error("invalid proxy config: {0}")]
    Config(String),

    /// The listener could not bind its localhost address.
    #[error("proxy bind failed: {0}")]
    Bind(String),

    /// A host was denied (default-deny allowlist) → HTTP 403.
    #[error("host denied: {0}")]
    HostDenied(String),

    /// A resolved IP was denied (a policy deny) → HTTP 403.
    #[error("ip denied: {0}")]
    IpDenied(String),

    /// A proxy-auth / session-token check failed → HTTP 407.
    #[error("invalid proxy token: {0}")]
    InvalidToken(String),

    /// A generic egress control denied the exchange → HTTP 403.
    #[error("control denied: {0}")]
    ControlDenied(String),

    /// A credential could not be attached (ambiguous binding, phantom mismatch, signer error) → 403.
    #[error("credential error: {0}")]
    Credential(String),

    /// No Connection-scope Decision Control authorized the request — the deny-by-default gate:
    /// empty set, no opted-in Connection kind, or a host matching no rule → HTTP 403.
    /// Names no host/IP (log-safe).
    #[error("not authorized (default-deny)")]
    NotAuthorized,

    /// The upstream connection failed → HTTP 502.
    #[error("upstream connect failed: {0}")]
    UpstreamConnect(String),

    /// A TLS-interception / MITM machinery failure → HTTP 502.
    #[error("intercept error: {0}")]
    Intercept(String),

    /// A response breached a configured size/content limit → HTTP 502.
    #[error("response limit exceeded: {0}")]
    ResponseLimit(String),

    /// An underlying I/O failure.
    #[error("io error: {0}")]
    Io(String),
}

/// The header naming a response as the gateway's own.
///
/// The gateway forges the origin's leaf certificate on interception, so a refusal it synthesises
/// inside its own tunnel is otherwise indistinguishable from the origin answering with the same
/// status. Set on the responses the gateway originates and on nothing it relays, so there is no
/// upstream hop to forward it to. A trusted client turns a response carrying it into a refusal and
/// never renders it.
pub const PROXY_ORIGIN_HEADER: &str = "x-strands-box-egress";

/// The one value [`PROXY_ORIGIN_HEADER`] carries: the question is only whether the gateway wrote it.
pub const PROXY_ORIGIN_VALUE: &str = "refused";

impl ProxyError {
    /// The HTTP status code this error maps to when the proxy must answer the workload:
    /// `407` for a proxy-auth failure, `403` for a host/IP/control/credential denial, `502` for an
    /// upstream/intercept/response-limit failure, `503` for a config/bind failure, `502` for I/O.
    pub fn http_status(&self) -> u16 {
        match self {
            ProxyError::InvalidToken(_) => 407,
            ProxyError::HostDenied(_)
            | ProxyError::IpDenied(_)
            | ProxyError::ControlDenied(_)
            | ProxyError::Credential(_)
            | ProxyError::NotAuthorized => 403,
            ProxyError::UpstreamConnect(_)
            | ProxyError::Intercept(_)
            | ProxyError::ResponseLimit(_)
            | ProxyError::Io(_) => 502,
            ProxyError::Config(_) | ProxyError::Bind(_) => 503,
        }
    }
}

/// A mapping failure preserves the vault's fail-closed reason — and
/// its `Display` never renders secret material, so this wrapper does not either.
impl From<credentials::CredentialError> for ProxyError {
    fn from(err: credentials::CredentialError) -> Self {
        ProxyError::Config(format!("route mapping failed: {err}"))
    }
}

/// Turn a [`DenyReason`](crate::boundary::DenyReason) into the matching fail-closed [`ProxyError`]
/// the interceptor answers the workload with.
impl From<crate::boundary::DenyReason> for ProxyError {
    fn from(reason: crate::boundary::DenyReason) -> Self {
        use crate::boundary::DenyReason;
        match reason {
            DenyReason::HostDenied(h) => ProxyError::HostDenied(h),
            DenyReason::IpDenied(m) => ProxyError::IpDenied(m),
            DenyReason::MutationCollision(m) => ProxyError::Config(m),
            DenyReason::Credential(m) => ProxyError::Credential(m),
            DenyReason::ControlDenied(m) => ProxyError::ControlDenied(m),
            DenyReason::ResponseLimit(m) => ProxyError::ResponseLimit(m),
            DenyReason::NotAuthorized => ProxyError::NotAuthorized,
        }
    }
}

/// Convenience alias for the crate's fallible operations.
pub type Result<T> = std::result::Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::DenyReason;

    #[test]
    fn http_status_mapping() {
        assert_eq!(ProxyError::InvalidToken("x".into()).http_status(), 407);
        assert_eq!(ProxyError::HostDenied("x".into()).http_status(), 403);
        assert_eq!(ProxyError::IpDenied("x".into()).http_status(), 403);
        assert_eq!(ProxyError::ControlDenied("x".into()).http_status(), 403);
        assert_eq!(ProxyError::Credential("x".into()).http_status(), 403);
        assert_eq!(ProxyError::UpstreamConnect("x".into()).http_status(), 502);
        assert_eq!(ProxyError::ResponseLimit("x".into()).http_status(), 502);
        assert_eq!(ProxyError::Config("x".into()).http_status(), 503);
        assert_eq!(ProxyError::Bind("x".into()).http_status(), 503);
    }

    #[test]
    fn deny_reason_maps_to_proxy_error() {
        assert!(matches!(
            ProxyError::from(DenyReason::HostDenied("h".into())),
            ProxyError::HostDenied(_)
        ));
        assert!(matches!(
            ProxyError::from(DenyReason::MutationCollision("v".into())),
            ProxyError::Config(_)
        ));
        assert!(matches!(
            ProxyError::from(DenyReason::ControlDenied("p".into())),
            ProxyError::ControlDenied(_)
        ));
    }

    #[test]
    fn credential_error_maps_to_config_fail_closed() {
        let err = credentials::CredentialError::Credential("bad".into());
        assert!(matches!(ProxyError::from(err), ProxyError::Config(_)));
    }
}
