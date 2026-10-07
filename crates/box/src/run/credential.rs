//! Turning stored locators into what the proxy needs, and a phantom for the
//! workload.

use std::collections::BTreeMap;
use std::sync::Arc;

use credentials::{Backend, Vault, VaultConfig};

use crate::error::{BoxError, Internal};
use crate::record::config::egress::{EgressEntry, EgressRoute, credsd_environments};

/// Validate every declared `credsd` credential before the workload starts.
///
/// A box that names no `credsd` source contacts no daemon. Otherwise this confirms the daemon is
/// reachable and speaks the protocol, and that each named environment holds a usable session; any
/// gap is a hard failure that stops the run before it spawns the workload.
/// Both maps are passed by construction: remote MCP is stored in its own map (`record.remote_mcp`),
/// so a credsd source declared only on a `[mcp.<name>] type = "http"` server is covered here rather
/// than deferred to the first request — the failure this preflight exists to prevent.
pub(crate) fn preflight_credsd(
    egress: &BTreeMap<String, EgressEntry>,
    remote_mcp: &BTreeMap<String, EgressEntry>,
) -> Result<(), BoxError> {
    let environments = credsd_environments(egress, remote_mcp);
    if environments.is_empty() {
        return Ok(());
    }
    // The socket resolves as the per-request fetch resolves it: no vault path is set at run
    // today, so both pass `None` and fall to `CREDSD_SOCKET`, else the platform default.
    credentials::credsd_preflight(None, &environments)?;
    Ok(())
}

/// What projecting the credential bindings produced.
pub(crate) struct Projection {
    /// The credential capabilities the proxy drives.
    pub(crate) capabilities: Vec<(credentials::DestinationPattern, Arc<Vault>)>,

    /// The phantom values, for the proxy to recognize on the way out.
    pub(crate) phantom_environment: Vec<(String, String)>,

    /// What every process's environment receives: every phantom, plus the signing placeholders.
    pub(crate) workload_environment: Vec<ProvisionedVariable>,
}

/// One variable a route provisions, placed in every process the box starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionedVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// Placeholder AWS credentials for a workload whose destination is a signed route.
const SIGNING_PLACEHOLDERS: [(&str, &str); 2] = [
    ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
    (
        "AWS_SECRET_ACCESS_KEY",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
];

/// Resolve every declared binding, minting one phantom per opaque route.
pub(crate) fn workspace(bindings: &[EgressRoute]) -> Result<Projection, BoxError> {
    let mut capabilities = Vec::with_capacity(bindings.len());
    let mut phantom_environment = Vec::new();
    let mut workload_environment: Vec<ProvisionedVariable> = Vec::new();
    for binding in bindings {
        // `require_every_route` is the box's fail-closed stance, now owned by the vault:
        let opened = Vault::open(
            VaultConfig::new(
                Backend::local(),
                format!("strands-box-{}", std::process::id()),
            )
            .route(binding.to_route_spec()?)
            .require_every_route(),
        )
        .map_err(|source| {
            Internal::CredentialProjection(format!(
                "credential for {host} did not resolve: {source}",
                host = binding.host()
            ))
        })?;

        // A signed binding mints no phantom (nothing is placed for the proxy to
        // match); an opaque one mints exactly one.
        match (binding.provisioned_name(), opened.phantoms()) {
            (Some(name), [phantom]) => {
                phantom_environment.push((name.to_string(), phantom.token().to_string()));
                workload_environment.push(ProvisionedVariable {
                    name: name.to_string(),
                    value: phantom.token().to_string(),
                });
            }
            // A signed route mints nothing to place. It does need the process to believe it holds
            // credentials, which `SIGNING_PLACEHOLDERS` supplies, once per signed route.
            (None, []) => {
                for (name, value) in SIGNING_PLACEHOLDERS {
                    workload_environment.push(ProvisionedVariable {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            // A minted phantom this crate cannot deliver. Unreachable today — `validate` admits
            // only `env://` (which names a variable) and `aws://` (which mints none), so the two
            (None, phantoms) => {
                return Err(Internal::CredentialProjection(format!(
                    "credential for {} minted {} phantom binding(s) the box cannot place: a \
                     credential with no provisioned variable can only be a signed route, which \
                     mints none",
                    binding.host(),
                    phantoms.len()
                ))
                .into());
            }
            (Some(_), phantoms) => {
                return Err(Internal::CredentialProjection(format!(
                    "credential for {} produced {} phantom bindings, expected one",
                    binding.host(),
                    phantoms.len()
                ))
                .into());
            }
        }
        capabilities.push((binding.destination().clone(), Arc::new(opened.into_vault())));
    }

    Ok(Projection {
        workload_environment,
        capabilities,
        phantom_environment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::config::egress::EgressEntry;

    /// `HOME`-free fixture: the credential vault reads no layout, only the locator.
    fn target(toml: &str) -> EgressEntry {
        toml::from_str(toml).expect("the fixture must be a well-formed credential entry")
    }

    /// A resolved binding mints exactly one phantom, and both copies agree.
    #[test]
    fn a_resolved_binding_mints_one_phantom_both_sides_agree_on() {
        // SAFETY: the variable is namespaced to this test, so no other test reads or
        // writes it, and it is removed before the test returns.
        unsafe { std::env::set_var("STRANDS_BOX_PRESENT_FOR_TESTS", "sk-real-secret") };
        let binding = target(
            r#"
            destinations = ["api.anthropic.com"]
            secret.ref = "env://STRANDS_BOX_PRESENT_FOR_TESTS"
            secret.header = "x-api-key"
            secret.prefix = ""
            "#,
        )
        .to_bindings()
        .expect("an env locator whose variable is set must bind");

        let projection = workspace(&binding).expect("the locator resolves");

        assert_eq!(projection.capabilities.len(), 1);
        let placed: Vec<(String, String)> = projection
            .workload_environment
            .iter()
            .map(|variable| (variable.name.clone(), variable.value.clone()))
            .collect();
        assert_eq!(
            projection.phantom_environment, placed,
            "with no signed route the two sets are equal: the proxy and the workload must watch \
             for the same literal"
        );
        let variable = &projection.workload_environment[0];
        let (name, value) = (&variable.name, &variable.value);
        assert_eq!(
            name, "STRANDS_BOX_PRESENT_FOR_TESTS",
            "the phantom is provisioned under the variable the locator named"
        );
        assert_ne!(
            value, "sk-real-secret",
            "the workload must receive a phantom, never the real secret"
        );
        assert!(
            !value.is_empty(),
            "an empty phantom would match every outbound request"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("STRANDS_BOX_PRESENT_FOR_TESTS") };
    }

    /// Every binding produces a capability, phantom or not.
    #[test]
    fn every_binding_yields_a_capability() {
        // SAFETY: both variables are namespaced to this test.
        unsafe {
            std::env::set_var("STRANDS_BOX_FIRST_FOR_TESTS", "first");
            std::env::set_var("STRANDS_BOX_SECOND_FOR_TESTS", "second");
        }
        let bindings: Vec<_> = [
            r#"
            destinations = ["api.anthropic.com"]
            secret.ref = "env://STRANDS_BOX_FIRST_FOR_TESTS"
            "#,
            r#"
            destinations = ["api.openai.com"]
            secret.ref = "env://STRANDS_BOX_SECOND_FOR_TESTS"
            "#,
        ]
        .into_iter()
        .flat_map(|toml| target(toml).to_bindings().unwrap())
        .collect();

        let projection = workspace(&bindings).expect("both locators resolve");

        assert_eq!(
            projection.capabilities.len(),
            2,
            "a dropped capability is a destination reachable with no credential"
        );
        assert_eq!(projection.workload_environment.len(), 2);
        let phantoms: Vec<&str> = projection
            .workload_environment
            .iter()
            .map(|variable| variable.value.as_str())
            .collect();
        assert_ne!(
            phantoms[0], phantoms[1],
            "two secrets sharing one phantom would let either be swapped for the other"
        );
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("STRANDS_BOX_FIRST_FOR_TESTS");
            std::env::remove_var("STRANDS_BOX_SECOND_FOR_TESTS");
        }
    }

    /// A box that declares no egress resolves nothing.
    #[test]
    fn a_box_with_no_declared_egress_resolves_nothing() {
        let projection = workspace(&[]).expect("no bindings is not a failure");

        assert!(projection.capabilities.is_empty());
        assert!(projection.workload_environment.is_empty());
        assert!(projection.phantom_environment.is_empty());
    }

    /// **A signed route gives the workload placeholder AWS credentials, and the proxy none.**
    ///
    /// The two sets differ here and are equal for an opaque route. That asymmetry is the whole
    #[test]
    fn a_signed_route_places_nothing_and_still_credentials_the_workload() {
        let bindings = target(
            r#"
            destinations = ["bedrock-runtime.us-east-2.amazonaws.com"]
            secret.ref = "aws://default"
            "#,
        )
        .to_bindings()
        .expect("an aws locator binds as a signed route");

        let Ok(projection) = workspace(&bindings) else {
            // Resolving the profile needs an ambient AWS identity, which CI may not have. The
            // shape below is what this test is about, so skip rather than assert on the host.
            eprintln!("skipping: no ambient AWS identity to open a signed route with");
            return;
        };

        assert!(
            projection.phantom_environment.is_empty(),
            "a signed route places nothing for the proxy to match"
        );
        let names: Vec<&str> = projection
            .workload_environment
            .iter()
            .map(|variable| variable.name.as_str())
            .collect();
        assert!(
            names.contains(&"AWS_ACCESS_KEY_ID") && names.contains(&"AWS_SECRET_ACCESS_KEY"),
            "the workload must receive placeholder credentials, or its own SDK refuses to send: \
             {names:?}"
        );
        assert!(
            !names.contains(&"AWS_SESSION_TOKEN"),
            "no session token is set, so nothing invents one an SDK may validate: {names:?}"
        );
    }

    /// A `credsd://` route with no declared `secret.type` opens as a signed route without contacting
    /// the daemon, and gives the workload placeholder credentials while the proxy gets none.
    ///
    /// Unlike the `aws://` case above, this needs no ambient AWS identity: a signed route resolves
    /// nothing at open, and credsd resolves per request, inferring the type from `material.type`.
    #[test]
    fn a_credsd_route_opens_signed_and_credentials_the_workload() {
        let bindings = target(
            r#"
            destinations = ["bedrock-runtime.us-east-2.amazonaws.com"]
            secret.ref = "credsd://prod-inference"
            "#,
        )
        .to_bindings()
        .expect("an untyped credsd locator binds as a signed route");

        let projection =
            workspace(&bindings).expect("a credsd route opens without contacting the daemon");

        assert!(
            projection.phantom_environment.is_empty(),
            "a signed route places nothing for the proxy to match"
        );
        let names: Vec<&str> = projection
            .workload_environment
            .iter()
            .map(|variable| variable.name.as_str())
            .collect();
        assert!(
            names.contains(&"AWS_ACCESS_KEY_ID") && names.contains(&"AWS_SECRET_ACCESS_KEY"),
            "the workload receives placeholder credentials: {names:?}"
        );
    }
}
