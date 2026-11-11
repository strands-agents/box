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

/// The bindings that share one vault: every binding provisioned under one variable, or one binding
/// that provisions none.
fn credential_groups(bindings: &[EgressRoute]) -> Vec<Vec<&EgressRoute>> {
    let mut groups: Vec<Vec<&EgressRoute>> = Vec::new();
    for binding in bindings {
        let shared = binding.provisioned_name().and_then(|name| {
            groups
                .iter_mut()
                .find(|group| group[0].provisioned_name() == Some(name))
        });
        match shared {
            Some(group) => group.push(binding),
            None => groups.push(vec![binding]),
        }
    }
    groups
}

/// Open one vault over a group of routes that share one credential authority, failing closed if any
/// route does not resolve. `label` names the vault's tenant; `subject` names the host(s) for an
/// error. Both projection paths open through here, so the fail-closed stance has one home.
fn open_vault<'a>(
    label: &str,
    subject: &str,
    routes: impl IntoIterator<Item = &'a EgressRoute>,
) -> Result<credentials::Opened, BoxError> {
    let mut config = VaultConfig::new(Backend::local(), format!("{label}-{}", std::process::id()))
        .require_every_route();
    for route in routes {
        config = config.route(route.to_route_spec()?);
    }
    Vault::open(config).map_err(|source| {
        Internal::CredentialProjection(format!(
            "credential for {subject} did not resolve: {source}"
        ))
        .into()
    })
}

/// Open one vault per backend entry group, each holding that entry's strip-phantom destination
/// secret and box-owned backend token together (one credential authority on one destination). The
/// strip route provisions a phantom to the workload; the box-owned token and a signed `aws://` auth
/// are attached at the gateway and placed in no workload environment. An absent credential is hard
/// here. A backend entry keeps its routes in ONE vault, so this groups per entry rather than by
/// provisioned variable the way [`workspace`] does.
pub(crate) fn backend_capabilities(
    groups: &[(credentials::DestinationPattern, Vec<EgressRoute>)],
) -> Result<Projection, BoxError> {
    let mut capabilities = Vec::with_capacity(groups.len());
    let mut workload_environment = Vec::new();
    for (original, routes) in groups {
        let Some(first) = routes.first() else {
            continue;
        };
        let opened = open_vault("strands-box-backend", first.host(), routes)?;
        // A strip-phantom destination secret mints one phantom, provisioned to the workload under the
        // destination secret's variable name. The box-owned token and a signed `aws://` auth mint none.
        let provisioned_name = routes.iter().find_map(EgressRoute::provisioned_name);
        for phantom in opened.phantoms() {
            if let Some(name) = provisioned_name {
                workload_environment.push(ProvisionedVariable {
                    name: name.to_string(),
                    value: phantom.token().to_string(),
                });
            }
        }
        capabilities.push((original.clone(), Arc::new(opened.into_vault())));
    }
    Ok(Projection {
        capabilities,
        workload_environment,
    })
}

/// Combine the ordinary routes' provisioned variables with the backend entries' strip-phantom
/// placeholders. A variable named by both an ordinary route and a backend entry's strip route keeps
/// the ORDINARY route's phantom: that route's swap is Strict and needs its own placeholder present,
/// while the backend strip is unconditional and removes whatever value the workload sent. So the two
/// share one placeholder, and the backend's duplicate is dropped.
pub(crate) fn merge_workload_environment(
    ordinary: Vec<ProvisionedVariable>,
    backend: Vec<ProvisionedVariable>,
) -> Vec<ProvisionedVariable> {
    let ordinary_names: std::collections::HashSet<String> = ordinary
        .iter()
        .map(|variable| variable.name.clone())
        .collect();
    let mut merged = ordinary;
    for variable in backend {
        if !ordinary_names.contains(&variable.name) {
            merged.push(variable);
        }
    }
    merged
}

/// Resolve every declared binding, minting one phantom per provisioned variable.
pub(crate) fn workspace(bindings: &[EgressRoute]) -> Result<Projection, BoxError> {
    let mut capabilities = Vec::with_capacity(bindings.len());
    let mut workload_environment: Vec<ProvisionedVariable> = Vec::new();
    for group in credential_groups(bindings) {
        let binding = group[0];
        let hosts = group
            .iter()
            .map(|binding| binding.host())
            .collect::<Vec<_>>()
            .join(", ");
        let opened = open_vault("strands-box", &hosts, group.iter().copied())?;

        // A signed binding mints no phantom (nothing is placed for the proxy to
        // match); the routes of one variable share exactly one.
        match (binding.provisioned_name(), opened.phantoms()) {
            (Some(name), [phantom, rest @ ..])
                if rest.len() + 1 == group.len()
                    && rest.iter().all(|other| other.token() == phantom.token()) =>
            {
                workload_environment.push(ProvisionedVariable {
                    name: name.to_string(),
                    value: phantom.token().to_string(),
                });
            }
            // A signed route mints nothing to place. It does need the process to believe it holds
            // credentials, which `SIGNING_PLACEHOLDERS` supplies, once per signed route. `signs()` is
            // asked directly, rather than inferred from the absent name, so a box-owned backend token
            // — which also has no name and no phantom — is never mistaken for a signed route.
            (None, []) if binding.signs() => {
                for (name, value) in SIGNING_PLACEHOLDERS {
                    workload_environment.push(ProvisionedVariable {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            // A box-owned token (a backend's own credential): no name, no phantom, and nothing placed
            // in the workload environment, because the box attaches it at the gateway.
            (None, []) => {}
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
                    "credential for {hosts} produced {} phantom bindings for {} routes, expected \
                     one shared phantom",
                    phantoms.len(),
                    group.len()
                ))
                .into());
            }
        }
        // One vault serves every destination of the group; each destination is its own capability.
        let vault = Arc::new(opened.into_vault());
        for member in &group {
            capabilities.push((member.destination().clone(), Arc::clone(&vault)));
        }
    }

    Ok(Projection {
        workload_environment,
        capabilities,
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

    /// One key that serves two hosts gets one phantom, and a strict check accepts it at each host,
    /// whether one route lists both hosts or two routes name one variable.
    #[test]
    fn one_variable_for_two_hosts_provisions_one_phantom_accepted_at_both() {
        // SAFETY: the variable is namespaced to this test, so no other test reads or writes it,
        // and it is removed before the test returns.
        unsafe { std::env::set_var("STRANDS_BOX_SHARED_FOR_TESTS", "ksk-real-secret") };
        let one_route = vec![
            r#"
            destinations = ["management.example.dev", "runtime.example.dev"]
            secret.ref = "env://STRANDS_BOX_SHARED_FOR_TESTS"
            "#,
        ];
        let two_routes = vec![
            r#"
            destinations = ["management.example.dev"]
            secret.ref = "env://STRANDS_BOX_SHARED_FOR_TESTS"
            "#,
            r#"
            destinations = ["runtime.example.dev"]
            secret.ref = "env://STRANDS_BOX_SHARED_FOR_TESTS"
            secret.inject = "always"
            "#,
        ];
        for shape in [one_route, two_routes] {
            let bindings: Vec<_> = shape
                .into_iter()
                .flat_map(|toml| target(toml).to_bindings().unwrap())
                .collect();

            let projection = workspace(&bindings).expect("the locator resolves");

            let [variable] = projection.workload_environment.as_slice() else {
                panic!(
                    "one variable is provisioned once: {:?}",
                    projection.workload_environment
                );
            };
            assert_eq!(projection.capabilities.len(), 2, "one capability per host");
            let headers = vec![(
                "Authorization".to_string(),
                format!("Bearer {}", variable.value),
            )];
            for (pattern, vault) in &projection.capabilities {
                let host = pattern.as_written();
                let url = format!("https://{host}/");
                let attachment = vault
                    .attach_for(credentials::Outbound {
                        destination: credentials::Destination {
                            host: &host,
                            port: 443,
                            path: "/",
                        },
                        method: "GET",
                        url: &url,
                        query: "",
                        headers: &headers,
                        body: b"",
                    })
                    .unwrap_or_else(|error| panic!("{host} must accept the one phantom: {error}"));
                assert!(attachment.is_some(), "{host} attaches the credential");
            }
        }
        // SAFETY: as above.
        unsafe { std::env::remove_var("STRANDS_BOX_SHARED_FOR_TESTS") };
    }

    /// A backend entry's credentials open as ONE vault (one control on one destination): the
    /// box-owned backend token provisions no workload variable, and the strip-phantom destination
    /// secret provisions exactly one.
    #[test]
    fn a_backend_entry_opens_one_capability_and_provisions_only_its_strip_phantom() {
        // SAFETY: the variables are namespaced to this test.
        unsafe {
            std::env::set_var("STRANDS_BOX_BACKEND_FOR_TESTS", "gw-real-token");
            std::env::set_var("STRANDS_BOX_DESTSECRET_FOR_TESTS", "dest-token");
        }
        let entry = target(
            r#"
            destinations = ["api.github.com"]
            secret.ref = "env://STRANDS_BOX_DESTSECRET_FOR_TESTS"

            [[backends]]
            url = "https://gateway-1.example.com"
            auth.ref = "env://STRANDS_BOX_BACKEND_FOR_TESTS"
            "#,
        );
        let routes = entry
            .backend_credential_routes()
            .expect("the backend credential routes build");
        assert_eq!(routes.len(), 2, "a strip route and a box-owned route");
        let original = entry
            .primary_destination()
            .expect("pattern builds")
            .expect("a backend entry has one destination");
        let projection =
            backend_capabilities(&[(original, routes)]).expect("the backend vault opens");
        assert_eq!(
            projection.capabilities.len(),
            1,
            "one control for the one destination"
        );
        assert_eq!(
            projection.workload_environment.len(),
            1,
            "only the strip-phantom destination secret provisions a workload variable"
        );
        let variable = &projection.workload_environment[0];
        assert_eq!(variable.name, "STRANDS_BOX_DESTSECRET_FOR_TESTS");
        assert_ne!(variable.value, "dest-token", "the workload gets a phantom");
        assert_ne!(variable.value, "gw-real-token", "never the backend token");
        // SAFETY: as above.
        unsafe {
            std::env::remove_var("STRANDS_BOX_BACKEND_FOR_TESTS");
            std::env::remove_var("STRANDS_BOX_DESTSECRET_FOR_TESTS");
        }
    }

    /// A backend box launches with its destination secret UNSET: the strip-phantom route mints a
    /// placeholder and strips it, so the box never reads the real value and does not require it. This
    /// is the case a backend exists for — the operator has no destination token.
    #[test]
    fn a_backend_strip_phantom_opens_without_the_destination_secret_set() {
        // SAFETY: the variable is namespaced to this test and is never set; remove it defensively so
        // a stray value from another run cannot mask the property under test.
        unsafe { std::env::remove_var("STRANDS_BOX_UNSET_DESTSECRET_FOR_TESTS") };
        let entry = target(
            r#"
            destinations = ["api.github.com"]
            secret.ref = "env://STRANDS_BOX_UNSET_DESTSECRET_FOR_TESTS"

            [[backends]]
            url = "https://gateway-1.example.com"
            "#,
        );
        let routes = entry
            .backend_credential_routes()
            .expect("the backend credential routes build");
        assert_eq!(routes.len(), 1, "only the strip-phantom destination secret");
        let original = entry
            .primary_destination()
            .expect("pattern builds")
            .expect("a backend entry has one destination");
        let projection = backend_capabilities(&[(original, routes)])
            .expect("the backend vault opens with the var unset");
        assert_eq!(projection.capabilities.len(), 1);
        assert_eq!(
            projection.workload_environment.len(),
            1,
            "the strip-phantom route still provisions its placeholder"
        );
        let variable = &projection.workload_environment[0];
        assert_eq!(variable.name, "STRANDS_BOX_UNSET_DESTSECRET_FOR_TESTS");
        assert!(
            !variable.value.is_empty(),
            "the workload gets a minted phantom, not the unset real value"
        );
    }

    /// A variable named by both an ordinary route and a backend entry's strip route resolves to ONE
    /// placeholder — the ordinary route's, because its swap is Strict and the backend strip is
    /// unconditional. So the workload holds one value both the direct and the re-routed host handle.
    #[test]
    fn a_shared_variable_keeps_the_ordinary_phantom_and_drops_the_backend_duplicate() {
        let ordinary = vec![ProvisionedVariable {
            name: "GITHUB_TOKEN".to_string(),
            value: "ordinary-phantom".to_string(),
        }];
        let backend = vec![ProvisionedVariable {
            name: "GITHUB_TOKEN".to_string(),
            value: "backend-phantom".to_string(),
        }];
        let merged = merge_workload_environment(ordinary, backend);
        assert_eq!(merged.len(), 1, "one placeholder for the one variable");
        assert_eq!(
            merged[0].value, "ordinary-phantom",
            "the ordinary route's Strict-checked phantom survives; the backend strip is unconditional"
        );
    }

    /// A backend-only variable (no ordinary route names it) is still provisioned.
    #[test]
    fn a_backend_only_variable_is_provisioned() {
        let merged = merge_workload_environment(
            Vec::new(),
            vec![ProvisionedVariable {
                name: "GW_TOKEN".to_string(),
                value: "backend-phantom".to_string(),
            }],
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "GW_TOKEN");
    }

    /// A box that declares no egress resolves nothing.
    #[test]
    fn a_box_with_no_declared_egress_resolves_nothing() {
        let projection = workspace(&[]).expect("no bindings is not a failure");

        assert!(projection.capabilities.is_empty());
        assert!(projection.workload_environment.is_empty());
    }

    /// **A signed route gives the workload placeholder AWS credentials.**
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
