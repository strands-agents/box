//! End-to-end vault flow through the **public API only**.
//!
//! Unlike the per-module `#[cfg(test)]` unit tests (which can reach private internals), this file is a
//! separate crate: it can touch only what `credentials` re-exports. That makes it the file that proves
//! the *bounded* surface is sufficient — it drives the real seam `egress-proxy` uses, and it can no
//! longer reach a plaintext secret at all, because there is no public method that vends
//! one. Every assertion about a secret here is therefore made through
//! [`Vault::attach_for`] or [`Vault::redact_leaks`], which is exactly how the proxy
//! sees it.
//!
//! It exercises the in-process sources (`env://`, `file://`) through the real [`Backend::local`], so it
//! needs no network, no `op` CLI, and no AWS credentials — it is hermetic and runs on any host. The
//! subprocess-backed `op://` source and the AWS provider chain cannot run hermetically; their
//! parse/spawn/redaction behaviour is proven by their own in-crate unit tests.

use std::io::Write;

use credentials::{
    Backend, Destination, DestinationPattern, InjectMode, Locator, Outbound, PhantomCheck,
    RouteSpec, Vault, VaultConfig,
};

fn header(format: &str) -> InjectMode {
    InjectMode::header(format.to_string(), None).unwrap()
}

fn dest<'a>(host: &'a str, port: u16, path: &'a str) -> Destination<'a> {
    Destination { host, port, path }
}

/// An outbound request presenting `phantom` in an `Authorization: Bearer …` header.
fn bearer_request<'a>(
    destination: Destination<'a>,
    headers: &'a [(String, String)],
    url: &'a str,
) -> Outbound<'a> {
    Outbound {
        destination,
        method: "GET",
        url,
        query: "",
        headers,
        body: b"",
    }
}

fn bearer_headers(phantom: &str) -> Vec<(String, String)> {
    vec![("Authorization".to_string(), format!("Bearer {phantom}"))]
}

/// The single secret an [`Attachment`](credentials::Attachment) attaches to `Authorization`.
///
/// The test's only window onto a resolved secret: the vault vends edits,
/// never plaintext, so a test asserts what would reach the wire rather than what the vault holds.
fn attached_authorization(store: &Vault, req: Outbound<'_>) -> String {
    let attachment = store
        .attach_for(req)
        .expect("the phantom matches its binding")
        .expect("a credential is bound for this destination");
    attachment
        .set_headers()
        .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
        .map(|(_, value)| value.to_string())
        .expect("an opaque header route sets Authorization")
}

/// Set `name` to `value` for the duration of the test.
fn set_var(name: &str, value: &str) {
    // SAFETY: every caller uses a name scoped to its own test, so no other test reads or writes it.
    unsafe { std::env::set_var(name, value) };
}

fn clear_var(name: &str) {
    // SAFETY: as above.
    unsafe { std::env::remove_var(name) };
}

/// The happy path: two `env://` routes open cleanly, and each destination attaches the real secret
/// pulled from the environment — the whole `route → open → attach_for` chain, through the public API
/// only, against the real `Backend::local` and its `env://` source.
#[test]
fn opens_env_routes_and_attaches_the_real_secret() {
    set_var("E2E_GITHUB_TOKEN", "ghp_real_github");
    set_var("E2E_STRIPE_KEY", "sk_live_real_stripe");

    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a")
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.github.com").unwrap(),
                Locator::parse_uri("env://E2E_GITHUB_TOKEN").unwrap(),
                header("Bearer {}"),
            ))
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.stripe.com").unwrap(),
                Locator::parse_uri("env://E2E_STRIPE_KEY").unwrap(),
                header("Bearer {}"),
            )),
    )
    .expect("both env routes resolve");

    assert!(
        opened.skipped().is_empty(),
        "both secrets are present, so nothing is skipped"
    );
    assert_eq!(opened.phantoms().len(), 2, "one phantom per opaque route");

    // Each phantom names its destination, so a supervisor knows which variable to seed.
    let github_phantom = opened
        .phantoms()
        .iter()
        .find(|p| p.destination() == &DestinationPattern::parse("api.github.com").unwrap())
        .expect("the github route minted a phantom")
        .token()
        .to_string();
    let stripe_phantom = opened
        .phantoms()
        .iter()
        .find(|p| p.destination() == &DestinationPattern::parse("api.stripe.com").unwrap())
        .expect("the stripe route minted a phantom")
        .token()
        .to_string();
    assert_ne!(
        github_phantom, stripe_phantom,
        "two secrets sharing one phantom would let either be swapped for the other"
    );

    let store = opened.into_vault();

    // Each destination attaches its own real secret — and only its own.
    let headers = bearer_headers(&github_phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.github.com", 443, "/user"),
                &headers,
                "https://api.github.com/user"
            )
        ),
        "Bearer ghp_real_github"
    );

    let headers = bearer_headers(&stripe_phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.stripe.com", 443, "/v1/charges"),
                &headers,
                "https://api.stripe.com/v1/charges"
            )
        ),
        "Bearer sk_live_real_stripe"
    );

    // A destination no route names has nothing bound: `Ok(None)`, not an error.
    let headers = bearer_headers(&github_phantom);
    assert!(
        store
            .attach_for(bearer_request(
                dest("api.openai.com", 443, "/v1"),
                &headers,
                "https://api.openai.com/v1"
            ))
            .expect("an unbound destination is not a failure")
            .is_none()
    );

    clear_var("E2E_GITHUB_TOKEN");
    clear_var("E2E_STRIPE_KEY");
}

/// A custom prefix mints an `sk-ant-` phantom, and the vault swaps it on a full-string match — the
/// prefix changes the minted literal, not the match.
#[test]
fn a_custom_prefix_route_mints_and_swaps() {
    set_var("E2E_ANTHROPIC_TOKEN", "sk-ant-realkey");

    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a").route(
            RouteSpec::opaque(
                DestinationPattern::parse("api.anthropic.com").unwrap(),
                Locator::parse_uri("env://E2E_ANTHROPIC_TOKEN").unwrap(),
                header("Bearer {}"),
            )
            .phantom_prefix("sk-ant-")
            .expect("an unreserved prefix is accepted"),
        ),
    )
    .expect("the route resolves");

    let phantom = opened.phantoms()[0].token().to_string();
    assert!(
        phantom.starts_with("sk-ant-"),
        "the minted phantom carries the custom prefix: {phantom}"
    );
    let store = opened.into_vault();

    let headers = bearer_headers(&phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.anthropic.com", 443, "/v1/messages"),
                &headers,
                "https://api.anthropic.com/v1/messages"
            )
        ),
        "Bearer sk-ant-realkey"
    );

    clear_var("E2E_ANTHROPIC_TOKEN");
}

/// A `file://` route resolves end-to-end through the real file source (trailing newline stripped),
/// proving the source axis is pluggable through the same public flow — no special casing per scheme.
#[test]
fn opens_a_file_route_and_strips_the_trailing_newline() {
    let dir = std::env::temp_dir().join(format!("credentials-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("token");
    let mut file = std::fs::File::create(&path).expect("create secret file");
    // The trailing newline a shell redirect leaves behind must not become part of the secret.
    writeln!(file, "file_real_secret").expect("write secret");

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::opaque(
            DestinationPattern::parse("api.internal.example").unwrap(),
            Locator::parse_uri(&format!("file://{}", path.display())).unwrap(),
            header("Bearer {}"),
        ),
    ))
    .expect("the file route resolves");

    let phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();
    let headers = bearer_headers(&phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.internal.example", 443, "/"),
                &headers,
                "https://api.internal.example/"
            )
        ),
        "Bearer file_real_secret",
        "the trailing newline must not survive into the attached value"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The **soft-miss** path (come up degraded, not down): a route whose `env://` variable is absent is
/// reported as skipped while every present route still opens and attaches.
#[test]
fn a_missing_secret_skips_only_its_own_route() {
    set_var("E2E_PRESENT_TOKEN", "present_real_secret");
    clear_var("E2E_ABSENT_TOKEN");

    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a")
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.present.example").unwrap(),
                Locator::parse_uri("env://E2E_PRESENT_TOKEN").unwrap(),
                header("Bearer {}"),
            ))
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.absent.example").unwrap(),
                Locator::parse_uri("env://E2E_ABSENT_TOKEN").unwrap(),
                header("Bearer {}"),
            )),
    )
    .expect("an absent secret is soft: the vault still comes up");

    assert_eq!(opened.skipped().len(), 1, "exactly the absent route");
    let skipped = &opened.skipped()[0];
    assert_eq!(skipped.destination(), "api.absent.example");
    assert_eq!(skipped.code(), "secret_not_found");
    // The skip is loggable: the variable name is redacted at the diagnostic's constructor.
    let rendered = skipped.to_string();
    assert!(
        !rendered.contains("E2E_ABSENT_TOKEN"),
        "the reference body leaked into an operator-facing line: {rendered}"
    );

    // Only the present route minted a phantom, and it still attaches.
    assert_eq!(opened.phantoms().len(), 1);
    let phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();
    let headers = bearer_headers(&phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.present.example", 443, "/"),
                &headers,
                "https://api.present.example/"
            )
        ),
        "Bearer present_real_secret"
    );

    // The skipped destination has nothing bound — it is reachable and uncredentialed, which is exactly
    // what the diagnostic warned about.
    let headers = bearer_headers(&phantom);
    assert!(
        store
            .attach_for(bearer_request(
                dest("api.absent.example", 443, "/"),
                &headers,
                "https://api.absent.example/"
            ))
            .expect("no binding is not an error")
            .is_none()
    );

    clear_var("E2E_PRESENT_TOKEN");
}

/// `require_every_route` turns that same soft miss into a startup failure, naming the destination.
///
/// This is the stance both supervisors want and used to hand-roll: for a process launching one
/// workload, a skipped route means the destination stays reachable with no credential, so the request
/// goes out bare and the upstream's `401` reads like the boundary denying it.
#[test]
fn require_every_route_refuses_to_open_with_a_missing_secret() {
    clear_var("E2E_REQUIRED_ABSENT");

    let err = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a")
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.required.example").unwrap(),
                Locator::parse_uri("env://E2E_REQUIRED_ABSENT").unwrap(),
                header("Bearer {}"),
            ))
            .require_every_route(),
    )
    .expect_err("the caller required every route");

    let message = err.to_string();
    assert!(message.contains("api.required.example"), "got {message}");
    assert!(
        !message.contains("E2E_REQUIRED_ABSENT"),
        "the reference body must stay redacted even in a hard error: {message}"
    );
}

/// Tenant isolation is **structural**: a vault opened for tenant B has no binding for tenant
/// A's destination, even when both configs name the same host — proven end-to-end through the public
/// API, with no cross-store leakage.
#[test]
fn stores_are_isolated_by_tenant_instance() {
    set_var("E2E_TENANT_A_TOKEN", "tenant_a_secret");
    set_var("E2E_TENANT_B_TOKEN", "tenant_b_secret");

    let open_for = |tenant: &str, variable: &str, host: &str| {
        Vault::open(
            VaultConfig::new(Backend::local(), tenant).route(RouteSpec::opaque(
                DestinationPattern::parse(host).unwrap(),
                Locator::parse_uri(&format!("env://{variable}")).unwrap(),
                header("Bearer {}"),
            )),
        )
        .expect("each tenant's secret is present")
    };

    let a = open_for("tenant-a", "E2E_TENANT_A_TOKEN", "api.shared.example");
    let b = open_for("tenant-b", "E2E_TENANT_B_TOKEN", "api.b-only.example");

    let a_phantom = a.phantoms()[0].token().to_string();
    let b_phantom = b.phantoms()[0].token().to_string();
    let a_store = a.into_vault();
    let b_store = b.into_vault();

    // Tenant A's vault attaches A's secret for the shared host.
    let headers = bearer_headers(&a_phantom);
    assert_eq!(
        attached_authorization(
            &a_store,
            bearer_request(
                dest("api.shared.example", 443, "/"),
                &headers,
                "https://api.shared.example/"
            )
        ),
        "Bearer tenant_a_secret"
    );

    // Tenant B's vault has no binding for it at all — not a denied lookup, an absent one.
    let headers = bearer_headers(&b_phantom);
    assert!(
        b_store
            .attach_for(bearer_request(
                dest("api.shared.example", 443, "/"),
                &headers,
                "https://api.shared.example/"
            ))
            .expect("an unbound destination is not a failure")
            .is_none(),
        "tenant B must not hold tenant A's binding"
    );

    // And A's phantom is meaningless in B's vault even on B's own host: the placeholder does not match
    // the binding, so the exchange fails closed rather than attaching B's secret.
    let headers = bearer_headers(&a_phantom);
    assert!(
        b_store
            .attach_for(bearer_request(
                dest("api.b-only.example", 443, "/"),
                &headers,
                "https://api.b-only.example/"
            ))
            .is_err(),
        "a phantom from another vault must not redeem a secret here"
    );

    clear_var("E2E_TENANT_A_TOKEN");
    clear_var("E2E_TENANT_B_TOKEN");
}

/// The phantom check cannot be skipped, because there is no unvalidated call to make.
///
/// The predecessor surface had `resolve_for`, which returned the real secret through a public field
/// with the phantom check left to the caller's discretion. This test is the regression guard on that:
/// the only way to a secret is `attach_for`, and it refuses both a mismatched and an absent phantom.
#[test]
fn a_wrong_or_missing_phantom_never_yields_a_secret() {
    set_var("E2E_UNSKIPPABLE_TOKEN", "unskippable_real_secret");

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::opaque(
            DestinationPattern::parse("api.guarded.example").unwrap(),
            Locator::parse_uri("env://E2E_UNSKIPPABLE_TOKEN").unwrap(),
            header("Bearer {}"),
        ),
    ))
    .unwrap();
    let real_phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();

    // A phantom-shaped value that is not this binding's phantom.
    let wrong = bearer_headers(
        "strands_box_0000000000000000000000000000000000000000000000000000000000000000",
    );
    let err = store
        .attach_for(bearer_request(
            dest("api.guarded.example", 443, "/"),
            &wrong,
            "https://api.guarded.example/",
        ))
        .expect_err("an unrecognised placeholder must fail closed");
    assert!(
        !err.to_string().contains("unskippable_real_secret"),
        "the error must not leak the secret it refused to attach: {err}"
    );

    // No phantom at all.
    let empty: Vec<(String, String)> = Vec::new();
    assert!(
        store
            .attach_for(bearer_request(
                dest("api.guarded.example", 443, "/"),
                &empty,
                "https://api.guarded.example/"
            ))
            .is_err(),
        "a request presenting no placeholder must not be credentialed"
    );

    // The correct phantom still works, so the guard is not simply refusing everything.
    let right = bearer_headers(&real_phantom);
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.guarded.example", 443, "/"),
                &right,
                "https://api.guarded.example/"
            )
        ),
        "Bearer unskippable_real_secret"
    );

    clear_var("E2E_UNSKIPPABLE_TOKEN");
}

/// An advisory route attaches the real secret without a matching placeholder, but the
/// secret still only reaches its bound destination — relaxing the check does not widen the binding.
#[test]
fn an_advisory_route_injects_without_a_placeholder_but_stays_bound() {
    set_var("E2E_ADVISORY_TOKEN", "advisory_real_secret");

    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a").route(
            RouteSpec::opaque(
                DestinationPattern::parse("api.advisory.example").unwrap(),
                Locator::parse_uri("env://E2E_ADVISORY_TOKEN").unwrap(),
                header("Bearer {}"),
            )
            .phantom_check(PhantomCheck::Advisory),
        ),
    )
    .unwrap();
    let store = opened.into_vault();

    // No placeholder at all: advisory attaches the real secret anyway, and records a non-secret
    // reason for the gateway to journal on the allow decision.
    let empty: Vec<(String, String)> = Vec::new();
    let attachment = store
        .attach_for(bearer_request(
            dest("api.advisory.example", 443, "/"),
            &empty,
            "https://api.advisory.example/",
        ))
        .expect("advisory attaches without a placeholder")
        .expect("a credential is bound here");
    let reason = attachment
        .advisory_reason()
        .expect("an advisory injection records a reason");
    assert!(
        reason.contains("inject = always"),
        "the reason names the mode: {reason}"
    );
    assert!(
        !reason.contains("advisory_real_secret"),
        "the reason carries no secret: {reason}"
    );
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.advisory.example", 443, "/"),
                &empty,
                "https://api.advisory.example/"
            )
        ),
        "Bearer advisory_real_secret"
    );

    // A foreign placeholder: still attached, and the foreign value is stripped rather than carried.
    let foreign = bearer_headers(
        "strands_box_0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert_eq!(
        attached_authorization(
            &store,
            bearer_request(
                dest("api.advisory.example", 443, "/"),
                &foreign,
                "https://api.advisory.example/"
            )
        ),
        "Bearer advisory_real_secret"
    );

    // An off-route destination gets nothing: advisory relaxes the placeholder, never the binding.
    assert!(
        store
            .attach_for(bearer_request(
                dest("api.other.example", 443, "/"),
                &empty,
                "https://api.other.example/"
            ))
            .expect("an unbound destination is not a failure")
            .is_none(),
        "advisory must not widen where the secret may go"
    );

    clear_var("E2E_ADVISORY_TOKEN");
}

/// Two bindings matching one destination fail closed rather than the vault guessing which secret
/// to attach to the host.
#[test]
fn an_ambiguous_binding_fails_closed() {
    set_var("E2E_APEX_TOKEN", "apex_secret");
    set_var("E2E_WILDCARD_TOKEN", "wildcard_secret");

    let opened = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a")
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.ambiguous.example").unwrap(),
                Locator::parse_uri("env://E2E_APEX_TOKEN").unwrap(),
                header("Bearer {}"),
            ))
            .route(RouteSpec::opaque(
                DestinationPattern::parse("*.ambiguous.example").unwrap(),
                Locator::parse_uri("env://E2E_WILDCARD_TOKEN").unwrap(),
                header("Bearer {}"),
            )),
    )
    .expect("both secrets are present, so the open itself succeeds");

    let phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();
    let headers = bearer_headers(&phantom);
    let err = store
        .attach_for(bearer_request(
            dest("api.ambiguous.example", 443, "/"),
            &headers,
            "https://api.ambiguous.example/",
        ))
        .expect_err("two bindings match, so the vault must not choose");
    let message = err.to_string();
    assert!(message.contains("api.ambiguous.example"), "got {message}");
    // The message tells the operator how to fix it.
    assert!(message.contains("narrow the bindings"), "got {message}");

    clear_var("E2E_APEX_TOKEN");
    clear_var("E2E_WILDCARD_TOKEN");
}

/// A secret echoed back by an upstream is redacted out of the response, and the scan happens
/// inside the vault — the caller never holds the plaintext it is scanning for.
#[test]
fn a_leaked_secret_is_redacted_out_of_the_response() {
    set_var("E2E_LEAKBACK_TOKEN", "leaked_real_secret");

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::opaque(
            DestinationPattern::parse("api.echo.example").unwrap(),
            Locator::parse_uri("env://E2E_LEAKBACK_TOKEN").unwrap(),
            header("Bearer {}"),
        ),
    ))
    .unwrap();
    let store = opened.into_vault();

    // A body echoing the secret is scrubbed.
    let body = br#"{"received":"leaked_real_secret"}"#;
    let redactions = store
        .redact_leaks(credentials::Inbound {
            destination: dest("api.echo.example", 443, "/"),
            headers: &[],
            body,
        })
        .expect("the secret leaked, so there is something to redact");
    let scrubbed = String::from_utf8(redactions.body().expect("the body leaked").to_vec()).unwrap();
    assert!(!scrubbed.contains("leaked_real_secret"), "got {scrubbed}");
    assert!(scrubbed.contains("[REDACTED]"), "got {scrubbed}");

    // A header echoing it is redacted through an edit.
    let headers = vec![("X-Echo".to_string(), "leaked_real_secret".to_string())];
    let redactions = store
        .redact_leaks(credentials::Inbound {
            destination: dest("api.echo.example", 443, "/"),
            headers: &headers,
            body: b"",
        })
        .expect("the header leaked");
    let edits: Vec<(&str, &str)> = redactions.set_headers().collect();
    assert_eq!(edits, [("X-Echo", "[REDACTED]")]);

    // A clean response needs nothing.
    assert!(
        store
            .redact_leaks(credentials::Inbound {
                destination: dest("api.echo.example", 443, "/"),
                headers: &[],
                body: br#"{"ok":true}"#,
            })
            .is_none()
    );

    clear_var("E2E_LEAKBACK_TOKEN");
}

/// A `cmd://` route is refused at open, naming the destination.
///
/// Registering it was the fail-open: it loaded clean, nothing dispatched it, and the request went
/// upstream carrying no credential at all — so the upstream's `401` read like the boundary denying the
/// call. An OAuth2 route cannot even be expressed here: no constructor accepts one.
#[test]
fn a_cmd_route_is_refused_at_open() {
    let err = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a").route(RouteSpec::opaque(
            DestinationPattern::parse("api.github.com").unwrap(),
            Locator::parse_uri("cmd://gh auth token").unwrap(),
            header("Bearer {}"),
        )),
    )
    .expect_err("a cmd:// route cannot be captured, so it must not open");

    let message = err.to_string();
    assert!(message.contains("cmd://"), "got {message}");
    assert!(message.contains("api.github.com"), "got {message}");
    // The refusal says what to use instead.
    assert!(message.contains("env://"), "got {message}");
}

/// An `oauth2` route is refused at open, at the seam the box path actually reaches.
///
/// The refusal used to live at `egress-gateway`'s `RouteConfig` seam, whose `map_routes` bridge has
/// **no production caller** — so the machinery, and the test asserting "every credential-bearing
/// route maps through the one refusing seam", protected a path the box never takes. On the box's path
/// the route was refused only incidentally, by the source registry declining an unclaimed scheme. A
/// reviewer checking whether the `oauth2` fail-open was closed found the machinery and stopped.
#[test]
fn an_oauth2_route_is_refused_at_open() {
    let err = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a").route(RouteSpec::opaque(
            DestinationPattern::parse("api.github.com").unwrap(),
            Locator::parse_uri("oauth2://provider/client").unwrap(),
            header("Bearer {}"),
        )),
    )
    .expect_err("an oauth2 route has no mint lifecycle, so it must not open");

    let message = err.to_string();
    assert!(message.contains("oauth2://"), "got {message}");
    assert!(
        message.contains("api.github.com"),
        "the destination is named: {message}"
    );
    assert!(
        message.contains("env://"),
        "the refusal says what to use instead: {message}"
    );
    assert!(
        !err.is_soft(),
        "a deferred-mint scheme is never a soft skip"
    );
}

/// A signed AWS route registers without resolving anything, and mints no phantom.
///
/// Its credentials are fetched per request, because session credentials expire — so a vault can open on
/// a host with no AWS credentials at all, which is what makes this test hermetic. The signing itself is
/// covered by the AWS source's own unit tests against the published `get-vanilla` vector.
#[test]
fn a_signed_aws_route_registers_without_resolving_or_minting() {
    let fields = [("source", "aws"), ("profile", "prod")]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            Locator::structured(fields).unwrap(),
        ),
    ))
    .expect("a signed route resolves nothing at open");

    assert!(
        opened.phantoms().is_empty(),
        "nothing is placed for a signed route, so nothing may be minted to match"
    );
    assert!(opened.skipped().is_empty());
}

/// The `query_param` placement strips the phantom AND sets the real secret.
///
/// **Both halves, deliberately.** Without the strip the phantom and the real secret both egress as
/// duplicate parameters, and which one the upstream honours is server-dependent — so the placeholder
/// the design exists to keep out of the upstream's hands is the thing that reaches it. Only the
/// `Header` placement was ever driven end to end, which is why the phantom-strip mutants survived.
///
/// Measured against the mutants: removing *either* strip alone still passes, and correctly so — the
/// harness-side strip (`swap_phantom`) and the attach-side one name the same parameter and
/// `strip_query_param` dedupes, so when the harness and inject locations agree, either is redundant.
/// Removing *both* fails this test. The property pinned is therefore "the phantom is stripped", not
/// "this particular line runs", which is the property that matters and the only one a shipped
/// configuration can distinguish.
#[test]
fn a_query_param_route_strips_the_phantom_and_sets_the_secret() {
    set_var("E2E_MAPS_KEY", "AIza-real-maps-key");

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::opaque(
            DestinationPattern::parse("maps.googleapis.com").unwrap(),
            Locator::parse_uri("env://E2E_MAPS_KEY").unwrap(),
            InjectMode::query_param("key").unwrap(),
        ),
    ))
    .expect("the query-param route resolves");

    let phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();

    let attachment = store
        .attach_for(Outbound {
            destination: dest("maps.googleapis.com", 443, "/maps/api/geocode/json"),
            method: "GET",
            url: "https://maps.googleapis.com/maps/api/geocode/json",
            query: &format!("address=x&key={phantom}"),
            headers: &[],
            body: b"",
        })
        .expect("the phantom matches its binding")
        .expect("a credential is bound for this destination");

    let stripped: Vec<&str> = attachment.strip_query().collect();
    assert_eq!(stripped, ["key"], "the phantom parameter must be stripped");

    let set: Vec<(&str, &str)> = attachment
        .set_query()
        .map(|(name, value)| (name, value.as_str()))
        .collect();
    assert_eq!(
        set,
        [("key", "AIza-real-maps-key")],
        "the real secret replaces it under the same name"
    );

    // The secret does not also land in a header — a placement attaches in exactly one place.
    assert_eq!(attachment.set_headers().count(), 0);
    assert!(attachment.rewrite_path_to().is_none());

    clear_var("E2E_MAPS_KEY");
}

/// The `basic_auth` placement emits the credential as the password half.
#[test]
fn a_basic_auth_route_emits_the_secret_as_the_password_half() {
    set_var("E2E_TWILIO_TOKEN", "twilio-real-auth-token");

    let opened = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::opaque(
            DestinationPattern::parse("api.twilio.com").unwrap(),
            Locator::parse_uri("env://E2E_TWILIO_TOKEN").unwrap(),
            InjectMode::basic_auth(),
        ),
    ))
    .expect("the basic-auth route resolves");

    let phantom = opened.phantoms()[0].token().to_string();
    let store = opened.into_vault();

    // The harness presents `Basic base64(user:<phantom>)`, as the design's own vocabulary describes.
    let pair = format!("AC-account-sid:{phantom}");
    let encoded = base64_encode(pair.as_bytes());
    let headers = vec![("Authorization".to_string(), format!("Basic {encoded}"))];

    let attachment = store
        .attach_for(Outbound {
            destination: dest("api.twilio.com", 443, "/2010-04-01/Accounts"),
            method: "POST",
            url: "https://api.twilio.com/2010-04-01/Accounts",
            query: "",
            headers: &headers,
            body: b"",
        })
        .expect("the phantom matches its binding")
        .expect("a credential is bound for this destination");

    let set: Vec<(&str, &str)> = attachment
        .set_headers()
        .map(|(name, value)| (name, value.as_str()))
        .collect();
    let (name, value) = set
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
        .expect("basic auth attaches to Authorization");
    assert_eq!(*name, "Authorization");
    assert!(
        value.starts_with("Basic "),
        "the emitted value is a Basic pair: {value}"
    );
    assert!(
        !value.contains(&phantom),
        "the phantom must not survive into the emitted pair: {value}"
    );

    clear_var("E2E_TWILIO_TOKEN");
}

/// Minimal RFC 4648 base64, so this file needs no dependency for the Basic fixture.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A workload's own signing headers are stripped before the boundary signs.
///
/// **The one reachable security guard with no coverage.** `STRIP_SIGNING_HEADERS` is
/// operator-reachable through `aws = true` and workload-triggerable — the gateway hands `attach_for`
/// the workload's headers verbatim — and reducing it to a single entry kept the whole suite green.
/// The signer computes the canonical payload hash itself, so a surviving workload-supplied
/// `X-Amz-Content-Sha256` would be *vouched for by the box's own signature* while contradicting the
/// body the box forwards.
///
/// The plausible regression it guards is specific: someone removes `x-amz-content-sha256` from the
/// strip set because S3 requires that header, not noticing the signer supplies it.
#[test]
fn a_signed_route_strips_the_workloads_own_signing_headers() {
    // The ambient chain must be reachable for the signer to run at all, and no profile may be
    // declared — the shipped provider refuses one it cannot honour.
    set_var("AWS_ACCESS_KEY_ID", "AKIATESTONLYNOTREAL");
    set_var("AWS_SECRET_ACCESS_KEY", "test-only-not-real");
    set_var("AWS_REGION", "us-west-2");

    let fields = [("source", "aws")]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let store = Vault::open(VaultConfig::new(Backend::local(), "tenant-a").route(
        RouteSpec::signed_aws(
            DestinationPattern::parse("*.amazonaws.com").unwrap(),
            Locator::structured(fields).unwrap(),
        ),
    ))
    .expect("a signed route opens against the ambient chain")
    .into_vault();

    // Every artifact a workload could forge, with a value the box must not vouch for.
    let hostile = vec![
        (
            "Authorization".to_string(),
            "AWS4-HMAC-SHA256 Credential=forged".to_string(),
        ),
        ("X-Amz-Date".to_string(), "19700101T000000Z".to_string()),
        (
            "X-Amz-Security-Token".to_string(),
            "forged-token".to_string(),
        ),
        ("X-Amz-Content-Sha256".to_string(), "deadbeef".to_string()),
        (
            "X-Amz-Signature".to_string(),
            "forged-signature".to_string(),
        ),
    ];

    let attachment = store
        .attach_for(Outbound {
            destination: dest("s3.us-west-2.amazonaws.com", 443, "/bucket/key"),
            method: "PUT",
            url: "https://s3.us-west-2.amazonaws.com/bucket/key",
            query: "",
            headers: &hostile,
            body: b"the real body the signature must cover",
        })
        .expect("the signed route attaches")
        .expect("a credential is bound for this destination");

    // (a) All five are stripped, not just `authorization`.
    let stripped: Vec<String> = attachment
        .strip_headers()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    for name in [
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "x-amz-signature",
    ] {
        assert!(
            stripped.iter().any(|s| s == name),
            "{name} must be stripped before signing, got {stripped:?}"
        );
    }

    // (b) No workload-supplied value survives into what the box signs.
    let signed: Vec<(String, String)> = attachment
        .set_headers()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let rendered = format!("{signed:?}");
    for forged in [
        "deadbeef",
        "forged-signature",
        "forged-token",
        "Credential=forged",
        "19700101T000000Z",
    ] {
        assert!(
            !rendered.contains(forged),
            "a workload-supplied {forged:?} must not reach the signature: {rendered}"
        );
    }

    // (c) The boundary's own signature is what goes out.
    let authorization = signed
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
        .map(|(_, value)| value.as_str())
        .expect("a signed route sets Authorization");
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIATESTONLYNOTREAL/"),
        "the box signs with the identity it resolved: {authorization}"
    );

    clear_var("AWS_ACCESS_KEY_ID");
    clear_var("AWS_SECRET_ACCESS_KEY");
    clear_var("AWS_REGION");
}

/// The `Backend::resolve` door: one locator to plaintext, with no destination, tenant, or request.
///
/// This is the ingress front door's whole integration with the crate, and the one place a plaintext
/// legitimately crosses the façade — its consumer converts it to a SHA-256 digest immediately.
#[test]
fn the_backend_door_dereferences_one_locator() {
    set_var("E2E_INGRESS_KEY", "ingress_api_key");

    let secret = Backend::local()
        .resolve(&Locator::parse_uri("env://E2E_INGRESS_KEY").unwrap())
        .expect("a set variable resolves");
    assert_eq!(secret.as_str(), "ingress_api_key");

    // An absent secret is the crate's one soft failure, so a single-secret caller can treat it as fatal
    // while the vault's open path skips that route.
    clear_var("E2E_INGRESS_ABSENT");
    let err = Backend::local()
        .resolve(&Locator::parse_uri("env://E2E_INGRESS_ABSENT").unwrap())
        .expect_err("an unset variable does not resolve");
    assert!(err.is_soft());

    // A structured `aws://` reference is refused rather than downgraded to a string: it resolves to
    // session credentials for signing, not a bearer token.
    let err = Backend::local()
        .resolve(&Locator::parse_uri("aws://prod").unwrap())
        .expect_err("aws:// is structured, not opaque");
    assert!(!err.is_soft(), "a structured reference must fail closed");

    clear_var("E2E_INGRESS_KEY");
}

// ═══════════════════════════════════════════════════════════════════════════════
// An Unusable_Value cannot become a Secret
// (docs/design/decisions.md#an-unusable-secret-value-is-unrepresentable).
// ═══════════════════════════════════════════════════════════════════════════════

/// An empty secret must not open a vault.
///
/// This is the audit's C1, live through two audits. An empty value resolved `Ok`, bound as a
/// credential, reached the wire as `Authorization: Bearer ` with nothing after it, and — because
/// `Redactions::scan` returns `None` for an empty needle — silently disabled that route's
/// leak-back scan for the vault's lifetime. `require_every_route()`, the strictest posture the
/// crate offers, did not catch it: it branches on `is_soft()`, and an empty secret was `Ok`.
#[test]
fn an_empty_secret_is_refused_at_open() {
    set_var("E2E_EMPTY_SECRET", "");

    let err = Vault::open(
        VaultConfig::new(Backend::local(), "tenant-a")
            .route(RouteSpec::opaque(
                DestinationPattern::parse("api.github.com").unwrap(),
                Locator::parse_uri("env://E2E_EMPTY_SECRET").unwrap(),
                header("Bearer {}"),
            ))
            .require_every_route(),
    )
    .expect_err("an empty secret cannot become a credential");

    assert!(
        !err.is_soft(),
        "an unusable value fails closed, never skips"
    );
    let message = err.to_string();
    assert!(
        message.contains("[REDACTED]"),
        "the error names the redacted reference: {message}"
    );

    clear_var("E2E_EMPTY_SECRET");
}

/// Whitespace-only is unusable too, and it is the spelling that reached the wire.
///
/// `box/src/config.rs`'s presence gate was strictly-empty, so `"   "` passed it and produced
/// `Authorization: "Bearer    "`. A credential that is entirely whitespace cannot authenticate
/// anywhere, so accepting it only defers the failure to the upstream's 401 — which an operator
/// reads as the box denying the call.
#[test]
fn a_whitespace_only_secret_is_refused_at_open() {
    for spelling in [" ", "   ", "\n", "\t "] {
        set_var("E2E_WS_SECRET", spelling);

        let err = Vault::open(
            VaultConfig::new(Backend::local(), "tenant-a")
                .route(RouteSpec::opaque(
                    DestinationPattern::parse("api.github.com").unwrap(),
                    Locator::parse_uri("env://E2E_WS_SECRET").unwrap(),
                    header("Bearer {}"),
                ))
                .require_every_route(),
        )
        .expect_err("a whitespace-only secret cannot become a credential");

        assert!(!err.is_soft(), "{spelling:?} must fail closed");
    }

    clear_var("E2E_WS_SECRET");
}

/// A control byte in a secret is refused where the value is owned.
///
/// The wire writer is a hand-rolled string concatenation with no `HeaderValue` type to refuse a
/// control character, so a CRLF that reaches an `Attachment` reaches the socket. No shipped
/// surface delivers one today — this closes the trap rather than an exposure — and the invariant
/// belongs here because only this crate knows the value is a secret it may not echo back.
#[test]
fn a_secret_carrying_a_control_byte_is_refused_at_open() {
    // A NUL is absent from this list because the OS refuses to set an environment variable
    // containing one, so `env://` cannot deliver it — `Secret`'s own unit test covers that byte
    // directly.
    for spelling in [
        "tok\r\nX-Evil: yes",
        "tok\nmore",
        "tok\u{7f}",
        "tok\u{1}more",
    ] {
        set_var("E2E_CTRL_SECRET", spelling);

        let err = Vault::open(
            VaultConfig::new(Backend::local(), "tenant-a")
                .route(RouteSpec::opaque(
                    DestinationPattern::parse("api.github.com").unwrap(),
                    Locator::parse_uri("env://E2E_CTRL_SECRET").unwrap(),
                    header("Bearer {}"),
                ))
                .require_every_route(),
        )
        .expect_err("a control byte cannot ride in a header value");

        assert!(!err.is_soft(), "{spelling:?} must fail closed");
        assert!(
            !err.to_string().contains("X-Evil"),
            "the refusal must not echo the value"
        );
    }

    clear_var("E2E_CTRL_SECRET");
}

/// The same rule holds for a `file://` secret — an empty file and a bare newline.
///
/// `file.rs`'s own test asserts `strip_trailing_newline("\n") == ""`, so a one-byte newline file
/// became a bound credential. That contract is unchanged; what changes is that the stripped
/// result must still be a usable value.
#[test]
fn an_empty_file_secret_is_refused_at_open() {
    let dir = std::env::temp_dir().join(format!("credentials-e2e-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    for (index, contents) in ["", "\n", "  \n"].iter().enumerate() {
        let path = dir.join(format!("token-{index}"));
        let mut file = std::fs::File::create(&path).expect("create secret file");
        file.write_all(contents.as_bytes()).expect("write secret");
        let path = path.display().to_string();

        let err = Vault::open(
            VaultConfig::new(Backend::local(), "tenant-a")
                .route(RouteSpec::opaque(
                    DestinationPattern::parse("api.github.com").unwrap(),
                    Locator::parse_uri(&format!("file://{path}")).unwrap(),
                    header("Bearer {}"),
                ))
                .require_every_route(),
        )
        .expect_err("an empty file cannot become a credential");

        assert!(!err.is_soft(), "{contents:?} must fail closed");
    }
}

/// The narrow door refuses an unusable value too, so the ingress front door — whose
/// whole integration is one `Backend::resolve` — gets the refusal without holding the type.
#[test]
fn the_backend_door_refuses_an_unusable_value() {
    set_var("E2E_DOOR_EMPTY", "");
    let err = Backend::local()
        .resolve(&Locator::parse_uri("env://E2E_DOOR_EMPTY").unwrap())
        .expect_err("an empty value is not a secret");
    assert!(!err.is_soft(), "an unusable value fails closed");

    set_var("E2E_DOOR_WS", "  ");
    let err = Backend::local()
        .resolve(&Locator::parse_uri("env://E2E_DOOR_WS").unwrap())
        .expect_err("a whitespace-only value is not a secret");
    assert!(!err.is_soft());

    clear_var("E2E_DOOR_EMPTY");
    clear_var("E2E_DOOR_WS");
}

// ═══════════════════════════════════════════════════════════════════════════════
// credsd — the whole path through the public API, against a mocked daemon.
//
// A fake credsd daemon speaks the line-delimited JSON-RPC 2.0 protocol over a Unix domain socket.
// The test opens a Vault with a `credsd://` signed route, drives `attach_for`, and asserts a real
// SigV4 signature was produced from the daemon-vended credentials — socket connect, `credential/get`
// request, response parse, AWS delivery adapter, and signer, end to end.
// ═══════════════════════════════════════════════════════════════════════════════

mod credsd_e2e {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::Receiver;
    use std::thread::JoinHandle;

    use credentials::{
        Destination, DestinationPattern, Locator, Outbound, RouteSpec, Vault, VaultConfig,
    };

    const BEDROCK_HOST: &str = "bedrock-runtime.us-west-2.amazonaws.com";

    /// A `session_credentials` response for `credential/get`.
    fn ok_response() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"result":{"credential":"login","material":{"type":"session_credentials","access_key_id":"ASIACREDSDE2E","secret_access_key":"e2eSecretKeyMaterialExample","session_token":"e2eSessionTokenExample"},"expires_at":"2027-01-01T00:00:00Z","provenance":"minted_for_request"}}"#.to_vec()
    }

    /// A per-test socket path under the temp dir, unique across concurrent tests.
    fn socket_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("credsd-e2e-{}-{nonce}.sock", std::process::id()))
    }

    /// A fake daemon that accepts one connection, records the request line, and replies `response`.
    fn fake_daemon(
        path: &std::path::Path,
        response: Vec<u8>,
    ) -> (Receiver<Vec<u8>>, JoinHandle<()>) {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("bind the fake credsd socket");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one connection");
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = Vec::new();
            reader
                .read_until(b'\n', &mut request)
                .expect("read the request line");
            let _ = tx.send(request);
            stream.write_all(&response).expect("write the response");
            stream.flush().expect("flush the response");
        });
        (rx, handle)
    }

    fn bedrock_request<'a>(headers: &'a [(String, String)]) -> Outbound<'a> {
        Outbound {
            destination: Destination {
                host: BEDROCK_HOST,
                port: 443,
                path: "/model/invoke",
            },
            method: "POST",
            url: "https://bedrock-runtime.us-west-2.amazonaws.com/model/invoke",
            query: "",
            headers,
            body: b"{}",
        }
    }

    fn credsd_vault(socket: PathBuf) -> Vault {
        Vault::open(
            VaultConfig::new(credentials::Backend::local(), "tenant-e2e")
                .credsd_socket(socket)
                .route(RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    Locator::parse_uri("credsd://prod-inference").unwrap(),
                ))
                .require_every_route(),
        )
        .expect("a credsd signed route registers at open without touching the daemon")
        .into_vault()
    }

    /// The full credsd path: the daemon receives `credential/get` for the environment, and the box
    /// signs the request with SigV4 from the vended session credentials.
    #[test]
    fn a_credsd_route_signs_with_the_vended_credentials() {
        let path = socket_path();
        let mut response = ok_response();
        response.push(b'\n'); // credsd newline-terminates every response line (protocol v1).
        let (rx, handle) = fake_daemon(path.as_path(), response);

        let vault = credsd_vault(path.clone());
        let attachment = vault
            .attach_for(bedrock_request(&[]))
            .expect("the signed resolve succeeds against the fake daemon")
            .expect("the amazonaws.com destination is bound");

        let authorization = attachment
            .set_headers()
            .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
            .map(|(_, value)| value.to_string())
            .expect("a signed route sets Authorization");
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 "),
            "the credsd route produced a SigV4 signature: {authorization}"
        );
        assert!(
            authorization.contains("/us-west-2/bedrock/aws4_request"),
            "the signing scope derives from the host, not the credential: {authorization}"
        );
        // The vended session token rides as X-Amz-Security-Token.
        assert!(
            attachment
                .set_headers()
                .any(|(name, _)| name.eq_ignore_ascii_case("X-Amz-Security-Token")),
            "a session credential signs a security-token header"
        );
        // The real credential never appears as a header value.
        assert!(
            attachment
                .set_headers()
                .all(|(_, value)| !value.contains("e2eSecretKeyMaterialExample")),
            "the secret access key must never reach a header value"
        );

        // The daemon received exactly `credential/get` for the environment, with no profile, scope,
        // or claim.
        let request = rx.recv().expect("the daemon recorded one request");
        let value: serde_json::Value =
            serde_json::from_slice(request.trim_ascii_end()).expect("one JSON line");
        assert_eq!(value["method"], "credential/get");
        assert_eq!(value["params"]["environment"], "prod-inference");
        assert!(value["params"].get("profile").is_none());
        assert!(value["params"].get("scope").is_none());
        assert!(value["params"].get("claim").is_none());

        handle.join().expect("the daemon thread joins");
        let _ = std::fs::remove_file(&path);
    }

    /// A relative credsd socket is refused when the vault opens, naming the path.
    #[test]
    fn a_relative_credsd_socket_is_refused_at_open() {
        let error = Vault::open(
            VaultConfig::new(credentials::Backend::local(), "t")
                .credsd_socket("relative/credsd.sock")
                .route(RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    Locator::parse_uri("credsd://dev").unwrap(),
                )),
        )
        .expect_err("a relative socket path is a configuration error at open");
        assert!(!error.is_soft(), "a config refusal is hard");
        assert!(
            error.to_string().contains("relative/credsd.sock"),
            "the refusal names the path: {error}"
        );
    }

    /// An unreachable socket fails the per-request resolve, and the open still succeeds — a
    /// signed route resolves nothing at open.
    #[test]
    fn an_unreachable_credsd_socket_fails_the_request_not_the_open() {
        let path = socket_path(); // never bound
        let vault = credsd_vault(path);
        let error = vault
            .attach_for(bedrock_request(&[]))
            .expect_err("the socket is unreachable, so the resolve fails");
        assert!(!error.is_soft(), "an unreachable credsd is a hard failure");
        assert!(
            error.to_string().contains("prod-inference"),
            "the failure names the environment: {error}"
        );
    }

    /// A vault with no `credsd://` route never resolves the socket — the credsd machinery is
    /// inert when unused, so even a relative configured socket is ignored and the open succeeds.
    #[test]
    fn a_vault_with_no_credsd_route_ignores_the_socket() {
        super::set_var("E2E_BACKCOMPAT_TOKEN", "ghp_real");
        let opened = Vault::open(
            VaultConfig::new(credentials::Backend::local(), "t")
                .credsd_socket("relative/would-refuse-if-resolved.sock")
                .route(RouteSpec::opaque(
                    DestinationPattern::parse("api.github.com").unwrap(),
                    Locator::parse_uri("env://E2E_BACKCOMPAT_TOKEN").unwrap(),
                    credentials::InjectMode::header("Bearer {}".to_string(), None).unwrap(),
                )),
        )
        .expect("a vault with no credsd route opens regardless of the credsd socket");
        assert!(opened.skipped().is_empty());
        super::clear_var("E2E_BACKCOMPAT_TOKEN");
    }

    /// A live smoke test against the real daemon at the platform default socket, when present. It
    /// asserts the transport and error mapping interoperate with the shipped daemon: a nonexistent
    /// environment is a hard failure, never a hang or a panic. Skips when the socket is absent, per
    /// the crate's skip-don't-fail convention.
    #[test]
    fn a_live_daemon_maps_an_unknown_environment_to_a_hard_failure() {
        // The same resolution the client uses: CREDSD_SOCKET if set, else the platform default
        // (macOS /var/run, Linux /run), so this runs against the real daemon on either OS.
        let socket = std::env::var_os("CREDSD_SOCKET")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if cfg!(target_os = "macos") {
                    PathBuf::from("/var/run/credsd/credsd.sock")
                } else {
                    PathBuf::from("/run/credsd/credsd.sock")
                }
            });
        if !socket.exists() {
            eprintln!("skipping: no credsd daemon at {}", socket.display());
            return;
        }
        // An environment no daemon is enrolled for, so the only live outcome is a hard
        // ENVIRONMENT_NOT_FOUND. `credsd_vault` hard-wires `prod-inference`, which a host enrolled
        // for it would sign — minting real credentials during a unit-test run — so this route names
        // a unique nonexistent environment and the test never accepts a success.
        let environment = format!("strands-e2e-nonexistent-{}", std::process::id());
        let vault = Vault::open(
            VaultConfig::new(credentials::Backend::local(), "tenant-e2e")
                .credsd_socket(socket)
                .route(RouteSpec::signed_aws(
                    DestinationPattern::parse("*.amazonaws.com").unwrap(),
                    Locator::parse_uri(&format!("credsd://{environment}")).unwrap(),
                ))
                .require_every_route(),
        )
        .expect("a credsd signed route registers at open without touching the daemon")
        .into_vault();
        // The round-trip reaches the real daemon and comes back a hard failure, never a hang, a
        // panic, or a soft miss.
        let error = vault
            .attach_for(bedrock_request(&[]))
            .expect_err("an environment no daemon is enrolled for must fail");
        assert!(
            !error.is_soft(),
            "a live credsd failure must be hard, got a soft miss: {error}"
        );
    }
}
