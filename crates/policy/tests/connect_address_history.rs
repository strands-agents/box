//! A `net:connect` outcome records each destination address attribute a rule reads, in the
//! spellings the request leg records.

mod support;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use policy::{GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

/// The host every leg of these tests names.
const HOST: &str = "api.example.test";

/// The IPv4 address each probe rule names, as a rule spells it.
const ADDRESS: &str = "203.0.113.7";

/// The NAT64 wire form that carries `ADDRESS`, as a rule spells it.
const WIRE: &str = "64:ff9b::cb00:7107";

/// The IPv4-mapped spelling of `ADDRESS` — the one IPv6 form a synthesising implementation would
/// invent for a plain IPv4 destination. Nothing records it.
const MAPPED: &str = "::ffff:203.0.113.7";

/// One probe per event kind and per address attribute. A probe connect pins no address, so it
/// writes no `ip4` and no `ip6` of its own and only the recorded attempt can satisfy a predicate.
fn probed_policy() -> PolicyEngine {
    let mut source = String::from(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#,
    );
    for (label, kind, attribute, literal, port) in probes() {
        source.push_str(&format!(
            r#"
@id("after-{label}")
forbid(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.port == {port} }}
when temporal {{
    formerly within 3600s (
        Box::Action::"net:connect"::{kind}{{ input.{attribute}: "{literal}" }}
    )
}};
"#
        ));
    }
    support::open_policy(vec![Policy {
        origin: PathBuf::from("connect-address-history.dw"),
        text: source,
    }])
    .expect("the probes load")
}

/// Each probe: its label, the event kind it watches, the attribute it reads, the spelling it
/// names, and the port that carries it. Both outcome legs are probed on both attributes, because
/// a rule on one family must not see only the request leg. `mapped-response` names the one value a
/// synthesised IPv6 form would take, so it stays permitted only while nothing synthesises one.
fn probes() -> [(&'static str, &'static str, &'static str, &'static str, u16); 7] {
    [
        ("request-ip4", "request", "ip4", ADDRESS, 9001),
        ("request-ip6", "request", "ip6", WIRE, 9002),
        ("response-ip4", "response", "ip4", ADDRESS, 9003),
        ("response-ip6", "response", "ip6", WIRE, 9004),
        ("error-ip4", "error", "ip4", ADDRESS, 9005),
        ("error-ip6", "error", "ip6", WIRE, 9006),
        ("mapped-response", "response", "ip6", MAPPED, 9007),
    ]
}

/// The port of the probe `label` names.
fn port_of(label: &str) -> u16 {
    probes()
        .into_iter()
        .find(|(probe_label, ..)| *probe_label == label)
        .map(|(.., port)| port)
        .expect("a probe with that label")
}

/// Whether the probe on `port` is still permitted.
fn probe(policy: &PolicyEngine, port: u16) -> bool {
    policy
        .decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::Connect {
                host: HOST,
                ip: None,
                port,
            },
        )
        .is_allow()
}

fn record(policy: &PolicyEngine, address: IpAddr, connected: bool) {
    policy
        .record(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Outcome::Connect {
                host: HOST,
                port: 443,
                address: SocketAddr::new(address, 443),
                connected,
            },
        )
        .expect("the outcome records");
}

fn wire() -> IpAddr {
    WIRE.parse().expect("an address")
}

/// A plain IPv4 destination carries `ip4` alone, on every leg.
#[test]
fn a_plain_ipv4_outcome_records_the_ipv4_attribute_and_no_ipv6_form() {
    let policy = probed_policy();
    let address: IpAddr = ADDRESS.parse().expect("an address");

    assert!(probe(&policy, port_of("response-ip4")));
    assert!(probe(&policy, port_of("mapped-response")));
    record(&policy, address, true);
    assert!(
        !probe(&policy, port_of("response-ip4")),
        "a rule keyed on `input.ip4` must see the address the response leg records"
    );
    assert!(
        probe(&policy, port_of("mapped-response")),
        "an IPv4 destination has no IPv6 wire form, so the leg records no `input.ip6` — not even \
         the IPv4-mapped spelling of the same address"
    );
}

/// The response leg carries both attributes of a wrapped address, as the request leg does.
#[test]
fn a_connect_that_opened_records_both_address_attributes() {
    let policy = probed_policy();

    assert!(probe(&policy, port_of("response-ip4")));
    assert!(probe(&policy, port_of("response-ip6")));
    record(&policy, wire(), true);
    assert!(
        !probe(&policy, port_of("response-ip4")),
        "a rule keyed on `input.ip4` must see the carried address the response leg records"
    );
    assert!(
        !probe(&policy, port_of("response-ip6")),
        "a rule keyed on `input.ip6` must see the wire form the response leg records"
    );
}

/// The error leg carries both attributes too, so a failed connect is not a blind spot.
#[test]
fn a_connect_that_did_not_open_records_both_address_attributes_on_its_error_leg() {
    let policy = probed_policy();

    assert!(probe(&policy, port_of("error-ip4")));
    assert!(probe(&policy, port_of("error-ip6")));
    record(&policy, wire(), false);
    assert!(
        !probe(&policy, port_of("error-ip4")),
        "a rule keyed on `input.ip4` must see the carried address the error leg records"
    );
    assert!(
        !probe(&policy, port_of("error-ip6")),
        "a rule keyed on `input.ip6` must see the wire form the error leg records"
    );
}

/// One wrapped address reaches both attributes on the request leg and on the outcome leg, so a
/// rule of either family reads the same destination on both.
#[test]
fn the_request_and_the_outcome_record_one_set_of_attributes() {
    let policy = probed_policy();

    for attribute in ["ip4", "ip6"] {
        assert!(probe(&policy, port_of(&format!("request-{attribute}"))));
    }
    assert!(
        policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Connect {
                    host: HOST,
                    ip: Some(wire()),
                    port: 443,
                },
            )
            .is_allow(),
        "the permit grants the attempt"
    );
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(&format!("request-{attribute}"))),
            "the request leg records `input.{attribute}`"
        );
    }

    for attribute in ["ip4", "ip6"] {
        assert!(probe(&policy, port_of(&format!("response-{attribute}"))));
    }
    record(&policy, wire(), true);
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(&format!("response-{attribute}"))),
            "and the outcome leg records the same `input.{attribute}`"
        );
    }
}
