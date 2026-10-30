//! A `net:connect` outcome records the destination address a rule reads, in the spelling the
//! request leg records.

mod support;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use policy::{GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

/// The host every leg of these tests names.
const HOST: &str = "api.example.test";

/// The address each probe rule names, as a rule spells it.
const ADDRESS: &str = "203.0.113.7";

/// The probe port whose `forbid` fires once history holds a `net:connect::request` on `ADDRESS`.
const AFTER_REQUEST: u16 = 9001;

/// The probe port whose `forbid` fires once history holds a `net:connect::response` on `ADDRESS`.
const AFTER_RESPONSE: u16 = 9002;

/// The probe port whose `forbid` fires once history holds a `net:connect::error` on `ADDRESS`.
const AFTER_ERROR: u16 = 9003;

/// One probe per event kind. A probe connect pins no address, so it writes no `ip` of its own
/// and only the recorded attempt can satisfy a predicate.
fn probed_policy() -> PolicyEngine {
    let mut source = String::from(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#,
    );
    for (kind, port) in [
        ("request", AFTER_REQUEST),
        ("response", AFTER_RESPONSE),
        ("error", AFTER_ERROR),
    ] {
        source.push_str(&format!(
            r#"
@id("after-{kind}")
forbid(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource)
when {{ context.input.port == {port} }}
when temporal {{
    formerly within 3600s (
        Box::Action::"net:connect"::{kind}{{ input.ip: "{ADDRESS}" }}
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

fn address() -> IpAddr {
    ADDRESS.parse().expect("an address")
}

#[test]
fn a_connect_that_opened_records_the_address_a_rule_reads() {
    let policy = probed_policy();

    assert!(
        probe(&policy, AFTER_RESPONSE),
        "nothing is in history yet, so the probe is permitted"
    );
    record(&policy, address(), true);
    assert!(
        !probe(&policy, AFTER_RESPONSE),
        "a rule keyed on `input.ip` must see the address the response leg records"
    );
}

#[test]
fn a_connect_that_did_not_open_records_the_address_on_its_error_leg() {
    let policy = probed_policy();

    assert!(probe(&policy, AFTER_ERROR), "nothing is in history yet");
    record(&policy, address(), false);
    assert!(
        !probe(&policy, AFTER_ERROR),
        "a rule keyed on `input.ip` must see the address the error leg records"
    );
}

#[test]
fn the_request_and_the_outcome_record_one_spelling_of_one_address() {
    // Both legs fold an address to one spelling, so one rule literal reads an IPv6 encoding of
    // an IPv4 address on either leg.
    let policy = probed_policy();
    let encoded: IpAddr = "::ffff:203.0.113.7".parse().expect("an address");

    assert!(probe(&policy, AFTER_REQUEST), "nothing is in history yet");
    assert!(
        policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Connect {
                    host: HOST,
                    ip: Some(encoded),
                    port: 443,
                },
            )
            .is_allow(),
        "the permit grants the attempt"
    );
    assert!(
        !probe(&policy, AFTER_REQUEST),
        "the request leg records the folded spelling"
    );

    assert!(
        probe(&policy, AFTER_RESPONSE),
        "no outcome is in history yet"
    );
    record(&policy, encoded, true);
    assert!(
        !probe(&policy, AFTER_RESPONSE),
        "and the outcome leg records the same spelling of the same address"
    );
}
