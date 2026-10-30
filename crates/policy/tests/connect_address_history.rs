//! A `net:connect` outcome records each destination-address attribute a rule reads, in the
//! spelling the request leg records.

mod support;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use policy::{GovernedBox, Outcome, Policy, PolicyEngine, Principal, Request};

/// The host every leg of these tests names.
const HOST: &str = "api.example.test";

/// The IPv4 address an `ip4` probe rule names, as a rule spells it.
const ADDRESS: &str = "203.0.113.7";

/// The IPv6 wire form an `ip6` probe rule names, which wraps [`ADDRESS`].
const WIRE_FORM: &str = "::ffff:203.0.113.7";

/// Each probe: the attribute it reads, the literal it names, the event kind that satisfies it,
/// and the port whose `forbid` then fires.
const PROBES: [(&str, &str, &str, u16); 6] = [
    ("ip4", ADDRESS, "request", 9001),
    ("ip4", ADDRESS, "response", 9002),
    ("ip4", ADDRESS, "error", 9003),
    ("ip6", WIRE_FORM, "request", 9004),
    ("ip6", WIRE_FORM, "response", 9005),
    ("ip6", WIRE_FORM, "error", 9006),
];

/// The port of the probe on `attribute` that one `kind` event satisfies.
fn port_of(attribute: &str, kind: &str) -> u16 {
    PROBES
        .iter()
        .find(|(probed, _, probed_kind, _)| *probed == attribute && *probed_kind == kind)
        .map(|(_, _, _, port)| *port)
        .expect("a declared probe")
}

/// One probe per attribute and event kind. A probe connect pins no address, so it writes neither
/// address attribute of its own and only the recorded attempt can satisfy a predicate.
fn probed_policy() -> PolicyEngine {
    let mut source = String::from(
        r#"permit(principal == Box::Agent::"self", action == Box::Action::"net:connect", resource);
"#,
    );
    for (attribute, literal, kind, port) in PROBES {
        source.push_str(&format!(
            r#"
@id("after-{kind}-on-{attribute}")
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

fn wire_form() -> IpAddr {
    WIRE_FORM.parse().expect("an address")
}

/// The response leg carries both attributes, so a rule on either family sees the address it
/// records.
#[test]
fn a_connect_that_opened_records_both_attributes_a_rule_reads() {
    let policy = probed_policy();

    for attribute in ["ip4", "ip6"] {
        assert!(
            probe(&policy, port_of(attribute, "response")),
            "nothing is in history yet, so the {attribute} probe is permitted"
        );
    }
    record(&policy, wire_form(), true);
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(attribute, "response")),
            "a rule keyed on input.{attribute} must see what the response leg records"
        );
    }
}

/// The error leg carries both attributes on the same terms as the response leg.
#[test]
fn a_connect_that_did_not_open_records_both_attributes_on_its_error_leg() {
    let policy = probed_policy();

    for attribute in ["ip4", "ip6"] {
        assert!(
            probe(&policy, port_of(attribute, "error")),
            "nothing is in history yet"
        );
    }
    record(&policy, wire_form(), false);
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(attribute, "error")),
            "a rule keyed on input.{attribute} must see what the error leg records"
        );
    }
}

/// The request leg and the outcome leg write the same two spellings of one destination: the IPv4
/// address it carries, and the IPv6 form it arrived as.
#[test]
fn the_request_and_the_outcome_record_the_same_two_spellings() {
    let policy = probed_policy();

    for attribute in ["ip4", "ip6"] {
        assert!(
            probe(&policy, port_of(attribute, "request")),
            "nothing is in history yet"
        );
    }
    assert!(
        policy
            .decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Connect {
                    host: HOST,
                    ip: Some(wire_form()),
                    port: 443,
                },
            )
            .is_allow(),
        "the permit grants the attempt"
    );
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(attribute, "request")),
            "the request leg records input.{attribute}"
        );
    }

    for attribute in ["ip4", "ip6"] {
        assert!(
            probe(&policy, port_of(attribute, "response")),
            "no outcome is in history yet"
        );
    }
    record(&policy, wire_form(), true);
    for attribute in ["ip4", "ip6"] {
        assert!(
            !probe(&policy, port_of(attribute, "response")),
            "and the outcome leg records the same input.{attribute}"
        );
    }
}
