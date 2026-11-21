//! The `@box/bedrock` and `@box/bedrock-mantle` packs: how the box signs in to Bedrock.

use crate::support::*;

/// Each agent and the Bedrock pack it uses, and the host that pack routes.
const AGENTS: [(&str, &str, &str); 3] = [
    (
        "claude",
        "bedrock",
        "bedrock-runtime.us-west-2.amazonaws.com",
    ),
    (
        "codex",
        "bedrock",
        "bedrock-runtime.us-west-2.amazonaws.com",
    ),
    (
        "codex",
        "bedrock-mantle",
        "bedrock-mantle.us-west-2.api.aws",
    ),
];

fn egress(host: &FakeHost, agent: &str, pack: &str, auth: Option<&str>) -> toml::Table {
    let mut trial = host.trial().with(agent).with(pack);
    if agent == "codex" && pack == "bedrock" {
        trial = trial.option("codex.host", "amazon-bedrock-runtime");
    }
    if let Some(auth) = auth {
        trial = trial.option("bedrock.sign-in", auth);
    }
    let generated = trial.generate().expect("a configuration");
    let file: toml::Table = toml::from_str(generated.box_toml()).expect("TOML");
    file["egress"].as_table().expect("egress").clone()
}

#[test]
fn bedrock_signs_with_the_default_aws_identity_unless_the_profile_picks_a_key() {
    let host = FakeHost::new();
    for (agent, pack, endpoint) in AGENTS {
        let signed = egress(&host, agent, pack, None);
        assert_eq!(
            signed["bedrock"]["secret"]["ref"].as_str(),
            Some("aws://"),
            "{agent} {pack}: {signed:?}"
        );
        assert_eq!(strings(&signed["bedrock"]["destinations"]), [endpoint]);
        assert!(!signed.contains_key("bedrock-api-key"), "{signed:?}");
        assert_eq!(egress(&host, agent, pack, Some("aws")), signed);

        let keyed = egress(&host, agent, pack, Some("api-key"));
        assert_eq!(
            keyed["bedrock-api-key"]["secret"]["ref"].as_str(),
            Some("env://AWS_BEARER_TOKEN_BEDROCK"),
            "{agent} {pack}: {keyed:?}"
        );
        assert_eq!(
            strings(&keyed["bedrock-api-key"]["destinations"]),
            [endpoint]
        );
        assert!(!keyed.contains_key("bedrock"), "{keyed:?}");
    }
}

#[test]
fn the_next_steps_ask_for_a_key_only_when_the_profile_picks_one() {
    let host = FakeHost::new();
    for (agent, pack, endpoint) in AGENTS {
        let steps = |auth: Option<&str>| {
            let mut profile = host.profile().with(agent).with(pack).force(true);
            if agent == "codex" && pack == "bedrock" {
                profile = profile.option("codex.host", "amazon-bedrock-runtime");
            }
            if let Some(auth) = auth {
                profile = profile.option("bedrock.sign-in", auth);
            }
            profile.create().expect("a profile").next_steps(false)
        };
        let signed = steps(None);
        assert!(!signed.contains("AWS_BEARER_TOKEN_BEDROCK"), "{signed}");
        assert!(
            signed.contains("The bedrock route signs with your default AWS identity."),
            "{signed}"
        );
        let keyed = steps(Some("api-key"));
        assert!(
            keyed.contains(&format!(
                "Put the key for {endpoint} in AWS_BEARER_TOKEN_BEDROCK."
            )),
            "{keyed}"
        );
    }
}

#[test]
fn a_new_bedrock_profile_saves_its_sign_in_so_a_later_default_does_not_move_it() {
    let host = FakeHost::new();
    for (agent, pack, _) in AGENTS {
        let mut profile = host.profile().with(agent).with(pack).force(true);
        if agent == "codex" && pack == "bedrock" {
            profile = profile.option("codex.host", "amazon-bedrock-runtime");
        }
        let created = profile
            .policy("open")
            .answer(None)
            .expect("answers without a terminal")
            .create()
            .expect("a profile");
        let file: toml::Table = toml::from_str(created.text()).expect("TOML");
        assert_eq!(
            file["options"]["bedrock"]["sign-in"].as_str(),
            Some("aws"),
            "{agent} {pack}: {}",
            created.text()
        );
    }
}
