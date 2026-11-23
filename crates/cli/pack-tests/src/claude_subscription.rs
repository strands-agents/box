use crate::support::*;

/// The one host that a setup token reaches.
const SUBSCRIPTION_HOST: [&str; 1] = ["api.anthropic.com"];

#[test]
fn a_claude_subscription_puts_its_setup_token_on_every_request_to_anthropics_host_alone() {
    let host = FakeHost::new();
    let generated = host
        .trial()
        .with("claude")
        .with("claude-subscription")
        .option("claude.host", "anthropic")
        .generate()
        .expect("a configuration");
    let file: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
    let route = &file["egress"]["anthropic-subscription"];
    assert_eq!(
        strings(&route["destinations"]),
        SUBSCRIPTION_HOST,
        "the token goes to Anthropic's host and nowhere else"
    );
    assert_eq!(
        route["secret"]["inject"].as_str(),
        Some("always"),
        "WebFetch's check and telemetry send no stand-in, and phantom would refuse them"
    );
    assert_eq!(
        route["secret"]["ref"].as_str(),
        Some("env://CLAUDE_CODE_OAUTH_TOKEN")
    );
    assert_eq!(
        route["secret"]["phantom_prefix"].as_str(),
        Some("sk-ant-oat01-")
    );
}

#[test]
fn a_claude_subscription_profile_passes_box_cores_check_and_one_that_also_lists_the_api_pack_does_not()
 {
    let host = FakeHost::new();
    host.profile()
        .with("claude")
        .with("claude-subscription")
        .option("claude.host", "anthropic")
        .create()
        .expect("a profile")
        .write(false)
        .expect("a write");
    let launch = host
        .launcher()
        .prepare("claude", &host.project(), None)
        .expect("Box Core accepts the subscription profile");
    let file: toml::Value =
        toml::from_str(&std::fs::read_to_string(launch.config()).expect("box.toml")).expect("TOML");
    assert_eq!(
        strings(&file["egress"]["anthropic-subscription"]["destinations"]),
        SUBSCRIPTION_HOST
    );
    let path = profiles_root(&host.home().join(".strands/box")).join("claude/profile.toml");
    let saved = std::fs::read_to_string(&path).expect("the profile");
    let both = saved.replacen(
        "\"@box/claude-subscription\"",
        "\"@box/claude-subscription\", \"@box/anthropic\"",
        1,
    );
    assert!(both.contains("@box/anthropic"), "{saved}");
    std::fs::write(&path, both).expect("the profile with both packs");
    let error = host
        .launcher()
        .prepare("claude", &host.project(), None)
        .expect_err("two routes on api.anthropic.com");
    assert!(
        format!("{error:?}").contains("`anthropic-subscription` overlaps `anthropic`"),
        "{error:?}"
    );
}
