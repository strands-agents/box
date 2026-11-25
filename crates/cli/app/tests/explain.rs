use std::process::{Command, Output};

fn explain(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_box"))
        .arg("explain")
        .args(args)
        .env_clear()
        .env("BOX_HOME", "relative")
        .current_dir(home.path())
        .output()
        .unwrap()
}

fn tagged(path: &str) -> String {
    format!(
        "https://github.com/strands-agents/box/blob/v{}/docs/user/{path}",
        env!("CARGO_PKG_VERSION")
    )
}

#[test]
fn a_code_prints_its_meaning_what_to_do_and_its_block_without_a_box_home() {
    for code in ["B0102", "b0102"] {
        let output = explain(&[code]);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            text,
            format!(
                "B0102: strands-box error\n\n\
                 A filesystem grant is refused, so the box did not start.\n\n\
                 What to do:\n  \
                 Correct the entry that the text names. See what is refused\n  \
                 ({}).\n\n\
                 More: {}\n",
                tagged("config.md#what-is-refused"),
                tagged("message-codes.md#b01"),
            ),
        );
    }
}

#[test]
fn json_keeps_what_to_do_as_markdown_with_absolute_links() {
    let output = explain(&["P0201", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "code": "P0201",
            "source": "policy",
            "severity": "warning",
            "meaning": "A rule errored while it decided a request, so the request was denied.",
            "what_to_do": format!(
                "Read the reason in the text, and correct the rule. The agent receives the denial \
                 `because the request could not be evaluated.`, as [how a denial reads]({}) describes.",
                tagged("policy.md#how-a-denial-reads"),
            ),
            "docs": tagged("message-codes.md#p02"),
        }),
    );
}

#[test]
fn a_malformed_code_is_a_usage_error() {
    for malformed in ["foo", "P02", "P02011", "P02x1", "00201"] {
        let output = explain(&[malformed]);
        assert_eq!(output.status.code(), Some(2), "{malformed}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.starts_with(&format!(
                "box: error: invalid value '{malformed}' for '<CODE>': \
                 a code is a letter and four digits, such as P0201\n"
            )),
            "{malformed}: {error}"
        );
    }
}

#[test]
fn an_unknown_code_names_this_box_and_the_page() {
    let output = explain(&["p0999"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error = String::from_utf8(output.stderr.clone()).unwrap();
    let error = error.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        error.contains(&format!(
            "box: error: P0999 is not a message code that box {} knows. A newer box may know it; \
             see: https://github.com/strands-agents/box/blob/main/docs/user/message-codes.md",
            env!("CARGO_PKG_VERSION")
        )),
        "{error}"
    );
    let raw = String::from_utf8(output.stderr).unwrap();
    assert!(
        raw.lines().any(|line| line.trim()
            == "https://github.com/strands-agents/box/blob/main/docs/user/message-codes.md"),
        "the URL stays whole on its own line: {raw}"
    );
}
