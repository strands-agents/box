//! `strands_box::check_workload_env` judges an `env` entry as a box judges it when it loads
//! `box.toml`.

use strands_box::{EnvRefusal, check_workload_env};

fn kind(name: &str, value: &str) -> Option<EnvRefusal> {
    check_workload_env(name, value)
        .err()
        .map(|refused| refused.kind())
}

/// Load a `box.toml` whose `table` sets `name` to `value`, and return the load's refusal.
fn load_refusal(table: &str, name: &str, value: &str) -> Option<String> {
    let directory = tempfile::tempdir().expect("a directory");
    let config = directory.path().join("box.toml");
    let body = match table {
        "agent" => "[agent]\ncommand = [\"/bin/sh\"]\n[agent.env]\n".to_string(),
        _ => format!(
            "[mcp.{table}]\ntype = \"stdio\"\ncommand = [\"mcp-server\"]\n[mcp.{table}.env]\n"
        ),
    };
    std::fs::write(
        &config,
        format!(
            "name = \"check\"\nbox_dir = \"{}\"\n{body}{name:?} = {value:?}\n",
            directory.path().join("box").display()
        ),
    )
    .expect("write box.toml");
    strands_box::check_policy(config)
        .err()
        .map(|failed| failed.to_string())
}

const SET_BY_BOX: [&str; 11] = [
    "HTTPS_PROXY",
    "http_proxy",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "AWS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_A_SIGNAL_NOT_INVENTED_YET",
    "PWD",
    "USER",
];

const LOADS_CODE: [&str; 16] = [
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "RUBYOPT",
    "PERL5LIB",
    "PERL5OPT",
    "GEM_PATH",
    "CLASSPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
];

const INVALID: [&str; 4] = ["", "1ABC", "A-B", "A B"];

const ACCEPTED: [(&str, &str); 7] = [
    ("HOME", "/Users/operator"),
    ("TMPDIR", "/tmp"),
    ("PATH", "relative:/usr/bin"),
    ("TERM", "xterm-256color"),
    ("OTEL_SERVICE_NAME", "agent"),
    ("GITHUB_TOKEN", "x"),
    ("_PRIVATE", "x"),
];

#[test]
fn a_name_the_box_sets_itself_is_refused_as_set_by_the_box() {
    for name in SET_BY_BOX {
        assert_eq!(kind(name, "x"), Some(EnvRefusal::SetByBox), "{name}");
    }
}

#[test]
fn a_name_that_makes_a_runtime_load_code_is_refused_as_loading_code() {
    for name in LOADS_CODE {
        assert_eq!(kind(name, "x"), Some(EnvRefusal::LoadsCode), "{name}");
    }
}

#[test]
fn a_name_that_is_not_a_variable_name_is_refused_as_invalid() {
    for name in INVALID {
        assert_eq!(kind(name, "x"), Some(EnvRefusal::InvalidName), "{name:?}");
    }
}

#[test]
fn a_relative_home_or_tmpdir_is_refused_and_a_relative_path_is_not() {
    for name in ["HOME", "TMPDIR"] {
        for value in ["relative", "", "~/x"] {
            assert_eq!(
                kind(name, value),
                Some(EnvRefusal::NotAbsolute),
                "{name}={value:?}"
            );
        }
    }
    assert_eq!(kind("PATH", "relative"), None);
    assert_eq!(kind("WORKDIR", "relative"), None);
}

#[test]
fn an_operator_name_with_an_ordinary_value_passes() {
    for (name, value) in ACCEPTED {
        assert_eq!(kind(name, value), None, "{name}={value:?}");
    }
}

#[test]
fn the_check_and_a_box_load_refuse_the_same_entries_with_the_same_reason() {
    let mut refused: Vec<(&str, &str)> = SET_BY_BOX
        .iter()
        .chain(LOADS_CODE.iter())
        .map(|name| (*name, "x"))
        .collect();
    refused.extend([
        ("1ABC", "x"),
        ("A-B", "x"),
        ("HOME", "relative"),
        ("TMPDIR", ""),
    ]);
    for table in ["agent", "server"] {
        for (name, value) in &refused {
            let reason = check_workload_env(name, value)
                .expect_err("the check refuses it")
                .to_string();
            let load = load_refusal(table, name, value).expect("a box load refuses it");
            assert!(
                load.contains(&reason),
                "[{table}] {name}: {load} / {reason}"
            );
        }
        for (name, value) in ACCEPTED {
            assert_eq!(
                load_refusal(table, name, value),
                None,
                "[{table}] {name}={value:?}"
            );
        }
    }
}
