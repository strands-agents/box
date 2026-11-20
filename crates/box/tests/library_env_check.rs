//! `strands_box::check_workload_env` judges an `env` entry as a box judges it when it loads
//! `box.toml`.

use strands_box::{EnvRefusal, ReservedEnv, check_workload_env, reserved_env};

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

const LOADS_CODE: [&str; 5] = [
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "LD_BIND_NOW",
];

const RUNTIME_OPTIONS: [&str; 14] = [
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONUNBUFFERED",
    "PYTHONIOENCODING",
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
fn a_name_the_dynamic_loader_reads_is_refused_as_loading_code() {
    for name in LOADS_CODE {
        assert_eq!(kind(name, "x"), Some(EnvRefusal::LoadsCode), "{name}");
    }
}

#[test]
fn a_runtime_option_variable_passes() {
    for name in RUNTIME_OPTIONS {
        assert_eq!(kind(name, "x"), None, "{name}");
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
        for name in RUNTIME_OPTIONS {
            assert_eq!(
                load_refusal(table, name, "x"),
                None,
                "[{table}] {name} must load"
            );
        }
    }
}

const GATEWAY_PROXY: [&str; 7] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
];

const GATEWAY_CA_FILE: [&str; 6] = [
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "CODEX_CA_CERTIFICATE",
    "AWS_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

#[test]
fn reserved_env_names_the_kind_of_each_reserved_name() {
    for name in GATEWAY_PROXY {
        assert_eq!(
            reserved_env(name),
            Some(ReservedEnv::GatewayProxy),
            "{name}"
        );
    }
    for name in GATEWAY_CA_FILE {
        assert_eq!(
            reserved_env(name),
            Some(ReservedEnv::GatewayCaFile),
            "{name}"
        );
    }
    for name in ["PWD", "USER", "OTEL_EXPORTER_OTLP_ENDPOINT"] {
        assert_eq!(reserved_env(name), Some(ReservedEnv::SetByBox), "{name}");
    }
    for name in LOADS_CODE.iter().chain(RUNTIME_OPTIONS.iter()) {
        assert_eq!(reserved_env(name), Some(ReservedEnv::LoadsCode), "{name}");
    }
    for (name, _) in ACCEPTED {
        assert_eq!(reserved_env(name), None, "{name}");
    }
}

#[test]
fn reserved_env_agrees_with_the_env_check() {
    for name in SET_BY_BOX.iter().chain(GATEWAY_PROXY.iter()) {
        assert!(
            matches!(
                reserved_env(name),
                Some(
                    ReservedEnv::GatewayProxy | ReservedEnv::GatewayCaFile | ReservedEnv::SetByBox
                )
            ),
            "{name}"
        );
        assert_eq!(kind(name, "x"), Some(EnvRefusal::SetByBox), "{name}");
    }
    for name in GATEWAY_CA_FILE {
        assert_eq!(kind(name, "x"), Some(EnvRefusal::SetByBox), "{name}");
    }
}

/// Load a `box.toml` whose stdio server has `contain_egress = false` and sets `name` to `value`.
fn native_egress_load_refusal(name: &str, value: &str) -> Option<String> {
    let directory = tempfile::tempdir().expect("a directory");
    let config = directory.path().join("box.toml");
    std::fs::write(
        &config,
        format!(
            "name = \"check\"\nbox_dir = \"{}\"\n[agent]\ncommand = [\"/bin/sh\"]\n\
             [mcp.direct]\ntype = \"stdio\"\ncommand = [\"mcp-server\"]\n\
             [mcp.direct.network]\ncontain_egress = false\n[mcp.direct.env]\n{name:?} = {value:?}\n",
            directory.path().join("box").display()
        ),
    )
    .expect("write box.toml");
    strands_box::check_policy(config)
        .err()
        .map(|failed| failed.to_string())
}

#[test]
fn a_direct_server_may_set_each_gateway_name_and_no_other_reserved_name() {
    for name in GATEWAY_PROXY.iter().chain(GATEWAY_CA_FILE.iter()) {
        assert!(
            matches!(
                reserved_env(name),
                Some(ReservedEnv::GatewayProxy | ReservedEnv::GatewayCaFile)
            ),
            "{name}"
        );
        assert_eq!(
            native_egress_load_refusal(name, "x"),
            None,
            "{name} must load"
        );
    }
    for name in ["PWD", "USER", "OTEL_EXPORTER_OTLP_ENDPOINT", "LD_PRELOAD"] {
        assert!(
            native_egress_load_refusal(name, "x").is_some(),
            "{name} must be refused"
        );
    }
}
