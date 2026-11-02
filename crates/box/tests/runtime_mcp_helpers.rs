//! Native imports and child access through a declared Linux stdio server.

#![cfg(target_os = "linux")]

use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};

const PROGRAM: &str = "native-helper";
const TIMEOUT: Duration = Duration::from_secs(45);
const BLOCK: &str = ": > \"$HOME/ready\"; while [ ! -e \"$HOME/release\" ]; do :; done";

enum Grant {
    Read,
    OmittedExtension,
    DeniedExtension,
    OmittedHelper,
}

fn run_probe(grant: Grant) -> Option<Value> {
    if !fixture::namespace_launcher_is_usable() {
        eprintln!("skipping: Linux namespace launcher unavailable");
        return None;
    }
    let python = Path::new("/usr/bin/python3")
        .canonicalize()
        .expect("resolve Python");
    let discovery = Command::new(&python)
        .args(["-c", "import _sqlite3; print(_sqlite3.__file__)"])
        .output()
        .expect("query Python native extension");
    assert!(
        discovery.status.success(),
        "Python needs _sqlite3: {discovery:?}"
    );
    let original = PathBuf::from(String::from_utf8(discovery.stdout).unwrap().trim());
    let box_ = RuntimeMcpBox::new("mcp-helpers");
    let home = box_.operator_home();
    let data = home.join("probe-data");
    let native = home.join("native");
    let helpers = home.join("helpers");
    for dir in [&data, &native, &helpers, &home.join(".aws")] {
        std::fs::create_dir(dir).unwrap();
    }
    let extension = native.join(original.file_name().unwrap());
    std::fs::copy(&original, &extension).expect("copy the selected native extension");
    let helper = helpers.join("python-helper");
    std::fs::copy(&python, &helper).expect("copy the helper executable");
    let readable = data.join("readable");
    let denied = data.join("denied");
    let credential = home.join(".aws/credentials");
    for (path, text) in [
        (&readable, "READABLE_CONTROL"),
        (&denied, "DENIED_CONTROL"),
        (&credential, "SYNTHETIC_CREDENTIAL_CONTROL"),
    ] {
        std::fs::write(path, text).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = home.join("workspace/.strands-box/box.toml");
    let settings_path = data.join("settings.json");
    let settings = json!({
        "extension": extension, "helper": helper, "readable": readable,
        "protected": {"denied": denied, "credential": credential,
            "config": config, "state": box_.root().join("private/box.toml")},
        "port": listener.local_addr().unwrap().port(),
    });
    std::fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    let script = box_.install_program(
        PROGRAM,
        &format!(
            "#!{}\n{}",
            python.display(),
            include_str!("support/mcp_native_helper.py")
        ),
    );
    let server = Server::new("native", PROGRAM, "verify", DiscoveryBehavior::Ready)
        .with_env("PROBE_SETTINGS", settings_path.to_str().unwrap());
    box_.write_workspace(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
           when { context.input.server == "native" };
           permit (principal, action == native::Action::"verify", resource);"#,
        &[server],
        BLOCK,
    );
    let mut authored: toml::Value =
        toml::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    let fs = authored["mcp"]["native"]["filesystem"]
        .as_table_mut()
        .unwrap();
    let read = fs.get_mut("read").unwrap().as_array_mut().unwrap();
    read.push(toml::Value::String(data.display().to_string()));
    if !matches!(grant, Grant::OmittedExtension) {
        read.push(toml::Value::String(native.display().to_string()));
    }
    if !matches!(grant, Grant::OmittedHelper) {
        read.push(toml::Value::String(helpers.display().to_string()));
    }
    let mut deny = vec![toml::Value::String(denied.display().to_string())];
    if matches!(grant, Grant::DeniedExtension) {
        deny.push(toml::Value::String(extension.display().to_string()));
    }
    fs.insert("deny".to_string(), toml::Value::Array(deny));
    std::fs::write(&config, toml::to_string(&authored).unwrap()).unwrap();

    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("ready"), TIMEOUT);
    let control = Command::new(&helper)
        .args([
            script.as_os_str(),
            "--host".as_ref(),
            settings_path.as_os_str(),
        ])
        .output()
        .expect("run the uncontained control");
    assert!(control.status.success(), "host control failed: {control:?}");
    listener
        .accept()
        .expect("the host control reached the listener");
    let protected: Vec<_> = settings["protected"]
        .as_object()
        .unwrap()
        .values()
        .map(|path| {
            let path = PathBuf::from(path.as_str().unwrap());
            let contents = std::fs::read(&path).unwrap();
            (path, contents)
        })
        .collect();

    let mut client = box_.open_client(PROGRAM);
    client.initialize_and_activate(json!(1), TIMEOUT);
    let catalog = client.list_root(json!(2), TIMEOUT);
    assert_eq!(catalog["result"]["tools"][0]["name"], "verify", "{catalog}");
    client.send(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "verify", "arguments": {}}}));
    let response = client.receive(TIMEOUT);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "the contained child must not reach the host listener"
    );
    for (path, contents) in protected {
        assert_eq!(std::fs::read(path).unwrap(), contents);
    }
    drop(client);
    box_.release_workload();
    let output = run.wait(TIMEOUT);
    assert!(output.status.success(), "{output:?}");
    if matches!(grant, Grant::Read) {
        let records = std::fs::read_to_string(box_.root().join("private/telemetry/records.jsonl"))
            .expect("read drained telemetry");
        assert!(
            records.lines().any(|line| {
                let batch: Value = serde_json::from_str(line).expect("parse telemetry");
                log_records(&batch).any(|record| {
                    let attribute = |name: &str| {
                        record["attributes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|entry| entry["key"] == name)
                            .and_then(|entry| entry["value"]["stringValue"].as_str())
                    };
                    attribute("strands.box.policy.action") == Some("net:connect")
                        && attribute("strands.box.policy.verdict") == Some("deny")
                        && attribute("strands.box.policy.resource")
                            .is_some_and(|value| value.contains("helper-proof.invalid"))
                })
            }),
            "the gateway must record the refused child request; response: {response}"
        );
    }
    Some(response)
}

fn log_records(batch: &Value) -> impl Iterator<Item = &Value> {
    batch["resourceLogs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|resource| resource["scopeLogs"].as_array().into_iter().flatten())
        .flat_map(|scope| scope["logRecords"].as_array().into_iter().flatten())
}

#[test]
fn a_stdio_server_and_its_helper_load_granted_native_code_and_preserve_denials() {
    let Some(response) = run_probe(Grant::Read) else {
        return;
    };
    assert_eq!(response["result"]["isError"], false, "{response}");
    let proof: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let mut child = proof["child"].clone();
    child["refused"]
        .as_array_mut()
        .unwrap()
        .sort_unstable_by(|left, right| left.as_str().cmp(&right.as_str()));
    assert_eq!(
        child,
        json!({
            "extension": proof["server_extension"].as_str().expect("server extension path"),
            "sqlite_result": 42,
            "host": false,
            "refused": ["config", "credential", "denied", "state"],
        })
    );
}

#[test]
fn an_omitted_native_extension_grant_refuses_the_server_operation() {
    assert_refusal(Grant::OmittedExtension, "NATIVE_EXTENSION_UNAVAILABLE:");
}

#[test]
fn an_explicit_native_extension_denial_overrides_the_directory_grant() {
    assert_refusal(Grant::DeniedExtension, "NATIVE_EXTENSION_UNAVAILABLE:");
}

#[test]
fn an_omitted_helper_grant_refuses_the_child() {
    assert_refusal(Grant::OmittedHelper, "HELPER_UNAVAILABLE:");
}

fn assert_refusal(grant: Grant, reason: &str) {
    let Some(response) = run_probe(grant) else {
        return;
    };
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(reason),
        "{response}"
    );
}
