use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::Receiver;

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use serde_json::{Value, json};

const CANONICAL_SCHEMA: &str = include_str!("../../policy/schema/actions.cedarschema");
const EVENT_SCHEMA: &[u8] = include_bytes!("../../policy/schema/events.dwschema");

fn box_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_strands-box"))
}

fn install_script(path: &Path, script: &str) {
    std::fs::write(path, script).expect("write the fake MCP server");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).expect("make the fake server executable");
    }
}

fn install_server(bin: &Path, program: &str, action: &str, field: &str) {
    install_server_response(bin, program, &tools_response(action, field));
}

fn tools_response(action: &str, field: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [{
                "name": action,
                "description": "Test tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        field: {"type": "string"}
                    },
                    "required": [field]
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "body": {"type": "string"}
                    },
                    "required": ["body"]
                }
            }]
        }
    })
}

fn install_server_response(bin: &Path, program: &str, tools: &Value) {
    let path = bin.join(program);
    install_script(&path, &server_script(program, tools));
}

fn server_script(program: &str, tools: &Value) -> String {
    format!(
        r#"#!/bin/sh
set -eu
IFS= read -r initialize
printf '%s' "$HOME" > "{program}.home"
printf '%s\n' "$initialize" > "{program}.trace"
printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"{program}","version":"0.1"}}}}}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> "{program}.trace"
IFS= read -r tools
printf '%s\n' "$tools" >> "{program}.trace"
printf '%s\n' '{tools}'
"#
    )
}

fn install_server_with_shared_type(bin: &Path, program: &str, action: &str, definition_type: &str) {
    let tools = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [{
                "name": action,
                "description": "Test shared type",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "shared": {"$ref": "#/$defs/SharedText"}
                    },
                    "required": ["shared"]
                }
            }],
            "$defs": {
                "SharedText": {"type": definition_type}
            }
        }
    });
    install_server_response(bin, program, &tools);
}

fn install_duplicate_tool_server(bin: &Path, program: &str, across_pages: bool) {
    let tool = json!({
        "name": "repeat",
        "description": "Repeated tool",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    });
    let first = if across_pages {
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [tool.clone()],
                "nextCursor": "next"
            }
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [tool.clone(), tool.clone()]
            }
        })
    };
    let second_exchange = if across_pages {
        let second = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "tools": [tool]
            }
        });
        format!("IFS= read -r second\nprintf '%s\\n' '{second}'\n")
    } else {
        String::new()
    };
    let script = format!(
        r#"#!/bin/sh
set -eu
IFS= read -r initialize
printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":"2024-11-05","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"duplicate","version":"0.1"}}}}}}'
IFS= read -r initialized
IFS= read -r first
printf '%s\n' '{first}'
{second_exchange}"#
    );
    install_script(&bin.join(program), &script);
}

fn install_server_with_shadowed_type(bin: &Path, program: &str) {
    let tools = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [{
                "name": "read",
                "description": "Test local type shadowing",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "shared": {"$ref": "#/$defs/SharedText"}
                    },
                    "required": ["shared"],
                    "$defs": {
                        "SharedText": {"type": "integer"}
                    }
                }
            }],
            "$defs": {
                "SharedText": {"type": "string"}
            }
        }
    });
    install_server_response(bin, program, &tools);
}

fn install_failing_server(bin: &Path, program: &str) {
    let path = bin.join(program);
    install_script(
        &path,
        "#!/bin/sh\nset -eu\nIFS= read -r initialize\nexit 12\n",
    );
}

fn trace(workspace: &Path, program: &str) -> Vec<Value> {
    std::fs::read_to_string(workspace.join(format!("{program}.trace")))
        .expect("the server recorded its requests")
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON-RPC request"))
        .collect()
}

fn artifact_paths(config: &Path) -> (PathBuf, PathBuf) {
    (
        config.join("actions.cedarschema"),
        config.join("events.dwschema"),
    )
}

fn install_existing_artifacts(config: &Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(config).expect("create the schema directory");
    let paths = artifact_paths(config);
    std::fs::write(&paths.0, "existing actions\n").expect("write existing actions");
    std::fs::write(&paths.1, "existing events\n").expect("write existing events");
    paths
}

fn assert_existing_artifacts(paths: &(PathBuf, PathBuf)) {
    assert_eq!(
        std::fs::read_to_string(&paths.0).expect("read existing actions"),
        "existing actions\n"
    );
    assert_eq!(
        std::fs::read_to_string(&paths.1).expect("read existing events"),
        "existing events\n"
    );
}

fn read_http_json(stream: &std::net::TcpStream) -> Value {
    use std::io::{BufRead as _, BufReader, Read as _};

    let mut reader = BufReader::new(stream.try_clone().expect("clone the HTTP stream"));
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("read the HTTP request line");
    assert!(
        request_line.starts_with("POST /mcp HTTP/1.1"),
        "{request_line}"
    );

    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read an HTTP header");
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().expect("parse Content-Length");
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).expect("read the HTTP body");
    serde_json::from_slice(&body).expect("parse the JSON-RPC request")
}

fn write_http_json(
    stream: &mut std::net::TcpStream,
    status: &str,
    body: Option<&Value>,
    session: bool,
) {
    use std::io::Write as _;

    let body = body.map(Value::to_string).unwrap_or_default();
    let session = if session {
        "Mcp-Session-Id: schema-test\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{session}Content-Length: \
         {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .expect("write HTTP headers");
    stream.write_all(body.as_bytes()).expect("write HTTP body");
    stream.flush().expect("flush the HTTP response");
}

fn remote_mcp_server(tools: Value) -> (String, Receiver<Vec<Value>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the remote MCP server");
    let destination = listener.local_addr().expect("read the MCP address");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut requests = Vec::new();

        let (mut stream, _) = listener.accept().expect("accept initialize");
        requests.push(read_http_json(&stream));
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "remote-test", "version": "0.1"}
            }
        });
        write_http_json(&mut stream, "200 OK", Some(&initialize), true);

        let (mut stream, _) = listener.accept().expect("accept initialized");
        requests.push(read_http_json(&stream));
        write_http_json(&mut stream, "202 Accepted", None, false);

        let (mut stream, _) = listener.accept().expect("accept tools/list");
        let request = read_http_json(&stream);
        let response = json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"tools": tools}
        });
        requests.push(request);
        write_http_json(&mut stream, "200 OK", Some(&response), false);

        sender.send(requests).expect("send the remote MCP trace");
    });
    (destination.to_string(), receiver)
}

fn failing_remote_mcp_server() -> (String, Receiver<Value>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the remote MCP server");
    let destination = listener.local_addr().expect("read the MCP address");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept initialize");
        sender
            .send(read_http_json(&stream))
            .expect("send the remote MCP request");
        let body = json!({"error": "discovery unavailable"});
        write_http_json(&mut stream, "503 Service Unavailable", Some(&body), false);
    });
    (destination.to_string(), receiver)
}

#[test]
fn generate_schema_requires_an_output_directory() {
    let home = tempfile::tempdir().expect("an operator home");
    let config = home.path().join("workspace/.strands-box");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::write(config.join("box.toml"), "name = \"schema\"\n").expect("write box.toml");
    let existing = install_existing_artifacts(&config);

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .env("HOME", home.path())
        .current_dir(config.parent().unwrap())
        .output()
        .expect("run the schema command");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("<OUTPUT_DIR>"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_existing_artifacts(&existing);
}

#[test]
fn generate_schema_requires_a_config_argument() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("workspace");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::write(config.join("box.toml"), "name = \"schema\"\n").expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--output-dir"])
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--config <FILE>"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!directory.exists());
    assert!(!config.join("actions.cedarschema").exists());
}

#[test]
fn generate_schema_refuses_a_positional_output_directory() {
    let home = tempfile::tempdir().expect("an operator home");
    let config = home.path().join("box.toml");
    let directory = home.path().join("schemas");
    std::fs::write(&config, "name = \"schema\"\n").expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(&config)
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(home.path())
        .output()
        .expect("run the schema command");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!directory.exists());
}

#[test]
fn generate_schema_uses_the_selected_config_outside_the_operator_home() {
    let home = tempfile::tempdir().expect("an operator home");
    let root = tempfile::tempdir().expect("an external configuration tree");
    let working = root.path().join("caller/deep");
    let ambient = root.path().join("caller/.strands-box");
    let config = root.path().join("chosen.toml");
    let bin = root.path().join("bin");
    let directory = working.join("schemas");
    std::fs::create_dir_all(&working).expect("create the working directory");
    std::fs::create_dir(&bin).expect("create the server directory");
    let existing = install_existing_artifacts(&ambient);
    std::fs::write(
        ambient.join("box.toml"),
        "name = \"decoy\"\n[mcp.decoy]\ntype = \"stdio\"\ncommand = [\"must-not-run\"]\n",
    )
    .expect("write the ambient config");
    std::fs::write(
        &config,
        "name = \"selected\"\nbox_dir = \"/nonexistent/schema-generation\"\n[mcp.selected]\ntype = \"stdio\"\ncommand = [\"chosen-mcp\"]\n",
    )
    .expect("write the selected config");
    install_server(&bin, "chosen-mcp", "selected_tool", "value");

    let output = Command::new(box_binary())
        .args([
            "policy",
            "generate-schema",
            "--config",
            "../../chosen.toml",
            "--output-dir",
            "schemas",
        ])
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&working)
        .output()
        .expect("run the schema command");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actions =
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("read actions");
    assert!(actions.contains("namespace selected {"), "{actions}");
    assert!(
        actions.contains(r#"action "selected_tool" appliesTo"#),
        "{actions}"
    );
    assert!(!actions.contains("namespace decoy {"), "{actions}");
    assert_eq!(
        std::fs::read(directory.join("events.dwschema")).expect("read events"),
        EVENT_SCHEMA
    );
    assert_eq!(trace(&working, "chosen-mcp").len(), 3);
    assert!(!root.path().join("chosen-mcp.trace").exists());
    assert!(!root.path().join("schemas").exists());
    assert_existing_artifacts(&existing);
}

#[test]
fn an_invalid_selected_config_keeps_existing_schema_artifacts() {
    for invalid in ["missing", "directory", "malformed"] {
        let home = tempfile::tempdir().expect("an operator home");
        let workspace = home.path().join("workspace");
        let ambient = workspace.join(".strands-box");
        let config = workspace.join("selected.toml");
        let directory = workspace.join("schemas");
        std::fs::create_dir_all(&ambient).expect("create the ambient config directory");
        std::fs::write(ambient.join("box.toml"), "name = \"decoy\"\n")
            .expect("write the ambient config");
        match invalid {
            "directory" => {
                std::fs::create_dir(&config).expect("create the invalid config directory")
            }
            "malformed" => std::fs::write(&config, "[").expect("write the invalid config"),
            _ => {}
        }
        let existing = install_existing_artifacts(&directory);

        let output = Command::new(box_binary())
            .args(["policy", "generate-schema", "--config"])
            .arg(&config)
            .arg("--output-dir")
            .arg(&directory)
            .env("HOME", home.path())
            .current_dir(&workspace)
            .output()
            .expect("run the schema command");

        assert_eq!(output.status.code(), Some(1), "{invalid}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(config.to_str().unwrap()),
            "{invalid}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_existing_artifacts(&existing);
        assert!(!ambient.join("actions.cedarschema").exists());
    }
}

#[test]
fn generate_schema_refuses_a_file_as_the_output_directory() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("workspace");
    let config = workspace.join(".strands-box");
    let directory = home.path().join("schemas");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::write(
        config.join("box.toml"),
        "name = \"schema\"\nbox_dir = \"/nonexistent/schema-generation\"\n",
    )
    .expect("write box.toml");
    std::fs::write(&directory, "keep this file\n").expect("write the destination file");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(directory.to_str().unwrap()),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&directory).expect("read the destination file"),
        "keep this file\n"
    );
    assert!(!config.join("actions.cedarschema").exists());
    assert!(!config.join("events.dwschema").exists());
}

#[test]
fn generate_schema_writes_the_engine_composition_from_a_nested_directory() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let nested = workspace.join("src/deep");
    let config = workspace.join(".strands-box");
    let directory = nested.join("generated/schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&nested).expect("create the nested working directory");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");
    std::fs::create_dir_all(config.join("mcp-schemas")).expect("create the old schema set");
    std::fs::write(
        config.join("mcp-schemas/stale.cedarschema"),
        "stale schema\n",
    )
    .expect("write a stale schema");
    install_existing_artifacts(&directory);
    let old_location = install_existing_artifacts(&config);

    install_server(&bin, "fake-issues-mcp", "read_wiki", "page");
    install_server(&bin, "fake-aws-mcp", "read_wiki", "account");
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.issues-mcp]
        type = "stdio"
        command = ["fake-issues-mcp"]

        [mcp.aws-mcp]
        type = "stdio"
        command = ["fake-aws-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg("../../.strands-box/box.toml")
        .arg("--output-dir")
        .arg("generated/schemas")
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&nested)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_existing_artifacts(&old_location);
    assert!(!workspace.join("generated").exists());

    let issues = policy::generate_mcp_schema(
        "issues-mcp",
        &tools_response("read_wiki", "page").to_string(),
    )
    .expect("the expected issues schema");
    let aws = policy::generate_mcp_schema(
        "aws-mcp",
        &tools_response("read_wiki", "account").to_string(),
    )
    .expect("the expected AWS schema");
    let expected_actions =
        policy::compose_action_schema(&[("aws-mcp", &aws), ("issues-mcp", &issues)])
            .expect("the expected action composition");
    let actions =
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("the action schema");
    assert_eq!(actions, expected_actions);
    assert_eq!(
        std::fs::read(directory.join("events.dwschema")).expect("the event schema"),
        EVENT_SCHEMA
    );
    assert_eq!(
        std::fs::read_to_string(config.join("mcp-schemas/stale.cedarschema"))
            .expect("the retained legacy schema"),
        "stale schema\n",
        "generation must leave the legacy directory unchanged"
    );

    for (schema, namespace, action, field) in [
        (&issues, "issues_mcp", "read_wiki", "page"),
        (&aws, "aws_mcp", "read_wiki", "account"),
    ] {
        assert!(schema.contains(&format!("namespace {namespace} {{")));
        assert_eq!(schema.matches("namespace ").count(), 1, "{schema}");
        assert!(
            schema.contains(&format!(r#"action "{action}" appliesTo"#)),
            "{action} is absent from:\n{schema}"
        );
        assert!(schema.contains("input: read_wikiInput"), "{schema}");
        assert!(schema.contains(&format!("{field}: String")));
        assert!(schema.contains("type read_wikiInput ="));
        assert!(!schema.contains("entity Agent"));
        assert!(!schema.contains("entity Resource"));
        assert!(!schema.contains(r#""output""#));
        assert!(!schema.contains("McpTool_"), "{schema}");
        assert!(!schema.contains("McpType_"), "{schema}");
    }
    let (_, warnings) =
        Schema::from_cedarschema_str(&actions).expect("the complete action schema parses");
    assert_eq!(warnings.count(), 0);

    for program in ["fake-issues-mcp", "fake-aws-mcp"] {
        let requests = trace(&nested, program);
        assert_eq!(requests.len(), 3, "{program} received {requests:?}");
        assert_eq!(requests[0]["method"], "initialize");
        assert_eq!(requests[0]["params"]["protocolVersion"], "2024-11-05");
        assert_eq!(requests[1]["method"], "notifications/initialized");
        assert_eq!(requests[2]["method"], "tools/list");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(directory.join("actions.cedarschema").to_str().unwrap()),
        "{stdout}"
    );
    assert!(
        stdout.contains(directory.join("events.dwschema").to_str().unwrap()),
        "{stdout}"
    );
}

#[test]
fn generate_schema_composes_lowered_remote_mcp_tools() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = home.path().join("remote-config");
    let directory = workspace.join("schemas");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&workspace).expect("create the working directory");
    let tools = json!([{
        "name": "inspect",
        "description": "Inspect remote state",
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {"type": "string", "enum": ["ready", "busy"]},
                "weight": {"type": "number"}
            },
            "required": ["state", "weight"]
        }
    }]);
    let (destination, requests) = remote_mcp_server(tools);
    std::fs::write(
        config.join("box.toml"),
        format!(
            "name = \"schema\"\nbox_dir = \"/nonexistent/schema-generation\"\n[mcp.remote]\ntype = \"http\"\n\
             destinations = [\"{destination}\"]\n"
        ),
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let schema =
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("the action schema");
    assert!(schema.contains("namespace remote {"), "{schema}");
    assert!(schema.contains(r#"action "inspect" appliesTo"#));
    assert_eq!(schema.matches("namespace remote {").count(), 1, "{schema}");
    assert!(schema.contains("state: String"), "{schema}");
    assert!(schema.contains("weight: Long"), "{schema}");
    assert!(!schema.contains(r#""ready""#), "{schema}");
    let methods = requests
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("receive the remote MCP trace")
        .into_iter()
        .map(|request| request["method"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        ["initialize", "notifications/initialized", "tools/list"]
    );
}

#[test]
fn a_remote_mcp_failure_keeps_existing_schema_artifacts() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    let existing = install_existing_artifacts(&directory);
    let (destination, request) = failing_remote_mcp_server();
    std::fs::write(
        config.join("box.toml"),
        format!(
            "name = \"schema\"\nbox_dir = \"/nonexistent/schema-generation\"\n[mcp.remote]\ntype = \"http\"\n\
             destinations = [\"{destination}\"]\n"
        ),
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(!output.status.success(), "remote discovery must fail");
    assert_existing_artifacts(&existing);
    let request = request
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("receive the remote MCP request");
    assert_eq!(request["method"], "initialize");
}

#[test]
fn top_level_type_names_are_readable_and_scoped_per_server() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_server_with_shared_type(&bin, "fake-issues-mcp", "read", "string");
    install_server_with_shared_type(&bin, "fake-aws-mcp", "lookup", "integer");
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.issues-mcp]
        type = "stdio"
        command = ["fake-issues-mcp"]

        [mcp.aws-mcp]
        type = "stdio"
        command = ["fake-aws-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let actions = std::fs::read_to_string(directory.join("actions.cedarschema")).unwrap();
    assert!(actions.contains("namespace issues_mcp {"), "{actions}");
    assert!(actions.contains("namespace aws_mcp {"), "{actions}");
    assert!(!actions.contains("namespace Mcp::"), "{actions}");
    assert!(actions.contains(r#"action "read" appliesTo"#));
    assert!(actions.contains(r#"action "lookup" appliesTo"#));
    assert!(actions.contains("type SharedText = String;"), "{actions}");
    assert!(actions.contains("type SharedText = Long;"), "{actions}");
    assert!(!actions.contains("McpType_"), "{actions}");

    let (_, warnings) =
        Schema::from_cedarschema_str(&actions).expect("server-scoped common types compose");
    assert_eq!(warnings.count(), 0);
}

#[test]
fn duplicate_tool_names_are_refused_before_schema_install() {
    for across_pages in [false, true] {
        let home = tempfile::tempdir().expect("an operator home");
        let workspace = home.path().join("work/service");
        let config = workspace.join(".strands-box");
        let directory = workspace.join("schemas");
        let bin = home.path().join("bin");
        std::fs::create_dir_all(&config).expect("create the config directory");
        std::fs::create_dir_all(&bin).expect("create the test bin directory");
        let existing = install_existing_artifacts(&directory);

        install_duplicate_tool_server(&bin, "fake-duplicate-mcp", across_pages);
        std::fs::write(
            config.join("box.toml"),
            r#"
            name = "schema"
        box_dir = "/nonexistent/schema-generation"
            [mcp.duplicate]
            type = "stdio"
            command = ["fake-duplicate-mcp"]
            "#,
        )
        .expect("write box.toml");

        let output = Command::new(box_binary())
            .args(["policy", "generate-schema", "--config"])
            .arg(config.join("box.toml"))
            .arg("--output-dir")
            .arg(&directory)
            .env("HOME", home.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .current_dir(&workspace)
            .output()
            .expect("run the schema command");
        assert!(!output.status.success(), "duplicate tools must be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(r#"repeated the tool name "repeat""#),
            "{stderr}"
        );
        assert_existing_artifacts(&existing);
    }
}

#[cfg(unix)]
#[test]
fn colliding_server_namespaces_are_refused_before_schema_install() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");
    let existing = install_existing_artifacts(&directory);

    let dot_server_script = toml::Value::String(server_script(
        "fake-a-dot-mcp",
        &tools_response("first", "first"),
    ));
    let dash_server_script = toml::Value::String(server_script(
        "fake-a-dash-mcp",
        &tools_response("second", "second"),
    ));
    std::os::unix::fs::symlink("/bin/sh", bin.join("fake-a-dot-mcp"))
        .expect("install the dot fake MCP server");
    std::os::unix::fs::symlink("/bin/sh", bin.join("fake-a-dash-mcp"))
        .expect("install the dash fake MCP server");
    std::fs::write(
        config.join("box.toml"),
        format!(
            r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.a-b]
        type = "stdio"
        command = ["fake-a-dash-mcp", "-c", {dash_server_script}]

        [mcp."a.b"]
        type = "stdio"
        command = ["fake-a-dot-mcp", "-c", {dot_server_script}]
        "#,
        ),
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        !output.status.success(),
        "colliding namespaces must be refused"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(r#""a-b""#), "{stderr}");
    assert!(stderr.contains(r#""a.b""#), "{stderr}");
    assert!(stderr.contains(r#""a_b""#), "{stderr}");
    assert_existing_artifacts(&existing);
}

#[test]
fn input_local_type_shadows_the_same_named_server_type() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_server_with_shadowed_type(&bin, "fake-shadow-mcp");
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.shadow]
        type = "stdio"
        command = ["fake-shadow-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let generated = std::fs::read_to_string(directory.join("actions.cedarschema")).unwrap();
    assert!(generated.contains("namespace shadow {"), "{generated}");
    assert!(generated.contains(r#"action "read" appliesTo"#));
    assert!(generated.contains(" = String;"), "{generated}");
    assert!(generated.contains(" = Long;"), "{generated}");

    let (schema, warnings) =
        Schema::from_cedarschema_str(&generated).expect("the shadowed schema composes");
    assert_eq!(warnings.count(), 0);
    let policy = |value: &str| -> PolicySet {
        format!(
            r#"permit (
                principal == Box::Agent::"self",
                action == shadow::Action::"read",
                resource == Box::Resource::"unused"
            ) when {{
                context.input.shared == {value}
            }};"#
        )
        .parse()
        .expect("valid policy syntax")
    };
    assert!(
        Validator::new(schema.clone())
            .validate(&policy("7"), ValidationMode::Strict)
            .validation_passed(),
        "the input-local Long type must apply:\n{generated}"
    );
    assert!(
        !Validator::new(schema)
            .validate(&policy(r#""server""#), ValidationMode::Strict)
            .validation_passed(),
        "the server-level String type must not replace the input-local type:\n{generated}"
    );
}

#[test]
fn paginated_tools_and_a_server_ping_complete_one_schema() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_script(
        &bin.join("fake-paged-mcp"),
        r##"#!/bin/sh
set -eu
IFS= read -r initialize
printf '%s\n' "$initialize" > paged.trace
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"paged","version":"0.1"}}}'
IFS= read -r initialized
printf '%s\n' "$initialized" >> paged.trace
IFS= read -r first_page
printf '%s\n' "$first_page" >> paged.trace
printf '%s\n' '{"jsonrpc":"2.0","id":99,"method":"ping","params":{}}'
IFS= read -r ping
printf '%s\n' "$ping" >> paged.trace
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"paged__first","description":"First","inputSchema":{"type":"object","properties":{"one":{"type":"string"},"mode":{"type":"string","enum":["Mcp::admin"]}},"required":["one","mode"]}}],"$defs":{"SharedText":{"type":"string"}},"nextCursor":"page-2"}}'
IFS= read -r second_page
printf '%s\n' "$second_page" >> paged.trace
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"second","description":"Second","inputSchema":{"type":"object","properties":{"two":{"$ref":"#/$defs/SharedText"}},"required":["two"]}}]}}'
"##,
    );
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.paged]
        type = "stdio"
        command = ["fake-paged-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let schema =
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("the action schema");
    assert!(schema.contains("namespace paged {"), "{schema}");
    assert!(schema.contains(r#"action "paged__first" appliesTo"#));
    assert!(schema.contains(r#"action "second" appliesTo"#));
    assert_eq!(schema.matches("namespace paged {").count(), 1, "{schema}");
    assert!(schema.contains("type SharedText = String;"), "{schema}");
    assert!(!schema.contains("McpType_"), "{schema}");
    assert!(!schema.contains("McpTool_"), "{schema}");
    // The `mode` enum is lowered to `String` at generation, so a rule reads its bare value; the
    // enum entity (and its `"Mcp::admin"` variant) is gone.
    assert!(schema.contains("mode: String"), "{schema}");
    assert!(!schema.contains("Mcp::admin"), "{schema}");

    let requests = trace(&workspace, "paged");
    assert_eq!(requests.len(), 5, "{requests:?}");
    assert_eq!(requests[2]["method"], "tools/list");
    assert_eq!(requests[3]["id"], 99);
    assert_eq!(requests[3]["result"], json!({}));
    assert_eq!(requests[4]["method"], "tools/list");
    assert_eq!(requests[4]["params"]["cursor"], "page-2");
}

#[cfg(unix)]
#[test]
fn non_utf8_home_and_workspace_paths_keep_their_approved_identity() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let root = tempfile::tempdir().expect("a fixture root");
    let home = root.path().join(OsString::from_vec(b"home-\xff".to_vec()));
    let workspace = home.join("work/service");
    let lossy_workspace = root.path().join("home-\u{fffd}/work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.join("bin");
    // macOS APFS refuses non-UTF-8 filenames at the syscall level (EILSEQ), so
    // the property this test pins has no way to be observed there. Skip rather
    // than fail; the Linux leg still exercises it.
    if let Err(error) = std::fs::create_dir_all(&config) {
        if error.raw_os_error() == Some(libc::EILSEQ) {
            eprintln!("skipping: this filesystem refuses non-UTF-8 pathnames ({error})");
            return;
        }
        panic!("create the Box config directory: {error:?}");
    }
    std::fs::create_dir_all(&bin).expect("create the test bin directory");
    std::fs::create_dir_all(&lossy_workspace).expect("create the lossy-spelling decoy");

    let server_script = toml::Value::String(server_script(
        "fake-path-mcp",
        &tools_response("read", "path"),
    ));
    std::os::unix::fs::symlink("/bin/sh", bin.join("fake-path-mcp"))
        .expect("install the fake MCP server");
    std::fs::write(
        config.join("box.toml"),
        format!(
            r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.path]
        type = "stdio"
        command = ["fake-path-mcp", "-c", {server_script}]
        "#
        ),
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", &home)
        .env(
            "PATH",
            std::env::join_paths([bin.as_path(), Path::new("/usr/bin"), Path::new("/bin")])
                .expect("join the test PATH"),
        )
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "schema generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(workspace.join("fake-path-mcp.trace").exists());
    assert!(!lossy_workspace.join("fake-path-mcp.trace").exists());
    assert_eq!(
        std::fs::read(workspace.join("fake-path-mcp.home")).expect("the server's HOME trace"),
        home.as_os_str().as_bytes()
    );
    assert!(directory.join("actions.cedarschema").is_file());
    assert!(directory.join("events.dwschema").is_file());
}

#[test]
fn an_incompatible_initialize_result_is_refused_before_tools_list() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_script(
        &bin.join("fake-future-mcp"),
        r#"#!/bin/sh
set -eu
IFS= read -r initialize
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2099-01-01","capabilities":{},"serverInfo":{"name":"future","version":"0.1"}}}'
"#,
    );
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.future]
        type = "stdio"
        command = ["fake-future-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported protocol version"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!directory.join("actions.cedarschema").exists());
    assert!(!directory.join("events.dwschema").exists());
}

#[test]
fn a_server_without_the_tools_capability_is_refused_before_tools_list() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the Box config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_script(
        &bin.join("fake-no-tools-mcp"),
        r#"#!/bin/sh
set -eu
IFS= read -r initialize
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"no-tools","version":"0.1"}}}'
"#,
    );
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.no-tools]
        type = "stdio"
        command = ["fake-no-tools-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not advertise the tools capability"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!directory.join("actions.cedarschema").exists());
    assert!(!directory.join("events.dwschema").exists());
}

#[test]
fn no_declared_servers_write_both_canonical_artifacts_and_keep_legacy_files() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = home.path().join("generated/policy schemas");
    let legacy = config.join("mcp-schemas/removed.cedarschema");
    std::fs::create_dir_all(legacy.parent().expect("the legacy directory"))
        .expect("create the legacy schema directory");
    std::fs::write(&legacy, "old\n").expect("write the legacy schema");
    std::fs::write(
        config.join("box.toml"),
        "name = \"schema\"\nbox_dir = \"/nonexistent/schema-generation\"\n",
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!config.join("actions.cedarschema").exists());
    assert!(!config.join("events.dwschema").exists());
    assert_eq!(
        std::fs::read_to_string(directory.join("actions.cedarschema")).expect("read actions"),
        CANONICAL_SCHEMA
    );
    assert_eq!(
        std::fs::read(directory.join("events.dwschema")).expect("read events"),
        EVENT_SCHEMA
    );
    assert_eq!(
        std::fs::read_to_string(legacy).expect("read the retained legacy schema"),
        "old\n"
    );
}

#[test]
fn one_server_failure_leaves_every_existing_schema_unchanged() {
    let home = tempfile::tempdir().expect("an operator home");
    let workspace = home.path().join("work/service");
    let config = workspace.join(".strands-box");
    let directory = workspace.join("schemas");
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&config).expect("create the config directory");
    std::fs::create_dir_all(&bin).expect("create the test bin directory");

    install_server(&bin, "fake-good-mcp", "read", "path");
    install_failing_server(&bin, "fake-broken-mcp");
    let existing = install_existing_artifacts(&directory);
    std::fs::write(
        config.join("box.toml"),
        r#"
        name = "schema"
        box_dir = "/nonexistent/schema-generation"
        [mcp.a-good]
        type = "stdio"
        command = ["fake-good-mcp"]

        [mcp.z-broken]
        type = "stdio"
        command = ["fake-broken-mcp"]
        "#,
    )
    .expect("write box.toml");

    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(config.join("box.toml"))
        .arg("--output-dir")
        .arg(&directory)
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .current_dir(&workspace)
        .output()
        .expect("run the schema command");
    assert!(!output.status.success(), "the broken server must fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("z-broken"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_existing_artifacts(&existing);
}

#[test]
fn stdio_schema_discovery_uses_declared_workspace_and_environment() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let working = root.path().join("caller");
    let declared = root.path().join("declared");
    let bin = root.path().join("bin");
    for directory in [&home, &working, &declared, &bin] {
        std::fs::create_dir(directory).unwrap();
    }
    let config = root.path().join("box.toml");
    let mut script = server_script("declared-mcp", &tools_response("read", "value"));
    script = script.replacen(
        "set -eu",
        "set -eu\ntest \"$SCHEMA_LABEL\" = selected\ntest -z \"${UNDECLARED_OPERATOR_VALUE-}\"",
        1,
    );
    install_script(&bin.join("declared-mcp"), &script);
    let content = format!(
        "name = \"schema\"\nbox_dir = \"/nonexistent/discovery\"\n[mcp.selected]\ntype = \"stdio\"\ncommand = [\"declared-mcp\"]\nworkspace = {:?}\nenv = {{ SCHEMA_LABEL = \"selected\", PATH = {:?} }}\n",
        declared.to_str().unwrap(),
        bin.to_str().unwrap()
    );
    std::fs::write(&config, content).unwrap();
    let output = Command::new(box_binary())
        .args(["policy", "generate-schema", "--config"])
        .arg(&config)
        .args(["--output-dir", "schemas"])
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("UNDECLARED_OPERATOR_VALUE", "must-not-inherit")
        .current_dir(&working)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(trace(&declared, "declared-mcp").len(), 3);
    assert!(!working.join("declared-mcp.trace").exists());
    assert!(working.join("schemas/actions.cedarschema").exists());
}
