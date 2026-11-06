use super::*;

async fn discover_script(script: &str, log: &Path) -> io::Result<Value> {
    let server = McpServer {
        argument_wildcards: false,
        name: "modern".to_string(),
        command: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "modern-mcp".to_string(),
            log.to_string_lossy().into_owned(),
        ],
    };
    list_tools(&server, Path::new("/tmp"), Path::new("/tmp")).await
}

#[tokio::test]
async fn offline_modern_discovery_collects_every_page_without_initialize() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let tools = discover_script(
        r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
case "$frame" in
  *'"method":"server/discover"'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}}' ;;
  *'"cursor":"next"'*) printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[{"name":"second","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}' ;;
  *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"first","inputSchema":{"type":"object"}}],"nextCursor":"next","ttlMs":0,"cacheScope":"private"}}' ;;
esac
done"#,
        log.path(),
    ).await.expect("modern schema discovery");
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 2);
    let frames: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0]["method"], "server/discover");
    assert!(frames.iter().all(
        |frame| frame["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    ));
    assert!(!frames.iter().any(|frame| frame["method"] == "initialize"));
}

#[tokio::test]
async fn offline_modern_version_errors_do_not_fall_back_to_initialize() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let error = discover_script(
        r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
printf '%s\n' '{"jsonrpc":"2.0","id":0,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2099-01-01"],"requested":"2026-07-28"}}}'
done"#,
        log.path(),
    ).await.expect_err("unsupported modern version");
    assert!(error.to_string().contains("modern discovery"), "{error}");
    assert_eq!(
        std::fs::read_to_string(log.path()).unwrap().lines().count(),
        1
    );
}

#[tokio::test]
async fn offline_probe_timeout_preserves_legacy_fallback() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let tools = discover_script(
        r#"while IFS= read -r frame; do
printf '%s\n' "$frame" >> "$1"
case "$frame" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1"}}}' ;;
  *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}' ;;
esac
done"#,
        log.path(),
    ).await.expect("legacy discovery after a silent probe");
    assert_eq!(tools["result"]["tools"], json!([]));
    let frames: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames[0]["method"], "server/discover");
    assert_eq!(frames[1]["method"], "initialize");
    assert_eq!(frames[2]["method"], "notifications/initialized");
}

#[tokio::test]
async fn a_partial_probe_response_cannot_become_a_legacy_frame() {
    let log = tempfile::NamedTempFile::new().unwrap();
    let error = discover_script(
        r#"IFS= read -r frame
printf '%s\n' "$frame" >> "$1"
printf '{"jsonrpc":"2.0",'
while IFS= read -r frame; do printf '%s\n' "$frame" >> "$1"; done"#,
        log.path(),
    )
    .await
    .expect_err("partial frame");
    assert!(
        error.to_string().contains("within a response frame"),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(log.path()).unwrap().lines().count(),
        1
    );
}
