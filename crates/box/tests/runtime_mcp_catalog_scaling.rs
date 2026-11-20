//! Catalog timing in a separate test binary, without concurrent policy-staging workloads.

#![cfg(unix)]

use std::io::Write as _;
use std::time::Duration;

use serde_json::{Value, json};

#[path = "support/fixture.rs"]
mod fixture;
#[path = "support/runtime_mcp.rs"]
mod runtime_mcp;

use runtime_mcp::{DiscoveryBehavior, RuntimeMcpBox, Server};

const BOX_STARTUP: Duration = Duration::from_secs(45);
const STARTUP: Duration = Duration::from_secs(8);
const SHUTDOWN: Duration = Duration::from_secs(8);
const CATALOG_TIMEOUT: Duration = Duration::from_secs(20);

const BLOCKING_WORKLOAD: &str = r#"
set -eu
: > "$HOME/workload.started"
while [ ! -e "$HOME/release" ]; do :; done
"#;

fn mcp_call_policy_for(server: &str) -> String {
    format!(
        r#"permit (principal, action == Box::Action::"mcp:call", resource)
        when {{ context.input.server == "{server}" }};"#
    )
}

fn assert_list_page(response: &Value, id: &Value, tool: &str, page: usize) {
    assert_eq!(
        response.get("id"),
        Some(id),
        "the client id must be restored"
    );
    assert_eq!(
        response.pointer("/result/tools/0/name"),
        Some(&Value::String(tool.to_string()))
    );
    assert_eq!(
        response.pointer("/result/tools/0/fixtureField"),
        Some(&Value::String(format!("tool-{page}"))),
        "the cached tool must preserve extension fields"
    );
    assert_eq!(
        response.pointer("/result/fixturePageField"),
        Some(&Value::String(format!("page-{page}"))),
        "the cached result must preserve extension fields"
    );
    assert_eq!(
        response.get("fixtureResponseField"),
        Some(&Value::String(format!("response-{page}"))),
        "the cached response must preserve extension fields"
    );
}

/// Time one box from its first `tools/list` to its first catalog, over `pages` pages.
fn time_to_first_catalog(pages: usize) -> Duration {
    let box_ = RuntimeMcpBox::new(&format!("mcp-first-catalog-{pages}"));
    let server = Server::new(
        "paged",
        "paged-mcp",
        "read",
        DiscoveryBehavior::Pages(pages),
    );
    box_.install_server(&server);
    box_.write_workspace(
        &mcp_call_policy_for(server.name),
        &[server],
        BLOCKING_WORKLOAD,
    );
    let mut run = box_.spawn();
    run.wait_for(box_.workload_path("workload.started"), BOX_STARTUP);
    let mut client = box_.open_client("paged-mcp");
    run.wait_for_through_alias(box_.server_started("paged-mcp"), STARTUP);
    client.initialize_and_activate(json!("initialize"), STARTUP);
    let started = std::time::Instant::now();
    let exchange = client.list_all(1, json!({}), CATALOG_TIMEOUT);
    let elapsed = started.elapsed();
    assert_list_page(&exchange.pages[0], &json!(1), "read", 0);
    assert!(
        exchange.last().get("result").is_some(),
        "{}",
        exchange.last()
    );
    assert_eq!(
        box_.list_count("paged-mcp"),
        pages,
        "the first catalog must page through the whole listing"
    );
    drop(client);
    box_.release_workload();
    let output = run.wait(SHUTDOWN);
    assert!(
        output.status.success(),
        "the timed run must finish cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    elapsed
}

#[test]
fn the_first_catalog_of_256_pages_costs_at_most_three_times_one_of_128_pages() {
    if !fixture::namespace_launcher_is_usable() {
        return;
    }
    const LARGEST_RATIO: f64 = 3.0;
    let full = time_to_first_catalog(256);
    let half = time_to_first_catalog(128);
    let ratio = full.as_secs_f64() / half.as_secs_f64().max(f64::EPSILON);
    let _ = writeln!(
        std::io::stderr().lock(),
        "NFR-09 time to the first catalog: 128 pages {half:?} ({:.1} ms per page), 256 pages \
         {full:?} ({:.1} ms per page), ratio {ratio:.2}, limit {LARGEST_RATIO}; {} build",
        half.as_secs_f64() * 1000.0 / 128.0,
        full.as_secs_f64() * 1000.0 / 256.0,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    assert!(
        ratio <= LARGEST_RATIO,
        "the first catalog of 256 pages took {full:?} against {half:?} for 128 pages (ratio \
         {ratio:.2}, limit {LARGEST_RATIO}): the cost per page grows with the page count"
    );
}
