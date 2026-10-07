// The workload and policy constants `include!`d by each case that starts the fetch server; the
// fixture helpers are in `strands_det_harness::mcp_fixture`.

/// A workload that holds the box open until the case releases it.
#[allow(dead_code)]
const BLOCK: &str = ": > .det-ready; while [ ! -e .det-go ]; do :; done";

/// A policy that starts the fetch server and permits its tool calls.
#[allow(dead_code)]
const SERVER_PERMIT: &str = r#"@id("fetch_start") permit (principal, action == Box::Action::"shell:spawn", resource);
@id("fetch_server") permit (principal, action == Box::Action::"mcp:call", resource)
    when { context.input.server == "fetch" };"#;
