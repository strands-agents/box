//! The stdio MCP fetch server fixture that the MCP cases share.
//!
//! Each case keeps its own `FETCH_PROGRAM` name as a literal in its own file, because the Linux CI step
//! that pre-creates the MCP fixture paths finds the names with a grep over `tests/containment/*.rs`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use crate::{BoxFixture, find_box};

/// The built server binary, beside `strands-box`.
pub const FETCH_BINARY: &str = "box-mcp-fetch-server";

/// A file beside the `strands-box` binary.
pub fn box_sibling(name: &str) -> PathBuf {
    find_box()
        .expect("locate strands-box")
        .parent()
        .expect("the box binary has a parent directory")
        .join(name)
}

/// Where the server binary is placed: `/usr/bin` on Linux; a canonical test-owned dir on macOS,
/// injected onto the box PATH and granted read and exec.
pub fn server_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let dir = PathBuf::from("/tmp/strands-det-mcp-bin");
        std::fs::create_dir_all(&dir).expect("create the macOS MCP server dir");
        // Canonical, so the grant names the path the kernel checks (`/tmp` is `/private/tmp`).
        dir.canonicalize()
            .expect("canonicalize the macOS MCP server dir")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/usr/bin")
    }
}

/// The box's broker socket.
pub fn broker_socket(b: &BoxFixture) -> PathBuf {
    b.alias_dir()
        .parent()
        .expect("the alias dir sits under the box dir")
        .join("run")
        .join("box.sock")
}

/// Copy the fetch server into [`server_dir`] under `program`, executable.
pub fn place_server(program: &str) {
    let on_path = server_dir().join(program);
    std::fs::copy(box_sibling(FETCH_BINARY), &on_path)
        .expect("copy the fetch server onto the operator PATH");
    let mut perms = std::fs::metadata(&on_path)
        .expect("stat the fetch server")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&on_path, perms).expect("make the fetch server executable");
}

/// Declare the `fetch` MCP server, started as `program`, in its default (gateway) posture.
pub fn with_fetch_server(config: String, program: &str) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n",
        quote(program)
    );
    #[cfg(target_os = "macos")]
    {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}
