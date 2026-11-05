//! The stdio MCP fetch server fixture that the MCP cases share.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::OnceLock;

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

/// The canonical server directory, outside every case's agent write grants.
pub fn server_dir() -> PathBuf {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY
        .get_or_init(|| {
            let base = std::env::var_os("DET_BOX_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| crate::user_home().join(".det-harness-boxes"));
            std::fs::create_dir_all(&base).expect("DET_ERROR: create the MCP fixture root");
            tempfile::Builder::new()
                .prefix("mcp-bin-")
                .tempdir_in(base)
                .expect("DET_ERROR: create the MCP server directory")
                .keep()
                .canonicalize()
                .expect("DET_ERROR: canonicalize the MCP server directory")
        })
        .clone()
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
    let mut tables = format!(
        "\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n",
        quote(program)
    );
    {
        let dir = quote(&server_dir().display().to_string());
        tables.push_str(&format!("[mcp.fetch.filesystem]\nread = [{dir}]\n"));
    }
    config + &tables
}
