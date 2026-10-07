use std::path::Path;
use std::process::Command;

use strands_det_harness::mcp_fixture::{box_sibling, place_server, server_dir};
use strands_det_harness::{BoxFixture, Platform, RunResult, det_case};

// A stdio MCP server runs in its own leaf, and its filesystem reach is its `[mcp.<name>.filesystem]`
// lists and nothing else. The server is the `box-mcp-fetch-server` fixture, whose `read` tool reads a
// file by its own syscall inside the leaf. A `tools/call` of `read` on a file under its `read` list
// returns the bytes; the same call on a planted secret outside every list returns the errno the leaf
// refuses with, and no byte of it. The client is `box-mcp-call-probe`, one `tools/call` per target.


/// A unique program name, so no other case copies over this executing file (`ETXTBSY`).
#[cfg(target_os = "linux")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-mf-linux";
#[cfg(target_os = "macos")]
const FETCH_PROGRAM: &str = "box-mcp-fetch-mf-macos";

include!("../probes/fetch_server.rs");

fn with_fetch_server(config: String, grant: &Path) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap();
    let mut reads = vec![quote(&grant.display().to_string())];
    if Platform::current() == Platform::Macos {
        let dir = quote(&server_dir().display().to_string());
        reads.push(dir);
    }
    format!(
        "{config}\n[mcp.fetch]\ntype = \"stdio\"\ncommand = [{}]\n[mcp.fetch.filesystem]\nread = [{}]\n",
        quote(FETCH_PROGRAM),
        reads.join(", ")
    )
}

/// One box, one `tools/call` of `read` per path, in order.
fn read_through_server(b: &BoxFixture, grant: &Path, paths: &[&Path]) -> (Vec<String>, RunResult) {
    let socket = b.box_dir().join("run").join("box.sock");
    let probe = box_sibling("box-mcp-call-probe");
    place_server(FETCH_PROGRAM);
    let mut outputs = Vec::new();
    let meanwhile = || {
        for path in paths {
            let arguments = serde_json::json!({ "path": path.to_string_lossy() }).to_string();
            let output = Command::new(&probe)
                .arg(&socket)
                .arg(FETCH_PROGRAM)
                .arg("read")
                .arg(arguments)
                .output()
                .expect("run box-mcp-call-probe");
            outputs.push(
                String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr),
            );
        }
    };
    let path = format!("{}:{}", server_dir().display(), std::env::var("PATH").unwrap_or_default());
    let run = b.run_sh_with_config_meanwhile_env(
        |config| with_fetch_server(config, grant),
        BLOCK,
        &[("PATH", path.as_str())],
        meanwhile,
    );
    (outputs, run)
}

det_case! {
    name: cn_mf_01,
    id:   "CN-MF-01",
    platforms: [Linux, Macos],
    desc: "MCP leaf filesystem: a stdio MCP server's own read of a planted secret outside its [mcp.x.filesystem] lists is refused and yields no bytes, while a file under its read list returns its content",
    run: |b| {
        let root = b.workspace().parent().unwrap().to_path_buf();
        let grant = root.join("mf01-grant");
        std::fs::create_dir(&grant).expect("DET_ERROR: the server's read grant");
        let inside = grant.join("inside.txt");
        std::fs::write(&inside, "DET_INSIDE_MF01").expect("DET_ERROR: plant the in-grant file");
        let secret = format!("DET_SECRET_MF01_{}", std::process::id());
        let secret_path = root.join("mf01-secret.txt");
        std::fs::write(&secret_path, &secret).expect("DET_ERROR: plant the secret");
        assert_eq!(std::fs::read_to_string(&secret_path).unwrap(), secret, "DET_ERROR: the host cannot read the secret");
        b.apply_policy(SERVER_PERMIT);

        let (out, run) = read_through_server(b, &grant, &[&inside, &secret_path]);
        let both = RunResult::bare(format!("{}\n{}\n[box output]\n{}", out[0], out[1], run.out), 0);
        // The control: the server reads under its own list, so the server started and its read works.
        assert!(out[0].contains("read:DET_INSIDE_MF01"), "the server did not read its own grant; out=[{}]", out[0]);
        run.assert_mediated_permitted("shell:spawn", FETCH_PROGRAM);
        run.assert_mediated_permitted("mcp:call", "fetch/read");
        // The boundary: the read outside every list is refused by the leaf, and no byte returns.
        let errno = match Platform::current() {
            Platform::Linux => "read-failed:errno=2",
            Platform::Macos => "read-failed:errno=1",
        };
        assert!(out[1].contains(errno), "the server's read of the secret was not refused with {errno}; out=[{}]", out[1].replace(&secret, "<REDACTED>"));
        both.assert_absent_secret(&secret, "CN-MF-01 secret");
        assert_eq!(std::fs::read_to_string(&secret_path).unwrap(), secret, "the secret changed on the host");
    }
}
