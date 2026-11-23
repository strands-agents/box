use crate::support::*;

#[test]
fn uvx_in_a_shared_bin_does_not_read_sibling_credentials() {
    for prefix in [".cargo", ".local"] {
        let host = FakeHost::new();
        let home = host.home();
        let bin = home.join(prefix).join("bin");
        binary(&bin.join("uvx"));
        let python = home.join(".local/share/uv/python");
        std::fs::create_dir_all(&python).expect("managed Python");
        let secrets = [
            home.join(".cargo/credentials.toml"),
            home.join(".local/share/uv/credentials/credentials.toml"),
            home.join(".local/state/another-app/token"),
        ];
        for secret in &secrets {
            write(secret, "dummy-token");
        }
        write(
            &home.join(".claude.json"),
            r#"{"mcpServers":{"probe":{"command":"uvx","args":["example-server"]}}}"#,
        );
        let generated = trial(&host, &[&bin])
            .option("claude.import-mcp", "true")
            .with("uvx")
            .tools(Vec::<String>::new())
            .generate()
            .expect("uvx as a tool and MCP server");
        let config: toml::Value = toml::from_str(generated.box_toml()).expect("TOML");
        for (name, process) in [
            ("tool", &config["tool"]["uvx"]),
            ("MCP server", &config["mcp"]["probe"]),
        ] {
            let reads = strings(&process["filesystem"]["read"]);
            for secret in &secrets {
                assert!(
                    reads.iter().all(|grant| !secret.starts_with(grant)),
                    "{prefix} {name} grants access to {}: {reads:?}",
                    secret.display()
                );
            }
            assert!(reads.contains(&text(&bin)), "{prefix} {name}: {reads:?}");
            assert!(reads.contains(&text(&python)), "{prefix} {name}: {reads:?}");
        }
    }
}
