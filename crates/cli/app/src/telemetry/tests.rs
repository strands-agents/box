use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::{Observations, contributing_packs};
use crate::lang::{self, Layer, Lookup, PACK_FILE, PackLocation};
use crate::mcp::{Detected, Launcher, Servers, Skipped, Transport};
use crate::profile::Profile;

fn snapshot(observations: Observations) -> Value {
    serde_json::to_value(observations.finish()).unwrap()
}

fn lookup(directory: &Path) -> Lookup {
    Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: directory.join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    }
}

fn graph(text: &str, lookup: &Lookup) -> Vec<Layer> {
    let table = toml::from_str(text).unwrap();
    lang::chain(&table, text, Path::new("profile.toml"), None, lookup).unwrap()
}

fn write_pack(root: &Path, id: &str, text: &str) {
    let folder = root.join(id);
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join(lang::PACK_FILE), text).unwrap();
}

fn shipped(id: &str) -> String {
    fs::read_to_string(
        crate::resources::source_tree()
            .join("packs")
            .join(id)
            .join(lang::PACK_FILE),
    )
    .unwrap()
}

#[test]
fn policy_presence_agrees_with_profile_validation() {
    for policies in [
        "",
        "policies = []",
        "policies = ['rules.dw']",
        "policies = ['rules.dw', 'other.dw']",
        "policies = [7]",
        "policies = ['']",
        "policies = ['${{ workspace }}/rules.dw']",
        "policies = ['rules.dw', 7]",
        "policies = 'rules.dw'",
        "policies = [{ path = 'rules.dw' }]",
    ] {
        let text = format!("{policies}\n[agent]\ncommand = ['/usr/bin/true']\n");
        let expected = Profile::parse(&text, Path::new("profile.toml"))
            .map(|profile| !profile.policies().is_empty())
            .ok();
        let mut observations = Observations::default();
        observations.profile(text.as_bytes());
        assert_eq!(
            snapshot(observations)["profile_policy_present"],
            json!(expected),
            "{policies}"
        );
    }
}

#[test]
fn graph_includes_transitive_packs_once_in_id_order() {
    let temporary = tempfile::tempdir().unwrap();
    let lookup = lookup(temporary.path());
    let layers = graph(
        "packs = ['@box/codex', '@box/claude', '@box/base', '@box/codex']",
        &lookup,
    );
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!(["base", "claude", "codex"]));
    assert_eq!(value["has_custom_packs"], false);
    assert_eq!(value["mcp_configured"], Value::Null);
}

#[test]
fn resolved_empty_graph_reports_none_without_counting_the_profile() {
    let temporary = tempfile::tempdir().unwrap();
    let lookup = lookup(temporary.path());
    let layers = graph("", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], false);
}

#[test]
fn custom_pack_names_never_reach_the_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let lookup = lookup(temporary.path());
    write_pack(
        &lookup.operator,
        "secret-customer",
        "[pack]\nname = 'secret-customer'\nversion = 1\nkind = 'support'\nextend = ['@box/base']",
    );
    let layers = graph("packs = ['secret-customer']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!(["base"]));
    assert_eq!(value["has_custom_packs"], true);
    assert!(!value.to_string().contains("secret-customer"));
}

#[test]
fn a_collection_pack_is_custom_and_its_names_never_reach_the_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let mut lookup = lookup(temporary.path());
    let root = temporary.path().join("secret-org");
    lookup.collections.push(crate::lang::Collection {
        scope: "secret-org".to_string(),
        root: root.clone(),
    });
    write_pack(
        &root.join("packs"),
        "base",
        "[pack]\nname = '@secret-org/base'\nversion = 1\nkind = 'support'\nextend = ['@box/base']",
    );
    let layers = graph("packs = ['@secret-org/base']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!(["base"]));
    assert_eq!(value["has_custom_packs"], true);
    assert!(!value.to_string().contains("secret-org"));
}

#[test]
fn a_plugin_is_not_a_pack_in_the_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let lookup = lookup(temporary.path());
    let folder = temporary.path().join("plugins/vault");
    fs::create_dir_all(&folder).unwrap();
    fs::write(
        folder.join("plugin.toml"),
        "[plugin]\nname = 'vault'\nversion = 1\nkind = 'secret-source'\nscheme = 'vault'\n\
         [inputs.vault.path]\ntype = 'program'\nprogram = 'vault'\n\
         [run]\ncommand = ['${{ inputs.vault.path }}', '{ref}']\n",
    )
    .unwrap();
    let layers = graph("packs = ['@box/base']\nplugins = ['vault']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(
        (&value["builtin_packs"], &value["has_custom_packs"]),
        (&json!(["base"]), &json!(false))
    );
}

#[test]
fn an_operator_pack_with_a_builtin_short_name_is_custom() {
    let temporary = tempfile::tempdir().unwrap();
    let lookup = lookup(temporary.path());
    write_pack(
        &lookup.operator,
        "base",
        "[pack]\nname = 'base'\nversion = 1\nkind = 'support'\n",
    );
    let layers = graph("packs = ['base']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], true);
}

#[test]
fn resource_overrides_must_match_the_compiled_catalog() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("resources/packs");
    fs::create_dir_all(&shared).unwrap();
    let alias = temporary.path().join("resource-alias");
    std::os::unix::fs::symlink(&shared, &alias).unwrap();
    let lookup = Lookup {
        vendored: Some(alias),
        operator: temporary.path().join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    for (text, ids, custom) in [
        (shipped("base"), json!(["base"]), false),
        (
            format!("{}\n# a local edit\n", shipped("base")),
            json!([]),
            true,
        ),
    ] {
        write_pack(&shared, "base", &text);
        let layers = graph("packs = ['@box/base']", &lookup);
        let mut observations = Observations::default();
        observations.packs(&layers);
        let value = snapshot(observations);
        assert_eq!(value["builtin_packs"], ids);
        assert_eq!(value["has_custom_packs"], custom);
    }
    write_pack(
        &shared,
        "private-customer",
        "[pack]\nname = '@box/private-customer'\nversion = 1\nkind = 'support'\n",
    );
    let layers = graph("packs = ['@box/private-customer']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], true);
    assert!(!value.to_string().contains("private-customer"));
}

#[test]
fn catalog_hashes_the_loaded_pack_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("resources/packs");
    let lookup = Lookup {
        vendored: Some(shared.clone()),
        operator: temporary.path().join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    write_pack(&shared, "base", &shipped("base"));
    let layers = graph("packs = ['@box/base']", &lookup);
    write_pack(&shared, "base", "# changed after resolution");
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!(["base"]));
    assert_eq!(value["has_custom_packs"], false);
}

#[test]
fn an_added_grammar_is_custom_even_after_the_sidecar_is_removed() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("resources/packs");
    let lookup = Lookup {
        vendored: Some(shared.clone()),
        operator: temporary.path().join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    write_pack(&shared, "node", &shipped("node"));
    let grammar = shared.join("node/grammar.toml");
    fs::write(
        &grammar,
        "format = 1\nversion = 1\nname = 'node'\nprogram = 'node'\n\
         [shell.status]\nusage = 'node status'\n",
    )
    .unwrap();
    let layers = graph("packs = ['@box/node']", &lookup);
    fs::remove_file(grammar).unwrap();
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], true);
}

#[test]
fn loaded_catalog_sources_survive_removal() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("resources/packs");
    let lookup = Lookup {
        vendored: Some(shared.clone()),
        operator: temporary.path().join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    for id in ["base", "anthropic"] {
        write_pack(&shared, id, &shipped(id));
    }
    let layers = graph("packs = ['@box/base', '@box/anthropic']", &lookup);
    fs::remove_file(shared.join("anthropic").join(lang::PACK_FILE)).unwrap();
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], json!(["anthropic", "base"]));
    assert_eq!(value["has_custom_packs"], false);
}

#[cfg(unix)]
#[test]
fn linked_catalog_sources_leave_location_unknown() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("resources/packs");
    fs::create_dir_all(&shared).unwrap();
    let lookup = Lookup {
        vendored: Some(shared.clone()),
        operator: temporary.path().join("packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    write_pack(&lookup.operator, "base", &shipped("base"));
    std::os::unix::fs::symlink(lookup.operator.join("base"), shared.join("base")).unwrap();
    let layers = graph("packs = ['@box/base']", &lookup);
    let mut observations = Observations::default();
    observations.packs(&layers);
    let value = snapshot(observations);
    assert_eq!(value["builtin_packs"], Value::Null);
    assert_eq!(value["has_custom_packs"], Value::Null);
}

#[test]
fn catalog_keeps_the_source_of_the_loaded_bytes_after_link_replacement() {
    for directory_link in [true, false] {
        let temporary = tempfile::tempdir().unwrap();
        let shared = temporary.path().join("resources/packs");
        let lookup = Lookup {
            vendored: Some(shared.clone()),
            operator: temporary.path().join("packs"),
            collections: Vec::new(),
            version: crate::VERSION,
        };
        write_pack(&lookup.operator, "base", &shipped("base"));
        let (outside, link) = if directory_link {
            fs::create_dir_all(&shared).unwrap();
            (lookup.operator.join("base"), shared.join("base"))
        } else {
            fs::create_dir_all(shared.join("base")).unwrap();
            (
                lookup.operator.join("base").join(lang::PACK_FILE),
                shared.join("base").join(lang::PACK_FILE),
            )
        };
        std::os::unix::fs::symlink(outside, &link).unwrap();
        let layers = graph("packs = ['@box/base']", &lookup);
        fs::remove_file(link).unwrap();
        write_pack(&shared, "base", &shipped("base"));
        let mut observations = Observations::default();
        observations.packs(&layers);
        let value = snapshot(observations);
        assert_eq!(value["builtin_packs"], Value::Null);
        assert_eq!(value["has_custom_packs"], Value::Null);
    }
}

#[test]
fn contributing_packs_keep_each_accepted_launcher_once() {
    let temporary = tempfile::tempdir().unwrap();
    let shared = temporary.path().join("packs");
    for (name, extends) in [
        ("node", ""),
        ("npx", "extend = ['@box/node']\n"),
        ("uvx", ""),
    ] {
        let folder = shared.join(name);
        fs::create_dir_all(&folder).unwrap();
        fs::write(
            folder.join(PACK_FILE),
            format!(
                "[pack]\nname = '@box/{name}'\nversion = 1\nkind = 'tool'\n{extends}{}",
                lang::test_tool_pack(name, "").trim_start_matches("kind = \"tool\"\n")
            ),
        )
        .unwrap();
    }
    let lookup = Lookup {
        vendored: Some(shared.clone()),
        operator: temporary.path().join("operator"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let profile = Profile::parse(
        "packs = ['@box/node']\n[agent]\ncommand = []",
        Path::new("profile.toml"),
    )
    .unwrap();
    let layers = profile.layers(None, &lookup).unwrap();
    let launchers = lookup.launchers().unwrap();
    let original_npx = fs::read_to_string(shared.join("npx").join(PACK_FILE)).unwrap();
    fs::remove_dir_all(&shared).unwrap();
    let mut servers = Servers {
        detected: vec![Detected {
            installations: vec![],
            name: "accepted".into(),
            source: "host.json".into(),
            transport: Transport::Stdio {
                program: "npx".into(),
                program_path: "/host/npx".into(),
                launcher: Some(Box::new(Launcher {
                    pack: "@box/npx".into(),
                    hosts: vec![],
                    env: Default::default(),
                    read: vec![],
                    list: vec![],
                    deny: vec![],
                    cache: "/cache/npx".into(),
                })),
            },
            extended: false,
            variables: vec![],
            env: vec![],
            dropped: vec![],
            options: vec![],
        }],
        skipped: vec![Skipped {
            name: "rejected-uvx".into(),
            source: "host.json".into(),
            reason: "unavailable".into(),
        }],
        ..Servers::default()
    };
    let mut second = servers.detected[0].clone();
    second.name = "also-accepted".into();
    servers.detected.push(second);
    let packs: Vec<_> = contributing_packs(&layers, &launchers, &servers).collect();
    let names: Vec<_> = packs
        .iter()
        .filter(|layer| layer.shared)
        .map(|layer| layer.name.as_str())
        .collect();
    assert_eq!(names, ["@box/node", "@box/node", "@box/npx"]);
    assert!(packs.iter().any(|layer| !layer.shared));
    let npx = packs.iter().find(|layer| layer.name == "@box/npx").unwrap();
    assert_eq!(npx.text, original_npx);
    assert!(matches!(npx.location, PackLocation::Resources));
}
