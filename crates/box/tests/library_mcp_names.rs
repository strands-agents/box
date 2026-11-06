//! The library checks the namespaces used by MCP schema composition.

use strands_box::check_mcp_names;

#[test]
fn distinct_names_need_no_server_or_configuration() {
    check_mcp_names(&[]).unwrap();
    check_mcp_names(&["alpha", "beta", "box", "BOX"]).unwrap();
}

#[test]
fn normalized_names_cannot_share_a_namespace() {
    for names in [
        ["a-b", "a_b"],
        ["a.b", "a_b"],
        ["7-demo", "_7_demo"],
        ["if", "if_"],
        ["true", "true_"],
        ["__cedar", "__cedar_"],
        ["same", "same"],
    ] {
        let error = check_mcp_names(&names).unwrap_err().to_string();
        assert!(error.contains(names[0]), "{error}");
        assert!(error.contains(names[1]), "{error}");
        assert!(error.contains("namespace"), "{error}");
    }
}

#[test]
fn the_box_namespace_is_reserved() {
    let error = check_mcp_names(&["Box"]).unwrap_err().to_string();
    assert!(error.contains("reserved"), "{error}");
    assert!(error.contains("Box"), "{error}");
}

#[test]
fn name_checks_agree_with_schema_composition() {
    for names in [
        vec![],
        vec!["alpha", "beta"],
        vec!["a-b", "a_b"],
        vec!["Box"],
    ] {
        let schemas = names
            .iter()
            .map(|name| policy::generate_mcp_schema(name, r#"{"result":{"tools":[{"name":"read","description":"Read","inputSchema":{"type":"object","properties":{}}}]}}"#))
            .collect::<Result<Vec<_>, _>>();
        let composed = schemas.and_then(|schemas| {
            let named = names
                .iter()
                .zip(&schemas)
                .map(|(name, schema)| (*name, schema.as_str()))
                .collect::<Vec<_>>();
            policy::validate_mcp_schema_composition(&named)
        });
        assert_eq!(
            check_mcp_names(&names).is_ok(),
            composed.is_ok(),
            "{names:?}: {composed:?}"
        );
    }
}
