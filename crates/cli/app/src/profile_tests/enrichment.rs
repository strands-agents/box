//! `[enrichment.<name>]` compiled into `box.toml`, and what `box profile show` says about it.

use super::*;

/// One classification table, of Box Core's `in-memory` test kind.
const THREAT: &str = "[enrichment.threat]\nkind = \"in-memory\"\n\
                      endpoint = \"file:///srv/classification.json\"\noutputs = [\"malware\"]\n\
                      min_confidence = \"HIGH\"\n";

/// A profile's table reaches `box.toml` as written, and so does a pack's, with each key the
/// profile sets over the pack's.
#[test]
fn an_enrichment_table_reaches_box_toml_from_a_profile_or_a_pack() {
    let scene = Scene::new();
    let written: toml::Value = toml::from_str(THREAT).expect("TOML");
    let compiled = scene
        .compile(&profile(&format!("{MINIMAL}\n{THREAT}")), None)
        .expect("a compile");
    assert_eq!(table(&compiled)["enrichment"], written["enrichment"]);

    scene.share("classifier", THREAT);
    let compiled = scene
        .compile(
            &profile(&format!(
                "packs = [\"@box/classifier\"]\n{MINIMAL}\n[enrichment.threat]\n\
                 endpoint = \"file:///srv/mine.json\"\n"
            )),
            None,
        )
        .expect("a compile");
    let mut expected = written["enrichment"].clone();
    expected["threat"]["endpoint"] = "file:///srv/mine.json".into();
    assert_eq!(table(&compiled)["enrichment"], expected);
}

/// `box profile show` names each table and its kind, in text and in JSON, once Box Core accepts
/// the table, and Box Core's own message refuses a key the table does not take.
#[cfg(feature = "test-support")]
#[test]
fn show_names_each_enrichment_table_and_box_core_refuses_an_unknown_key() {
    let root = tempfile::tempdir().expect("a root");
    let home = root.path().canonicalize().expect("a canonical home");
    let workspace = home.join("project");
    std::fs::create_dir_all(&workspace).expect("a workspace");
    let folder = home.join(".strands/box/profiles/threat");
    std::fs::create_dir_all(&folder).expect("a profile folder");
    let write = |extra: &str| {
        std::fs::write(
            folder.join("profile.toml"),
            format!(
                "packs = [\"@box/base\"]\n\n[agent]\ncommand = [\"/usr/bin/true\"]\n\n\
                 {THREAT}{extra}"
            ),
        )
        .expect("a profile");
    };
    let launcher = Launcher::from_host()
        .home(&home)
        .search_path("/usr/bin:/bin")
        .environment(&[]);

    write("");
    let preview = launcher
        .preview("threat", &workspace)
        .unwrap_or_else(|error| panic!("Box Core accepts the table: {error}"));
    assert!(
        preview
            .overview()
            .contains(&("enrichment", "threat (kind \"in-memory\")".to_string())),
        "{:?}",
        preview.overview()
    );
    assert_eq!(
        preview.json("threat", false).expect("JSON")["enrichment"],
        serde_json::json!([{"name": "threat", "kind": "in-memory"}])
    );

    write("colour = \"red\"\n");
    match launcher.preview("threat", &workspace) {
        Err(error @ Error::PolicyCheck { .. }) => assert!(
            error.to_string().contains("unknown field `colour`"),
            "{error}"
        ),
        other => panic!("Box Core refuses the key, not {other:?}"),
    }
}
