use std::path::PathBuf;

use super::*;

/// A box home whose `external/` can hold collections.
struct Fixture {
    _directory: tempfile::TempDir,
    box_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let box_home = std::fs::canonicalize(directory.path())
            .expect("a real path")
            .join("box");
        std::fs::create_dir_all(&box_home).expect("a box home");
        Self {
            _directory: directory,
            box_home,
        }
    }

    /// The collection folder `external/<name>`, with `text` as its `collection.toml` if any.
    fn collection(&self, name: &str, text: Option<&str>) -> PathBuf {
        let root = self.box_home.join(EXTERNAL).join(name);
        std::fs::create_dir_all(&root).expect("a collection folder");
        if let Some(text) = text {
            std::fs::write(root.join(COLLECTION_FILE), text).expect("collection.toml");
        }
        root
    }

    fn listed(&self) -> Result<Vec<Collection>, String> {
        listed(&self.box_home).map_err(|error| error.to_string())
    }
}

#[test]
fn no_external_folder_lists_no_collection() {
    let fixture = Fixture::new();
    assert_eq!(fixture.listed(), Ok(Vec::new()));
    std::fs::create_dir_all(fixture.box_home.join(EXTERNAL)).expect("external/");
    assert_eq!(fixture.listed(), Ok(Vec::new()));
}

#[test]
fn each_folder_in_external_is_a_collection_named_by_the_folder_in_name_order() {
    let fixture = Fixture::new();
    let tools = fixture.collection("acme-tools", None);
    let acme = fixture.collection("acme", Some(""));
    std::fs::create_dir_all(fixture.box_home.join("external/.git")).expect("a hidden folder");
    std::fs::write(fixture.box_home.join("external/.DS_Store"), "").expect("a hidden file");
    assert_eq!(
        fixture.listed(),
        Ok(vec![
            Collection {
                scope: "acme".to_string(),
                root: acme,
            },
            Collection {
                scope: "acme-tools".to_string(),
                root: tools,
            },
        ])
    );
}

#[test]
fn external_refuses_a_link_a_file_and_a_bad_name() {
    for (setup, error) in [
        (
            "link",
            "a collection is a symbolic link; clone the repository into external/",
        ),
        ("file", "external/ holds only collection folders"),
        ("Acme", "\"Acme\" is not a collection name"),
        ("-acme", "\"-acme\" is not a collection name"),
        ("a.b", "\"a.b\" is not a collection name"),
        ("box", "a collection can't be called box"),
    ] {
        let fixture = Fixture::new();
        let external = fixture.box_home.join(EXTERNAL);
        std::fs::create_dir_all(&external).expect("external/");
        match setup {
            "link" => {
                let real = fixture.box_home.join("elsewhere");
                std::fs::create_dir_all(&real).expect("a folder");
                std::os::unix::fs::symlink(&real, external.join("acme")).expect("a link");
            }
            "file" => std::fs::write(external.join("acme"), "").expect("a file"),
            name => {
                fixture.collection(name, None);
            }
        }
        let found = fixture.listed().expect_err(setup);
        assert!(found.contains(error), "{setup}: {found}");
    }
}

#[test]
fn a_collection_adds_only_its_own_names_and_removes_only_shipped_ones() {
    let fixture = Fixture::new();
    let root = fixture.collection(
        "acme",
        Some(
            "[starters]\nadd = [\"@acme/claude\"]\nremove = [\"@box/claude\"]\n\
             [policy-starters]\nadd = [\"@acme/team\"]\nremove = [\"@box/open\"]\n\
             default = \"@acme/team\"\n",
        ),
    );
    let collection = Collection {
        scope: "acme".to_string(),
        root: root.clone(),
    };
    assert_eq!(
        read(&collection).expect("read"),
        Menus {
            starters_add: vec!["@acme/claude".to_string()],
            starters_remove: vec!["@box/claude".to_string()],
            policies_add: vec!["@acme/team".to_string()],
            policies_remove: vec!["@box/open".to_string()],
            policies_default: Some("@acme/team".to_string()),
        }
    );
    std::fs::remove_file(root.join(COLLECTION_FILE)).expect("remove");
    assert_eq!(read(&collection).expect("no file"), Menus::default());
    for (text, error) in [
        ("name = \"@acme\"\n", "the unknown key `name`"),
        (
            "[starters]\nadd = [\"claude\"]\n",
            "a collection adds only its own",
        ),
        (
            "[starters]\nadd = [\"@other/claude\"]\n",
            "a collection adds only its own",
        ),
        (
            "[starters]\nremove = [\"claude\"]\n",
            "a collection removes only what box ships",
        ),
        (
            "[starters]\nremove = [\"@acme/x\"]\n",
            "a collection removes only what box ships",
        ),
        (
            "[starters]\nonly = [\"@acme/x\"]\n",
            "`[starters]` holds the unknown key `only`",
        ),
        (
            "[starters]\ndefault = \"@acme/x\"\n",
            "`[starters]` holds the unknown key `default`",
        ),
        (
            "[policy-starters]\nonly = []\n",
            "`[policy-starters]` holds the unknown key `only`",
        ),
        (
            "[policy-starters]\ndefault = 1\n",
            "`[policy-starters] default` is not a name",
        ),
        ("not toml [", "collection.toml"),
    ] {
        std::fs::write(root.join(COLLECTION_FILE), text).expect("collection.toml");
        let found = read(&collection).expect_err(text).to_string();
        assert!(found.contains(error), "{text}: {found}");
    }
}
