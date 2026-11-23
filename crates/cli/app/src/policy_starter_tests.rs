use std::path::PathBuf;

use super::*;

/// A resources root with two policy starters, `@box/open` and `@box/shut`, and a box home.
struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    lookup: Lookup,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().to_path_buf();
        std::fs::create_dir_all(root.join("resources/packs")).expect("packs");
        let fixture = Self {
            lookup: Lookup {
                vendored: Some(root.join("resources/packs")),
                operator: root.join("home/.strands/box/packs"),
                collections: Vec::new(),
                version: crate::VERSION,
            },
            _directory: directory,
            root,
        };
        fixture.policy(
            "open",
            "@box/open",
            "Open",
            "Any host.",
            "@id(\"o\") permit (principal, action, resource);\n",
        );
        fixture.policy("shut", "@box/shut", "Shut", "No host.", "");
        fixture.built_in(
            "[starters]\nonly = []\n\n[policy-starters]\nonly = [\"@box/open\", \"@box/shut\"]\n\
             default = \"@box/open\"\n",
        );
        fixture
    }

    fn policy(&self, folder: &str, name: &str, label: &str, description: &str, rules: &str) {
        let folder = self.root.join("resources").join(POLICIES).join(folder);
        std::fs::create_dir_all(&folder).expect("a policy folder");
        std::fs::write(
            folder.join(STARTER_FILE),
            format!(
                "[policy]\nname = {name:?}\nlabel = {label:?}\ndescription = {description:?}\n"
            ),
        )
        .expect("policy.toml");
        std::fs::write(folder.join(RULES_FILE), rules).expect("policy.dw");
    }

    fn own_policy(&self, folder: &str, name: &str, label: &str) {
        let folder = self
            .root
            .join("home/.strands/box")
            .join(POLICIES)
            .join(folder);
        std::fs::create_dir_all(&folder).expect("a policy folder");
        std::fs::write(
            folder.join(STARTER_FILE),
            format!("[policy]\nname = {name:?}\nlabel = {label:?}\ndescription = \"Mine.\"\n"),
        )
        .expect("policy.toml");
        std::fs::write(folder.join(RULES_FILE), "// mine\n").expect("policy.dw");
    }

    fn built_in(&self, text: &str) {
        std::fs::write(self.root.join("resources").join(CONFIG_FILE), text).expect("config");
    }

    fn config(&self, text: &str) {
        std::fs::create_dir_all(self.root.join("home/.strands/box")).expect("box home");
        std::fs::write(self.root.join("home/.strands/box").join(CONFIG_FILE), text)
            .expect("config");
    }

    fn menu(&self) -> Result<PolicyMenu, Error> {
        PolicyMenu::load(&self.lookup)
    }

    fn names(&self) -> (Vec<String>, String) {
        let menu = self.menu().expect("a menu");
        let names = menu.starters.iter().map(|s| s.name.clone()).collect();
        (names, menu.starters[menu.default].name.clone())
    }
}

#[derive(Default)]
struct Call<'a> {
    given: Option<&'a str>,
    interactive: bool,
    input: &'a str,
    exists: bool,
}

fn choose_with(menu: &PolicyMenu, call: Call<'_>) -> Result<(String, String), Error> {
    let mut input = call.input.as_bytes();
    let mut output = Vec::new();
    let mut terminal = Terminal::new(&mut input, &mut output);
    let chosen = choose(
        menu,
        &Request {
            command: "box profile create mine",
            given: call.given,
            path: Path::new("profile.toml"),
            exists: call.exists,
        },
        call.interactive.then_some(&mut terminal),
    )?;
    Ok((chosen, String::from_utf8(output).expect("text")))
}

#[test]
fn the_menu_is_the_built_in_list_and_default_and_the_operator_replaces_each() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.names(),
        (
            vec!["@box/open".into(), "@box/shut".into()],
            "@box/open".into()
        )
    );
    fixture.config("[policy-starters]\ndefault = \"@box/shut\"\n");
    assert_eq!(
        fixture.names(),
        (
            vec!["@box/open".into(), "@box/shut".into()],
            "@box/shut".into()
        )
    );
    fixture.config("[policy-starters]\nonly = [\"@box/shut\"]\ndefault = \"@box/shut\"\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/shut".into()], "@box/shut".into())
    );
    fixture.config("[policy-starters]\nonly = [\"@box/shut\"]\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/shut".into()], "@box/shut".into()),
        "a list without the built-in default starts at its first entry"
    );
    fixture.config("[policy-starters]\nonly = [\"@box/shut\", \"@box/open\"]\n");
    assert_eq!(
        fixture.names().1,
        "@box/open",
        "a list that holds the built-in default keeps it"
    );
    fixture.config("[starters]\nadd = []\n");
    assert_eq!(
        fixture.names().1,
        "@box/open",
        "no table keeps the built-in one"
    );
}

#[test]
fn the_menu_refuses_each_bad_policy_starters_table() {
    let fixture = Fixture::new();
    for (config, reason) in [
        (
            "[policy-starters]\nkeep = [\"@box/open\"]\n",
            "`[policy-starters]` holds the unknown key `keep`; it holds `only`, `add`, `remove`, \
             and `default`",
        ),
        (
            "[policy-starters]\nonly = [\"@box/open\"]\nadd = [\"@box/shut\"]\n",
            "`[policy-starters]` holds `only` with `add` or `remove`; `only` is the whole list",
        ),
        (
            "[policy-starters]\nadd = [\"team_hosts\"]\n",
            "`[policy-starters] add`: \"team_hosts\" is not a policy name; a policy folder name \
             uses lowercase letters, digits, and -",
        ),
        (
            "[policy-starters]\nadd = [\"@box/open\"]\n",
            "`[policy-starters] add` names @box/open, which is already listed",
        ),
        (
            "[policy-starters]\nremove = [\"@box/gone\"]\n",
            "`[policy-starters] remove` names @box/gone, which is not in the policy menu; the \
             menu offers @box/open, @box/shut",
        ),
        (
            "[policy-starters]\nremove = [\"@box/open\", \"@box/shut\"]\n",
            "`[policy-starters]` lists no policy starter",
        ),
        (
            "[policy-starters]\nonly = [\"@box/shut\"]\ndefault = \"@box/open\"\n",
            "`[policy-starters] default` is @box/open, which is not in the list; the list is \
             @box/shut",
        ),
        (
            "[policy-starters]\nonly = []\n",
            "`[policy-starters]` lists no policy starter",
        ),
        (
            "[policy-starters]\nonly = [\"@box/open\", \"@box/open\"]\n",
            "`[policy-starters] only` names @box/open twice",
        ),
        (
            "[policy-starters]\nonly = [\"@box/gone\"]\n",
            "box ships no policy named @box/gone",
        ),
        (
            "[policy-starters]\nonly = [\"mine\"]\n",
            "`[policy-starters] only`: no policy named mine; neither ",
        ),
        (
            "[policy-starters]\ndefault = 1\n",
            "`[policy-starters] default` is not a policy name",
        ),
    ] {
        fixture.config(config);
        let error = fixture.menu().expect_err(config);
        assert!(matches!(error, Error::Config { .. }), "{error}");
        assert!(error.to_string().contains(reason), "{config}: {error}");
    }
}

#[test]
fn a_policy_starter_name_is_box_and_a_plain_short_name_that_matches_its_folder() {
    let fixture = Fixture::new();
    for name in [
        "@box/",
        "box/open",
        "@box/../open",
        "@box/Open",
        "@box/a/b",
        "Open",
        "../open",
        "acme/x",
    ] {
        let error = PolicyStarter::load(name, &fixture.lookup).expect_err(name);
        assert!(error.contains("is not a policy name"), "{name}: {error}");
    }
    let error = PolicyStarter::load("open", &fixture.lookup).expect_err("no own policy");
    assert!(error.contains("no policy named open; "), "{error}");
    fixture.policy("other", "@box/open", "Other", "Other.", "");
    let error = PolicyStarter::load("@box/other", &fixture.lookup).expect_err("a wrong name");
    assert!(
        error.contains("`[policy] name` is \"@box/open\", and the folder holds @box/other"),
        "{error}"
    );
    let starter = PolicyStarter::load("@box/open", &fixture.lookup).expect("@box/open");
    assert_eq!(
        (
            starter.label.as_str(),
            starter.description.as_str(),
            starter.flag_name()
        ),
        ("Open", "Any host.", "open")
    );
    assert!(starter.rules().expect("rules").contains("@id(\"o\")"));
}

#[test]
fn a_policy_starter_refuses_an_unknown_key_and_an_empty_label() {
    let fixture = Fixture::new();
    let folder = fixture.root.join("resources/policies/odd");
    std::fs::create_dir_all(&folder).expect("a folder");
    for (text, reason) in [
        (
            "[policy]\nname = \"@box/odd\"\nlabel = \"Odd\"\ndescription = \"Odd.\"\nrules = 1\n",
            "`[policy]` holds the unknown key `rules`",
        ),
        (
            "[policy]\nname = \"@box/odd\"\nlabel = \" \"\ndescription = \"Odd.\"\n",
            "`[policy] label` is not a nonempty string",
        ),
        (
            "[pack]\nname = \"@box/odd\"\n",
            "the unknown key `pack`; a policy starter holds `[policy]`",
        ),
    ] {
        std::fs::write(folder.join(STARTER_FILE), text).expect("policy.toml");
        let error = PolicyStarter::load("@box/odd", &fixture.lookup).expect_err(text);
        assert!(error.contains(reason), "{error}");
    }
}

#[test]
fn a_policy_starter_names_the_project_access_it_gives() {
    let fixture = Fixture::new();
    let folder = fixture.root.join("resources/policies/odd");
    std::fs::create_dir_all(&folder).expect("a folder");
    let header = "[policy]\nname = \"@box/odd\"\nlabel = \"Odd\"\ndescription = \"Odd.\"\n";
    for (line, expected) in [
        ("", None),
        ("project = \"none\"\n", Some(ProjectAccess::None)),
        ("project = \"read\"\n", Some(ProjectAccess::Read)),
        ("project = \"write\"\n", Some(ProjectAccess::Write)),
    ] {
        std::fs::write(folder.join(STARTER_FILE), format!("{header}{line}")).expect("policy.toml");
        let starter = PolicyStarter::load("@box/odd", &fixture.lookup).expect(line);
        assert_eq!(starter.project, expected, "{line}");
    }
    for line in ["project = \"rw\"\n", "project = true\n"] {
        std::fs::write(folder.join(STARTER_FILE), format!("{header}{line}")).expect("policy.toml");
        let error = PolicyStarter::load("@box/odd", &fixture.lookup).expect_err(line);
        assert!(
            error.contains("`[policy] project` is one of \"none\", \"read\", \"write\""),
            "{line}: {error}"
        );
        assert!(
            error.starts_with(&folder.join(STARTER_FILE).display().to_string()),
            "{line}: {error}"
        );
    }
}

#[test]
fn each_shipped_policy_starter_names_its_project_access() {
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: PathBuf::from("/nonexistent/.strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    for (name, access) in [
        ("@box/open", ProjectAccess::Write),
        ("@box/scoped", ProjectAccess::Write),
        ("@box/locked", ProjectAccess::Read),
    ] {
        let starter = PolicyStarter::load(name, &lookup).expect(name);
        assert_eq!(starter.project, Some(access), "{name}");
    }
}

#[test]
fn policy_names_a_starter_by_its_short_or_full_name_and_refuses_another() {
    let fixture = Fixture::new();
    let menu = fixture.menu().expect("a menu");
    for given in ["shut", "@box/shut"] {
        let (chosen, output) = choose_with(
            &menu,
            Call {
                given: Some(given),
                interactive: true,
                exists: true,
                ..Call::default()
            },
        )
        .expect(given);
        assert_eq!((chosen.as_str(), output.as_str()), ("@box/shut", ""));
    }
    let error = choose_with(
        &menu,
        Call {
            given: Some("closed"),
            ..Call::default()
        },
    )
    .expect_err("an unknown policy");
    assert_eq!(
        error.to_string(),
        "profile.toml: `--policy` names \"closed\", which is not a policy starter; the policy \
         starters are open, shut"
    );
}

#[test]
fn without_a_terminal_and_without_policy_the_step_stops_and_names_each_flag() {
    let fixture = Fixture::new();
    let error =
        choose_with(&fixture.menu().expect("a menu"), Call::default()).expect_err("unanswered");
    assert_eq!(
        error.to_string(),
        "box profile create mine needs an answer to \"Which policy should the agent start \
         with?\"\n  --policy open   Open\n  --policy shut   Shut"
    );
}

#[test]
fn at_a_terminal_enter_picks_the_default_and_a_number_picks_its_policy() {
    let fixture = Fixture::new();
    fixture.config("[policy-starters]\ndefault = \"@box/shut\"\n");
    let menu = fixture.menu().expect("a menu");
    let (chosen, output) = choose_with(
        &menu,
        Call {
            interactive: true,
            input: "\n",
            ..Call::default()
        },
    )
    .expect("enter");
    assert_eq!(chosen, "@box/shut");
    assert_eq!(
        output,
        "Which policy should the agent start with?\n  1. Open: Any host.\n  2. Shut: No host.\n\
         > [2] "
    );
    let (chosen, output) = choose_with(
        &menu,
        Call {
            interactive: true,
            input: "3\nx\n1\n",
            ..Call::default()
        },
    )
    .expect("a number");
    assert_eq!(chosen, "@box/open");
    assert_eq!(
        output.matches("Type a number from 1 to 2.").count(),
        2,
        "{output}"
    );
    let error = choose_with(
        &menu,
        Call {
            interactive: true,
            ..Call::default()
        },
    )
    .expect_err("end of input");
    assert!(matches!(error, Error::StarterAborted { .. }), "{error}");
}

#[test]
fn an_existing_profile_is_refused_before_the_policy_prompt() {
    let fixture = Fixture::new();
    let error = choose_with(
        &fixture.menu().expect("a menu"),
        Call {
            interactive: true,
            input: "1\n",
            exists: true,
            ..Call::default()
        },
    )
    .expect_err("exists");
    assert!(matches!(error, Error::Exists { .. }), "{error}");
}

#[test]
fn the_shipped_menu_offers_open_by_default_then_project() {
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: PathBuf::from("/nonexistent/.strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let menu = PolicyMenu::load(&lookup).expect("the shipped menu");
    let names: Vec<&str> = menu.starters.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["@box/open", "@box/scoped", "@box/locked"]);
    assert_eq!(menu.starters[menu.default].name, "@box/open");
    assert!(
        menu.starters[0].description.ends_with("but not localhost."),
        "{}",
        menu.starters[0].description
    );
    let open = menu.starters[0].rules().expect("open rules");
    for id in [
        "open_connect",
        "open_request",
        "open_loopback",
        "open_link_local",
    ] {
        assert!(open.contains(&format!("@id(\"{id}\")")), "{open}");
    }
    for starter in &menu.starters {
        let rules = starter.rules().expect("rules");
        assert!(
            !rules.contains("@id(\"metadata_"),
            "{}: {rules}",
            starter.name
        );
        for id in ["shell_commands", "dev_null"] {
            let rule = format!("@id(\"{id}\")");
            let expected = usize::from(starter.name != "@box/locked" || id == "dev_null");
            assert_eq!(
                rules.lines().filter(|line| *line == rule).count(),
                expected,
                "{}: {id} in {rules}",
                starter.name
            );
        }
        let lines: Vec<&str> = rules.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if line.starts_with("@id(") {
                assert!(
                    index > 0 && lines[index - 1].starts_with("// "),
                    "{}: a comment before {line}: {rules}",
                    starter.name
                );
            }
        }
    }
    let link_local = open
        .split("@id(\"open_link_local\")\n")
        .nth(1)
        .and_then(|rest| rest.split("};").next())
        .expect("the link-local forbid");
    assert!(
        link_local.starts_with("forbid (principal, action == Box::Action::\"net:connect\"")
            && link_local.contains(r#"context.input.ip4 like "169.254.*""#)
            && ["fe8*", "fe9*", "fea*", "feb*"]
                .iter()
                .all(|prefix| link_local.contains(&format!("context.input.ip6 like \"{prefix}\""))),
        "{link_local}"
    );
    let project = menu.starters[1].rules().expect("project rules");
    assert!(!project.contains("169.254"), "{project}");
    assert!(
        !project.contains("\npermit (principal, action == Box::Action::\"net:connect\"")
            && !project.contains("\npermit (principal, action == Box::Action::\"http:request\""),
        "{project}"
    );
    assert!(project.contains("\n// @id(\""), "{project}");
    let locked = menu.starters[2].rules().expect("locked rules");
    assert!(
        locked
            .lines()
            .filter(|line| line.starts_with("permit"))
            .all(|line| line.contains("\"fs:read\"")),
        "{locked}"
    );
    assert!(locked.contains("// @id(\"shell_commands\")"), "{locked}");
    assert!(project.contains("\n// permit ("), "{project}");
}

#[test]
fn a_copy_names_its_policy_starter_then_holds_its_rules() {
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: PathBuf::from("/nonexistent/.strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let open = PolicyStarter::load("@box/open", &lookup).expect("@box/open");
    let copy = open.copy().expect("a copy");
    assert_eq!(
        copy,
        format!(
            "// Copied from @box/open (Open) by `box profile create`. This file is yours: \
             only\n// `box profile create --force` replaces it. Edit the rules here, and the next run\n\
             // uses them.\n\n{}",
            open.rules().expect("rules")
        )
    );
}

#[test]
fn an_own_policy_starter_is_a_plain_name_in_the_box_home() {
    let fixture = Fixture::new();
    fixture.own_policy("team", "team", "Team");
    let team = PolicyStarter::load("team", &fixture.lookup).expect("team");
    assert_eq!((team.name.as_str(), team.flag_name()), ("team", "team"));
    assert_eq!(team.rules().expect("rules"), "// mine\n");
    assert!(
        team.copy()
            .expect("a copy")
            .starts_with("// Copied from team (Team) ")
    );
    assert_eq!(full_name("team", &fixture.lookup), "team");
    assert_eq!(full_name("shut", &fixture.lookup), "@box/shut");
    assert_eq!(full_name("@box/team", &fixture.lookup), "@box/team");
    fixture.own_policy("wrong", "@box/wrong", "Wrong");
    let error = PolicyStarter::load("wrong", &fixture.lookup).expect_err("an @box/ name");
    assert!(
        error.contains("`[policy] name` is \"@box/wrong\", and the folder holds wrong"),
        "{error}"
    );
}

#[test]
fn the_operator_adds_and_removes_policy_starters() {
    let fixture = Fixture::new();
    fixture.own_policy("team", "team", "Team");
    fixture.config("[policy-starters]\nadd = [\"team\"]\nremove = [\"shut\"]\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/open".into(), "team".into()], "@box/open".into())
    );
    fixture.config("[policy-starters]\nremove = [\"@box/open\"]\nadd = [\"team\"]\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/shut".into(), "team".into()], "@box/shut".into()),
        "a list without the built-in default starts at its first entry"
    );
    fixture.config("[policy-starters]\nadd = [\"team\"]\ndefault = \"team\"\n");
    assert_eq!(fixture.names().1, "team");
}

#[test]
fn an_own_policy_starter_with_a_shipped_name_wins_and_the_shipped_one_keeps_box() {
    let fixture = Fixture::new();
    fixture.own_policy("open", "open", "My open");
    fixture.config("[policy-starters]\nadd = [\"open\"]\n");
    let menu = fixture.menu().expect("a menu");
    let flags: Vec<(&str, &str)> = menu
        .starters
        .iter()
        .map(|starter| (starter.name.as_str(), starter.flag_name()))
        .collect();
    assert_eq!(
        flags,
        [
            ("@box/open", "@box/open"),
            ("@box/shut", "shut"),
            ("open", "open")
        ]
    );
    for (given, chosen) in [("open", "open"), ("@box/open", "@box/open")] {
        let (picked, _) = choose_with(
            &menu,
            Call {
                given: Some(given),
                ..Call::default()
            },
        )
        .expect(given);
        assert_eq!(picked, chosen);
    }
}

#[test]
fn policy_names_an_own_policy_starter_only_when_the_menu_lists_it() {
    let fixture = Fixture::new();
    fixture.own_policy("team", "team", "Team");
    let error = choose_with(
        &fixture.menu().expect("a menu"),
        Call {
            given: Some("team"),
            ..Call::default()
        },
    )
    .expect_err("not listed");
    assert!(
        error.to_string().contains("which is not a policy starter"),
        "{error}"
    );
    fixture.config("[policy-starters]\nadd = [\"team\"]\n");
    let (picked, _) = choose_with(
        &fixture.menu().expect("a menu"),
        Call {
            given: Some("team"),
            ..Call::default()
        },
    )
    .expect("listed");
    assert_eq!(picked, "team");
}

#[test]
fn an_own_policy_folder_without_policy_toml_claims_its_name_and_never_falls_back_to_box() {
    let fixture = Fixture::new();
    let folder = fixture
        .root
        .join("home/.strands/box")
        .join(POLICIES)
        .join("open");
    std::fs::create_dir_all(&folder).expect("a policy folder");
    std::fs::write(folder.join(RULES_FILE), "// mine\n").expect("policy.dw");
    // Not `Policy.toml`: macOS folders ignore case, so that one would be found as policy.toml.
    std::fs::write(folder.join("policy.tml"), "[policy]\n").expect("a misnamed policy.toml");
    assert_eq!(full_name("open", &fixture.lookup), "open");
    let error = PolicyStarter::find("open", &fixture.lookup).expect_err("no policy.toml");
    assert!(
        error.contains("no policy named open; ") && error.contains("open/policy.toml is missing"),
        "{error}"
    );
    let error = choose_with(
        &fixture.menu().expect("a menu"),
        Call {
            given: Some("open"),
            ..Call::default()
        },
    )
    .expect_err("the shipped open is @box/open now");
    assert!(
        error.to_string().contains("which is not a policy starter"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn a_broken_link_in_the_own_policy_folder_claims_its_name_and_never_falls_back_to_box() {
    let fixture = Fixture::new();
    let root = fixture.root.join("home/.strands/box").join(POLICIES);
    std::fs::create_dir_all(&root).expect("the policies folder");
    std::os::unix::fs::symlink(fixture.root.join("gone"), root.join("open")).expect("a link");
    assert_eq!(full_name("open", &fixture.lookup), "open");
    let error = PolicyStarter::find("open", &fixture.lookup).expect_err("a broken link");
    assert!(error.contains("is a symbolic link"), "{error}");
}

#[cfg(unix)]
#[test]
fn a_linked_own_policy_starter_is_refused_so_a_box_cannot_write_its_rules() {
    let fixture = Fixture::new();
    let root = fixture.root.join("home/.strands/box").join(POLICIES);
    std::fs::create_dir_all(&root).expect("the policies folder");
    let workspace = fixture.root.join("work/team-policy");
    std::fs::create_dir_all(&workspace).expect("a folder a box can write");
    std::fs::write(
        workspace.join(STARTER_FILE),
        "[policy]\nname = \"team\"\nlabel = \"Team\"\ndescription = \"Team.\"\n",
    )
    .expect("policy.toml");
    std::fs::write(
        workspace.join(RULES_FILE),
        "permit (principal, action, resource);\n",
    )
    .expect("policy.dw");
    std::os::unix::fs::symlink(&workspace, root.join("team")).expect("a linked folder");
    let error = PolicyStarter::find("team", &fixture.lookup).expect_err("a linked folder");
    assert!(error.contains("is a symbolic link"), "{error}");

    std::fs::remove_file(root.join("team")).expect("the link removed");
    let folder = root.join("team");
    std::fs::create_dir(&folder).expect("a real folder");
    std::os::unix::fs::symlink(workspace.join(STARTER_FILE), folder.join(STARTER_FILE))
        .expect("a linked policy.toml");
    std::fs::write(folder.join(RULES_FILE), "// mine\n").expect("policy.dw");
    let error = PolicyStarter::find("team", &fixture.lookup).expect_err("a linked policy.toml");
    assert!(error.contains("a symbolic link"), "{error}");

    std::fs::remove_file(folder.join(STARTER_FILE)).expect("the link removed");
    std::fs::copy(workspace.join(STARTER_FILE), folder.join(STARTER_FILE)).expect("policy.toml");
    std::fs::remove_file(folder.join(RULES_FILE)).expect("policy.dw removed");
    std::os::unix::fs::symlink(workspace.join(RULES_FILE), folder.join(RULES_FILE))
        .expect("a linked policy.dw");
    let starter = PolicyStarter::find("team", &fixture.lookup).expect("policy.toml is real");
    let error = starter.copy().expect_err("a linked policy.dw");
    assert!(error.contains("a symbolic link"), "{error}");

    std::fs::remove_file(folder.join(RULES_FILE)).expect("the link removed");
    std::fs::hard_link(workspace.join(RULES_FILE), folder.join(RULES_FILE))
        .expect("a hard-linked policy.dw");
    let error = starter.copy().expect_err("a hard-linked policy.dw");
    assert!(error.contains("exactly one hard link"), "{error}");
    std::fs::remove_file(folder.join(RULES_FILE)).expect("the hard link removed");
    std::fs::hard_link(
        folder.join(STARTER_FILE),
        workspace.join("policy.toml.copy"),
    )
    .expect("a hard-linked policy.toml");
    let error =
        PolicyStarter::find("team", &fixture.lookup).expect_err("a hard-linked policy.toml");
    assert!(error.contains("exactly one hard link"), "{error}");
}

#[test]
fn a_collection_adds_and_removes_policy_starters_and_the_operator_still_wins() {
    let mut fixture = Fixture::new();
    let root = fixture.root.join("org/box");
    let folder = root.join(POLICIES).join("team");
    std::fs::create_dir_all(&folder).expect("a policy folder");
    std::fs::write(
        folder.join(STARTER_FILE),
        "[policy]\nname = \"@acme/team\"\nlabel = \"Team\"\ndescription = \"Acme's.\"\n",
    )
    .expect("policy.toml");
    std::fs::write(folder.join(RULES_FILE), "// team\n").expect("policy.dw");
    let collection = |text: &str| {
        std::fs::write(
            root.join(crate::collection::COLLECTION_FILE),
            format!("[policy-starters]\n{text}"),
        )
        .expect("collection.toml");
    };
    fixture.lookup.collections.push(crate::lang::Collection {
        scope: "acme".into(),
        root: root.clone(),
    });
    collection("add = [\"@acme/team\"]\n");
    assert_eq!(
        fixture.names(),
        (
            vec!["@box/open".into(), "@box/shut".into(), "@acme/team".into()],
            "@box/open".into()
        )
    );
    let menu = fixture.menu().expect("a menu");
    let team = menu.named("@acme/team").expect("the collection's policy");
    assert_eq!(team.label, "Team");
    assert_eq!(team.flag_name(), "@acme/team");
    collection("add = [\"@acme/team\"]\nremove = [\"@box/shut\"]\ndefault = \"@acme/team\"\n");
    assert_eq!(
        fixture.names(),
        (
            vec!["@box/open".into(), "@acme/team".into()],
            "@acme/team".into()
        )
    );
    fixture.config("[policy-starters]\ndefault = \"@box/open\"\n");
    assert_eq!(
        fixture.names().1,
        "@box/open",
        "the operator's default wins"
    );
    fixture.config("[policy-starters]\nremove = [\"@acme/team\"]\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/open".into()], "@box/open".into()),
        "the operator removes what a collection adds"
    );
    fixture.config("[policy-starters]\nonly = [\"@box/shut\"]\n");
    assert_eq!(fixture.names().0, vec!["@box/shut".to_string()]);
    fixture.config("");
    collection("remove = [\"@box/none\"]\n");
    let error = fixture.menu().expect_err("an unknown removal").to_string();
    assert!(
        error.contains("collection.toml") && error.contains("names @box/none"),
        "{error}"
    );
    collection("add = [\"@acme/none\"]\n");
    let error = fixture.menu().expect_err("a missing policy").to_string();
    assert!(
        error.contains("collection.toml") && error.contains("@acme/none"),
        "{error}"
    );
}

#[test]
fn collections_apply_in_their_listed_order_and_a_later_default_wins() {
    let mut fixture = Fixture::new();
    for scope in ["acme", "beta"] {
        let root = fixture.root.join(scope);
        let folder = root.join(POLICIES).join("team");
        std::fs::create_dir_all(&folder).expect("a policy folder");
        std::fs::write(
            folder.join(STARTER_FILE),
            format!("[policy]\nname = \"@{scope}/team\"\nlabel = \"T\"\ndescription = \"D.\"\n"),
        )
        .expect("policy.toml");
        std::fs::write(folder.join(RULES_FILE), "").expect("policy.dw");
        std::fs::write(
            root.join(crate::collection::COLLECTION_FILE),
            format!(
                "[policy-starters]\nadd = [\"@{scope}/team\"]\n\
                 default = \"@{scope}/team\"\n"
            ),
        )
        .expect("collection.toml");
        fixture.lookup.collections.push(crate::lang::Collection {
            scope: scope.into(),
            root,
        });
    }
    assert_eq!(
        fixture.names(),
        (
            vec![
                "@box/open".into(),
                "@box/shut".into(),
                "@acme/team".into(),
                "@beta/team".into()
            ],
            "@beta/team".into()
        )
    );
    fixture.lookup.collections.reverse();
    assert_eq!(
        fixture.names(),
        (
            vec![
                "@box/open".into(),
                "@box/shut".into(),
                "@beta/team".into(),
                "@acme/team".into()
            ],
            "@acme/team".into()
        )
    );
}

#[test]
fn a_repeated_remove_changes_nothing_and_a_removed_default_starts_at_the_first_entry() {
    let mut fixture = Fixture::new();
    let root = fixture.root.join("acme");
    std::fs::create_dir_all(&root).expect("a collection");
    std::fs::write(
        root.join(crate::collection::COLLECTION_FILE),
        "[policy-starters]\nremove = [\"@box/open\"]\n",
    )
    .expect("collection.toml");
    fixture.lookup.collections.push(crate::lang::Collection {
        scope: "acme".into(),
        root,
    });
    assert_eq!(
        fixture.names(),
        (vec!["@box/shut".into()], "@box/shut".into()),
        "a collection that removes the default and names none starts at the first entry"
    );
    fixture.config("[policy-starters]\nremove = [\"@box/open\"]\n");
    assert_eq!(
        fixture.names(),
        (vec!["@box/shut".into()], "@box/shut".into()),
        "the operator may remove what a collection already removed"
    );
    fixture.config("[policy-starters]\nremove = [\"@box/opne\"]\n");
    let error = fixture.menu().expect_err("a typo").to_string();
    assert!(
        error.contains("names @box/opne, which is not in the policy menu"),
        "{error}"
    );
}
