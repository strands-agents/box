use std::path::PathBuf;

use super::*;
use crate::lang::VENDORED;

/// A pack root on disk: the packs `box` ships, the operator's packs, and both `config.toml` files.
struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    lookup: Lookup,
}

const PROVIDER: &str = r#"
[pack]
name = "@box/cloud"
version = 1
kind = "support"

[inputs.cloud.region]
description = "The region."
pattern = "[a-z]+-[0-9]"
default = "east-1"

[inputs.cloud.account]
description = "The account."
"#;

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().to_path_buf();
        let lookup = Lookup {
            vendored: Some(root.join("resources/packs")),
            operator: root.join("home/.strands/box/packs"),
            collections: Vec::new(),
            version: crate::VERSION,
        };
        let fixture = Self {
            _directory: directory,
            root,
            lookup,
        };
        fixture.built_in("[starters]\nonly = [\"@box/agent\"]\n");
        for pack in [
            "@box/local",
            "@box/github",
            "@box/proxy-us",
            "@box/proxy-eu",
        ] {
            fixture.pack(
                pack,
                &format!("[pack]\nname = \"{pack}\"\nversion = 1\nkind = \"support\"\n"),
            );
        }
        fixture.pack("@box/cloud", PROVIDER);
        fixture
    }

    fn pack(&self, name: &str, text: &str) {
        let folder = match name.strip_prefix(VENDORED) {
            Some(short) => self.root.join("resources/packs").join(short),
            None => self.root.join("home/.strands/box/packs").join(name),
        };
        std::fs::create_dir_all(&folder).expect("a pack folder");
        std::fs::write(folder.join(lang::PACK_FILE), text).expect("a pack");
    }

    /// The starter `name` with `text` as its `starter.toml`.
    fn starter(&self, name: &str, text: &str) {
        let folder = match name.strip_prefix(VENDORED) {
            Some(short) => self.root.join("resources").join(STARTERS).join(short),
            None => self
                .root
                .join("home/.strands/box")
                .join(STARTERS)
                .join(name),
        };
        std::fs::create_dir_all(&folder).expect("a starter folder");
        std::fs::write(folder.join(STARTER_FILE), text).expect("a starter");
    }

    /// The agent pack `@box/agent` and the starter `@box/agent`, from `text`: its `starter`,
    /// `source`, and `question` tables go to the `starter.toml`, which gets the name `@box/agent`,
    /// the label "The agent", and the packs `@box/agent` when it sets none. Every other table goes
    /// to the pack.
    fn agent(&self, text: &str) {
        let mut starter: toml::Table = toml::from_str(text).expect("a fixture table");
        let mut pack: toml::Table = toml::from_str(
            "[run]\ncommand = [\"/bin/agent\"]\n[inputs.agent.host]\n\
             values = [\"cloud\", \"local\"]\ndefault = \"cloud\"\n",
        )
        .expect("the agent pack");
        let moved: Vec<String> = starter
            .keys()
            .filter(|key| !matches!(key.as_str(), "starter" | "source" | "question"))
            .cloned()
            .collect();
        for key in moved {
            let value = starter.remove(&key).expect("a key");
            merge_into(&mut pack, key, value);
        }
        self.pack(
            "@box/agent",
            &format!(
                "\n[pack]\nname = \"@box/agent\"\nversion = 1\nkind = \"agent\"\n{}",
                toml::to_string(&pack).expect("a pack text")
            ),
        );
        let text = toml::to_string(&starter).expect("a starter text");
        self.starter("@box/agent", &with_header("@box/agent", &text));
    }

    fn built_in(&self, text: &str) {
        std::fs::create_dir_all(self.root.join("resources")).expect("resources");
        std::fs::write(self.root.join("resources").join(CONFIG_FILE), text).expect("config");
    }

    fn config(&self, text: &str) {
        std::fs::create_dir_all(self.root.join("home/.strands/box")).expect("box home");
        std::fs::write(self.root.join("home/.strands/box").join(CONFIG_FILE), text)
            .expect("config");
    }

    fn parse(&self) -> Result<Starter, String> {
        Starter::load("@box/agent", &self.lookup)
    }

    fn answer(&self, call: Call<'_>) -> Result<(Answered, String), Error> {
        let starter =
            Starter::load("@box/agent", &self.lookup).map_err(|reason| Error::Profile {
                path: PathBuf::from("profile.toml"),
                line: None,
                reason,
            })?;
        let with: Vec<String> = call.with.iter().map(|item| item.to_string()).collect();
        let options: Vec<(String, String)> = call
            .options
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let path = self
            .root
            .join("home/.strands/box/profiles/mine/profile.toml");
        let mut host = crate::host::Host::current();
        host.set_home(self.root.join("home"));
        host.variables = Some(
            call.variables
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        );
        let workspace = self.root.join(call.workspace.unwrap_or("project"));
        let request = Request {
            name: "mine",
            with: &with,
            options: &options,
            lookup: &self.lookup,
            path: &path,
            exists: call.exists,
            host: &host,
            workspace: &workspace,
        };
        let mut input = call.input.as_bytes();
        let mut output = Vec::new();
        let mut terminal = Terminal::new(&mut input, &mut output);
        if call.review_settings {
            let mut session = crate::prompt::Session::default();
            session.edit_setup();
            terminal.session = Some(session);
        }
        let answered = answer(
            &starter,
            &request,
            call.interactive.then_some(&mut terminal),
            call.saved,
        )?;
        Ok((answered, String::from_utf8(output).expect("text")))
    }
}

#[derive(Default)]
struct Call<'a> {
    saved: Option<&'a crate::Profile>,
    with: &'a [&'a str],
    options: &'a [(&'a str, &'a str)],
    interactive: bool,
    input: &'a str,
    exists: bool,
    variables: &'a [(&'a str, &'a str)],
    workspace: Option<&'a str>,
    review_settings: bool,
}

const PROVIDER_QUESTION: &str = r#"
[starter]
label = "The agent"

[[question]]
id = "provider"
prompt = "Which provider?"

[[question.choice]]
id = "cloud"
label = "The cloud"
packs = ["@box/cloud"]
options = { "agent.host" = "cloud" }

[[question.choice]]
id = "local"
label = "This machine"
packs = ["@box/local"]
options = { "agent.host" = "local" }
"#;

/// Put `value` at `key` in `table`, merging it into a table already there.
fn merge_into(table: &mut toml::Table, key: String, value: toml::Value) {
    match (table.get_mut(&key), value) {
        (Some(toml::Value::Table(old)), toml::Value::Table(new)) => {
            for (key, value) in new {
                merge_into(old, key, value);
            }
        }
        (_, value) => {
            table.insert(key, value);
        }
    }
}

/// `text` with the `[starter]` keys `name`, `label`, and `packs` that it does not set.
fn with_header(name: &str, text: &str) -> String {
    let mut table: toml::Table = toml::from_str(text).expect("a starter table");
    let header = table
        .entry("starter")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .expect("a [starter] table");
    header.entry("name").or_insert_with(|| name.into());
    header.entry("label").or_insert_with(|| "The agent".into());
    header
        .entry("packs")
        .or_insert_with(|| toml::Value::Array(vec![name.into()]));
    toml::to_string(&table).expect("a starter text")
}

fn refused(fixture: &Fixture, starter: &str, reason: &str) {
    fixture.agent(starter);
    let error = fixture.parse().expect_err("a refused starter");
    assert!(error.contains(reason), "{error}");
}

fn expected(packs: &[&str], options: &[(&str, &str)]) -> Answered {
    Answered {
        packs: packs.iter().map(|pack| pack.to_string()).collect(),
        options: options
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        detected: Vec::new(),
        policy: None,
    }
}

#[test]
fn a_starter_parses_its_questions_and_resolves_short_pack_names() {
    let fixture = Fixture::new();
    fixture.agent(&PROVIDER_QUESTION.replace("@box/local", "local"));
    let starter = fixture.parse().expect("a starter");
    assert_eq!(starter.label, "The agent");
    assert_eq!(starter.packs, ["@box/agent"]);
    assert_eq!(starter.questions[0].choices[1].packs, ["@box/local"]);
}

#[test]
fn a_starter_refuses_a_question_or_choice_id_given_twice() {
    let fixture = Fixture::new();
    refused(
        &fixture,
        &format!(
            "{PROVIDER_QUESTION}\n{}",
            PROVIDER_QUESTION[PROVIDER_QUESTION.find("[[question]]").unwrap()..]
                .replace("@box/cloud", "@box/github")
                .replace("@box/local", "@box/proxy-us")
        ),
        "two questions have the id \"provider\"",
    );
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace("id = \"local\"", "id = \"cloud\""),
        "two choices of question \"provider\" have the id \"cloud\"",
    );
}

#[test]
fn a_question_default_must_name_a_choice_of_that_question() {
    let fixture = Fixture::new();
    for (value, reason) in [
        (
            r#""This machine""#,
            r#"names an unknown choice "This machine""#,
        ),
        ("2", "is not a string"),
    ] {
        refused(
            &fixture,
            &PROVIDER_QUESTION.replace("[[question]]", &format!("[[question]]\ndefault = {value}")),
            &format!("the `default` of question \"provider\" {reason}"),
        );
    }
}

#[test]
fn a_starter_refuses_a_question_that_offers_no_real_choice() {
    let fixture = Fixture::new();
    let only_none = "[[question]]\nid = \"q\"\nprompt = \"Q?\"\n\n[[question.choice]]\nid = \"no\"\npacks = []\n";
    refused(
        &fixture,
        only_none,
        "needs two choices, or one choice that adds a pack",
    );
    let one = "[[question]]\nid = \"q\"\nprompt = \"Q?\"\n\n[[question.choice]]\nid = \"yes\"\npacks = [\"@box/github\"]\n";
    fixture.agent(one);
    fixture.parse().expect("one choice that adds a pack");
}

#[test]
fn a_starter_refuses_two_none_choices_and_a_none_choice_with_options() {
    let fixture = Fixture::new();
    refused(
        &fixture,
        &PROVIDER_QUESTION
            .replace(
                "packs = [\"@box/cloud\"]\noptions = { \"agent.host\" = \"cloud\" }",
                "packs = []",
            )
            .replace(
                "packs = [\"@box/local\"]\noptions = { \"agent.host\" = \"local\" }",
                "packs = []",
            ),
        "has 2 choices that add no pack",
    );
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace("packs = [\"@box/cloud\"]", "packs = []"),
        "the none choice sets no options",
    );
}

#[test]
fn a_starter_refuses_one_pack_in_two_choices_of_a_question() {
    let fixture = Fixture::new();
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace(
            "packs = [\"@box/local\"]",
            "packs = [\"@box/cloud\", \"@box/local\"]",
        ),
        "both add @box/cloud",
    );
}

#[test]
fn a_starter_refuses_a_when_that_names_no_earlier_question_or_choice() {
    let fixture = Fixture::new();
    let proxy = |when: &str| {
        format!(
            "{PROVIDER_QUESTION}\n[[question]]\nid = \"proxy\"\nprompt = \"Proxy?\"\nwhen = {when}\n\n\
             [[question.choice]]\nid = \"us\"\npacks = [\"@box/proxy-us\"]\n\n\
             [[question.choice]]\nid = \"eu\"\npacks = [\"@box/proxy-eu\"]\n"
        )
    };
    refused(
        &fixture,
        &proxy("{ variable = \"answers.region\", equals = \"cloud\" }"),
        "no earlier question has that id",
    );
    refused(
        &fixture,
        &proxy("{ variable = \"answers.provider\", equals = \"clod\" }"),
        "\"clod\", which is not a choice of question \"provider\"",
    );
    refused(
        &fixture,
        &proxy("{ variable = \"inputs.agent.host\", equals = \"cloud\" }"),
        "a starter reads answers.<question id>",
    );
    fixture.agent(&proxy(
        "{ variable = \"answers.provider\", equals = \"cloud\" }",
    ));
    fixture.parse().expect("a when on an earlier answer");
}

#[test]
fn a_starter_name_that_leaves_its_folder_is_refused() {
    let fixture = Fixture::new();
    for name in ["", ".hidden", "..", "a/b", "@box/", "@box/..", "sp ace"] {
        let error = Starter::load(name, &fixture.lookup).expect_err("a bad name");
        assert!(
            error.contains("is not a starter name") || error.contains("does not exist"),
            "{name:?}: {error}"
        );
        assert!(!error.contains("unknown key"), "{name:?}: {error}");
    }
}

#[test]
fn a_shipped_starter_is_named_with_the_box_scope_and_not_as_a_folder() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    Starter::load("@box/agent", &fixture.lookup).expect("the shipped starter");
    let error = Starter::load("box/agent", &fixture.lookup).expect_err("the old spelling");
    assert!(
        error.contains(
            "\"box/agent\" is not a starter name; the starter that box ships is @box/agent"
        ),
        "{error}"
    );
    let error = Starter::load("box/nope", &fixture.lookup).expect_err("no shipped starter");
    assert!(
        error.ends_with("\"box/nope\" is not a starter name"),
        "{error}"
    );
}

#[test]
fn a_linked_starter_file_or_folder_is_refused() {
    let fixture = Fixture::new();
    fixture.agent("");
    let workspace = fixture.root.join("project");
    std::fs::create_dir_all(&workspace).expect("a workspace");
    let text = "[starter]\nname = \"mine\"\nlabel = \"Planted\"\npacks = [\"@box/agent\"]\n";
    std::fs::write(workspace.join(STARTER_FILE), text).expect("a planted file");
    let starters = fixture.root.join("home/.strands/box").join(STARTERS);
    std::fs::create_dir_all(starters.join("mine")).expect("a starter folder");
    std::os::unix::fs::symlink(
        workspace.join(STARTER_FILE),
        starters.join("mine").join(STARTER_FILE),
    )
    .expect("a linked file");
    let error = Starter::load("mine", &fixture.lookup).expect_err("a linked file");
    assert!(error.contains("symbolic link"), "{error}");
    std::fs::remove_dir_all(starters.join("mine")).expect("removed");
    std::os::unix::fs::symlink(&workspace, starters.join("mine")).expect("a linked folder");
    let error = Starter::load("mine", &fixture.lookup).expect_err("a linked folder");
    assert!(error.contains("symbolic link"), "{error}");
    std::fs::remove_file(starters.join("mine")).expect("removed");
    std::fs::create_dir_all(starters.join("mine")).expect("a starter folder");
    std::fs::hard_link(
        workspace.join(STARTER_FILE),
        starters.join("mine").join(STARTER_FILE),
    )
    .expect("a hard-linked file");
    let error = Starter::load("mine", &fixture.lookup).expect_err("a hard-linked file");
    assert!(error.contains("exactly one hard link"), "{error}");
    std::fs::remove_dir_all(starters.join("mine")).expect("removed");
    std::fs::create_dir_all(&starters).expect("starters");
    fixture.starter("mine", text);
    Starter::load("mine", &fixture.lookup).expect("a regular starter file");
}

#[test]
fn a_team_starter_names_the_packs_and_options_its_profiles_start_with() {
    let fixture = Fixture::new();
    fixture.agent("");
    fixture.starter(
        "team",
        "[starter]\nname = \"team\"\nlabel = \"Team\"\npacks = [\"agent\", \"cloud\"]\n\
         options = { \"cloud.account\" = \"42\" }\n",
    );
    let starter = Starter::load("team", &fixture.lookup).expect("a team starter");
    assert_eq!(starter.label, "Team");
    assert_eq!(starter.packs, ["@box/agent", "@box/cloud"]);
    assert_eq!(
        starter.options,
        [("cloud.account".to_string(), "42".to_string())]
    );
}

#[test]
fn a_starter_refuses_an_unknown_key_a_choice_without_packs_and_a_bad_ask_name() {
    let fixture = Fixture::new();
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace("label = \"The agent\"", "describe = \"The agent\""),
        "`[starter]` holds the unknown key `describe`",
    );
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace("packs = [\"@box/local\"]\n", ""),
        "choice \"local\" of question \"provider\" has no `packs`",
    );
    refused(
        &fixture,
        &PROVIDER_QUESTION.replace("label = \"The agent\"", "ask = [\"region\"]"),
        "name an input as <namespace>.<key>",
    );
}

#[test]
fn the_menu_is_the_built_in_list_changed_by_add_and_remove_or_replaced_by_only() {
    let fixture = Fixture::new();
    fixture.built_in("[starters]\nonly = [\"@box/agent\", \"@box/cloud\"]\n");
    let menu = |fixture: &Fixture| Menu::load(&fixture.lookup).map(|menu| menu.starters);
    assert_eq!(
        menu(&fixture).expect("a menu"),
        ["@box/agent", "@box/cloud"]
    );
    fixture.config("[starters]\nadd = [\"team\"]\nremove = [\"@box/agent\"]\n");
    assert_eq!(menu(&fixture).expect("a menu"), ["@box/cloud", "team"]);
    fixture.config("[starters]\nonly = [\"team\"]\n");
    assert_eq!(menu(&fixture).expect("a menu"), ["team"]);
    fixture.config("");
    assert_eq!(
        menu(&fixture).expect("a menu"),
        ["@box/agent", "@box/cloud"]
    );
}

#[test]
fn the_menu_refuses_each_bad_starters_table() {
    let fixture = Fixture::new();
    for (config, reason) in [
        (
            "[starters]\nonly = [\"@box/agent\"]\nadd = [\"x\"]\n",
            "holds `only` with `add` or `remove`",
        ),
        (
            "[starters]\nremove = [\"@box/codx\"]\n",
            "\"@box/codx\", which is not in the starter menu",
        ),
        (
            "[starters]\nadd = [\"@box/agent\"]\n",
            "\"@box/agent\", which is already a starter",
        ),
        (
            "[starters]\nadd = [\"agent\"]\n",
            "@box/agent and agent share the name \"agent\"",
        ),
        (
            "[starters]\nappend = [\"agent\"]\n",
            "the unknown key `append`",
        ),
        ("default = \"claude\"\n", "the unknown key `default`"),
    ] {
        fixture.config(config);
        let error = Menu::load(&fixture.lookup).expect_err(config).to_string();
        assert!(error.contains(reason), "{config}: {error}");
    }
}

#[test]
fn the_starter_is_the_with_entry_in_the_menu_else_the_profile_name() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    fixture.pack(
        "agent2",
        "[pack]\nname = \"agent2\"\nversion = 1\nkind = \"agent\"\n[run]\ncommand = [\"/bin/x\"]",
    );
    fixture.starter(
        "agent2",
        "[starter]\nname = \"agent2\"\nlabel = \"Two\"\npacks = [\"agent2\"]\n",
    );
    fixture.config("[starters]\nadd = [\"agent2\"]\n");
    let menu = Menu::load(&fixture.lookup).expect("a menu");
    let path = PathBuf::from("profile.toml");
    let select_for = |name: &str, with: &[&str]| {
        let with: Vec<String> = with.iter().map(|item| item.to_string()).collect();
        select(
            &menu,
            &Request {
                name,
                with: &with,
                options: &[],
                lookup: &fixture.lookup,
                path: &path,
                exists: false,
                host: &crate::host::Host::current(),
                workspace: &path,
            },
        )
    };
    assert_eq!(
        select_for("work", &["agent"])
            .expect("a starter")
            .as_deref(),
        Some("@box/agent")
    );
    assert_eq!(
        select_for("agent", &["cloud"])
            .expect("a starter")
            .as_deref(),
        Some("@box/agent")
    );
    assert_eq!(select_for("work", &["cloud"]).expect("no starter"), None);
    let error = select_for("work", &["agent", "agent2"]).expect_err("two starters");
    assert!(error.to_string().contains("names two starters"), "{error}");
}

#[test]
fn a_short_name_names_your_pack_before_a_shipped_pack_of_that_name() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.lookup.full_name("cloud").as_deref(),
        Ok("@box/cloud")
    );
    fixture.pack(
        "cloud",
        "[pack]\nname = \"cloud\"\nversion = 1\nkind = \"support\"\n",
    );
    assert_eq!(fixture.lookup.full_name("cloud").as_deref(), Ok("cloud"));
    assert_eq!(
        fixture.lookup.full_name("@box/cloud").as_deref(),
        Ok("@box/cloud")
    );
    assert_eq!(fixture.lookup.spelling("@box/cloud"), "@box/cloud");
    assert_eq!(fixture.lookup.spelling("cloud"), "cloud");
    assert_eq!(fixture.lookup.spelling("@box/local"), "local");
}

#[test]
fn your_pack_with_a_starters_short_name_selects_no_starter() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    fixture.pack(
        "agent",
        "[pack]\nname = \"agent\"\nversion = 1\nkind = \"agent\"\n[run]\ncommand = [\"/bin/mine\"]",
    );
    let menu = Menu::load(&fixture.lookup).expect("a menu");
    let path = PathBuf::from("profile.toml");
    let select_for = |name: &str, with: &[&str]| {
        let with: Vec<String> = with.iter().map(|item| item.to_string()).collect();
        select(
            &menu,
            &Request {
                name,
                with: &with,
                options: &[],
                lookup: &fixture.lookup,
                path: &path,
                exists: false,
                host: &crate::host::Host::current(),
                workspace: &path,
            },
        )
        .expect("a selection")
    };
    assert_eq!(select_for("work", &["agent"]), None);
    assert_eq!(select_for("agent", &["cloud"]), None);
    assert_eq!(
        select_for("work", &["@box/agent"]).as_deref(),
        Some("@box/agent")
    );
    assert_eq!(menu.named(&fixture.lookup, "agent"), None);
    assert_eq!(
        menu.named(&fixture.lookup, "@box/agent"),
        Some("@box/agent")
    );
    let error = fixture
        .answer(Call {
            with: &["@box/agent", "agent", "local"],
            ..Call::default()
        })
        .expect_err("two agent packs");
    assert!(
        error
            .to_string()
            .contains("the profile has two agent packs, @box/agent and agent; keep one"),
        "{error}"
    );
}

#[test]
fn a_flag_hint_names_the_shipped_pack_in_full_when_your_pack_has_its_name() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    fixture.pack(
        "cloud",
        "[pack]\nname = \"cloud\"\nversion = 1\nkind = \"support\"\n",
    );
    let error = fixture.answer(Call::default()).expect_err("unanswered");
    assert_eq!(
        error.to_string(),
        "box profile create mine needs an answer to \"Which provider?\"\n  \
         --with @box/cloud   The cloud\n  --with local        This machine"
    );
}

#[test]
fn a_with_refusal_names_the_shipped_pack_in_full_when_your_pack_has_its_name() {
    let fixture = Fixture::new();
    fixture.pack(
        "github",
        "[pack]\nname = \"github\"\nversion = 1\nkind = \"support\"\n",
    );
    fixture.pack(
        "proxy-eu",
        "[pack]\nname = \"proxy-eu\"\nversion = 1\nkind = \"support\"\n",
    );
    fixture.agent(
        r#"
[starter]
label = "The agent"

[[question]]
id = "provider"
prompt = "Which provider?"

[[question.choice]]
id = "cloud"
label = "The cloud"
packs = ["@box/cloud"]

[[question.choice]]
id = "local"
label = "This machine"
packs = ["@box/local"]

[[question]]
id = "where"
prompt = "Where?"

[[question.choice]]
id = "here"
label = "Here"
packs = ["@box/github"]

[[question.choice]]
id = "there"
label = "There"
packs = ["@box/proxy-us"]

[[question]]
id = "proxy"
prompt = "Which proxy?"
when = { variable = "answers.provider", equals = "cloud" }

[[question.choice]]
id = "eu"
label = "Europe"
packs = ["@box/proxy-eu"]

[[question.choice]]
id = "us"
label = "Not Europe"
packs = ["@box/github"]
"#,
    );
    let error = fixture
        .answer(Call {
            with: &["@box/github"],
            ..Call::default()
        })
        .expect_err("two questions");
    assert!(
        error
            .to_string()
            .contains("`--with @box/github` answers more than one question"),
        "{error}"
    );
    let error = fixture
        .answer(Call {
            with: &["local", "proxy-us", "@box/proxy-eu"],
            ..Call::default()
        })
        .expect_err("a skipped question");
    assert!(
        error
            .to_string()
            .contains("`--with @box/proxy-eu` answers \"Which proxy?\""),
        "{error}"
    );
}

#[test]
fn your_pack_with_a_choice_packs_name_answers_its_question_in_place_of_it() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    fixture.pack(
        "cloud",
        "\n[pack]\nname = \"cloud\"\nversion = 1\nkind = \"support\"\nextend = [\"@box/cloud\"]",
    );
    let expected = expected(
        &["@box/agent", "cloud"],
        &[("agent.host", "cloud"), ("cloud.account", "1")],
    );
    for interactive in [false, true] {
        let (answered, output) = fixture
            .answer(Call {
                with: &["cloud"],
                options: &[("cloud.account", "1")],
                interactive,
                ..Call::default()
            })
            .expect("answered");
        assert_eq!(answered, expected, "interactive: {interactive}");
        assert!(!output.contains("Which provider?"), "{output}");
    }
}

#[test]
fn with_answers_a_question_by_the_pack_its_choice_adds() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    let (answered, output) = fixture
        .answer(Call {
            with: &["agent", "local", "github"],
            interactive: true,
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/local", "@box/github"],
            &[("agent.host", "local")]
        )
    );
    assert_eq!(output, "", "nothing is asked");
}

#[test]
fn a_question_with_one_choice_takes_it_and_a_when_that_does_not_hold_skips_its_question() {
    let fixture = Fixture::new();
    fixture.agent(&format!(
        "{PROVIDER_QUESTION}\n[[question]]\nid = \"proxy\"\nprompt = \"Proxy?\"\n\
         when = {{ variable = \"answers.provider\", equals = \"cloud\" }}\n\n\
         [[question.choice]]\nid = \"us\"\npacks = [\"@box/proxy-us\"]\n"
    ));
    let (answered, _) = fixture
        .answer(Call {
            with: &["cloud"],
            options: &[("cloud.account", "1")],
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/cloud", "@box/proxy-us"],
            &[("agent.host", "cloud"), ("cloud.account", "1")]
        )
    );
    let (answered, _) = fixture
        .answer(Call {
            with: &["local"],
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(&["@box/agent", "@box/local"], &[("agent.host", "local")])
    );
}

#[test]
fn a_with_entry_that_answers_two_questions_is_refused() {
    let fixture = Fixture::new();
    fixture.agent(&format!(
        "{PROVIDER_QUESTION}\n[[question]]\nid = \"extra\"\nprompt = \"Extra?\"\n\n\
         [[question.choice]]\nid = \"no\"\npacks = []\n\n\
         [[question.choice]]\nid = \"yes\"\npacks = [\"@box/local\"]\n"
    ));
    let error = fixture
        .answer(Call {
            with: &["local"],
            ..Call::default()
        })
        .expect_err("two questions");
    assert!(
        error
            .to_string()
            .contains("`--with local` answers more than one question"),
        "{error}"
    );
}

#[test]
fn starter_packs_and_options_start_the_profile_and_later_values_replace_them() {
    let fixture = Fixture::new();
    fixture.agent(&PROVIDER_QUESTION.replace(
        "label = \"The agent\"",
        "label = \"The agent\"\npacks = [\"@box/agent\", \"@box/github\"]\noptions = { \"agent.host\" = \"none\", \"cloud.account\" = \"7\", \"cloud.region\" = \"west-2\" }",
    ));
    let (answered, output) = fixture
        .answer(Call {
            with: &["cloud"],
            options: &[("cloud.region", "north-3")],
            interactive: true,
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/github", "@box/cloud"],
            &[
                ("agent.host", "cloud"),
                ("cloud.account", "7"),
                ("cloud.region", "north-3")
            ]
        )
    );
    assert_eq!(
        output, "",
        "[starter] options set the input with no default"
    );
}

#[test]
fn without_a_terminal_a_default_fills_an_ask_input_and_an_unanswered_question_names_its_flags() {
    let fixture = Fixture::new();
    fixture.agent(&PROVIDER_QUESTION.replace(
        "label = \"The agent\"",
        "label = \"The agent\"\nask = [\"cloud.region\", \"other.thing\"]",
    ));
    let (answered, _) = fixture
        .answer(Call {
            with: &["cloud"],
            options: &[("cloud.account", "1")],
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/cloud"],
            &[("agent.host", "cloud"), ("cloud.account", "1")]
        )
    );
    let error = fixture.answer(Call::default()).expect_err("unanswered");
    assert_eq!(
        error.to_string(),
        "box profile create mine needs an answer to \"Which provider?\"\n  \
         --with cloud   The cloud\n  --with local   This machine"
    );
    let error = fixture
        .answer(Call {
            with: &["cloud"],
            ..Call::default()
        })
        .expect_err("no account");
    assert_eq!(
        error.to_string(),
        "box profile create mine needs an answer to \"The account.\"\n  \
         --option cloud.account=<value>   The account."
    );
}

#[test]
fn a_question_default_is_used_only_for_a_new_unanswered_profile() {
    let fixture = Fixture::new();
    fixture.agent(&format!(
        "{}\n[[question.choice]]\nid = \"none\"\npacks = []\n",
        PROVIDER_QUESTION.replace("[[question]]", "[[question]]\ndefault = \"local\"")
    ));
    let local = expected(&["@box/agent", "@box/local"], &[("agent.host", "local")]);
    assert_eq!(
        fixture.answer(Call::default()).expect("no terminal").0,
        local
    );
    let (answered, output) = fixture
        .answer(Call {
            interactive: true,
            input: "\n",
            ..Call::default()
        })
        .expect("Enter takes the default");
    assert_eq!(answered, local);
    assert!(output.ends_with("3. This machine\n> [3] "), "{output}");

    let saved = crate::Profile::parse(
        r#"packs = ["@box/agent"]"#,
        Path::new("profile.toml"),
        crate::VERSION,
    )
    .expect("a saved profile without a provider pack");
    let (answered, output) = fixture
        .answer(Call {
            saved: Some(&saved),
            with: &["@box/agent"],
            interactive: true,
            input: "\n",
            ..Call::default()
        })
        .expect("Enter keeps the saved choice");
    assert_eq!(answered, expected(&["@box/agent"], &[]));
    assert!(output.ends_with("> [1] "), "{output}");
}

#[test]
fn the_none_choice_is_the_answer_to_enter_and_to_no_terminal() {
    let fixture = Fixture::new();
    let github = "[[question]]\nid = \"github\"\nprompt = \"GitHub?\"\n\n\
                  [[question.choice]]\nid = \"yes\"\nlabel = \"Yes\"\npacks = [\"@box/github\"]\n\n\
                  [[question.choice]]\nid = \"no\"\nlabel = \"No\"\npacks = []\n";
    fixture.agent(github);
    let (answered, _) = fixture.answer(Call::default()).expect("no terminal");
    assert_eq!(answered, expected(&["@box/agent"], &[]));
    let (answered, output) = fixture
        .answer(Call {
            interactive: true,
            input: "\n",
            ..Call::default()
        })
        .expect("enter");
    assert_eq!(answered, expected(&["@box/agent"], &[]));
    assert_eq!(output, "GitHub?\n  1. No\n  2. Yes\n> [1] ");
    let (answered, _) = fixture
        .answer(Call {
            interactive: true,
            input: "2\n",
            ..Call::default()
        })
        .expect("yes");
    assert_eq!(answered, expected(&["@box/agent", "@box/github"], &[]));
    let (answered, _) = fixture
        .answer(Call {
            with: &["github"],
            ..Call::default()
        })
        .expect("with");
    assert_eq!(answered, expected(&["@box/agent", "@box/github"], &[]));
}

#[test]
fn at_a_terminal_each_question_and_input_is_asked_until_the_answer_is_valid() {
    let fixture = Fixture::new();
    fixture.agent(&PROVIDER_QUESTION.replace(
        "label = \"The agent\"",
        "label = \"The agent\"\nask = [\"cloud.region\"]",
    ));
    let (answered, output) = fixture
        .answer(Call {
            interactive: true,
            input: "3\n1\n\nACME\nEAST\nwest-9\n",
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/cloud"],
            &[
                ("agent.host", "cloud"),
                ("cloud.account", "ACME"),
                ("cloud.region", "west-9")
            ]
        )
    );
    assert!(output.contains("Type a number from 1 to 2."), "{output}");
    assert!(
        output.contains("cloud.account has no default; type a value."),
        "{output}"
    );
    assert!(
        output.contains("The account (cloud.account)\n> "),
        "{output}"
    );
    assert!(
        output.contains("The region (cloud.region)\n> [east-1] "),
        "{output}"
    );
    assert!(output.contains("does not match its pattern"), "{output}");
    let (answered, _) = fixture
        .answer(Call {
            interactive: true,
            input: "1\nACME\n\n",
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/cloud"],
            &[("agent.host", "cloud"), ("cloud.account", "ACME")]
        ),
        "Enter keeps the default and writes nothing"
    );
    let error = fixture
        .answer(Call {
            interactive: true,
            input: "",
            ..Call::default()
        })
        .expect_err("end of input");
    assert!(matches!(error, Error::Interrupted), "{error}");
}

#[test]
fn an_input_with_a_warning_shows_it_before_the_answer() {
    let fixture = Fixture::new();
    fixture.agent(
        "[inputs.agent.import]\n\
         description = \"Import host servers.\"\ntype = \"bool\"\ndefault = false\n\
         warning = \"Each server runs in the box.\"\n\n[starter]\nlabel = \"The agent\"\n\
         ask = [\"agent.import\"]\n",
    );
    let (answered, output) = fixture
        .answer(Call {
            interactive: true,
            input: "1\n",
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        output,
        "Import host servers\n\n  ! Each server runs in the box.\n\n  1. Yes\n  \
         2. No\n> [No] "
    );
    assert_eq!(
        answered,
        expected(&["@box/agent"], &[("agent.import", "true")])
    );
    for input in ["\n", "2\n", "No\n", "n\n", "false\n"] {
        let (answered, _) = fixture
            .answer(Call {
                interactive: true,
                input,
                ..Call::default()
            })
            .expect("answered");
        assert_eq!(
            answered,
            expected(&["@box/agent"], &[("agent.import", "false")]),
            "{input:?} records the default of an input with a warning"
        );
    }
    for input in ["Yes\n", "y\n", "true\n"] {
        let (answered, _) = fixture
            .answer(Call {
                interactive: true,
                input,
                ..Call::default()
            })
            .expect("answered");
        assert_eq!(
            answered,
            expected(&["@box/agent"], &[("agent.import", "true")])
        );
    }
    let (answered, output) = fixture.answer(Call::default()).expect("no terminal");
    assert_eq!(output, "");
    assert_eq!(
        answered,
        expected(&["@box/agent"], &[("agent.import", "false")]),
        "without a terminal, the default of an input with a warning is recorded"
    );
}

#[test]
fn a_warning_on_an_input_of_a_with_pack_is_asked_and_shown() {
    let fixture = Fixture::new();
    fixture.agent("[starter]\nlabel = \"The agent\"\n");
    fixture.pack(
        "@box/github",
        "[pack]\nname = \"@box/github\"\nversion = 1\nkind = \"support\"\n\n[inputs.github.write]\ntype = \
         \"bool\"\ndefault = false\nwarning = \"The agent can push.\"\n",
    );
    let (answered, output) = fixture
        .answer(Call {
            with: &["github"],
            interactive: true,
            input: "1\n",
            ..Call::default()
        })
        .expect("answered");
    assert!(
        output.contains("github.write\n\n  ! The agent can push.\n"),
        "{output}"
    );
    assert_eq!(
        answered,
        expected(&["@box/agent", "@box/github"], &[("github.write", "true")])
    );
}

#[test]
fn a_profile_without_a_starter_asks_and_records_each_input_with_a_warning() {
    let host = crate::FakeHost::new();
    crate::test_support::write(
        &host
            .home()
            .join(".strands/box/packs/team-agent")
            .join(lang::PACK_FILE),
        "\n[pack]\nname = \"team-agent\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/bin/sh\"]\n[inputs.team.push]\ntype = \"bool\"\ndefault = false\n\
         warning = \"The agent can push.\"\n",
    );
    let create = |input: Option<&str>| {
        let mut bytes = input.unwrap_or_default().as_bytes();
        let mut output = Vec::new();
        let terminal = input.map(|_| Terminal::new(&mut bytes, &mut output));
        let created = host
            .profile()
            .name("team")
            .with("team-agent")
            .policy("open")
            .tools(Vec::<String>::new())
            .answer(terminal)
            .and_then(|profile| profile.create())
            .expect("created");
        (
            created.text().to_string(),
            String::from_utf8(output).expect("text"),
        )
    };
    let (text, output) = create(Some("1\n"));
    assert!(output.contains("  ! The agent can push.\n"), "{output}");
    assert!(text.contains("team.push = \"true\""), "{text}");
    let (text, output) = create(None);
    assert_eq!(output, "");
    assert!(text.contains("team.push = \"false\""), "{text}");
}

#[test]
fn the_claude_and_codex_starters_ask_how_the_box_signs_in_to_bedrock() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: directory.path().join(".strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let path = directory
        .path()
        .join(".strands/box/profiles/mine/profile.toml");
    let mut host = crate::host::Host::current();
    host.set_home(directory.path().to_path_buf());
    let workspace = directory.path().join("project");
    for starter_name in ["@box/claude", "@box/codex"] {
        let starter = Starter::load(starter_name, &lookup).expect("a shipped starter");
        assert!(
            starter.ask.iter().any(|name| name == "bedrock.sign-in"),
            "{starter_name}"
        );
        for pack in ["@box/bedrock", "@box/bedrock-mantle"] {
            let request = Request {
                name: "mine",
                with: &[],
                options: &[],
                lookup: &lookup,
                path: &path,
                exists: false,
                host: &host,
                workspace: &workspace,
            };
            let found = merged(&[pack.to_string()], &request, None)
                .expect("declarations")
                .declarations;
            assert_eq!(
                found["bedrock.sign-in"].default_value(),
                Some("aws"),
                "{pack}"
            );
            assert_eq!(
                found["bedrock.sign-in"].allowed(),
                ["aws", "api-key"],
                "{pack}"
            );
        }
    }
}

#[test]
fn the_kiro_starter_asks_for_the_sign_in_and_adds_no_pack() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: directory.path().join(".strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let starter = Starter::load("@box/kiro", &lookup).expect("the Kiro starter");
    assert_eq!(starter.label, "Kiro CLI");
    assert!(starter.questions.is_empty());
    assert_eq!(starter.ask, ["kiro.sign-in"]);
}

#[test]
fn each_shipped_starter_that_imports_mcp_servers_asks_for_it_off_by_default_and_with_a_warning() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: directory.path().join(".strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let path = directory
        .path()
        .join(".strands/box/profiles/mine/profile.toml");
    let mut host = crate::host::Host::current();
    host.set_home(directory.path().to_path_buf());
    let workspace = directory.path().join("project");
    for (pack, input) in [
        ("@box/claude", "claude.import-mcp"),
        ("@box/codex", "codex.import-mcp"),
    ] {
        let starter = Starter::load(pack, &lookup).expect("a shipped starter");
        assert!(starter.ask.iter().any(|name| name == input), "{pack}");
        let request = Request {
            name: "mine",
            with: &[],
            options: &[],
            lookup: &lookup,
            path: &path,
            exists: false,
            host: &host,
            workspace: &workspace,
        };
        let found = merged(&[pack.to_string()], &request, None)
            .expect("declarations")
            .declarations;
        assert_eq!(found[input].default_value(), Some("false"), "{pack}");
        assert!(
            found[input]
                .warnings()
                .iter()
                .any(|warning| warning.contains("servers you add later")),
            "{pack}"
        );
    }
}

#[test]
fn an_existing_profile_is_refused_before_the_first_prompt() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    let error = fixture
        .answer(Call {
            interactive: true,
            input: "1\n",
            exists: true,
            ..Call::default()
        })
        .expect_err("exists");
    assert!(matches!(error, Error::Exists { .. }), "{error}");
    fixture
        .answer(Call {
            with: &["local"],
            interactive: true,
            exists: true,
            ..Call::default()
        })
        .expect("nothing asked, so the write decides");
}

#[test]
fn a_pack_that_holds_a_starter_table_is_refused() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    fixture.pack(
        "@box/agent",
        "\n[pack]\nname = \"@box/agent\"\nversion = 1\nkind = \"agent\"\n[run]\n\
         command = [\"/bin/agent\"]\n\n[starter]\nlabel = \"The agent\"\n",
    );
    let mut table = toml::Table::new();
    table.insert(
        "packs".into(),
        toml::Value::Array(vec!["@box/agent".into()]),
    );
    let error = lang::chain(&table, "", Path::new("profile.toml"), None, &fixture.lookup)
        .map(|_| ())
        .expect_err("a pack with a starter table");
    assert!(error.to_string().contains("`starter`"), "{error}");
}

#[test]
fn a_starter_needs_its_own_name_a_label_and_packs() {
    let fixture = Fixture::new();
    let refused = |text: &str, reason: &str| {
        fixture.starter("@box/agent", text);
        let error = fixture.parse().expect_err("a refused starter");
        assert!(error.contains(reason), "{error}");
    };
    refused(
        "[starter]\nname = \"@box/other\"\nlabel = \"A\"\npacks = []\n",
        "`[starter] name` is \"@box/other\", and the folder holds @box/agent",
    );
    refused(
        "[starter]\nname = \"@box/agent\"\npacks = []\n",
        "[starter] has no `label`",
    );
    refused(
        "[starter]\nname = \"@box/agent\"\nlabel = \"A\"\n",
        "`[starter]` has no `packs`",
    );
    refused(
        "[[question]]\nid = \"q\"\nprompt = \"Q?\"\n",
        "a starter needs a `[starter]` table",
    );
    refused(
        "[starter]\nname = \"@box/agent\"\nlabel = \"A\"\npacks = []\n[inputs.x.y]\n",
        "`starter.toml` holds the unknown key `inputs`",
    );
    let error = Starter::load("@box/gone", &fixture.lookup).expect_err("no starter");
    assert!(
        error.contains("the starter @box/gone does not exist"),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn each_path_through_each_shipped_starter_writes_a_profile_that_resolves() {
    let host = crate::FakeHost::new();
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: host.home().join(".strands/box/packs"),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let menu = Menu::load(&lookup).expect("the shipped menu");
    assert!(!menu.starters.is_empty());
    for pack in &menu.starters {
        let starter = Starter::load(pack, &lookup).expect("a shipped starter");
        let mut paths: Vec<Vec<String>> = vec![Vec::new()];
        for question in &starter.questions {
            paths = paths
                .into_iter()
                .flat_map(|path| {
                    question.choices.iter().map(move |choice| {
                        let mut path = path.clone();
                        path.extend(choice.packs.first().cloned());
                        path
                    })
                })
                .collect();
        }
        for (index, path) in paths.iter().enumerate() {
            for policy in ["open", "scoped", "locked"] {
                let name = format!("{}-{index}-{policy}", short_name(pack));
                let mut profile = host.profile().name(&name).with(pack.clone()).policy(policy);
                for answer in path {
                    profile = profile.with(answer.clone());
                }
                let created = profile
                    .answer(None)
                    .and_then(|profile| profile.create())
                    .unwrap_or_else(|error| panic!("{name} {path:?}: {error}"));
                created.write(false).expect("written");
                let preview = host
                    .launcher()
                    .preview(&name, &host.project())
                    .unwrap_or_else(|error| panic!("{name} {path:?}: {error}"));
                assert_eq!(preview.warnings, Vec::<String>::new(), "{name} {path:?}");
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_starter_of_yours_that_replaces_a_built_in_one_writes_its_own_packs() {
    let host = crate::FakeHost::new();
    let folder = host.home().join(".strands/box/packs/claude");
    std::fs::create_dir_all(&folder).expect("a pack folder");
    std::fs::write(
        folder.join(lang::PACK_FILE),
        "\n[pack]\nname = \"claude\"\nversion = 1\nkind = \"agent\"\nextend = [\"@box/claude\"]",
    )
    .expect("a pack");
    crate::test_support::write(
        &host
            .home()
            .join(".strands/box")
            .join(STARTERS)
            .join("claude")
            .join(STARTER_FILE),
        "[starter]\nname = \"claude\"\nlabel = \"Claude Code\"\npacks = [\"claude\"]\n",
    );
    std::fs::write(
        host.home().join(".strands/box").join(CONFIG_FILE),
        "[starters]\nadd = [\"claude\"]\nremove = [\"@box/claude\"]\n",
    )
    .expect("config");
    let created = host
        .profile()
        .name("work")
        .with("claude")
        .with("bedrock")
        .policy("open")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("created");
    assert_eq!(created.profile().packs()[..2], ["claude", "@box/bedrock"]);
}

#[cfg(target_os = "macos")]
#[test]
fn your_provider_pack_with_a_shipped_name_answers_the_shipped_starter() {
    let host = crate::FakeHost::new();
    let folder = host.home().join(".strands/box/packs/bedrock");
    std::fs::create_dir_all(&folder).expect("a pack folder");
    std::fs::write(
        folder.join(lang::PACK_FILE),
        "\n[pack]\nname = \"bedrock\"\nversion = 1\nkind = \"support\"\n\
         extend = [\"@box/bedrock\"]",
    )
    .expect("a pack");
    let created = host
        .profile()
        .name("work")
        .with("claude")
        .with("bedrock")
        .policy("open")
        .answer(None)
        .and_then(|profile| profile.create())
        .expect("created");
    let packs = created.profile().packs();
    assert_eq!(packs[..2], ["@box/claude", "bedrock"]);
    assert!(!packs.contains(&"@box/bedrock".to_string()), "{packs:?}");
}

#[test]
fn a_run_of_a_profile_that_exists_refuses_a_config_toml_that_does_not_parse() {
    let host = crate::FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("created")
        .write(false)
        .expect("written");
    std::fs::write(
        host.home().join(".strands/box").join(CONFIG_FILE),
        "not toml [",
    )
    .expect("config");
    for flag in [None, Some(true), Some(false)] {
        let error = host
            .launcher()
            .banner(flag)
            .prepare("claude", &host.project(), None)
            .map(|_| ())
            .expect_err("a bad config.toml stops the run");
        assert!(matches!(error, Error::Config { .. }), "{flag:?}: {error}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn a_preview_of_a_profile_that_exists_does_not_read_config_toml() {
    let host = crate::FakeHost::new();
    host.profile()
        .with("claude")
        .with("bedrock")
        .create()
        .expect("created")
        .write(false)
        .expect("written");
    std::fs::write(
        host.home().join(".strands/box").join(CONFIG_FILE),
        "[starters]\nonly = 1\n",
    )
    .expect("config");
    host.launcher()
        .preview("claude", &host.project())
        .expect("a profile that exists resolves");
    let error = host
        .launcher()
        .preview("other", &host.project())
        .expect_err("a missing profile reads config.toml");
    assert!(matches!(error, Error::Config { .. }), "{error}");
}

#[test]
fn a_with_entry_for_a_question_that_its_when_skips_is_refused() {
    let fixture = Fixture::new();
    fixture.agent(&format!(
        "{PROVIDER_QUESTION}\n[[question]]\nid = \"proxy\"\nprompt = \"Proxy?\"\n\
         when = {{ variable = \"answers.provider\", equals = \"cloud\" }}\n\n\
         [[question.choice]]\nid = \"us\"\npacks = [\"@box/proxy-us\"]\n\n\
         [[question.choice]]\nid = \"eu\"\npacks = [\"@box/proxy-eu\"]\n"
    ));
    let error = fixture
        .answer(Call {
            with: &["local", "proxy-us"],
            ..Call::default()
        })
        .expect_err("a skipped question");
    assert!(
        error
            .to_string()
            .contains("asks only when question \"provider\" is answered \"cloud\""),
        "{error}"
    );
}

#[test]
fn an_option_given_twice_is_refused() {
    let fixture = Fixture::new();
    fixture.agent(PROVIDER_QUESTION);
    let error = fixture
        .answer(Call {
            with: &["local"],
            options: &[("cloud.region", "east-1"), ("cloud.region", "west-2")],
            ..Call::default()
        })
        .expect_err("twice");
    assert!(
        matches!(
            error,
            Error::OptionFlag {
                reason: "is given twice",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn an_input_with_from_is_never_asked_even_through_ask() {
    let fixture = Fixture::new();
    fixture.pack(
        "@box/github",
        "[pack]\nname = \"@box/github\"\nversion = 1\nkind = \"support\"\n\n[inputs.github.user]\n\
         description = \"The user.\"\nfrom = \"env:GITHUB_USER\"\n",
    );
    fixture.agent(&PROVIDER_QUESTION.replace(
        "label = \"The agent\"",
        "label = \"The agent\"\nask = [\"github.user\"]",
    ));
    let (answered, output) = fixture
        .answer(Call {
            with: &["local", "github"],
            interactive: true,
            ..Call::default()
        })
        .expect("answered");
    assert_eq!(
        answered,
        expected(
            &["@box/agent", "@box/local", "@box/github"],
            &[("agent.host", "local")]
        )
    );
    assert_eq!(output, "");
}

/// A starter that detects its provider from a settings file and the environment, and fills the
/// region of `@box/cloud` and the `bool` input `agent.ask` from the same file.
const DETECTING: &str = r#"
[inputs.agent.ask]
description = "Ask before each action."
type = "bool"
default = false

[inputs.agent.note]
description = "A note."
default = "none"

[starter]
label = "The agent"

[[source]]
id = "use-cloud"
label = "Provider"
places = [
  { file = "~/.agent/settings.json", kind = "json", key = ["env", "USE_CLOUD"] },
  { env = "USE_CLOUD" },
]

[[source]]
id = "region"
label = "Region"
input = "cloud.region"
places = [
  { file = "~/.agent/settings.json", kind = "json", key = ["env", "REGION"] },
  { env = "REGION" },
]

[[source]]
id = "mode"
label = "Permissions"
input = "agent.ask"
equals = ["ask", "plan"]
places = [{ file = "~/.agent/settings.json", kind = "json", key = ["permissions", "mode"] }]

[[question]]
id = "provider"
prompt = "Which provider?"

[[question.choice]]
id = "cloud"
label = "The cloud"
packs = ["@box/cloud"]
options = { "agent.host" = "cloud", "cloud.account" = "acct" }
detect = { source = "use-cloud", equals = ["1", "true"] }

[[question.choice]]
id = "local"
label = "This machine"
packs = ["@box/local"]
options = { "agent.host" = "local" }
detect = { source = "use-cloud", equals = "0" }
"#;

impl Fixture {
    /// Write `text` to the settings file of the detecting starter, under the fixture home.
    fn settings(&self, text: &str) {
        let folder = self.root.join("home/.agent");
        std::fs::create_dir_all(&folder).expect("a settings folder");
        std::fs::write(folder.join("settings.json"), text).expect("settings");
    }

    fn detected(&self, call: Call<'_>) -> Result<(Answered, Vec<String>), Error> {
        let (answered, _) = self.answer(call)?;
        let lines = answered
            .detected
            .iter()
            .map(|line| line.to_string())
            .collect();
        Ok((answered, lines))
    }
}

fn option<'a>(answered: &'a Answered, name: &str) -> Option<&'a str> {
    answered
        .options
        .iter()
        .find(|(known, _)| known == name)
        .map(|(_, value)| value.as_str())
}

#[test]
fn a_starter_refuses_a_source_or_detect_that_it_cannot_read() {
    let fixture = Fixture::new();
    refused(
        &fixture,
        &DETECTING.replace(
            "file = \"~/.agent/settings.json\"",
            "file = \"~/\", directory-env = \"AGENT_HOME\"",
        ),
        "has no file name",
    );
    refused(
        &fixture,
        &DETECTING.replace("{ env = \"REGION\" }", "{ env = \"REGION\", path = \"x\" }"),
        "holds the unknown key `path`",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "{ env = \"REGION\" }",
            "{ env = \"REGION\", file = \"~/x\", kind = \"json\", key = [\"a\"] }",
        ),
        "has both `file` and `env`",
    );
    refused(
        &fixture,
        &DETECTING.replace("id = \"region\"", "id = \"use-cloud\""),
        "two sources have the id \"use-cloud\"",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "source = \"use-cloud\", equals = \"0\"",
            "source = \"nope\", equals = \"0\"",
        ),
        "names the source \"nope\", which the starter does not have",
    );
    refused(
        &fixture,
        &DETECTING.replace("input = \"agent.ask\"\n", ""),
        "has `equals` but no `input`",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "id = \"use-cloud\"",
            "id = \"use-cloud\"\npack = \"@box/cloud\"",
        ),
        "has `pack` but no `input`",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "id = \"use-cloud\"",
            "id = \"use-cloud\"\npack = \"@box/cloud\"\ninput = \"agent.host\"",
        ),
        "cannot detect a choice from pack-specific source \"use-cloud\"",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "id = \"use-cloud\"",
            "id = \"use-cloud\"\npack = \"box/cloud\"\ninput = \"agent.host\"",
        ),
        "source \"use-cloud\": \"box/cloud\" is not a pack name; the pack that box ships is \
         @box/cloud",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "id = \"use-cloud\"",
            "id = \"use-cloud\"\npack = \"@box/clod\"\ninput = \"agent.host\"",
        ),
        "source \"use-cloud\": the pack \"@box/clod\" does not exist",
    );
    refused(
        &fixture,
        &DETECTING.replace(
            "file = \"~/.agent/settings.json\", kind = \"json\", key = [\"permissions\"",
            "file = \"settings.json\", kind = \"json\", key = [\"permissions\"",
        ),
        "is not absolute and does not start with `~/`",
    );
}

#[test]
fn a_detected_answer_answers_a_question_and_fills_its_inputs_without_a_terminal() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(
        r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}, "permissions": {"mode": "plan"}}"#,
    );
    let (answered, lines) = fixture.detected(Call::default()).expect("detected");
    assert_eq!(answered.packs, ["@box/agent", "@box/cloud"]);
    assert_eq!(option(&answered, "agent.host"), Some("cloud"));
    assert_eq!(option(&answered, "cloud.region"), Some("west-2"));
    assert_eq!(option(&answered, "agent.ask"), Some("true"));
    assert_eq!(
        lines,
        [
            "Provider | The cloud | env.USE_CLOUD in ~/.agent/settings.json",
            "Region | west-2 | env.REGION in ~/.agent/settings.json",
            "Permissions | true | permissions.mode in ~/.agent/settings.json",
        ]
    );
}

#[test]
fn switching_agents_reads_the_selected_agents_settings() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#);
    let first =
        std::fs::read_to_string(fixture.root.join("resources/packs/agent/pack.toml")).unwrap();
    fixture.pack("@box/other", &first.replace("@box/agent", "@box/other"));
    let first_starter = std::fs::read_to_string(
        fixture
            .root
            .join("resources")
            .join(STARTERS)
            .join("agent")
            .join(STARTER_FILE),
    )
    .unwrap();
    fixture.starter(
        "@box/other",
        &first_starter
            .replace("@box/agent", "@box/other")
            .replace("~/.agent/settings.json", "~/.other/settings.json"),
    );
    crate::test_support::write(
        &fixture.root.join("home/.other/settings.json"),
        r#"{"env": {"USE_CLOUD": "1", "REGION": "east-1"}}"#,
    );
    let mut host = Host::current();
    host.set_home(fixture.root.join("home"));
    host.variables = Some(Vec::new());
    let mut input = "\n\n\n".as_bytes();
    let mut output = Vec::new();
    let mut terminal = Terminal::new(&mut input, &mut output);
    terminal.session = Some(crate::prompt::Session::default());
    let request = Request {
        name: "mine",
        with: &[],
        options: &[],
        lookup: &fixture.lookup,
        path: &fixture
            .root
            .join("home/.strands/box/profiles/mine/profile.toml"),
        exists: false,
        host: &host,
        workspace: &fixture.root.join("project"),
    };
    for (pack, region) in [("@box/agent", "west-2"), ("@box/other", "east-1")] {
        let starter = Starter::load(pack, &fixture.lookup).unwrap();
        let answered = answer(&starter, &request, Some(&mut terminal), None).unwrap();
        assert_eq!(option(&answered, "cloud.region"), Some(region));
    }
}

#[test]
fn a_starter_reads_a_config_directory_from_the_environment() {
    let fixture = Fixture::new();
    fixture.agent(&DETECTING.replace(
        "file = \"~/.agent/settings.json\"",
        "file = \"~/.agent/settings.json\", directory-env = \"AGENT_HOME\"",
    ));
    let settings = r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#;
    fixture.settings(settings);
    let custom = fixture.root.join("custom");
    crate::test_support::write(
        &custom.join("settings.json"),
        &settings.replace("west-2", "east-1"),
    );
    for (variables, region) in [
        (vec![], "west-2"),
        (vec![("AGENT_HOME", "")], "west-2"),
        (vec![("AGENT_HOME", custom.to_str().unwrap())], "east-1"),
    ] {
        let (answered, _) = fixture
            .detected(Call {
                variables: &variables,
                ..Call::default()
            })
            .expect("settings select the provider and region");
        assert_eq!(answered.packs, ["@box/agent", "@box/cloud"]);
        assert_eq!(option(&answered, "cloud.region"), Some(region));
    }
    for directory in [
        "relative",
        fixture.root.join("home/.strands/box").to_str().unwrap(),
    ] {
        let (answered, lines) = fixture
            .detected(Call {
                variables: &[("AGENT_HOME", directory)],
                with: &["local"],
                ..Call::default()
            })
            .expect("invalid directories skip detection");
        assert_eq!(answered.packs, ["@box/agent", "@box/local"]);
        assert!(
            lines.iter().any(|line| line.contains("AGENT_HOME")),
            "{lines:?}"
        );
        assert_eq!(option(&answered, "cloud.region"), None);
    }
}

#[test]
fn reviewing_settings_prefills_detected_values_and_preserves_unrelated_answers() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(
        r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}, "permissions": {"mode": "plan"}}"#,
    );
    let (answered, output) = fixture
        .answer(Call {
            interactive: true,
            input: "\nnorth-3\n\n",
            review_settings: true,
            ..Call::default()
        })
        .expect("asked");
    assert!(output.contains("> [west-2] "), "{output}");
    assert_eq!(option(&answered, "agent.host"), Some("cloud"));
    assert_eq!(option(&answered, "cloud.region"), Some("north-3"));
    assert_eq!(
        option(&answered, "agent.ask"),
        Some("true"),
        "unrelated values stay"
    );
    let (answered, _) = fixture
        .detected(Call {
            interactive: true,
            input: "\n\n\n",
            review_settings: true,
            ..Call::default()
        })
        .expect("Enter keeps what was detected");
    assert_eq!(option(&answered, "agent.host"), Some("cloud"));
    assert_eq!(option(&answered, "cloud.region"), Some("west-2"));
    let (answered, _) = fixture
        .detected(Call {
            interactive: true,
            input: "2\n\n",
            review_settings: true,
            ..Call::default()
        })
        .expect("a changed provider");
    assert_eq!(answered.packs, ["@box/agent", "@box/local"]);
    assert_eq!(
        option(&answered, "cloud.region"),
        None,
        "a value of a pack the change removes is not asked or kept"
    );
}

#[test]
fn a_higher_place_wins_and_a_lower_place_fills_a_missing_key() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "true"}}"#);
    let (answered, lines) = fixture
        .detected(Call {
            variables: &[("USE_CLOUD", "0"), ("REGION", "south-1")],
            ..Call::default()
        })
        .expect("detected");
    assert_eq!(option(&answered, "agent.host"), Some("cloud"));
    assert_eq!(option(&answered, "cloud.region"), Some("south-1"));
    assert!(
        lines.contains(&"Region | south-1 | REGION in the environment".to_string()),
        "{lines:?}"
    );
}

#[test]
fn a_value_that_answers_no_choice_leaves_the_question_open_and_is_not_printed() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "https://user:secret@gateway"}}"#);
    let Err(Error::StarterUnanswered { question, .. }) = fixture.answer(Call::default()) else {
        panic!("an open question");
    };
    assert_eq!(question, "Which provider?");
    let (answered, lines) = fixture
        .detected(Call {
            interactive: true,
            input: "2\n",
            ..Call::default()
        })
        .expect("answered at the terminal");
    assert_eq!(option(&answered, "agent.host"), Some("local"));
    assert!(
        lines.iter().any(|line| line.starts_with("Provider | ")),
        "the unmatched value has a report line: {lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("secret")),
        "{lines:?}"
    );
    fixture.agent(&DETECTING.replace("equals = \"0\"", "equals = \"1\""));
    fixture.settings(r#"{"env": {"USE_CLOUD": "1"}}"#);
    let Err(Error::StarterUnanswered { .. }) = fixture.answer(Call::default()) else {
        panic!("two choices hold, so the question stays open");
    };
}

#[test]
fn a_value_that_answers_no_choice_is_named_by_its_place_in_the_report() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "https://user:secret@gateway"}}"#);
    let (_, lines) = fixture
        .detected(Call {
            interactive: true,
            input: "1\n",
            ..Call::default()
        })
        .expect("asked");
    assert!(
        lines.contains(
            &"Provider | env.USE_CLOUD in ~/.agent/settings.json matches no choice".to_string()
        ),
        "{lines:?}"
    );
}

#[test]
fn the_flags_beat_a_detected_answer() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#);
    let (answered, _) = fixture
        .detected(Call {
            with: &["local"],
            ..Call::default()
        })
        .expect("answered by --with");
    assert_eq!(answered.packs, ["@box/agent", "@box/local"]);
    let (answered, _) = fixture
        .detected(Call {
            options: &[("cloud.region", "north-9")],
            ..Call::default()
        })
        .expect("answered by --option");
    assert_eq!(option(&answered, "cloud.region"), Some("north-9"));
}

#[test]
fn a_source_whose_input_no_chosen_pack_declares_is_not_used() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "0", "REGION": "west-2"}}"#);
    let (answered, lines) = fixture.detected(Call::default()).expect("detected");
    assert_eq!(answered.packs, ["@box/agent", "@box/local"]);
    assert_eq!(option(&answered, "cloud.region"), None);
    assert!(
        lines.iter().all(|line| !line.starts_with("Region")),
        "{lines:?}"
    );
}

#[test]
fn a_detected_value_that_its_input_refuses_is_not_used_or_printed() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "sk-secret-value"}}"#);
    let (answered, lines) = fixture.detected(Call::default()).expect("detected");
    assert_eq!(option(&answered, "cloud.region"), None);
    assert!(
        lines.contains(
            &"Region | env.REGION in ~/.agent/settings.json is not a valid cloud.region"
                .to_string()
        ),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains("sk-secret")),
        "{lines:?}"
    );
}

#[test]
fn a_source_that_fills_an_unbounded_input_stops_the_step() {
    let fixture = Fixture::new();
    fixture.agent(&DETECTING.replace("input = \"cloud.region\"", "input = \"agent.note\""));
    fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#);
    let error = fixture
        .answer(Call::default())
        .expect_err("an unbounded input");
    assert!(
        error.to_string().contains("has no `pattern` or `values`"),
        "{error}"
    );
}

#[test]
fn a_bool_source_gives_true_false_or_the_default_and_never_its_value() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "0"}, "permissions": {"mode": "yolo-secret"}}"#);
    let (answered, lines) = fixture.detected(Call::default()).expect("detected");
    assert_eq!(option(&answered, "agent.ask"), Some("false"));
    assert!(lines.iter().all(|line| !line.contains("yolo")), "{lines:?}");
    for mode in ["ask", "plan"] {
        fixture.settings(&format!(
            r#"{{"env": {{"USE_CLOUD": "0"}}, "permissions": {{"mode": "{mode}"}}}}"#
        ));
        let (answered, _) = fixture.detected(Call::default()).expect("detected");
        assert_eq!(option(&answered, "agent.ask"), Some("true"), "{mode}");
    }
    fixture.settings(r#"{"env": {"USE_CLOUD": "0"}}"#);
    let (answered, _) = fixture.detected(Call::default()).expect("detected");
    assert_eq!(option(&answered, "agent.ask"), None);
    fixture.agent(&DETECTING.replace("input = \"agent.ask\"", "input = \"agent.note\""));
    let error = fixture
        .answer(Call::default())
        .expect_err("equals on a string input");
    assert!(
        error
            .to_string()
            .contains("`equals` is only for a `bool` input"),
        "{error}"
    );
}

#[test]
fn a_place_that_reads_a_variable_that_a_secret_source_passes_stops_the_step() {
    let table: toml::Table = toml::from_str(
        "[secret-source.op]\ncommand = [\"/usr/local/bin/op\"]\npass-secret-env = [\"OP_SESSION_*\"]",
    )
    .expect("TOML");
    let credentials = crate::reference::Credentials::of(&table, &std::collections::BTreeMap::new());
    let place = |variable: &str| crate::detect::Source {
        id: "session".to_string(),
        label: "Session".to_string(),
        input: None,
        pack: None,
        equals: Vec::new(),
        places: vec![crate::detect::Place {
            at: crate::detect::At::Env(variable.to_string()),
            when: None,
        }],
    };
    assert_eq!(
        crate::detect::credential_place(&[place("OP_SESSION_my")], &credentials),
        Some(
            "source \"session\" reads OP_SESSION_my, which `[secret-source.op]` of the profile \
             passes to its program as a credential; detection reads no credential"
                .to_string()
        )
    );
    assert_eq!(
        crate::detect::credential_place(&[place("OP_ACCOUNT")], &credentials),
        None
    );
}

#[test]
fn a_place_that_reads_a_variable_that_a_saved_profiles_source_passes_stops_the_step() {
    let plugin = "[plugin]\nname = \"@box/1password\"\nversion = 1\nkind = \"secret-source\"\n\
                  scheme = \"op\"\n\
                  [inputs.onepassword.path]\ntype = \"program\"\nprogram = \"op\"\n\
                  [run]\n\
                  command = [\"${{ inputs.onepassword.path }}\", \"read\", \"op://{ref}\"]\n\
                  [env]\n\
                  OP_ACCOUNT = { from = \"env:OP_ACCOUNT\" }\n\
                  OP_SERVICE_ACCOUNT_TOKEN = { from = \"env:OP_SERVICE_ACCOUNT_TOKEN\" }\n\
                  [protect]\nenv = [\"OP_SERVICE_ACCOUNT_TOKEN\"]\n";
    let own = "[secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"{ref}\"]\n\
               pass-secret-env = [\"USE_*\"]\n";
    let listed = "plugins = [\"@box/1password\"]\n";
    let by_plugin = "the plugin @box/1password";
    for (saved, variable, holder) in [
        (
            own,
            "USE_CLOUD",
            Some("`[secret-source.vault]` of the profile"),
        ),
        (listed, "OP_SERVICE_ACCOUNT_TOKEN", Some(by_plugin)),
        (listed, "OP_SESSION_my", None),
        (listed, "OP_ACCOUNT", None),
        ("", "OP_SERVICE_ACCOUNT_TOKEN", None),
    ] {
        let fixture = Fixture::new();
        let folder = fixture.root.join("resources/plugins/1password");
        std::fs::create_dir_all(&folder).expect("a plugin folder");
        std::fs::write(folder.join("plugin.toml"), plugin).expect("a plugin");
        fixture.agent(&DETECTING.replace("USE_CLOUD", variable));
        let profile = crate::Profile::parse(saved, Path::new("profile.toml"), crate::VERSION)
            .expect("a profile");
        let answered = fixture.answer(Call {
            saved: Some(&profile),
            ..Call::default()
        });
        match holder {
            Some(holder) => {
                let error = answered.expect_err("a credential place");
                assert!(
                    error.to_string().contains(&format!(
                        "source \"use-cloud\" reads {variable}, which {holder} passes to its \
                         program as a credential; detection reads no credential"
                    )),
                    "{saved}{variable}: {error}"
                );
            }
            None => {
                answered.expect("a place that reads no credential");
            }
        }
    }
}

#[test]
fn a_pack_specific_source_follows_a_local_replacement_or_inherited_pack() {
    for inherited in [false, true] {
        let fixture = Fixture::new();
        let scope = if inherited {
            "@box/github"
        } else {
            "@box/cloud"
        };
        fixture.agent(&DETECTING.replace(
            "input = \"cloud.region\"",
            &format!("input = \"cloud.region\"\npack = \"{scope}\""),
        ));
        if inherited {
            fixture.pack(
                "@box/cloud",
                &PROVIDER.replace(
                    "kind = \"support\"",
                    "kind = \"support\"\nextend = [\"@box/github\"]",
                ),
            );
        } else {
            fixture.pack("cloud", &PROVIDER.replace("@box/cloud", "cloud"));
        }
        fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#);
        let (answered, lines) = fixture
            .detected(Call {
                with: &["cloud"],
                ..Call::default()
            })
            .expect("selected pack");
        assert_eq!(
            option(&answered, "cloud.region"),
            Some("west-2"),
            "{lines:?}"
        );
    }
}

#[test]
fn a_credential_inherited_by_an_unselected_choice_stops_detection() {
    let fixture = Fixture::new();
    fixture.pack(
        "@box/cloud",
        &format!("{PROVIDER}\n[egress.model]\ndestinations = [\"cloud.example.com\"]\n"),
    );
    fixture.pack(
        "@box/local",
        "[pack]\nname = \"@box/local\"\nversion = 1\nkind = \"support\"\nextend = [\"@box/github\"]\n",
    );
    fixture.pack(
        "@box/github",
        "[pack]\nname = \"@box/github\"\nversion = 1\nkind = \"support\"\n\n[egress.model]\ndestinations = \
         [\"model.example.com\"]\nsecret.ref = \"env://USE_CLOUD\"\n",
    );
    fixture.agent(DETECTING);
    let error = fixture
        .answer(Call {
            with: &["cloud"],
            ..Call::default()
        })
        .expect_err("a credential place");
    assert!(
        error
            .to_string()
            .contains("reads USE_CLOUD, which a route or a server names as its credential"),
        "{error}"
    );
    fixture.agent(&DETECTING.replace(
        "file = \"~/.agent/settings.json\"",
        "file = \"~/.agent/settings.json\", directory-env = \"SECRET_HOME\"",
    ));
    fixture.pack(
        "@box/local",
        "[pack]\nname = '@box/local'\nversion = 1\nkind = 'support'\n\
         [egress.model]\ndestinations = ['model.example.com']\n\
         secret.ref = 'env://SECRET_HOME'\n",
    );
    let error = fixture
        .answer(Call::default())
        .expect_err("a directory variable cannot read a credential");
    assert!(
        error
            .to_string()
            .contains("reads SECRET_HOME, which a route or a server names as its credential"),
        "{error}"
    );
}

/// A file place in a path that a secret source lists in `reads` or `deny` is skipped, so
/// detection reads no file that the box keeps from every workload.
#[test]
fn a_file_place_in_a_path_that_a_secret_source_protects_is_skipped() {
    for (reads, region) in [("~/.agent", None), ("~/.other", Some("west-2"))] {
        let fixture = Fixture::new();
        fixture.agent(DETECTING);
        fixture.settings(r#"{"env": {"REGION": "west-2"}}"#);
        let saved = crate::Profile::parse(
            &format!(
                "[secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"{{ref}}\"]\n\
                 reads = [{reads:?}]\n"
            ),
            Path::new("profile.toml"),
            crate::VERSION,
        )
        .expect("a profile");
        let (answered, lines) = fixture
            .detected(Call {
                saved: Some(&saved),
                with: &["cloud"],
                options: &[("cloud.account", "1")],
                ..Call::default()
            })
            .expect("a starter");
        assert_eq!(
            option(&answered, "cloud.region"),
            region,
            "{reads}: {lines:?}"
        );
        let skipped = lines.iter().any(|line| {
            line.contains(
                "~/.agent/settings.json lies in ~/.agent, a path that `[secret-source.vault]` of \
                 the profile lists in `reads`, which the box keeps from every workload; detection \
                 does not read it",
            )
        });
        assert_eq!(skipped, region.is_none(), "{reads}: {lines:?}");
    }
}

#[test]
fn a_starter_with_no_packs_still_skips_the_current_directory_and_box_home() {
    let fixture = Fixture::new();
    let project = fixture.root.join("project/settings.json");
    crate::test_support::write(&project, r#"{"provider": "cloud"}"#);
    fixture.agent(&format!(
        r#"
[starter]
packs = []
[[source]]
id = "provider"
places = [
  {{ file = "{}", kind = "json", key = ["provider"] }},
  {{ file = "~/.strands/box/settings.json", kind = "json", key = ["provider"] }},
]
"#,
        project.display()
    ));
    let (_, lines) = fixture.detected(Call::default()).expect("a starter");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].contains("lies in the current directory"),
        "{lines:?}"
    );
    assert!(lines[1].contains("lies in the box home"), "{lines:?}");
}

#[test]
fn a_place_that_a_with_pack_routes_as_a_credential_stops_the_step() {
    let fixture = Fixture::new();
    fixture.pack(
        "@box/github",
        "[pack]\nname = \"@box/github\"\nversion = 1\nkind = \"support\"\n\n[egress.github]\ndestinations = \
         [\"api.github.com\"]\nsecret.ref = \"env://REGION\"\n",
    );
    fixture.agent(DETECTING);
    let error = fixture
        .answer(Call {
            with: &["local", "github"],
            ..Call::default()
        })
        .expect_err("a credential that a --with pack routes");
    assert!(
        error
            .to_string()
            .contains("reads REGION, which a route or a server names as its credential"),
        "{error}"
    );
}

#[test]
fn a_place_under_an_unselected_choices_conditional_write_grant_is_skipped() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.pack(
        "@box/cloud",
        &format!("{PROVIDER}\n[mcp.cloud.filesystem]\nwrite = [{{ path = \"~/.agent\", when = \"macos\" }}]\n"),
    );
    fixture.settings(r#"{"env": {"USE_CLOUD": "1"}}"#);
    let (answered, lines) = fixture
        .detected(Call {
            with: &["local"],
            ..Call::default()
        })
        .expect("answered by --with");
    assert_eq!(option(&answered, "agent.host"), Some("local"));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("Provider | ") && line.contains("a write grant")),
        "{lines:?}"
    );
}

#[test]
fn a_place_under_a_write_grant_above_the_workspace_is_skipped() {
    let fixture = Fixture::new();
    fixture.agent(&format!(
        "[filesystem]\nwrite = [\"${{{{ workspace.parent }}}}/.agent\"]\n{DETECTING}"
    ));
    fixture.settings(r#"{"env": {"USE_CLOUD": "1"}}"#);
    let (answered, lines) = fixture
        .detected(Call {
            with: &["local"],
            workspace: Some("home/project"),
            ..Call::default()
        })
        .expect("answered by --with");
    assert_eq!(option(&answered, "agent.host"), Some("local"));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("Provider | ") && line.contains("a write grant")),
        "{lines:?}"
    );
}

#[test]
fn a_create_run_from_the_home_folder_still_reads_the_settings_there() {
    let fixture = Fixture::new();
    fixture.agent(DETECTING);
    fixture.settings(r#"{"env": {"USE_CLOUD": "1", "REGION": "west-2"}}"#);
    let (answered, lines) = fixture
        .detected(Call {
            workspace: Some("home"),
            ..Call::default()
        })
        .expect("detected from the home folder");
    assert_eq!(option(&answered, "agent.host"), Some("cloud"), "{lines:?}");
    assert_eq!(
        option(&answered, "cloud.region"),
        Some("west-2"),
        "{lines:?}"
    );
}

#[test]
fn an_own_pack_in_place_of_a_choice_pack_with_its_route_still_answers() {
    let fixture = Fixture::new();
    let routed = format!(
        "{PROVIDER}\n[egress.cloud]\ndestinations = [\"model.example.com\"]\nsecret.ref = \
         \"env://CLOUD_KEY\"\n"
    );
    fixture.pack("@box/cloud", &routed);
    fixture.pack(
        "cloud",
        &routed.replace("name = \"@box/cloud\"", "name = \"cloud\""),
    );
    fixture.agent(DETECTING);
    let (answered, _) = fixture
        .detected(Call {
            with: &["cloud"],
            options: &[("cloud.account", "acct")],
            ..Call::default()
        })
        .expect("the own pack stands in for @box/cloud");
    assert!(
        answered.packs.contains(&"cloud".to_string()),
        "{:?}",
        answered.packs
    );
    assert!(
        !answered.packs.contains(&"@box/cloud".to_string()),
        "{:?}",
        answered.packs
    );
}

#[test]
fn a_starter_policy_names_a_shipped_policy_starter() {
    let fixture = Fixture::new();
    let folder = fixture.root.join("resources/policies/shut");
    std::fs::create_dir_all(&folder).expect("a policy folder");
    std::fs::write(
        folder.join(crate::policy_starter::STARTER_FILE),
        "[policy]\nname = \"@box/shut\"\nlabel = \"Shut\"\ndescription = \"No host.\"\n",
    )
    .expect("policy.toml");
    fixture.agent("[starter]\nlabel = \"The agent\"\npolicy = \"@box/shut\"\n");
    assert_eq!(
        fixture.parse().expect("a starter").policy.as_deref(),
        Some("@box/shut")
    );
    let (answered, _) = fixture.answer(Call::default()).expect("answered");
    assert_eq!(answered.policy.as_deref(), Some("@box/shut"));
    refused(
        &fixture,
        "[starter]\npolicy = \"@box/gone\"\n",
        "`[starter] policy`: box ships no policy named @box/gone",
    );
    refused(
        &fixture,
        "[starter]\npolicy = \"@box/Mine\"\n",
        "`[starter] policy`: \"@box/Mine\" is not a policy name",
    );
    fixture.agent("[starter]\nlabel = \"The agent\"\npolicy = \"shut\"\n");
    assert_eq!(
        fixture.parse().expect("a short name").policy.as_deref(),
        Some("@box/shut")
    );
    let own = fixture.root.join("home/.strands/box/policies/mine");
    std::fs::create_dir_all(&own).expect("an own policy folder");
    std::fs::write(
        own.join(crate::policy_starter::STARTER_FILE),
        "[policy]\nname = \"mine\"\nlabel = \"Mine\"\ndescription = \"Mine.\"\n",
    )
    .expect("policy.toml");
    fixture.agent("[starter]\nlabel = \"The agent\"\npolicy = \"mine\"\n");
    assert_eq!(
        fixture.parse().expect("an own policy").policy.as_deref(),
        Some("mine")
    );
    refused(
        &fixture,
        "[starter]\npolicy = 1\n",
        "`[starter] policy` is not a policy name",
    );
}

/// The fixture with the tool packs `alpha`, `beta`, and `gamma`, and `[tools] defaults` set to
/// `defaults`.
fn tools_fixture(defaults: &str) -> Fixture {
    let fixture = Fixture::new();
    for tool in ["alpha", "beta", "gamma"] {
        fixture.pack(
            &format!("@box/{tool}"),
            &format!(
                "\n[pack]\nname = \"@box/{tool}\"\nversion = 1\n{}",
                crate::lang::test_tool_pack(tool, "")
            ),
        );
    }
    fixture.built_in(&format!(
        "[starters]\nonly = [\"@box/agent\"]\n\n[tools]\ndefaults = {defaults}\n"
    ));
    fixture
}

#[test]
fn the_default_tools_are_the_shipped_list_in_its_order() {
    let fixture = tools_fixture("[\"gamma\", \"alpha\"]");
    assert_eq!(
        default_tools(&fixture.lookup).expect("the defaults"),
        ["@box/gamma", "@box/alpha"]
    );
    let fixture = tools_fixture("[]");
    assert!(
        default_tools(&fixture.lookup)
            .expect("the defaults")
            .is_empty()
    );
}

#[test]
fn a_default_tool_must_be_a_shipped_tool_pack_named_once() {
    for (defaults, reason) in [
        (
            "[\"alpha\", \"delta\"]",
            "names `delta`, which is not a tool pack `box` ships",
        ),
        (
            "[\"cloud\"]",
            "names `cloud`, which is not a tool pack `box` ships",
        ),
        ("[\"alpha\", \"alpha\"]", "names `alpha` twice"),
        (
            "\"alpha\"",
            "`[tools] defaults` is not a list of tool names",
        ),
    ] {
        let error = default_tools(&tools_fixture(defaults).lookup)
            .expect_err(defaults)
            .to_string();
        assert!(error.contains(reason), "{defaults}: {error}");
    }
}

#[test]
fn a_shipped_config_with_no_default_tools_is_refused() {
    let fixture = tools_fixture("[\"alpha\"]");
    for (config, reason) in [
        (
            "[starters]\nonly = [\"@box/agent\"]\n",
            "`config.toml` holds no `[tools] defaults`",
        ),
        (
            "[starters]\nonly = [\"@box/agent\"]\n\n[tools]\n",
            "`config.toml` holds no `[tools] defaults`",
        ),
    ] {
        fixture.built_in(config);
        let error = default_tools(&fixture.lookup)
            .expect_err(config)
            .to_string();
        assert!(error.contains(reason), "{config}: {error}");
    }
    std::fs::remove_file(fixture.root.join("resources").join(CONFIG_FILE)).expect("a removal");
    let error = default_tools(&fixture.lookup)
        .expect_err("no file")
        .to_string();
    assert!(
        error.contains("the `config.toml` that ships with `box` is missing"),
        "{error}"
    );
}

#[test]
fn your_config_cannot_set_the_default_tools() {
    let fixture = tools_fixture("[\"alpha\"]");
    fixture.config("[tools]\ndefaults = [\"beta\"]\n");
    let error = Menu::load(&fixture.lookup)
        .expect_err("a refusal")
        .to_string();
    assert!(
        error.contains("`config.toml` holds the unknown key `tools`; it holds `[starters]` and `[policy-starters]`"),
        "{error}"
    );
    assert_eq!(
        default_tools(&fixture.lookup).expect("the defaults"),
        ["@box/alpha"]
    );
}

#[test]
fn every_shipped_default_tool_is_a_shipped_tool_pack() {
    let lookup = Lookup {
        vendored: Some(crate::resources::source_tree().join("packs")),
        operator: PathBuf::new(),
        collections: Vec::new(),
        version: crate::VERSION,
    };
    let defaults = default_tools(&lookup).expect("the shipped defaults resolve");
    assert!(!defaults.is_empty());
}

#[test]
fn a_collection_adds_and_removes_starters_by_full_name_and_the_operator_still_wins() {
    let mut fixture = Fixture::new();
    fixture.agent("");
    let root = fixture.root.join("org/box");
    for (folder, text) in [
        (
            "packs/helper/pack.toml",
            "[pack]\nname = \"@acme/helper\"\nversion = 1\nkind = \"agent\"\n\
             [run]\ncommand = [\"/bin/helper\"]\n",
        ),
        (
            "starters/helper/starter.toml",
            "[starter]\nname = \"@acme/helper\"\nlabel = \"Acme helper\"\n\
             packs = [\"@acme/helper\"]\n",
        ),
    ] {
        let path = root.join(folder);
        std::fs::create_dir_all(path.parent().expect("a folder")).expect("a folder");
        std::fs::write(path, text).expect("a file");
    }
    let collection = |text: &str| {
        std::fs::write(
            root.join(crate::collection::COLLECTION_FILE),
            format!("[starters]\n{text}"),
        )
        .expect("collection.toml");
    };
    fixture.lookup.collections.push(crate::lang::Collection {
        scope: "acme".into(),
        root: root.clone(),
    });
    let menu = |fixture: &Fixture| {
        Menu::load(&fixture.lookup)
            .map(|menu| menu.starters)
            .map_err(|error| error.to_string())
    };
    collection("add = [\"@acme/helper\"]\n");
    assert_eq!(
        menu(&fixture).expect("a menu"),
        ["@box/agent", "@acme/helper"]
    );
    let loaded = Menu::load(&fixture.lookup).expect("a menu");
    assert_eq!(
        loaded.named(&fixture.lookup, "@acme/helper"),
        Some("@acme/helper")
    );
    assert_eq!(
        loaded.named(&fixture.lookup, "helper"),
        None,
        "a short name never reaches a collection"
    );
    let starter = Starter::load("@acme/helper", &fixture.lookup).expect("the starter");
    assert_eq!(starter.label, "Acme helper");
    assert_eq!(starter.packs, ["@acme/helper"]);
    collection("add = [\"@acme/helper\"]\nremove = [\"@box/agent\"]\n");
    assert_eq!(menu(&fixture).expect("a menu"), ["@acme/helper"]);
    fixture.config("[starters]\nremove = [\"@acme/helper\"]\nadd = [\"@box/agent\"]\n");
    assert_eq!(menu(&fixture).expect("a menu"), ["@box/agent"]);
    fixture.config("[starters]\nonly = [\"@box/agent\", \"@acme/helper\"]\n");
    assert_eq!(
        menu(&fixture).expect("a menu"),
        ["@box/agent", "@acme/helper"]
    );
    fixture.config("[starters]\nadd = [\"@other/helper\"]\n");
    let error = menu(&fixture).expect_err("an unknown collection");
    assert!(error.contains("names the collection @other"), "{error}");
    fixture.config("");
    collection("remove = [\"@box/none\"]\n");
    let error = menu(&fixture).expect_err("an unknown removal");
    assert!(
        error.contains("collection.toml") && error.contains("\"@box/none\""),
        "{error}"
    );
}

#[test]
fn a_collection_starter_is_read_with_the_same_link_rules() {
    let mut fixture = Fixture::new();
    let root = fixture.root.join("org/box");
    let folder = root.join(STARTERS).join("helper");
    std::fs::create_dir_all(&folder).expect("a starter folder");
    let real = fixture.root.join("elsewhere.toml");
    std::fs::write(
        &real,
        "[starter]\nname = \"@acme/helper\"\nlabel = \"Acme helper\"\npacks = [\"@box/agent\"]\n",
    )
    .expect("a starter");
    std::os::unix::fs::symlink(&real, folder.join(STARTER_FILE)).expect("a link");
    fixture.lookup.collections.push(crate::lang::Collection {
        scope: "acme".into(),
        root,
    });
    let error = Starter::load("@acme/helper", &fixture.lookup).expect_err("a linked starter");
    assert!(error.contains("symbolic link"), "{error}");
    std::fs::remove_file(folder.join(STARTER_FILE)).expect("remove the link");
    std::fs::hard_link(&real, folder.join(STARTER_FILE)).expect("a hard link");
    let error = Starter::load("@acme/helper", &fixture.lookup).expect_err("a hard link");
    assert!(error.contains("exactly one hard link"), "{error}");
}

#[test]
fn a_remove_that_an_earlier_layer_already_made_changes_nothing() {
    let mut fixture = Fixture::new();
    fixture.built_in("[starters]\nonly = [\"@box/agent\", \"@box/cloud\"]\n");
    for scope in ["acme", "beta"] {
        let root = fixture.root.join(scope);
        std::fs::create_dir_all(&root).expect("a collection");
        std::fs::write(
            root.join(crate::collection::COLLECTION_FILE),
            "[starters]\nremove = [\"@box/cloud\"]\n",
        )
        .expect("collection.toml");
        fixture.lookup.collections.push(crate::lang::Collection {
            scope: scope.into(),
            root,
        });
    }
    fixture.config("[starters]\nremove = [\"@box/cloud\"]\n");
    let menu = Menu::load(&fixture.lookup).expect("each layer may remove the same starter");
    assert_eq!(menu.starters, ["@box/agent"]);
    fixture.config("[starters]\nremove = [\"@box/codx\"]\n");
    let error = Menu::load(&fixture.lookup).expect_err("a typo").to_string();
    assert!(
        error.contains("\"@box/codx\", which is not in the starter menu"),
        "{error}"
    );
}
