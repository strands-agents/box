#![cfg(unix)]

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const GUIDE: &str = "editing-box-profile.md";
const STALE: &str =
    "---\n# box-managed-profile-editing-guide\nname: editing-box-profile\n---\nold guidance\n";

fn fixture(profile: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("box-guide-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let home = root.path().join("home");
    let folder = home.join(".strands/box/profiles/test");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::create_dir(home.join("project")).unwrap();
    std::fs::write(folder.join("profile.toml"), profile).unwrap();
    (root, home)
}

fn command(home: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_box"))
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(home.join("project"))
        .output()
        .unwrap()
}

#[test]
fn show_displays_saved_settings_without_allowing_a_run_over_the_launcher() {
    let source = "[agent]\ncommand = [\"/usr/bin/true\"]\n\n[project]\naccess = \"write\"\n";
    let (_root, home) = fixture(source);
    let workspace = Path::new(env!("CARGO_BIN_EXE_box")).parent().unwrap();
    let mut commands: Vec<&[&str]> = vec![&["profile", "show", "--full", "test"]];
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        commands.push(&["run", "test", "--no-banner"]);
    }
    for arguments in commands {
        let result = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(arguments)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(workspace)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(
            error.contains("could change files that box trusts"),
            "{error}"
        );
        let output = String::from_utf8(result.stdout).unwrap();
        if arguments[0] == "profile" {
            assert!(
                output.contains("Saved settings") && output.contains(source),
                "{output}"
            );
            assert!(output.contains("Run preview unavailable"), "{output}");
            assert!(!output.contains("Resolves for this directory"), "{output}");
        }
        let runs = home.join(".strands/box/r");
        assert!(!runs.exists() || std::fs::read_dir(runs).unwrap().next().is_none());
        assert!(!home.join(".strands/box/storage").exists());
    }
}

#[test]
fn show_and_run_leave_an_old_copy_in_a_profile_folder_unchanged() {
    for profile in [
        "[not valid TOML\n",
        "[agent]\ncommand = [\"/usr/bin/true\"]\n",
    ] {
        let (_root, home) = fixture(profile);
        let copy = home.join(".strands/box/profiles/test").join(GUIDE);
        std::fs::write(&copy, STALE).unwrap();
        let before = std::fs::metadata(&copy).unwrap();
        for arguments in [
            &["profile", "show", "test"][..],
            &["profile", "show", "--full", "test"],
            &["run", "test", "--no-banner"],
        ] {
            let result = command(&home, arguments);
            let stderr = String::from_utf8(result.stderr).unwrap();
            assert!(
                !stderr.contains("refresh") && !stderr.contains(GUIDE),
                "{arguments:?}: {stderr}"
            );
            assert_eq!(std::fs::read_to_string(&copy).unwrap(), STALE);
            let after = std::fs::metadata(&copy).unwrap();
            assert_eq!(
                (before.ino(), before.mtime_nsec()),
                (after.ino(), after.mtime_nsec()),
                "{arguments:?}"
            );
            assert!(
                !home.join(".strands/box").join(GUIDE).exists(),
                "{arguments:?}"
            );
        }
    }
}

const ASSET: &str = include_str!("../../../../resources/editing-box-profile.md");

const PACK: &str = "[pack]\nname = \"extra\"\nversion = 1\nkind = \"support\"\n\n\
[inputs.extra.host]\ndescription = \"A host the box reaches.\"\npattern = \"[a-z.]+\"\n\
default = \"example.com\"\n\n[egress.extra]\ndestinations = [\"${{ inputs.extra.host }}\"]\n";

const BASE: &str = "policies = [\"policy.dw\"]\n\n[project]\naccess = \"write\"\n\n\
[agent]\ncommand = [\"/usr/bin/true\"]\n";

const POLICY: &str = "@id(\"shell_commands\")\n\
permit (principal, action == Box::Action::\"shell:exec\", resource);\n";

/// A home with the profile `test`, its `policy.dw`, and the operator pack `extra`.
fn configured(profile: &str, rules: &str) -> (tempfile::TempDir, PathBuf) {
    let (root, home) = fixture(profile);
    let folder = home.join(".strands/box/profiles/test");
    std::fs::write(folder.join("policy.dw"), format!("{POLICY}{rules}")).unwrap();
    let pack = home.join(".strands/box/packs/extra");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("pack.toml"), PACK).unwrap();
    std::fs::create_dir(home.join("notes")).unwrap();
    (root, home)
}

/// The `## ` section of the guide whose heading gives the anchor `anchor`.
fn section(anchor: &str) -> String {
    let slug = |heading: &str| {
        heading
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join("-")
    };
    let text = ASSET
        .split("\n## ")
        .skip(1)
        .find(|text| slug(text.lines().next().unwrap_or_default()) == anchor)
        .unwrap_or_else(|| panic!("the guide has no section {anchor}"));
    format!("## {text}")
}

fn guide(home: &Path) -> Output {
    command(home, &["help", "agent"])
}

fn packs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../resources/packs")
}

/// `box` with the resource directory `resources`, and no other variable but `HOME` and `PATH`.
fn with_resources(home: &Path, resources: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_box"))
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("BOX_RESOURCES", resources)
        .current_dir(home)
        .output()
        .unwrap()
}

/// What `box help agent` prints for the resource directory and the Box home.
fn topic(resources: &Path, box_home: &Path, names: &str) -> String {
    format!(
        "Read this file and follow it to create or change a profile:\n  {resources}/{GUIDE}\n\n\
         box         {version}\n\
         box home    {home}\n\
         profiles    {home}/profiles   ({names})\n\
         packs       {resources}/packs\n\n\
         For one profile, run: box profile show <name> --full\n\
         Run this on the host, not in a box. A boxed agent cannot change a profile.\n",
        resources = resources.display(),
        home = box_home.display(),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Each entry under `root` with its type and, for a file, its bytes.
fn tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    entries
        .into_iter()
        .flat_map(|path| {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                let below = tree(&path);
                std::iter::once((path, None)).chain(below).collect()
            } else {
                let bytes = metadata.is_file().then(|| std::fs::read(&path).unwrap());
                vec![(path, bytes)]
            }
        })
        .collect()
}

#[test]
fn help_agent_prints_the_shipped_guide_and_where_things_are_and_writes_nothing() {
    let (_root, home) = fixture(BASE);
    // `box` prints the home with its links resolved, and `/var` is a link on macOS.
    let box_home = home.canonicalize().unwrap().join(".strands/box");
    let resources = packs().parent().unwrap().canonicalize().unwrap();
    assert!(std::fs::read_to_string(resources.join(GUIDE)).unwrap() == ASSET);
    for name in ["work", "alpha"] {
        let folder = box_home.join("profiles").join(name);
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("profile.toml"), BASE).unwrap();
    }
    let before = tree(&home);
    let output = with_resources(&home, &resources, &["help", "agent"]);
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        topic(&resources, &box_home, "alpha, test, work")
    );
    assert_eq!(tree(&home), before);
}

#[test]
fn help_agent_leaves_a_guide_that_an_older_box_wrote_and_never_reads_it() {
    for old in [STALE, "# My guide\n"] {
        let (_root, home) = fixture(BASE);
        let path = home.join(".strands/box").join(GUIDE);
        std::fs::write(&path, old).unwrap();
        let written = std::fs::metadata(&path).unwrap();
        let before = tree(&home);
        let output = guide(&home);
        assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
        assert!(output.status.success());
        let printed = String::from_utf8(output.stdout).unwrap();
        assert!(
            !printed.contains(&path.display().to_string()) && !printed.contains("yours"),
            "{printed}"
        );
        assert_eq!(tree(&home), before);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (written.ino(), written.mtime_nsec()),
            (after.ino(), after.mtime_nsec())
        );
    }
    let (_root, home) = fixture(BASE);
    let path = home.join(".strands/box").join(GUIDE);
    let outside = home.join("outside.md");
    std::fs::write(&outside, STALE).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(guide(&home).status.success());
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), STALE);
    assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
}

#[test]
fn help_agent_makes_no_box_home() {
    let (_root, home) = fixture(BASE);
    std::fs::remove_dir_all(home.join(".strands/box")).unwrap();
    let box_home = home.canonicalize().unwrap().join(".strands/box");
    let resources = packs().parent().unwrap().canonicalize().unwrap();
    let before = tree(&home);
    let output = with_resources(&home, &resources, &["help", "agent"]);
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        topic(&resources, &box_home, "none")
    );
    assert!(!box_home.exists());
    assert_eq!(tree(&home), before);
}

#[test]
fn help_agent_fails_and_names_where_it_looked_when_the_guide_did_not_ship() {
    let (_root, home) = fixture(BASE);
    let absent = home.join("absent");
    let packs_only = home.join("resources");
    std::fs::create_dir_all(packs_only.join("packs")).unwrap();
    for (resources, message) in [
        (&absent, format!("lookedat{}.", absent.display())),
        (
            &packs_only,
            format!(
                "theprofileguideismissing:{}doesnotexist",
                packs_only.join(GUIDE).display()
            ),
        ),
    ] {
        let before = tree(&home);
        let output = with_resources(&home, resources, &["help", "agent"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "{output:?}");
        let error: String = String::from_utf8(output.stderr)
            .unwrap()
            .split_whitespace()
            .collect();
        assert!(error.contains(&message), "{error}");
        assert_eq!(tree(&home), before);
    }
}

#[test]
fn help_prints_the_help_of_a_command_and_refuses_another_name() {
    let (_root, home) = fixture(BASE);
    for path in [
        &[][..],
        &["run"],
        &["profile"],
        &["profile", "create"],
        &["runs", "history"],
    ] {
        let named = command(&home, &[&["help"], path].concat());
        let flag = command(&home, &[path, &["--help"]].concat());
        assert_eq!(named.status.code(), Some(0), "{path:?}");
        assert!(!named.stdout.is_empty(), "{path:?}");
        assert_eq!(named.stdout, flag.stdout, "{path:?}");
        assert_eq!(named.stderr, flag.stderr, "{path:?}");
    }
    let nested = command(&home, &["profile", "help", "create"]);
    assert_eq!(
        nested.stdout,
        command(&home, &["profile", "create", "--help"]).stdout
    );

    for arguments in [
        &["help", "nope"][..],
        &["help", "profile", "nope"],
        &["help", "agent", "work"],
    ] {
        let output = command(&home, arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("is not a command or a help topic")
                && error.contains("Help topics: agent"),
            "{error}"
        );
    }
    let output = command(&home, &["profile", "guide"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("unrecognized subcommand 'guide'"), "{error}");
    assert!(!home.join(".strands/box").join(GUIDE).exists());

    let output = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["help", "agent"])
        .env_clear()
        .current_dir(home.join("project"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn help_starts_with_the_line_for_a_coding_agent_and_names_the_topic() {
    let help = |arguments: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_box"))
            .args(arguments)
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    for arguments in [&["--help"][..], &["-h"], &["help"]] {
        let help = help(arguments);
        assert!(
            help.starts_with(
                "Coding agents: run `box help agent` before you create or change a profile.\n\n"
            ),
            "{help}"
        );
        let topics = "\nHelp topics:\n  box help agent            \
                      What a coding agent reads to create or change a profile\n\nExamples:\n";
        assert!(help.contains(topics), "{help}");
        assert!(
            help.contains(
                "\n  help       Print this message, the help of a command, or a help topic\n"
            ),
            "{help}"
        );
        assert!(!help.contains("profile guide"), "{help}");
    }
    let profile = help(&["profile", "--help"]);
    assert!(
        profile.ends_with(
            "\nTo change a profile with a coding agent, tell the agent: \
             Run box help agent and follow it.\n"
        ),
        "{profile}"
    );
    assert!(!profile.contains("guide"), "{profile}");
    let topic = help(&["help", "--help"]);
    for sentence in [
        "  box help agent ",
        "Run box help agent and follow it to create a profile.",
        "Run box help agent and follow it to update profile <name>.",
    ] {
        assert!(topic.contains(sentence), "{topic}");
    }
}

#[test]
fn the_create_procedure_names_each_flag_and_works_without_a_terminal() {
    let procedure = section("create-a-profile");
    let help = Command::new(env!("CARGO_BIN_EXE_box"))
        .args(["profile", "create", "--help"])
        .env_clear()
        .output()
        .unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    let flags: Vec<&str> = help
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("--"))
        .filter_map(|line| line.split(|c: char| c.is_whitespace()).next())
        .filter(|flag| *flag != "help")
        .collect();
    assert!(flags.len() >= 5, "{flags:?}");
    for flag in flags {
        assert!(procedure.contains(&format!("`--{flag}`")), "--{flag}");
    }

    let (_root, home) = fixture(BASE);
    let unanswered = command(
        &home,
        &["profile", "create", "work", "--with", "claude,bedrock"],
    );
    assert_eq!(unanswered.status.code(), Some(1));
    let error = String::from_utf8(unanswered.stderr).unwrap();
    assert!(error.contains("needs an answer to"), "{error}");
    assert!(procedure.contains("needs an answer to"));
    assert!(!home.join(".strands/box/profiles/work").exists());

    let created = command(
        &home,
        &[
            "profile",
            "create",
            "work",
            "--with",
            "claude,bedrock",
            "--policy",
            "scoped",
            "--option",
            "bedrock.region=us-east-1",
        ],
    );
    let report =
        String::from_utf8(created.stdout).unwrap() + &String::from_utf8(created.stderr).unwrap();
    assert!(created.status.success(), "{report}");
    let line: String = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        line.contains("Run box help agent and follow it to update profile work."),
        "{report}"
    );
    let folder = home.join(".strands/box/profiles/work");
    let mut written: Vec<_> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(written, ["policy.dw", "profile.toml"]);
    assert!(!home.join(".strands/box").join(GUIDE).exists());
    let profile = std::fs::read_to_string(folder.join("profile.toml")).unwrap();
    assert!(
        profile.contains(
            "# For help from a coding agent, tell it: Run box help agent and follow it.\n"
        ),
        "{profile}"
    );
    assert!(
        profile.contains("bedrock.region = \"us-east-1\""),
        "{profile}"
    );
}

/// One correct edit for a task of the guide: what to add to the profile and its policy, and what
/// `box profile show --full` then prints.
struct Edit {
    task: &'static str,
    profile: &'static str,
    rules: &'static str,
    shows: &'static [&'static str],
}

const EDITS: &[Edit] = &[
    Edit {
        task: "add-or-remove-a-pack",
        profile: "packs = [\"extra\"]\n#\n[options]\nextra.host = \"docs.rs\"\n",
        rules: "",
        shows: &["extra.host", "route_extra_connect", "\"docs.rs\""],
    },
    Edit {
        task: "add-a-tool",
        profile: "#\n[tool.jq]\ncommand = [\"/usr/bin/true\"]\n\n[tool.jq.filesystem]\n\
                  read = [\"${{ workspace }}\"]\n",
        rules: "@id(\"spawn_my_jq\") permit (principal, action == Box::Action::\"shell:spawn\", \
                resource) when { context.input.program_path == \"/usr/bin/true\" };\n",
        shows: &["[tool.jq]", "spawn_my_jq"],
    },
    Edit {
        task: "add-an-mcp-server",
        profile: "#\n[mcp.notes]\ntype = \"stdio\"\ncommand = [\"/usr/bin/true\", \"serve\"]\n",
        rules: "",
        shows: &["[mcp.notes]", "mcp_notes_call", "mcp_notes_spawn"],
    },
    Edit {
        task: "add-an-mcp-server",
        profile: "#\n[mcp.docs]\ntype = \"http\"\ndestinations = [\"mcp.example.com\"]\n",
        rules: "",
        shows: &["mcp_docs_call", "mcp.example.com"],
    },
    Edit {
        task: "choose-the-model-provider",
        profile: "#\n[egress.model]\ndestinations = [\"model.example.com\"]\n\
                  secret.ref = \"env://MODEL_KEY\"\n",
        rules: "",
        shows: &["model.example.com", "MODEL_KEY"],
    },
    Edit {
        task: "edit-stored-files",
        profile: "#\n[storage]\ndirectories = [\"config\"]\n\n[[storage.files]]\n\
                  source = \"${{ home }}/absent.json\"\ntarget = \"config/settings.json\"\n\
                  kind = \"json\"\noptional = true\nkeep = [[\"theme\"]]\n",
        rules: "",
        shows: &[
            "agent/config/settings.json",
            "storage/test/default/agent/config",
        ],
    },
    Edit {
        task: "edit-policy",
        profile: "#\n[agent.filesystem]\nread = [\"${{ home }}/notes\"]\n",
        rules: "@id(\"notes_read\") permit (principal, action == Box::Action::\"fs:read\", \
                resource) when { context.input.path like \"~/notes/*\" };\n\
                @id(\"no_new_dependencies\") forbid (principal, action == \
                Box::Action::\"shell:spawn\", resource) when { context.input.program == \"npm\" \
                && context.input has arg1 && context.input.arg1 == \"install\" && \
                context.input has arg2 };\n",
        shows: &["notes_read", "no_new_dependencies", "/notes"],
    },
];

/// The profile text of an edit: its top-level keys go before the base, and its tables after.
fn edited(edit: &Edit) -> String {
    let (top, tables) = edit.profile.split_once("#\n").unwrap();
    format!("{top}{BASE}\n{tables}")
}

#[test]
fn a_correct_edit_for_each_task_passes_the_check_the_guide_names() {
    for edit in EDITS {
        assert!(
            section(edit.task).contains("(#check-a-change)"),
            "{}",
            edit.task
        );
        let (_root, home) = configured(&edited(edit), edit.rules);
        let shown = command(&home, &["profile", "show", "--full", "test"]);
        let output = String::from_utf8(shown.stdout).unwrap();
        let error = String::from_utf8(shown.stderr).unwrap();
        assert!(shown.status.success(), "{}: {error}", edit.task);
        for text in edit.shows {
            assert!(
                output.contains(text),
                "{}: no {text} in\n{output}",
                edit.task
            );
        }
        assert!(
            !home.join(".strands/box/r").exists(),
            "the check starts no box"
        );
    }
}

#[test]
fn the_policy_table_names_fields_that_the_policy_check_accepts() {
    let rules = "@id(\"a\") forbid (principal, action in [Box::Action::\"fs:read\", \
                 Box::Action::\"fs:write\", Box::Action::\"fs:delete\", Box::Action::\"fs:move\"], \
                 resource) when { context.input.path == \"/nowhere\" };\n\
                 @id(\"b\") forbid (principal, action == Box::Action::\"net:connect\", resource) \
                 when { context.input.host == \"h\" && context.input.port == 1 };\n\
                 @id(\"c\") forbid (principal, action == Box::Action::\"http:request\", resource) \
                 when { context.input.host == \"h\" && context.input.port == 1 && \
                 context.input.method == \"GET\" && context.input.path == \"/\" };\n\
                 @id(\"d\") forbid (principal, action == Box::Action::\"shell:exec\", resource) \
                 when { context.input.program == \"p\" && context.input.command == \"p\" && \
                 context.input has arg1 && context.input.arg1 == \"a\" && context.input has arg2 \
                 && context.input.arg2 == \"b\" && context.input.arg_count == 2 && \
                 context.input.cwd == \"/\" };\n\
                 @id(\"e\") forbid (principal, action == Box::Action::\"shell:spawn\", resource) \
                 when { context.input.program_path == \"/p\" && context.input.program == \"p\" };\n\
                 @id(\"f\") forbid (principal, action == Box::Action::\"mcp:call\", resource) \
                 when { context.input.server == \"s\" && context.input.method == \"m\" && \
                 context.input has tool && context.input.tool == \"t\" };\n";
    let rules = format!(
        "{rules}\
         @id(\"g\") forbid (principal, action == Box::Action::\"fs:read\", resource) when {{ \
         context.input.operation == Box::FsReadOperation::\"exec\" }};\n\
         @id(\"h\") forbid (principal, action == Box::Action::\"fs:write\", resource) when {{ \
         context.input.operation == Box::FsWriteOperation::\"set_permissions\" }};\n\
         @id(\"i\") forbid (principal, action == Box::Action::\"fs:delete\", resource) when {{ \
         context.input.operation == Box::FsDeleteOperation::\"remove_dir\" }};\n\
         @id(\"j\") forbid (principal, action == Box::Action::\"fs:move\", resource) when {{ \
         context.input.operation == Box::FsMoveOperation::\"rename\" }};\n\
         @id(\"l\") forbid (principal, action == Box::Action::\"net:connect\", resource) when {{ \
         context.input has ip4 && context.input.ip4 == \"192.0.2.1\" && \
         context.input has ip6 && context.input.ip6 == \"2001:db8::1\" }};\n\
         @id(\"m\") forbid (principal, action == Box::Action::\"http:request\", resource) when {{ \
         context.input.body_bytes > 1000000 && context.input.intercepted }};\n\
         @id(\"n\") forbid (principal, action == Box::Action::\"shell:spawn\", resource) when {{ \
         context.input has credential_reads && \
         context.input.credential_reads.contains(\"x\") }};\n\
         @id(\"o\") forbid (principal, action == Box::Action::\"mcp:call\", resource) when {{ \
         context.input has prompt && context.input.prompt == \"p\" && \
         context.input has uri && context.input.uri like \"file:///etc/*\" }};\n"
    );
    let rules = rules.as_str();
    let table = section("edit-policy");
    for name in [
        "fs:read",
        "fs:write",
        "fs:delete",
        "fs:move",
        "net:connect",
        "http:request",
        "shell:exec",
        "shell:spawn",
        "mcp:call",
        "path",
        "host",
        "port",
        "method",
        "program",
        "command",
        "arg1",
        "arg2",
        "arg_count",
        "cwd",
        "program_path",
        "server",
        "tool",
        "operation",
        "set_permissions",
        "remove_dir",
        "rename",
        "ip4",
        "ip6",
        "body_bytes",
        "intercepted",
        "credential_reads",
        "prompt",
        "uri",
    ] {
        assert!(table.contains(&format!("`{name}`")), "{name}");
    }
    let (_root, home) = configured(BASE, rules);
    let shown = command(&home, &["profile", "show", "--full", "test"]);
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8(shown.stderr).unwrap()
    );
}

#[test]
fn each_planted_mistake_gives_the_message_that_the_error_table_holds() {
    let table = section("fix-an-error");
    let mistakes: &[(&str, &str, &str)] = &[
        (
            "[options]\nnope.region = \"x\"\n",
            "",
            "sets an input that no pack declares",
        ),
        (
            "packs = [\"extra\"]\n#\n[options]\nextra.host = \"NOT A HOST\"\n",
            "",
            "does not match its pattern",
        ),
        (
            "[agent.filesytem]\nread = []\n",
            "",
            "holds the unknown key",
        ),
        ("packs = [\"@box/clade\"]\n#\n", "", "does not exist"),
        (
            "packs = [\"@box/claude\"]\n#\n[options]\nclaude.host = \"nope\"\n",
            "",
            "is not one of",
        ),
        (
            "box_dir = \"/tmp/x\"\n#\n",
            "",
            "a profile holds no `box_dir`",
        ),
        (
            "",
            "@id(\"project_read\") permit (principal, action == Box::Action::\"fs:read\", resource);\n",
            "box writes a rule with the id",
        ),
        (
            "",
            "@id(\"r\") permit (principal, action == Box::Action::\"fs:raed\", resource);\n",
            "unrecognized action",
        ),
        (
            "",
            "@id(\"r\") forbid (principal, action == Box::Action::\"mcp:call\", resource) when { context.input.uri like \"file:///etc/*\" };\n",
            "unable to guarantee safety of access to optional attribute",
        ),
        (
            "",
            "@id(\"r\") permit (principal, action == Box::Action::\"fs:read\", resource) when { context.input.pth == \"/\" };\n",
            "not found",
        ),
    ];
    for (profile, rules, message) in mistakes {
        assert!(table.contains(message), "the table holds no {message:?}");
        let text = match profile.split_once("#\n") {
            Some((top, tables)) => format!("{top}{BASE}\n{tables}"),
            None => format!("{BASE}\n{profile}"),
        };
        let (_root, home) = configured(&text, rules);
        let shown = command(&home, &["profile", "show", "--full", "test"]);
        let error: String = String::from_utf8(shown.stderr)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(shown.status.code(), Some(1), "{message}: {error}");
        assert!(error.contains(message), "{message}: {error}");
    }
}
