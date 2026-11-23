//! Plugins compiled into `box.toml`: the secret source, its program, and the feature switch.

use super::*;
use crate::fixtures::binary;

/// The host of a plugin test: `PATH` is one folder of programs, and `variables` are set.
struct Host {
    bin: PathBuf,
    variables: Vec<(&'static str, String)>,
}

impl Host {
    fn new(bin: PathBuf) -> Self {
        Self {
            bin,
            variables: Vec::new(),
        }
    }
}

impl Sources for Host {
    fn env(&self, name: &str) -> Option<String> {
        if name == "PATH" {
            return Some(self.bin.display().to_string());
        }
        self.variables
            .iter()
            .find(|(set, _)| *set == name)
            .map(|(_, value)| value.clone())
    }

    fn env_with_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.variables
            .iter()
            .filter(|(set, _)| set.starts_with(prefix))
            .map(|(set, value)| (set.to_string(), value.clone()))
            .collect()
    }

    fn program(&mut self, name: &str) -> Option<PathBuf> {
        Some(self.bin.join(name)).filter(|candidate| candidate.is_file())
    }

    fn search(&self, name: &str) -> Option<PathBuf> {
        Some(self.bin.join(name)).filter(|candidate| candidate.is_file())
    }

    fn developer_dir(&mut self) -> Result<String, String> {
        Err("ran xcode-select, which this host never runs".to_string())
    }

    fn search_path(&self) -> Vec<PathBuf> {
        vec![self.bin.clone()]
    }
}

/// A plugin like `@box/1password`, which reads `op://` references with `op`.
const ONEPASSWORD: &str = r#"[plugin]
name    = "@box/1password"
version = 1
kind    = "secret-source"
scheme  = "op"

[inputs.onepassword.path]
type    = "program"
program = "op"

[run]
command = ["${{ inputs.onepassword.path }}", "read", "op://{ref}"]

[env]
OP_ACCOUNT               = { from = "env:OP_ACCOUNT" }
OP_CONNECT_HOST          = { from = "env:OP_CONNECT_HOST" }
OP_SERVICE_ACCOUNT_TOKEN = { from = "env:OP_SERVICE_ACCOUNT_TOKEN" }
OP_CONNECT_TOKEN         = { from = "env:OP_CONNECT_TOKEN" }

[protect]
env   = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"]
paths = ["${{ home }}/.config/op"]
"#;

/// A plugin like `@box/aws-secrets-manager`, which reads JSON secrets with `aws`.
const SECRETS_MANAGER: &str = r#"[plugin]
name    = "@box/aws-secrets-manager"
version = 1
kind    = "secret-source"
scheme  = "aws-secretsmanager"

[inputs.aws-secrets-manager.path]
type    = "program"
program = "aws"

[run]
command = ["${{ inputs.aws-secrets-manager.path }}", "secretsmanager", "get-secret-value",
           "--secret-id", "{ref}", "--query", "SecretString", "--output", "json"]
output  = "json"

[env]
AWS_PROFILE           = { from = "env:AWS_PROFILE" }
AWS_REGION            = { from = "env:AWS_REGION" }
AWS_ACCESS_KEY_ID     = { from = "env:AWS_ACCESS_KEY_ID" }
AWS_SECRET_ACCESS_KEY = { from = "env:AWS_SECRET_ACCESS_KEY" }
AWS_SESSION_TOKEN     = { from = "env:AWS_SESSION_TOKEN" }

[protect]
env   = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
paths = ["~/.aws"]
"#;

/// A profile that lists both plugins and names one reference for each.
const BOTH: &str = r#"
plugins = ["@box/1password", "@box/aws-secrets-manager"]

[agent]
command = ["/usr/bin/true"]

[egress.github]
destinations = ["api.github.com"]
secret.ref = "op://Personal/BoxTest-GitHub/token"
secret.env = "GH_TOKEN"

[telemetry.otlp]
kind = "otlp"
destination = "http://localhost:4318"
secret.ref = "aws-secretsmanager://box/telemetry#OTLP_KEY"
secret.header = "x-api-key"
"#;

/// Write the plugin `@box/<name>` beside the scene's packs.
fn plugin(scene: &Scene, name: &str, text: &str) {
    let folder = scene.root.join("plugins").join(name);
    std::fs::create_dir_all(&folder).expect("a plugin folder");
    std::fs::write(folder.join("plugin.toml"), text).expect("a plugin");
}

/// A scene with both plugins, and a host whose `PATH` holds `op` and `aws`.
fn plugins_scene() -> (Scene, Host) {
    let scene = Scene::new();
    plugin(&scene, "1password", ONEPASSWORD);
    plugin(&scene, "aws-secrets-manager", SECRETS_MANAGER);
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    binary(&bin.join("aws"));
    (scene, Host::new(bin))
}

/// Whether `error` is the refusal of `what`, a part of the source's `command` at `file`, which
/// reaches its file through a link in a write grant, at the path `command`.
fn is_link_refusal(error: &Error, command: &str, what: &str, file: &Path) -> bool {
    matches!(error, Error::Profile { path, reason, .. }
        if path.display().to_string() == command
            && reason.starts_with(&format!("{what} {} is a link", file.display())))
}

/// Why compiling `text` against `host` is refused.
fn refused(scene: &Scene, text: &str, host: &mut Host) -> String {
    match scene.compile_using(&profile(text), host, "/usr/bin:/bin") {
        Err(Error::Profile { reason, .. }) => reason,
        other => panic!("a refusal, not {other:?}"),
    }
}

/// The parts of `box.toml` that a plugin and its references write, whole: each
/// `[secret-source.<scheme>]` table, the feature that Box Core reads it with, and the `secret` of
/// each route and target that names a reference. Every other top-level table is as for the same
/// profile without its plugins and its references, and each route and target is, but for its
/// `secret`, as for the same profile with a key from a variable. The tests of those tables own
/// what is in them.
#[test]
fn a_plugin_writes_its_secret_source_into_box_toml_with_its_program() {
    let (scene, mut host) = plugins_scene();
    let (_, compiled) = scene
        .compile_using(&profile(BOTH), &mut host, "/usr/bin:/bin")
        .expect("a compile");
    let written = table(&compiled);
    let expected: toml::Value = toml::from_str(&format!(
        r#"
        [egress.github.secret]
        ref = "op://Personal/BoxTest-GitHub/token"
        env = "GH_TOKEN"

        [telemetry.otlp.secret]
        ref = "aws-secretsmanager://box/telemetry#OTLP_KEY"
        header = "x-api-key"

        [secret-source.op]
        protocol = "box.secret-source.v1"
        command = ["{bin}/op", "read", "op://{{ref}}"]
        pass-env = ["OP_ACCOUNT", "OP_CONNECT_HOST"]
        pass-secret-env = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"]
        deny = ["~/.config/op"]

        [secret-source.aws-secretsmanager]
        protocol = "box.secret-source.v1"
        command = ["{bin}/aws", "secretsmanager", "get-secret-value", "--secret-id", "{{ref}}",
                   "--query", "SecretString", "--output", "json"]
        output = "json"
        pass-env = ["AWS_PROFILE", "AWS_REGION"]
        pass-secret-env = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
        deny = ["~/.aws"]

        [experimental-features]
        secret-sources = true
        "#,
        bin = host.bin.display(),
    ))
    .expect("TOML");
    for at in [
        &["secret-source"][..],
        &["experimental-features", "secret-sources"],
        &["egress", "github", "secret"],
        &["telemetry", "otlp", "secret"],
    ] {
        let part = |file: &toml::Value| {
            at.iter()
                .try_fold(file, |value, key| value.get(*key))
                .cloned()
        };
        let wanted = part(&expected).expect("an expected part");
        assert_eq!(part(&written), Some(wanted), "{at:?}");
    }
    let without = BOTH
        .replace("plugins = [\"@box/1password\", \"@box/aws-secrets-manager\"]\n", "")
        .replace("secret.ref = \"op://Personal/BoxTest-GitHub/token\"\nsecret.env = \"GH_TOKEN\"\n", "")
        .replace(
            "secret.ref = \"aws-secretsmanager://box/telemetry#OTLP_KEY\"\nsecret.header = \"x-api-key\"\n",
            "",
        );
    assert!(
        !without.contains("secret") && !without.contains("plugins"),
        "{without}"
    );
    let (_, plain) = scene
        .compile_using(&profile(&without), &mut host, "/usr/bin:/bin")
        .expect("the same profile without its plugins");
    let plain = table(&plain);
    let keys = |file: &toml::Value| -> Vec<String> {
        file.as_table().expect("a table").keys().cloned().collect()
    };
    for key in keys(&written).iter().chain(&keys(&plain)) {
        if [
            "secret-source",
            "experimental-features",
            "egress",
            "telemetry",
        ]
        .contains(&key.as_str())
        {
            continue;
        }
        assert_eq!(
            written.get(key),
            plain.get(key),
            "`{key}`: a plugin adds nothing to it"
        );
    }
    let mut features = written["experimental-features"]
        .as_table()
        .cloned()
        .expect("the features");
    features.remove("secret-sources");
    assert_eq!(
        Some(features).filter(|features| !features.is_empty()),
        plain
            .get("experimental-features")
            .and_then(toml::Value::as_table)
            .cloned(),
        "a plugin adds only `secret-sources` to the features"
    );
    let routed = BOTH
        .replace(
            "plugins = [\"@box/1password\", \"@box/aws-secrets-manager\"]\n",
            "",
        )
        .replace(
            "secret.ref = \"op://Personal/BoxTest-GitHub/token\"\nsecret.env = \"GH_TOKEN\"\n",
            "secret.ref = \"env://GH_TOKEN\"\n",
        )
        .replace(
            "secret.ref = \"aws-secretsmanager://box/telemetry#OTLP_KEY\"",
            "secret.ref = \"env://OTLP_KEY\"",
        );
    assert!(
        !routed.contains("op://") && !routed.contains("aws-secretsmanager://"),
        "{routed}"
    );
    let (_, routed) = scene
        .compile_using(&profile(&routed), &mut host, "/usr/bin:/bin")
        .expect("the same profile with each key from a variable");
    let routed = table(&routed);
    let but_for_secrets = |file: &toml::Value, key: &str| {
        let mut entries = file[key].as_table().cloned().expect("a table");
        for (_, entry) in entries.iter_mut() {
            if let Some(entry) = entry.as_table_mut() {
                entry.remove("secret");
            }
        }
        entries
    };
    for key in ["egress", "telemetry"] {
        assert_eq!(
            but_for_secrets(&written, key),
            but_for_secrets(&routed, key),
            "`{key}`: a plugin changes only the `secret` of a route or a target"
        );
    }
}

/// **`box` keeps no copy of Box Core's rules for a source**: what a source may hold reaches
/// `box.toml` as the plugin writes it, and Box Core refuses it when the box starts, as it does
/// for a source of the profile. A `*` in a path of a plugin is literal text, which no step of
/// `box` matches against a folder.
#[test]
fn what_box_core_checks_reaches_box_toml_as_the_plugin_writes_it() {
    let scene = Scene::new();
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    let matched = scene.home().join(".config/op/accounts");
    std::fs::create_dir_all(&matched).expect("a folder that the pattern would match");
    let mut host = Host::new(bin);
    plugin(
        &scene,
        "1password",
        r#"[plugin]
name    = "@box/1password"
version = 1
kind    = "secret-source"
scheme  = "op"

[inputs.onepassword.path]
type    = "program"
program = "op"

[run]
command = ["${{ inputs.onepassword.path }}", "read"]
output  = "yaml"

[env]
HOME = { from = "env:HOME" }

[protect]
paths = ["${{ home }}/.config/op/*", "relative/../path"]
"#,
    );
    let text = "plugins = [\"@box/1password\"]\n[agent]\ncommand = [\"/usr/bin/true\"]";
    let (_, compiled) = scene
        .compile_using(&profile(text), &mut host, "/usr/bin:/bin")
        .expect("`box` leaves each of these to Box Core");
    assert_eq!(
        table(&compiled)["secret-source"]["op"],
        toml::from_str::<toml::Value>(&format!(
            "protocol = \"box.secret-source.v1\"\ncommand = [\"{}/op\", \"read\"]\n\
             output = \"yaml\"\npass-env = [\"HOME\"]\n\
             deny = [\"~/.config/op/*\", \"relative/../path\"]\n",
            host.bin.display()
        ))
        .expect("TOML")
    );
}

#[test]
fn a_plugins_program_is_an_input_that_the_profile_can_set() {
    let (scene, mut host) = plugins_scene();
    let other = scene.root.join("opt/op");
    binary(&other);
    let text = format!(
        "{BOTH}\n[options]\nonepassword.path = {:?}\n",
        other.display()
    );
    let (resolved, compiled) = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect("a compile");
    assert_eq!(
        table(&compiled)["secret-source"]["op"]["command"],
        toml::Value::from(vec![
            other.display().to_string(),
            "read".to_string(),
            "op://{ref}".to_string(),
        ])
    );
    let mut read: Vec<(String, String, String)> = resolved
        .inputs
        .into_iter()
        .map(|input| (input.name, input.value, input.source))
        .collect();
    read.sort();
    assert_eq!(
        read,
        vec![
            (
                "aws-secrets-manager.path".to_string(),
                host.bin.join("aws").display().to_string(),
                "search".to_string(),
            ),
            (
                "onepassword.path".to_string(),
                other.display().to_string(),
                "your profile".to_string(),
            ),
        ]
    );
}

#[test]
fn a_plugins_program_passes_the_checks_of_a_program_input() {
    let (scene, mut host) = plugins_scene();
    let planted = scene.workspace().join("bin/op");
    binary(&planted);
    let reason = refused(
        &scene,
        &format!(
            "{BOTH}\n[options]\nonepassword.path = {:?}\n",
            planted.display()
        ),
        &mut host,
    );
    assert!(
        reason.starts_with(&format!(
            "`run.command.0` of the plugin @box/1password: `inputs.onepassword.path` = {:?} ",
            planted.display().to_string()
        )) && reason.contains("the workspace"),
        "the program check names the key of the plugin's file, its input, and the workspace: \
         {reason}"
    );
    let reason = refused(
        &scene,
        &BOTH.replace(
            "[agent]\ncommand = [\"/usr/bin/true\"]",
            &format!(
                "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]",
                host.bin.display()
            ),
        ),
        &mut host,
    );
    assert!(
        reason.starts_with(&format!(
            "`inputs.aws-secrets-manager.path` = {:?} lies under the write grant {}",
            host.bin.join("aws").display().to_string(),
            host.bin.display()
        )),
        "the write grant check of a program input names the plugin's input: {reason}"
    );
    std::fs::remove_file(host.bin.join("op")).expect("no op");
    match scene.compile_using(&profile(BOTH), &mut host, "/usr/bin:/bin") {
        Err(Error::NotOnHost { reason, .. }) => assert!(
            reason.contains("onepassword.path"),
            "the error names the option that sets the program: {reason}"
        ),
        other => panic!("a host absence, not {other:?}"),
    }
}

#[test]
fn an_input_in_a_later_argument_of_a_source_needs_a_bound() {
    let scene = Scene::new();
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    let mut host = Host::new(bin);
    host.variables
        .push(("OP_ACCOUNT", "my.1password.com".to_string()));
    let account = |bound: &str| {
        ONEPASSWORD
            .replace(
                "[run]",
                &format!(
                    "[inputs.onepassword.account]\nfrom = \"env:OP_ACCOUNT\"\n{bound}\n\
                     [run]"
                ),
            )
            .replace(
                "\"read\", \"op://{ref}\"",
                "\"--account\", \"${{ inputs.onepassword.account }}\", \"read\", \"op://{ref}\"",
            )
    };
    let text = "plugins = [\"@box/1password\"]\n[agent]\ncommand = [\"/usr/bin/true\"]";
    plugin(&scene, "1password", &account(""));
    let reason = refused(&scene, text, &mut host);
    assert!(
        reason.starts_with(
            "`run.command.2` of the plugin @box/1password: `inputs.onepassword.account` reaches \
             `command`"
        ),
        "the bound check names the key of the plugin's file and its input: {reason}"
    );
    plugin(&scene, "1password", &account("pattern = \"[a-z0-9.-]+\""));
    let (_, compiled) = scene
        .compile_using(&profile(text), &mut host, "/usr/bin:/bin")
        .expect("a bounded input");
    assert_eq!(
        table(&compiled)["secret-source"]["op"]["command"],
        toml::Value::from(vec![
            host.bin.join("op").display().to_string(),
            "--account".to_string(),
            "my.1password.com".to_string(),
            "read".to_string(),
            "op://{ref}".to_string(),
        ])
    );
}

#[test]
fn a_profiles_own_secret_source_turns_the_feature_on() {
    let scene = Scene::new();
    let compiled = scene
        .compile(
            &profile(&format!(
                "{MINIMAL}\n[secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"kv\", \
                 \"get\", \"{{ref}}\"]\n"
            )),
            None,
        )
        .expect("a compile");
    let file = table(&compiled);
    assert_eq!(
        (&file["secret-source"], &file["experimental-features"]),
        (
            &toml::from_str::<toml::Value>(
                "[vault]\ncommand = [\"/usr/local/bin/vault\", \"kv\", \"get\", \"{ref}\"]"
            )
            .expect("TOML"),
            &toml::from_str::<toml::Value>("secret-sources = true").expect("TOML"),
        )
    );
}

#[test]
fn a_secret_env_turns_the_feature_on_without_a_secret_source() {
    let scene = Scene::new();
    let switch = |extra: &str| {
        let compiled = scene
            .compile(&profile(&format!("{MINIMAL}\n{extra}")), None)
            .expect("a compile");
        let file = table(&compiled);
        (
            file.get("experimental-features").cloned(),
            file.get("secret-source").is_some(),
        )
    };
    let on = Some(toml::from_str::<toml::Value>("secret-sources = true").expect("TOML"));
    assert_eq!(
        [
            switch(
                "[egress.model]\ndestinations = [\"model.example.com\"]\n\
                 secret.ref = \"env://MODEL_KEY\"\nsecret.env = \"MODEL_KEY\""
            ),
            switch(
                "[mcp.docs]\ntype = \"http\"\ndestinations = [\"docs.example.com\"]\n\
                 secret.ref = \"env://DOCS_KEY\"\nsecret.env = \"DOCS_KEY\""
            ),
            switch(
                "[egress.model]\ndestinations = [\"model.example.com\"]\n\
                 secret.ref = \"env://MODEL_KEY\""
            ),
        ],
        [(on.clone(), false), (on, false), (None, false)]
    );
}

#[test]
fn a_profile_without_a_secret_source_writes_no_source_and_no_feature() {
    let scene = Scene::new();
    let compiled = scene.compile(&profile(MINIMAL), None).expect("a compile");
    let written = table(&compiled);
    assert!(
        written.get("agent").is_some(),
        "the compiled box.toml: {written}"
    );
    assert_eq!(written.get("secret-source"), None, "no source table");
    assert_eq!(
        written
            .get("experimental-features")
            .and_then(|features| features.get("secret-sources")),
        None,
        "no secret-sources feature"
    );
}

#[test]
fn no_env_entry_copies_the_host_value_of_a_variable_that_secret_env_names() {
    let (scene, mut host) = plugins_scene();
    host.variables
        .push(("GH_TOKEN", "the host token".to_string()));
    for env in [
        "secret.env = \"GH_TOKEN\"",
        "secret.env = { value = \"GH_TOKEN\", when = \"macos\" }",
    ] {
        let reason = refused(
            &scene,
            &BOTH
                .replace(
                    "[agent]\ncommand = [\"/usr/bin/true\"]",
                    "[agent]\ncommand = [\"/usr/bin/true\"]\n\
                     env.GH_TOKEN = { from = \"env:GH_TOKEN\" }",
                )
                .replace("secret.env = \"GH_TOKEN\"", env),
            &mut host,
        );
        assert_eq!(
            reason,
            "`agent.env.GH_TOKEN` would give the workload the host's `GH_TOKEN`, which a route or \
             a server names as its credential",
            "{env}"
        );
    }
}

#[test]
fn no_input_or_env_entry_copies_a_variable_that_a_source_passes_to_its_program() {
    let (scene, mut host) = plugins_scene();
    for (name, value) in [
        ("OP_SERVICE_ACCOUNT_TOKEN", "ops_real"),
        ("OP_CONNECT_TOKEN", "connect_real"),
        ("OP_ACCOUNT", "my.1password.com"),
        ("VAULT_TOKEN", "vault_real"),
    ] {
        host.variables.push((name, value.to_string()));
    }
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]";
    let token = refused(
        &scene,
        &BOTH.replace(
            agent,
            &format!("{agent}\nenv.T = {{ from = \"env:OP_SERVICE_ACCOUNT_TOKEN\" }}"),
        ),
        &mut host,
    );
    assert_eq!(
        token,
        "`agent.env.T` would give the workload the host's `OP_SERVICE_ACCOUNT_TOKEN`, which \
         the plugin @box/1password passes to its program as a credential"
    );
    scene.share(
        "session",
        "[inputs.op.session]\nfrom = \"env:OP_CONNECT_TOKEN\"\n\
         [agent.env]\nSESSION = \"${{ inputs.op.session }}\"",
    );
    let session = refused(
        &scene,
        &format!("packs = [\"@box/session\"]\n{BOTH}"),
        &mut host,
    );
    assert_eq!(
        session,
        "`agent.env.SESSION`: `inputs.op.session` would give the workload the host's \
         `OP_CONNECT_TOKEN`, which the plugin @box/1password passes to its program as a \
         credential"
    );
    let own = refused(
        &scene,
        &format!(
            "{agent}\nenv.V = {{ from = \"env:VAULT_TOKEN\" }}\n\
             [secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"{{ref}}\"]\n\
             pass-secret-env = [\"VAULT_*\"]"
        ),
        &mut host,
    );
    assert_eq!(
        own,
        "`agent.env.V` would give the workload the host's `VAULT_TOKEN`, which \
         `[secret-source.vault]` of the profile passes to its program as a credential"
    );
    let (_, compiled) = scene
        .compile_using(
            &profile(&BOTH.replace(
                agent,
                &format!("{agent}\nenv.A = {{ from = \"env:OP_ACCOUNT\" }}"),
            )),
            &mut host,
            "/usr/bin:/bin",
        )
        .expect("a pass-env name is a plain setting");
    assert_eq!(
        table(&compiled)["agent"]["env"],
        toml::from_str::<toml::Value>("A = \"my.1password.com\"").expect("TOML")
    );
}

/// The `#!` interpreter of a source's program runs outside every sandbox too, so one that a
/// write grant reaches, as written or through a link, stops the load, for a plugin's program and
/// for a profile's own source.
#[test]
fn a_sources_interpreter_under_a_write_grant_is_refused() {
    let (scene, mut host) = plugins_scene();
    let granted = scene.root.join("granted");
    binary(&granted.join("python3"));
    std::os::unix::fs::symlink(host.bin.join("aws"), granted.join("linked")).expect("a link");
    let script = |name: &str, interpreter: &Path| {
        let path = scene.root.join("tools").join(name);
        crate::fixtures::write(&path, &format!("#!{}\nexit 0\n", interpreter.display()));
        crate::fixtures::executable(&path);
        path
    };
    let direct = script("vault", &granted.join("python3"));
    let through_link = script("vault-link", &granted.join("linked"));
    let grant = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n",
        granted.display()
    );
    let own = |program: &Path| {
        format!(
            "{grant}[secret-source.vault]\ncommand = [{:?}, \"read\", \"{{ref}}\"]\n",
            program.display()
        )
    };
    let plugin = format!(
        "plugins = [\"@box/1password\"]\n{grant}[options]\nonepassword.path = {:?}\n",
        direct.display()
    );
    for text in [own(&direct), plugin] {
        let error = scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .expect_err("an interpreter that the box can replace");
        assert_eq!(
            error.to_string(),
            format!(
                "{} lies under the write grant {} of `[agent]`, so the workload can replace it; \
                 keep the program of each secret source, its `#!` interpreter, and each path in \
                 its `command`, outside every write grant",
                granted.join("python3").display(),
                granted.display()
            ),
            "{text}"
        );
    }
    let later = script("vault-later", &granted.join("python-later"));
    let error = scene
        .compile_using(&profile(&own(&later)), &mut host, "/usr/bin:/bin")
        .expect_err("an interpreter that the box can make");
    assert_eq!(
        error.to_string(),
        format!(
            "{} lies under the write grant {} of `[agent]`, so the workload can replace it; keep \
             the program of each secret source, its `#!` interpreter, and each path in its \
             `command`, outside every write grant",
            granted.join("python-later").display(),
            granted.display()
        ),
        "an interpreter that is absent"
    );
    let error = scene
        .compile_using(&profile(&own(&through_link)), &mut host, "/usr/bin:/bin")
        .expect_err("an interpreter link that the box can replace");
    assert!(
        is_link_refusal(
            &error,
            "[secret-source.vault] command",
            "its interpreter",
            &granted.join("linked")
        ),
        "{error}"
    );
    let unfollowed = scene.root.join("tools/vault-env");
    crate::fixtures::write(
        &unfollowed,
        &format!("#!/usr/bin/env -P {} python3\nexit 0\n", granted.display()),
    );
    crate::fixtures::executable(&unfollowed);
    match scene.compile_using(&profile(&own(&unfollowed)), &mut host, "/usr/bin:/bin") {
        Err(Error::Profile { path, reason, .. }) => assert_eq!(
            (path.display().to_string(), reason),
            (
                "[secret-source.vault] command".to_string(),
                format!(
                    "its program {} has the #! line `/usr/bin/env -P {} python3`, which names no \
                     interpreter that box can check; a secret source runs outside every sandbox",
                    unfollowed.display(),
                    granted.display()
                )
            )
        ),
        other => panic!("an interpreter that box cannot follow, not {other:?}"),
    }
    scene
        .compile_using(
            &profile(&own(&script("vault-system", Path::new("/bin/sh")))),
            &mut host,
            "/usr/bin:/bin",
        )
        .expect("an interpreter outside every write grant");
}

#[test]
fn a_part_of_a_source_in_a_place_that_a_box_can_write_is_refused() {
    let (scene, mut host) = plugins_scene();
    let in_workspace = scene.workspace().join("vault");
    binary(&in_workspace);
    let in_storage = scene.storage().join("vault");
    binary(&in_storage);
    let in_box_home = scene.home().join(".strands/box/bin/vault");
    binary(&in_box_home);
    let config = scene.workspace().join("vault.toml");
    crate::fixtures::write(&config, "");
    let script = scene.root.join("tools/vault");
    crate::fixtures::write(&script, &format!("#!{}\nexit 0\n", in_workspace.display()));
    crate::fixtures::executable(&script);
    let own = |access: &str, command: &[&Path]| {
        let command: Vec<String> = command
            .iter()
            .map(|part| format!("{:?}", part.display().to_string()))
            .chain(["\"{ref}\"".to_string()])
            .collect();
        format!(
            "[project]\naccess = \"{access}\"\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
             [secret-source.vault]\ncommand = [{}]\n",
            command.join(", ")
        )
    };
    let op = host.bin.join("op");
    let plugin = format!(
        "plugins = [\"@box/1password\"]\n[project]\naccess = \"none\"\n\
         [agent]\ncommand = [\"/usr/bin/true\"]\n[options]\nonepassword.path = {:?}\n",
        script.display().to_string()
    );
    let home = scene.home();
    let under_home =
        |path: &Path| Path::new("~").join(path.strip_prefix(&home).expect("a path under the home"));
    let (home_config, home_storage, home_box) = (
        under_home(&config),
        under_home(&in_storage),
        under_home(&in_box_home),
    );
    for (text, command, what, path, root) in [
        (
            own("none", &[&op, Path::new("--config"), &home_config]),
            "[secret-source.vault] command",
            "its file",
            &config,
            "the workspace",
        ),
        (
            own(
                "read",
                &[
                    &op,
                    Path::new(&format!("-config={}", home_config.display())),
                ],
            ),
            "[secret-source.vault] command",
            "its file",
            &config,
            "the workspace",
        ),
        (
            own("none", &[&op, &home_storage]),
            "[secret-source.vault] command",
            "its file",
            &in_storage,
            "the run's storage",
        ),
        (
            own("none", &[&op, &home_box]),
            "[secret-source.vault] command",
            "its file",
            &in_box_home,
            "the box home",
        ),
        (
            own("read", &[&in_workspace]),
            "[secret-source.vault] command",
            "its program",
            &in_workspace,
            "the workspace",
        ),
        (
            own("none", &[&in_workspace]),
            "[secret-source.vault] command",
            "its program",
            &in_workspace,
            "the workspace",
        ),
        (
            own("read", &[&op, Path::new("--config"), &config]),
            "[secret-source.vault] command",
            "its file",
            &config,
            "the workspace",
        ),
        (
            own(
                "none",
                &[&op, Path::new(&format!("-config={}", config.display()))],
            ),
            "[secret-source.vault] command",
            "its file",
            &config,
            "the workspace",
        ),
        (
            own("none", &[&script]),
            "[secret-source.vault] command",
            "its interpreter",
            &in_workspace,
            "the workspace",
        ),
        (
            own("none", &[&in_storage]),
            "[secret-source.vault] command",
            "its program",
            &in_storage,
            "the run's storage",
        ),
        (
            own("none", &[&in_box_home]),
            "[secret-source.vault] command",
            "its program",
            &in_box_home,
            "the box home",
        ),
        (
            plugin,
            "[run] command of the plugin @box/1password",
            "its interpreter",
            &in_workspace,
            "the workspace",
        ),
    ] {
        match scene.compile_using(&profile(&text), &mut host, "/usr/bin:/bin") {
            Err(Error::Profile {
                path: at, reason, ..
            }) => assert_eq!(
                (at.display().to_string(), reason),
                (
                    command.to_string(),
                    format!(
                        "{what} {} lies in {root}, which a box can write; a secret source runs \
                         outside every sandbox",
                        path.display()
                    )
                ),
                "{text}"
            ),
            other => panic!("a part of a source that a box can plant, not {other:?}\n{text}"),
        }
    }
    scene
        .compile_using(&profile(&own("none", &[&op])), &mut host, "/usr/bin:/bin")
        .expect("a program outside every place that a box can write");
}

#[test]
fn a_profiles_own_source_program_and_files_are_refused_under_a_write_grant() {
    let (scene, mut host) = plugins_scene();
    let planted = scene.workspace().join("vault");
    binary(&planted);
    let granted = scene.root.join("granted");
    binary(&granted.join("vault"));
    for (program, grant, extra) in [
        (planted.clone(), scene.workspace(), String::new()),
        (
            granted.join("vault"),
            granted.clone(),
            format!("filesystem.write = [{:?}]\n", granted.display()),
        ),
    ] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\n{extra}\
             [secret-source.vault]\ncommand = [{:?}, \"read\", \"{{ref}}\"]\n",
            program.display()
        );
        let error = scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .expect_err("a program that the box can replace");
        assert_eq!(
            error.to_string(),
            format!(
                "{} lies under the write grant {} of `[agent]`, so the workload can replace it; \
                 keep the program of each secret source, its `#!` interpreter, and each path in \
                 its `command`, outside every write grant",
                program.display(),
                grant.display()
            )
        );
    }
    let protected = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         filesystem.deny_write = [{:?}]\n\
         [secret-source.vault]\ncommand = [{:?}, \"read\", \"{{ref}}\"]\n",
        granted.display(),
        granted.display(),
        granted.join("vault").display()
    );
    let protected_everywhere = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         [filesystem]\ndeny_write = [{:?}]\n\
         [secret-source.vault]\ncommand = [{:?}, \"read\", \"{{ref}}\"]\n",
        granted.display(),
        granted.display(),
        granted.join("vault").display()
    );
    for text in [&protected, &protected_everywhere] {
        let error = scene
            .compile_using(&profile(text), &mut host, "/usr/bin:/bin")
            .expect_err("a deny_write does not keep a source's program");
        assert!(
            matches!(&error, Error::SourceProgramUnderWrite { writer, .. } if writer == "agent"),
            "{text}: {error}"
        );
    }
    let link = granted.join("op");
    std::os::unix::fs::symlink(host.bin.join("op"), &link).expect("a link");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         [secret-source.vault]\ncommand = [{:?}, \"read\", \"{{ref}}\"]\n",
        granted.display(),
        link.display()
    );
    let error = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect_err("a link that the box can replace");
    assert!(
        is_link_refusal(
            &error,
            "[secret-source.vault] command",
            "its program",
            &link
        ),
        "{error}"
    );
    let outside = scene.root.join("etc/vault.toml");
    crate::fixtures::write(&outside, "");
    let config_link = granted.join("vault.toml");
    std::os::unix::fs::symlink(&outside, &config_link).expect("a link");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         [secret-source.vault]\ncommand = [{:?}, \"--config\", {:?}, \"{{ref}}\"]\n",
        granted.display(),
        host.bin.join("op").display(),
        config_link.display()
    );
    let error = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect_err("a linked file that the box can replace");
    assert!(
        is_link_refusal(
            &error,
            "[secret-source.vault] command",
            "its file",
            &config_link
        ),
        "{error}"
    );
    let config = granted.join("config.toml");
    std::fs::write(&config, "").expect("a config file");
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         [secret-source.vault]\ncommand = [{:?}, \"--config\", {:?}, \"{{ref}}\"]\n",
        granted.display(),
        host.bin.join("op").display(),
        config.display()
    );
    let error = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect_err("a file argument that the box can replace");
    assert_eq!(
        error.to_string(),
        format!(
            "{} lies under the write grant {} of `[agent]`, so the workload can replace it; keep \
             the program of each secret source, its `#!` interpreter, and each path in its \
             `command`, outside every write grant",
            config.display(),
            granted.display()
        )
    );
    let folder = granted.join("confdir");
    std::fs::create_dir_all(&folder).expect("a folder");
    let absent = granted.join("missing.json");
    let home_grant = scene.home().join("vaultconf");
    std::fs::create_dir_all(&home_grant).expect("a folder under the home");
    let op = host.bin.join("op").display().to_string();
    let under = |arguments: &str, grant: &Path| {
        format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
             [secret-source.vault]\ncommand = [{op:?}, {arguments}, \"{{ref}}\"]\n",
            grant.display()
        )
    };
    for (arguments, grant, path) in [
        (
            format!("\"--config\", {:?}", folder.display()),
            &granted,
            &folder,
        ),
        (
            format!("\"--config\", {:?}", absent.display()),
            &granted,
            &absent,
        ),
        (
            format!("\"-config={}\"", absent.display()),
            &granted,
            &absent,
        ),
        (
            "\"--config\", \"~/vaultconf/absent.json\"".to_string(),
            &home_grant,
            &home_grant.join("absent.json"),
        ),
        (
            "\"-config=~/vaultconf/absent.json\"".to_string(),
            &home_grant,
            &home_grant.join("absent.json"),
        ),
    ] {
        let text = under(&arguments, grant);
        let error = scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .expect_err("a folder or an absent file that the box can fill");
        assert_eq!(
            error.to_string(),
            format!(
                "{} lies under the write grant {} of `[agent]`, so the workload can replace it; \
                 keep the program of each secret source, its `#!` interpreter, and each path in \
                 its `command`, outside every write grant",
                path.display(),
                grant.display()
            ),
            "{text}"
        );
    }
    let holder = scene.root.join("holder");
    let inner = holder.join("cache");
    std::fs::create_dir_all(&inner).expect("a folder in a folder");
    for arguments in [
        format!("\"--config-dir\", {:?}", holder.display()),
        format!("\"--config-dir={}\"", holder.display()),
    ] {
        let text = under(&arguments, &inner);
        let error = scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .expect_err("a folder that holds a write grant");
        assert_eq!(
            error.to_string(),
            format!(
                "{} holds the write grant {} of `[agent]`, so the workload can change what is \
                 in it; keep the program of each secret source, its `#!` interpreter, and each \
                 path in its `command`, outside every write grant",
                holder.display(),
                inner.display()
            ),
            "{text}"
        );
    }
    for arguments in ["\"--config\", \"~\"", "\"--dir=~\""] {
        let text = under(arguments, &home_grant);
        let error = scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .expect_err("the home, which holds a write grant");
        assert!(
            matches!(
                &error,
                Error::SourceProgramUnderWrite { program, holds: true, writer, .. }
                    if *program == scene.home() && writer == "agent"
            ),
            "{text}: {error}"
        );
        assert!(
            error.to_string().starts_with(&format!(
                "{} holds the write grant ",
                scene.home().display()
            )) && error.to_string().ends_with(
                " of `[agent]`, so the workload can change what is in it; keep the program of \
                 each secret source, its `#!` interpreter, and each path in its `command`, \
                 outside every write grant"
            ),
            "{text}: {error}"
        );
    }
    let elsewhere = scene.root.join("etc");
    for arguments in [
        format!(
            "\"--config\", {:?}",
            elsewhere.join("absent.json").display()
        ),
        format!("\"--config-dir={}\"", elsewhere.display()),
        "\"--path\", \"/v1/secret/data\"".to_string(),
        "\"read\", \"granted/missing.json\"".to_string(),
    ] {
        let text = under(&arguments, &granted);
        scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .unwrap_or_else(|error| {
                panic!("a path outside every write grant, and an argument that is no full path: {text}: {error}")
            });
    }
    for (arguments, grant) in [
        (format!("{:?}", absent.display()), &granted),
        (format!("{:?}", folder.display()), &granted),
        (format!("{:?}", holder.display()), &inner),
    ] {
        let text = format!(
            "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
             [tool.vault]\ncommand = [{op:?}, \"--config\", {arguments}]\n",
            grant.display()
        );
        scene
            .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
            .unwrap_or_else(|error| {
                panic!("a tool runs in its sandbox, so its check does not change: {text}: {error}")
            });
    }
    let text = format!(
        "[agent]\ncommand = [\"/usr/bin/true\"]\nfilesystem.write = [{:?}]\n\
         env.PATH = \"{}:/usr/bin\"\n",
        inner.display(),
        holder.display()
    );
    scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .unwrap_or_else(|error| {
            panic!("a folder of a workload that holds a write grant passes, as before: {error}")
        });
    plugin(
        &scene,
        "vault",
        &format!(
            "[plugin]\nname = \"@box/vault\"\nversion = 1\nkind = \"secret-source\"\n\
             scheme = \"vault\"\n\
             [inputs.vault.path]\ntype = \"program\"\nprogram = \"op\"\n\
             [run]\ncommand = [\"${{{{ inputs.vault.path }}}}\", \"-config={}\", \"{{ref}}\"]\n",
            absent.display()
        ),
    );
    let text = format!(
        "plugins = [\"@box/vault\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
         filesystem.write = [{:?}]\n",
        granted.display()
    );
    let error = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect_err("an absent file of a plugin's command that the box can make");
    assert_eq!(
        error.to_string(),
        format!(
            "{} lies under the write grant {} of `[agent]`, so the workload can replace it; keep \
             the program of each secret source, its `#!` interpreter, and each path in its \
             `command`, outside every write grant",
            absent.display(),
            granted.display()
        )
    );
}

/// The text of the plugin `@box/<name>` that `box` ships.
fn shipped(name: &str) -> String {
    let path = crate::resources::source_tree()
        .join(crate::plugin::PLUGINS)
        .join(name)
        .join(crate::plugin::PLUGIN_FILE);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_shipped_plugins_write_their_sources_into_box_toml() {
    let scene = Scene::new();
    plugin(&scene, "1password", &shipped("1password"));
    plugin(
        &scene,
        "aws-secrets-manager",
        &shipped("aws-secrets-manager"),
    );
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    binary(&bin.join("aws"));
    let mut host = Host::new(bin);
    let (resolved, compiled) = scene
        .compile_using(&profile(BOTH), &mut host, "/usr/bin:/bin")
        .expect("a compile");
    let mut inputs: Vec<&str> = resolved
        .inputs
        .iter()
        .map(|input| input.name.as_str())
        .collect();
    inputs.sort_unstable();
    assert_eq!(
        inputs,
        ["aws-secrets-manager.path", "onepassword.path"],
        "the program input that each plugin's README names"
    );
    let expected: toml::Value = toml::from_str(&format!(
        r#"
        [op]
        protocol = "box.secret-source.v1"
        command = ["{bin}/op", "read", "op://{{ref}}"]
        pass-env = ["OP_ACCOUNT", "OP_CONNECT_HOST", "TMPDIR"]
        pass-secret-env = ["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"]
        deny = ["~/.config/op", "~/.op", "~/Library/Group Containers/2BUA8C4S2C.com.1password"]

        [aws-secretsmanager]
        protocol = "box.secret-source.v1"
        command = ["{bin}/aws", "secretsmanager", "get-secret-value", "--secret-id", "{{ref}}",
                   "--query", "SecretString", "--output", "json"]
        output = "json"
        pass-env = ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN",
                    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_EC2_METADATA_DISABLED"]
        pass-secret-env = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                           "AWS_CONTAINER_AUTHORIZATION_TOKEN"]
        deny = ["~/.aws", "/var/run/secrets/eks.amazonaws.com",
                "/var/run/secrets/pods.eks.amazonaws.com"]
        "#,
        bin = host.bin.display(),
    ))
    .expect("TOML");
    assert_eq!(table(&compiled)["secret-source"], expected);
}

/// The source that the README of `@box/1password` gives for a manual sign-in is a source of the
/// profile: it reaches `box.toml` as the README writes it, and no `env` entry copies a session
/// variable that its prefix entry covers.
#[test]
fn the_1password_readme_source_for_a_manual_sign_in_compiles_in_a_profile() {
    let readme = crate::resources::source_tree().join("plugins/1password/README.md");
    let readme = std::fs::read_to_string(&readme).expect("the README of @box/1password");
    let source = readme
        .split("```")
        .find(|block| block.starts_with("toml\n") && block.contains("[secret-source.op]\n"))
        .expect("the source of a manual sign-in")
        .lines()
        .skip(1)
        .map(str::trim_start)
        .collect::<Vec<_>>()
        .join("\n");
    let scene = Scene::new();
    let mut host = Host::new(scene.root.join("bin"));
    host.variables
        .push(("OP_SESSION_my", "session".to_string()));
    let agent = "[agent]\ncommand = [\"/usr/bin/true\"]\n";
    let (_, compiled) = scene
        .compile_using(
            &profile(&format!("{agent}{source}")),
            &mut host,
            "/usr/bin:/bin",
        )
        .expect("a profile's own source");
    let written: toml::Value = toml::from_str(&source).expect("TOML");
    assert_eq!(
        table(&compiled)["secret-source"]["op"],
        written["secret-source"]["op"]
    );
    assert_eq!(
        written["secret-source"]["op"]["pass-secret-env"],
        toml::Value::from(vec!["OP_SESSION_*"])
    );
    assert_eq!(
        refused(
            &scene,
            &format!("{agent}env.S = {{ from = \"env:OP_SESSION_my\" }}\n{source}"),
            &mut host
        ),
        "`agent.env.S` would give the workload the host's `OP_SESSION_my`, which \
         `[secret-source.op]` of the profile passes to its program as a credential"
    );
}

/// A copy of `@box/1password` that names one session variable in `[env]` and in `[protect] env`,
/// as its README says for a manual sign-in, passes it to the program as a credential, and no
/// `env` entry copies it.
#[test]
fn a_copy_of_the_1password_plugin_names_a_session_variable_as_a_credential() {
    let shipped = shipped("1password");
    let token_list = "env   = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_CONNECT_TOKEN\"]";
    assert_eq!(
        (
            shipped.matches("[env]\n").count(),
            shipped.matches(token_list).count()
        ),
        (1, 1),
        "the lines that the README tells a copy to change"
    );
    let copy = shipped
        .replace(
            "[env]\n",
            "[env]\nOP_SESSION_my = { from = \"env:OP_SESSION_my\" }\n",
        )
        .replace(
            token_list,
            "env = [\"OP_SERVICE_ACCOUNT_TOKEN\", \"OP_CONNECT_TOKEN\", \"OP_SESSION_my\"]",
        );
    let scene = Scene::new();
    plugin(&scene, "1password", &copy);
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    let mut host = Host::new(bin);
    host.variables
        .push(("OP_SESSION_my", "session".to_string()));
    let text = "plugins = [\"@box/1password\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n";
    let (_, compiled) = scene
        .compile_using(&profile(text), &mut host, "/usr/bin:/bin")
        .expect("a copy with a session variable");
    let source = &table(&compiled)["secret-source"]["op"];
    assert_eq!(
        source["pass-secret-env"],
        toml::Value::from(vec![
            "OP_SESSION_my",
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_TOKEN"
        ])
    );
    assert_eq!(
        source["pass-env"],
        toml::Value::from(vec!["OP_ACCOUNT", "OP_CONNECT_HOST", "TMPDIR"]),
        "the copy passes TMPDIR, where op keeps the file of the session"
    );
    assert_eq!(
        refused(
            &scene,
            &format!("{text}env.S = {{ from = \"env:OP_SESSION_my\" }}\n"),
            &mut host
        ),
        "`agent.env.S` would give the workload the host's `OP_SESSION_my`, which the plugin \
         @box/1password passes to its program as a credential"
    );
}

/// The AWS plugin's program input does not take the name of an `aws` tool pack's input, so a
/// profile can list both, and each finds its own `aws`.
#[test]
fn the_aws_plugin_loads_beside_an_aws_tool_pack() {
    let scene = Scene::new();
    plugin(
        &scene,
        "aws-secrets-manager",
        &shipped("aws-secrets-manager"),
    );
    scene.share("aws", &crate::lang::test_tool_pack("aws", ""));
    let bin = scene.root.join("bin");
    binary(&bin.join("aws"));
    let mut host = Host::new(bin);
    let path = format!("{}:/usr/bin:/bin", host.bin.display());
    let (_, compiled) = scene
        .compile_using(
            &profile(
                "packs = [\"@box/aws\"]\nplugins = [\"@box/aws-secrets-manager\"]\n\n\
                 [agent]\ncommand = [\"/usr/bin/true\"]\n",
            ),
            &mut host,
            &path,
        )
        .expect("a compile");
    let file = table(&compiled);
    let aws = host.bin.join("aws").display().to_string();
    assert_eq!(
        (
            file["tool"]["aws"]["command"][0].as_str(),
            file["secret-source"]["aws-secretsmanager"]["command"][0].as_str(),
        ),
        (Some(aws.as_str()), Some(aws.as_str()))
    );
}

/// A profile that reads a shipped pack's key from 1Password keeps the pack's other secret keys,
/// such as `@box/anthropic`'s header and stand-in prefix.
#[test]
fn a_vault_key_on_a_shipped_packs_route_keeps_the_packs_secret_keys() {
    let scene = Scene::new();
    plugin(&scene, "1password", &shipped("1password"));
    let pack = crate::resources::source_tree().join("packs/anthropic/pack.toml");
    scene.share_raw(
        "anthropic",
        &std::fs::read_to_string(&pack).expect("the shipped @box/anthropic"),
    );
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    let mut host = Host::new(bin);
    let (_, compiled) = scene
        .compile_using(
            &profile(
                "packs = [\"@box/anthropic\"]\nplugins = [\"@box/1password\"]\n\n\
                 [agent]\ncommand = [\"/usr/bin/true\"]\n\n\
                 [egress.anthropic.secret]\nref = \"op://Private/Anthropic/credential\"\n\
                 env = \"ANTHROPIC_API_KEY\"\n",
            ),
            &mut host,
            "/usr/bin:/bin",
        )
        .expect("a compile");
    assert_eq!(
        table(&compiled)["egress"]["anthropic"],
        toml::from_str::<toml::Value>(
            "destinations = [\"api.anthropic.com\"]\n\
             secret = { ref = \"op://Private/Anthropic/credential\", env = \"ANTHROPIC_API_KEY\", \
             header = \"x-api-key\", phantom_prefix = \"sk-ant-\" }"
        )
        .expect("TOML")
    );
}

#[test]
fn an_mcp_server_that_reads_a_vault_credential_or_a_stand_in_variable_is_skipped() {
    let (scene, mut host) = plugins_scene();
    host.variables
        .push(("OP_SERVICE_ACCOUNT_TOKEN", "ops_real".to_string()));
    host.variables
        .push(("GH_TOKEN", "stale_host_token".to_string()));
    binary(&host.bin.join("vault-mcp"));
    binary(&host.bin.join("github-mcp"));
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"${{ home }}/.agent.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]\nenv-var-locations = { env = \"references\" }\n\
         env-var-syntax = \"${NAME}\"",
    );
    crate::fixtures::write(
        &scene.home().join(".agent.json"),
        r#"{"mcpServers": {
            "vault": {"command": "vault-mcp", "env": {"T": "${OP_SERVICE_ACCOUNT_TOKEN}"}},
            "github": {"command": "github-mcp", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GH_TOKEN}"}}
        }}"#,
    );
    let text = format!("packs = [\"@box/agent\"]\n{BOTH}");
    let (resolved, compiled) = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect("a compile");
    assert_eq!(
        resolved.servers.skipped_lines(&scene.home()),
        vec![
            (
                "github".to_string(),
                "~/.agent.json".to_string(),
                "reads GH_TOKEN, which the route github names in `secret.env` for its op:// key, \
                 and the host's value of GH_TOKEN is not that key"
                    .to_string()
            ),
            (
                "vault".to_string(),
                "~/.agent.json".to_string(),
                "reads OP_SERVICE_ACCOUNT_TOKEN, which the plugin @box/1password \
                 passes to its program as a credential, so no server in the box gets its value"
                    .to_string()
            ),
        ]
    );
    for value in ["ops_real", "stale_host_token"] {
        assert!(
            !compiled.box_toml.contains(value),
            "{value}: {}",
            compiled.box_toml
        );
    }
}

/// An MCP configuration file in a path that a secret source protects is not read, so no server
/// in it, and no `env` that it holds, reaches the box.
#[test]
fn an_mcp_configuration_in_a_path_that_a_source_protects_is_not_read() {
    let (scene, mut host) = plugins_scene();
    binary(&host.bin.join("q-mcp"));
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"${{ home }}/.aws/amazonq/mcp.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]\n\
         [[mcp-servers]]\nfile = \"${{ home }}/.agent.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]",
    );
    for file in [".aws/amazonq/mcp.json", ".agent.json"] {
        crate::fixtures::write(
            &scene.home().join(file),
            r#"{"mcpServers": {"q": {"command": "q-mcp", "env": {"KEY": "typed-in-key"}}}}"#,
        );
    }
    let (resolved, compiled) = scene
        .compile_using(
            &profile(&format!("packs = [\"@box/agent\"]\n{BOTH}")),
            &mut host,
            "/usr/bin:/bin",
        )
        .expect("a compile");
    assert_eq!(
        resolved.servers.unread_lines(&scene.home()),
        vec![(
            "~/.aws/amazonq/mcp.json".to_string(),
            "~/.aws/amazonq/mcp.json lies in ~/.aws, a path that \
             the plugin @box/aws-secrets-manager lists in `[protect] paths`, \
             which the box keeps from every workload; box reads no MCP configuration from there"
                .to_string()
        )]
    );
    assert_eq!(
        resolved
            .servers
            .detected_lines(&scene.home())
            .into_iter()
            .map(|(name, file, _)| (name, file))
            .collect::<Vec<_>>(),
        vec![("q".to_string(), "~/.agent.json".to_string())],
        "the same server in a file outside the path comes in"
    );
    assert_eq!(compiled.box_toml.matches("typed-in-key").count(), 1);
}

/// A detected server whose program, `#!` interpreter, or CA file lies in a path that a secret
/// source protects is skipped, or goes without that CA variable, so Box Core does not refuse the
/// run for a grant on it.
#[test]
fn a_detected_servers_part_in_a_path_that_a_source_protects_is_not_granted() {
    let (scene, mut host) = plugins_scene();
    let home = scene.home();
    let planted = home.join(".aws/bin/planted");
    binary(&planted);
    let python = home.join(".aws/venv/bin/python3");
    binary(&python);
    let script = host.bin.join("script");
    crate::fixtures::write(&script, &format!("#!{}\nexit 0\n", python.display()));
    crate::fixtures::executable(&script);
    binary(&host.bin.join("fetcher"));
    let ca = home.join(".aws/ca.pem");
    crate::fixtures::write(&ca, "pem");
    scene.share(
        "agent",
        "[[mcp-servers]]\nfile = \"${{ home }}/.agent.json\"\nkind = \"json\"\n\
         key = [\"mcpServers\"]",
    );
    crate::fixtures::write(
        &home.join(".agent.json"),
        &format!(
            r#"{{"mcpServers": {{
            "planted": {{"command": "{}"}},
            "script": {{"command": "script"}},
            "fetch": {{"command": "fetcher", "env": {{"NODE_EXTRA_CA_CERTS": "{}"}}}}
        }}}}"#,
            planted.display(),
            ca.display()
        ),
    );
    let text =
        format!("packs = [\"@box/agent\"]\n{BOTH}\n[mcp.fetch.network]\ncontain_egress = false");
    let (resolved, compiled) = scene
        .compile_using(&profile(&text), &mut host, "/usr/bin:/bin")
        .expect("a compile");
    let protected = "lies in ~/.aws, a path that the plugin @box/aws-secrets-manager \
                     lists in `[protect] paths`, which the box keeps from every \
                     workload";
    assert_eq!(
        resolved.servers.skipped_lines(&home),
        vec![
            (
                "planted".to_string(),
                "~/.agent.json".to_string(),
                format!(
                    "its program ~/.aws/bin/planted {protected}; box runs no program from there"
                )
            ),
            (
                "script".to_string(),
                "~/.agent.json".to_string(),
                format!(
                    "its interpreter ~/.aws/venv/bin/python3 {protected}; box runs no program \
                     from there"
                )
            ),
        ]
    );
    assert_eq!(
        resolved.servers.dropped_lines(&home),
        vec![(
            "NODE_EXTRA_CA_CERTS".to_string(),
            "fetch".to_string(),
            "~/.agent.json".to_string(),
            format!(
                "its NODE_EXTRA_CA_CERTS names a file the box grants no server: ~/.aws/ca.pem \
                 {protected}"
            )
        )]
    );
    let aws = home.join(".aws").display().to_string();
    assert!(
        !compiled.box_toml.contains(&aws),
        "no grant reaches ~/.aws: {}",
        compiled.box_toml
    );
}

#[test]
fn a_storage_row_that_reaches_a_path_that_a_source_protects_is_refused() {
    let scene = Scene::new();
    plugin(&scene, "1password", &shipped("1password"));
    let bin = scene.root.join("bin");
    binary(&bin.join("op"));
    let mut host = Host::new(bin);
    let home = scene.home();
    let app = "Library/Group Containers/2BUA8C4S2C.com.1password";
    for file in [
        ".config/op/config",
        ".op/config",
        &format!("{app}/settings.json"),
    ] {
        crate::fixtures::write(&home.join(file), "{}");
    }
    std::os::unix::fs::symlink(home.join(".op"), home.join("notes")).expect("a link");
    let agent = |rows: &str| {
        format!(
            "plugins = [\"@box/1password\"]\n[agent]\ncommand = [\"/usr/bin/true\"]\n\
             [storage]\ndirectories = [\"config\"]\n{rows}"
        )
    };
    let copy = |source: &str| {
        agent(&format!(
            "[[storage.files]]\nsource = {source:?}\ntarget = \"config/x\"\n"
        ))
    };
    let tool = |mode: &str| {
        agent(&format!(
            "[tool.vaulty]\ncommand = [\"/usr/bin/true\"]\nstorage.directories = [\"state\"]\n\
             storage.files = [{{ source = \"~/.op\", target = \"state/op\", mode = {mode:?} }}]\n"
        ))
    };
    let named = |key: &str| {
        format!(
            "the plugin @box/1password lists in `{key}`, which the box keeps from \
             every workload"
        )
    };
    let reads = named("[protect] paths");
    for (text, wanted) in [
        (
            copy("${{ home }}/.config/op"),
            format!(
                "`storage.files[0] source`: ~/.config/op is a path that {reads}; box copies no \
                 file from there"
            ),
        ),
        (
            copy("${{ home }}/.config/op/config"),
            format!(
                "`storage.files[0] source`: ~/.config/op/config lies in ~/.config/op, a path \
                 that {reads}; box copies no file from there"
            ),
        ),
        (
            copy("${{ home }}/.config"),
            format!(
                "`storage.files[0] source`: ~/.config holds ~/.config/op, a path that {reads}; \
                 box copies no file from there"
            ),
        ),
        (
            copy("${{ home }}/notes"),
            format!(
                "`storage.files[0] source`: ~/notes (a link to ~/.op) is a path that {reads}; box \
                 copies no file from there"
            ),
        ),
        (
            copy(&format!("${{{{ home }}}}/{app}/settings.json")),
            format!(
                "`storage.files[0] source`: ~/{app}/settings.json lies in ~/{app}, a path that \
                 {}; box copies no file from there",
                named("[protect] paths")
            ),
        ),
        (
            tool("copy"),
            format!(
                "`tool.vaulty.storage.files[0] source`: ~/.op is a path that {reads}; box copies \
                 no file from there"
            ),
        ),
        (
            tool("link"),
            format!(
                "`tool.vaulty.storage.files[0] source`: ~/.op is a path that {reads}; box links \
                 nothing from there"
            ),
        ),
    ] {
        assert_eq!(refused(&scene, &text, &mut host), wanted, "{text}");
    }
    let own = "[agent]\ncommand = [\"/usr/bin/true\"]\n[storage]\ndirectories = [\"config\"]\n\
               [[storage.files]]\nsource = \"${{ home }}/.op\"\ntarget = \"config/x\"\n\
               [secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"{ref}\"]\n\
               reads = [\"~/.op\"]\n";
    assert_eq!(
        refused(&scene, own, &mut host),
        "`storage.files[0] source`: ~/.op is a path that `[secret-source.vault]` of the profile \
         lists in `reads`, which the box keeps from every workload; box copies no file from there"
    );
    assert_eq!(
        refused(
            &scene,
            &own.replace("reads = [\"~/.op\"]", "deny = [\"~/.op\"]"),
            &mut host
        ),
        "`storage.files[0] source`: ~/.op is a path that `[secret-source.vault]` of the profile \
         lists in `deny`, which the box keeps from every workload; box copies no file from there",
        "a source of the profile keeps Box Core's name for its list"
    );
    assert_eq!(
        refused(
            &scene,
            &own.replace("reads = [\"~/.op\"]", "reads = [\"~\"]"),
            &mut host
        ),
        format!(
            "`storage.files[0] source`: ~/.op lies in {}, a path that `[secret-source.vault]` of \
             the profile lists in `reads`, which the box keeps from every workload; box copies no \
             file from there",
            home.display()
        )
    );
    let skills = home.join("skills");
    crate::fixtures::write(&skills.join("a.md"), "a\n");
    std::os::unix::fs::symlink(home.join(".config/op"), skills.join("vault")).expect("a link");
    let resolved = scene
        .resolve_using(
            &profile(&copy("${{ home }}/skills")),
            &scene.context(),
            &mut host,
        )
        .expect("a copy of a folder that links to a protected path");
    let run = scene.root.join("run");
    std::fs::create_dir_all(&run).expect("a run directory");
    crate::run::prepare_storage(&resolved.storage, &home).expect("storage");
    let copied =
        crate::storage_sync::copy_files(&resolved.storage, &run, &home, &home).expect("copies");
    assert_eq!(
        copied.not_copied,
        vec![(
            "~/skills/vault".to_string(),
            format!("~/.config/op is a path that {reads}; box copies no file from there")
        )]
    );
    let copy_root = resolved.storage.files[0].target.clone();
    assert!(copy_root.join("a.md").is_file());
    assert!(
        !copy_root.join("vault").exists(),
        "the link is not followed"
    );
    scene
        .resolve_using(
            &profile(
                &copy("${{ home }}/.config/op").replace("plugins = [\"@box/1password\"]\n", ""),
            ),
            &scene.context(),
            &mut host,
        )
        .expect("a path that no declared source lists is copied as before");
}

#[test]
fn show_names_each_plugin_and_the_program_that_each_source_runs() {
    let root = tempfile::tempdir().expect("a root");
    let home = root.path().canonicalize().expect("a canonical home");
    let workspace = home.join("project");
    let bin = home.join("bin");
    std::fs::create_dir_all(&workspace).expect("a workspace");
    for program in ["op", "aws", "vault"] {
        binary(&bin.join(program));
    }
    let write = |name: &str, text: &str| {
        let path = home
            .join(".strands/box/profiles")
            .join(name)
            .join("profile.toml");
        std::fs::create_dir_all(path.parent().expect("a folder")).expect("a profile folder");
        std::fs::write(path, text).expect("a profile");
    };
    write(
        "plugins",
        &format!(
            "packs = [\"@box/base\"]\nplugins = [\"@box/1password\", \"@box/aws-secrets-manager\"]\n\
             policies = [\"policy.dw\"]\n\n\
             [agent]\ncommand = [\"/usr/bin/true\"]\n\n\
             [secret-source.vault]\nprotocol = \"box.secret-source.v1\"\n\
             command = [{:?}, \"kv\", \"get\", \"{{ref}}\"]\n",
            bin.join("vault").display().to_string()
        ),
    );
    std::fs::write(
        home.join(".strands/box/profiles/plugins/policy.dw"),
        "// No rules.\n",
    )
    .expect("a policy");
    write(
        "plain",
        "packs = [\"@box/base\"]\n\n[agent]\ncommand = [\"/usr/bin/true\"]\n",
    );
    write(
        "anthropic",
        "packs = [\"@box/base\", \"@box/anthropic\"]\nplugins = [\"@box/1password\"]\n\n\
         [agent]\ncommand = [\"/usr/bin/true\"]\n\n\
         [egress.anthropic.secret]\nref = \"op://Private/Anthropic/credential\"\n\
         env = \"ANTHROPIC_API_KEY\"\n",
    );
    let launcher = Launcher::from_host()
        .home(&home)
        .search_path(format!("{}:/usr/bin:/bin", bin.display()))
        .environment(&[]);
    let checked = |name: &str| {
        let preview = launcher
            .preview(name, &workspace)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(preview.warnings, Vec::<String>::new(), "{name}");
        preview
    };
    let storage = |name: &str| {
        home.join(".strands/box/storage")
            .join(name)
            .join("default")
            .display()
            .to_string()
    };
    let bin = bin.display();
    assert_eq!(
        checked("plugins").overview(),
        vec![
            ("packs", "@box/base 1".to_string()),
            (
                "plugins",
                "@box/1password 1, @box/aws-secrets-manager 1".to_string()
            ),
            ("source", format!("op:// runs {bin}/op (@box/1password)")),
            (
                "source",
                format!("aws-secretsmanager:// runs {bin}/aws (@box/aws-secrets-manager)")
            ),
            (
                "source",
                format!("vault:// runs {bin}/vault (your profile)")
            ),
            ("policies", "policy.dw".to_string()),
            ("storage", storage("plugins")),
            ("project", "none (no [project] in this profile)".to_string()),
        ]
    );
    assert_eq!(
        checked("plain").overview(),
        vec![
            ("packs", "@box/base 1".to_string()),
            ("storage", storage("plain")),
            ("project", "none (no [project] in this profile)".to_string()),
        ]
    );
    assert_eq!(
        checked("anthropic").overview(),
        vec![
            ("packs", "@box/base 1, @box/anthropic 1".to_string()),
            ("plugins", "@box/1password 1".to_string()),
            ("source", format!("op:// runs {bin}/op (@box/1password)")),
            ("storage", storage("anthropic")),
            ("project", "none (no [project] in this profile)".to_string()),
        ]
    );
}

/// `reads` and `deny` are literal, so a placeholder in one stops the load, and the storage check
/// and Box Core read the same paths.
#[test]
fn a_placeholder_in_a_sources_reads_or_deny_is_refused() {
    let scene = Scene::new();
    for key in ["reads", "deny"] {
        let reason = scene.resolve_refusal(&format!(
            "{MINIMAL}\n[secret-source.vault]\ncommand = [\"/usr/local/bin/vault\", \"kv\", \
             \"get\", \"{{ref}}\"]\n{key} = [\"${{{{ home }}}}/.vault-token\"]\n"
        ));
        assert!(
            reason.starts_with(&format!(
                "`secret-source.vault.{key}.0` is literal and holds no placeholder;"
            )),
            "{key}: {reason}"
        );
    }
}

/// An operator's plugin with a `program` input and a bounded `string` input, which reads
/// `vault://` references.
const TEAM_VAULT: &str = r#"[plugin]
name    = "team-vault"
version = 1
kind    = "secret-source"
scheme  = "vault"

[inputs.vault.path]
type    = "program"
program = "vault"

[inputs.vault.namespace]
type    = "string"
values  = ["dev", "prod"]
default = "dev"

[run]
command = ["${{ inputs.vault.path }}", "kv", "get", "-namespace=${{ inputs.vault.namespace }}", "{ref}"]
"#;

/// An operator's plugin whose program input searches the folders that an unbounded `string` input
/// and a `string` input with a `pattern` that admits a path name, with a `pattern` input and a
/// `values` input that only `command` reads, and a `bool` input.
const TEAM_DIR: &str = r#"[plugin]
name    = "team-dir"
version = 1
kind    = "secret-source"
scheme  = "dir"

[inputs.dir.folder]
type    = "string"
default = "${{ home }}/bin"

[inputs.dir.wide]
type    = "string"
pattern = "/.+"
default = "/usr/local/bin"

[inputs.dir.mount]
type    = "string"
pattern = "[a-z]+"
default = "kv"

[inputs.dir.engine]
type    = "string"
values  = ["kv1", "kv2"]
default = "kv2"

[inputs.dir.verbose]
type    = "bool"
default = false

[inputs.dir.path]
type    = "program"
program = "vault"
search  = ["${{ inputs.dir.folder }}", "${{ inputs.dir.wide }}"]

[run]
command = ["${{ inputs.dir.path }}", "${{ inputs.dir.engine }}", "get", "-mount=${{ inputs.dir.mount }}", "{ref}"]
"#;

/// A home with the plugins `team-vault`, `team-dir`, `team-local`, which searches `~/opt/vault`, and
/// `team-fixed`, which names its program in `default`, in `~/.strands/box/plugins/`; `vault` on `PATH`; a
/// second `vault` in `~/opt/vault`; and a project.
struct PathProfiles {
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
    bin: PathBuf,
    other: PathBuf,
}

impl PathProfiles {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a root");
        let home = root.path().canonicalize().expect("a canonical home");
        let workspace = home.join("project");
        let bin = home.join("bin");
        let other = home.join("opt/vault/vault");
        std::fs::create_dir_all(&workspace).expect("a workspace");
        binary(&bin.join("vault"));
        binary(&other);
        let found = |name: &str, scheme: &str, input: &str| {
            format!(
                "[plugin]\nname = {name:?}\nversion = 1\nkind = \"secret-source\"\n\
                 scheme = \"{scheme}\"\n\n\
                 [inputs.{scheme}.path]\ntype = \"program\"\n{input}\n\n\
                 [run]\n\
                 command = [\"${{{{ inputs.{scheme}.path }}}}\", \"read\", \"{{ref}}\"]\n"
            )
        };
        for (name, text) in [
            ("team-vault", TEAM_VAULT.to_string()),
            ("team-dir", TEAM_DIR.to_string()),
            (
                "team-local",
                found(
                    "team-local",
                    "local",
                    "program = \"vault\"\nsearch = [\"~/opt/vault\"]",
                ),
            ),
            (
                "team-fixed",
                found(
                    "team-fixed",
                    "fixed",
                    &format!("default = {:?}", bin.join("vault").display().to_string()),
                ),
            ),
        ] {
            let folder = home.join(".strands/box/plugins").join(name);
            std::fs::create_dir_all(&folder).expect("a plugin folder");
            std::fs::write(folder.join("plugin.toml"), text).expect("a plugin");
        }
        Self {
            _root: root,
            home,
            workspace,
            bin,
            other,
        }
    }

    fn launcher(&self) -> Launcher {
        Launcher::from_host()
            .home(&self.home)
            .search_path(format!("{}:/usr/bin:/bin", self.bin.display()))
            .environment(&[])
    }

    /// The profile file `~/repo/box/profile.toml`, named `weather`, with `text` after its header.
    fn file(&self, text: &str) -> PathBuf {
        let path = self.home.join("repo/box/profile.toml");
        std::fs::create_dir_all(path.parent().expect("a folder")).expect("a profile folder");
        std::fs::write(
            &path,
            format!("packs = [\"@box/base\"]\n{text}\n[profile]\nname = \"weather\"\n\n[agent]\ncommand = [\"/usr/bin/true\"]\n"),
        )
        .expect("a profile file");
        path
    }

    /// The profile `~/.strands/box/profiles/weather/profile.toml` with `text` after its `packs`.
    fn named(&self, text: &str) -> String {
        let path = self.home.join(".strands/box/profiles/weather/profile.toml");
        std::fs::create_dir_all(path.parent().expect("a folder")).expect("a profile folder");
        std::fs::write(
            &path,
            format!("packs = [\"@box/base\"]\n{text}\n[agent]\ncommand = [\"/usr/bin/true\"]\n"),
        )
        .expect("a profile");
        "weather".to_string()
    }

    /// `box profile show` of `argument`, which `box` loads.
    fn loads(&self, argument: &str) {
        if let Err(error) = self.launcher().preview(argument, &self.workspace) {
            panic!("{argument}: {error}");
        }
    }

    /// The file, the line, and the reason of the refusal of `argument` by `box profile show` and
    /// by `box run`, which refuse it the same way.
    fn refused(&self, argument: &str) -> (PathBuf, Option<usize>, String) {
        let shown = match self.launcher().preview(argument, &self.workspace) {
            Err(Error::Profile { path, line, reason }) => (path, line, reason),
            Err(error) => panic!("{argument}: a refusal of the profile, not {error}"),
            Ok(_) => panic!("{argument}: a refusal, not a preview"),
        };
        match self.launcher().prepare(argument, &self.workspace, None) {
            Err(Error::Profile { path, line, reason }) => {
                assert_eq!((path, line, reason), shown.clone(), "{argument}");
            }
            Err(error) => panic!("{argument}: a refusal of the profile, not {error}"),
            Ok(_) => panic!("{argument}: a refusal, not a run"),
        }
        shown
    }
}

/// **A profile file that runs by its path declares no secret source**: a project that comes with
/// one would run a host program of its choice, outside the box. The same table in a profile in
/// `~/.strands/box/profiles/` still loads.
#[test]
fn a_profile_file_that_runs_by_its_path_declares_no_secret_source() {
    let homes = PathProfiles::new();
    let source = format!(
        "\n[secret-source.vault]\nprotocol = \"box.secret-source.v1\"\ncommand = [{:?}, \"kv\", \"get\", \"{{ref}}\"]\n\n\
         [egress.github]\ndestinations = [\"api.github.com\"]\nsecret.ref = \"vault://team/github\"\n\
         secret.env = \"GH_TOKEN\"\n",
        homes.bin.join("vault").display().to_string()
    );
    let file = homes.file(&source);
    let (path, line, reason) = homes.refused(&file.display().to_string());
    assert_eq!(
        (path, line, reason),
        (
            file.clone(),
            Some(3),
            "a profile file that runs by its path declares no `[secret-source.vault]`, because a \
             secret source runs a program on the host, outside the box; put the source in a \
             plugin in ~/.strands/box/plugins/<name>/ and list it in `plugins`, or move the profile to \
             ~/.strands/box/profiles/weather/"
                .to_string()
        )
    );
    std::fs::remove_file(&file).expect("the profile file is gone");
    homes.loads(&homes.named(&source));
}

/// **A profile file that runs by its path sets a plugin's input only to a value that the plugin
/// lists**: an input with no `values` can name the folder where the plugin finds its program, or
/// an argument of the program, and a `pattern` limits the form of a value, not what it names. A
/// `values` input and a `bool` stay settable, and a profile in `~/.strands/box/profiles/` still sets the
/// other inputs.
#[test]
fn a_profile_file_that_runs_by_its_path_sets_only_a_listed_value_of_a_plugin() {
    let homes = PathProfiles::new();
    let folder = homes
        .other
        .parent()
        .expect("the folder of the second vault")
        .display()
        .to_string();
    let route = "\n[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret.ref = \"dir://team/github\"\nsecret.env = \"GH_TOKEN\"\n";
    for (input, options, line) in [
        (
            "dir.folder",
            format!("\n[options]\ndir.folder = {folder:?}\n"),
            5,
        ),
        (
            "dir.folder",
            format!("\n[options.dir]\nengine = \"kv1\"\nfolder = {folder:?}\n"),
            6,
        ),
        (
            "dir.wide",
            format!("\n[options]\ndir.wide = {folder:?}\n"),
            5,
        ),
        (
            "dir.mount",
            "\n[options]\ndir.mount = \"secret\"\n".to_string(),
            5,
        ),
    ] {
        let file = homes.file(&format!("plugins = [\"team-dir\"]\n{options}{route}"));
        assert_eq!(
            homes.refused(&file.display().to_string()),
            (
                file.clone(),
                Some(line),
                format!(
                    "`[options] {input}` sets an input of the plugin team-dir that lists no \
                     `values` for it, and a profile file that runs by its path sets a plugin's \
                     input only to a value that the plugin lists, because the input can name the \
                     program that runs outside the box or what the program reads; move the \
                     profile to ~/.strands/box/profiles/weather/"
                )
            ),
            "{options}"
        );
    }
    for options in [
        "\n[options]\ndir.engine = \"kv1\"\n",
        "\n[options]\ndir.verbose = true\n",
    ] {
        let file = homes.file(&format!("plugins = [\"team-dir\"]\n{options}{route}"));
        homes.loads(&file.display().to_string());
    }
    std::fs::remove_file(homes.home.join("repo/box/profile.toml")).expect("the file is gone");
    homes.loads(&homes.named(&format!(
        "plugins = [\"team-dir\"]\n\n[options]\ndir.folder = {folder:?}\ndir.wide = {folder:?}\n\
         dir.mount = \"secret\"\n{route}"
    )));
}

/// Plugins of the operator's own that read the folder of the profile: in the `search` or the
/// `default` of the program input, and in an element of `command`, as the folder or the file.
/// Each with how a profile in `~/.strands/box/profiles/weather/` stops on it, where the folder lies in
/// the box home.
const READS_PROFILE: [(&str, &str, &str, &str, &str); 4] = [
    (
        "prof-search",
        "profile",
        "program = \"vault\"\nsearch = [\"${{ profile }}/bin\"]",
        "",
        "no `vault` that the box can run in the folders `[inputs.p.path] search` names",
    ),
    (
        "prof-default",
        "profile",
        "default = \"${{ profile }}/bin/vault\"",
        "",
        "/.strands/box/profiles/weather/bin/vault\" is not an executable file",
    ),
    (
        "prof-command",
        "profile",
        "program = \"vault\"",
        ", \"-config=${{ profile }}/vault.hcl\"",
        "/.strands/box/profiles/weather/vault.hcl lies in the box home, which a box can write",
    ),
    (
        "prof-file",
        "profile.file",
        "program = \"vault\"",
        ", \"-config=${{ profile.file }}\"",
        "/.strands/box/profiles/weather/profile.toml lies in the box home, which a box can write",
    ),
];

/// Write the plugin `name` of `READS_PROFILE` into `~/.strands/box/plugins/`, with the scheme `name`.
fn reads_profile(homes: &PathProfiles, name: &str, input: &str, argument: &str) {
    let folder = homes.home.join(".strands/box/plugins").join(name);
    std::fs::create_dir_all(&folder).expect("a plugin folder");
    std::fs::write(
        folder.join("plugin.toml"),
        format!(
            "[plugin]\nname = {name:?}\nversion = 1\nkind = \"secret-source\"\n\
             scheme = \"{name}\"\n\n\
             [inputs.p.path]\ntype = \"program\"\n{input}\n\n\
             [run]\n\
             command = [\"${{{{ inputs.p.path }}}}\"{argument}, \"read\", \"{{ref}}\"]\n"
        ),
    )
    .expect("a plugin");
}

/// **A profile file that runs by its path lists no plugin that reads `${{ profile }}`**: in that
/// file it is the folder of the file, so the file would choose the program that runs outside the
/// box or a file that the program reads. A plugin that reads neither loads, and a profile in
/// `~/.strands/box/profiles/` is checked as before: there the folder lies in the box home, which the
/// program checks refuse.
#[test]
fn a_profile_file_that_runs_by_its_path_lists_no_plugin_that_reads_its_folder() {
    let homes = PathProfiles::new();
    for (name, placeholder, input, argument, named_refusal) in READS_PROFILE {
        reads_profile(&homes, name, input, argument);
        let route = format!(
            "\n[egress.github]\ndestinations = [\"api.github.com\"]\n\
             secret.ref = \"{name}://team/github\"\nsecret.env = \"GH_TOKEN\"\n"
        );
        let named = homes.named(&format!("plugins = [{name:?}]\n{route}"));
        match homes.launcher().preview(&named, &homes.workspace) {
            Err(error) => assert!(error.to_string().contains(named_refusal), "{name}: {error}"),
            Ok(_) => panic!("{name}: a refusal of a folder in the box home"),
        }
        std::fs::remove_dir_all(homes.home.join(".strands/box/profiles/weather")).expect("gone");
        let file = homes.file(&format!("plugins = [{name:?}]\n{route}"));
        assert_eq!(
            homes.refused(&file.display().to_string()),
            (
                file.clone(),
                Some(2),
                format!(
                    "the plugin {name} reads `${{{{ {placeholder} }}}}`, and a profile file that \
                     runs by its path lists no such plugin, because there it names that file or its folder, so \
                     the file would choose the program that runs outside the box or a file that \
                     the program reads; write a fixed path in the plugin, or move the profile to \
                     ~/.strands/box/profiles/weather/"
                )
            ),
            "{name}"
        );
        std::fs::remove_file(&file).expect("the file is gone");
    }
    let file = homes.file("plugins = [\"team-vault\"]\n\n[egress.github]\ndestinations = [\"api.github.com\"]\nsecret.ref = \"vault://team/github\"\nsecret.env = \"GH_TOKEN\"\n");
    homes.loads(&file.display().to_string());
}

/// **A profile file that runs by its path sets no program input of a plugin**, so it chooses no
/// program that runs outside the box. It still lists a plugin, names a reference in its scheme,
/// and sets the plugin's other inputs, which the plugin bounds. A profile in `~/.strands/box/profiles/`
/// still sets the program.
#[test]
fn a_profile_file_that_runs_by_its_path_sets_no_program_of_a_plugin() {
    let homes = PathProfiles::new();
    let other = homes.other.display().to_string();
    let on_path = "finds `vault` on `PATH`, so put the program on `PATH`";
    for (plugin, input, options, line, found) in [
        (
            "team-vault",
            "vault.path",
            format!("\n[options]\nvault.path = {other:?}\n"),
            5,
            on_path,
        ),
        (
            "team-vault",
            "vault.path",
            format!("\n[options]\n\"vault.path\" = {other:?}\n"),
            5,
            on_path,
        ),
        (
            "team-vault",
            "vault.path",
            format!("\n[options.vault]\nnamespace = \"prod\"\npath = {other:?}\n"),
            6,
            on_path,
        ),
        (
            "team-local",
            "local.path",
            format!("\n[options]\nlocal.path = {other:?}\n"),
            5,
            "finds `vault` in the folders of its `search`, so put the program in one of them",
        ),
        (
            "team-fixed",
            "fixed.path",
            format!("\n[options]\nfixed.path = {other:?}\n"),
            5,
            "names its program in `default`, so use that program",
        ),
    ] {
        let file = homes.file(&format!("plugins = [{plugin:?}]\n{options}"));
        assert_eq!(
            homes.refused(&file.display().to_string()),
            (
                file.clone(),
                Some(line),
                format!(
                    "`[options] {input}` sets the program of the plugin {plugin}, and a profile \
                     file that runs by its path chooses no program that runs outside the box; the \
                     plugin {found}, or move the profile to ~/.strands/box/profiles/weather/"
                )
            ),
            "{options}"
        );
    }
    let telemetry = "\n[telemetry.otlp]\nkind = \"otlp\"\ndestination = \"https://otlp.example.com\"\n\
                     secret.ref = \"vault://team/otlp\"\nsecret.header = \"x-api-key\"\n";
    let route = "\n[egress.github]\ndestinations = [\"api.github.com\"]\n\
                 secret.ref = \"vault://team/github\"\nsecret.env = \"GH_TOKEN\"\n";
    for text in [
        format!("plugins = [\"team-vault\"]\n{telemetry}"),
        format!("plugins = [\"team-vault\"]\n{route}"),
        format!("plugins = [\"team-vault\"]\n\n[options]\nvault.namespace = \"prod\"\n{route}"),
    ] {
        let file = homes.file(&text);
        homes.loads(&file.display().to_string());
    }
    std::fs::remove_file(homes.home.join("repo/box/profile.toml")).expect("the file is gone");
    homes.loads(&homes.named(&format!(
        "plugins = [\"team-vault\"]\n\n[options]\nvault.path = {other:?}\n{route}"
    )));
}
