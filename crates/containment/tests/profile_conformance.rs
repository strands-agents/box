//! Conformance tests for the one fixed macOS Agent profile.

use containment::test_support::generate_seatbelt_profile;
use containment::{ContainmentConfig, Network, Operation, Scope};

/// The profile's rules, with comments and blank lines removed.
///
/// Every assertion that something is *absent* must run against this rather than
/// the raw text. The profile documents its own placeholders in comments, so a
/// comment describing a rule would otherwise satisfy a `contains` check and make
/// an absence assertion pass or fail for the wrong reason.
fn rules(profile: &str) -> String {
    profile
        .lines()
        .filter(|line| !line.trim_start().starts_with(';') && !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A minimal certificate bundle: one `CERTIFICATE` block and no key material, which is
/// what `require_trust_bundle_contents` accepts. One copy, so the accepted format is
/// pinned in a single place rather than in every fixture.
const TRUST_BUNDLE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n";

/// The three grants the fixed profile recognizes, and nothing else.
///
/// Each states exactly the access the profile enforces: the executable is
/// execute-only because the profile grants `process-exec` and no read, and the
/// home is read-write because the profile grants both over its subtree.
fn fixed_config() -> (tempfile::TempDir, ContainmentConfig) {
    fixed_config_with_write(true)
}

fn fixed_config_with_write(writable: bool) -> (tempfile::TempDir, ContainmentConfig) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    // An existence allow takes its filter from where the path sits, so a `$TMPDIR` under the
    // operator home would make this fixture render `subpath` and fail an assertion that names the
    // grant's scope as the cause. The tests that mean to sit inside the home say so themselves.
    if let Ok(spellings) = containment::test_support::operator_home_spellings() {
        assert!(
            !spellings.iter().any(|home| root.starts_with(home)),
            "this fixture must sit outside the operator home; $TMPDIR resolves to {}",
            root.display()
        );
    }
    let home_directory = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home_directory).expect("home directory fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    let config = if writable {
        config
            .allow(&home_directory, Operation::Write, Scope::Root)
            .expect("exact home directory")
    } else {
        config
    };
    (directory, config)
}

/// **A refusal renders after every allow, because Seatbelt takes the last matching rule.**
///
/// This is the property the whole subtraction rests on: a refusal inside a granted tree only wins if
/// its deny is matched last. Nothing else in this crate could fail if the block moved above an allow,
/// and the allow census cannot see it — that census counts permitted operations and a deny is not one.
#[test]
fn a_refusal_renders_after_every_allow() {
    let (directory, config) = fixed_config();
    let refused = directory.path().join("home").join("private");
    std::fs::create_dir(&refused).expect("the refused directory");
    let config = config.refuse(&refused, Scope::Root).expect("a refusal");

    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let text = rules(&profile);
    let escaped = refused
        .canonicalize()
        .expect("canonical")
        .display()
        .to_string();

    let deny = text
        .find(&format!("(deny file-read* (subpath \"{escaped}\"))"))
        .expect("the refusal renders its read deny");
    let last_allow = text
        .rfind("(allow file-")
        .expect("the profile grants something");
    assert!(
        deny > last_allow,
        "every refusal must render after the last allow, or an enclosing subpath allow wins:\n{text}"
    );
}

/// A refusal renders under BOTH spellings, because one rule family matches the pre-resolution path.
#[test]
fn a_refusal_reached_through_a_link_renders_both_spellings() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical");
    let real = root.join("home").join("secrets");
    std::fs::create_dir(&real).expect("the real directory");
    let route = root.join("home").join("link-to-secrets");
    std::os::unix::fs::symlink(&real, &route).expect("a second route");

    let config = config
        .refuse(&route, Scope::Root)
        .expect("a refusal through a link");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let text = rules(&profile);

    for spelling in [route.display().to_string(), real.display().to_string()] {
        assert!(
            text.contains(&format!("(deny file-read* (subpath \"{spelling}\"))")),
            "the refusal must deny {spelling}, because the operation matches the pre-resolution \
             path for one rule family and the identity for another:\n{text}"
        );
    }
}

/// **A denial is legal at `Root` and `File` scope, and `Dir` is refused**, through the public verb.
///
/// A `Dir` denial would subtract a directory's own entry and leave its contents reachable, so no
/// backend renders one. A `File` denial names one file, and a directory cannot satisfy it: the
/// entry alone would be denied while everything under it stayed reachable.
#[test]
fn a_refusal_at_dir_scope_is_refused_and_file_scope_names_one_file() {
    let (directory, config) = fixed_config();
    let file = directory.path().join("home").join("a-denied-file");
    std::fs::write(&file, "bytes").expect("a real file");
    let tree = directory.path().join("home").join("a-denied-tree");
    std::fs::create_dir(&tree).expect("a real directory");

    assert!(
        ContainmentConfig::new().refuse(&file, Scope::Dir).is_err(),
        "a denial at Dir scope must be refused, because no backend renders one"
    );
    assert!(
        matches!(
            ContainmentConfig::new().refuse(&tree, Scope::File),
            Err(containment::ContainmentError::ExpectedFile(_))
        ),
        "a file denial on a directory must be refused, or its contents stay reachable"
    );
    // The controls, on the same paths: without them a blanket refusal would pass.
    config
        .clone()
        .refuse(&file, Scope::File)
        .expect("a file is refused at File scope")
        .refuse(&tree, Scope::Root)
        .expect("a tree is refused at Root scope");
    ContainmentConfig::new()
        .refuse(&file, Scope::Root)
        .expect("a file may still be refused as a tree of one");
}

/// **A refusal may name a path that does not exist, and renders anyway.**
///
/// The one property separating a denial from every authorization, and this crate had no test for it:
/// reverting `PathGrant::denial` to require the path left all 165 containment tests green, and only a
/// box end-to-end test on a host that happened to lack one of four directories went red.
#[test]
fn a_refusal_may_name_a_path_that_does_not_exist() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical");
    let absent = root.join("home").join("never-created").join("deeper");
    assert!(!absent.exists(), "the fixture must not create the path");

    let config = config
        .refuse(&absent, Scope::Root)
        .expect("an absent path may be refused, because the subtraction must outlive its absence");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let text = rules(&profile);
    assert!(
        text.contains(&format!(
            "(deny file-read* (subpath \"{}\"))",
            absent.display()
        )),
        "a refusal on an absent path must still render, or a grant enclosing its future location \
         goes unsubtracted:\n{text}"
    );
}

/// **A refused path whose identity drifted between writing and loading is refused.**
///
/// The wire type re-resolves exactly as a grant's does. Nothing else reaches that branch, so without
/// this the drift check could be deleted and every suite would stay green.
#[test]
fn a_refusal_whose_identity_drifted_is_refused_on_load() {
    let (directory, config) = fixed_config();
    let refused = directory.path().join("home").join("carve-out");
    std::fs::create_dir(&refused).expect("the refused directory");
    let config = config.refuse(&refused, Scope::Root).expect("a refusal");
    let json = config.to_json().expect("serialize");

    // The control: what was written loads.
    ContainmentConfig::from_json(&json).expect("the configuration this build wrote must load");

    // Now claim a different identity for the same caller spelling. **Only `resolved` moves.**
    // Rewriting every occurrence moves `original` with it, which leaves the two agreeing and is no
    // drift at all — it reached this refusal on macOS only because a temporary directory sits under a
    // symlink there, so the two fields held different spellings and one of them survived the rewrite.
    let canonical = refused.canonicalize().expect("canonical");
    let drifted = json.replace(
        &format!("\"resolved\": \"{}\"", canonical.display()),
        &format!(
            "\"resolved\": \"{}\"",
            canonical.with_file_name("somewhere-else").display()
        ),
    );
    assert_ne!(drifted, json, "the rewrite must change the payload");
    let error = ContainmentConfig::from_json(&drifted)
        .expect_err("a refusal whose resolved path drifted must be refused");
    assert!(
        error.to_string().contains("refused path") || error.to_string().contains("drift"),
        "the refusal must name what drifted: {error}"
    );
}

#[test]
fn renderer_only_replaces_the_checked_in_placeholders() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home_directory = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");

    assert!(!profile.contains("{{"));
    assert!(profile.starts_with(
        "; Deny every operation unless a rule below grants it.\n(version 1)\n(deny default)\n"
    ));
    assert!(profile.contains("(deny process-info*)"));
    assert!(profile.contains("(allow process-info* (target self))"));
    assert!(!profile.contains("(allow process-info* (target same-sandbox))"));
    assert!(profile.contains(&format!(
        "(allow process-exec (literal \"{}\"))",
        executable.display()
    )));
    assert_eq!(profile.matches("(allow process-fork)").count(), 1);
    assert!(profile.contains("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))"));
    // `/`, `/etc` and `/dev/null` were static text here, so every box carried them whether or not
    // it needed them. They are grants the box's floor states now, and this config declares none.
    for absent in [
        "(literal \"/\")",
        "(literal \"/etc\")",
        "(literal \"/dev/null\")",
    ] {
        assert!(
            !profile.contains(absent),
            "{absent} must arrive as a grant, never as profile text"
        );
    }
    // The executable is execute-only: the profile grants `process-exec` on it
    // and never a read, which is exactly what `Operation::Exec` states.
    assert!(!profile.contains(&format!(
        "(allow file-read* (literal \"{}\"))",
        executable.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-read-metadata (path-ancestors \"{}\"))",
        home_directory.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-read* (literal \"{}\"))",
        trust_bundle.display()
    )));
    // The whole Agent home is readable and writable, so an Agent may keep state
    // wherever it likes and TMPDIR is simply a directory inside it.
    assert!(profile.contains(&format!(
        "(allow file-read* (subpath \"{}\"))",
        home_directory.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-write-data (subpath \"{}\"))",
        home_directory.display()
    )));
    // No rule names a specific Agent state directory: the box owns the home, so
    // the profile does not decide which harnesses may store what where.
    for state_directory in [".codex", ".claude", ".kiro", ".agents"] {
        assert!(
            !profile.contains(state_directory),
            "profile must not name {state_directory}"
        );
    }
    // Writable authority stops at the home: its parent is metadata-only.
    let home_parent = home_directory.parent().expect("home parent");
    assert!(!profile.contains(&format!(
        "(allow file-write-data (subpath \"{}\"))",
        home_parent.display()
    )));
    assert!(profile.contains("(sysctl-name \"hw.pagesize_compat\")"));
    assert!(
        profile.contains(
            "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
        )
    );
    assert!(profile.contains("(deny network*)"));
    let rules = rules(&profile);
    assert!(
        !rules.contains("system-socket"),
        "the write root renders no socket-family rule: {profile}"
    );
    for operation in ["network-bind", "network-inbound", "network-outbound"] {
        assert!(rules.contains(&format!(
            "(allow {operation} (subpath \"{}\"))",
            home_directory.display()
        )));
    }
    assert!(!rules.contains("(path \""), "no pathname socket route");
    assert!(profile.contains("(allow network-outbound\n    (remote tcp \"localhost:43123\"))"));
    assert_eq!(
        profile
            .lines()
            .filter(|line| {
                **line
                    == format!(
                        "(allow process-exec (literal \"{}\"))",
                        executable.display()
                    )
            })
            .count(),
        1
    );
    // The read rule, plus the pair the existence block adds: the path at its own scope and its
    // ancestor chain. `every_grant_renders_an_existence_allow_at_its_own_scope` names them.
    assert_eq!(
        profile.matches(&trust_bundle.display().to_string()).count(),
        3
    );
    // Thirteen rules, and the count is 6 + 3 + 2 + 2. Six write leaf allows. Three denies: two on the
    // literal fixing the directory's own identity, and one over the subtree taking the executable
    // mapping off it. Two read allows: the ancestor-chain metadata and the subtree read. Two existence
    // rules, once for the path granted read and write. The BSD file flags, the access-control list and
    // the owner need no deny, because the cell never names them. See
    // `the_home_directory_itself_cannot_be_replaced`, `every_writable_path_refuses_a_file_flag`,
    // `every_writable_path_refuses_an_access_control_list`,
    // `every_writable_path_refuses_an_ownership_change`,
    // `every_writable_path_refuses_an_executable_mapping`, and
    // `every_grant_renders_an_existence_allow_at_its_own_scope`.
    assert_eq!(
        profile
            .matches(&home_directory.display().to_string())
            .count(),
        16
    );
}

/// The profile reads seven named sysctls, and no eighth.
///
/// Whole names rather than a prefix, because a prefix over `kern.` reaches `kern.procargs2`,
/// which holds another process's argument vector.
#[test]
fn the_profile_reads_exactly_seven_named_sysctls() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    let mut names: Vec<&str> = rules
        .split("(sysctl-name \"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    names.sort_unstable();

    assert_eq!(
        names,
        [
            "hw.machine",
            "hw.ncpu",
            "hw.pagesize_compat",
            "kern.hostname",
            "kern.osrelease",
            "kern.ostype",
            "kern.version",
        ],
        "the sysctl name set changed. Each name must be a public property of the host and no \
         name may reach another process's memory or arguments.\nrendered profile:\n{profile}"
    );
    assert_eq!(
        rules.matches("(allow sysctl-read").count(),
        1,
        "one rule holds every name, so the operation census does not move when a name is added"
    );
}

/// An execute grant reached through a link renders a metadata read on the link too, and no second
/// `process-exec`.
///
/// The two things this must NOT do are the assertions that matter: only the resolved identity gets
/// `process-exec`, and neither spelling gets `file-read*`.
#[test]
fn an_execute_grant_reached_through_a_link_renders_metadata_on_both_spellings() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let target = root.join("real-agent");
    std::fs::write(&target, "agent").expect("the real program");
    let route = root.join("agent-link");
    std::os::unix::fs::symlink(&target, &route).expect("the link");

    let home_directory = root.join("home");
    std::fs::create_dir(&home_directory).expect("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust");

    let config = ContainmentConfig::new()
        .allow(&route, Operation::Exec, Scope::File)
        .expect("the grant names the route")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let rules = rules(&profile);

    assert!(
        rules.contains(&format!(
            "(allow process-exec (literal \"{}\"))",
            target.display()
        )),
        "the resolved identity must carry the exec rule: {profile}"
    );
    assert!(
        !rules.contains(&format!(
            "(allow process-exec (literal \"{}\"))",
            route.display()
        )),
        "the link must NOT carry an exec rule of its own; one grant authorizes one program: \
         {profile}"
    );
    for spelling in [&target, &route] {
        assert!(
            rules.contains(&format!(
                "(allow file-read-metadata (literal \"{}\"))",
                spelling.display()
            )),
            "both spellings need a metadata read so the kernel can resolve the route: {profile}"
        );
        assert!(
            !rules.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                spelling.display()
            )),
            "a program's bytes stay unreadable: {profile}"
        );
    }
    assert_eq!(
        rules.matches("(allow process-exec").count(),
        1,
        "one execute grant renders exactly one exec rule: {profile}"
    );
}

/// An execute grant reached through a chain of links renders a metadata read on every link node.
#[test]
fn an_execute_grant_reached_through_a_link_chain_renders_metadata_on_every_node() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let target = root.join("real-agent");
    std::fs::write(&target, "agent").expect("the real program");
    // Every link target is spelled canonically. A target reached through a link of its own adds an
    // unrendered node and moves what this test measures.
    let first = root.join("hop-1");
    let second = root.join("hop-2");
    let route = root.join("hop-3");
    std::os::unix::fs::symlink(&target, &first).expect("hop 1");
    std::os::unix::fs::symlink(&first, &second).expect("hop 2");
    std::os::unix::fs::symlink(&second, &route).expect("hop 3");
    // A second link to the same target, beside the chain and not on it. Nothing may render for it,
    // or the walk would be granting a directory's links rather than one lookup's own nodes.
    let decoy = root.join("beside-the-chain");
    std::os::unix::fs::symlink(&target, &decoy).expect("the decoy");

    let home_directory = root.join("home");
    std::fs::create_dir(&home_directory).expect("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust");

    let config = ContainmentConfig::new()
        .allow(&route, Operation::Exec, Scope::File)
        .expect("the grant names the chain head")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43124))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let rules = rules(&profile);

    // The head, both middles, and the identity. Dropping any one of the middles is what the kernel
    // refused.
    for node in [&route, &second, &first, &target] {
        assert!(
            rules.contains(&format!(
                "(allow file-read-metadata (literal \"{}\"))",
                node.display()
            )),
            "every node the lookup traverses needs a metadata read: {} missing from {profile}",
            node.display()
        );
        assert!(
            !rules.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                node.display()
            )),
            "a program's bytes stay unreadable at every node: {profile}"
        );
    }
    assert!(
        rules.contains(&format!(
            "(allow process-exec (literal \"{}\"))",
            target.display()
        )),
        "the resolved identity carries the exec rule: {profile}"
    );
    assert_eq!(
        rules.matches("(allow process-exec").count(),
        1,
        "a chain is still one program, so it renders one exec rule: {profile}"
    );
    assert!(
        !rules.contains(&format!("\"{}\"", decoy.display())),
        "only the nodes this lookup traverses render, not every link beside them: {profile}"
    );
}

/// A grant whose ancestor is a link renders the node the kernel checks, not only the one authored.
#[test]
fn a_grant_through_a_linked_ancestor_renders_the_node_the_kernel_checks() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let real_directory = root.join("real-directory");
    std::fs::create_dir(&real_directory).expect("the real directory");
    let target = real_directory.join("real-agent");
    std::fs::write(&target, "agent").expect("the real program");
    let leaf = real_directory.join("agent-link");
    std::os::unix::fs::symlink(&target, &leaf).expect("the leaf link");
    // The ancestor is a link, so the authored spelling is not what the kernel checks.
    let linked_directory = root.join("linked-directory");
    std::os::unix::fs::symlink(&real_directory, &linked_directory).expect("the ancestor link");
    let route = linked_directory.join("agent-link");

    let home_directory = root.join("home");
    std::fs::create_dir(&home_directory).expect("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust");

    let config = ContainmentConfig::new()
        .allow(&route, Operation::Exec, Scope::File)
        .expect("the grant names the authored route")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43125))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let rules = rules(&profile);

    assert!(
        rules.contains(&format!(
            "(allow file-read-metadata (literal \"{}\"))",
            leaf.display()
        )),
        "the node under the resolved ancestor is what the kernel checks: {profile}"
    );
    assert!(
        rules.contains(&format!(
            "(allow file-read-metadata (literal \"{}\"))",
            target.display()
        )),
        "the identity still carries its own metadata read: {profile}"
    );
    assert_eq!(
        rules.matches("(allow process-exec").count(),
        1,
        "one execute grant renders one exec rule: {profile}"
    );
}

#[test]
fn fixed_profile_contains_none_of_the_removed_widening_rules() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    for absent in [
        "process-exec*",
        "(allow sysctl-read)\n",
        "mDNSResponder",
        "socket-domain AF_INET",
        "socket-domain AF_INET6",
        "(allow network-bind)",
        "(allow network-inbound)",
        "(subpath \"/\")",
        "(subpath \"/dev\")",
        "pseudo-tty",
    ] {
        assert!(!rules.contains(absent), "unexpected rule: {absent}");
    }
    // A host shell is never an exec literal, however many literals there are:
    // the whole point of routing through Shell is that the box grants its own
    // alias, not the system's interpreter.
    for shell in ["/bin/sh", "/bin/bash", "/bin/zsh"] {
        assert!(
            !rules.contains(&format!("(literal \"{shell}\")")),
            "unexpected Shell grant: {shell}"
        );
    }
}

/// A path naming a profile placeholder is refused, not escaped.
///
/// Placeholders are substituted sequentially, so a path containing the literal text
/// of a *later* placeholder would be injected as text and then expanded by the next
/// iteration — a grant's path injecting a rule. Refusing the opener makes the
/// substitution order irrelevant rather than load-bearing.
///
/// Today such a profile happens to fail SBPL parsing, so it fails closed; this test
/// exists so the guarantee comes from the renderer rather than from the parser's
/// accident.
#[test]
fn a_path_naming_a_profile_placeholder_is_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    // Every placeholder the renderer substitutes, including the two that expand to a
    // whole block of rules.
    for placeholder in [
        "{{UNIX_SOCKET_RULES}}",
        "{{EXEC_LITERALS}}",
        "{{PROXY_PORTS}}",
        "{{TRUST_BUNDLE_PATH}}",
        "{{HOME_DIRECTORY_PATH}}",
    ] {
        let hostile = root.join(placeholder);
        std::fs::create_dir_all(&hostile).expect("hostile directory");
        let executable = hostile.join("prog");
        std::fs::write(&executable, "agent").expect("executable fixture");

        let config = ContainmentConfig::new()
            .allow(&executable, Operation::Exec, Scope::File)
            .expect("the portable model accepts the path")
            .allow(&trust_bundle, Operation::Read, Scope::File)
            .expect("trust bundle")
            .allow(&home, Operation::Read, Scope::Root)
            .expect("home")
            .allow(&home, Operation::Write, Scope::Root)
            .expect("home")
            .set_network(Network::localhost().connect(43123))
            .expect("proxy port");

        let error = generate_seatbelt_profile(&config)
            .expect_err("a path naming a placeholder must be refused");
        assert!(
            error.to_string().contains("placeholder"),
            "unexpected error for {placeholder}: {error}"
        );
    }
}

#[test]
fn fixed_profile_grants_exactly_one_exec_literal_and_fork() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");

    let executable = root.join("agent");
    assert_eq!(
        profile
            .matches(&format!(
                "(allow process-exec (literal \"{}\"))",
                executable.display()
            ))
            .count(),
        1
    );
    assert_eq!(
        profile.matches("(allow process-exec ").count(),
        1,
        "one execute grant renders one exec literal: {profile}"
    );
    assert_eq!(profile.matches("(allow process-fork)").count(), 1);
    assert!(!profile.contains("process-exec*"));
}

/// A second execute-only file renders a second exec literal, and nothing else.
///
/// This is what lets a Shell alias be plumbed without new containment
/// vocabulary: an alias is one more execute-only file. The count of authorized
/// paths grows by exactly one; the *shape* does not change — still one literal
/// per line, still no `process-exec*`, still no directory form. So N grants
/// authorize exactly N paths and a caller cannot reach a tree.
#[test]
fn each_execute_grant_renders_its_own_exec_literal() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let alias = root.join("zsh");
    std::fs::write(&alias, "alias").expect("alias fixture");
    let executable = root.join("agent");
    let config = config
        .allow(&alias, Operation::Exec, Scope::File)
        .expect("a second execute-only file");

    let profile = generate_seatbelt_profile(&config).expect("two exec literals are expressible");
    for path in [&executable, &alias] {
        assert_eq!(
            profile
                .matches(&format!(
                    "(allow process-exec (literal \"{}\"))",
                    path.display()
                ))
                .count(),
            1,
            "{} must be granted exactly once: {profile}",
            path.display()
        );
    }
    assert_eq!(
        profile.matches("(allow process-exec ").count(),
        2,
        "two execute grants render exactly two literals: {profile}"
    );
    assert!(!profile.contains("process-exec*"));
    assert_eq!(profile.matches("(allow process-fork)").count(), 1);
    // Execute is execute: neither path becomes readable by being exec'able.
    for path in [&executable, &alias] {
        assert!(!profile.contains(&format!(
            "(allow file-read* (literal \"{}\"))",
            path.display()
        )));
    }
}

/// Two execute grants naming one path are refused rather than emitting a
/// duplicate rule, so a caller that believes it granted two things finds out.
#[test]
fn two_execute_grants_on_one_path_are_rejected() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let config = config
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("the portable model accepts a second");

    let error = generate_seatbelt_profile(&config).expect_err("a duplicate exec grant is refused");
    assert!(
        error.to_string().contains("is granted Exec twice"),
        "unexpected error: {error}"
    );
}

/// A profile permitting no exec could never start the workload it exists for,
/// so an empty execute set is a refusal rather than a profile with a blank line.
#[test]
fn a_config_with_no_execute_grant_is_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");

    let error = generate_seatbelt_profile(&config).expect_err("no exec grant is refused");
    assert!(
        error.to_string().contains("missing Agent executable"),
        "unexpected error: {error}"
    );
}

/// Bind a real socket at `path` and drop the listener, leaving the inode.
fn socket_fixture(path: &std::path::Path) {
    std::fs::create_dir_all(path.parent().expect("socket parent")).expect("socket directory");
    drop(std::os::unix::net::UnixListener::bind(path).expect("socket fixture"));
}

/// A connect-only grant on one existing socket file renders an AF_UNIX route.
///
/// This is what carries a Shell shim: the contained workload connects to the
/// shim's socket and reaches nothing else over AF_UNIX. No `system-socket` rule
/// renders.
#[test]
fn a_connect_only_socket_file_renders_one_afunix_route() {
    let (directory, config) = fixed_config_with_write(false);
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let socket = root.join("run").join("shell.sock");
    socket_fixture(&socket);
    let config = config
        .allow(&socket, Operation::Connect, Scope::File)
        .expect("connect-only socket grant");

    let profile = generate_seatbelt_profile(&config).expect("a socket route is expressible");
    assert!(profile.contains(&format!(
        "(allow network-outbound\n    (path \"{}\"))",
        socket.display()
    )));
    assert!(
        !rules(&profile).contains("system-socket"),
        "a socket grant renders no socket-family rule: {profile}"
    );
    // The TCP proxy route is untouched by adding a socket.
    assert!(profile.contains("(allow network-outbound\n    (remote tcp \"localhost:43123\"))"));
    assert!(profile.contains("(deny network*)"));
    // No bind or inbound authority comes along with a connect grant.
    assert!(!profile.contains("network-bind"));
    assert!(!profile.contains("network-inbound"));
}

/// A profile with no write root and no socket grant renders no `system-socket` rule.
#[test]
fn no_write_root_or_socket_grant_means_no_afunix_capability() {
    let (_directory, config) = fixed_config_with_write(false);
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    assert!(
        !rules.contains("system-socket"),
        "no AF_UNIX capability without a socket grant: {profile}"
    );
    assert!(!rules.contains("(path \""), "no pathname socket route");
}

/// A connect grant permits no bind or inbound operation.
#[test]
fn no_socket_grant_shape_can_widen_the_route() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let socket = root.join("run").join("shell.sock");
    socket_fixture(&socket);
    let socket_directory = socket.parent().expect("socket parent").to_path_buf();

    for scope in [Scope::Dir, Scope::Root] {
        let (_directory, base) = fixed_config();
        let error = base
            .allow(&socket_directory, Operation::Connect, scope)
            .expect_err("a directory-scoped socket grant must be refused");
        assert!(
            error.to_string().contains("a socket grant names one"),
            "unexpected error for {scope:?}: {error}"
        );
    }
}

/// A socket grant authored through a symlink renders as the socket it names.
///
/// Same reason a filesystem grant does: Seatbelt matches the vnode the kernel
/// arrives at, so the link spelling would name something no `connect(2)` is ever
/// checked against — reading as a route while enforcing nothing.
#[test]
fn an_authored_socket_symlink_renders_as_the_socket_it_names() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let socket = root.join("run").join("shell.sock");
    socket_fixture(&socket);
    let socket_link = root.join("run").join("shell-link.sock");
    std::os::unix::fs::symlink(&socket, &socket_link).expect("socket symlink");
    let config = config
        .allow(&socket_link, Operation::Connect, Scope::File)
        .expect("the portable model accepts the symlink");

    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    assert!(profile.contains(&format!(
        "(allow network-outbound\n    (path \"{}\"))",
        socket.display()
    )));
    // The route itself names the socket alone. The link spelling reaches one rule and one only:
    // an existence allow at `literal` scope, because the operator's home refuses that operation
    // and the operation matches the pre-resolution path, so a caller naming the link would
    // otherwise read `EPERM` where the grant says the socket is reachable.
    assert_eq!(
        rules(&profile)
            .matches(&socket_link.display().to_string())
            .count(),
        1,
        "the link spelling reaches exactly one rule: {profile}"
    );
    assert!(
        rules(&profile).contains(&format!(
            "(allow file-test-existence (literal \"{}\"))",
            socket_link.display()
        )),
        "and that rule is the existence allow: {profile}"
    );
}

/// Two grants naming one socket are refused rather than emitting a duplicate.
#[test]
fn two_socket_grants_on_one_path_are_rejected() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let socket = root.join("run").join("shell.sock");
    socket_fixture(&socket);
    let config = config
        .allow(&socket, Operation::Connect, Scope::File)
        .expect("first socket grant")
        .allow(&socket, Operation::Connect, Scope::File)
        .expect("the portable model accepts a second");

    let error = generate_seatbelt_profile(&config).expect_err("a duplicate socket is refused");
    assert!(
        error.to_string().contains("is granted Connect twice"),
        "unexpected error: {error}"
    );
}

/// Every filesystem grant the profile cannot express is refused, never
/// silently widened to the nearest slot or narrowed to fit one.
///
/// This is the guard the deleted `allow_system_*` builders used to provide by
/// rejecting write access up front: the check now lives where the enforcement
/// is, so it covers grants arriving over the wire too.
#[test]
fn grant_shapes_the_profile_cannot_express_are_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let file = root.join("file");
    let subdirectory = root.join("subdirectory");
    std::fs::write(&file, "fixture").expect("file fixture");
    std::fs::create_dir(&subdirectory).expect("directory fixture");

    // A writable file, and a tree the profile would have to make writable without making it
    // readable: the vocabulary states each of these, and no rule block renders one.
    //
    // **The list is empty: every cell the vocabulary calls legal renders a block.** It held
    // `Write` at `File` scope until that block was added, and before that `Write` at `Root`. A
    // shrinking denylist cannot say when it reaches zero, so this asserts the total property
    // instead — `cell_refusal` is the only thing that refuses a cell.
    for (path, scope) in [
        (file.as_path(), Scope::File),
        (root.as_path(), Scope::Dir),
        (root.as_path(), Scope::Root),
    ] {
        for operation in [
            Operation::Read,
            Operation::List,
            Operation::Write,
            Operation::Metadata,
            Operation::Exec,
            Operation::Connect,
        ] {
            let (_directory, base) = fixed_config();
            let Ok(config) = base.allow(path, operation, scope) else {
                continue; // The vocabulary refuses this cell, which is not this test's subject.
            };
            assert!(
                generate_seatbelt_profile(&config).is_ok(),
                "{operation:?} at {scope:?} is legal and renders no block"
            );
        }
    }
}

/// **Read at file scope repeats, and each grant renders its own rule.**
///
/// It was singular, holding the proxy trust bundle — a role, in a crate whose own rule is that a grant
/// states what it authorizes and never who asked. The bundle's contents check moved to `box`.
#[test]
fn read_at_file_scope_repeats_and_each_grant_renders_its_own_rule() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let second = root.join("authored.txt");
    std::fs::write(&second, "not a certificate").expect("fixture");

    let config = config
        .allow(&second, Operation::Read, Scope::File)
        .expect("a second readable file");
    let profile = generate_seatbelt_profile(&config).expect("both files render");

    for path in [root.join("proxy-ca.pem"), second] {
        assert!(
            profile.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                path.display()
            )),
            "each read-at-file-scope grant renders its own rule: {profile}"
        );
    }
    assert_eq!(profile.matches("(allow file-read* (literal ").count(), 2);
}

/// Each **singular** slot must be filled exactly once. A missing grant is
/// refused rather than rendered as an empty placeholder, and a second one is not
/// silently dropped in favour of the first.
///
/// The executable is in this set for the "missing" half only: at least one is
/// required, but a second is a further exec literal rather than a collision —
/// `each_execute_grant_renders_its_own_exec_literal` covers that side.
#[test]
fn the_one_required_cell_is_refused_when_absent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let second_home = root.join("home2");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::create_dir(&second_home).expect("second home fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let grants: [(&std::path::Path, &[Operation], Scope); 3] = [
        (&executable, &[Operation::Exec], Scope::File),
        (&trust_bundle, &[Operation::Read], Scope::File),
        (&home, &[Operation::Read, Operation::Write], Scope::Root),
    ];
    for omitted in 0..grants.len() {
        let mut config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(43123))
            .expect("proxy port");
        for (index, (path, operations, scope)) in grants.iter().enumerate() {
            if index == omitted {
                continue;
            }
            for operation in *operations {
                config = config.allow(path, *operation, *scope).expect("grant");
            }
        }
        let rendered = generate_seatbelt_profile(&config);
        // One cell is required and the rest are optional: a profile permitting no exec could never
        // start the workload it is built for. The readable file and the read-write root are neither,
        // so a profile without one renders.
        match omitted {
            0 => {
                let refusal = rendered
                    .expect_err("the required cell is refused when absent")
                    .to_string();
                assert!(
                    refusal.contains("missing Agent executable"),
                    "unexpected error for the omitted executable: {refusal}"
                );
            }
            _ => {
                rendered.expect("a config without an optional cell still renders");
            }
        }
    }

    // Every cell repeats, so a second read-write directory renders rather than colliding.
    let (_directory, two_roots) = fixed_config();
    let two_roots = two_roots
        .allow(&second_home, Operation::Read, Scope::Root)
        .expect("the portable model accepts a second directory")
        .allow(&second_home, Operation::Write, Scope::Root)
        .expect("the portable model accepts a second directory");
    generate_seatbelt_profile(&two_roots)
        .expect("a second read-write root renders rather than colliding");
}

#[test]
fn noncanonical_grants_are_normalized() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let executable_link = root.join("agent-link");
    let home_directory = root.join("home");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home_directory).expect("home directory fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::os::unix::fs::symlink(&executable, &executable_link).expect("executable symlink");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow_prepared(
            ContainmentConfig::prepare_filesystem_path(&executable_link).expect("prepare symlink"),
            Operation::Exec,
            Scope::File,
        )
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");

    let profile = generate_seatbelt_profile(&config).expect("prepared paths are canonicalized");
    assert!(profile.contains(&format!(
        "(allow process-exec (literal \"{}\"))",
        executable.display()
    )));
    // **No AUTHORITY names the link spelling**, which is what normalization is for. This asserted
    // that the spelling appeared nowhere at all, and that is a stronger claim than the property:
    // the link now carries one `file-read-metadata` rule so the kernel can resolve a route the
    // operator named, and `an_execute_grant_reached_through_a_link_renders_metadata_on_both_spellings`
    // pins that half. Enforcement is still on the canonical identity alone.
    for authority in [
        "process-exec",
        "file-read*",
        "file-write*",
        "file-read-data",
    ] {
        assert!(
            !profile.contains(&format!(
                "(allow {authority} (literal \"{}\"))",
                executable_link.display()
            )),
            "{authority} must name the canonical identity, never the link spelling: {profile}"
        );
    }
    assert!(
        !profile.contains(&format!("(subpath \"{}\")", executable_link.display())),
        "no subtree rule may name the link spelling: {profile}"
    );
}

/// A READ grant reached through a chain of links renders metadata on every node in the chain.
///
/// The data rule names the resolved directory alone, so without a rule on each link node the
/// lookup stops before it reaches the data. A decoy link beside the chain must render nothing.
#[test]
fn a_read_grant_reached_through_a_link_chain_renders_metadata_on_every_node() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let target = root.join("data");
    std::fs::create_dir(&target).expect("the data directory");
    let hop1 = root.join("hop-1");
    let hop2 = root.join("hop-2");
    std::os::unix::fs::symlink(&target, &hop1).expect("hop 1");
    std::os::unix::fs::symlink(&hop1, &hop2).expect("hop 2");
    let decoy = root.join("decoy");
    std::os::unix::fs::symlink(&target, &decoy).expect("a link beside the chain");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("box home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("box home")
        .allow(&hop2, Operation::Read, Scope::Root)
        .expect("the chain head")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    assert!(
        rules.contains(&format!(
            "(allow file-read* (subpath \"{}\"))",
            target.display()
        )),
        "the data rule names the resolved directory:\n{profile}"
    );
    // Every chain node is bounded in TOTAL, not merely present. Without this a later change could
    // add a data rule on a middle node and stay green.
    for node in [&hop2, &hop1] {
        let spelling = node.display().to_string();
        assert!(
            rules.contains(&format!(
                "(allow file-read-metadata (literal \"{spelling}\"))"
            )),
            "every node carries metadata, missing {spelling}:\n{profile}"
        );
        assert_eq!(
            rules.matches(&spelling).count(),
            2,
            "chain node {spelling} reaches exactly two rules:\n{profile}"
        );
        for forbidden in [
            format!("(allow file-read* (subpath \"{spelling}\"))"),
            format!("(allow file-read* (literal \"{spelling}\"))"),
            format!("(allow file-read-data (literal \"{spelling}\"))"),
        ] {
            assert!(
                !rules.contains(&forbidden),
                "no data rule may name a chain node, found {forbidden}:\n{profile}"
            );
        }
    }
    assert!(
        !rules.contains(&decoy.display().to_string()),
        "a link beside the chain reaches no rule:\n{profile}"
    );
}

/// A directory grant authored through a symlink carries its DATA on the directory itself, and
/// reaches the link spelling for metadata alone.
#[test]
fn an_authored_symlink_is_rendered_as_the_directory_it_names() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let home_link = root.join("home-link");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&home).expect("home fixture");
    std::os::unix::fs::symlink(&home, &home_link).expect("home symlink");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home_link, Operation::Read, Scope::Root)
        .expect("the portable model accepts the symlink")
        .allow(&home_link, Operation::Write, Scope::Root)
        .expect("the portable model accepts the symlink")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");

    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    assert!(profile.contains(&format!(
        "(allow file-write-data (subpath \"{}\"))",
        home.display()
    )));
    // Read, write and the ancestor metadata all name the directory alone. The link spelling reaches
    // one rule and one only: an existence allow at `literal` scope, never `subpath`, so nothing
    // beneath the link becomes testable through it.
    let rules = rules(&profile);
    let spelling = home_link.display().to_string();
    assert_eq!(
        rules.matches(&spelling).count(),
        2,
        "the link spelling reaches exactly two rules: {profile}"
    );
    for expected in [
        format!("(allow file-test-existence (literal \"{spelling}\"))"),
        format!("(allow file-read-metadata (literal \"{spelling}\"))"),
    ] {
        assert!(rules.contains(&expected), "missing {expected}: {profile}");
    }
    // The security half, and the reason two rules are safe where a third would not be. A data rule
    // on the link spelling would make every entry beneath it readable through that name.
    for forbidden in [
        format!("(allow file-read* (subpath \"{spelling}\"))"),
        format!("(allow file-read* (literal \"{spelling}\"))"),
        format!("(allow file-read-data (literal \"{spelling}\"))"),
        format!("(allow file-write-data (subpath \"{spelling}\"))"),
        format!("(allow file-test-existence (subpath \"{spelling}\"))"),
    ] {
        assert!(
            !rules.contains(&forbidden),
            "no data or subpath rule may name the link spelling, found {forbidden}: {profile}"
        );
    }
}

/// **Native egress reaches IP hosts and the system resolver, and no other pathname socket.**
#[test]
fn allow_all_renders_ip_only_outbound() {
    let (_directory, config) = fixed_config();

    let direct = config
        .set_network(Network::AllowAll)
        .expect("portable model accepts allow-all");
    let profile = generate_seatbelt_profile(&direct).expect("allow-all renders");
    let (_proxied_directory, proxied) = fixed_config();
    let proxied = rules(&generate_seatbelt_profile(&proxied).expect("the proxy port renders"));
    let rules = rules(&profile);
    let outbound = |profile: &str| profile.matches("(allow network-outbound").count();
    assert_eq!(
        outbound(&rules),
        outbound(&proxied) + 1,
        "native egress must replace the one port rule with the IP rule and the resolver rule alone: \
         {profile}"
    );
    let deny = rules
        .find("(deny network*)")
        .expect("the base deny is present");
    for rule in [
        "(allow network-outbound\n    (remote ip \"*:*\"))",
        "(allow network-outbound\n    (literal \"/private/var/run/mDNSResponder\"))",
    ] {
        let allow = rules
            .find(rule)
            .unwrap_or_else(|| panic!("native egress must render {rule}: {profile}"));
        assert!(
            allow > deny,
            "{rule} must render after (deny network*): {profile}"
        );
    }
}

/// Each `(allow network…)` rule in `rules`, as its operation and its filter with whitespace collapsed.
fn network_allows(rules: &str) -> Vec<(String, String)> {
    let mut allows = Vec::new();
    for (start, _) in rules.match_indices("(allow") {
        let rest = &rules[start + "(allow".len()..];
        if !rest.starts_with(char::is_whitespace) || !rest.trim_start().starts_with("network") {
            continue;
        }
        let mut depth = 0usize;
        let end = rules[start..]
            .char_indices()
            .find_map(|(offset, character)| {
                match character {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(start + offset)
            })
            .expect("a rendered rule closes");
        let body = rules[start + "(allow".len()..end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let (operation, filter) = body.split_once(' ').unwrap_or((&body, ""));
        allows.push((operation.to_string(), filter.to_string()));
    }
    allows.sort();
    allows
}

/// **Every network allow names a target the config granted, so no rule reaches an unlisted socket.**
#[test]
fn every_network_allow_names_a_granted_target() {
    for (network, direct) in [
        (
            Network::localhost().connect(43123),
            vec!["(remote tcp \"localhost:43123\")"],
        ),
        (
            Network::AllowAll,
            vec![
                "(remote ip \"*:*\")",
                "(literal \"/private/var/run/mDNSResponder\")",
            ],
        ),
    ] {
        let (directory, base) = fixed_config();
        let root = directory.path().canonicalize().expect("canonical tempdir");
        let home = root.join("home");
        let socket = root.join("run").join("box.sock");
        socket_fixture(&socket);
        let config = base
            .allow(&socket, Operation::Connect, Scope::File)
            .expect("socket grant")
            .set_network(network.clone())
            .expect("the network shape is accepted")
            .allow_runtime_services();
        let profile = generate_seatbelt_profile(&config).expect("the profile renders");

        let write_root = format!("(subpath \"{}\")", home.display());
        let connect = format!("(path \"{}\")", socket.display());
        let mut expected = [
            ("network-bind", write_root.as_str()),
            ("network-inbound", &write_root),
            ("network-outbound", &write_root),
            ("network-outbound", &connect),
        ]
        .into_iter()
        .chain(
            direct
                .into_iter()
                .map(|filter| ("network-outbound", filter)),
        )
        .map(|(operation, filter)| (operation.to_string(), filter.to_string()))
        .collect::<Vec<_>>();
        expected.sort();

        assert_eq!(
            network_allows(&rules(&profile)),
            expected,
            "{network:?}: a network allow names a target the config did not grant: {profile}"
        );
    }
}

/// Relaxing `require_expressible` to accept `AllowAll` must not accept the postures it still cannot
/// express. A `Network::Localhost` with an inbound `listen` port has no lowering on this backend, so
/// the profile must refuse it rather than silently render a boundary that omits the bind — the
/// macOS backend surfaces the unexpressible posture instead of masking it.
#[test]
fn a_localhost_listen_port_is_still_rejected() {
    let (_directory, config) = fixed_config();

    let with_listen = config
        .set_network(Network::localhost().connect(43123).listen(8080))
        .expect("the portable model accepts a listen port");
    let refusal = generate_seatbelt_profile(&with_listen)
        .expect_err("a listen port has no lowering on macOS and must be refused");
    assert!(
        refusal.to_string().contains("localhost ports"),
        "the refusal must name the unexpressible network posture: {refusal}"
    );
}

#[test]
fn agent_account_lookup_does_not_grant_leaf_network_runtime_services() {
    // The only `system-socket` a profile can carry is the runtime-services grant's own.
    let (_agent_dir, agent) = fixed_config_with_write(false);
    let agent_profile = generate_seatbelt_profile(&agent).expect("agent renders");
    let agent_rules = rules(&agent_profile);
    assert!(
        !agent_rules.contains("system-socket"),
        "the agent box gets no routing socket: {agent_profile}"
    );
    assert!(
        !agent_rules.contains("(sysctl-name-prefix \"net.\")"),
        "the agent box reads no net.* sysctls: {agent_profile}"
    );
    let mach_grants: Vec<_> = agent_rules
        .lines()
        .filter(|line| line.contains("(allow mach-lookup"))
        .collect();
    assert_eq!(
        mach_grants,
        ["(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"],
        "the agent gets exactly one named Mach service: {agent_profile}"
    );

    let (_leaf_dir, leaf) = fixed_config_with_write(false);
    let leaf = leaf.allow_broad_exec();
    let unopted_leaf = generate_seatbelt_profile(&leaf).expect("unopted leaf renders");
    let unopted_rules = rules(&unopted_leaf);
    assert!(!unopted_rules.contains("mach-lookup"));
    assert!(!unopted_rules.contains("system-socket"));
    assert!(!unopted_rules.contains("(sysctl-name-prefix \"net.\")"));
    let leaf = leaf.allow_runtime_services();
    let leaf_profile = generate_seatbelt_profile(&leaf).expect("leaf renders");
    let leaf_rules = rules(&leaf_profile);
    assert!(
        leaf_rules.contains("(allow system-socket (socket-domain AF_ROUTE))"),
        "a leaf with runtime services gets the routing socket, scoped to AF_ROUTE: {leaf_profile}"
    );
    assert!(
        leaf_rules.contains("(allow sysctl-read (sysctl-name-prefix \"net.\"))"),
        "a leaf with runtime services reads the net.* sysctls: {leaf_profile}"
    );
    assert!(
        leaf_rules.contains(
            "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))"
        ),
        "a leaf with runtime services resolves identities via opendirectoryd: {leaf_profile}"
    );
    // The capability is not egress: the base deny still stands.
    assert!(
        leaf_rules.contains("(deny network*)"),
        "runtime services must not lift the network deny: {leaf_profile}"
    );

    // Seatbelt is last-match-wins, so each runtime-services grant only takes effect because it
    // renders BEFORE `(deny network*)`. A substring check alone would still pass if a template edit
    // moved the cell below the deny (silently breaking `getifaddrs` in a leaf), so pin the order.
    let deny_at = leaf_rules
        .find("(deny network*)")
        .expect("the base network deny is present");
    for grant in [
        "(allow system-socket (socket-domain AF_ROUTE))",
        "(allow sysctl-read (sysctl-name-prefix \"net.\"))",
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))",
    ] {
        let at = leaf_rules
            .find(grant)
            .unwrap_or_else(|| panic!("runtime-services grant present: {grant}\n{leaf_profile}"));
        assert!(
            at < deny_at,
            "runtime-services grant must render before (deny network*): {grant}\n{leaf_profile}"
        );
    }
}

#[test]
fn strict_inputs_survive_the_exec_boundary() {
    let (_directory, config) = fixed_config();
    let json = config.to_json().expect("serialize");
    let restored = ContainmentConfig::from_json(&json).expect("restore");

    assert_eq!(
        generate_seatbelt_profile(&restored).expect("render restored"),
        generate_seatbelt_profile(&config).expect("render original")
    );
}

/// The read-only root slot is optional, and read-only.
///
/// Optional so a workload Agent that supplies none renders a profile with no such
/// rule at all; read-only because that is what makes it safe — a read grant confers
/// no exec authority, and the Agent cannot rewrite the code that drives it.
#[test]
fn the_read_only_root_slot_is_optional_and_read_only() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let read_root = root.join("runner");
    std::fs::create_dir(&read_root).expect("directory fixture");

    // Absent: the profile still renders, and mentions no extra subpath.
    let (_directory, base) = fixed_config();
    let without = generate_seatbelt_profile(&base).expect("a workload box renders");
    assert!(!without.contains(&read_root.display().to_string()));

    // Present: exactly one read subpath and its ancestor-metadata line, and NO
    // write or exec rule for that root.
    let (_directory2, base) = fixed_config();
    let config = base
        .allow(&read_root, Operation::Read, Scope::Root)
        .expect("the portable model accepts it");
    let with = generate_seatbelt_profile(&config).expect("a handler box renders");
    let path = read_root.display().to_string();
    assert_eq!(
        with.matches(&format!("(allow file-read* (subpath \"{path}\"))"))
            .count(),
        1,
        "exactly one read subpath for the read-only root"
    );
    assert!(!with.contains(&format!("(allow file-write-data (subpath \"{path}\"))")));
    assert!(!with.contains(&format!("(allow process-exec (literal \"{path}\"))")));
    // Still exactly one exec literal overall: the read root grants no exec.
    assert_eq!(with.matches("(allow process-exec ").count(), 1);
    // A second read-only root is ACCEPTED, unlike the three single slots. Launching a
    // handler needs two disjoint roots — the staged runner and a dynamically linked
    // interpreter's install tree — and the only single grant covering both is `/`.
    // Each renders the same read-only pair, so they need no pairwise distinction.
    let second = read_root.parent().expect("has a parent").join("other");
    std::fs::create_dir(&second).expect("second fixture");
    let (_directory3, base) = fixed_config();
    let both = base
        .allow(&read_root, Operation::Read, Scope::Root)
        .and_then(|config| config.allow(&second, Operation::Read, Scope::Root))
        .expect("two read-only roots are accepted");
    let rendered = generate_seatbelt_profile(&both).expect("two roots render");
    for root in [&read_root, &second] {
        let path = root.display().to_string();
        assert_eq!(
            rendered
                .matches(&format!("(allow file-read* (subpath \"{path}\"))"))
                .count(),
            1,
            "each read-only root renders exactly once"
        );
        assert!(!rendered.contains(&format!("(allow file-write-data (subpath \"{path}\"))")));
    }
    // Still one exec literal: extra read roots confer no exec authority.
    assert_eq!(rendered.matches("(allow process-exec ").count(), 1);
}

/// **Recognition does not depend on the order grants arrive in.**
///
/// Each rule block is reached by one `(Operation, Scope)` cell, so the same grants in a different
/// order must render the same authority. If two blocks accepted one cell, dispatch would follow
/// arrival order and the rendered profile would differ.
#[test]
fn recognition_is_independent_of_grant_order() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let read_root = root.join("runtime");
    let entries = root.join("project");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    let socket = root.join("box.sock");
    for created in [&home, &read_root, &entries] {
        std::fs::create_dir(created).expect("directory fixture");
    }
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");
    socket_fixture(&socket);

    let grants = [
        (executable.as_path(), Operation::Exec, Scope::File),
        (trust_bundle.as_path(), Operation::Read, Scope::File),
        (home.as_path(), Operation::Read, Scope::Root),
        (home.as_path(), Operation::Write, Scope::Root),
        (read_root.as_path(), Operation::Read, Scope::Root),
        (entries.as_path(), Operation::Read, Scope::Dir),
        (socket.as_path(), Operation::Connect, Scope::File),
    ];

    let render = |ordered: Vec<(&std::path::Path, Operation, Scope)>| {
        let mut config = ContainmentConfig::new()
            .set_network(Network::localhost().connect(43123))
            .expect("proxy port");
        for (path, operation, scope) in ordered {
            config = config.allow(path, operation, scope).expect("grant");
        }
        let profile = generate_seatbelt_profile(&config).expect("fixed profile");
        let mut lines: Vec<String> = rules(&profile).lines().map(str::to_string).collect();
        lines.sort();
        lines
    };

    let forward = render(grants.to_vec());
    let mut reversed = grants.to_vec();
    reversed.reverse();
    assert_eq!(
        forward,
        render(reversed),
        "the rendered authority changed with grant order"
    );
}

/// A path cannot inject SBPL through placeholder substitution. The read-only-root
/// value is multi-line rule text, so substituting placeholders in sequential passes
/// would let a path containing a later placeholder's literal name have that rule
/// block expanded inside its own rule.
#[test]
fn a_path_naming_a_placeholder_cannot_inject_rules() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    // A directory whose NAME is the read-only-root placeholder.
    let hostile = root.join("{{READ_ONLY_ROOT_RULES}}");
    std::fs::create_dir(&hostile).expect("hostile fixture");
    let executable = hostile.join("agent");
    std::fs::write(&executable, "#!/bin/sh\n").expect("executable fixture");

    let (_directory, base) = fixed_config();
    let config = base
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("the portable model accepts it");
    // Either it refuses, or it renders with the placeholder text inert — never with
    // an extra `allow` rule spliced into the exec line.
    if let Ok(profile) = generate_seatbelt_profile(&config) {
        let exec_lines: Vec<&str> = profile
            .lines()
            .filter(|line| line.contains("(allow process-exec "))
            .collect();
        assert_eq!(exec_lines.len(), 1, "exactly one exec rule: {exec_lines:?}");
        assert!(
            exec_lines[0].ends_with("\"))"),
            "the exec rule was reshaped: {}",
            exec_lines[0]
        );
        assert_eq!(
            profile.matches("(allow file-read* (subpath ").count(),
            1,
            "only the home's own read subpath; no injected rule"
        );
    }
}

/// **The closed-world census: the rendered profile grants these operations and no
/// others.**
///
/// Every other assertion in this file is *positive* ("this rule is present, exactly
/// once") or a targeted absence against a short denylist. Neither bounds the profile
/// from above, so a rule ADDED to `seatbelt-agent.sb` was invisible: appending
/// `(allow file-read* (subpath "/Users"))`, `(allow file-write-data (subpath "/tmp"))`,
/// `(allow network-outbound (remote tcp "*:443"))`, or even `(allow default)` left all
/// 22 tests passing. Measured, not hypothesized.
///
/// This test inverts that. It extracts the operation name from every `allow` in the
/// rendered profile and compares the whole multiset against an expected list. Any
/// added rule fails here — including one whose operation is already present, since the
/// counts must match too.
///
/// **When this fails, the profile gained or lost authority.** That is either the point
/// of your change (update the list, and say in the commit why the new authority is
/// necessary and why it cannot be narrower) or the bug this test exists to catch.
#[test]
fn the_rendered_profile_grants_exactly_these_operations_and_no_others() {
    // The fixed profile plus a fully-populated request: one exec literal, the trust
    // bundle, the home, one read-only root, one socket. Every placeholder non-empty,
    // so the census covers the widest profile the recognizer will render for a
    // single-executable box.
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let read_root = root.join("runner");
    std::fs::create_dir(&read_root).expect("read root fixture");
    let socket = root.join("run").join("shell.sock");
    socket_fixture(&socket);

    let (_directory, base) = fixed_config();
    let config = base
        .allow(&read_root, Operation::Read, Scope::Root)
        .expect("read-only root")
        .allow(&socket, Operation::Connect, Scope::File)
        .expect("socket grant");
    let profile = generate_seatbelt_profile(&config).expect("the widest fixed profile renders");

    // `(allow <operation> ...)` → "<operation>", over the comment-stripped view so a
    // commented-out rule cannot register as one.
    let mut granted: Vec<String> = rules(&profile)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("(allow "))
        .map(|rest| {
            rest.split([' ', '(', ')'])
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|operation| !operation.is_empty())
        .collect();
    granted.sort();

    // One line per authority, with why it exists. `process-fork` is what lets a harness invoke a
    // child at all; the rest are the placeholders' own rules.
    //
    // **Five operations left this list and none joined it.** `/`, `/etc`, `/private/tmp` and
    // `/dev/null` were static text, so every box carried them whether or not its start program
    // needed one — a Python box carried Bun's `/private/tmp` entry. Each is a grant the box's
    // floor states now, so it renders through the same cells every other grant uses. The profile's
    // own authority is strictly smaller than it was.
    let mut expected = vec![
        "mach-lookup",
        "process-info*", // self-inspection only; paired with (deny process-info*)
        "process-exec",  // the one execute grant
        "file-read-metadata", // that literal, so a PATH search can stat it
        "process-fork",  // unscoped; SBPL has no argv/child-count filter
        "file-ioctl",    // inherited PTY slave
        "file-read*",    // the trust bundle
        "file-read-metadata", // path-ancestors of the home
        "file-read*",    // home subtree
        // The home subtree's write authority, named one leaf at a time. The flags, the
        // access-control list, the owner, and the set-user-ID bit are absent from this list, and
        // that absence is the authority the write cell no longer carries.
        "file-write-data",
        "file-write-create",
        "file-write-unlink",
        "file-write-xattr",
        "file-write-mode",
        "file-write-times",
        "file-read-metadata", // path-ancestors of the read-only root
        "file-read*",         // read-only root subtree
        // One rule holds all seven names, so this stays one entry. The name set has its own
        // test, `the_profile_reads_exactly_seven_named_sysctls`.
        "sysctl-read",
        "network-bind",
        "network-inbound",
        "network-outbound",
        "network-outbound", // the granted socket path
        "network-outbound", // the localhost proxy port
        // The existence test, allowed back on what a grant names after the home refuses it. Two
        // rules per distinct granted path — the path itself, and its ancestor chain — and this
        // config names five: the executable, the trust bundle, the home, the read-only root, and
        // the socket. The home is granted read and write and pairs once. The filter each one takes
        // is `a_dir_grant_inside_the_operator_home_reaches_its_own_entries`; this census counts
        // operation names and never a filter.
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
        "file-test-existence",
    ];
    expected.sort();

    assert_eq!(
        granted, expected,
        "the profile's granted operations changed.\n\
         If this is intentional, update the expected list and record why the new \
         authority is required and why it cannot be narrower.\n\
         rendered profile:\n{profile}"
    );

    // The census counts operations, so it would not notice `(allow default)` becoming
    // `(deny default)`. Pin the two denies that make the profile fail-closed.
    let rules = rules(&profile);
    assert!(
        rules.contains("(deny default)"),
        "the profile must deny by default"
    );
    assert!(
        rules.contains("(deny network*)"),
        "network must be denied before the two allows"
    );
    assert!(
        !rules.contains("(allow default)"),
        "a blanket allow undoes the whole profile"
    );
    assert!(
        rules.contains("(deny file-test-existence (subpath "),
        "without an explicit credential exception, every credential store must refuse an \
         existence test"
    );
}

/// Without an exception, every credential store refuses an existence test at every spelling.
#[test]
fn every_credential_store_refuses_an_existence_test() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    let protected = containment::test_support::credential_store_paths().expect("credential stores");
    // One per credential spelling, plus one per spelling of the home itself, and nothing else.
    let homes = containment::test_support::operator_home_spellings().expect("home spellings");
    assert_eq!(
        rules
            .matches("(deny file-test-existence (subpath \"")
            .count(),
        protected.len() + homes.len(),
        "one rule per credential spelling, plus one per home spelling, and no rule without one.\n\
         rendered profile:\n{profile}"
    );
    // At least one per row per home spelling. Not exact, because a row whose anchor is a symlink
    // renders two paths rather than one, and `floors.rs` pins the exact name set against a fixture
    // home in `the_existence_deny_covers_exactly_these_credential_stores`.
    assert!(
        protected.len() >= 12 * homes.len(),
        "twelve rows across {} home spellings is at least {}, not {}",
        homes.len(),
        12 * homes.len(),
        protected.len()
    );
    for path in &protected {
        let rule = format!(
            "(deny file-test-existence (subpath \"{}\"))",
            path.display()
        );
        assert!(
            rules.contains(&rule),
            "{rule} is missing.\nrendered profile:\n{profile}"
        );
    }

    // In this baseline, each credential deny follows every existence allow and no exception restores
    // one afterward.
    let last_allow = rules
        .rfind("(allow file-test-existence")
        .expect("an existence allow");
    for path in &protected {
        let rule = format!(
            "(deny file-test-existence (subpath \"{}\"))",
            path.display()
        );
        assert!(
            rules.find(&rule).expect("the rule is present above") > last_allow,
            "{rule} precedes an existence allow, so last-match-wins could re-open it.\n\
             rendered profile:\n{profile}"
        );
    }
}

/// The home deny comes first, at every spelling, and every existence allow follows it.
#[test]
fn the_operator_home_refuses_an_existence_test_before_any_allow() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    let spellings =
        containment::test_support::operator_home_spellings().expect("operator home spellings");
    // macOS reaches the home through the data volume as well, and the operation matches the
    // pre-resolution path, so one rule per spelling or the others keep answering.
    assert!(
        spellings.len() >= 2,
        "the home answers to at least two names on macOS: {spellings:?}"
    );
    for home in &spellings {
        let deny = format!(
            "(deny file-test-existence (subpath \"{}\"))",
            home.display()
        );
        assert_eq!(
            rules.matches(&deny).count(),
            1,
            "{deny} must render exactly once.\nrendered profile:\n{profile}"
        );
        assert!(
            rules.find(&deny) < rules.find("(allow file-test-existence"),
            "the home deny must precede every existence allow.\nrendered profile:\n{profile}"
        );
    }
}

/// A grant naming the operator home ITSELF stays `literal`, so no allow undoes the home deny.
///
/// The floor permits this grant — `AnyOverlap` refuses a grant inside a credential row, and a
/// `Dir`-scope grant on their common ancestor is not one — so the renderer is what must refuse it.
/// Rendering `subpath` here would re-open every name in the home except the credential rows, which
/// alone render after the allows.
#[cfg(target_os = "macos")]
#[test]
fn a_grant_naming_the_operator_home_itself_reaches_no_entry() {
    let spellings =
        containment::test_support::operator_home_spellings().expect("operator home spellings");
    let home = spellings.first().expect("at least one spelling").clone();
    let fixture = tempfile::Builder::new()
        .prefix(".strands-containment-test-")
        .tempdir_in(&home)
        .expect("fixture inside the operator home");
    let root = fixture
        .path()
        .canonicalize()
        .expect("canonical fixture root");
    let box_home = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&box_home).expect("box home fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&box_home, Operation::Read, Scope::Root)
        .expect("box home")
        .allow(&box_home, Operation::Write, Scope::Root)
        .expect("box home")
        .allow(&home, Operation::Read, Scope::Dir)
        .expect("the floor permits a Dir grant on the home, so the renderer must bound it")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    assert!(
        !rules.contains(&format!(
            "(allow file-test-existence (subpath \"{}\"))",
            home.display()
        )),
        "the home itself must not reach its own entries.\nrendered profile:\n{profile}"
    );
    assert!(
        rules.contains(&format!(
            "(allow file-test-existence (literal \"{}\"))",
            home.display()
        )),
        "the home itself still answers for itself.\nrendered profile:\n{profile}"
    );
    // The deny is what the assertion above protects, so it must still be there to protect.
    assert!(
        rules.contains(&format!(
            "(deny file-test-existence (subpath \"{}\"))",
            home.display()
        )),
        "the home deny must render.\nrendered profile:\n{profile}"
    );
}

/// A `Dir` grant inside the operator home reaches its own entries, and one outside it does not.
#[cfg(target_os = "macos")]
#[test]
fn a_dir_grant_inside_the_operator_home_reaches_its_own_entries() {
    let spellings =
        containment::test_support::operator_home_spellings().expect("operator home spellings");
    let home = spellings.first().expect("at least one spelling");
    let fixture = tempfile::Builder::new()
        .prefix(".strands-containment-test-")
        .tempdir_in(home)
        .expect("fixture inside the operator home");
    let root = fixture
        .path()
        .canonicalize()
        .expect("canonical fixture root");
    let box_home = root.join("home");
    let project = root.join("project");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir(&box_home).expect("box home fixture");
    std::fs::create_dir(&project).expect("project fixture");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&box_home, Operation::Read, Scope::Root)
        .expect("box home")
        .allow(&box_home, Operation::Write, Scope::Root)
        .expect("box home")
        .allow(&project, Operation::Read, Scope::Dir)
        .expect("the project the workload stands in")
        .allow(std::path::Path::new("/"), Operation::Read, Scope::Dir)
        .expect("the root's own entry")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    assert!(
        rules.contains(&format!(
            "(allow file-test-existence (subpath \"{}\"))",
            project.display()
        )),
        "a Dir grant inside the home reaches its entries.\nrendered profile:\n{profile}"
    );
    // `/` is the same scope OUTSIDE the home, and it is the reason the rule is not unconditional:
    // this block renders after the home deny, so a subpath allow on an ancestor would undo it.
    assert!(
        rules.contains("(allow file-test-existence (literal \"/\"))"),
        "a Dir grant outside the home stays literal.\nrendered profile:\n{profile}"
    );
    assert!(
        !rules.contains("(allow file-test-existence (subpath \"/\"))"),
        "no existence allow may reach the home through an ancestor.\nrendered profile:\n{profile}"
    );
}

/// Every grant outside the operator home carries an existence allow at its own scope, plus its
/// ancestor chain. `a_dir_grant_inside_the_operator_home_reaches_its_own_entries` owns the
/// inside-the-home rule.
#[test]
fn every_grant_renders_an_existence_allow_at_its_own_scope() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home_directory = root.join("home");
    let executable = root.join("agent");
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    // The read-write home is the fixture's only `Root` grant, so it is the `subpath` case.
    assert!(
        rules.contains(&format!(
            "(allow file-test-existence (subpath \"{}\"))",
            home_directory.display()
        )),
        "a root grant renders subpath.\nrendered profile:\n{profile}"
    );
    // The executable is a `File` grant, so it is the `literal` case and never a subpath.
    assert!(
        rules.contains(&format!(
            "(allow file-test-existence (literal \"{}\"))",
            executable.display()
        )),
        "a file grant renders literal.\nrendered profile:\n{profile}"
    );
    assert!(
        !rules.contains(&format!(
            "(allow file-test-existence (subpath \"{}\"))",
            executable.display()
        )),
        "a file grant must not render subpath.\nrendered profile:\n{profile}"
    );
    // The ancestor chain, because a tool walking upward from its own home must read "absent"
    // rather than "refused".
    assert!(
        rules.contains(&format!(
            "(allow file-test-existence (path-ancestors \"{}\"))",
            home_directory.display()
        )),
        "the ancestor chain must carry the operation.\nrendered profile:\n{profile}"
    );
    // `/` has no ancestor to name, and the filter is an SBPL parse error there.
    assert!(
        !rules.contains("(allow file-test-existence (path-ancestors \"/\"))"),
        "the root has no ancestor rule.\nrendered profile:\n{profile}"
    );
}

/// Without an exception, no existence allow reaches a credential store.
#[test]
fn no_existence_allow_reaches_a_credential_store() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("fixed profile");
    let rules = rules(&profile);

    for path in containment::test_support::credential_store_paths().expect("credential stores") {
        for filter in ["literal", "subpath", "path-ancestors"] {
            let rule = format!(
                "(allow file-test-existence ({filter} \"{}\"))",
                path.display()
            );
            assert!(
                !rules.contains(&rule),
                "{rule} would re-open a credential store.\nrendered profile:\n{profile}"
            );
        }
    }
}

/// The home's own identity is fixed: its contents are the Agent's, the directory is not.
///
/// `(subpath X)` covers `X` as well as its descendants, so the read-write root grant
/// alone lets the Agent remove its own home and leave a symbolic link at that path —
/// both operations succeeded before these two denies existed.
///
/// The census above cannot catch a regression here, because it counts `allow`
/// operations only; deleting either deny leaves it passing. The kernel-level proof is
/// `contains_exec_target.rs::the_agent_cannot_replace_its_own_home_directory`, and this
/// asserts the rendered text so a renderer change is caught without spawning anything.
///
/// Both verbs are required. `file-write-unlink` alone stops removal, and a later
/// `symlink` then fails only because the directory is still in the way — refused by
/// luck rather than by the profile. `file-write-create` is what refuses it outright.
#[test]
fn the_home_directory_itself_cannot_be_replaced() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let home = _directory
        .path()
        .canonicalize()
        .expect("canonical tempdir")
        .join("home");
    let home = home.to_str().expect("UTF-8 home");
    let rules = rules(&profile);

    for verb in ["file-write-unlink", "file-write-create"] {
        assert!(
            rules.contains(&format!("(deny {verb} (literal \"{home}\"))")),
            "the home literal must deny {verb}, or the Agent can replace its own home:\
             \n{rules}"
        );
    }

    // Ordering is not what makes the deny win — measured both ways — but the writable
    // subtree must still be granted, or this would be a home the Agent cannot use.
    assert!(
        rules.contains(&format!("(allow file-write-data (subpath \"{home}\"))")),
        "the home's contents must stay writable: {rules}"
    );
}

/// **Every writable path refuses `chflags`, and no other path carries the rule.**
///
/// `file-write*` is a wildcard over the write family, and that family includes
/// `file-write-flags`. The kernel checks a BSD file flag *above* the ownership check, so a
/// flag the Agent sets refuses the operator too: one `UF_IMMUTABLE` in the box home made
/// `remove_dir_all` fail, so `rm` and `reset` exited 1 while `ls` still listed the box, and
/// only an out-of-band `chflags -R` recovered it.
///
/// **One rule per write cell is complete, and a rule anywhere else would enforce zero.**
/// The profile denies by default, so a path with no `file-write*` rule cannot reach
/// `chflags` at all. The write cells are the only two emitters of that wildcard.
///
/// **One rule also covers both flag classes and every bit.** `chflags(2)` is a single
/// Seatbelt operation whose flag argument no rule can read, so the owner class, the
/// super-user class a root-mode box could reach, and any bit Apple adds later are all
/// refused by the same line. `contains_exec_target.rs::the_agent_cannot_set_a_file_flag_in_its_own_home`
/// is the kernel-level proof for the owner class.
///
/// The census cannot catch a regression here, because it counts `allow` operations only.
/// Separate from `the_home_directory_itself_cannot_be_replaced` so each rule is
/// independently falsifiable — deleting the flags deny must fail exactly one test.
#[test]
fn every_writable_path_refuses_a_file_flag() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    // Outside the home, as `/dev/null` is: a write FILE grant is its own cell, and this is
    // the shape the box's floor states.
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let home = root.join("home");
    let home = home.to_str().expect("UTF-8 home");
    let sink = sink.to_str().expect("UTF-8 sink");

    // Neither cell names the flags leaf, so the default deny is what refuses it.
    assert!(
        !rules.contains("(allow file-write-flags "),
        "no write cell may grant a BSD file flag: {rules}"
    );
    // And neither reaches it through the family wildcard, which would grant every leaf at once.
    assert!(
        !rules.contains("(allow file-write* "),
        "a write cell names leaves and never the family wildcard: {rules}"
    );
    // The controls. Both paths must still be writable, or this is a refuse-all rather than
    // one operation withheld.
    for granted in [
        format!("(allow file-write-data (subpath \"{home}\"))"),
        format!("(allow file-write-data (literal \"{sink}\"))"),
    ] {
        assert!(
            rules.contains(&granted),
            "the write grant must survive, or this test proves nothing: {granted}"
        );
    }
    // Extended attributes and the mode stay granted over a write ROOT, because a workload sets an
    // attribute and tightens a file it created there. The write FILE cell grants the contents alone,
    // pinned by `a_write_file_grant_refuses_a_mode_change_and_a_write_root_does_not`.
    assert!(
        rules.contains(&format!("(allow file-write-xattr (subpath \"{home}\"))")),
        "a write root keeps the extended-attribute leaf: {rules}"
    );
    assert!(
        rules.contains(&format!("(allow file-write-mode (subpath \"{home}\"))")),
        "a write root keeps the mode leaf: {rules}"
    );
}

/// Every writable path refuses an executable mapping, and no other path does.
///
/// The kernel-level guard is
/// `contains_exec_target.rs::a_library_written_in_the_home_cannot_be_loaded`, and the census cannot
/// catch a regression here because it counts `allow` operations only.
#[test]
fn every_writable_path_refuses_an_executable_mapping() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let read_only = root.join("runner");
    std::fs::create_dir(&read_only).expect("read root fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file")
        .allow(&read_only, Operation::Read, Scope::Root)
        .expect("a read-only root");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let home = root.join("home");
    let home = home.to_str().expect("UTF-8 home");
    let sink = sink.to_str().expect("UTF-8 sink");
    let read_only = read_only.to_str().expect("UTF-8 read root");

    assert!(
        rules.contains(&format!("(deny file-map-executable (subpath \"{home}\"))")),
        "a write root must refuse an executable mapping over its whole subtree: {rules}"
    );
    assert!(
        rules.contains(&format!("(deny file-map-executable (literal \"{sink}\"))")),
        "a write file must refuse an executable mapping on itself: {rules}"
    );
    // **The bound, and it is the half that keeps this from being a refuse-all.** A read-only root is
    // where every runtime library a workload needs comes from, so the deny must not reach one.
    //
    // The positive assertion comes first, because the absence one below is true of a root that never
    // rendered at all and would pass while measuring nothing.
    assert!(
        rules.contains(&format!("(allow file-read* (subpath \"{read_only}\"))")),
        "the read-only root must render, or the absence assertion below is vacuous: {rules}"
    );
    assert!(
        !rules.contains(&format!(
            "(deny file-map-executable (subpath \"{read_only}\"))"
        )),
        "a read-only root must keep loading libraries: {rules}"
    );
    assert!(
        !rules.contains("(deny file-map-executable)"),
        "the deny must stay scoped to the writable paths, never blanket: {rules}"
    );
    // The write grants must survive, or one operation was not subtracted, everything was.
    for granted in [
        format!("(allow file-write-data (subpath \"{home}\"))"),
        format!("(allow file-write-data (literal \"{sink}\"))"),
    ] {
        assert!(
            rules.contains(&granted),
            "the write grant must survive the deny, or this test proves nothing: {granted}"
        );
    }
}

/// Every writable path refuses an ownership change.
///
/// **`file-write*` bundles `file-write-owner`**, so a write grant handed over who owns each path as
/// well as what is in it. Inside the box home that is nearly inert, because the tree is the Agent's.
/// The cell that made it matter is the write FILE, whose one grant is a device the operator owns —
/// so ordinary file ownership was the only thing refusing, and that is a property of the caller
/// rather than of the box. Both cells deny it together so neither can drift.
///
/// Separate from the flags and mode tests so each rule is independently falsifiable: deleting the
/// owner deny must fail exactly one test. `contains_exec_target.rs` holds the kernel-level proofs.
#[test]
fn every_writable_path_refuses_an_ownership_change() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let home = root.join("home");
    let home = home.to_str().expect("UTF-8 home");
    let sink = sink.to_str().expect("UTF-8 sink");

    // Neither cell names the owner leaf. `setattrlist` reaches the owner through the family
    // wildcard and past any leaf deny, so withholding the leaf is the only shape that refuses it.
    assert!(
        !rules.contains("(allow file-write-owner "),
        "no write cell may grant an ownership change: {rules}"
    );
    assert!(
        !rules.contains("(allow file-write* "),
        "a write cell names leaves and never the family wildcard: {rules}"
    );
    // The controls, so this is one operation withheld rather than a refuse-all.
    for granted in [
        format!("(allow file-write-data (subpath \"{home}\"))"),
        format!("(allow file-write-data (literal \"{sink}\"))"),
    ] {
        assert!(
            rules.contains(&granted),
            "the write grant must survive, or this test proves nothing: {granted}"
        );
    }
}

/// A write grant on a file inside a write root is refused.
///
/// The file cell denies its own literal, and a specific deny beats an enclosing `subpath` allow, so
/// the nested path would silently lose the mode, the owner, and its identity while every sibling in
/// the tree kept them.
#[test]
fn a_write_file_inside_a_write_root_is_refused() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let nested = root.join("home").join("nested.txt");
    std::fs::write(&nested, "nested").expect("a file inside the write root");

    let config = base
        .allow(&nested, Operation::Write, Scope::File)
        .expect("the vocabulary accepts the grant");
    let error = generate_seatbelt_profile(&config)
        .expect_err("a write file inside a write root must be refused");
    let message = error.to_string();
    // The nested path by name, because three floors share the phrase "lies inside the write root"
    // and a message check alone would pass on a neighbouring rule firing for its own reason.
    assert!(
        message.contains("lies inside the write root")
            && message.contains(&nested.display().to_string()),
        "the refusal must name the nested grant: {message}"
    );

    // The control: the same grant OUTSIDE the write root still renders, or this floor would refuse
    // `/dev/null` and every other legitimate file-scope write.
    let (outside_directory, outside_base) = fixed_config();
    let outside_root = outside_directory
        .path()
        .canonicalize()
        .expect("canonical tempdir");
    let sink = outside_root.join("sink");
    std::fs::write(&sink, "sink").expect("a file outside the write root");
    let permitted = outside_base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    generate_seatbelt_profile(&permitted)
        .expect("a write file outside every write root must still render");
}

/// Every writable path refuses an access-control-list change.
///
/// `file-write*` bundles `file-write-acl`, and a deny entry the workload writes refuses the file's
/// own owner — the availability shape the flags deny already closes, reached at ordinary privilege
/// instead of root. `contains_exec_target.rs::the_agent_cannot_set_an_access_control_list_in_its_own_home`
/// is the kernel-level proof.
#[test]
fn every_writable_path_refuses_an_access_control_list() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let home = root.join("home");
    let home = home.to_str().expect("UTF-8 home");
    let sink = sink.to_str().expect("UTF-8 sink");

    // Neither cell names the access-control-list leaf. `setattrlist` reaches the list through the
    // family wildcard and past any leaf deny, so withholding the leaf is the only shape that
    // refuses it — and the list is the member that locks the operator out of their own tree.
    assert!(
        !rules.contains("(allow file-write-acl "),
        "no write cell may grant an access-control list: {rules}"
    );
    assert!(
        !rules.contains("(allow file-write* "),
        "a write cell names leaves and never the family wildcard: {rules}"
    );
    // The controls, so this is one operation withheld rather than a refuse-all.
    for granted in [
        format!("(allow file-write-data (subpath \"{home}\"))"),
        format!("(allow file-write-data (literal \"{sink}\"))"),
    ] {
        assert!(
            rules.contains(&granted),
            "the write grant must survive, or this test proves nothing: {granted}"
        );
    }
}

/// A write FILE grant refuses a mode change, and a write ROOT grant does not.
///
/// **The asymmetry is the decision, so the test asserts both halves.** A workload tightens a file it
/// created in its own tree, so the root cell names the mode leaf. A file-scope grant names one file
/// the box does not own, and nothing writing that file's contents needs its permission bits, so the
/// file cell names the contents alone.
///
/// A reader who sees only one cell will try to make the two match. Asserting the *absence* over the
/// file cell is what stops that being a green change.
#[test]
fn a_write_file_grant_refuses_a_mode_change_and_a_write_root_does_not() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let home = root.join("home");
    let home = home.to_str().expect("UTF-8 home");
    let sink = sink.to_str().expect("UTF-8 sink");

    assert!(
        !rules.contains(&format!("(allow file-write-mode (literal \"{sink}\"))")),
        "a write file must not grant a mode change on itself: {rules}"
    );
    assert!(
        rules.contains(&format!("(allow file-write-mode (subpath \"{home}\"))")),
        "a write root keeps the mode, because a workload tightens a file it created: {rules}"
    );
    // One rule and one path is the property, so a count states it. A single spelling would leave a
    // mode allow on any other path, in any other shape, passing.
    assert_eq!(
        rules.matches("(allow file-write-mode ").count(),
        1,
        "exactly one cell grants the mode, and it is the write ROOT: {rules}"
    );
}

/// A write FILE grant cannot remove or replace the file it names.
///
/// **The same question `the_home_directory_itself_cannot_be_replaced` answers for a write root**,
/// at one path. The cell names the contents leaf alone, so both halves of the path's identity are
/// withheld and the default deny refuses each — without that, the granted path could be unlinked and
/// a symbolic link put in its place, and a reader of the grant would predict a boundary that is not
/// there.
#[test]
fn a_granted_file_itself_cannot_be_replaced() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let sink = root.join("sink");
    std::fs::write(&sink, "sink").expect("sink fixture");
    let config = base
        .allow(&sink, Operation::Write, Scope::File)
        .expect("a write grant on one file");
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);

    let sink = sink.to_str().expect("UTF-8 sink");
    for withheld in [
        format!("(allow file-write-unlink (literal \"{sink}\"))"),
        format!("(allow file-write-create (literal \"{sink}\"))"),
    ] {
        assert!(
            !rules.contains(&withheld),
            "a write file must keep its own identity: {withheld} is present in {rules}"
        );
    }
    assert!(
        rules.contains(&format!("(allow file-write-data (literal \"{sink}\"))")),
        "the write grant must survive, or this test proves nothing: {rules}"
    );
}

/// **A request is not a set of independent grants, and the profile is its most
/// restrictive reading.**
///
/// Two `allow` rules cannot narrow each other, so a profile rendered from grants that
/// disagree about a path enforces their *union* — the widest reading — and nothing
/// downstream can recover which the caller meant. The conflict below is therefore
/// refused rather than rendered. The write-plus-exec pair is the one union that renders,
/// with a warning; `a_write_plus_exec_grant_set_validates_renders_and_yields_the_warning`
/// owns it.
///
/// This is about `allow`s, not about SBPL evaluation generally: an explicit `deny` on a
/// literal does override an enclosing `subpath` allow, which is how
/// `the_home_directory_itself_cannot_be_replaced` pins the home's identity. A grant
/// conflict has no such tool, because both sides are allows.
#[test]
fn grants_that_combine_into_more_authority_than_either_states_are_rejected() {
    // A write root that CONTAINS the home's write root: the union is the outer root, so
    // the inner grant states a narrowing the profile does not enforce.
    {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical tempdir");
        let enclosing = root.join("staged");
        let home = enclosing.join("home");
        std::fs::create_dir_all(&home).expect("home fixture");
        let executable = root.join("agent");
        std::fs::write(&executable, "agent").expect("executable fixture");
        let trust_bundle = root.join("proxy-ca.pem");
        std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

        let config = ContainmentConfig::new()
            .allow(&executable, Operation::Exec, Scope::File)
            .expect("executable")
            .allow(&trust_bundle, Operation::Read, Scope::File)
            .expect("trust bundle")
            .allow(&home, Operation::Read, Scope::Root)
            .expect("home")
            .allow(&home, Operation::Write, Scope::Root)
            .expect("home")
            .allow(&enclosing, Operation::Write, Scope::Root)
            .expect("the portable model accepts it")
            .set_network(Network::localhost().connect(43123))
            .expect("proxy port");

        let error = generate_seatbelt_profile(&config)
            .expect_err("a write root containing the home's write root must be refused");
        assert!(
            error.to_string().contains("lies inside the write root"),
            "unexpected error: {error}"
        );
    }
}

/// An executable may be inside a read-only root.
#[test]
fn an_execute_grant_inside_a_read_only_root_is_still_expressible() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let runtime_root = root.join("runtime");
    std::fs::create_dir(&runtime_root).expect("runtime root fixture");
    let interpreter = runtime_root.join("python3");
    std::fs::write(&interpreter, "interpreter").expect("interpreter fixture");
    let home = root.join("home");
    std::fs::create_dir(&home).expect("home fixture");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&interpreter, Operation::Exec, Scope::File)
        .expect("interpreter")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("home")
        .allow(&runtime_root, Operation::Read, Scope::Root)
        .expect("the interpreter's own install tree")
        .set_network(Network::localhost().connect(43123))
        .expect("proxy port");

    let profile =
        generate_seatbelt_profile(&config).expect("exec inside a READ-ONLY root stays legal");
    assert!(profile.contains(&format!(
        "(allow process-exec (literal \"{}\"))",
        interpreter.display()
    )));
    // Read-only really is read-only: no write rule for the tree holding the program.
    assert!(!profile.contains(&format!(
        "(allow file-write-data (subpath \"{}\"))",
        runtime_root.display()
    )));
}

/// No grant may name the whole filesystem or an operator-owned tree.
///
/// Breadth is independent of the cell: `Write` at `Tree` scope on `/` is a well-formed
/// grant of everything. Before this floor, `home = "/"` rendered
/// `file-write* (subpath "/")` and a read-only root of `/` rendered
/// `file-read* (subpath "/")` — the exact widening the profile's own denylist claims is
/// absent, arriving through a grant instead of through the fixed text.
#[test]
fn grants_naming_a_whole_filesystem_or_system_root_are_rejected() {
    // **A root the running host does not have is skipped, not asserted.** `/Users` is macOS-only,
    // and a grant on a path that does not resolve is refused *before* the breadth floor is
    // consulted — so on Linux it would pass for the wrong reason. `FORBIDDEN_GRANT_ROOTS` still
    // lists it, and macOS covers it.
    let mut checked = 0;
    for (root, operation) in [
        ("/", Operation::Write),
        ("/", Operation::Read),
        ("/usr", Operation::Read),
        ("/etc", Operation::Read),
        ("/Users", Operation::Read),
    ] {
        if !std::path::Path::new(root).is_dir() {
            continue;
        }
        checked += 1;
        let (_directory, base) = fixed_config();
        let config = base
            .allow(root, operation, Scope::Root)
            .expect("the vocabulary accepts it");
        let error = generate_seatbelt_profile(&config).expect_err(&format!(
            "a grant on {root} as {operation:?} must be refused"
        ));
        assert!(
            error.to_string().contains("never a grantable tree"),
            "unexpected error for {root} as {operation:?}: {error}"
        );
    }
    assert!(
        checked >= 4,
        "every host has /, /usr, and /etc, so a run that checked {checked} entries measured \
         almost nothing"
    );
}
/// **Every repeatable rule renders one rule per grant, and no count bounds it.**
///
/// The renderer holds no ceiling. The caller's floor and `[agent]` grants state the outer boundary
/// for a command, so a limit here would refuse a composition the caller authorized, at a layer that
/// cannot see what was asked for.
/// This asserts the rendering is exactly per-grant in both directions: the counts match the grants,
/// and a wide composition renders rather than being refused.
#[test]
fn every_repeatable_rule_renders_one_rule_per_grant() {
    const REPEATS: usize = 30;

    let (directory, mut config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");

    for index in 0..REPEATS {
        let program = root.join(format!("program-{index}"));
        std::fs::write(&program, "program").expect("program fixture");
        config = config
            .allow(&program, Operation::Exec, Scope::File)
            .expect("an execute grant is never bounded by a count");

        let read_root = root.join(format!("read-root-{index}"));
        std::fs::create_dir(&read_root).expect("read root fixture");
        config = config
            .allow(&read_root, Operation::Read, Scope::Root)
            .expect("a read-only root is never bounded by a count");

        let entries = root.join(format!("project-{index}"));
        std::fs::create_dir(&entries).expect("directory-entries fixture");
        config = config
            .allow(&entries, Operation::Read, Scope::Dir)
            .expect("a directory-entries grant is never bounded by a count");

        let socket = root.join("run").join(format!("shell-{index}.sock"));
        socket_fixture(&socket);
        config = config
            .allow(&socket, Operation::Connect, Scope::File)
            .expect("a socket route is never bounded by a count");
    }

    let (_baseline_directory, baseline) = fixed_config();
    let baseline = generate_seatbelt_profile(&baseline).expect("the baseline renders");
    let profile = generate_seatbelt_profile(&config).expect("a wide composition renders");

    // The delta against the baseline, not an absolute count: `fixed_config`'s own grants render
    // some of the same rule kinds, and an absolute number would pin their arithmetic instead.
    for (rule, label) in [
        ("(allow process-exec (literal", "execute grant"),
        ("(allow file-read* (subpath ", "read-only root"),
        ("(allow file-read-data (literal ", "directory-entries grant"),
        ("(allow network-outbound", "socket route"),
    ] {
        assert_eq!(
            profile.matches(rule).count() - baseline.matches(rule).count(),
            REPEATS,
            "every {label} must render its own rule"
        );
    }
    assert!(!profile.contains("{{"), "every placeholder is substituted");
}

/// The telemetry port is one more `network-outbound` rule, and only when one is asked for.
///
/// Both halves matter. Rendered, the workload can reach the composition's own collector on
/// loopback. Absent, the profile is byte-for-byte what it was, so a box that keeps no telemetry
/// carries no second route.
#[test]
fn a_second_served_port_renders_one_more_localhost_rule_and_nothing_else() {
    let (directory, without) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home_directory = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");

    let with = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(Network::localhost().connect(43123).connect(43124))
        .expect("two localhost ports");

    let without = generate_seatbelt_profile(&without).expect("fixed profile");
    let with = generate_seatbelt_profile(&with).expect("fixed profile with a second port");

    let proxy_rule = "(allow network-outbound\n    (remote tcp \"localhost:43123\"))";
    let second_rule = "(allow network-outbound\n    (remote tcp \"localhost:43124\"))";

    assert!(with.contains(proxy_rule), "the proxy route survives");
    assert!(with.contains(second_rule), "and the service is reachable");
    assert!(
        !rules(&without).contains("localhost:43124"),
        "one port means one rule"
    );
    assert!(!with.contains("{{"), "every placeholder is substituted");

    // Exactly one rule is added, and the difference is that rule. A count catches a renderer
    // that emitted the block twice, which a `contains` check reads as a pass.
    assert_eq!(
        rules(&with).matches("(allow network-outbound").count(),
        rules(&without).matches("(allow network-outbound").count() + 1,
        "a second port adds one outbound rule, not a block"
    );
}

/// Listen ports and a telemetry port do not compose, and the refusal says which shape failed.
#[test]
fn listen_ports_are_still_the_only_network_shape_the_profile_refuses() {
    let (directory, _config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home_directory = root.join("home");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("exact home directory")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("exact home directory")
        .set_network(
            Network::localhost()
                .connect(43123)
                .connect(43124)
                .listen(3000),
        )
        .expect("the portable model accepts listen ports");

    let error = generate_seatbelt_profile(&config).expect_err("the profile cannot bind");
    assert!(
        error.to_string().contains("network access other than"),
        "unexpected error: {error}"
    );
}
/// An execute grant whose CALLER spelling sits inside the read-write root carries the warning.
///
/// The check once compared only the resolved target, and this backend renders
/// `file-read-metadata` on the caller spelling too when the two differ. So a link *inside* the
/// writable home pointing at a program outside it put a metadata rule on a path the workload
/// writes, and said nothing. It renders and warns now, naming the spelling the workload controls.
#[test]
fn an_execute_grant_reached_through_the_read_write_root_warns() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let target = root.join("real-agent");
    std::fs::write(&target, "agent").expect("the real program");

    let home_directory = root.join("home");
    std::fs::create_dir(&home_directory).expect("home");
    // The route lives inside the writable home; its target does not.
    let route = home_directory.join("agent-link");
    std::os::unix::fs::symlink(&target, &route).expect("the link");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust");

    let config = ContainmentConfig::new()
        .allow(&route, Operation::Exec, Scope::File)
        .expect("the grant names the route")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43124))
        .expect("proxy port");

    generate_seatbelt_profile(&config).expect("the pair renders with a warning");
    let warnings = config.warnings();
    assert_eq!(warnings.len(), 1, "one pair, one warning: {warnings:?}");
    let message = warnings[0].to_string();
    assert!(
        message.contains(&route.display().to_string())
            && message.contains(&home_directory.display().to_string()),
        "the warning must name the spelling the workload controls and the write grant that \
         reaches it: {message}"
    );
}

/// A spelling difference alone is NOT a conflict, which is the over-refusal to avoid.
///
/// On macOS a temporary directory is reached through `/tmp -> /private/tmp`, so a grant's caller and
/// resolved spellings routinely differ while naming one file. Testing the caller spelling against a
/// *resolved* root would refuse every box under a temporary home — the whole suite, not one
/// assertion. The comparison is original against original for that reason.
#[test]
fn a_spelling_difference_alone_is_not_a_conflicting_grant() {
    let directory = tempfile::tempdir().expect("tempdir");
    let real = directory.path().canonicalize().expect("canonical tempdir");

    // The symlink is built here rather than borrowed from the host. `/tmp -> /private/tmp` gives the
    // same shape on macOS, but on Linux `/tmp` canonicalizes to itself, so a test resting on it
    // fails there — and this file is deliberately ungated so it runs on every platform.
    let route = real.join("route");
    let inside = real.join("inside");
    std::fs::create_dir(&inside).expect("the real directory");
    std::os::unix::fs::symlink(&inside, &route).expect("the directory link");

    // Authored through the link, so `original` and `resolved` differ for every grant below.
    let program = route.join("agent");
    std::fs::write(&program, "agent").expect("the program");
    let home_directory = route.join("home");
    std::fs::create_dir(&home_directory).expect("home");
    let trust_bundle = route.join("proxy-ca.pem");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust");

    // The premise, asserted rather than assumed: without it this test would pass vacuously on a
    // filesystem that resolved the link away.
    assert_ne!(
        program,
        program.canonicalize().expect("the program resolves"),
        "the grant must be authored through a link for this test to mean anything"
    );

    let config = ContainmentConfig::new()
        .allow(&program, Operation::Exec, Scope::File)
        .expect("the program grant")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("trust bundle")
        .allow(&home_directory, Operation::Read, Scope::Root)
        .expect("home")
        .allow(&home_directory, Operation::Write, Scope::Root)
        .expect("home")
        .set_network(Network::localhost().connect(43125))
        .expect("proxy port");

    // The program is a SIBLING of the home, so nothing conflicts — only the spellings differ.
    generate_seatbelt_profile(&config)
        .expect("a spelling difference is not a conflict and must still render");
}

/// A credential store under the caller's OWN home is refused, though the passwd database names a
/// different home.
///
/// **This is the divergence the declared home closes.** The box resolves every `~/`-relative grant
/// against `$HOME`, and the floor anchors its credential rows at `passwd(getuid())`. The two
/// disagree under `sudo -E`, in a container, and in this test, because a fixture home is never the
/// passwd home. While they disagreed, every credential row guarded a tree no grant could reach.
/// `docs/design/decisions.md#a-caller-adds-a-floor-anchor-and-never-moves-one` holds the rest.
///
/// The fixture home is what makes this run without root: the condition is the two homes differing,
/// and `euid` 0 is only one way to produce it.
#[test]
fn a_credential_store_under_the_declared_home_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let box_home = root.join("home");
    let credentials = root.join(".aws");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::create_dir(&box_home).expect("box home fixture");
    std::fs::create_dir(&credentials).expect("credential store fixture");

    let config = ContainmentConfig::new()
        .anchored_at(&root)
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&box_home, Operation::Write, Scope::Root)
        .expect("box home")
        // What an `[agent] code` entry looks like when it names a credential directory. The floor is
        // that key's only credential check.
        .allow(&credentials, Operation::Read, Scope::Root)
        .expect("the grant is well formed; the floor is what refuses it")
        .set_network(Network::localhost().connect(43126))
        .expect("proxy port");

    let refusal = generate_seatbelt_profile(&config)
        .expect_err("a credential store under the declared home must be refused")
        .to_string();
    assert!(
        refusal.contains("credential"),
        "the refusal must name what it protects rather than only the path: {refusal}"
    );
}

/// Stating a home never unprotects the passwd home's own credential stores.
///
/// The anchor set is additive, so this asserts the half
/// `a_credential_store_under_the_declared_home_is_refused` cannot: replacing the anchor instead of
/// adding to it passes that test while handing a caller the power to switch the floor off.
///
/// **It names whichever credential store the passwd home actually has**, rather than `.ssh` alone. A
/// single hard-coded store makes this skip on a host that lacks it — a container or a CI runner, which
/// are the hosts the divergence is most likely on — and libtest captures the skip line, so a green run
/// would be indistinguishable from one that asserted nothing.
#[test]
fn declaring_one_home_does_not_unprotect_the_other() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let box_home = root.join("home");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::create_dir(&box_home).expect("box home fixture");

    // A store the passwd home really holds, so this skips only when it holds none of them.
    let passwd_home = containment::test_support::passwd_home_for_test()
        .expect("this platform reports a passwd home");
    let Some(passwd_credentials) = [
        ".ssh",
        ".aws",
        ".gnupg",
        ".docker",
        ".kube",
        ".config/gcloud",
    ]
    .into_iter()
    .map(|store| passwd_home.join(store))
    .find(|path| path.is_dir()) else {
        eprintln!("skipping: the passwd home holds none of the credential stores this floor names");
        return;
    };

    let config = ContainmentConfig::new()
        .anchored_at(&root)
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&box_home, Operation::Write, Scope::Root)
        .expect("box home")
        .allow(&passwd_credentials, Operation::Read, Scope::Root)
        .expect("the grant is well formed; the floor is what refuses it")
        .set_network(Network::localhost().connect(43127))
        .expect("proxy port");

    let refusal = generate_seatbelt_profile(&config)
        .expect_err("declaring a fixture home must not unprotect the passwd home's key store")
        .to_string();
    // The reason, not just the refusal: any unrelated error would satisfy a bare `expect_err`, and
    // then this test would pass for a reason that is not the floor.
    assert!(
        refusal.contains("credential"),
        "the refusal must name what it protects rather than only the path: {refusal}"
    );
}

/// A stated home survives the JSON boundary the trampoline crosses, and still anchors a row.
///
/// **The floor that runs in production runs after a round trip.** `box` writes the config to
/// `private/containment/<digest>.json` and the trampoline reloads it with `from_json`, so a test that
/// only calls the renderer in-process never exercises the path that enforces. Both guards above build
/// their subject differently from production; this one does not.
#[test]
fn a_stated_home_still_anchors_a_row_after_the_wire_round_trip() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let box_home = root.join("home");
    let credentials = root.join(".ssh");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::create_dir(&box_home).expect("box home fixture");
    std::fs::create_dir(&credentials).expect("credential store fixture");

    // Serialized WITHOUT the credential grant, because a config carrying it cannot be rendered — the
    // floor is what this test is about. The grant is added back on the far side of the wire.
    let json = ContainmentConfig::new()
        .anchored_at(&root)
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&box_home, Operation::Write, Scope::Root)
        .expect("box home")
        .set_network(Network::localhost().connect(43128))
        .expect("proxy port")
        .to_json()
        .expect("serialize");

    let reloaded = ContainmentConfig::from_json(&json)
        .expect("the config the trampoline reads")
        .allow(&credentials, Operation::Read, Scope::Root)
        .expect("the grant is well formed; the floor is what refuses it");

    let refusal = generate_seatbelt_profile(&reloaded)
        .expect_err("the stated home must survive the wire and still anchor its rows")
        .to_string();
    assert!(
        refusal.contains("credential"),
        "the reloaded config lost its anchor: {refusal}"
    );
}

/// Every view-changing and node-creating operation is denied by its exact leaf name.
///
/// **A wildcard cannot stand in for these names.** `(deny default)` does not reach an operation the
/// version-1 preamble grants unconditionally, and a wildcard deny does not take one back either — so
/// three of the eleven below were reachable in a shipped box, and a `fs-snapshot*` line would have
/// left the one that matters open. The crate's `AGENTS.md` records which three and how it was
/// measured.
///
/// The other eight are already refused by the default deny. They are named anyway so each closure can
/// be falsified by deleting one line.
///
/// Nine render unconditionally and the two grafting names render behind a test of their own name.
/// Each assertion matches a whole line, so a name cannot move between the two classes.
#[test]
fn every_view_changing_operation_is_denied_by_its_exact_name() {
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let rules = rules(&profile);
    let renders = |rule: &str| rules.lines().any(|line| line.trim() == rule);

    for operation in [
        "file-mknod",
        "file-mount",
        "file-mount-update",
        "file-unmount",
        "file-chroot",
        "fs-snapshot-create",
        "fs-snapshot-delete",
        "fs-snapshot-mount",
        "fs-snapshot-revert",
    ] {
        assert!(
            renders(&format!("(deny {operation})")),
            "{operation} must be denied by name and unconditionally: {rules}"
        );
    }
    for operation in ["file-graft", "file-ungraft"] {
        assert!(
            renders(&format!("(if (defined? '{operation}) (deny {operation}))")),
            "{operation} must be denied by name, behind a test of that name: {rules}"
        );
    }
    // `file-clone` belongs on that list and is deliberately NOT there yet. It waits on a
    // measurement of Node's and Bun's `fs.copyFile` fallback, and only the Node half is taken: Bun is
    // not installable on this host, and both shipped harness packs are Bun-compiled. Adding the deny
    // before that measurement would break every file copy in a Bun box.
    assert!(
        !rules.contains("(deny file-clone)"),
        "file-clone stays granted until the Bun measurement is taken: {rules}"
    );
    // A wildcard in place of the four snapshot names would read as complete and leave the mount
    // reachable, so its absence is part of the property.
    assert!(
        !rules.contains("(deny fs-snapshot*)"),
        "a snapshot wildcard does not reach the mount and must not stand in for it: {rules}"
    );
}

/// A test of an operation's own name loads where the name is absent, and refuses where it is bound.
#[cfg(target_os = "macos")]
#[test]
fn a_test_of_an_operation_name_loads_where_the_operation_is_absent() {
    /// A name no release binds, so the compiler rejects it when no guard stands in front.
    const ABSENT: &str = "file-strands-box-no-such-operation";
    /// The refusal `sandbox_init` reports for a name the host does not bind.
    const UNBOUND: &str = "unbound variable";
    /// The refusal the kernel reports for an operation a rule denied.
    const REFUSED: &str = "Operation not permitted";

    let run = |profile: String, program: &[&str]| {
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .args(program)
            .output()
            .expect("sandbox-exec is on every macOS host");
        let message = String::from_utf8_lossy(&output.stderr).into_owned();
        (output.status.success(), message)
    };
    let head = "(version 1)\n(allow default)\n";

    let (reported_ran, reported) = run(format!("{head}(deny {ABSENT})\n"), &["/usr/bin/true"]);
    assert!(
        !reported_ran && reported.contains(UNBOUND),
        "an unguarded absent name must refuse the whole profile: {reported}"
    );

    let (guarded_ran, guarded) = run(
        format!("{head}(if (defined? '{ABSENT}) (deny {ABSENT}))\n"),
        &["/usr/bin/true"],
    );
    assert!(guarded_ran, "a guarded absent name must load: {guarded}");

    // The lines the template renders, read back out of a rendered profile rather than spelled again
    // here, so an edit to the guard's form cannot leave this leg compiling the old one.
    let (_directory, config) = fixed_config();
    let profile = generate_seatbelt_profile(&config).expect("the fixed profile renders");
    let tail: String = rules(&profile)
        .lines()
        .filter(|line| line.contains("defined?"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(
        tail.lines().count(),
        2,
        "the profile must render two guarded lines: {tail}"
    );
    let (tail_ran, tail_message) = run(format!("{head}{tail}"), &["/usr/bin/true"]);
    assert!(
        tail_ran,
        "the guarded lines the profile renders must load on this release: {tail_message}"
    );

    // `file-clone` is the right subject, and an ordinary read leaf was not: the property the two
    // grafting names need is that an exact leaf name takes back an operation the version-1 preamble
    // grants unconditionally, and `file-clone` is in that class.
    let directory = tempfile::tempdir().expect("a directory to clone inside");
    let root = directory.path().canonicalize().expect("canonical root");
    let source = root.join("source");
    std::fs::write(&source, b"bytes to clone").expect("the clone source");
    let source = source.display().to_string();
    let clone = |name: &str, deny: &str| {
        let destination = root.join(name).display().to_string();
        run(
            format!("{head}{deny}"),
            &["/bin/cp", "-c", &source, &destination],
        )
    };

    let (control_ran, control) = clone("control", "");
    assert!(
        control_ran,
        "the control must clone, or the refusal below measures nothing: {control}"
    );

    let (denied_ran, denied) = clone("denied", "(if (defined? 'file-clone) (deny file-clone))\n");
    assert!(
        !denied_ran && denied.contains(REFUSED) && !denied.contains(UNBOUND),
        "a guarded deny must refuse the operation, and not fail to compile: {denied}"
    );
}

/// A refusal names every leaf a cell can grant, because a wildcard deny loses to a leaf allow.
///
/// `ContainmentConfig::refuse` is documented as refusing a path "whatever any grant says". Seatbelt
/// resolves a rule by operation-name specificity before rule order, so a `file-read*` or
/// `file-write*` deny loses to a leaf allow on a path inside the refused tree, in either order.
/// Measured: with a `file-read-data` leaf allow present, a read through
/// `(deny file-read* (subpath …))` **succeeded**, and a matching leaf deny refused it.
#[test]
fn a_refusal_denies_every_leaf_a_cell_can_grant() {
    let (directory, config) = fixed_config();
    let refused = directory.path().join("home").join("private");
    std::fs::create_dir(&refused).expect("the refused directory");
    let config = config.refuse(&refused, Scope::Root).expect("a refusal");
    let profile = generate_seatbelt_profile(&config).expect("the profile renders");
    let rules = rules(&profile);
    let path = refused
        .canonicalize()
        .expect("the refused path resolves")
        .display()
        .to_string();

    // `file-read-data` is the enumeration leaf a `Read`+`Dir` grant carries, and it is the one this
    // cell was missing.
    for leaf in [
        "file-read-data",
        "file-read-metadata",
        "file-write-data",
        "file-write-create",
        "file-write-unlink",
        "file-write-xattr",
        "file-write-mode",
        "file-write-times",
    ] {
        assert!(
            rules.contains(&format!("(deny {leaf} (subpath \"{path}\"))")),
            "a refusal must name {leaf}, or a leaf allow inside it wins: {rules}"
        );
    }
    // The wildcards stay, so a leaf no cell grants today is still refused.
    for wildcard in ["file-read*", "file-write*"] {
        assert!(
            rules.contains(&format!("(deny {wildcard} (subpath \"{path}\"))")),
            "a refusal keeps its {wildcard} deny for the leaves no cell names: {rules}"
        );
    }
}

// ── Recorded shapes ──────────────────────────────────────────────────────────────────

/// Where a recorded profile lives, one file per composed shape.
fn golden_directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// The proxy and telemetry ports every composed shape connects to.
const SHAPE_PORTS: [u16; 2] = [51_234, 51_235];

/// Every path one composed shape is built from.
///
/// The layout follows the box's own: an operator home holding a box directory with its home, alias
/// images, broker socket, trust bundle and private state; a project holding the box's own authority
/// files; stand-ins for the operating-system paths the box's floor names; and the programs a shape
/// starts.
struct ShapeFixture {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    operator_home: std::path::PathBuf,
    box_root: std::path::PathBuf,
    project: std::path::PathBuf,
    box_toml: std::fs::File,
    policy: std::fs::File,
    trust_bundle: std::fs::File,
}

impl ShapeFixture {
    fn new() -> Self {
        // `/var/tmp`, not `$TMPDIR`: the broker socket is bound at a path that must fit a
        // `sockaddr_un`, and the macOS `$TMPDIR` alone is most of that budget.
        let directory = tempfile::Builder::new()
            .prefix("shape")
            .tempdir_in("/var/tmp")
            .expect("a fixture directory");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical fixture root");
        if let Ok(spellings) = containment::test_support::operator_home_spellings() {
            assert!(
                !spellings.iter().any(|home| root.starts_with(home)),
                "this fixture must sit outside the operator home: {}",
                root.display()
            );
        }
        let file = |path: &std::path::Path, contents: &str| {
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("parent directories");
            std::fs::write(path, contents).expect("a fixture file");
        };
        let operator_home = root.join("operator");
        let box_root = operator_home.join(".strands-box/b/box-0123");
        for alias in ["zsh", "bash", "python3", "python", "demo"] {
            file(&box_root.join("bin").join(alias), "alias");
        }
        std::fs::create_dir_all(box_root.join("home")).expect("the box home");
        std::fs::create_dir_all(box_root.join("private")).expect("the private state");
        socket_fixture(&box_root.join("run/box.sock"));
        file(&box_root.join("trust/ca.pem"), TRUST_BUNDLE_PEM);
        file(
            &operator_home.join(".gitconfig"),
            "[user]\n\tname = operator\n",
        );

        let project = root.join("project");
        file(&project.join(".strands-box/box.toml"), "box_dir = \"/b\"\n");
        file(&project.join(".strands-box/policy.dw"), "// policy\n");
        file(&project.join("src/main.rs"), "fn main() {}\n");

        for program in ["claude", "codex", "git"] {
            file(&root.join("tools").join(program), "program");
        }
        for tool in [
            "Developer/usr/bin/git",
            "Developer/usr/bin/clang",
            "Developer/usr/libexec/git-core/git-remote-https",
            "usr/bin/xcrun",
            "usr/bin/env",
        ] {
            file(&root.join("host").join(tool), "tool");
        }
        std::fs::create_dir_all(root.join("host/System/Library")).expect("a system tree");
        std::fs::create_dir_all(root.join("host/Library/Frameworks")).expect("a framework tree");

        file(&root.join("os/localtime"), "UTC");
        for tree in ["os/icu", "os/zoneinfo", "os/etc", "os/var", "os/tmp"] {
            std::fs::create_dir_all(root.join(tree)).expect("an operating-system tree");
        }

        let open =
            |path: std::path::PathBuf| std::fs::File::open(path).expect("an opened authority");
        Self {
            box_toml: open(project.join(".strands-box/box.toml")),
            policy: open(project.join(".strands-box/policy.dw")),
            trust_bundle: open(box_root.join("trust/ca.pem")),
            _directory: directory,
            root,
            operator_home,
            box_root,
            project,
        }
    }

    /// The grants every box makes before the floor: the program, its home, and the port pair.
    fn start(&self, program: &str) -> ContainmentConfig {
        let home = self.box_root.join("home");
        ContainmentConfig::new()
            .set_network(Network::Localhost {
                connect: SHAPE_PORTS.to_vec(),
                listen: Vec::new(),
            })
            .expect("the port pair")
            .allow(
                self.root.join("tools").join(program),
                Operation::Exec,
                Scope::File,
            )
            .expect("the program")
            .allow(&home, Operation::Read, Scope::Root)
            .expect("the box home")
            .allow(&home, Operation::Write, Scope::Root)
            .expect("the box home")
    }

    /// One exec literal per alias image the box lays down.
    fn aliases(&self, config: ContainmentConfig, names: &[&str]) -> ContainmentConfig {
        names.iter().fold(config, |config, name| {
            config
                .allow(
                    self.box_root.join("bin").join(name),
                    Operation::Exec,
                    Scope::File,
                )
                .expect("an alias")
        })
    }

    /// The floor every box states: the operating-system cells, then one denial per harness
    /// directory, anchored at the operator home.
    fn floor(&self, config: ContainmentConfig) -> ContainmentConfig {
        let os = self.root.join("os");
        let cells: [(std::path::PathBuf, Operation, Scope); 9] = [
            ("/dev/null".into(), Operation::Read, Scope::File),
            (os.join("localtime"), Operation::Read, Scope::File),
            ("/".into(), Operation::Read, Scope::Dir),
            (os.join("icu"), Operation::Read, Scope::Root),
            (os.join("zoneinfo"), Operation::Read, Scope::Root),
            (os.join("etc"), Operation::Metadata, Scope::Dir),
            (os.join("var"), Operation::Metadata, Scope::Dir),
            (os.join("tmp"), Operation::Metadata, Scope::Root),
            ("/dev/null".into(), Operation::Write, Scope::File),
        ];
        let config = cells.into_iter().fold(
            config.anchored_at(&self.operator_home),
            |config, (path, operation, scope)| {
                config.allow(path, operation, scope).expect("a floor cell")
            },
        );
        [".claude", ".codex", ".kiro", ".agents"]
            .into_iter()
            .fold(config, |config, directory| {
                config
                    .refuse(self.operator_home.join(directory), Scope::Root)
                    .expect("a harness denial")
            })
    }

    /// The broker route and the gateway's trust bundle.
    fn attachment(&self, config: ContainmentConfig) -> ContainmentConfig {
        let trust = self.box_root.join("trust/ca.pem");
        config
            .allow(
                self.box_root.join("run/box.sock"),
                Operation::Connect,
                Scope::File,
            )
            .expect("the broker socket")
            .allow(&trust, Operation::Read, Scope::File)
            .expect("the trust bundle")
            .protect_write(&trust, &self.trust_bundle)
            .expect("the trust bundle keeps its identity")
    }

    /// The box's own authority files keep their identity, and stay unwritable under a write root.
    fn authorities(&self, config: ContainmentConfig, writable: bool) -> ContainmentConfig {
        let authority = self.project.join(".strands-box");
        [
            (authority.join("box.toml"), &self.box_toml),
            (authority.join("policy.dw"), &self.policy),
        ]
        .into_iter()
        .fold(config, |config, (path, opened)| {
            let config = config
                .require_file_identity(&path, opened)
                .expect("an identity requirement");
            if writable {
                config
                    .protect_write(&path, opened)
                    .expect("a write protection")
            } else {
                config
            }
        })
    }

    /// The agent box of `claude-code-workload` and `codex-cli-workload`: no `[agent]` list, so the
    /// project is entered and not read.
    fn bare_agent(&self, program: &str) -> ContainmentConfig {
        let config = self
            .start(program)
            .allow(&self.project, Operation::Read, Scope::Dir)
            .expect("the project entry");
        let config = self.aliases(config, &["zsh", "bash", "python3", "python"]);
        let config = self.floor(config);
        let config = self.attachment(config);
        self.authorities(config, false)
    }

    /// The agent box of `codex-cli-mcp-workload`: a `write` entry naming the workspace, and one
    /// MCP alias.
    fn agent_with_a_writable_workspace(&self) -> ContainmentConfig {
        let config = self.start("codex");
        let config = self.aliases(config, &["zsh", "bash", "python3", "python", "demo"]);
        let config = self
            .floor(config)
            .refuse(self.project.join(".strands-box"), Scope::Root)
            .expect("the project's own authority is subtracted")
            .allow(&self.project, Operation::Read, Scope::Root)
            .expect("the write entry reads")
            .allow(&self.project, Operation::Write, Scope::Root)
            .expect("the write entry writes");
        let config = self.attachment(config);
        self.authorities(config, true)
    }

    /// A tool's leaf box: a writable workspace, the trust bundle, home discovery without the box
    /// directory, broad exec, and the runtime services.
    fn leaf_with_a_writable_workspace(&self) -> ContainmentConfig {
        let trust = self.box_root.join("trust/ca.pem");
        self.floor(self.start("git"))
            .refuse(self.project.join(".strands-box"), Scope::Root)
            .expect("the project's own authority is subtracted")
            .allow(&self.project, Operation::Read, Scope::Root)
            .expect("the write entry reads")
            .allow(&self.project, Operation::Write, Scope::Root)
            .expect("the write entry writes")
            .allow(&trust, Operation::Read, Scope::File)
            .expect("the trust bundle")
            .protect_write(&trust, &self.trust_bundle)
            .expect("the trust bundle keeps its identity")
            .allow_discovery(&self.operator_home)
            .deny_discovery(&self.box_root)
            .allow_broad_exec()
            .allow_runtime_services()
    }
}

/// The quoted path of a rule, or nothing for a line that carries none.
fn quoted_path(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let end = start + line[start..].find('"')?;
    Some(&line[start..end])
}

/// The rendered profile with what the HOST decides taken out, so one recording holds on every host.
///
/// Three parts of a profile are the host's rather than the configuration's: the passwd home and
/// its credential-store rows, and the ancestors of the fixture root that an identity requirement
/// lists. Each is removed by name, and each removal is checked, so a missing rule is a failure
/// rather than a normalization.
fn normalized(profile: &str, root: &std::path::Path) -> String {
    let passwd_home =
        containment::test_support::passwd_home_for_test().expect("this host reports a passwd home");
    let stores = containment::test_support::credential_store_paths().expect("credential stores");
    let identity_heading = "; Metadata and existence lookup for identity-checked files";

    let mut kept: Vec<&str> = Vec::new();
    let mut removed_stores: std::collections::BTreeSet<&std::path::Path> =
        std::collections::BTreeSet::new();
    let mut in_identity_block = false;
    for line in profile.lines() {
        if line.starts_with(identity_heading) {
            in_identity_block = true;
        } else if in_identity_block && line.starts_with(';') {
            in_identity_block = false;
        }
        let quoted = quoted_path(line).map(std::path::Path::new);
        if let Some(store) = quoted.and_then(|path| stores.iter().find(|store| *store == path)) {
            removed_stores.insert(store);
            continue;
        }
        if in_identity_block && quoted.is_some_and(|path| path != root && root.starts_with(path)) {
            continue;
        }
        kept.push(line);
    }
    assert_eq!(
        removed_stores.len(),
        stores.len(),
        "every credential store under the passwd home renders an existence deny"
    );
    let mut text = kept.join("\n");
    text.push('\n');
    text.replace(&root.display().to_string(), "{ROOT}")
        .replace(&passwd_home.display().to_string(), "{PASSWD_HOME}")
}

/// Render one shape and hold it to its recording, or record it when asked to.
fn assert_matches_recording(name: &str, root: &std::path::Path, config: &ContainmentConfig) {
    let profile = generate_seatbelt_profile(config).expect("the shape renders");
    let actual = normalized(&profile, root);
    let path = golden_directory().join(name);
    if std::env::var_os("STRANDS_BOX_CONTAINMENT_RECORD_GOLDEN").is_some() {
        std::fs::write(&path, &actual).expect("the recording is written");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no recording at {}: {error}", path.display()));
    if actual != expected {
        let first_difference = actual
            .lines()
            .zip(expected.lines())
            .position(|(left, right)| left != right)
            .map_or_else(
                || "the two differ only in length".to_string(),
                |index| {
                    format!(
                        "line {}:\n  rendered: {}\n  recorded: {}",
                        index + 1,
                        actual.lines().nth(index).unwrap_or_default(),
                        expected.lines().nth(index).unwrap_or_default()
                    )
                },
            );
        panic!(
            "{name}: the rendered profile differs from its recording at {first_difference}\n\
             rendered profile:\n{actual}"
        );
    }
}

/// **Every shape a caller composes today renders byte for byte what it rendered before.**
///
/// Two shapes: the agent box of the two shipped examples, and the agent box of the MCP example
/// with its writable workspace. The recordings under `tests/golden/` were made
/// by the renderer before the vocabulary gained its three cells, so a change to any existing cell's
/// rules fails here by name. Set `STRANDS_BOX_CONTAINMENT_RECORD_GOLDEN=1` to record again, and
/// say in the commit why the bytes moved.
#[test]
fn every_composed_shape_renders_byte_for_byte_what_it_rendered_before() {
    let fixture = ShapeFixture::new();
    for (name, config) in [
        ("agent-claude-code.sb", fixture.bare_agent("claude")),
        ("agent-codex-cli.sb", fixture.bare_agent("codex")),
        (
            "agent-codex-cli-mcp.sb",
            fixture.agent_with_a_writable_workspace(),
        ),
    ] {
        assert_matches_recording(name, &fixture.root, &config);
    }
}

/// A leaf with discovery, broad exec, runtime services, and a write root renders its recording.
#[test]
fn a_leaf_shape_renders_byte_for_byte_what_it_rendered_before() {
    let fixture = ShapeFixture::new();
    assert_matches_recording(
        "leaf-writable-workspace.sb",
        &fixture.root,
        &fixture.leaf_with_a_writable_workspace(),
    );
}

// ── The three cells added on 2026-09-19 ──────────────────────────────────────────────

/// **`List` at `Root` renders directory reads and no regular file's data.**
///
/// Metadata over the subtree, so an entry can be stat'd, and the data operation on directory
/// vnodes alone, so `readdir` succeeds where `read` does not. The recording is the whole profile,
/// normalized as the composed shapes are.
#[test]
fn list_at_root_renders_directory_reads_and_no_file_data() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let listed = root.join("listed");
    std::fs::create_dir_all(listed.join("nested")).expect("a listed tree");
    std::fs::write(listed.join("nested/notes.txt"), "bytes").expect("a file inside it");
    let config = config
        .allow(&listed, Operation::List, Scope::Root)
        .expect("a list grant at root scope");

    let profile = generate_seatbelt_profile(&config).expect("the list cell renders");
    let rules = rules(&profile);
    let path = listed.display().to_string();
    assert!(
        rules.contains(&format!(
            "(allow file-read-data (require-all (subpath \"{path}\") (vnode-type DIRECTORY)))"
        )),
        "enumeration is the data operation on directory vnodes alone: {rules}"
    );
    assert!(
        rules.contains(&format!("(allow file-read-metadata (subpath \"{path}\"))")),
        "every entry under the tree can be stat'd: {rules}"
    );
    assert!(
        rules.contains(&format!(
            "(allow file-read-metadata (path-ancestors \"{path}\"))"
        )),
        "a lookup reaches the tree through its ancestors: {rules}"
    );
    for widening in [
        format!("(allow file-read* (subpath \"{path}\"))"),
        format!("(allow file-read-data (subpath \"{path}\"))"),
        format!("(allow file-read* (literal \"{path}\"))"),
    ] {
        assert!(
            !rules.contains(&widening),
            "a list grant must not read a regular file's bytes: {widening}"
        );
    }
    assert_matches_recording("cell-list-root.sb", &root, &config);
}

/// **`Deny` at `File` renders a deny on the literal, whether or not the file exists.**
///
/// Both an existing file and a future one under the granted home render the same rule set on the
/// literal alone, so the rest of the home stays reachable and the one file does not.
#[test]
fn a_file_refusal_renders_a_deny_on_the_literal_whether_or_not_it_exists() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let present = root.join("home/secrets.env");
    std::fs::write(&present, "TOKEN=1").expect("an existing file");
    let future = root.join("home/not-yet-written.env");
    assert!(
        !future.exists(),
        "the fixture must not create the future file"
    );
    let config = config
        .refuse(&present, Scope::File)
        .expect("an existing file is refused")
        .refuse(&future, Scope::File)
        .expect("a future file is refused");

    let profile = generate_seatbelt_profile(&config).expect("the file refusals render");
    let rules = rules(&profile);
    for refused in [&present, &future] {
        let path = refused.display().to_string();
        for operation in [
            "file-read*",
            "file-write*",
            "file-read-data",
            "file-read-metadata",
            "file-test-existence",
            "process-exec",
            "file-map-executable",
        ] {
            assert!(
                rules.contains(&format!("(deny {operation} (literal \"{path}\"))")),
                "a file refusal denies {operation} on the literal: {rules}"
            );
        }
        for leaf in containment::test_support::write_root_leaves() {
            assert!(
                rules.contains(&format!("(deny {leaf} (literal \"{path}\"))")),
                "a file refusal denies the write leaf {leaf}, or a leaf allow inside the home wins"
            );
        }
        assert!(
            !rules.contains(&format!("(subpath \"{path}\")")),
            "a file refusal never renders as a tree: {rules}"
        );
    }
    // The denies render after the home's allows, so they win under last-match.
    let last_allow = rules.rfind("(allow file-").expect("the home is granted");
    let first_deny = rules
        .find(&format!(
            "(deny file-read* (literal \"{}\"))",
            present.display()
        ))
        .expect("the refusal renders");
    assert!(
        first_deny > last_allow,
        "a file refusal must render after every allow: {rules}"
    );
    assert_matches_recording("cell-deny-file.sb", &root, &config);
}

/// **`Exec` at `Root` renders `process-exec` over the subpath with its paired metadata read.**
///
/// The subtree's metadata is what lets a `PATH` search stat a candidate, and no `file-read*` comes
/// with it: a program's bytes stay unreadable under a tree as they do under one literal.
#[test]
fn exec_at_root_renders_process_exec_on_the_subpath_with_its_metadata_read() {
    let (directory, config) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let tools = root.join("tools");
    std::fs::create_dir_all(tools.join("bin")).expect("an exec tree");
    std::fs::write(tools.join("bin/format"), "program").expect("a program inside it");
    let config = config
        .allow(&tools, Operation::Exec, Scope::Root)
        .expect("an exec grant at root scope");

    let profile = generate_seatbelt_profile(&config).expect("the exec tree renders");
    let rules = rules(&profile);
    let path = tools.display().to_string();
    assert!(
        rules.contains(&format!("(allow process-exec (subpath \"{path}\"))")),
        "every program under the tree runs: {rules}"
    );
    assert!(
        rules.contains(&format!("(allow file-read-metadata (subpath \"{path}\"))")),
        "a lookup stats its way to each program: {rules}"
    );
    assert!(
        rules.contains(&format!(
            "(allow file-read-metadata (path-ancestors \"{path}\"))"
        )),
        "and reaches the tree through its ancestors: {rules}"
    );
    assert!(
        !rules.contains(&format!("(allow file-read* (subpath \"{path}\"))"))
            && !rules.contains(&format!("(allow file-read-data (subpath \"{path}\"))")),
        "a program's bytes stay unreadable under an exec tree: {rules}"
    );
    assert!(
        !rules.contains("process-exec*"),
        "an exec tree is one subpath rule and never broad exec: {rules}"
    );
    assert_eq!(
        rules.matches("(allow process-exec ").count(),
        2,
        "the fixture's one literal and the tree render one exec rule each: {rules}"
    );
    assert_matches_recording("cell-exec-root.sb", &root, &config);
}

// ── The write-plus-exec floor, demoted ───────────────────────────────────────────────

/// **A write-plus-exec grant set validates, renders, and yields the warning.**
///
/// Four shapes carry the pair: an exec literal inside a write root, an exec tree inside a write
/// root, a write root inside an exec tree, and one file granted both. Each clears every floor,
/// renders an executable-mapping allow after the write cell's deny so the exec is not defeated under
/// last-match, and reports exactly the pair in `warnings`. The control is a disjoint pair, which
/// warns of nothing.
#[test]
fn a_write_plus_exec_grant_set_validates_renders_and_yields_the_warning() {
    let (directory, base) = fixed_config();
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let home = root.join("home");
    let inside = home.join("built");
    std::fs::write(&inside, "built").expect("a program the workload builds");
    let output = home.join("target");
    std::fs::create_dir_all(output.join("debug")).expect("build output");
    let tools = root.join("tools");
    std::fs::create_dir_all(tools.join("cache")).expect("an exec tree with a writable corner");
    let device = root.join("device");
    std::fs::write(&device, "device").expect("one file granted both");

    let cache = tools.join("cache");
    let literal = |path: &std::path::Path| format!("(literal \"{}\")", path.display());
    let subpath = |path: &std::path::Path| format!("(subpath \"{}\")", path.display());
    /// One shape of the pair: the write cell's deny, the carve-out that must follow it, and the
    /// two paths the warning names.
    struct Pair<'a> {
        label: &'a str,
        config: ContainmentConfig,
        denied: String,
        carved: String,
        executable: &'a std::path::Path,
        writable: &'a std::path::Path,
    }
    let cases = [
        Pair {
            label: "an exec literal inside the write root",
            config: base
                .clone()
                .allow(&inside, Operation::Exec, Scope::File)
                .expect("the pair is well formed"),
            denied: subpath(&home),
            carved: literal(&inside),
            executable: &inside,
            writable: &home,
        },
        Pair {
            label: "an exec tree inside the write root",
            config: base
                .clone()
                .allow(&output, Operation::Exec, Scope::Root)
                .expect("the pair is well formed"),
            denied: subpath(&home),
            carved: subpath(&output),
            executable: &output,
            writable: &home,
        },
        Pair {
            label: "a write root inside an exec tree",
            config: base
                .clone()
                .allow(&tools, Operation::Exec, Scope::Root)
                .expect("the tree")
                .allow(&cache, Operation::Write, Scope::Root)
                .expect("the pair is well formed"),
            denied: subpath(&cache),
            carved: subpath(&cache),
            executable: &tools,
            writable: &cache,
        },
        Pair {
            label: "one file granted write and exec",
            config: base
                .clone()
                .allow(&device, Operation::Exec, Scope::File)
                .expect("the exec")
                .allow(&device, Operation::Write, Scope::File)
                .expect("the pair is well formed"),
            denied: literal(&device),
            carved: literal(&device),
            executable: &device,
            writable: &device,
        },
    ];
    for Pair {
        label,
        config,
        denied,
        carved,
        executable,
        writable,
    } in cases
    {
        let profile = generate_seatbelt_profile(&config)
            .unwrap_or_else(|error| panic!("{label}: the pair must clear every floor: {error}"));
        let rules = rules(&profile);
        let deny = rules
            .find(&format!("(deny file-map-executable {denied})"))
            .unwrap_or_else(|| panic!("{label}: the write cell denies the mapping: {rules}"));
        let allow = rules
            .find(&format!("(allow file-map-executable {carved})"))
            .unwrap_or_else(|| panic!("{label}: the carve-out must render: {rules}"));
        assert!(
            allow > deny,
            "{label}: the mapping allow must follow the write cell's deny it carves: {rules}"
        );
        let warnings = config.warnings();
        assert_eq!(
            warnings.len(),
            1,
            "{label}: one pair, one warning: {warnings:?}"
        );
        assert_eq!(
            warnings[0],
            containment::ContainmentWarning::WritableAndExecutable {
                executable: executable.to_path_buf(),
                writable: writable.to_path_buf(),
            },
            "{label}: the warning names the pair"
        );
        let text = warnings[0].to_string();
        assert!(
            text.contains("both writable and executable")
                && text.contains("replace a program it is authorized to run"),
            "{label}: the warning says what the pair costs: {text}"
        );
    }

    // The control: the fixture's own program sits beside the home, so nothing warns.
    generate_seatbelt_profile(&base).expect("the fixture renders");
    assert!(
        base.warnings().is_empty(),
        "a disjoint pair warns of nothing: {:?}",
        base.warnings()
    );
}
