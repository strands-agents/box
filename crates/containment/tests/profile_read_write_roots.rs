//! The read-write root SET, rendered — and this file is **deliberately not macOS-gated**.
//!
//! `containment/AGENTS.md` says the conformance suite "runs it on every platform, so a rule added
//! to `seatbelt-agent.sb` fails CI wherever CI runs". **That was not true when this file was
//! written**: `profile_conformance.rs`, `backend_seatbelt.rs`, and `contains_exec_target.rs` all
//! carry `#![cfg(target_os = "macos")]`, so every Seatbelt profile assertion was skipped on
//! Linux — silently, as a pass.
//!
//! The renderer is pure string work over a checked-in profile and needs no macOS kernel, so this
//! file runs everywhere and closes that gap for the rules it covers. A change to the read-write
//! blocks now fails on either platform.
//!
//! It does **not** replace the macOS-gated suites: the census, the trust-bundle content check, and
//! every kernel-level enforcement test still only run there.

const TRUST_BUNDLE_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

use containment::{ContainmentConfig, Network, Operation, Scope};

// ── The read-write root SET ─────────────────────────────────────────────────────
//
// It was one root, and became a set when the box shared the operator's home. That box-side design
// was reversed and `strands-box` composes one root again — but these tests are about the RENDERER,
// which still supports a set because this crate is a library. They pin what distinguishes a set
// from a repeated singular slot, and that is worth keeping whatever any one caller composes.

/// **Several read-write roots render, and each keeps its own denies.**
///
/// Rendering the grants but dropping the identity denies would leave every root replaceable by
/// a symlink, which is the escape the singular slot's two denies exist to close. Dropping the
/// flags deny would let a workload wedge every root against the operator's own cleanup. A set
/// has to carry all three per root, not once.
#[test]
fn every_read_write_root_renders_with_its_own_identity_denies() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let writable: Vec<_> = ["codex", "claude", "scratch"]
        .iter()
        .map(|name| {
            let path = root.join(name);
            std::fs::create_dir(&path).expect("a read-write root");
            path
        })
        .collect();

    let mut config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");
    for path in &writable {
        config = config
            .allow(path, Operation::Read, Scope::Root)
            .expect("a read-write root is expressible")
            .allow(path, Operation::Write, Scope::Root)
            .expect("a read-write root is expressible");
    }

    let profile = containment::test_support::generate_seatbelt_profile(&config)
        .expect("three read-write roots render");

    for path in &writable {
        let shown = path.display();
        for expected in [
            format!("(allow file-read* (subpath \"{shown}\"))"),
            format!("(allow file-write-data (subpath \"{shown}\"))"),
            format!("(allow file-write-create (subpath \"{shown}\"))"),
            format!("(allow file-write-unlink (subpath \"{shown}\"))"),
            format!("(allow file-write-xattr (subpath \"{shown}\"))"),
            format!("(allow file-write-mode (subpath \"{shown}\"))"),
            format!("(allow file-write-times (subpath \"{shown}\"))"),
            format!("(deny file-write-unlink (literal \"{shown}\"))"),
            format!("(deny file-write-create (literal \"{shown}\"))"),
            format!("(deny file-map-executable (subpath \"{shown}\"))"),
        ] {
            assert!(
                profile.contains(&expected),
                "every read-write root must render its own rules, missing: {expected}"
            );
        }
        // The flags, the access-control list and the owner are withheld per root, not denied.
        for withheld in [
            format!("(allow file-write-flags (subpath \"{shown}\"))"),
            format!("(allow file-write-acl (subpath \"{shown}\"))"),
            format!("(allow file-write-owner (subpath \"{shown}\"))"),
        ] {
            assert!(
                !profile.contains(&withheld),
                "no read-write root may grant path authority, present: {withheld}"
            );
        }
    }
}

#[test]
fn an_exempted_credential_read_root_can_contain_its_write_root() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let operator_home = root.join("operator");
    let outer = operator_home.join(".aws");
    let inner = outer.join("sso/cache");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir_all(&inner).expect("the nested roots");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .anchored_at(&operator_home)
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow_credential_store(&outer, Operation::Read, Scope::Root)
        .expect("the credential read root");
    #[cfg(target_os = "linux")]
    let config = config
        .allow_credential_store(&inner, Operation::Read, Scope::Root)
        .expect("Linux states the read authority its writable bind carries");
    let config = config
        .allow_credential_store(&inner, Operation::Write, Scope::Root)
        .expect("the credential write root")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");

    let profile = containment::test_support::generate_seatbelt_profile(&config)
        .expect("the explicit nested operations render");
    assert!(profile.contains(&format!(
        "(allow file-read* (subpath \"{}\"))",
        outer.display()
    )));
    assert!(profile.contains(&format!(
        "(allow file-write-data (subpath \"{}\"))",
        inner.display()
    )));
    assert!(
        !profile.contains(&format!(
            "(allow file-write-data (subpath \"{}\"))",
            outer.display()
        )),
        "the nested write grant must not widen to the outer read root"
    );
}

/// **A read-write root inside another is refused.**
///
/// The union is the outer root, so the inner grant enforces nothing it appears to — and a
/// reader of the config would predict a boundary that is not there. Both grants are
/// well-formed on their own, which is why this is refused rather than left to the caller.
#[test]
fn a_read_write_root_inside_another_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let outer = root.join("outer");
    let inner = outer.join("inner");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::create_dir_all(&inner).expect("the nested roots");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .allow(&outer, Operation::Read, Scope::Root)
        .expect("the outer root")
        .allow(&outer, Operation::Write, Scope::Root)
        .expect("the outer root")
        .allow(&inner, Operation::Read, Scope::Root)
        .expect("the inner root is well-formed on its own")
        .allow(&inner, Operation::Write, Scope::Root)
        .expect("the inner root is well-formed on its own")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");

    let error = containment::test_support::generate_seatbelt_profile(&config)
        .expect_err("two nested read-write roots must be refused");
    assert!(
        error.to_string().contains("lies inside the write root"),
        "the refusal must name the nesting: {error}"
    );
}

/// A config with no read-write root at all still renders.
#[test]
fn no_read_write_root_still_renders() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port");

    containment::test_support::generate_seatbelt_profile(&config)
        .expect("a workload with nowhere to write still renders");
}

// ── The traverse-only root ──────────────────────────────────────────────────────
//
// **`Read` at `Dir` scope is the one cell whose macOS rendering cannot be checked on macOS
// hardware here**, so these two tests are the only coverage of it until someone runs the suite on a
// Mac. The renderer is pure string work over a checked-in profile, so they are worth as much as a
// macOS run for the *text*, and nothing for the kernel's interpretation of it.

/// **A traverse-only root renders metadata on its literal and its ancestors, plus enumeration.**
///
/// The ancestors are what let `chdir` succeed: resolving a path walks each component and stats it.
/// The literal is what the workload stands in.
#[test]
fn a_traverse_root_renders_metadata_on_the_literal_and_its_ancestors() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    let home = root.join("home");
    let project = root.join("project");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");
    std::fs::create_dir(&home).expect("a read-write root");
    std::fs::create_dir(&project).expect("the project");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("the box home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("the box home")
        .allow(&project, Operation::Read, Scope::Dir)
        .expect("a traverse-only root is expressible");

    let profile = containment::test_support::generate_seatbelt_profile(&config)
        .expect("a traverse root renders");
    let shown = project.display();

    for expected in [
        format!("(allow file-read-metadata (path-ancestors \"{shown}\"))"),
        format!("(allow file-read-metadata (literal \"{shown}\"))"),
        format!("(allow file-read-data (literal \"{shown}\"))"),
    ] {
        assert!(
            profile.contains(&expected),
            "a traverse root must render its metadata rules, missing: {expected}"
        );
    }
}

/// **A traverse-only root renders no DESCENDANT read and no write, which is the whole property.**
///
/// The literal is enumerable; nothing under it is granted, so every read of a file there is an
/// interpreter request policy decides instead.
///
/// Asserted as an absence, because the failure mode is an *extra* rule rather than a missing one.
/// Each read operation is named individually, not only the wildcard.
#[test]
fn a_traverse_root_renders_no_descendant_read_and_no_write() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().canonicalize().expect("canonical tempdir");
    let executable = root.join("agent");
    let trust_bundle = root.join("proxy-ca.pem");
    let home = root.join("home");
    let project = root.join("project");
    std::fs::write(&executable, "agent").expect("executable fixture");
    std::fs::write(&trust_bundle, TRUST_BUNDLE_PEM).expect("trust fixture");
    std::fs::create_dir(&home).expect("a read-write root");
    std::fs::create_dir(&project).expect("the project");

    let config = ContainmentConfig::new()
        .allow(&executable, Operation::Exec, Scope::File)
        .expect("exact executable")
        .allow(&trust_bundle, Operation::Read, Scope::File)
        .expect("exact trust bundle")
        .set_network(Network::localhost().connect(43123))
        .expect("exact proxy port")
        .allow(&home, Operation::Read, Scope::Root)
        .expect("the box home")
        .allow(&home, Operation::Write, Scope::Root)
        .expect("the box home")
        .allow(&project, Operation::Read, Scope::Dir)
        .expect("a traverse-only root is expressible");

    let profile = containment::test_support::generate_seatbelt_profile(&config)
        .expect("a traverse root renders");
    let shown = project.display();

    let mut forbidden = vec![
        format!("(allow file-read* (subpath \"{shown}\"))"),
        format!("(allow file-read-data (subpath \"{shown}\"))"),
        format!("(allow file-read-metadata (subpath \"{shown}\"))"),
        format!("(allow file-write* (subpath \"{shown}\"))"),
        format!("(allow process-exec (literal \"{shown}\"))"),
    ];
    // **Every write leaf, derived from the renderer's own list rather than copied.** This test is the
    // pin for "no write rule of any kind lands on a non-writable path", and it is an absence
    // assertion, so naming one leaf while the cell grants six leaves five holes open. Both spellings,
    // because the root cell renders `subpath` and the file cell renders `literal`.
    for leaf in containment::test_support::write_root_leaves() {
        forbidden.push(format!("(allow {leaf} (subpath \"{shown}\"))"));
        forbidden.push(format!("(allow {leaf} (literal \"{shown}\"))"));
    }
    // Every write-cell rule belongs to the write cells and nowhere else. A path with no write leaf
    // cannot reach any of these operations at all, because the profile denies by default — so a deny
    // here would enforce zero while reading like a control. The executable-mapping deny would do
    // worse than enforce zero: on a path a workload cannot write, refusing the mapping only removes
    // a library load that write-xor-exec has no reason to touch.
    //
    // **Both spellings for every verb**, because the two write cells disagree about which they use:
    // the root cell renders `subpath` and the file cell renders `literal`. One spelling per verb
    // leaves the other injectable. The three path-authority verbs are here too: no cell renders a
    // deny for them any more, so an assertion that one appeared would catch a return to the old
    // shape.
    for verb in [
        "file-write-flags",
        "file-write-acl",
        "file-write-owner",
        "file-write-mode",
        "file-write-unlink",
        "file-write-create",
        "file-map-executable",
    ] {
        forbidden.push(format!("(deny {verb} (subpath \"{shown}\"))"));
        forbidden.push(format!("(deny {verb} (literal \"{shown}\"))"));
    }
    for forbidden in forbidden {
        assert!(
            !profile.contains(&forbidden),
            "a traverse root grants presence only; it must not render: {forbidden}"
        );
    }

    // The control: the read-write root in the same profile DOES render its read, so the absence
    // above is the traverse mode rather than the renderer emitting nothing at all.
    assert!(
        profile.contains(&format!(
            "(allow file-read* (subpath \"{}\"))",
            home.display()
        )),
        "the read-write root must still render its read, or this test proves nothing: {profile}"
    );
}
