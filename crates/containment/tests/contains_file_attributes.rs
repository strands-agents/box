//! Real apply-then-probe tests for the macOS `file-attributes` switch on a write root, through the
//! `utimensat` and `setattrlist` routes that `touch` and `cp -p` take.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use containment::{ContainmentConfig, Network, Operation, Scope};

/// The fixtures one test composes its box from.
struct AttributeBox {
    /// Dropping it removes every fixture.
    _fixtures: tempfile::TempDir,
    /// The write root.
    home: PathBuf,
    /// A file inside the write root.
    inside: PathBuf,
    /// A file inside the write root that the box protects from writes.
    protected: PathBuf,
    /// A file in a folder inside the write root that the box refuses.
    refused: PathBuf,
    /// A file in a root the box can read and not write.
    outside: PathBuf,
    config_path: PathBuf,
    probe: PathBuf,
    working_directory: PathBuf,
}

impl AttributeBox {
    fn new(file_attributes: bool) -> Self {
        let fixtures = tempfile::tempdir().expect("fixtures");
        let root = fixtures.path().canonicalize().expect("canonical fixtures");
        let home = root.join("home");
        let readable = root.join("readable");
        std::fs::create_dir(&home).expect("home fixture");
        std::fs::create_dir(&readable).expect("readable fixture");
        let trust_bundle = root.join("proxy-ca.pem");
        std::fs::write(
            &trust_bundle,
            "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n",
        )
        .expect("trust bundle");
        let inside = home.join("inner.txt");
        let protected = home.join("authority");
        let outside = readable.join("outer.txt");
        let refused_folder = home.join("refused");
        std::fs::create_dir(&refused_folder).expect("refused folder fixture");
        let refused = refused_folder.join("secret.txt");
        for file in [&inside, &protected, &outside, &refused] {
            std::fs::write(file, "fixture").expect("a fixture file");
        }
        let opened_protected = std::fs::File::open(&protected).expect("opened protected file");

        let probe = PathBuf::from(env!("CARGO_BIN_EXE_containment-test-probe"));
        let config = ContainmentConfig::new()
            .allow(&probe, Operation::Exec, Scope::File)
            .expect("exact executable")
            .allow(&trust_bundle, Operation::Read, Scope::File)
            .expect("exact trust bundle")
            .allow(&home, Operation::Read, Scope::Root)
            .expect("home read")
            .allow(&home, Operation::Write, Scope::Root)
            .expect("home write")
            .allow(&readable, Operation::Read, Scope::Root)
            .expect("readable root")
            .protect_write(&protected, &opened_protected)
            .expect("protected object")
            .refuse(&refused_folder, Scope::Root)
            .expect("refused folder")
            .set_network(Network::localhost().connect(43127))
            .expect("exact proxy port");
        let config = if file_attributes {
            config.allow_file_attributes()
        } else {
            config
        };
        let config_path = root.join("containment.json");
        std::fs::write(&config_path, config.to_json().expect("config JSON")).expect("write config");

        Self {
            _fixtures: fixtures,
            home,
            inside,
            protected,
            refused,
            outside,
            config_path,
            probe,
            working_directory: root,
        }
    }

    /// Run the probes in the box and require each to behave as demanded.
    fn expect(&self, probes: &[(&str, &str, &Path)]) {
        let mut command = Command::new(&self.probe);
        command.arg(&self.config_path);
        for (expectation, verb, target) in probes {
            command.arg(format!("{expectation}:{verb}:{}", target.display()));
        }
        let output = command
            .current_dir(&self.working_directory)
            .output()
            .expect("spawn containment-test-probe");
        assert_eq!(
            output.status.code(),
            Some(0),
            "every probe must behave as demanded: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Without the switch, `utimes` works and `utimensat` and `setattrlist` times are refused, so
/// `touch` fails.
#[test]
fn without_the_switch_a_write_root_refuses_touch_and_keeps_utimes() {
    let fixture = AttributeBox::new(false);
    fixture.expect(&[
        ("expect-ok", "utimes-old", &fixture.inside),
        ("expect-deny", "utimensat", &fixture.inside),
        ("expect-deny", "utimensat-unseen", &fixture.inside),
        ("expect-deny", "setattrlist-modtime", &fixture.inside),
    ]);
}

/// Without the switch, the set-user-ID bit and a group change are refused through `setattrlist` too.
#[test]
fn without_the_switch_a_write_root_refuses_the_setuid_bit_and_the_group_through_setattrlist() {
    let fixture = AttributeBox::new(false);
    fixture.expect(&[
        ("expect-deny", "setattrlist-setuid", &fixture.inside),
        ("expect-deny", "setattrlist-group", &fixture.inside),
        ("expect-deny", "setattrlist-owner-self", &fixture.inside),
    ]);
}

/// With the switch, the time routes `touch`, `cp -p`, and `tar -x` use succeed on a write root.
#[test]
fn with_the_switch_a_write_root_accepts_touch_and_setattrlist_times() {
    let fixture = AttributeBox::new(true);
    fixture.expect(&[
        ("expect-ok", "utimes-old", &fixture.inside),
        ("expect-ok", "utimensat", &fixture.inside),
        ("expect-ok", "utimensat-unseen", &fixture.inside),
        ("expect-ok", "setattrlist-modtime", &fixture.inside),
    ]);
}

/// With the switch, flags, ACLs, ownership, and the `chmod` set-ID bits stay refused.
#[test]
fn with_the_switch_a_write_root_still_refuses_flags_acls_ownership_and_chmod_setid() {
    let fixture = AttributeBox::new(true);
    fixture.expect(&[
        ("expect-ok", "write", &fixture.inside),
        ("expect-deny", "chflags-uf", &fixture.inside),
        ("expect-deny", "acl", &fixture.inside),
        ("expect-deny", "chown-self", &fixture.inside),
        ("expect-deny", "setuid-bit", &fixture.inside),
        ("expect-deny", "setgid-bit", &fixture.inside),
        ("expect-deny", "setattrlist-finderinfo", &fixture.inside),
    ]);
}

/// With the switch, a protected object, a refused path inside the write root, and a path outside
/// every write root stay unwritable.
#[test]
fn with_the_switch_a_protected_object_a_refused_path_and_an_outside_path_stay_refused() {
    use std::os::unix::fs::MetadataExt as _;

    let fixture = AttributeBox::new(true);
    let refused_time = std::fs::metadata(&fixture.refused)
        .expect("the refused fixture")
        .mtime();
    fixture.expect(&[
        ("expect-deny", "write", &fixture.refused),
        ("expect-deny", "utimensat-unseen", &fixture.refused),
        ("expect-deny", "write", &fixture.protected),
        ("expect-deny", "utimes-old", &fixture.protected),
        ("expect-deny", "utimensat", &fixture.protected),
        ("expect-deny", "setattrlist-modtime", &fixture.protected),
        ("expect-deny", "setattrlist-setuid", &fixture.protected),
        ("expect-deny", "utimensat", &fixture.outside),
        ("expect-deny", "setattrlist-modtime", &fixture.outside),
        ("expect-ok", "utimensat", &fixture.inside),
    ]);
    assert!(fixture.home.join("authority").exists());
    assert_eq!(
        std::fs::metadata(&fixture.refused)
            .expect("the refused fixture")
            .mtime(),
        refused_time,
        "the refused file keeps its time"
    );
}

/// **Residual, pinned.** With the switch, `setattrlist` stores the set-user-ID bit
/// (`ATTR_CMN_ACCESSMASK`), moves the group (`ATTR_CMN_GRPID`), and reaches the owner
/// (`ATTR_CMN_OWNERID`), because no Seatbelt rule separates them from the time attributes. Only
/// the ownership check then limits the owner, so a root process can give a file away.
#[test]
fn with_the_switch_setattrlist_reaches_the_setuid_bit_the_group_and_the_owner_as_known_residuals() {
    let fixture = AttributeBox::new(true);
    fixture.expect(&[
        ("expect-ok", "setattrlist-setuid", &fixture.inside),
        ("expect-ok", "setattrlist-group", &fixture.inside),
        ("expect-ok", "setattrlist-owner-self", &fixture.inside),
    ]);
}
