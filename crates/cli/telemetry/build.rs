//! The shipped pack catalog.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    pack_catalog(&manifest, &out);
}

fn pack_catalog(manifest: &Path, out: &Path) {
    let shared = manifest
        .ancestors()
        .nth(3)
        .expect("the crate is in the workspace")
        .join("resources/packs");
    println!("cargo:rerun-if-changed={}", shared.display());
    let mut packs: Vec<_> = std::fs::read_dir(&shared)
        .unwrap_or_else(|error| panic!("read {}: {error}", shared.display()))
        .map(|entry| entry.expect("a resource entry"))
        .filter(|entry| entry.path().is_dir())
        .collect();
    packs.sort_by_key(|entry| entry.file_name());
    let ids: Vec<_> = packs
        .iter()
        .map(|entry| entry.file_name().into_string().expect("a pack ID is UTF-8"))
        .collect();
    assert!(ids.len() <= 64, "the telemetry pack catalog exceeds 64 IDs");
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    for id in &ids {
        assert!(
            (1..=32).contains(&id.len())
                && alphanumeric(id.as_bytes()[0])
                && id.bytes().all(|byte| alphanumeric(byte) || byte == b'-'),
            "the telemetry pack ID {id:?} is outside the schema bounds"
        );
    }
    let mut catalog = String::from("const BUILTIN_PACKS: &[(&str, Fingerprint)] = &[\n");
    for (pack, id) in packs.iter().zip(&ids) {
        let path = pack.path().join("pack.toml");
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let fingerprint: [u8; 32] = Sha256::digest(bytes).into();
        let grammar = pack.path().join("grammar.toml");
        let grammar: Option<[u8; 32]> = match std::fs::read(&grammar) {
            Ok(bytes) => Some(Sha256::digest(bytes).into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read {}: {error}", grammar.display()),
        };
        writeln!(catalog, "    ({id:?}, ({fingerprint:?}, {grammar:?})),").expect("write a string");
    }
    catalog.push_str("];\n");
    let path = out.join("builtin_packs.rs");
    std::fs::write(&path, catalog)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    #[test]
    fn entrypoint_checks_the_shipped_catalog() {
        const CHILD: &str = "BOX_TEST_TELEMETRY_BUILD_SCRIPT";
        const TEST: &str = "build::tests::entrypoint_checks_the_shipped_catalog";
        if std::env::var_os(CHILD).is_some() {
            super::main();
            return;
        }

        let temporary = tempfile::tempdir().unwrap();
        let manifest = temporary.path().join("crates/cli/telemetry");
        let shared = temporary.path().join("resources/packs");
        let out = temporary.path().join("out");
        for directory in [&manifest, &shared, &out] {
            fs::create_dir_all(directory).unwrap();
        }
        let write_pack = |id: &str| {
            let folder = shared.join(id);
            fs::create_dir(&folder).unwrap();
            fs::write(folder.join("pack.toml"), "[pack]\nversion = 1\n").unwrap();
        };
        write_pack("base");
        let override_resources = temporary.path().join("override");
        let override_pack = override_resources.join("packs/override-only");
        fs::create_dir_all(&override_pack).unwrap();
        fs::write(override_pack.join("pack.toml"), "[pack]\nversion = 2\n").unwrap();

        let executable = std::env::current_exe().unwrap();
        let run = || {
            Command::new(&executable)
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, "1")
                .env("CARGO_MANIFEST_DIR", &manifest)
                .env("OUT_DIR", &out)
                .env("BOX_RESOURCES", &override_resources)
                .output()
                .unwrap()
        };
        let valid = run();
        assert!(
            valid.status.success(),
            "{}",
            String::from_utf8_lossy(&valid.stderr)
        );
        let catalog = fs::read_to_string(out.join("builtin_packs.rs")).unwrap();
        let fingerprint: [u8; 32] =
            <sha2::Sha256 as sha2::Digest>::digest("[pack]\nversion = 1\n").into();
        assert!(
            catalog.contains(&format!("(\"base\", ({fingerprint:?}, None))")),
            "{catalog}"
        );
        assert!(!catalog.contains("override-only"), "{catalog}");

        let grammar = shared.join("base/grammar.toml");
        for text in ["version = 1\n", "version = 2\n"] {
            fs::write(&grammar, text).unwrap();
            assert!(run().status.success());
            let with_grammar = fs::read_to_string(out.join("builtin_packs.rs")).unwrap();
            let grammar_fingerprint: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(text).into();
            assert!(with_grammar.contains(&format!(
                "(\"base\", ({fingerprint:?}, Some({grammar_fingerprint:?})))"
            )));
        }
        fs::remove_file(grammar).unwrap();
        assert!(run().status.success());
        assert_eq!(
            fs::read_to_string(out.join("builtin_packs.rs")).unwrap(),
            catalog
        );

        let longest = "a".repeat(32);
        write_pack(&longest);
        assert!(run().status.success());
        fs::remove_dir_all(shared.join(longest)).unwrap();

        for id in [
            "-base",
            "Uppercase",
            "private_customer",
            "café",
            &"a".repeat(33),
        ] {
            write_pack(id);
            let invalid = run();
            assert!(!invalid.status.success(), "{id}");
            assert!(String::from_utf8_lossy(&invalid.stderr).contains("outside the schema bounds"));
            fs::remove_dir_all(shared.join(id)).unwrap();
        }

        for index in 0..63 {
            write_pack(&format!("p{index}"));
        }
        assert!(run().status.success());
        write_pack("p63");
        let too_many = run();
        assert!(!too_many.status.success());
        assert!(String::from_utf8_lossy(&too_many.stderr).contains("exceeds 64 IDs"));
    }
}
