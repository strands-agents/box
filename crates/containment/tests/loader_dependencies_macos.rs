//! Native startup and build controls for writable dependency chains.
#![cfg(target_os = "macos")]

use containment::{ContainmentConfig, Network, Operation, Scope};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn succeeds(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

fn contained(
    config: &ContainmentConfig,
    directory: &Path,
    command: &Path,
    args: &[&str],
) -> Output {
    let json = config.to_json().unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), json).unwrap();
    Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(directory)
        .arg("--config")
        .arg(file.path())
        .args([
            "--config-sha256",
            &digest,
            "--target-env-json",
            r#"{"PATH":"/usr/bin:/bin"}"#,
            "--",
        ])
        .arg(command)
        .args(args)
        .output()
        .unwrap()
}

fn base(project: &Path) -> ContainmentConfig {
    ContainmentConfig::new()
        .allow(project, Operation::Read, Scope::Root)
        .unwrap()
        .allow(project, Operation::Write, Scope::Root)
        .unwrap()
        .allow("/", Operation::Read, Scope::Dir)
        .unwrap()
        .allow("/etc", Operation::Metadata, Scope::Dir)
        .unwrap()
        .allow("/dev/null", Operation::Read, Scope::File)
        .unwrap()
        .allow("/dev/null", Operation::Write, Scope::File)
        .unwrap()
        .set_network(Network::localhost().connect(43123))
        .unwrap()
}

#[test]
fn native_missing_reads_refuse_startup_and_explicit_reads_restore_execution() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let project = root.join("project");
    std::fs::create_dir(&project).unwrap();
    let codec = root.join("libcodec.dylib");
    let storage = root.join("libstorage.dylib");
    let source = project.join("library.c");
    std::fs::write(&source, "int answer(void) { return 42; }\n").unwrap();
    succeeds(
        Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-o"])
            .arg(&codec)
            .arg(&source),
    );
    std::fs::write(&source, "int stored(void) { return 7; }\n").unwrap();
    succeeds(
        Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-o"])
            .arg(&storage)
            .arg(&source),
    );
    let main = project.join("main.c");
    std::fs::write(&main, "#include <stdio.h>\nextern int answer(void); extern int stored(void); int main(int argc, char **argv) { if (answer() != 42 || stored() != 7) return 1; if (argc > 1) { FILE *f = fopen(argv[1], \"r\"); if (f) return 2; } puts(\"LIBRARIES_RAN_PRIVATE_READ_REFUSED\"); return 0; }\n").unwrap();
    let app = project.join("app");
    succeeds(
        Command::new("/usr/bin/cc")
            .arg(&main)
            .arg(&codec)
            .arg(&storage)
            .arg("-o")
            .arg(&app),
    );
    let note = root.join("operator-note");
    std::fs::write(&note, "SYNTHETIC_PRIVATE_BYTES").unwrap();
    let config = base(&project)
        .allow(&app, Operation::Exec, Scope::File)
        .unwrap();
    let before = contained(&config, &project, &app, &[note.to_str().unwrap()]);
    assert_eq!(before.status.code(), Some(3), "{before:?}");
    let diagnostic = String::from_utf8_lossy(&before.stderr);
    assert!(
        diagnostic.contains("2 dependencies lack read access")
            && diagnostic.contains("libcodec.dylib")
            && diagnostic.contains("libstorage.dylib"),
        "{diagnostic}"
    );
    assert!(before.stdout.is_empty());
    let allowed = config
        .allow(&codec, Operation::Read, Scope::File)
        .unwrap()
        .allow(&storage, Operation::Read, Scope::File)
        .unwrap();
    let after = contained(&allowed, &project, &app, &[note.to_str().unwrap()]);
    assert!(after.status.success(), "{after:?}");
    assert!(String::from_utf8_lossy(&after.stdout).contains("LIBRARIES_RAN_PRIVATE_READ_REFUSED"));

    // An attacker changes a load command to name ordinary operator data, then launches a reader.
    succeeds(
        Command::new("/usr/bin/install_name_tool")
            .arg("-change")
            .arg(&codec)
            .arg(&note)
            .arg(&app),
    );
    let attack = allowed
        .allow("/bin/cat", Operation::Exec, Scope::File)
        .unwrap();
    let blocked = contained(
        &attack,
        &project,
        Path::new("/bin/cat"),
        &[note.to_str().unwrap()],
    );
    assert_eq!(blocked.status.code(), Some(3), "{blocked:?}");
    assert!(
        blocked.stdout.is_empty(),
        "operator bytes exposed: {blocked:?}"
    );
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("operator-note"));
}

#[test]
fn a_contained_compiler_builds_and_runs_a_library_in_its_readable_project() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().canonicalize().unwrap();
    let locate = |args: &[&str]| -> PathBuf {
        let output = succeeds(Command::new("/usr/bin/xcrun").args(args));
        PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
    };
    let compiler = locate(&["--find", "clang"]);
    let linker = locate(&["--find", "ld"]);
    let sdk = locate(&["--show-sdk-path"]);
    let tools = compiler.parent().unwrap().parent().unwrap();
    std::fs::write(
        project.join("library.c"),
        "int answer(void) { return 42; }\n",
    )
    .unwrap();
    std::fs::write(
        project.join("main.c"),
        "extern int answer(void); int main(void) { return answer() == 42 ? 0 : 1; }\n",
    )
    .unwrap();
    let config = base(&project)
        .allow(&project, Operation::Exec, Scope::Root)
        .unwrap()
        .allow(tools, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&sdk, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&compiler, Operation::Exec, Scope::File)
        .unwrap()
        .allow(&linker, Operation::Exec, Scope::File)
        .unwrap()
        .allow("/bin/bash", Operation::Exec, Scope::File)
        .unwrap();
    let script = r#"export TMPDIR="$4"; "$1" -isysroot "$3" -fuse-ld="$2" -dynamiclib library.c -Wl,-install_name,@loader_path/libbuilt.dylib -o libbuilt.dylib && "$1" -isysroot "$3" -fuse-ld="$2" main.c ./libbuilt.dylib -o app && ./app && echo CONTAINED_BUILD_AND_RUN_PASSED"#;
    let output = contained(
        &config,
        &project,
        Path::new("/bin/bash"),
        &[
            "-c",
            script,
            "build",
            compiler.to_str().unwrap(),
            linker.to_str().unwrap(),
            sdk.to_str().unwrap(),
            project.to_str().unwrap(),
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("CONTAINED_BUILD_AND_RUN_PASSED"));
}

#[test]
fn a_writable_hard_link_cannot_import_ungranted_dependency_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let project = root.join("project");
    std::fs::create_dir(&project).unwrap();
    let codec = root.join("libcodec.dylib");
    let source = project.join("library.c");
    std::fs::write(&source, "int answer(void) { return 42; }\n").unwrap();
    succeeds(
        Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-o"])
            .arg(&codec)
            .arg(&source),
    );
    let main = project.join("main.c");
    std::fs::write(
        &main,
        "extern int answer(void); int main(void) { return answer(); }\n",
    )
    .unwrap();
    let app = root.join("installed-app");
    succeeds(
        Command::new("/usr/bin/cc")
            .arg(&main)
            .arg(&codec)
            .arg("-o")
            .arg(&app),
    );
    let note = root.join("operator-note");
    std::fs::write(&note, "SYNTHETIC_PRIVATE_BYTES").unwrap();
    succeeds(
        Command::new("/usr/bin/install_name_tool")
            .arg("-change")
            .arg(&codec)
            .arg(&note)
            .arg(&app),
    );
    std::fs::hard_link(&app, project.join("app")).unwrap();
    let config = base(&project)
        .allow(&app, Operation::Exec, Scope::File)
        .unwrap()
        .allow("/bin/cat", Operation::Exec, Scope::File)
        .unwrap();
    let output = contained(
        &config,
        &project,
        Path::new("/bin/cat"),
        &[note.to_str().unwrap()],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "hardlinked image imported private bytes: {output:?}"
    );
}
