//! Linux build and execution controls for dependency admission.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Output};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

fn contained(config: &ContainmentConfig, directory: &Path, arguments: &[&str]) -> Output {
    let json = config.to_json().unwrap();
    let digest = Sha256::digest(json.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), json).unwrap();
    Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"))
        .current_dir(directory)
        .args(["--config"])
        .arg(file.path())
        .args([
            "--config-sha256",
            &digest,
            "--target-env-json",
            r#"{"PATH":"/usr/bin:/bin"}"#,
            "--",
        ])
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn a_contained_build_runs_its_library_and_a_new_launch_keeps_operator_bytes_private() {
    if !cfg!(target_arch = "aarch64") {
        println!("skipping: Linux containment supports ARM64 (aarch64), not this architecture");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let note = directory.path().join("operator-note");
    std::fs::write(&note, "synthetic operator bytes").unwrap();
    std::fs::write(
        project.join("lib.c"),
        "int built_answer(void) { return 42; }\n",
    )
    .unwrap();
    std::fs::write(
        project.join("main.c"),
        r#"#include <stdio.h>
extern int built_answer(void);
int main(int argc, char **argv) {
    if (built_answer() != 42) return 1;
    if (argc > 1) {
        FILE *file = fopen(argv[1], "r");
        if (file) { fclose(file); puts("OPERATOR_BYTES_EXPOSED"); return 2; }
        puts("OPERATOR_BYTES_REFUSED");
    }
    puts("BUILT_LIBRARY_RAN");
    return 0;
}
"#,
    )
    .unwrap();
    let mut build = ContainmentConfig::new()
        .allow(&project, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&project, Operation::Write, Scope::Root)
        .unwrap()
        .allow(&project, Operation::Exec, Scope::Root)
        .unwrap()
        .allow("/usr/include", Operation::Read, Scope::Root)
        .unwrap()
        .allow("/usr/lib", Operation::Read, Scope::Root)
        .unwrap();
    for program in ["/bin/sh", "/usr/bin/cc", "/usr/bin/as", "/usr/bin/ld"] {
        build = build.allow(program, Operation::Exec, Scope::File).unwrap();
    }
    for name in ["cc1", "collect2"] {
        let path = Command::new("/usr/bin/cc")
            .arg(format!("-print-prog-name={name}"))
            .output()
            .unwrap();
        assert!(path.status.success());
        let path = String::from_utf8(path.stdout).unwrap();
        build = build
            .allow(path.trim(), Operation::Exec, Scope::File)
            .unwrap();
    }
    let output = contained(
        &build,
        &project,
        &[
            "/bin/sh",
            "-c",
            r#"/usr/bin/cc -B/usr/bin/ -shared -fPIC "$1/lib.c" -o "$1/libbuilt.so" && /usr/bin/cc -B/usr/bin/ "$1/main.c" -L"$1" -lbuilt -Wl,-rpath,'$ORIGIN' -o "$1/app" && "$1/app""#,
            "build",
            project.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "contained compilation and execution failed: {output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("BUILT_LIBRARY_RAN"));
    let app = project.join("app");
    let execute = ContainmentConfig::new()
        .allow(&project, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&project, Operation::Write, Scope::Root)
        .unwrap()
        .allow(&app, Operation::Exec, Scope::File)
        .unwrap();
    let output = contained(
        &execute,
        &project,
        &[app.to_str().unwrap(), note.to_str().unwrap()],
    );
    assert!(
        output.status.success(),
        "new contained launch failed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BUILT_LIBRARY_RAN"), "{stdout}");
    assert!(stdout.contains("OPERATOR_BYTES_REFUSED"), "{stdout}");
    eprintln!(
        "contained build and run: passed; writable app with private library: passed; ungranted read: refused"
    );

    let output = contained(
        &build,
        &project,
        &[
            "/bin/sh",
            "-c",
            r#"/usr/bin/cc -B/usr/bin/ -shared -fPIC "$1/lib.c" -Wl,-soname,"$2" -o "$1/libevil.so" && /usr/bin/cc -B/usr/bin/ "$1/main.c" -L"$1" -levil -Wl,-rpath,'$ORIGIN' -o "$1/evil""#,
            "build",
            project.to_str().unwrap(),
            note.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "malicious fixture build failed: {output:?}"
    );
    let attack = execute
        .allow(project.join("evil"), Operation::Exec, Scope::File)
        .unwrap()
        .allow("/bin/sh", Operation::Exec, Scope::File)
        .unwrap()
        .allow("/usr/bin/cat", Operation::Exec, Scope::File)
        .unwrap();
    let output = contained(
        &attack,
        &project,
        &[
            "/bin/sh",
            "-c",
            r#"/usr/bin/cat "$1""#,
            "read",
            note.to_str().unwrap(),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "malicious dependency was not refused: {output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("no filesystem grant reaches"));
    assert!(
        output.stdout.is_empty(),
        "the target ran or exposed operator bytes: {output:?}"
    );
    eprintln!(
        "malicious compiled dependency: refused before target startup; operator bytes exposed=0"
    );
    let installed = directory.path().join("installed-evil");
    std::fs::hard_link(project.join("evil"), &installed).unwrap();
    let linked = ContainmentConfig::new()
        .allow(&project, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&project, Operation::Write, Scope::Root)
        .unwrap()
        .allow(&installed, Operation::Exec, Scope::File)
        .unwrap()
        .allow("/usr/bin/cat", Operation::Exec, Scope::File)
        .unwrap();
    let output = contained(&linked, &project, &["/usr/bin/cat", note.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "writable hard link was not refused: {output:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "operator bytes exposed: {output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("no filesystem grant reaches"));
}
