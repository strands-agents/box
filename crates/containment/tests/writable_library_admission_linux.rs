//! Linux dependency admission with writable library files and aliases.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use containment::{ContainmentConfig, Operation, Scope};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug)]
enum SearchPath {
    Runpath,
    Rpath,
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    libraries: PathBuf,
    workspace: PathBuf,
    library: PathBuf,
    app: PathBuf,
}

impl Fixture {
    fn new(search: SearchPath, transitive: bool, linked_search: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let libraries = root.join("libraries");
        let workspace = root.join("workspace");
        let installed = root.join("installed");
        for path in [&libraries, &workspace, &installed] {
            std::fs::create_dir(path).unwrap();
        }
        let search_directory = if linked_search {
            let alias = root.join("library-spelling");
            std::os::unix::fs::symlink(&libraries, &alias).unwrap();
            alias
        } else {
            libraries.clone()
        };
        let library = libraries.join("libanswer.so");
        let source = root.join("answer.c");
        std::fs::write(&source, "int answer(void) { return 42; }\n").unwrap();
        compile(
            Command::new("/usr/bin/cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libanswer.so"])
                .arg(&source)
                .arg("-o")
                .arg(&library),
        );
        let function = if transitive {
            let outer = root.join("outer.c");
            std::fs::write(
                &outer,
                "extern int answer(void); int outer_answer(void) { return answer(); }\n",
            )
            .unwrap();
            compile(library_search(
                Command::new("/usr/bin/cc")
                    .args(["-shared", "-fPIC", "-Wl,-soname,libouter.so"])
                    .arg(&outer)
                    .arg("-L")
                    .arg(&libraries)
                    .arg("-lanswer")
                    .arg("-o")
                    .arg(libraries.join("libouter.so")),
                search,
                &search_directory,
            ));
            "outer_answer"
        } else {
            "answer"
        };
        let main = root.join("main.c");
        std::fs::write(
            &main,
            format!(
                r#"#include <stdio.h>
extern int {function}(void);
int main(int argc, char **argv) {{
    if ({function}() != 42) return 1;
    if (argc > 1) {{
        FILE *file = fopen(argv[1], "w");
        if (!file) return 2;
        if (fputs("workspace remains writable\n", file) < 0) return 3;
        if (fclose(file) != 0) return 4;
        puts("WORKSPACE_WRITE_OK");
    }}
    puts("LIBRARY_42");
    return 0;
}}
"#
            ),
        )
        .unwrap();
        let app = installed.join("app");
        compile(library_search(
            Command::new("/usr/bin/cc")
                .arg(&main)
                .arg("-L")
                .arg(&libraries)
                .arg(if transitive { "-louter" } else { "-lanswer" })
                .arg(format!("-Wl,-rpath-link,{}", libraries.display()))
                .arg("-o")
                .arg(&app),
            search,
            &search_directory,
        ));
        let control = Command::new(&app).output().unwrap();
        assert_library_ran(&control);
        Self {
            _directory: directory,
            root,
            libraries,
            workspace,
            library,
            app,
        }
    }

    fn config(&self) -> ContainmentConfig {
        ContainmentConfig::new()
            .allow(&self.app, Operation::Exec, Scope::File)
            .unwrap()
    }

    fn writable_libraries(&self) -> ContainmentConfig {
        self.config()
            .allow(&self.libraries, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&self.libraries, Operation::Write, Scope::Root)
            .unwrap()
    }

    fn run(&self, config: &ContainmentConfig, write: Option<&Path>) -> Output {
        let arguments: Vec<_> = write.into_iter().collect();
        self.run_program(config, &self.app, &arguments)
    }

    fn run_program(
        &self,
        config: &ContainmentConfig,
        program: &Path,
        arguments: &[&Path],
    ) -> Output {
        let json = config.to_json().unwrap();
        let digest = Sha256::digest(json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), json).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_strands-box-contain-trampoline"));
        command
            .current_dir(&self.root)
            .arg("--config")
            .arg(file.path())
            .args([
                "--config-sha256",
                &digest,
                "--target-env-json",
                r#"{"PATH":"/usr/bin:/bin"}"#,
                "--",
            ])
            .arg(program)
            .args(arguments);
        command.output().unwrap()
    }
}

struct LibraryWriter {
    fixture: Fixture,
    writer: PathBuf,
    replacement: PathBuf,
    initial_bytes: Vec<u8>,
    replacement_bytes: Vec<u8>,
}

impl LibraryWriter {
    fn new(linked_search: bool) -> Self {
        let fixture = Fixture::new(SearchPath::Runpath, false, linked_search);
        let replacement = fixture.root.join("replacement.so");
        std::fs::copy(&fixture.library, &replacement).unwrap();
        let replacement_bytes = std::fs::read(&replacement).unwrap();
        let initial_source = fixture.root.join("initial.c");
        std::fs::write(&initial_source, "int answer(void) { return 7; }\n").unwrap();
        compile(
            Command::new("/usr/bin/cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libanswer.so"])
                .arg(&initial_source)
                .arg("-o")
                .arg(&fixture.library),
        );
        let initial_bytes = std::fs::read(&fixture.library).unwrap();
        assert_ne!(initial_bytes, replacement_bytes);
        let initial = Command::new(&fixture.app).output().unwrap();
        assert_eq!(
            initial.status.code(),
            Some(1),
            "the initial library must fail the app's answer check: {initial:?}"
        );
        assert!(initial.stdout.is_empty());
        let source = fixture.root.join("copy-library.c");
        std::fs::write(
            &source,
            r#"#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) return 10;
    FILE *source = fopen(argv[1], "rb");
    if (!source) return 11;
    FILE *target = fopen(argv[2], "wb");
    if (!target) return 12;
    unsigned char bytes[4096];
    size_t length;
    while ((length = fread(bytes, 1, sizeof(bytes), source)) != 0) {
        if (fwrite(bytes, 1, length, target) != length) return 13;
    }
    if (ferror(source)) return 14;
    if (fclose(source) != 0 || fclose(target) != 0) return 15;
    puts("FIXTURE_LIBRARY_WRITTEN");
    if (fflush(stdout) != 0) return 16;
    if (argc == 4) {
        char *arguments[] = { argv[3], NULL };
        execv(argv[3], arguments);
        return 17;
    }
    return 0;
}
"#,
        )
        .unwrap();
        let writer = fixture.root.join("installed/copy-library");
        compile(
            Command::new("/usr/bin/cc")
                .arg(&source)
                .arg("-o")
                .arg(&writer),
        );
        Self {
            fixture,
            writer,
            replacement,
            initial_bytes,
            replacement_bytes,
        }
    }

    fn config(&self, config: ContainmentConfig) -> ContainmentConfig {
        config
            .allow(&self.writer, Operation::Exec, Scope::File)
            .unwrap()
            .allow(&self.replacement, Operation::Read, Scope::File)
            .unwrap()
    }

    fn run(&self, config: &ContainmentConfig, execute_app: bool) -> Output {
        let mut arguments = vec![self.replacement.as_path(), self.fixture.library.as_path()];
        if execute_app {
            arguments.push(&self.fixture.app);
        }
        self.fixture.run_program(config, &self.writer, &arguments)
    }

    fn assert_copy_completed(&self, output: &Output) {
        assert!(output.status.success(), "fixture writer failed: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("FIXTURE_LIBRARY_WRITTEN"),
            "the writer did not report its completed copy: {output:?}"
        );
        assert_eq!(
            std::fs::read(&self.fixture.library).unwrap(),
            self.replacement_bytes,
            "the contained writer must copy the replacement library's exact bytes"
        );
    }
}

fn library_search<'a>(
    command: &'a mut Command,
    search: SearchPath,
    directory: &Path,
) -> &'a mut Command {
    command
        .arg(match search {
            SearchPath::Runpath => "-Wl,--enable-new-dtags",
            SearchPath::Rpath => "-Wl,--disable-new-dtags",
        })
        .arg(format!("-Wl,-rpath,{}", directory.display()))
}

fn compile(command: &mut Command) {
    let output = command.output().expect("the test requires /usr/bin/cc");
    assert!(
        output.status.success(),
        "fixture compilation failed: {output:?}"
    );
}

fn supported_architecture() -> bool {
    if cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        true
    } else {
        println!(
            "skipping: Linux containment supports ARM64 (aarch64) or x86-64 (x86_64), not this architecture"
        );
        false
    }
}

fn assert_writable_dependency_refused(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(3),
        "writable dependency must fail before workload startup: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("writable dependency"),
        "startup must identify the writable dependency: {output:?}"
    );
    assert!(output.stdout.is_empty(), "the workload ran: {output:?}");
}

fn assert_library_ran(output: &Output) {
    assert!(
        output.status.success(),
        "library control failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("LIBRARY_42"),
        "the library did not return its expected value: {output:?}"
    );
}

#[test]
fn read_and_write_grants_do_not_authorize_private_library_execution() {
    if !supported_architecture() {
        return;
    }
    for search in [SearchPath::Runpath, SearchPath::Rpath] {
        let fixture = Fixture::new(search, false, false);
        let output = fixture.run(&fixture.writable_libraries(), None);
        assert_writable_dependency_refused(&output);
        eprintln!("{search:?}: writable library tree refused before workload startup");
    }
}

#[test]
fn a_write_file_grant_does_not_authorize_private_library_execution() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, false, false);
    let config = fixture
        .config()
        .allow(&fixture.library, Operation::Read, Scope::File)
        .unwrap()
        .allow(&fixture.library, Operation::Write, Scope::File)
        .unwrap();
    assert_writable_dependency_refused(&fixture.run(&config, None));
}

#[test]
fn an_immutable_library_cannot_admit_a_writable_transitive_dependency() {
    if !supported_architecture() {
        return;
    }
    for search in [SearchPath::Runpath, SearchPath::Rpath] {
        let fixture = Fixture::new(search, true, false);
        let config = fixture
            .config()
            .allow(&fixture.library, Operation::Read, Scope::File)
            .unwrap()
            .allow(&fixture.library, Operation::Write, Scope::File)
            .unwrap();
        assert_writable_dependency_refused(&fixture.run(&config, None));
        eprintln!("{search:?}: writable transitive library refused before workload startup");
    }
}

#[test]
fn a_library_search_symlink_does_not_hide_a_writable_dependency() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, false, true);
    assert_writable_dependency_refused(&fixture.run(&fixture.writable_libraries(), None));
}

#[test]
fn a_write_grant_through_a_symlink_does_not_hide_a_writable_dependency() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, false, false);
    let alias = fixture.root.join("write-spelling");
    std::os::unix::fs::symlink(&fixture.libraries, &alias).unwrap();
    let config = fixture
        .config()
        .allow(&alias, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&alias, Operation::Write, Scope::Root)
        .unwrap();
    assert_writable_dependency_refused(&fixture.run(&config, None));
}

#[test]
fn writable_hard_links_cannot_supply_implicit_library_execution() {
    if !supported_architecture() {
        return;
    }
    for scope in [Scope::File, Scope::Root] {
        let fixture = Fixture::new(SearchPath::Runpath, false, false);
        let alias = fixture.workspace.join("library-alias.so");
        std::fs::hard_link(&fixture.library, &alias).unwrap();
        let writable = match scope {
            Scope::File => &alias,
            Scope::Root => &fixture.workspace,
            Scope::Dir => unreachable!(),
        };
        let config = fixture
            .config()
            .allow(&fixture.library, Operation::Read, Scope::File)
            .unwrap()
            .allow(writable, Operation::Read, scope)
            .unwrap()
            .allow(writable, Operation::Write, scope)
            .unwrap();
        assert_writable_dependency_refused(&fixture.run(&config, None));
        eprintln!("{scope:?}: writable hard-link alias refused before workload startup");
    }
}

#[test]
fn an_immutable_private_library_preserves_unrelated_workspace_writes() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, true, false);
    let config = fixture
        .config()
        .allow(&fixture.workspace, Operation::Read, Scope::Root)
        .unwrap()
        .allow(&fixture.workspace, Operation::Write, Scope::Root)
        .unwrap();
    let written = fixture.workspace.join("result");
    let output = fixture.run(&config, Some(&written));
    assert_library_ran(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("WORKSPACE_WRITE_OK"));
    assert_eq!(
        std::fs::read_to_string(written).unwrap(),
        "workspace remains writable\n"
    );
}

#[test]
fn explicit_execution_grants_preserve_writable_library_loads() {
    if !supported_architecture() {
        return;
    }
    for scope in [Scope::File, Scope::Root] {
        let fixture = Fixture::new(SearchPath::Runpath, false, false);
        let executable = match scope {
            Scope::File => &fixture.library,
            Scope::Root => &fixture.libraries,
            Scope::Dir => unreachable!(),
        };
        let config = fixture
            .writable_libraries()
            .allow(executable, Operation::Exec, scope)
            .unwrap();
        let output = fixture.run(&config, None);
        assert_library_ran(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("both writable and executable"),
            "intentional writable execution must retain its warning: {output:?}"
        );
        eprintln!("{scope:?}: explicit writable library execution ran with its warning");
    }
}

#[test]
fn broad_execution_preserves_writable_library_loads() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, true, false);
    let config = fixture.writable_libraries().allow_broad_exec();
    assert_library_ran(&fixture.run(&config, None));
}

#[test]
fn explicit_library_denial_still_overrides_broad_execution() {
    if !supported_architecture() {
        return;
    }
    let fixture = Fixture::new(SearchPath::Runpath, false, false);
    let config = fixture
        .writable_libraries()
        .allow_broad_exec()
        .refuse(&fixture.library, Scope::File)
        .unwrap();
    let output = fixture.run(&config, None);
    assert_eq!(output.status.code(), Some(3), "denial failed: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("explicitly denied"),
        "the explicit dependency denial must take precedence: {output:?}"
    );
    assert!(output.stdout.is_empty(), "the workload ran: {output:?}");
}

#[test]
fn same_run_library_writes_require_explicit_execution_permission() {
    if !supported_architecture() {
        return;
    }
    let writer = LibraryWriter::new(true);
    let fixture = &writer.fixture;
    let config = writer.config(fixture.writable_libraries());
    let output = writer.run(&config, true);
    assert_writable_dependency_refused(&output);
    assert_eq!(
        std::fs::read(&fixture.library).unwrap(),
        writer.initial_bytes,
        "refusal must occur before the contained writer changes any library bytes"
    );
    let allowed = config
        .allow(&fixture.library, Operation::Exec, Scope::File)
        .unwrap();
    let output = writer.run(&allowed, true);
    writer.assert_copy_completed(&output);
    assert_library_ran(&output);
    eprintln!(
        "same launch: implicit execution refused before copy; explicit execution copied and ran the 42-library through its other spelling"
    );
}

#[test]
fn a_library_staged_by_an_earlier_launch_requires_explicit_execution_permission() {
    if !supported_architecture() {
        return;
    }
    let writer = LibraryWriter::new(false);
    let fixture = &writer.fixture;
    let stage = writer.config(
        ContainmentConfig::new()
            .allow(&fixture.libraries, Operation::Read, Scope::Root)
            .unwrap()
            .allow(&fixture.libraries, Operation::Write, Scope::Root)
            .unwrap(),
    );
    let output = writer.run(&stage, false);
    writer.assert_copy_completed(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("LIBRARY_42"));
    let execute = fixture.writable_libraries();
    assert_writable_dependency_refused(&fixture.run(&execute, None));
    assert_eq!(
        std::fs::read(&fixture.library).unwrap(),
        writer.replacement_bytes,
        "the second launch must refuse without changing the staged library"
    );
    let allowed = execute
        .allow(&fixture.library, Operation::Exec, Scope::File)
        .unwrap();
    assert_library_ran(&fixture.run(&allowed, None));
    eprintln!(
        "separate launches: contained writer staged exact library bytes; implicit execution refused; explicit execution ran the 42-library"
    );
}
