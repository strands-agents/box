use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use strands_det_harness::{det_case, sh_quote, user_home};

fn reported_path(command: &str, args: &[&str]) -> PathBuf {
    let result = Command::new(command).args(args).output()
        .expect("DET_ERROR: query the installed compiler");
    assert!(result.status.success(), "DET_ERROR: compiler query failed: {result:?}");
    std::fs::canonicalize(String::from_utf8(result.stdout).unwrap().trim())
        .expect("DET_ERROR: resolve the installed compiler path")
}

fn quoted(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy()).unwrap()
}

fn journal_path(path: &Path) -> PathBuf {
    let home = user_home().canonicalize().expect("DET_ERROR: resolve home");
    path.strip_prefix(home)
        .map(|relative| Path::new("~").join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn roots(paths: impl IntoIterator<Item = PathBuf>) -> String {
    let paths: BTreeSet<_> = paths.into_iter().collect();
    paths.iter()
        .filter(|path| !paths.iter().any(|other| other != *path && path.starts_with(other)))
        .map(|path| quoted(path)).collect::<Vec<_>>().join(", ")
}

fn stage_linker_library(gcc: &Path, name: &str, directory: &Path) {
    let path = reported_path(gcc.to_str().unwrap(), &[&format!("-print-file-name={name}")]);
    let bytes = std::fs::read(&path).expect("DET_ERROR: read the installed linker input");
    let target = directory.join(name);
    if bytes.starts_with(b"\x7fELF") {
        std::os::unix::fs::symlink(path, target)
            .expect("DET_ERROR: link the installed shared library");
        return;
    }
    let script = String::from_utf8(bytes).expect("DET_ERROR: the linker script must be text");
    assert!(script.starts_with("/* GNU ld script"), "DET_ERROR: unsupported linker input: {}", path.display());
    let script = script.split_whitespace().map(|word| {
        let path = Path::new(word);
        if path.is_absolute() && path.is_file() {
            std::fs::canonicalize(path).expect("DET_ERROR: resolve a linker script input")
                .to_string_lossy().into_owned()
        } else {
            word.to_string()
        }
    }).collect::<Vec<_>>().join(" ");
    std::fs::write(target, script).expect("DET_ERROR: write the resolved linker script");
}

det_case! {
    name: cn_w_06,
    id: "CN-W-06",
    platforms: [Linux],
    desc: "Cargo compiles and runs a build script and generated output through supported grants; agent execution and ungranted access remain refused",
    run: |b| {
        let cargo = reported_path("rustup", &["which", "cargo"]);
        let rustc = reported_path("rustup", &["which", "rustc"]);
        let toolchain = rustc.parent().unwrap().parent().unwrap();
        let gcc = reported_path("sh", &["-c", "command -v gcc"]);
        let ld = reported_path("sh", &["-c", "command -v ld.bfd"]);
        let assembler = reported_path("sh", &["-c", "command -v as"]);
        let collect2 = reported_path(gcc.to_str().unwrap(), &["-print-prog-name=collect2"]);
        let support = collect2.parent().unwrap();
        let ws = b.workspace();
        let crate_root = ws.join("hello-crate");
        let parent = ws.parent().unwrap();
        let helpers = parent.join("compiler-helpers");
        let cargo_home = parent.join("cargo-home");
        let read_only = parent.join("cargo-read-only");
        let outside = parent.join("cargo-ungranted");
        for path in [&helpers, &cargo_home, &read_only, &outside] {
            std::fs::create_dir(path).expect("DET_ERROR: create the Cargo fixture directory");
        }
        for (name, target) in [("ld", &ld), ("ld.bfd", &ld), ("as", &assembler)] {
            std::os::unix::fs::symlink(target, helpers.join(name))
                .expect("DET_ERROR: create the selected compiler helper alias");
        }
        for name in ["libc.so", "libm.so"] {
            stage_linker_library(&gcc, name, &helpers);
        }
        let witness = read_only.join("unchanged");
        std::fs::write(&witness, "HOST_CONTENT").expect("DET_ERROR: the host can write the witness");
        let ungranted = outside.join("program");
        std::fs::copy(b.built_tool(), &ungranted).expect("DET_ERROR: copy the ungranted program");
        let host = Command::new(&ungranted).output().expect("DET_ERROR: run the ungranted host control");
        assert!(host.status.success(), "DET_ERROR: the ungranted program must work outside Box");
        let protected = ws.join(".strands-box/box.toml");
        let config_bytes = std::fs::read(&protected)
            .expect("DET_ERROR: read the protected configuration on the host");
        assert!(!config_bytes.is_empty(), "DET_ERROR: the protected configuration must not be empty");
        let flags = format!("-C linker={} -C link-arg=-B{}/ -C link-arg=-fuse-ld=bfd -C link-arg=-L{}",
            gcc.display(), helpers.display(), helpers.display());
        let source = "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n\
                      fn main() { generated(); println!(\"CARGO_OUTPUT_RAN\"); }\n";
        std::fs::write(crate_root.join("src/main.rs"), source).expect("DET_ERROR: write the crate");
        let generate = r#"
            let generated = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("generated.rs");
            std::fs::write(generated, "fn generated() { println!(\"GENERATED_CODE_RAN\"); }").unwrap();
            println!("cargo:warning=BUILD_SCRIPT_RAN");
        "#;
        std::fs::write(crate_root.join("build.rs"), format!("fn main() {{ {generate} }}"))
            .expect("DET_ERROR: write the host build script");
        let host_target = parent.join("host-target");
        let host = Command::new(&cargo)
            .args(["build", "--offline", "--target-dir"]).arg(&host_target)
            .env("CARGO_HOME", &cargo_home).env("RUSTC", &rustc).env("RUSTFLAGS", &flags)
            .current_dir(&crate_root).output().expect("DET_ERROR: build the host control");
        assert!(host.status.success(), "DET_ERROR: host compilation failed: {host:?}");
        let host = Command::new(host_target.join("debug/hello")).output()
            .expect("DET_ERROR: run the host build output");
        assert!(host.status.success(), "DET_ERROR: host build output must work");
        assert!(String::from_utf8_lossy(&host.stdout).contains("GENERATED_CODE_RAN"));
        std::fs::write(crate_root.join("build.rs"), format!(r#"
            fn main() {{
                assert_eq!(std::fs::read_to_string({w}).unwrap(), "HOST_CONTENT");
                assert!(std::fs::write({w}, "changed").is_err(), "write escaped");
                println!("cargo:warning=READ_ONLY_WRITE_REFUSED");
                assert!(std::process::Command::new({u}).output().is_err(), "ungranted program ran");
                println!("cargo:warning=UNGRANTED_PROGRAM_REFUSED");
                assert!(std::fs::read({p}).is_err(), "protected config readable");
                println!("cargo:warning=PROTECTED_CONFIG_REFUSED");
                {generate}
            }}
        "#, w=quoted(&witness), u=quoted(&ungranted), p=quoted(&protected)))
            .expect("DET_ERROR: write the contained build script");
        let libraries: Vec<_> = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .into_iter().filter_map(|path| std::fs::canonicalize(path).ok()).collect();
        let read = roots(libraries.iter().cloned().chain([
            ws.to_path_buf(), toolchain.to_path_buf(), support.to_path_buf(),
            helpers.clone(), cargo_home.clone(), read_only.clone(),
        ]));
        let tool = format!(
            "\n[tool.cargo]\ncommand = [{cargo}]\nworkspace = {c}\n\
             [tool.cargo.env]\nCARGO_HOME = {home}\nRUSTC = {rustc}\n\
             TMPDIR = {tmp}\nRUSTFLAGS = {flags}\nPATH = {path}\n\
             [tool.cargo.filesystem]\nread = [{read}]\nwrite = [{c}, {home}]\n\
             read_file = [{gcc}, {ld}, {assembler}]\n",
            cargo=quoted(&cargo), c=quoted(&crate_root), home=quoted(&cargo_home),
            rustc=quoted(&rustc), tmp=quoted(&crate_root.join("target/tmp")),
            flags=serde_json::to_string(&flags).unwrap(),
            path=serde_json::to_string(&format!("{}:/usr/bin:/bin", toolchain.join("bin").display())).unwrap(),
            gcc=quoted(&gcc), ld=quoted(&ld), assembler=quoted(&assembler),
        );
        b.apply_policy(r#"permit (principal, action == Box::Action::"shell:spawn", resource);"#);
        let shell = |path: &Path| sh_quote(&path.to_string_lossy());
        let r = b.run_mediated_with_config(|text| text + &tool,
            &format!("{} run --offline --verbose", shell(&cargo)));
        assert_eq!(r.rc, 0, "Cargo must complete: {}", r.out);
        for marker in ["BUILD_SCRIPT_RAN", "GENERATED_CODE_RAN", "CARGO_OUTPUT_RAN",
            "READ_ONLY_WRITE_REFUSED", "UNGRANTED_PROGRAM_REFUSED", "PROTECTED_CONFIG_REFUSED"] {
            r.assert_contains(marker);
        }
        r.assert_spawn_permitted_exactly(&journal_path(&cargo));
        assert_eq!(std::fs::read_to_string(&witness).unwrap(), "HOST_CONTENT");
        let built = crate_root.join("target/debug/hello");
        let host = Command::new(&built).output().expect("DET_ERROR: run the contained build output on the host");
        assert!(host.status.success(), "The contained build output must run on the host: {host:?}");
        assert!(String::from_utf8_lossy(&host.stdout).contains("CARGO_OUTPUT_RAN"),
            "The host must run the contained build output: {host:?}");
        let hello = format!(
            "\n[tool.hello]\ncommand = [{}]\nworkspace = {}\n\
             [tool.hello.filesystem]\nread = [{}]\n",
            quoted(&built), quoted(&crate_root),
            roots(libraries.into_iter().chain([crate_root.clone()])),
        );
        let edit = |text: String| text + &tool + &hello;
        let r = b.run_mediated_with_config(edit, &shell(&built));
        assert_eq!(r.rc, 0, "Declared output must run: {}", r.out);
        r.assert_contains("CARGO_OUTPUT_RAN");
        r.assert_spawn_permitted_exactly(&journal_path(&built));
        let stranger = built.with_file_name("other");
        std::fs::copy(&built, &stranger).expect("DET_ERROR: copy the undeclared output");
        let r = b.run_mediated_with_config(edit, &shell(&stranger));
        assert_ne!(r.rc, 0);
        r.assert_absent("CARGO_OUTPUT_RAN");
        r.assert_contains("no `[tool.<name>] command` matches");
        let r = b.run_sh_with_config(edit, &format!("{}; printf 'OUTPUT_RC=%s\\n' \"$?\"", shell(&built)));
        r.assert_absent("CARGO_OUTPUT_RAN");
        r.assert_contains("OUTPUT_RC=126");
        let r = b.run_mediated_with_config(|text| text, &format!("{} build --offline", shell(&cargo)));
        assert_ne!(r.rc, 0);
        r.assert_contains("no `[tool.<name>] command` matches");
    }
}
