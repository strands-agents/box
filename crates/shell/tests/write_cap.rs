//! The in-memory file size cap refuses the write that crosses it, and a bound host directory has
//! no cap.

use std::path::PathBuf;

use strands_shell::Shell;

const CAP: usize = 64;
const HEAD: usize = CAP / 2;
const WELL_OVER: usize = 4096;

fn rt() -> (tokio::runtime::Runtime, tokio::task::LocalSet) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    (rt, tokio::task::LocalSet::new())
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 26) as u8).collect()
}

/// A fresh host directory holding one patterned source file of each size a scenario reads.
fn host_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shell_write_cap_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create host directory");
    for len in [CAP - 1, CAP, CAP + 1, WELL_OVER] {
        std::fs::write(dir.join(format!("src{len}")), pattern(len)).expect("write source");
        let rest = len - HEAD;
        std::fs::write(dir.join(format!("src{rest}")), pattern(rest)).expect("write source");
    }
    std::fs::write(dir.join(format!("src{HEAD}")), pattern(HEAD)).expect("write source");
    dir
}

/// The bytes `/tmp/out` holds after `shape` has written `len` bytes with no refusal.
fn expected(shape: &str, len: usize) -> Vec<u8> {
    match shape {
        "append" | "group" => [pattern(HEAD), pattern(len - HEAD)].concat(),
        _ => pattern(len),
    }
}

fn capped_shell(dir: &std::path::Path) -> Shell {
    Shell::builder()
        .bind_direct_readonly(dir.to_str().unwrap(), "/src")
        .max_file_size(CAP)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// The command that writes `len` bytes to `/tmp/out` in each shape under test.
fn command(shape: &str, len: usize) -> String {
    match shape {
        "cp" => format!("cp /src/src{len} /tmp/out"),
        "cat" => format!("cat /src/src{len} > /tmp/out"),
        "printf" => format!(
            "printf '%s' {} > /tmp/out",
            String::from_utf8(pattern(len)).unwrap()
        ),
        "append" => format!(
            "cat /src/src{HEAD} > /tmp/out && cat /src/src{} >> /tmp/out",
            len - HEAD
        ),
        "group" => format!(
            "{{ cat /src/src{HEAD}; cat /src/src{}; }} > /tmp/out",
            len - HEAD
        ),
        "pipeline" => format!("cat /src/src{len} | cat > /tmp/out"),
        _ => unreachable!(),
    }
}

/// The destination's bytes once its drain task has run.
async fn landed(shell: &mut Shell) -> Vec<u8> {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    shell.read_file("/tmp/out").await.unwrap_or_default()
}

const SHAPES: [&str; 6] = ["cp", "cat", "printf", "append", "group", "pipeline"];

#[test]
fn a_write_under_the_cap_lands_in_full() {
    let dir = host_dir("under");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for shape in SHAPES {
            let mut shell = capped_shell(&dir);
            let out = shell.run(&command(shape, CAP - 1)).await;
            assert_eq!(
                out.status, 0,
                "{shape}: a write under the cap must succeed: {}",
                out.stderr
            );
            assert_eq!(
                out.stderr, "",
                "{shape}: a write under the cap prints nothing"
            );
            assert_eq!(
                landed(&mut shell).await,
                expected(shape, CAP - 1),
                "{shape}: every byte lands"
            );
        }
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_write_exactly_at_the_cap_lands_in_full() {
    let dir = host_dir("exact");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for shape in SHAPES {
            let mut shell = capped_shell(&dir);
            let out = shell.run(&command(shape, CAP)).await;
            assert_eq!(
                out.status, 0,
                "{shape}: a write that fills the cap must succeed: {}",
                out.stderr
            );
            assert_eq!(
                out.stderr, "",
                "{shape}: a write that fills the cap prints nothing"
            );
            assert_eq!(
                landed(&mut shell).await,
                expected(shape, CAP),
                "{shape}: every byte lands"
            );
        }
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_write_one_byte_over_the_cap_is_refused_and_keeps_the_prefix() {
    let dir = host_dir("over");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for shape in SHAPES {
            let mut shell = capped_shell(&dir);
            let out = shell.run(&command(shape, CAP + 1)).await;
            assert_ne!(out.status, 0, "{shape}: a write over the cap must fail");
            assert!(
                out.stderr
                    .contains(&format!("file size limit exceeded ({CAP} bytes)")),
                "{shape}: the refusal names the limit; stderr was {:?}",
                out.stderr
            );
            assert_eq!(
                landed(&mut shell).await,
                expected(shape, CAP + 1)[..CAP].to_vec(),
                "{shape}: the bytes up to the cap are kept"
            );
        }
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_write_well_over_the_cap_is_refused_and_keeps_the_prefix() {
    let dir = host_dir("well_over");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        for shape in SHAPES {
            let mut shell = capped_shell(&dir);
            let out = shell.run(&command(shape, WELL_OVER)).await;
            assert_ne!(
                out.status, 0,
                "{shape}: a write well over the cap must fail"
            );
            assert!(
                out.stderr
                    .contains(&format!("file size limit exceeded ({CAP} bytes)")),
                "{shape}: the refusal names the limit; stderr was {:?}",
                out.stderr
            );
            assert_eq!(
                landed(&mut shell).await,
                expected(shape, WELL_OVER)[..CAP].to_vec(),
                "{shape}: the bytes up to the cap are kept"
            );
        }
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_append_to_a_file_at_the_cap_is_refused_at_open() {
    let dir = host_dir("full");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = capped_shell(&dir);
        let out = shell.run(&format!("cat /src/src{CAP} > /tmp/out")).await;
        assert_eq!(out.status, 0, "filling the file succeeds: {}", out.stderr);
        let out = shell.run("true >> /tmp/out").await;
        assert_ne!(
            out.status, 0,
            "opening a full file for append fails before any write"
        );
        assert!(
            out.stderr
                .contains(&format!("file size limit exceeded ({CAP} bytes)")),
            "the open-time refusal names the limit; stderr was {:?}",
            out.stderr
        );
        let out = shell.run("printf x >> /tmp/out").await;
        assert_ne!(out.status, 0, "an append to a full file must fail");
        assert!(
            out.stderr
                .contains(&format!("file size limit exceeded ({CAP} bytes)")),
            "the refusal names the limit; stderr was {:?}",
            out.stderr
        );
        assert_eq!(
            landed(&mut shell).await,
            pattern(CAP),
            "the full file is unchanged"
        );
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bound_host_directory_has_no_cap() {
    let dir = host_dir("bound");
    let big = 12 * 1024 * 1024;
    std::fs::write(dir.join("big"), pattern(big)).expect("write big source");
    std::fs::create_dir_all(dir.join("out")).expect("create output directory");
    std::fs::write(dir.join("out").join("appended"), pattern(big)).expect("write append target");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = Shell::builder()
            .bind_direct_readonly(dir.to_str().unwrap(), "/src")
            .bind_direct(dir.join("out").to_str().unwrap(), "/out")
            .max_file_size(CAP)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap();
        for command in [
            "cp /src/big /out/copied",
            "cat /src/big > /out/redirected",
            "cat /src/big | cat > /out/piped",
            "cat /src/big >> /out/appended",
        ] {
            let out = shell.run(command).await;
            assert_eq!(
                out.status, 0,
                "{command}: a bound directory is not capped: {}",
                out.stderr
            );
            assert_eq!(
                out.stderr, "",
                "{command}: a bound directory prints no refusal"
            );
        }
    }));
    rt.block_on(local);
    for (name, expected) in [
        ("copied", pattern(big)),
        ("redirected", pattern(big)),
        ("piped", pattern(big)),
        ("appended", [pattern(big), pattern(big)].concat()),
    ] {
        let landed = std::fs::read(dir.join("out").join(name)).expect("read host file");
        assert_eq!(
            landed.len(),
            expected.len(),
            "{name}: every byte reaches the host file"
        );
        assert!(
            landed == expected,
            "{name}: the host file is byte-identical to its source"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_group_appending_to_a_file_at_the_cap_is_refused() {
    let dir = host_dir("group_full");
    let (rt, local) = rt();
    rt.block_on(local.run_until(async {
        let mut shell = capped_shell(&dir);
        let out = shell.run(&format!("cat /src/src{CAP} > /tmp/out")).await;
        assert_eq!(out.status, 0, "filling the file succeeds: {}", out.stderr);
        let out = shell.run("{ printf x; } >> /tmp/out").await;
        assert_ne!(out.status, 0, "a group appending to a full file must fail");
        assert!(
            out.stderr
                .contains(&format!("file size limit exceeded ({CAP} bytes)")),
            "the refusal names the limit; stderr was {:?}",
            out.stderr
        );
        assert_eq!(
            landed(&mut shell).await,
            pattern(CAP),
            "the full file is unchanged"
        );
    }));
    let _ = std::fs::remove_dir_all(&dir);
}
