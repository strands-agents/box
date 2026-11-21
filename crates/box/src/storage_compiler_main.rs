//! Private fresh-process entry for captured-storage permission compilation.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    strands_box::storage_compiler_main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "strands-box-storage-compiler: Linux storage compilation is unavailable on this platform"
    );
    std::process::ExitCode::FAILURE
}
