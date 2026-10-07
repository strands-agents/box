//! Test-only host binary that exits with a given code or ends by a given signal.

#[cfg(unix)]
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [mode, code] if mode == "exit" => match code.parse::<i32>() {
            Ok(code) => std::process::exit(code),
            Err(_) => usage(),
        },
        [mode, signal] if mode == "signal" => match signal.parse::<libc::c_int>() {
            Ok(signal) => {
                // SAFETY: `kill` on this process's own pid takes no pointer.
                unsafe { libc::kill(libc::getpid(), signal) };
                std::thread::sleep(std::time::Duration::from_secs(10));
                eprintln!("box-exit-probe: signal {signal} did not end the process");
                std::process::exit(2);
            }
            Err(_) => usage(),
        },
        _ => usage(),
    }
}

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn usage() -> ! {
    eprintln!("usage: box-exit-probe <exit CODE | signal NUMBER>");
    std::process::exit(2);
}
