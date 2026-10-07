//! leafprobe — one leaf-side act per invocation, run as a `[tool.<name>]` command or by the agent.
//!
//! Every answer is one line, `<TAG> <subject> <details>`, with the subject a quoted Rust string
//! literal (`{:?}`) as in `fs_probe.rs`, so `probe_lines.rs` parses it.
//!
//! Operations: `env NAME…` (`ENV_SET "NAME" value=…` or `ENV_UNSET "NAME"`, then `ENV_NAMES` with
//! every variable name sorted and joined by `,`), `copy FROM TO` (mode 0755), `exec PATH ARG…`
//! (`EXEC_OK "PATH" :: <stdout>`), `dlopen PATH` (calls the library's `det_leaf_value`), and
//! `fetch URL VAR` (an absolute-URI GET through `$HTTPS_PROXY` with `Authorization: Bearer $VAR`),
//! `path` (`PATH_SET value=…` or `PATH_UNSET`), `unix-connect PATH` (`CONNECT_OK "PATH"`), and
//! `http-connect URL` (a direct GET to the URL's own `http://` authority, with no proxy).
//! Not a case: `build.rs` scans only the category folders, so this file is never a test module.
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;

unsafe extern "C" {
    fn dlopen(path: *const std::ffi::c_char, flags: i32) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, name: *const std::ffi::c_char)
        -> *mut std::ffi::c_void;
    fn dlerror() -> *const std::ffi::c_char;
}

const RTLD_NOW: i32 = 2;

fn refused(operation: &str, subject: &str, error: &std::io::Error) {
    println!(
        "{operation}_REFUSED {subject} errno={} ({error})",
        error.raw_os_error().unwrap_or(-1)
    );
}

fn one_line(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn environment(names: &[String]) {
    for name in names {
        match std::env::var(name) {
            Ok(value) => println!("ENV_SET {name:?} value={}", one_line(&value)),
            Err(_) => println!("ENV_UNSET {name:?}"),
        }
    }
    let mut all: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    all.sort();
    println!("ENV_NAMES {}", all.join(","));
}

fn copy(from: &str, to: &str) {
    let subject = format!("{from:?} -> {to:?}");
    let copied = std::fs::copy(from, to)
        .and_then(|_| std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755)));
    match copied {
        Ok(()) => println!("COPY_OK {subject}"),
        Err(error) => refused("COPY", &subject, &error),
    }
}

fn exec(path: &str, arguments: &[String]) {
    match std::process::Command::new(path).args(arguments).output() {
        Ok(output) if output.status.success() => println!(
            "EXEC_OK {path:?} :: {}",
            one_line(String::from_utf8_lossy(&output.stdout).trim_end())
        ),
        Ok(output) => println!(
            "EXEC_FAILED {path:?} status={} :: {} :: {}",
            output.status.code().unwrap_or(-1),
            one_line(String::from_utf8_lossy(&output.stdout).trim_end()),
            one_line(&String::from_utf8_lossy(&output.stderr))
        ),
        Err(error) => refused("EXEC", &format!("{path:?}"), &error),
    }
}

fn load(path: &str) {
    let spelled = std::ffi::CString::new(path).expect("DET_ERROR: a path without NUL");
    let handle = unsafe { dlopen(spelled.as_ptr(), RTLD_NOW) };
    if handle.is_null() {
        let reason = unsafe {
            let text = dlerror();
            if text.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(text)
                    .to_string_lossy()
                    .into_owned()
            }
        };
        println!("DLOPEN_REFUSED {path:?} :: {}", one_line(&reason));
        return;
    }
    let symbol = unsafe { dlsym(handle, c"det_leaf_value".as_ptr()) };
    if symbol.is_null() {
        println!("DLOPEN_NOSYMBOL {path:?}");
        return;
    }
    let value: extern "C" fn() -> i32 = unsafe { std::mem::transmute(symbol) };
    println!("DLOPEN_OK {path:?} value={}", value());
}

fn fetch(url: &str, variable: &str) {
    let subject = format!("{url:?}");
    let Ok(proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) else {
        println!("FETCH_NOPROXY {subject}");
        return;
    };
    let proxy = proxy
        .strip_prefix("http://")
        .unwrap_or(&proxy)
        .trim_end_matches('/')
        .to_string();
    let authority = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    let credential = std::env::var(variable).unwrap_or_default();
    let mut stream = match std::net::TcpStream::connect(&proxy) {
        Ok(stream) => stream,
        Err(error) => return refused("FETCH", &subject, &error),
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {credential}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return refused("FETCH", &subject, &error);
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("0");
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    println!(
        "FETCH_STATUS {subject} status={status} :: {}",
        one_line(body.trim())
    );
}

fn search_path() {
    match std::env::var("PATH") {
        Ok(value) => println!("PATH_SET value={}", one_line(&value)),
        Err(_) => println!("PATH_UNSET"),
    }
}

fn connect(path: &str) {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => println!("CONNECT_OK {path:?}"),
        Err(error) => refused("CONNECT", &format!("{path:?}"), &error),
    }
}

fn http_connect(url: &str) {
    let subject = format!("{url:?}");
    let (authority, path) = url
        .strip_prefix("http://")
        .map(|rest| rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}"))))
        .unwrap_or(("", "/".to_string()));
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = match std::net::TcpStream::connect(&address) {
        Ok(stream) => stream,
        Err(error) => return refused("HTTP_CONNECT", &subject, &error),
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let request = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    if let Err(error) = stream.write_all(request.as_bytes()) {
        return refused("HTTP_CONNECT", &subject, &error);
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    println!("HTTP_CONNECT_OK {subject} :: {}", one_line(body.trim()));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let operation = args.get(1).map(String::as_str).unwrap_or("");
    let rest: &[String] = if args.len() > 2 { &args[2..] } else { &[] };
    match (operation, rest) {
        ("env", names) => environment(names),
        ("copy", [from, to]) => copy(from, to),
        ("exec", [path, arguments @ ..]) => exec(path, arguments),
        ("dlopen", [path]) => load(path),
        ("fetch", [url, variable]) => fetch(url, variable),
        ("path", []) => search_path(),
        ("unix-connect", [path]) => connect(path),
        ("http-connect", [url]) => http_connect(url),
        _ => {
            eprintln!(
                "usage: leafprobe env NAME... | copy FROM TO | exec PATH ARG... | dlopen PATH | fetch URL VAR | path | unix-connect PATH | http-connect URL"
            );
            std::process::exit(2);
        }
    }
}
