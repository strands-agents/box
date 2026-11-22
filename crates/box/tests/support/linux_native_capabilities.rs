//! Native startup with effective and permitted-only loader authority.
use super::{bounded_output::bounded_output, root};
use std::cell::Cell;
use std::process::{Command, ExitCode};
use std::rc::Rc;

const SYS_ADMIN: u64 = 1 << 21;
const PERFMON: u64 = 1 << 38;
const BPF: u64 = 1 << 39;
const PAIR: u64 = BPF | PERFMON;
const NATIVE: u64 = SYS_ADMIN | PAIR;
const MARKER: &str = "native-capability-workload-ran";

struct Case {
    name: &'static str,
    effective: u64,
    permitted: u64,
    enabled: Option<bool>,
    callback: bool,
    loads: bool,
}

const CASES: &[Case] = &[
    Case {
        name: "sys-admin",
        effective: SYS_ADMIN,
        permitted: SYS_ADMIN,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "sys-admin-bpf",
        effective: SYS_ADMIN | BPF,
        permitted: SYS_ADMIN | BPF,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "sys-admin-perfmon",
        effective: SYS_ADMIN | PERFMON,
        permitted: SYS_ADMIN | PERFMON,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "sys-admin-pair",
        effective: NATIVE,
        permitted: NATIVE,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "pair",
        effective: PAIR,
        permitted: PAIR,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "bpf",
        effective: BPF,
        permitted: BPF,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "perfmon",
        effective: PERFMON,
        permitted: PERFMON,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "neither",
        effective: 0,
        permitted: 0,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "permitted-sys-admin",
        effective: 0,
        permitted: SYS_ADMIN,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "permitted-pair",
        effective: 0,
        permitted: PAIR,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "effective-bpf-permitted-pair",
        effective: BPF,
        permitted: PAIR,
        enabled: Some(true),
        callback: true,
        loads: false,
    },
    Case {
        name: "effective-pair-permitted-sys-admin",
        effective: PAIR,
        permitted: NATIVE,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "effective-sys-admin-permitted-pair",
        effective: SYS_ADMIN,
        permitted: NATIVE,
        enabled: Some(true),
        callback: true,
        loads: true,
    },
    Case {
        name: "off-sys-admin",
        effective: SYS_ADMIN,
        permitted: SYS_ADMIN,
        enabled: Some(false),
        callback: false,
        loads: false,
    },
    Case {
        name: "off-partial-pair",
        effective: BPF,
        permitted: BPF,
        enabled: Some(false),
        callback: false,
        loads: false,
    },
    Case {
        name: "off-neither",
        effective: 0,
        permitted: 0,
        enabled: Some(false),
        callback: false,
        loads: false,
    },
    Case {
        name: "callback-off-sys-admin",
        effective: SYS_ADMIN,
        permitted: SYS_ADMIN,
        enabled: Some(false),
        callback: true,
        loads: true,
    },
    Case {
        name: "callback-off-neither",
        effective: 0,
        permitted: 0,
        enabled: Some(false),
        callback: true,
        loads: false,
    },
    Case {
        name: "absent-sys-admin",
        effective: SYS_ADMIN,
        permitted: SYS_ADMIN,
        enabled: None,
        callback: false,
        loads: false,
    },
];

fn sets() -> Vec<u64> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:"]
        .map(|field| {
            u64::from_str_radix(
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(field))
                    .unwrap()
                    .trim(),
                16,
            )
            .unwrap()
        })
        .to_vec()
}

fn select(case: &Case) {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: header and data have the Linux version-three capability ABI and valid storage.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) },
        0
    );
    for (index, word) in data.iter_mut().enumerate() {
        let shift = index * 32;
        let mask = (NATIVE >> shift) as u32;
        word.effective = (word.effective & !mask) | ((case.effective >> shift) as u32);
        word.permitted = (word.permitted & !mask) | ((case.permitted >> shift) as u32);
        word.inheritable = (word.inheritable & !mask) | ((case.permitted >> shift) as u32);
    }
    // SAFETY: this isolated child changes only its own capabilities using valid ABI storage.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) },
        0
    );
    for capability in [21, 38, 39] {
        if case.permitted & (1 << capability) != 0 {
            // SAFETY: the selected capability is in this child's permitted and inheritable sets.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE,
                        capability,
                        0,
                        0,
                    )
                },
                0
            );
        }
    }
    let actual = sets();
    assert_eq!(actual[0] & NATIVE, case.effective);
    for value in &actual[1..4] {
        assert_eq!(value & NATIVE, case.permitted);
    }
}

fn guard_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter(|path| path.to_string_lossy().starts_with("anon_inode:bpf"))
        .count()
}

pub(super) fn check(name: &str) {
    let case = CASES.iter().find(|case| case.name == name).unwrap();
    select(case);
    let before = sets();
    let directory = tempfile::tempdir_in("/var/tmp").unwrap();
    let root = directory.path();
    std::fs::create_dir(root.join("workspace")).unwrap();
    std::fs::write(
        root.join("policy.dw"),
        "permit(principal, action, resource);\n",
    )
    .unwrap();
    let quote =
        |path: std::path::PathBuf| toml::Value::String(path.display().to_string()).to_string();
    let selection = case
        .enabled
        .map(|enabled| format!("[experimental-features]\nnative-filesystem-policy = {enabled}\n"))
        .unwrap_or_default();
    let config = root.join("box.toml");
    std::fs::write(&config, format!(
        "name = \"capability-admission\"\nbox_dir = {}\npolicy = \"policy.dw\"\n{selection}[agent]\ncommand = [\"/usr/bin/printf\", \"{MARKER}\\n\"]\nworkspace = {}\n",
        quote(root.join("state")), quote(root.join("workspace"))
    )).unwrap();
    let enabled = case.enabled == Some(true);
    let callback_ran = Rc::new(Cell::new(false));
    let options = strands_box::RunOptions {
        on_ready: case.callback.then(|| {
            let callback_ran = Rc::clone(&callback_ran);
            Box::new(move || {
                callback_ran.set(true);
                assert_eq!(
                    guard_descriptors(),
                    if case.loads { 4 } else { 0 },
                    "{}: attached guard descriptors",
                    case.name
                );
                Ok(())
            }) as Box<dyn FnOnce() -> std::io::Result<()>>
        }),
        ..Default::default()
    };
    let result = strands_box::run(config, Vec::new(), options);
    assert_eq!(
        callback_ran.get(),
        case.callback,
        "{}: callback invocation",
        case.name
    );
    assert_eq!(
        result,
        if !enabled || case.loads {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        },
        "{}: startup result",
        case.name
    );
    let after = sets();
    for (index, value) in after.iter().enumerate() {
        assert_eq!(
            *value,
            if index == 4 {
                before[index]
            } else {
                before[index] & !PAIR
            },
            "{}: capability set {index}",
            case.name
        );
    }
    assert_eq!(guard_descriptors(), 0, "{}: guard detach", case.name);
}

pub(super) fn run() {
    // SAFETY: getuid has no arguments and reads this test process's identity.
    assert_eq!(unsafe { libc::getuid() }, 0);
    assert_eq!(
        sets()[0] & NATIVE,
        NATIVE,
        "root runner needs all three capabilities to select each case"
    );
    let directory = tempfile::tempdir_in("/var/tmp").unwrap();
    let binary = root::binary();
    let installed = root::install_bundle(
        directory.path(),
        &std::env::current_exe().unwrap(),
        binary.parent().unwrap(),
    );
    for case in CASES {
        let mut command = Command::new(&installed);
        command
            .arg(format!("--admission={}", case.name))
            .stdin(std::process::Stdio::null());
        let output = bounded_output(command);
        assert!(
            output.status.success(),
            "{}: {}",
            case.name,
            String::from_utf8_lossy(&output.stderr)
        );
        let ran = String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == MARKER);
        assert_eq!(
            ran,
            case.enabled != Some(true) || case.loads,
            "{}: workload marker",
            case.name
        );
        if case.enabled == Some(true) && !case.loads {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("requires CAP_BPF and CAP_PERFMON"),
                "{}: {}",
                case.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!("native capability admission: {} passed", case.name);
    }
}
