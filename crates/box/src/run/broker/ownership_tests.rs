//! Linux identity controls for file creation through the trusted interpreters.

use std::future::Future;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use policy::{GovernedBox, Policy, ShellPolicyInterceptor};
use strands_shell::Shell;
use strands_shell::os::{Follow, Kernel, OpenFlags};
use strands_shell::vfs_config::{VfsConfig, build_vfs};
use strands_shell::vfs_kernel::VfsKernel;

use super::held::HeldPath;
use super::kernel::CallKernel;
use super::mcp::DiscoveryRegistry;
use super::python;
use super::reach::Reach;
use super::shell::ShellSpec;
use crate::run::telemetry::DecisionRecorder;
use crate::test_support::open_policy;

const CHILD: &str = "BOX_OWNERSHIP_TEST_CHILD";
const COMPLETED: &str = "BOX_OWNERSHIP_TEST_COMPLETED=";

fn identity() -> (libc::uid_t, libc::uid_t) {
    // SAFETY: these calls only read this process's user identities.
    unsafe { (libc::getuid(), libc::geteuid()) }
}

pub(super) fn under_identity(name: &str, root: bool, body: impl FnOnce()) {
    let (real, effective) = identity();
    let matches = if root {
        real == 0 || effective == 0
    } else {
        real != 0 && effective != 0
    };
    if std::env::var(CHILD).as_deref() == Ok(name) {
        assert!(matches, "child has the wrong identity: {real}/{effective}");
    }
    if !matches {
        let executable = std::env::current_exe().expect("the test executable");
        let mut command = if root {
            let mut command = Command::new("/usr/bin/unshare");
            command
                .args(["--user", "--map-root-user", "--"])
                .arg(executable);
            command
        } else {
            let mut command = Command::new(executable);
            command.uid(65534).gid(65534);
            command
        };
        let exact = if name.contains("::") {
            name.to_string()
        } else {
            let module = module_path!().split_once("::").expect("the crate prefix").1;
            format!("{module}::{name}")
        };
        let output = command
            .env(CHILD, name)
            .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
            .output()
            .expect("start the identity-isolated test; setup failure is not a pass");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{exact}: {stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!("{COMPLETED}{name};")),
            "the child must execute every assertion: {stdout}\n{stderr}"
        );
        return;
    }
    body();
    println!("{COMPLETED}{name};ruid={real};euid={effective}");
}

pub(super) fn run(future: impl Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    runtime.block_on(tokio::task::LocalSet::new().run_until(future));
}

struct Fixture {
    _directory: tempfile::TempDir,
    home: PathBuf,
    spec: ShellSpec,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("an isolated fixture");
        let home = directory
            .path()
            .canonicalize()
            .expect("the canonical fixture");
        for name in ["existing", "source", "replacement"] {
            std::fs::write(home.join(name), b"ORIGINAL").expect("seed an existing file");
        }
        let spec = ShellSpec {
            command_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            reach: Arc::new(Reach::over(&home, None, None).expect("the fixture is reachable")),
            policy: Arc::new(open_policy(vec![Policy {
                origin: PathBuf::from("<ownership-test>"),
                text: "permit(principal, action, resource);".to_string(),
            }])),
            governed: GovernedBox::assigned("ownership"),
            spawn_credentials: Default::default(),
            mcp: Arc::new(Vec::new()),
            mcp_registry: DiscoveryRegistry::testing(&[]),
            mcp_working_directory: home.clone(),
            mcp_working_directory_handle: None,
            mcp_leaf_launcher: None,
            egress: None,
            recorder: DecisionRecorder::discarding(),
            host_spawner: None,
        };
        Self {
            _directory: directory,
            home,
            spec,
        }
    }

    async fn python(&self, source: &str) -> python::PythonOutcome {
        python::run_python(
            source.to_string(),
            &self.spec.reach,
            &self.spec.policy,
            &self.spec.governed,
            None,
            &self.spec.recorder,
        )
        .await
    }
}

struct Creation {
    source: &'static str,
    destination: &'static str,
    moves_source: bool,
}

const SHELL_CREATIONS: &[Creation] = &[
    Creation {
        source: "printf CREATED > created",
        destination: "created",
        moves_source: false,
    },
    Creation {
        source: "printf APPENDED >> appended",
        destination: "appended",
        moves_source: false,
    },
    Creation {
        source: "touch touched",
        destination: "touched",
        moves_source: false,
    },
    Creation {
        source: "cp existing copied",
        destination: "copied",
        moves_source: false,
    },
    Creation {
        source: "mkdir directory",
        destination: "directory",
        moves_source: false,
    },
    Creation {
        source: "ln -s existing link",
        destination: "link",
        moves_source: false,
    },
    Creation {
        source: "mv source moved",
        destination: "moved",
        moves_source: true,
    },
    Creation {
        source: "mv source replacement",
        destination: "replacement",
        moves_source: true,
    },
];

const PYTHON_CREATIONS: &[Creation] = &[
    Creation {
        source: "from pathlib import Path\nPath('created').write_text('CREATED')",
        destination: "created",
        moves_source: false,
    },
    Creation {
        source: "from pathlib import Path\nPath('bytes').write_bytes(b'CREATED')",
        destination: "bytes",
        moves_source: false,
    },
    Creation {
        source: "with open('opened', 'w') as file:\n    file.write('CREATED')",
        destination: "opened",
        moves_source: false,
    },
    Creation {
        source: "with open('appended', 'a') as file:\n    file.write('APPENDED')",
        destination: "appended",
        moves_source: false,
    },
    Creation {
        source: "from pathlib import Path\nPath('directory').mkdir()",
        destination: "directory",
        moves_source: false,
    },
    Creation {
        source: "from pathlib import Path\nPath('source').rename('moved')",
        destination: "moved",
        moves_source: true,
    },
    Creation {
        source: "from pathlib import Path\nPath('source').rename('replacement')",
        destination: "replacement",
        moves_source: true,
    },
];

fn check_creation(fixture: &Fixture, case: &Creation, status: i32, stderr: &str, root: bool) {
    let destination = fixture.home.join(case.destination);
    if root {
        assert_ne!(status, 0, "root unexpectedly completed {}", case.source);
        assert!(
            stderr.contains("root"),
            "expected an ownership refusal for {}: {stderr}",
            case.source
        );
        if case.destination == "replacement" {
            assert_eq!(std::fs::read(&destination).unwrap(), b"ORIGINAL");
        } else {
            assert_eq!(
                std::fs::symlink_metadata(&destination).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "no host entry may be created by {}",
                case.source
            );
        }
        assert_eq!(
            std::fs::read(fixture.home.join("source")).unwrap(),
            b"ORIGINAL"
        );
    } else {
        assert_eq!(
            status, 0,
            "ordinary-user creation failed for {}: {stderr}",
            case.source
        );
        assert_eq!(
            std::fs::symlink_metadata(&destination).unwrap().uid(),
            identity().1
        );
        if case.moves_source {
            assert!(!fixture.home.join("source").exists());
            assert_eq!(std::fs::read(&destination).unwrap(), b"ORIGINAL");
        }
    }
    assert_eq!(
        std::fs::read(fixture.home.join("existing")).unwrap(),
        b"ORIGINAL"
    );
}

async fn shell_creation_cases(root: bool) {
    for case in SHELL_CREATIONS {
        let fixture = Fixture::new();
        let mut shell = fixture.spec.build().expect("the production Shell builds");
        let output = shell.run(case.source).await;
        check_creation(&fixture, case, output.status, &output.stderr, root);
    }
}

async fn python_creation_cases(root: bool) {
    for case in PYTHON_CREATIONS {
        let fixture = Fixture::new();
        let output = fixture.python(case.source).await;
        check_creation(&fixture, case, output.status, &output.stderr, root);
    }
}

#[test]
fn root_shell_refuses_new_host_entries() {
    under_identity("root_shell_refuses_new_host_entries", true, || {
        run(shell_creation_cases(true))
    });
}

#[test]
fn root_python_refuses_new_host_entries() {
    under_identity("root_python_refuses_new_host_entries", true, || {
        run(python_creation_cases(true))
    });
}

#[test]
fn nonroot_shell_preserves_host_creation() {
    under_identity("nonroot_shell_preserves_host_creation", false, || {
        run(shell_creation_cases(false))
    });
}

#[test]
fn nonroot_python_preserves_host_creation() {
    under_identity("nonroot_python_preserves_host_creation", false, || {
        run(python_creation_cases(false))
    });
}

#[test]
fn root_shell_preserves_existing_reads_writes_and_append() {
    under_identity(
        "root_shell_preserves_existing_reads_writes_and_append",
        true,
        || {
            run(async {
                let fixture = Fixture::new();
                let mut shell = fixture.spec.build().expect("the production Shell builds");
                let output = shell.run("cat existing").await;
                assert_eq!(output.status, 0, "{}", output.stderr);
                assert_eq!(output.stdout, "ORIGINAL");
                for (command, expected) in [
                    ("printf UPDATED > existing", "UPDATED"),
                    ("printf APPENDED >> existing", "UPDATEDAPPENDED"),
                ] {
                    let output = shell.run(command).await;
                    assert_eq!(output.status, 0, "{command}: {}", output.stderr);
                    assert_eq!(
                        std::fs::read_to_string(fixture.home.join("existing")).unwrap(),
                        expected
                    );
                }
            })
        },
    );
}

#[test]
fn root_python_preserves_existing_reads_writes_and_append() {
    under_identity(
        "root_python_preserves_existing_reads_writes_and_append",
        true,
        || {
            run(async {
                let fixture = Fixture::new();
                let output = fixture
                    .python("from pathlib import Path\nprint(Path('existing').read_text())")
                    .await;
                assert_eq!(output.status, 0, "{}", output.stderr);
                assert_eq!(output.stdout, "ORIGINAL\n");
                for (source, expected) in [
                    (
                        "from pathlib import Path\nPath('existing').write_text('UPDATED')",
                        "UPDATED",
                    ),
                    (
                        "with open('existing', 'a') as file:\n    file.write('APPENDED')",
                        "UPDATEDAPPENDED",
                    ),
                ] {
                    let output = fixture.python(source).await;
                    assert_eq!(output.status, 0, "{source}: {}", output.stderr);
                    assert_eq!(
                        std::fs::read_to_string(fixture.home.join("existing")).unwrap(),
                        expected
                    );
                }
            })
        },
    );
}

#[test]
fn root_shell_does_not_recreate_a_leaf_removed_after_resolution() {
    under_identity(
        "root_shell_does_not_recreate_a_leaf_removed_after_resolution",
        true,
        || {
            run(async {
                for flags in [OpenFlags::write(), OpenFlags::append()] {
                    let fixture = Fixture::new();
                    let kernel = CallKernel::new(
                        fixture.spec.backend().expect("the production backend"),
                        telemetry::Correlation::from_headers(None, None),
                        None,
                    );
                    let mut process = kernel.new_process();
                    let path = fixture.home.join("existing");
                    let resolved = kernel
                        .resolve(&process, path.to_str().unwrap(), Follow::Yes)
                        .await;
                    assert!(
                        resolved.binding().is_some(),
                        "this must be a host-backed path"
                    );
                    std::fs::remove_file(&path).expect("remove the already resolved fixture leaf");
                    assert!(kernel.open(&mut process, resolved, flags).await.is_err());
                    assert_eq!(
                        std::fs::symlink_metadata(&path).unwrap_err().kind(),
                        io::ErrorKind::NotFound
                    );
                }
            })
        },
    );
}

#[test]
fn root_python_open_does_not_recreate_a_leaf_removed_after_reach() {
    under_identity(
        "root_python_open_does_not_recreate_a_leaf_removed_after_reach",
        true,
        || {
            for flags in [
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            ] {
                let fixture = Fixture::new();
                let path = fixture.home.join("existing");
                let held = HeldPath::of(&path).expect("hold the approved parent and leaf");
                std::fs::remove_file(&path).expect("remove the already reached fixture leaf");
                assert_eq!(
                    held.open(flags).unwrap_err().kind(),
                    io::ErrorKind::NotFound
                );
                assert_eq!(
                    std::fs::symlink_metadata(&path).unwrap_err().kind(),
                    io::ErrorKind::NotFound
                );
            }
        },
    );
}

#[test]
fn root_shell_preserves_virtual_storage() {
    under_identity("root_shell_preserves_virtual_storage", true, || {
        run(async {
            let fixture = Fixture::new();
            let mut backend =
                VfsKernel::new(build_vfs(&VfsConfig::default()).expect("a virtual filesystem"));
            backend.network_enabled = false;
            let kernel = CallKernel::new(
                Arc::new(backend),
                telemetry::Correlation::from_headers(None, None),
                None,
            );
            let process = kernel.new_process();
            let resolved = kernel
                .resolve(&process, "/tmp/ownership-control", Follow::No)
                .await;
            assert!(
                resolved.binding().is_none(),
                "the control must have no host binding"
            );
            let interceptor = ShellPolicyInterceptor::into_handle(
                Arc::clone(&fixture.spec.policy),
                policy::Principal::agent(),
                fixture.spec.governed.clone(),
            );
            let mut shell = Shell::builder()
                .kernel(Arc::new(kernel))
                .effect_interceptor(interceptor)
                .disable_network()
                .build()
                .expect("a Shell over virtual storage");
            let output = shell.run("mkdir /tmp/ownership-control && printf DATA > /tmp/ownership-control/item && printf APPEND >> /tmp/ownership-control/item && ln -s item /tmp/ownership-control/link && cat /tmp/ownership-control/link && mv /tmp/ownership-control/item /tmp/ownership-control/moved && cat /tmp/ownership-control/moved").await;
            assert_eq!(output.status, 0, "{}", output.stderr);
            assert_eq!(output.stdout, "DATAAPPENDDATAAPPEND");
        })
    });
}
