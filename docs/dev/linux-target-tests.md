# Linux target tests

Use this runner to check an installed Box package on ARM64 Linux.
It needs Python 3.9 or later, Bash at `/usr/bin/bash`, readable process information, and Linux process handles.
Run it as the same user that starts Box in the intended deployment.
It changes no platform settings and uses no cloud credentials.

## Prepare the package

Build Box and the existing lifecycle fixture on an ARM64 Linux build host:

```sh
cargo build --locked -p strands-box -p strands-box-containment --all-features
rustc --edition=2024 -O test-integ/tests/phase3/probe.rs -o target/debug/target-lifecycle-probe
```

Copy the following files to the target:

- `strands-box`, `strands-box-contain-trampoline`, and `strands-box-sock-alias` from the same build directory.
- `target-lifecycle-probe` from the command above.
- `test-integ/tools/target_validation.py`.

Keep the three Box executables together. Record the package source revision and deployment image identity.
The runner hashes each executable. The supplied revision is an operator assertion, not a verified link to source.
Use the deployment's normal Box environment and library dependencies.

## Run the checks

```sh
python3 target_validation.py run \
  --box /absolute/package/strands-box \
  --probe /absolute/package/target-lifecycle-probe \
  --revision FULL_SOURCE_COMMIT
```

The runner creates a private directory under `/var/tmp` and prints its report path.
Use `--root /absolute/new-directory` to select another location. That directory must not exist.
Keep the path short enough for Box's Unix sockets.
All fixtures, logs, and JSON reports remain available after the run.
The command exits nonzero if any check fails or cannot execute.

Seven checks cover startup, file access, normal exit, termination, forced termination, a harness deadline, and a later isolated run.
File checks require successful permitted access and unchanged protected contents.
Lifecycle checks observe a live workload and an advancing heartbeat before triggering shutdown.
They inspect survivors and further writes before test-owned cleanup.
The runner signals only processes identified inside its fixture tree and checks their process identities.

The deadline check sends a termination signal when a harness timer expires.
It does not test the deployment service's cancellation or timeout interface.
These focused checks supplement the full deterministic suite and workload matrices.
A passing report does not establish native filesystem mediation or release qualification.

## Check expected native refusal

Add `--expect-native-refusal` only when testing a native-capable candidate on a known unsupported configuration.
The extra case requires a recognized native setup error and no workload entry marker.
An arbitrary nonzero exit, a missing feature build, or a usage error cannot pass.
A supported native configuration should fail this refusal case because the workload can start.
Use the native enforcement suite to qualify successful mediation.

## Check continuity across restoration

First complete a passing `run`. Then start the bounded restoration fixture with the same package and report directory:

```sh
python3 target_validation.py restore-start \
  --box /absolute/package/strands-box \
  --probe /absolute/package/target-lifecycle-probe \
  --revision FULL_SOURCE_COMMIT --root /var/tmp/REPORTED_DIRECTORY
```

Use the deployment's actual suspend and resume operations. Retain their responses separately.
The fixture runs for at most 120 seconds. Resume and check it within that interval:

```sh
python3 target_validation.py restore-check \
  --box /absolute/package/strands-box \
  --probe /absolute/package/target-lifecycle-probe \
  --revision FULL_SOURCE_COMMIT --root /var/tmp/REPORTED_DIRECTORY
```

The check requires the same live Box process, unchanged binaries, an advancing heartbeat, and preserved file contents.
It then verifies cleanup, stopped writes, and a successful subsequent Box run.
Running these commands without a platform suspension tests the fixture only.
The report cannot prove that a platform restoration occurred.

## Test the evidence checks

```sh
python3 -m unittest discover -s test-integ/tools -p test_target_validation.py -v
```

These tests use test-owned processes and a substitute Box executable.
They reject missing workload entry, unrestricted access, missing heartbeat evidence, and unrelated native errors.
They also verify that cleanup leaves a similarly named process outside the fixture tree alive.
Run the installed-package checks as well; substitutes do not establish Box containment.
