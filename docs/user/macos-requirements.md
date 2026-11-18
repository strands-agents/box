# macOS requirements

Box supports macOS on Apple silicon. Check the release package and the workload's access under the macOS account that will run Box.

## Requirements

| Requirement | Required value or configuration | How to check | What failure means |
| --- | --- | --- | --- |
| Architecture | Apple silicon, using the ARM64 (64-bit Arm) macOS release. | Run `uname -m`; expect `arm64`. | The downloader refuses an unsupported operating system and architecture. |
| Release package | Keep `Box.app`, the `box` launcher, and both helper links from the same release together. The helper links point into `Box.app/Contents/MacOS`. | Download and extract the complete package, then [check that Box loads](#check-the-installed-package). | Missing or moved files can prevent Box or a helper from starting. |
| Private state | In `box.toml`, `box_dir` names an absolute path for Box's private state. Keep the state outside the workspace and paths the workload can write. | Follow the [state-directory requirements](./config.md#keys) for creating or reusing the directory. | Box cannot create the directory, or refuses its path, ownership, or permissions. |
| Workload dependencies and access | Supply the program, its interpreters, libraries, certificates, and tools. Configure their access in `box.toml`, including writes the workload needs in its workspace. | Run the workload and its tools inside Box. | The program can fail to load, or an operation can fail after Box starts. |

The [Strands CLI walkthrough prerequisites](./getting-started.md#before-you-start) apply to that example.
Check the requirements of the workload you intend to run.

## Check the installed package

First [download Box and verify its release checksum](./getting-started.md#step-1-download-box).
These commands use the guide's `./box-core` directory.

Record the architecture and macOS version:

```sh
uname -m
sw_vers -productVersion
```

Expect `arm64` for the architecture. Run these checks and the downloader from an ARM64 terminal: a Mac with Apple silicon can report `x86_64` under Rosetta, Apple's translation for Intel applications.
Record the macOS version with your workload's check results; the version alone does not establish compatibility.

Run the installed launcher directly:

```sh
./box-core/box --version
```

The command must exit successfully and print `strands-box` followed by its version.
This checks that the main executable loads. It does not test helper execution, sandbox startup, or the workload.
Check this command's output and exit status even if the downloader completed.

The release's signed and notarized `Box.app` contains its executables and provisioning profile.
Moving only an executable out of the bundle loses that profile. Keep the complete downloaded directory intact.
For a source build, follow [Build from source](./getting-started.md#build-from-source).

## Check sandbox startup and the workload

Use your intended `box.toml` configuration and macOS account.
The [configuration reference](./config.md) describes the program, workspace, and access settings.
Replace `/absolute/path/box.toml` with the absolute path to your configuration:

```sh
./box-core/box run --config /absolute/path/box.toml
```

Box applies its macOS process sandbox before starting the configured program.
If applying those restrictions fails, Box does not start that program.
Once it starts:

1. Run an operation its configuration permits and check the expected output or file change.
2. Attempt a file operation outside its configured access and check that the operation fails.
3. Check that excluded files retain their original contents.

Run these checks for the application and tools you intend to use. A program that starts outside Box can still fail inside its sandbox.
Repeat the checks when Box, macOS, the workload, or its configuration changes.

## Optional native filesystem policy

Signed macOS releases include [experimental native filesystem policy](./native-filesystem-policy.md), which adds policy checks to selected native file operations.
It is disabled by default. This feature requires macOS 27 or later and a compatible signed build.
Follow [Enable the experiment](./native-filesystem-policy.md#enable-the-experiment) for its build, signing, and `box.toml` opt-in requirements.
If you select the feature when its requirements are unavailable, Box refuses startup instead of silently disabling it.
