# Run Box on Linux

Box supports Linux ARM64 and macOS on Apple silicon.
ARM64 is the 64-bit Arm architecture.
This Linux example reads a file, writes an output, and refuses an overwrite of its read-only input.
It uses Bash and requires no model credentials.

## Before you start

Use Amazon Linux 2023 ARM64 with glibc 2.34 or newer and libgcc.
Install Bash, tar, gzip, and the `sha256sum` utility.
The surrounding OS must permit Box to create namespaces, mount filesystems, and apply system-call filters.
A namespace gives a process a separate view of resources such as files and network interfaces.
Container security settings can prevent this setup.

Keep Box's binaries, configuration, and state outside the workload's writable paths.
For cloud deployment requirements, see the [Amazon EKS](tutorials/eks.md) and
[AgentCore Runtime](tutorials/agentcore-runtime.md) examples.
Those examples state their tested configurations and limits.

## Step 1. Download Box

Create an empty `~/box-linux-tutorial` directory.
From the [Box releases](https://github.com/strands-agents/box/releases), download the
`box-<tag>-aarch64-unknown-linux-gnu.tar.gz` archive and `SHA256SUMS.txt` from the same release into that directory.
The release tag replaces `<tag>` in the archive name.

In that directory, verify the checksum before extraction:

```sh
sha256sum --check --ignore-missing SHA256SUMS.txt &&
  mkdir box-core &&
  tar -C box-core -xzf box-*-aarch64-unknown-linux-gnu.tar.gz &&
  ./box-core/box --version
```

The checksum command prints the archive name followed by `OK`.
The version command prints `strands-box` followed by the release version.
Keep `box`, `strands-box-sock-alias`, and `strands-box-contain-trampoline` together in `box-core`.
The Linux archive contains the executable and its helpers.
The macOS archive uses a signed application bundle.

For releases that request explicit Linux consent, set this variable in the terminal that runs Box:

```sh
export EXPERIMENTAL_LINUX_SUPPORT=TRUE
```

This setting grants no filesystem or network access.

## Step 2. Configure a workload

Create a readable project with one writable output directory:

```sh
mkdir -p project/output
printf 'hello from Linux\n' > project/input.txt
work_dir="$(pwd -P)"
cat > box.toml <<EOF
name = "linux-example"
box_dir = "$work_dir/state"
policy = "$work_dir/policy.dw"

[agent]
command = ["bash", "-eu", "-c", """
read -r message < input.txt
printf '%s\n' "\$message"
printf 'allowed\n' > output/result.txt
if printf 'forbidden\n' > input.txt; then
  printf 'ERROR: input.txt was writable\n'
  exit 1
fi
printf 'read-only input protected\n'
"""]
workspace = "$work_dir/project"

[agent.filesystem]
read = ["$work_dir/project"]
write = ["$work_dir/project/output"]
EOF
printf '' > policy.dw
```

The Bash workload reads the input, writes an output, and attempts to overwrite the
read-only input. These are direct operations from the workload's process. The operating
system enforces their grants. They do not produce individual policy decisions.
The empty policy permits no mediated actions through Box.

Linux requires explicit read access over the entire scope of each write grant.
Here, the parent read grant covers the writable output directory. Do not add read access
when the workload must have write-only access. Linux cannot enforce that requirement
through direct filesystem grants.

## Step 3. Run and check the result

Run the configured workload:

```sh
./box-core/box run --config box.toml &&
  cat project/output/result.txt &&
  cat project/input.txt
```

The workload should print `hello from Linux` and `read-only input protected`.
Bash also reports the refused attempt to overwrite `input.txt` on stderr.
The output file contains `allowed`. The input still contains `hello from Linux`.
A startup error does not prove that the sandbox refused the write during execution.

## Adapt an agent

Grant the agent's runtime files separately from project files.
Use the [configuration reference](config.md#direct-access-by-operating-system) when adapting a macOS configuration.
Linux requires read access across each write grant and refuses `list` grants.
Replacing `list` with `read` also exposes file contents.

Use [Strands Shell](shell.md) or [Monty](monty.md) when policy must decide each file operation.
Keep [gateway networking](egress.md) enabled when policy must decide outbound requests.
A tool or local server with `contain_egress = false` reaches surrounding-OS networks outside gateway policy.
See [network settings](mcp.md#network) before granting that access.

The experimental [native filesystem policy](native-filesystem-policy.md) requires macOS.

The [platform comparison](../design/platform-differences.md) covers filesystem, runtime, and network differences.
[Linux enforcement](../design/linux-enforcement.md) explains the isolation mechanisms and setup requirements.

## If startup fails

| Symptom | Action |
|---|---|
| Linux consent error | Set the opt-in variable if the release requests it. |
| Namespace or mount error | Check the complete setup requirements with the operator of the surrounding OS. |
| Write-grant refusal | Add read coverage only when the workload may read the entire writable scope. |
| Symbolic-link grant refusal | Grant the resolved target path. |
| Runtime fails while compiling code | Check its executable-memory requirements against the platform comparison. |
