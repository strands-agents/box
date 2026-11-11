# How Box runs Python scripts

Box's Python is [Monty](https://github.com/pydantic/monty), an interpreter for a subset of Python,
written in Rust by Pydantic. Monty performs no input or output itself. Each file operation pauses
the interpreter. Box asks policy for a decision and performs only permitted operations. A script
reaches the network through one function, `fetch()`.

| Monty | What it does |
|---|---|
| Runs in | The box's trusted process, beside the policy engine. One Monty instance for each script, with no state kept between scripts. |
| Is reached by | The `python3` or `python` alias, or a `python` command typed in Strands Shell. |
| Decides | `fs:read`, `fs:write`, `fs:delete`, or `fs:move` for each file operation. It raises no other action. |
| Reaches the network through | `fetch()`, which sends each request to the egress gateway. The gateway decides `net:connect` and `http:request`. |
| Refuses | Environment reads, `Path.resolve()`, `Path.absolute()`, `mkdir(parents=True)`, and every module Monty doesn't implement, whatever the policy says. |

The box's trusted process runs outside the agent's sandbox. It holds the policy engine, the broker,
which accepts the agent's requests to Box's interpreters, and the egress gateway, which checks and
forwards every outbound request. The reachable paths check is deny-only and runs after policy. It
refuses the box directory, the `box.toml` and policy this run loaded, and any path outside the
operator's home, the agent's `HOME`, and the workspace.

For the Python that Monty supports, the file operations, `fetch()`, and the rules to write, read
[Python scripts in a box](../user/monty.md).

## Why a script can't act on its own

Monty uses Ruff's parser and its own bytecode interpreter to run Python without CPython. Every call
a script makes that would touch the surrounding OS, such as `open()`, `Path.read_text()`, or
`os.listdir()`, pauses the interpreter and hands the call to Box. Box decides it, performs it or
refuses it, and resumes the script with the result. `import subprocess` raises
`ModuleNotFoundError`, so a script can't start a program either.

A process in the agent's sandbox reaches Monty only through an alias, a client program in the
sandbox that forwards a request over a local socket. The broker runs the script and returns its
output and its exit status. See [an interpreter runs beside the workload, never inside
it](decisions.md#interpreters-are-brokered-aliases). A tool's sandbox gets no alias, so a `python3`
that a tool runs is the host OS's Python, not the box's Python.

Monty supports a subset of Python. A script that imports a PyPI package or a module Monty does not
implement fails at that `import`.

## The two routes to Monty

The agent reaches Monty two ways, and Box decides both with its one policy engine, as the same
principal. See [a workload reaches Monty two ways](decisions.md#python-in-the-shell-is-monty):

| | The `python3` or `python` alias | `python` or `python3` typed in Strands Shell |
|---|---|---|
| Example | The harness runs `python3 -c "print(6*7)"` | The agent's shell command is `python3 report.py` |
| Command-level decision | None | `shell:exec`, with `program` set to the name typed |
| How the script file is read | The alias reads it, with the agent's own access, before it sends the source | Strands Shell reads it, and policy decides an `fs:read` on it |
| Effects of the script | `fs:*` for each file operation | The same |

Strands Shell implements `python` and `python3` as commands that run Monty. They select Monty even
when the operator's `PATH` contains the host OS's Python. `python3 --version` prints `Monty
(Strands-Box Python subset)`. See [a bare `python` name always means
Monty](decisions.md#a-bare-python-name-always-means-monty).

The broker provides no standard input and forwards no signals to a Python program. `input()` raises
`NameError`. In Strands Shell a `python` with no `-c` and no script file is refused rather than
opening a REPL.

## How Box decides a file operation

Each file operation a script makes passes through five steps, in this order. See [Monty is judged at
the effect level alone](decisions.md#monty-is-judged-at-the-effect-level-alone).

```mermaid
sequenceDiagram
    participant Agent
    participant Alias as python3 alias
    participant Broker as Broker, in the box's trusted process
    participant Monty
    participant Policy as Policy engine
    participant Floor as Reachable paths check
    participant Disk as Filesystem

    Agent->>Alias: python3 -c source
    Alias->>Broker: the source, over the local socket
    Broker->>Monty: run the script
    Monty->>Broker: pause at Path('notes.txt').read_text()
    Broker->>Broker: root notes.txt at the workspace
    Broker->>Policy: fs:read, read_content, ~/src/project/notes.txt
    Policy-->>Broker: permit
    Broker->>Floor: approve the canonical path
    Floor-->>Broker: approved
    Broker->>Disk: read through the held path
    Disk-->>Broker: the file's text
    Broker->>Policy: record completed
    Broker->>Monty: resume with the text
    Monty-->>Broker: complete, with the output
    Broker-->>Alias: output and status
    Alias-->>Agent: output and status
```

1. Root the path. A relative path is rooted at the workspace, the directory `[agent] workspace`
   names, so `notes.txt` means the same file it means in Strands Shell.
2. Ask policy. Box asks the policy engine for one `fs:*` decision on the rooted path, with an
   `operation` that says which kind of access it is. A path under the operator's home reaches policy
   as `~/<relative path>`, the same spelling Strands Shell uses. A denial resumes the script with a
   `PermissionError`, which it can catch like any Python error.
3. Approve the canonical path. After policy permits, the reachable paths check inspects the path's
   canonical form, with every link resolved. It refuses the box directory, the `box.toml` and policy
   this run loaded, anything outside the operator's home and the workspace, and any spelling that
   isn't its own canonical path. A permit can't widen it. See [the policy is the only decision
   authority](decisions.md#the-authored-policy-is-the-only-decision-authority), and its refusal is
   also a `PermissionError`.
4. Act on the approved path. Box walks the approved path from `/`, one directory at a time,
   following no symbolic link, and acts on the last path component inside the directory it holds
   open. A directory or a file the workload swaps for a link after the approval is never followed.
5. Record the outcome. Box records how the operation ended in the policy history, so a history rule
   can count completed reads, or close egress after a read. See [what a history rule
   sees](./policy.md#what-a-history-rule-sees).

`Path.rename()` checks both the source and destination. It reads and moves the source. It can
replace a destination after policy permits its deletion. Box asks `fs:read` and `fs:move` on the
source, `fs:delete` on an existing destination, and `fs:move` on the destination. The reachable
paths check approves both paths. See [an overwriting rename also raises a
delete](decisions.md#an-overwriting-rename-also-deletes-the-destination).

Box retains whether the destination existed when policy checked it. If it did not exist, the rename
must atomically refuse replacement. A destination created after that check survives, and Box records
a failed move. If the platform cannot perform that operation, Box returns the error without a
replacing retry.

## What Monty performs, and what it refuses

Box performs a file operation only when a rule can name it, and when its result reveals nothing a
rule didn't permit. See [Monty performs an effect only when policy can govern
it](decisions.md#monty-performs-only-effects-the-box-can-govern).

Box supports reading and writing text and bytes, appending, `open()`, listing directories, `stat`,
existence and type tests, creating one directory, removing a file or empty directory, and renaming.
`open()` returns a handle. Each later read or write pauses the interpreter for a new decision, so
the handle cannot access a path beyond its approved reach.

`stat` returns the real size and file type. It hides account identity by reporting the user ID and
group ID as `0` and the link count as `1`.

Box refuses the following calls regardless of policy:

- `Path.resolve()` and `Path.absolute()` return a path to the script. Box asks policy for an
  `fs:read` on the path first, so the attempt reaches the history, and then refuses the call with a
  `RuntimeError` that says it's not supported.
- `os.getenv()` and `os.environ` raise a `RuntimeError`. No policy action names an environment
  variable, and the agent's environment holds the placeholders that stand in for credentials.
- `mkdir(parents=True)` raises a `PermissionError`, because one decision on the last directory can't
  bound the directories it would create above it. A script creates each level with its own
  `mkdir()`.

## Time and randomness

`datetime.now()` returns the current UTC time without a time zone. `date.today()` returns the UTC
date, whereas CPython uses the local time zone. `time.time()`, the monotonic clock, `os.urandom()`,
and `time.sleep()` take no policy decision, because none of them touches a resource a rule could
name.

## How a script reaches the network

`fetch()` is the only network call a script has, and Box sends each request to the egress gateway.
See [how Box controls outbound traffic](./egress.md). Monty adds no decision of its own. The gateway
decides `net:connect` and `http:request`, for a script as for the agent's own traffic.

Before it sends anything, Box refuses a URL that names a local or private address, with the same
check `curl` in Strands Shell uses, and the request trusts only the gateway's certificate authority.
See [how traffic reaches the gateway](./egress.md#how-traffic-reaches-the-gateway). Box reads at
most 1 MiB of a response body, and a larger body raises an `OSError`.

A refusal reaches the script as a response. When `http:request` refuses a request, the script gets
an ordinary response with status `403`, the header `x-strands-box-egress: refused`, and a body that
says why. Strands Shell turns that response into an error for `curl`, and Monty doesn't turn it into
an exception. See [a gateway refusal never reaches the workload as a successful
response](decisions.md#a-gateway-refusal-never-reports-success).

## Limits and exit statuses

The broker builds a new Monty instance for each script and drops it at the end, so a variable one
script sets is undefined in the next. See [no interpreter state crosses a call
boundary](decisions.md#no-state-crosses-a-call-boundary). Two scripts can run at the same time.

Box limits the number of calls it answers for each script, the script's total sleep, and the size of
one allocation. See [Monty handles one request per VM, and bounds each
allocation](decisions.md#monty-is-per-request-and-buffers-its-output). A script that passes a bound
raises a Python exception, and the box keeps serving. The values are in [limits and exit
statuses](../user/monty.md#limits-and-exit-statuses).

The exit status identifies the outcome. `0` means the script completed. `1` means it raised an
exception it did not catch, such as a policy denial, a limit violation, a `NameError` for an
undefined name, or a script error. `125` means the script did not finish because Box failed or the
alias stopped waiting for the script. See [a suspension Box doesn't service is a Python
error](decisions.md#an-unserviced-suspension-is-a-python-error).

## Example: the write, and two refusals

The diagram above follows the read in this script. The workspace is `~/src/project`, and it holds
`notes.txt` and an empty `out` directory. `policy.dw` permits `fs:read` under the workspace and
`fs:write` under `out`.

```sh
python3 -c "from pathlib import Path
text = Path('notes.txt').read_text()
Path('out/notes.txt').write_text(text.upper())
print('wrote', len(text))"
```

1. After the read, `text.upper()` runs inside Monty without pausing.
2. `write_text()` pauses Monty. Box roots `out/notes.txt` at the workspace, and policy permits
   `fs:write` with operation `write_content` on `~/src/project/out/notes.txt`.
3. The reachable paths check approves the canonical path, Box writes the file through the directory
   it holds open, and records the write as completed.
4. The script prints `wrote 18`, and the alias exits `0`.

If the script writes `notes.txt` instead, policy denies the operation at step 2 because no
`fs:write` rule permits it. Box resumes the script with `PermissionError: policy denied this
operation on '<path>' [default-deny]`, the file is unchanged, and the alias exits `1`. A script that
catches the `PermissionError` carries on, and exits `0`.

If `notes.txt` links to `~/.aws/credentials`, policy permits the read because the rule compares the
path as text. The reachable paths check refuses it, because `notes.txt` resolves to a different
path, and the script gets a `PermissionError` that names the path of `notes.txt`, not the file
behind it. The check refuses a write through a link the same way, even when the link points at a
file that doesn't exist yet.

## Residual risk

- Monty runs in the box's trusted process. That process holds the policy engine, the certificate
  authority key that the egress gateway signs with, and the credentials Box resolved, and it's
  outside every sandbox. Monty contains `unsafe` Rust code, so treat a memory defect in Monty as
  code execution in that process. See [both interpreters run in the box's trusted
  process](decisions.md#the-interpreters-run-in-the-trusted-process). Without such a defect, every
  effect still has to come back to Box as a paused call.
- A script's total memory has no bound. Box refuses one allocation above 128 MiB, but a script that
  grows in small steps can use all the memory of the box's trusted process.
- `fetch()` returns a `403` response when the gateway refuses a request. A script that does not
  check the status may treat the refusal as a successful answer.
- One broad rule reaches the operator's secrets. Monty reaches the whole operator home, so an
  `fs:read` permit with no path condition reads `~/.ssh` and `~/.aws`. See [where policy
  sits](./policy.md#where-policy-sits).

## See also

- [Python scripts in a box](../user/monty.md): what Monty supports, `fetch()`, the limits, and the
  rules to write.
- [How Box contains a process](./containment.md): the agent's sandbox, and the two kinds of
  enforcement.
- [How Box controls outbound traffic](./egress.md): how the gateway decides and forwards a
  `fetch()`.
- [Policy](./policy.md): how the engine decides each request, and the reachable paths check.
