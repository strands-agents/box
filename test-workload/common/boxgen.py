#!/usr/bin/env python3
"""boxgen.py — compose a box.toml + policy.dw pair for one workload case.

The reference pairs for the seven workloads share one skeleton and differ only in
which tool tables they carry, which hosts they permit, and which extra fs actions
the workload needs. Checking in 42 near-identical files (7 workloads x 2 platforms
x 3 agents) would mean 42 places to fix one spelling rule, so the skeleton lives
here once and each dimension declares its differences in a small manifest.

Inputs (argv):
  1  manifest file   — `key=value` lines from the dimension's wl_manifest
  2  paths json      — the host paths resolved by workload-lib.sh (WL_* )
  3  agent           — claude | codex | strands; any other name is refused
  4  project dir     — absolute, already created
  5  out dir         — where box.toml and policy.dw are written
  6  journal path    — [telemetry.decisions] destination (outside every box dir)
  7  box dir         — the box's private directory (exists, empty, mode 0700)

Spelling rules this file enforces, because the box refuses the alternative:
  * a program under the operator's home is spelled `~/...` in a shell:spawn
    permit and canonically elsewhere;
  * a symbolic link and a system root are refused by name, so only canonical
    files reach a grant;
  * `write` does not imply `read`;
  * a write grant may not enclose the box's own policy.dw — so box.toml and
    policy.dw are written OUTSIDE the project the workload may write;
  * a tool table holds no `exec` and no `metadata` list: on macOS the leaf runs its toolchain through broad exec, and on Linux
    the paths a tool execs are named in `read`, the one list left to name them.
"""
import json
import os
import sys

manifest_path, paths_path, AGENT, PROJECT, OUT, JOURNAL, BOXDIR = sys.argv[1:8]

# The agents this generator knows. An unknown name is refused here, before any
# host, command or grant is selected: a pair composed from another agent's shape
# is wrong rather than absent, and the cell then reports a workload failure
# instead of a generator failure.
AGENTS = ("claude", "codex", "strands")
if AGENT not in AGENTS:
    raise SystemExit("boxgen: unknown agent %r (known: %s)" % (AGENT, " ".join(AGENTS)))

P = json.load(open(paths_path))
# A resolver that predates a key must not crash a cell: an absent path reads as
# "not available on this host", which the tool shapes already handle.
P = {k: P.get(k, "") for k in set(P) | {"CA_BUNDLE", "BREW_READ", "NODE_FORMULA"}}
HOME = P["HOME"].rstrip("/")
PLAT = P["PLATFORM"]
REGION = os.environ.get("AWS_REGION", "us-west-2")

man = {}
for line in open(manifest_path):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    man[k.strip()] = v.strip()


def subst(s):
    """Expand the placeholders a manifest and a goal may use."""
    out = s.replace("{{PROJECT}}", PROJECT).replace("{{HOME}}", HOME)
    for k, v in P.items():
        out = out.replace("{{%s}}" % k, v)
    return out


def items(key):
    """A manifest value as a list of paths.

    The placeholder is expanded BEFORE splitting: one of them ({{BREW_READ}})
    stands for several paths, and splitting first would emit them as a single
    grant with spaces in it.
    """
    return [x for x in subst(man.get(key, "")).split() if x]


def plat_items(key):
    """`key` plus its platform-qualified sibling (key_linux / key_macos)."""
    return items(key) + items("%s_%s" % (key, PLAT))


def tilde(path):
    """The spelling the box reports: `~/...` beneath the operator home."""
    if path == HOME:
        return "~"
    if path.startswith(HOME + "/"):
        return "~/" + path[len(HOME) + 1:]
    return path


def toml_string(value):
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def toml_list(xs):
    return "[" + ", ".join(toml_string(x) for x in xs) + "]"


def toml_env(d):
    return "{ " + ", ".join('%s = %s' % (k, toml_string(v)) for k, v in d.items()) + " }"


def prune(entries):
    """Drop an entry that lies inside another entry in the SAME list.

    The box refuses one list that names both a directory and something beneath
    it: the inner entry says nothing the outer does not already say, and the
    refusal names the pair. Nesting ACROSS lists is not only allowed but usually
    required — an agent's `exec` entry inside its `read` grant is what lets a
    program under a readable tree run, and the measured macOS pairs are exactly
    that shape.
    """
    uniq = sorted({e for e in entries if e})
    return [e for e in uniq
            if not any(o != e and e.startswith(o.rstrip("/") + "/") for o in uniq)]


def check_no_nesting(label, name, entries):
    """Fail the generator, not the case, if a list still nests after pruning."""
    for a in entries:
        for b in entries:
            if a != b and a.startswith(b.rstrip("/") + "/"):
                raise SystemExit("boxgen: %s %s names %s inside %s" % (label, name, a, b))


def emit_lists(out, label, lists):
    """Prune, self-check, and emit the filesystem lists of one process."""
    for name, entries in lists:
        kept = prune(entries)
        if not kept:
            continue
        check_no_nesting(label, name, kept)
        out.append("%s = %s" % (name, toml_list(kept)))


# --- The agent process ------------------------------------------------------
TMP = PROJECT + "/.tmp"
# Codex speaks the Mantle wire protocol. The Claude and the Strands agents call
# the Bedrock runtime, which the egress gateway signs with the instance role, so
# both name the same host and neither holds a credential.
BEDROCK_HOST = "bedrock-runtime.%s.amazonaws.com" % REGION
MANTLE_HOST = "bedrock-mantle.%s.api.aws" % REGION
MODEL_HOST = {"claude": BEDROCK_HOST,
              "strands": BEDROCK_HOST,
              "codex": MANTLE_HOST}[AGENT]

if AGENT == "claude":
    allowed = man.get("tools_allow", "Glob,Grep,Read,Write,Edit,Bash")
    # A dimension may run the agent through a launcher instead of the binary: on
    # Amazon Linux 2023 a hook execs /bin/sh, which is a symbolic link no grant may
    # name, and a `#!/bin/sh` launcher's own interpreter chain brings it into the
    # view under the spelling the child asks for.
    prog = (plat_items("agent_program") or [P["CLAUDE"]])[0]
    agent_cmd = [prog, "--allowedTools", allowed] + plat_items("agent_args")
    agent_env = {
        "PATH": man.get("agent_path", "/usr/bin:/bin"),
        "AWS_REGION": REGION,
        "CLAUDE_CODE_USE_BEDROCK": "1",
        # Claude Code accepts --dangerously-skip-permissions as root only when
        # IS_SANDBOX is exactly "1"; it runs as root under SSM.
        "IS_SANDBOX": "1",
        "TMPDIR": TMP,
        # 2.1.276 and later create their scratch directory at /tmp/claude-<uid>
        # and read only this variable to move it; no grant covers /tmp.
        "CLAUDE_CODE_TMPDIR": TMP,
        "CLAUDE_CONFIG_DIR": PROJECT + "/.claude-config",
    }
elif AGENT == "strands":
    # An entry script the host's canonical python3 runs, with the SDK in a
    # `pip install --target` directory. Neither path is a symbolic link on either
    # platform, so a grant can name both, and a virtual environment is not used
    # because its `bin/python3` is a link the box refuses.
    launcher = plat_items("agent_program")
    if launcher:
        agent_cmd = [launcher[0]]
    else:
        agent_cmd = [P["PYTHON"], P["STRANDS"]] + plat_items("agent_args")
    # The model id carries a geography prefix that differs by region, and a wrong
    # one fails at the first model call. There is no default: an empty id is
    # refused here, so no pair is written that names a model the region lacks.
    if not P["STRANDS_MODEL"]:
        raise SystemExit("boxgen: WL_STRANDS_MODEL is empty for agent strands; "
                         "set the region's inference profile id, no default exists")
    if not P["PYTHON"] or not P["STRANDS_LIB"] or (not launcher and not P["STRANDS"]):
        raise SystemExit("boxgen: the interpreter, the SDK directory or the entry "
                         "script is unresolved for agent strands")
    agent_env = {
        "PATH": man.get("agent_path", "/usr/bin:/bin"),
        "AWS_REGION": REGION,
        "TMPDIR": TMP,
        # The box reserves every loader hook, PYTHONPATH included, and it refuses a
        # table that claims one. So the SDK directory travels under a name of this
        # suite, and the entry script puts it on sys.path itself.
        "STRANDS_LIB_DIR": P["STRANDS_LIB"],
        # The model id and the scratch directory travel in the environment, so the
        # agent needs no configuration file and the pair names no extra path.
        "STRANDS_MODEL_ID": P["STRANDS_MODEL"],
        "STRANDS_STATE_DIR": PROJECT + "/.strands",
    }
elif AGENT == "codex":
    # The npm package ships a Node shim that starts the vendored native binary.
    # On Linux the shim runs under node, which the box stops without --jitless
    # (F29/F64: an executable memory permission is refused and NODE_OPTIONS is a
    # refused name), so the flag sits in `command` here too.
    launcher = plat_items("agent_program")
    if launcher:
        # A dimension may run the agent through a launcher — a hook execs /bin/sh,
        # which is a symbolic link on Amazon Linux 2023 that no grant may name, and
        # a `#!/bin/sh` launcher's own interpreter chain brings it into the view
        # (F49). When a launcher is named it carries the fixed arguments itself, so
        # `command` is the launcher alone and `run -- …` still appends the prompt.
        agent_cmd = [launcher[0]]
    else:
        agent_cmd = [P["NODE"]]
        if P["NODE_JITLESS"]:
            agent_cmd.append(P["NODE_JITLESS"])
        agent_cmd += [P["CODEX_SHIM"], "exec",
                      "--dangerously-bypass-approvals-and-sandbox",
                      "--skip-git-repo-check"] + plat_items("agent_args")
    agent_env = {
        "PATH": man.get("agent_path", "/usr/bin:/bin"),
        "AWS_REGION": REGION,
        "TMPDIR": TMP,
        "CODEX_HOME": PROJECT + "/.codex",
        # The provider block in .codex/config.toml reads its key from this name.
        # The real authorization is the gateway's SigV4 over `aws://default`;
        # this value is a placeholder Codex needs present to select the provider.
        "BOX_MANTLE_TOKEN": "box-managed",
    }
else:
    raise SystemExit("boxgen: no agent command for %r" % AGENT)

agent_read = [PROJECT] + plat_items("agent_read")
agent_write = [PROJECT] + plat_items("agent_write")
agent_exec = plat_items("agent_exec")
if AGENT == "codex":
    # The shim is a script node reads, and node execs the vendored binary.
    # The shim resolves its platform package with require.resolve, which walks
    # node_modules, so the install prefix is granted whole rather than the two
    # files: the vendored binary alone leaves the resolver unable to find the
    # package.json beside it.
    # The node binary is named explicitly, not left implicit: when a dimension
    # runs the agent through a launcher the launcher is element 0 of `command`, so
    # the interpreter it execs is no longer the implicitly granted program.
    agent_read += [P["TOOLS"], P["NODE_TREE"], P["NODE"]]
    agent_exec += [P["TOOLS"], P["NODE_TREE"], P["NODE"]]
    # Node is dynamically linked, and the Linux agent minimum states no loader
    # directory: the operator grants it. The real directory, not `/lib64`, which
    # is a symbolic link on AL2023 and so refused in a grant.
    if PLAT == "linux":
        agent_read += ["/usr/lib64", "/etc/ld.so.cache"]
    # Codex stages its own helper binaries — `apply_patch`, the execve wrapper —
    # into CODEX_HOME/tmp/arg0 inside the project, then execs them. Without exec
    # on the project those paths are absent from the exec view and Codex reports
    # "Could not find .../apply_patch" (ENOENT, not EPERM: the F49 signature),
    # after which the model improvises shell cleanup the Shell then refuses. The
    # launcher warns that the project is both writable and executable; that pair
    # is what this agent needs, and it is a Box CLI default for Codex.
    agent_exec += [PROJECT]
    if PLAT == "macos":
        agent_read += P["BREW_READ"].split()
        agent_exec += [P["NODE_FORMULA"]]
elif AGENT == "claude":
    agent_read += [P["CLAUDE"]]
    agent_exec += [P["CLAUDE"]]
elif AGENT == "strands":
    # The interpreter, the standard library and the `--target` directory, which
    # is the same shape the `python` tool table gets: an import reads the module
    # and execs a compiled extension beside it, so each tree is both read and
    # exec (F50). The entry script and the SDK are both under STRANDS_HOME.
    agent_read += [P["STRANDS_HOME"]]
    agent_exec += [P["PYTHON"], P["STRANDS_LIB"]]
    if PLAT == "macos":
        agent_read += P["BREW_READ"].split()
        agent_exec += [P["PY_KEG"]]
    else:
        agent_read += [P["PY_STDLIB"], P["PY_STDLIB64"]]
        agent_exec += [P["PY_STDLIB64"]]
else:
    raise SystemExit("boxgen: no agent grants for %r" % AGENT)

# Deduped like the fs actions and the spawn programs below: a dimension naming the
# same tool in both `tools` and `tools_<platform>` would emit the table twice, and
# the duplicate table would fail to load.
TOOL_NAMES = list(dict.fromkeys(plat_items("tools")))


def tool(name):
    """One tool table, per platform: command, env, read, write."""
    pr, pw = [PROJECT], [PROJECT]
    if name == "git":
        env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_AUTHOR_NAME": "Box Workload", "GIT_AUTHOR_EMAIL": "workload@example.invalid",
               "GIT_COMMITTER_NAME": "Box Workload", "GIT_COMMITTER_EMAIL": "workload@example.invalid",
               # /usr/bin/true as the editor, so a rebase continuation never
               # waits for a terminal.
               "GIT_EDITOR": P["TRUE"], "GIT_SEQUENCE_EDITOR": P["TRUE"]}
        if PLAT == "macos":
            rd = pr + [P["CLT"]]
        else:
            # The helpers git execs, and the editor, in the one list a tool may name.
            rd = pr + [P["GIT_HELPERS"], P["TRUE"]]
        return {"command": [P["GIT"]], "env": env, "read": rd, "write": pw}

    if name in ("cargo", "cargo-test"):
        target = PROJECT + ("/target-test" if name == "cargo-test" else "/target")
        env = {"PATH": P["TOOLCHAIN"] + "/bin:/usr/bin:/bin", "TMPDIR": TMP,
               "CARGO_HOME": PROJECT + "/.cargo", "CARGO_TARGET_DIR": target,
               "RUSTC": P["RUSTC"]}
        cmd = [P["CARGO"]] + (["test"] if name == "cargo-test" else [])
        if PLAT == "macos":
            rd = pr + [P["TOOLCHAIN"], P["CLT"]]
        else:
            # /usr/bin/cc and /usr/bin/ld are links a grant cannot name, so
            # RUSTFLAGS names gcc and the list names what gcc execs.
            env["RUSTFLAGS"] = "-C linker=" + P["GCC"]
            rd = pr + [P["TOOLCHAIN"], "/usr/include", "/usr/lib/gcc",
                       P["GCC"], "/usr/bin/as", "/usr/bin/ld.bfd",
                       P["GCC_LIBEXEC"] + "/cc1", P["GCC_LIBEXEC"] + "/collect2"]
        return {"command": cmd, "env": env, "read": rd, "write": pw}

    if name == "python":
        if PLAT == "macos":
            venv = PROJECT + "/.venv"
            env = {"PATH": venv + "/bin:/opt/homebrew/bin:/usr/bin:/bin",
                   "VIRTUAL_ENV": venv, "TMPDIR": TMP,
                   "PIP_CACHE_DIR": PROJECT + "/.pip-cache",
                   "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
            # CPython loads its extension modules, and Python.app, from beside
            # itself, so the keg tree is read whole rather than the one file (F50).
            rd = pr + P["BREW_READ"].split()
            interpreter = venv + "/bin/python3"
            if not os.path.exists(interpreter):
                interpreter = P["PYTHON"]
            return {"command": [interpreter], "env": env, "read": rd, "write": pw}
        env = {"PATH": "/usr/bin:/bin", "TMPDIR": TMP,
               "PIP_CACHE_DIR": PROJECT + "/.pip-cache",
               "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
        rd = pr + [P["PY_STDLIB"], P["PY_STDLIB64"]]
        return {"command": [P["PYTHON"]], "env": env, "read": rd, "write": pw}

    if name in ("node", "npm"):
        env = {"PATH": "/usr/bin:/bin", "TMPDIR": TMP,
               "npm_config_cache": PROJECT + "/.npm",
               "npm_config_update_notifier": "false",
               "npm_config_audit": "false", "npm_config_fund": "false",
               # npm runs package scripts through a shell; /bin/sh is a link on
               # Amazon Linux 2023, so this names the canonical bash.
               "npm_config_script_shell": P["SCRIPT_SHELL"]}
        cmd = [P["NODE"]] + ([P["NODE_JITLESS"]] if P["NODE_JITLESS"] else [])
        if name == "npm":
            cmd = cmd + [P["NPM_CLI"]]
        rd = pr + [P["NODE_TREE"]]
        if PLAT == "macos":
            rd += P["BREW_READ"].split()
        else:
            # The script shell npm spawns, in the one list a tool may name.
            rd += [P["BASH"]]
        return {"command": cmd, "env": env, "read": rd, "write": pw}

    raise SystemExit("boxgen: unknown tool %r" % name)


# --- box.toml ---------------------------------------------------------------
NAME = man.get("name", "workload")
b = []
b.append("# Generated by test-workload/common/boxgen.py for one workload case.")
b.append("# dimension=%s agent=%s platform=%s" % (man.get("dimension", "?"), AGENT, PLAT))
b.append('name = ' + toml_string(NAME))
b.append('box_dir = ' + toml_string(BOXDIR))
b.append('policy = "policy.dw"')
b.append("")
b.append("# The one process the box runs. `command` is the program and its fixed leading")
b.append("# arguments; the runner appends the agent's non-interactive flags and the prompt")
b.append("# through `run -- …`. `workspace` is the initial directory and grants nothing.")
b.append("[agent]")
b.append("command = " + toml_list(agent_cmd))
b.append('workspace = ' + toml_string(PROJECT))
b.append("env = " + toml_env(agent_env))
b.append("")
b.append("# What the agent's own system calls reach. `write` does not imply `read`.")
b.append("[agent.filesystem]")
emit_lists(b, "[agent]", [("read", agent_read), ("write", agent_write), ("exec", agent_exec)])
for t in TOOL_NAMES:
    d = tool(t)
    if AGENT == "codex":
        # Codex stages helpers under CODEX_HOME/tmp/arg0 as SYMBOLIC LINKS to its
        # own vendored binary in the install prefix, and routes the commands it runs
        # through them — so the process that runs inside a TOOL's boundary resolves
        # that link. The install prefix is granted to the agent but was granted to no
        # tool, so the link dangled in every tool view: a following stat returned
        # ENOENT and Codex reported "Could not find <arg0 dir>/apply_patch". No
        # policy refusal is involved, which is why the journal recorded nothing.
        # Read resolves the link and reads its target; the leaf's broad exec runs
        # it on macOS.
        d["read"] = d["read"] + [P["TOOLS"]]
    elif AGENT in ("claude", "strands"):
        # Neither agent stages a helper into the install prefix and then execs it
        # from inside a tool boundary, so no tool table needs that prefix. The arm
        # is written out rather than left to a default, so a fourth agent refuses
        # here instead of inheriting this decision without being named.
        pass
    else:
        raise SystemExit("boxgen: no per-tool agent grants for %r" % AGENT)
    b.append("")
    b.append("[tool.%s]" % t)
    b.append("command = " + toml_list(d["command"]))
    b.append('workspace = ' + toml_string(PROJECT))
    b.append("env = " + toml_env(d["env"]))
    b.append("")
    b.append("[tool.%s.filesystem]" % t)
    emit_lists(b, "[tool.%s]" % t, [("read", d["read"]), ("write", d["write"])])
b.append("")
b.append("# A credential binding is configuration, not an authorization: it attaches a")
b.append("# secret to a request the policy already permitted. `aws://default` signs with")
b.append("# the instance role on the host side; the workload never holds it.")
b.append("[egress.model]")
b.append('destinations = ' + toml_list([MODEL_HOST]))
b.append('secret.ref = "aws://default"')
b.append("")
b.append("# The journal the HOST oracle reads. Outside every box directory and outside")
b.append("# the project, so the workload cannot write to it.")
b.append("[telemetry.decisions]")
b.append('kind = "file"')
b.append('destination = ' + toml_string(JOURNAL))
# `include` replaced `signals`, and its words are groups: `trace` brings the agent's
# spans AND the control plane, where `agent_trace` brought only the spans.
b.append('include = ["deny", "permit", "trace"]')
open(os.path.join(OUT, "box.toml"), "w").write("\n".join(b) + "\n")

# --- policy.dw -------------------------------------------------------------
TP = tilde(PROJECT)


def permit(rid, action, cond=None):
    """One Dogwood permit line, assembled so no source line runs long."""
    head = '@id("%s") permit (principal, action == Box::Action::"%s", resource)' % (rid, action)
    return head + (" when { %s };" % cond if cond else ";")


def in_project(attr="path"):
    return 'context.input.%s == "%s" || context.input.%s like "%s/*"' % (attr, TP, attr, TP)


p = []
p.append("// Generated by boxgen.py. Absent policy denies, so this file only adds reach;")
p.append("// a floor beneath it refuses the box's own configuration whatever a permit says.")
p.append("// The connect leg sees a host and a port only; the request leg reads the real")
p.append("// host after the gateway terminates TLS.")
p.append(permit("model_connect", "net:connect", "context.input.port == 443"))
p.append(permit("model_request", "http:request", 'context.input.host == "%s"' % MODEL_HOST))
p.append("")
p.append("// `shell:exec` is wide on purpose: a harness submits a shell snapshot, then env,")
p.append("// then the command wrapped in eval, so a rule naming one program denies every run.")
p.append("// What confines the agent is the fs:* rules, raised per path a command touches.")
p.append(permit("shell_commands", "shell:exec"))
# Deduped for the same reason the spawn loop below is: Dogwood refuses a
# duplicate rule id, and a manifest naming an action the base list already has —
# or naming one in both `fs` and `fs_<platform>` — would emit the id twice and
# the pair would fail to load, one cell at a time.
seen_actions = set()
for act in ["read", "write"] + list(plat_items("fs")):
    if act in seen_actions:
        continue
    seen_actions.add(act)
    p.append(permit("workspace_" + act, "fs:" + act, in_project()))
p.append(permit("dev_null", "fs:write", 'context.input.path == "/dev/null"'))
p.append(permit("dev_null_read", "fs:read", 'context.input.path == "/dev/null"'))
if man.get("enumerate"):
    enum = 'context.input.operation == Box::FsReadOperation::"enumerate"'
    p.append(permit("project_enumerate", "fs:read",
                    '%s && context.input.path like "%s/*"' % (enum, TP)))
p.append("")
p.append("// `shell:spawn` authorizes a host binary; the program then runs in the boundary")
p.append("// of the tool table that matches it, and one permit covers its process tree.")
p.append("// `program_path` is spelled like `path`: `~/...` under the operator's home.")
spawn = []
for t in TOOL_NAMES:
    cmd0 = tool(t)["command"][0]
    # npm's identity is the script node runs, not node itself.
    if t == "npm":
        spawn += [P["NODE"], P["NPM_CLI"]]
    else:
        spawn.append(cmd0)
    if t == "python":
        # A virtualenv's interpreter is a link to the canonical one, and it
        # selects the same table — but the decision reports the spelling the
        # command used, virtualenv prefix and all. So the permit names both the
        # canonical interpreter and the virtualenv spellings the agent types,
        # or the Shell default-denies the spawn and reports exit 126.
        venv_bin = PROJECT + "/.venv/bin/"
        spawn += [P["PYTHON"], venv_bin + "python3",
                  venv_bin + "python" + P["PY_VER"], venv_bin + "pip"]
spawn += plat_items("spawn")
seen = set()
slugs = set()
for prog in spawn:
    if not prog or prog in seen:
        continue
    seen.add(prog)
    # Two programs can share a basename (the framework interpreter and the
    # virtualenv link to it), and Dogwood refuses a duplicate rule id, so the
    # slug is made unique rather than left to collide.
    slug = os.path.basename(prog).replace(".", "_").replace("-", "_")
    base, n = slug, 2
    while slug in slugs:
        slug = "%s_%d" % (base, n)
        n += 1
    slugs.add(slug)
    p.append(permit("spawn_" + slug, "shell:spawn",
                    'context.input.program_path == "%s"' % tilde(prog)))
hosts = list(dict.fromkeys(plat_items("http")))
if hosts:
    cond = " || ".join('context.input.host == "%s"' % h for h in hosts)
    p.append(permit("package_hosts", "http:request", cond))
# A dimension may carry rules this generator has no key for, such as a `forbid`
# with a temporal budget. The file is appended as written, with the project
# spelled the way the box reports it under `{{TILDE_PROJECT}}`.
extra_policy = subst(man.get("policy_file", ""))
if extra_policy:
    p.append("")
    p.append(subst(open(extra_policy).read()).replace("{{TILDE_PROJECT}}", TP).rstrip("\n"))
open(os.path.join(OUT, "policy.dw"), "w").write("\n".join(p) + "\n")

print(json.dumps({"name": NAME, "tools": TOOL_NAMES, "model_host": MODEL_HOST,
                  "agent_command": agent_cmd,
                  "timeout": int(man.get("timeout", "600")),
                  "residuals": items("residuals") + items("residuals_" + PLAT)}))
