# Decisions

This page records why `box` is the way it is. Each entry states one decision that a human made,
the alternative that lost, and what the decision costs. Read the headings to learn the design in
one pass. Git history holds how each decision got here, and the `decision` skill writes and
rewrites the entries.

An entry belongs here only when the choice refuses or redirects a later change to a different part of
`box`. The log can lag the code, and the code owns current behavior. A change that goes against an
entry either fits the code to the entry or rewrites the entry, and a human approves the rewrite. A
pull request that changes what an entry says fixes that entry.

- **Box Core**
  - [`box` links the Box Core library in its workspace](#box-runs-a-pinned-box-core-release)
  - [Box Core helper programs stay beside `box`](#box-finds-box-core-at-an-explicit-path)
  - [The packs that `box` ships are separate resource files](#the-starters-are-files-beside-box)
  - [The command is `box`](#the-command-is-box)
  - [The macOS `box` has its own identifier and signs through Box Core's setup](#box-signs-through-box-core)
  - [`box` supports macOS and Linux](#box-supports-macos-only)
  - [Packs and profiles are their own crate](#packs-and-profiles-are-their-own-crate)
- **Profiles and packs**
  - [A profile and its packs make an agent run in a box as it runs on the host, and never extend it](#a-pack-makes-an-agent-run-and-never-extends-it)
  - [An agent pack tells its agent about the box in the agent's command](#an-agent-pack-tells-its-agent-about-the-box)
  - [An organization's agent policy applies in the box, and `box` never overrides it](#an-organizations-agent-policy-applies-in-the-box)
  - [Only a profile adds arguments to the agent, where the agent pack's one slot puts them](#only-a-profile-adds-agent-arguments)
  - [A profile is what you write, and a profile pack is what it imports](#base-is-reserved)
  - [A profile is a folder that each run compiles again](#a-profile-is-a-folder)
  - [The release owns the standalone profile editing guide](#the-binary-owns-the-profile-editing-guide)
  - [A profile and a pack use Box Core's table names, and a profile refuses the keys of one run](#a-profile-uses-box-core-table-names)
  - [Installation support is shared without exposing tools](#installation-support-does-not-expose-agent-tools)
  - [Installation layouts are host discovery in code, and a tool names the ones that apply](#an-installation-pack-names-a-layout)
  - [Every pack is trusted like the operator's own profile](#every-profile-in-the-chain-is-trusted)
  - [A collection adds names under its own scope, and never replaces a name that another place gives](#a-collection-adds-scoped-names)
  - [Only a profile lists a plugin, and only the profile names a reference that a plugin reads](#only-a-profile-lists-a-plugin)
  - [`box` knows no provider and no agent, so the packs say what the report and the search need](#box-knows-no-provider)
  - [A pack states its kind, and `box` checks the kind against the pack](#a-pack-states-its-kind)
  - [`extend` builds a pack on another, and `include` loads a tool pack beside it](#extend-and-include)
  - [Each kind of file that `box` reads holds one kind of thing, so a pack holds no starter](#one-kind-per-file)
  - [A profile runs one agent](#a-profile-runs-one-agent)
- **Values and inputs**
  - [`${{ name }}` in a string marks what `box run` fills in, and only an `env` value names a host variable directly](#values-that-change-are-explicit-references)
  - [Host-file values are not profile inputs](#a-pack-reads-a-host-file-for-now)
  - [The agent gets a host variable only when a pack or the profile names it](#the-agent-gets-only-the-host-variables-a-pack-names)
  - [An input or a host variable cannot read a credential that a route or a secret source uses, and detection uses only a value a pack accepts](#an-env-reference-cannot-read-a-credential)
  - [An input in `command` or in a route's host needs `pattern` or `values`](#an-input-in-a-command-or-route-is-bounded)
  - [A condition is structured fields, never an expression](#a-bool-input-switches-with-when)
  - [A `when` never drops the program of a command or the secret of a route](#a-when-never-drops-a-program)
  - [An input exists only when it changes what the box allows or how it is wired](#an-option-changes-what-the-box-allows)
- **MCP servers**
  - [A pack names where its agent's MCP servers are, one generic reader reads them, and the profile turns import on](#a-pack-names-where-its-agents-mcp-servers-are)
  - [MCP configuration import does not require generated policy](#mcp-import-does-not-require-generated-policy)
  - [`box` declares a detected server as its configuration states it, and turns only a key in a variable into a placeholder](#a-detected-server-carries-no-credential)
  - [A local server declared from host settings keeps its key in `box.toml`](#a-local-servers-key-is-in-box-toml)
  - [A detected stdio server reads its install directory and gets the workspace as `[project] access` allows, and nothing its arguments name](#a-detected-server-reads-its-install-directory)
  - [Launcher caches are separate from agent tool caches](#launcher-caches-are-separate-from-agent-tool-caches)
  - [`@box/uv` installs tools into `@box/uvx`'s agent tool folder](#uv-installs-into-the-uvx-tool-folder)
  - [A tool pack's storage belongs to the tool, and its rows copy or link host entries into it](#a-tool-owns-its-state-outside-the-workspace)
  - [A tool's `[[storage.files]]` row names its mode](#a-tools-row-names-its-mode)
  - [A tool can have the gateway upgrade a host it reaches from `http://` to `https://`](#a-tool-can-have-the-gateway-upgrade-its-host)
  - [Launcher compatibility claims name tested versions and runtimes](#launcher-compatibility-claims-name-tested-versions-and-runtimes)
  - [A generated declaration keeps the server's name or is omitted](#a-server-name-is-renamed-and-a-collision-is-skipped)
- **Policy**
  - [A pack adds no authored policy, and `box` generates only the policy that configuration declares](#a-pack-adds-no-policy)
  - [`box` writes the policy rules a typed table implies, and `policy.dw` holds no placeholder](#policy-holds-no-placeholder)
  - [`box` writes a network permit by itself only for named destinations](#a-network-permit-needs-a-named-destination)
  - [A route with only `destinations` opens hosts that get no credential from the box, and a pack may write one](#a-route-with-only-destinations-opens-a-host)
  - [At a terminal, `box profile create` asks which policy starter to copy, and Enter picks `@box/open`, which reaches every host but loopback and link-local](#the-policy-question-defaults-to-open)
  - [`box profile create` copies the policy starter into the profile, and the copy is the operator's](#a-policy-starter-is-copied-into-the-profile)
  - [A bare `aws://` route signs with the host's default credential chain, and `box` adds no `~/.aws` guard](#an-aws-route-names-a-profile)
  - [`box` never parses the policy language, so a policy error has a line only where Box Core gives one](#box-never-parses-the-policy-language)
- **Runs**
  - [Each run gets its own box, unless the operator names an earlier run's box](#each-run-gets-its-own-box)
  - [Box Core uses the box ID that `box` mints](#box-core-uses-the-box-id)
  - [`box run` calls Box Core once](#box-run-replaces-itself-with-box-core)
  - [The telemetry crate owns observation and payload construction](#telemetry-owns-observation-and-payload-construction)
  - [Installation identity survives changes to `BOX_HOME`](#installation-identity-survives-box-home-changes)
  - [Smoke telemetry follows the caller's installation identity](#smoke-telemetry-follows-the-callers-identity)
  - [Telemetry sends from a thread in the CLI](#telemetry-sends-from-a-thread-in-the-cli)
  - [The telemetry choice lives with the installation ID](#the-telemetry-choice-lives-with-the-installation-id)
  - [A banner failure keeps the agent running](#banner-failure-keeps-the-agent-running)
  - [Policy off turns off what the operator adds, and keeps each forbid `box` writes for every box or to protect itself](#policy-off-keeps-the-forbids-box-writes)
  - [A run's grants and rules are what the profile says, so `box run` sets no input](#box-run-takes-no-option-values)
  - [The workspace is the current directory, and `[project] access` decides the grants `box` adds there](#the-workspace-is-the-current-directory)
  - [The profile's project access is one level that sets the project grants and permits `box` adds](#project-access-is-one-profile-level)
  - [Without native filesystem policy, a file rule decides only the Shell and Monty, and `[filesystem] deny` keeps a path from every process](#file-rules-decide-only-the-shell)
  - [A box sets file times unless `box` runs as root, and only the profile changes that](#file-times-follow-the-user-id)
  - [File watching is a key of each process table, and a pack can set it](#file-watching-is-a-key-of-each-table)
  - [Only a profile turns off a tool's network containment](#only-a-profile-turns-off-a-tools-network-containment)
  - [`box` creates no file in the workspace, except an empty `.box` on Linux](#a-profile-can-name-launch-directories)
  - [The profile is the unit of isolation, so the state that a box keeps between runs is one folder per profile](#storage-is-one-directory-per-profile-and-workspace)
  - [An agent's configuration folder is private to the box, and the host's folder is never granted](#an-agent-gets-a-private-configuration-folder)
  - [A copy of a host file is made once, and then belongs to the box, unless its row syncs or its pack changes or adds values](#a-copy-belongs-to-the-box)
  - [The packs decide what is copied and what changes in the copy, and a copy never reads a place a box can write or a path that a secret source protects](#the-packs-decide-what-is-copied)
  - [A hook is a command, so each run writes the imported hooks from the host file and permits each script](#imported-hooks-are-rebuilt-on-each-run)
  - [A run refuses write grants over `box`'s trusted directories](#a-run-cannot-write-what-a-later-run-trusts)
  - [A profile's `deny` and `deny_write` reach every process, and the Shell and Monty](#an-agents-deny-write-folder-is-closed-to-the-shell-and-monty)
  - [A run does not check the arguments of a detected server that no profile extends as programs](#a-detected-servers-arguments-are-not-programs)
  - [`box` guards what it runs and reads, and warns about a host tool that trusts what a box writes](#a-host-tool-that-trusts-the-workspace-gets-a-warning)
  - [A write grant never changes which program runs](#a-write-grant-never-picks-the-program)
  - [No file that the profile's box can write is read as an MCP source or a starter source](#no-file-a-box-can-write-is-an-input)
- **Commands**
  - [A command that removes state never also starts a box](#removing-state-never-starts-a-box)
  - [Each `box profile` removal command removes one kind of state, by name or `--all`](#reset-with-no-name-removes-every-profile)
  - [A starter answers from the host first, and `box` asks only at a terminal](#box-asks-only-at-a-terminal)

## Box Core

<a id="box-runs-a-pinned-box-core-release"></a>
### `box` links the Box Core library in its workspace

`box` reaches Box Core only through the `strands-box` library: `strands_box::check_policy()`,
`strands_box::run()`, `strands_box::reload()`, `strands_box::policy_decisions()` for the activity
banner, and, for a detected MCP server,
`strands_box::INTERPRETER_ALIASES`,
`strands_box::check_read_grant()`, and `strands_box::reserved_env()`. `box` keeps no copy of Box
Core's interpreter aliases, read-grant refusal lists, or reserved environment names
([a detected server reads its install directory](#a-detected-server-reads-its-install-directory)).
Box Core has a library target, and its design forbids a caller from linking its mechanism crates, because a second policy engine in another process breaks
enforcement. `box` depends on `crates/box` by path, so a Box Core change and the `box` change it
needs land in one commit.

**Rejected.** The latest Box Core release: a new release changed what `box` must write before
`box` changed (v0.1.0 refuses `[agent] dependency`). A git revision pinned in `Cargo.lock`: a Box
Core fix reached `box` only when a contributor moved the pin.

**Cost.** `box` cannot check a policy itself. It asks Box Core, which reads a `box.toml` and a
`policy.dw` from disk, so `box profile show` writes both to a temporary directory. A Box Core
change can break `box`, so CI runs the CLI's engine suite for each Box Core change.

<a id="box-finds-box-core-at-an-explicit-path"></a>
### Box Core helper programs stay beside `box`

Box Core locates `strands-box-sock-alias` and `strands-box-contain-trampoline` beside the `box`
binary. `box` does not download Box Core. For development, `just build` builds the helpers.

**Rejected.** Search `PATH`: a search can find the wrong binary.

**Cost.** An operator must put the helpers beside `box` before the first run.

<a id="the-starters-are-files-beside-box"></a>
### The packs that `box` ships are separate resource files

`@box/<name>` is the folder `resources/packs/<name>/`, which holds `pack.toml` and each file the
pack names through `${{ pack }}`. The agent packs (`claude` and `codex`), the model providers,
and `base` are there. `box` finds `resources/` at
`$BOX_RESOURCES`, else from its installed package, else, in a debug build, from the source tree.
An ordinary package puts `resources/` beside the binary. A signed experimental native macOS
package puts it in `Box.app/Contents/Resources`, outside the executable directory that Apple
checks for nested code. `resources::root` recognizes that app layout. The helpers remain beside
the real binary in `Contents/MacOS`.

**Rejected.** Embed them in the binary: an operator then cannot read one, and an agent cannot load
a file from a pack's folder.

**Cost.** An install must ship the resource files in the layout its binary expects. A native
macOS app seals those files before signing. Runs protect the entire installed package, including
its launcher, profile, and signature files.

<a id="the-command-is-box"></a>
### The command is `box`

The CLI uses the command `box`, the project directory `<workspace>/.box`, and the `BOX_*`
variables. Its home is `~/.strands/box/`, under the Strands namespace to avoid collisions with
other products. The Cargo package is `strands-box-cli`. The CLI links Box Core as a library and
does not install Box Core's own `box` binary.

**Rejected.** `boxy`: it gives one product two names.

**Rejected.** The tried `~/.box` home is short, but collides with the Box.com CLI.

**Cost.** Box Core's binary is also `box`. An operator who puts both on `PATH` runs the first
one, and the CLI and its macOS identifier must stay distinct from Box Core's. See
[the signing entry](#box-signs-through-box-core). The default home has no fallback: profiles and
saved telemetry choices under the former home are not loaded.

<a id="box-signs-through-box-core"></a>
### The macOS `box` has its own identifier and signs through Box Core's setup

`crates/cli/app/Info.plist` gives `box` the identifier `com.amazon.strands.box-cli`, and the two
helpers keep Box Core's `com.amazon.strands.box`. For ordinary packages,
`scripts/macos-release-cli.py` signs all three in one request for Box Core's application, with
Box Core's AWS role and notarization credential. The reusable `CLI release` workflow runs it, and
`Release Box` calls that workflow, so one release publishes both Box Core and `box`. The signing
service signs each program with the identifier in its plist. macOS does not treat the CLI and Box Core's `box` as one program, for example in the
access list of a keychain item.

A signed experimental native package keeps that identity separation and shared service setup.
It signs the helpers first, then signs a CLI app bundle with a separate distribution profile
for `com.amazon.strands.box-cli`. The profile must authorize Endpoint Security, Apple's API for
authorizing file operations. `CD_SIGNER_CLI_PROFILE_NAME` selects it. A missing or mismatched
profile stops signing; configuring it and granting access remain administrator actions.

**Rejected.** Box Core's identifier for the CLI: macOS would treat the CLI and Box Core's `box` as
one program.
A separate service role for ordinary CLI signing: the shared setup already signs that package.
Reusing the Core application profile for native CLI signing: its application identifier does
not authorize the CLI.

**Cost.** Two maintainers, one to start a run and one to approve it, can produce a program that
is signed and notarized under the configured Apple team.
Box Core and `box` use one AWS role and one bucket, under `box-release/`, and one change to the
notarization secret changes the credential for both. Native CLI signing also needs an authorized
CLI distribution profile. Local script tests do not establish that this permission is granted.

<a id="box-supports-macos-only"></a>
### `box` supports macOS and Linux

`box` runs on macOS on Apple silicon, and on Linux on aarch64 and x86_64. Box Core's Linux
containment runs on both, with no opt-in. A release publishes an x86_64 archive of `box` when
`publish_linux_x86` is set, which it is by default, and CI runs the engine suite only on macOS. Box
Core on Linux refuses a deny of an absent path, so on Linux `box run` creates an empty
`<workspace>/.box` before the run, and the run denies it as on macOS.

**Rejected.** No deny on Linux when `.box` is absent: the agent could then create it, and a later
run would read what the box wrote there.

**Cost.** A Linux run leaves an empty `.box` folder in each workspace.

<a id="packs-and-profiles-are-their-own-crate"></a>
### Packs and profiles are their own crate

`crates/cli/profile` (`strands-box-cli-profile`) owns packs and profiles from the file to the box: it
parses a profile and its packs, resolves them against a host, and compiles `box.toml` and
`policy.dw`. `crates/cli/app` owns the operator: the commands, `box run` and its terminal, starters,
`create`, `detect`, Box Core's policy check, and the call into Box Core. The profile crate names
no CLI module, and the CLI passes in what only it knows, such as its version for a pack's
`engine` floor (`Lookup::version`). This follows Box Core, whose `strands-box-policy` owns
Dogwood end to end. Both crates link `strands-box`, because a tool grammar and a read grant are
Box Core's rules, and the profile crate asks Box Core instead of copying them. The modules moved
whole, so git follows each file to its new path, and the CLI imports each one it names at its old
path.

**Rejected.** One crate: the CLI was about 50,000 lines, and nothing kept the language from
reaching into `run`. A split along new files: it loses rename detection for open pull requests,
and it adds changes of meaning to a move.

**Cost.** The crate's `pub` surface is whatever the CLI uses (about 300 items), with
`missing_docs` off apart from `error`, until a small documented entry point replaces it. A `pub`
item is never dead code, so nothing reports one that the CLI stops using. `Error` holds the CLI's
variants too. The crate still does three things a run does after it compiles: it writes the
agent's MCP configuration, copies `[[storage.files]]`, and updates the sync record. A later step
returns these as plans that the CLI carries out.

## Profiles and packs

<a id="a-pack-makes-an-agent-run-and-never-extends-it"></a>
### A profile and its packs make an agent run in a box as it runs on the host, and never extend it

A pack finds the agent, routes one model provider with its credential (or only its hosts, for an
agent that signs in inside the box), gives the agent storage, and grants what the agent and its
host tools need. It changes the agent's configuration only when the box makes a host setting fail,
or when the operator's host configuration holds the value.

**Rejected.** Packs that add a capability to the agent, such as an MCP server, a skill, or a hook:
`box` then becomes a runner with its own features, not an invisible one. So `box` refuses an
`[mcp.<name>]` table with a `type` in a `pack.toml`: a pack names where its harness keeps the
operator's servers, and only the profile declares a server. A pack's `[mcp.<name>]` table adds no
server: it holds only `filesystem` and `network`, and a `when` goes only on one filesystem entry. It merges over a server that the
operator configured, and a run that finds no server of that name drops it. So a pack can grant
what a known server needs to start in a box, as a pack grants what a host tool needs, and it
cannot change the program, the arguments, the environment, the destinations, or the key of the
server.

A copy of the operator's own instructions and skills into storage
([copies](#a-copy-belongs-to-the-box)) is not an added capability: it is the configuration the
agent has on the host. The MCP servers that the operator configured for the agent
([MCP servers](#a-pack-names-where-its-agents-mcp-servers-are)) are not one either.
Guidance that tells the agent it runs in a box ([guidance](#an-agent-pack-tells-its-agent-about-the-box))
is not one: the box makes a refusal look like a missing file, and the guidance corrects what the
agent tells the operator.

**Cost.** An operator who wants another capability adds it to the agent's own configuration on the
host. From the agent's settings file, only the display preferences, the model, the listed
variables, and the permission settings that its pack names come into the box. Its other settings, hooks, and sessions stay outside.
The agent receives the selected MCP entries with their command arguments. Box Core holds
the environment values of declared local servers
([MCP import](#mcp-import-does-not-require-generated-policy)).

<a id="an-agent-pack-tells-its-agent-about-the-box"></a>
### An agent pack tells its agent about the box in the agent's command

The guidance says what the box allows, what a refusal looks like, and which `profile.toml` change
the operator makes. It ends with one line that names `${{ profile }}`. Each agent pack puts it in
its `command`, so each run gives the current text, and only a `command` element takes a
placeholder.

- `@box/claude` starts Claude Code with `--append-system-prompt-file ${{ pack }}/box.md` and
  `--append-system-prompt` with the profile line. The file holds the fixed text, because Claude
  Code reads it as it is. The pack grants `read_file` on `box.md`.
- `@box/codex` starts Codex with `-c developer_instructions='''...'''`, and the profile line is the
  end of that value. Codex adds the value as a developer message and keeps its own instructions.
  Codex has no flag that reads a file into its instructions, so the text is in `pack.toml`. The
  text also says that Codex's own sandbox is off, because Codex tells the model that it has full
  access.
- `@box/kiro` copies `${{ pack }}/box.md` to Kiro CLI's global steering, `home/.kiro/steering/box.md`
  in storage, with `sync = true`. Kiro CLI has no flag or setting that adds text to its prompt, so
  this row is the exception to the `command` rule. `sync` gives each run the current text. The
  operator's steering copy moves to `home/.kiro/steering/host`, because two copies cannot share a
  folder, and Kiro CLI reads every file below `steering`. A copy holds no placeholder, so the pack
  sets `BOX_PROFILE` to `${{ profile }}` in the agent's environment, and the text names the
  variable.

Each pack keeps its own text. The texts name the agent's own stand-in keys and settings folder. All four texts hold the same `## Your shell` section and the same sentences about when a change
takes effect. The shell section tells the agent that its shell runs under a policy and is not a full
bash, and to try a simpler, portable form when a result is unexpected or empty. It names no command
and no task, and it leaves the refusal advice to "When the box refuses". The pack tests fail when one
text differs. Shorten or remove the shell section when the Shell gaps that it covers are fixed.

**Rejected.** A `[[storage.files]]` copy into `config/rules`, `config/CLAUDE.md`, or Codex's
`AGENTS.md`: a copy is made once and then belongs to the box
([copies](#a-copy-belongs-to-the-box)), so the text goes stale when `box` changes, and the target
collides with the operator's own copy. The managed `CLAUDE.md`: it is a host path that `box` does
not write. A `SessionStart` hook: it needs exec grants for the hook, and a second `--settings`
value beside the one `agent.skip-permissions` sets. Codex's `model_instructions_file`: it replaces
Codex's built-in instructions. A Codex line that tells the model to read a shared `box.md`: the
model can skip the read. One shared text with a placeholder that inlines a file: it adds a
language feature for two packs. A Kiro CLI agent in `home/.kiro/agents` with the text as its
`prompt`: Kiro CLI then drops its own instructions and its default tool set.

**Cost.** Claude Code and Codex record the guidance at the start of a conversation, so a resumed
conversation keeps its old text. Claude Code replaces it when it compacts.
`--append-subagent-system-prompt` applies only with `-p`, so a Claude Code subagent in the
interactive interface can start without the guidance. A `-c developer_instructions` in the
operator's `agent-args` comes later in the command and replaces the Codex guidance. Kiro CLI
reads the profile folder only when the model reads `BOX_PROFILE`. Kiro CLI can edit its copy, and
the edit stays until `box.md` in the pack changes. A change to the guidance changes every pack.

<a id="an-organizations-agent-policy-applies-in-the-box"></a>
### An organization's agent policy applies in the box, and `box` never overrides it

When an organization manages an agent on the host, the agent pack grants the agent read access to
each place it reads that policy from, so the agent enforces the policy in the box as on the host.
`box` checks no policy value itself, and a pack option such as `agent.skip-permissions` never works
around one.

**Rejected.** A check in `box` that stops a run when the policy forbids a pack option: the agent
already resolves the conflict itself. With bypass mode turned off, Claude Code ignores
`--dangerously-skip-permissions` and asks before it acts, in the box as on the host. A second check
only copies the agent's policy rules. No grant: the operating system then denies the read, and the
agent starts without the policy.

**Cost.** The policy applies whole. A managed `env` value reaches the agent, so a value that holds
a key is readable in the box, and a value for a variable the pack sets, such as an OpenTelemetry
endpoint, replaces the pack's value. A managed hook runs in the box with the agent's grants. The
comments in each agent pack name the policy places that its grants do not reach.

<a id="only-a-profile-adds-agent-arguments"></a>
### Only a profile adds arguments to the agent, where the agent pack's one slot puts them

An agent pack marks one place in its `command` with `{ slot = "agent-args" }`, and the
profile's top-level `agent-args` fills it. The pack author knows the agent, so the pack decides
where added arguments go. Box Core appends the run's `--` arguments, so a run can override the
profile. One file fills the slot, so no merge order decides an argument. `agent-args` sits beside
`packs` and `[options]`, so each key in a Box Core table means the same in a pack and a profile.
Each element is a string with no `when`, because a profile is one configuration. A pack writes a
whole `command` and never fills a slot, so a provider pack holds no agent flags.

**Rejected.** `args` appended after the command: tried first, and a pack could not put arguments
before a subcommand's or a trailing `--`. `[agent] args`: the one key in `[agent]` that a pack
cannot write and that fills a slot instead of a field. More than one named slot: no agent needs
two yet. A slot for the run's `--` arguments: Box Core already appends them, and `box` would
have to write them into `box.toml`, which holds only UTF-8 text and stays in the run's folder.
`agent-args` in any file, joined in merge order: pack order then decides the arguments, and a
provider pack can write one agent's flags. A list placeholder in a string, such as
`"${{ pack.command }}"`: an operator inside a string.

**Cost.** An agent pack with no slot takes no `agent-args`. Two profiles that need one argument
each state it. A profile drops a pack's flag only by restating `command`, and that command needs
its own slot to keep `agent-args`.

<a id="base-is-reserved"></a>
### A profile is what you write, and a profile pack is what it imports

A profile lists packs in `packs` and sets input values in `[options]`, and `box run` takes it. A
pack is a `pack.toml`: it imports packs with `extend`, declares `[inputs]`, and holds the agent
tables. Nothing imports a profile. `@box/<name>` is a pack that `box` ships, and a plain name
is a folder in `~/.strands/box/packs/`. Starters and policy starters use the same `@box/` scope. `base`
stays reserved as a profile name, and `~/.strands/box/config.toml` stays reserved for the settings of
`box`.

**Rejected.** One kind of file for both, the "shared profile": tried first, and it mixed what can
be set with what is set. A full copy of a pack in the profile: it never gets a fix to the pack.
`box/<name>` for a shipped pack: used first, and it read as a folder path, such as
`~/.strands/box/packs/box/<name>`.

**Cost.** A setting that two profiles need goes in a pack of the operator's own, but an agent
argument cannot ([only a profile adds agent arguments](#only-a-profile-adds-agent-arguments)). A
change to a pack changes every profile that uses it, on the next run.

<a id="a-profile-is-a-folder"></a>
### A profile is a folder that each run compiles again

A profile is `~/.strands/box/profiles/<name>/`, which holds `profile.toml` and other profile files.
Its `policies` paths stay within this folder, including each link target, so they use the existing
directory protections; other files use `${{ profile }}`.
Box Core never reads a profile.
Each `box run` compiles it, with its packs and the current directory, into a new `box.toml` and
`policy.dw`, so one profile works in any project and follows changes on the host.

**Rejected.** A `box init` that writes one `box.toml` for each project: the first design. Its
config fixed the host as it was on the day it was written, and Box Core's lock on `box_dir` let it
run only once at a time. A single `<name>.toml`: a profile holds a config, a policy, and other
files.

**Cost.** The config that `box` last wrote for a box is in its run directory, not in the profile. A
policy path cannot name a file in another profile folder.

<a id="a-profile-file-loads-by-its-path-and-names-itself"></a>
### A profile file loads by its path, names itself, and stays where the agent cannot write

`box run` and `box profile show` take a profile name or the path of a profile file. A value that
holds `/` or ends in `.toml` is a path, so a project can keep its profile in its repository. A
profile file declares `[profile] name`, which selects its storage and box IDs as a folder name does.
`box` refuses a name that a profile in `~/.strands/box/profiles/` has, and a name that another file owns.
It records the owning file in `~/.strands/box/storage/<name>/.profile-source`, outside every directory a
run can write. `box` also refuses a profile file, or a policy file, in the project, outside its
`.box` folder, because the agent can write the project.
Later runs trust the file, so it gets the protections of the box home: `box` refuses a write grant
that reaches the file or a policy file, a file with a second hard link, another owner, or group or
other write, and a project that holds a recorded profile file outside its own `.box`. The compiled
policy forbids writing, deleting, and moving the files, and moving or deleting each folder above
them, so the Shell and Monty cannot change them either. A profile name cannot end in `.toml`.

**Rejected.** A `--profile` flag: the positional argument already names the profile. The file name
or a hash of the path as the name: many projects use `profile.toml`, so a file name collides, and a
hash changes when the project moves, which leaves its storage behind. Reusing the top-level `name`:
`box.toml` holds the box's name there. `BOX_HOME`: it moves every profile, run, and storage folder,
not one profile.

**Cost.** Two clones of one project need two names. A moved profile file is refused until its old
storage is removed. The editing guide is not refreshed for a profile file.

<a id="the-binary-owns-the-profile-editing-guide"></a>
### The release owns the standalone profile editing guide

Changes to the profile language or editing workflow also update the standalone editing guide.
This curated file repeats user-reference facts so an agent can edit a profile without the source
checkout or a documentation site. The release ships it as one file beside the packs, and
[`box help agent`](#the-guide-for-a-coding-agent-is-a-command) prints its path. The operator
keeps ownership of `profile.toml` and authored policies.

**Rejected.** A pointer to repository documentation leaves editing context outside the artifact.
Generating the whole reference restores material outside the guide's editing scope.

**Cost.** Contributors maintain the repeated facts in the same change. The input-field check
detects missing keys; routes, MCP, storage, and workflow semantics still need manual review.

<a id="a-profile-uses-box-core-table-names"></a>
### A profile and a pack use Box Core's table names, and a profile refuses the keys of one run

`profile.toml` and each pack use Box Core's table names, such as `[agent]`, `[tool.<name>]`, and
`[egress]`, so a value means in a profile what it means in `box.toml`. Each kind of file adds a few
keys of its own, which `box` removes before Box Core reads the config:
[What a profile holds](../../cli/profiles-reference.md#what-a-profile-holds) and
[What a pack holds](../../cli/packs-reference.md#what-a-pack-holds) list them. Only
`profile.toml` can select an experimental feature or set its process overrides, so importing or
updating a pack cannot change the user's experimental selection. Box rejects these settings in
every pack before merging or checking conditions, including `false` values. An agent pack and a
tool pack each run one program, so `[run]`, `[env]`, and `[filesystem]` are that program's: an
agent pack's become `[agent]`, and a tool pack's become `[tool.<name>]`. Neither pack writes its
own table by name. A plugin runs one program too, on the host, so its `[run]` and `[env]` are
that program's, and its `[protect]` names what the box keeps from the agent, each tool, and each
MCP server. `box` translates them into the one
`[secret-source.<scheme>]` table that Box Core reads ([plugins.md](plugins.md#the-file)). A plugin's
`[run]` and `[env]` keep the forms of a pack's and take less: its `[env]` passes a host variable under its own
name. A plugin holds no `[filesystem]`, because it grants nothing. A support pack and a profile name the table of each process key, because
neither is one program. A profile's `[filesystem]` names no process: its lists, `deny` and
`deny_write`, reach every process
([below](#an-agents-deny-write-folder-is-closed-to-the-shell-and-monty)). `[pack] kind` alone says which program a pack runs, and the keys of `[run]`
must be that kind's. A profile refuses the keys that `box run` sets for each run, such as `name`
and each `workspace`. `box` refuses a key in the wrong kind of file and an unknown key in each
table it reads, and it leaves out a route with only `destinations`
([open routes](#a-route-with-only-destinations-opens-a-host)).

**Rejected.** A new vocabulary, such as `[paths.read]`: each key then needs a translation, and the
Box Core docs no longer apply. Box Core's own keys in a plugin, such as `pass-env`,
`pass-secret-env`, and `reads`: a plugin then reads unlike every pack, and its reader cannot tell
what the two pass lists do. `[env]` in a support pack, for the pack that extends it: a profile
lists a provider pack such as `@box/bedrock` directly, so its `[env]` has no program. A kind read
from the keys of `[run]`: a pack's role then changes with no error when a key moves. A pack that
selects native filesystem policy: importing reusable setup must not select an experiment for
the user, even when the profile could override it.

**Cost.** A change to the Box Core schema can need a change to the profile schema, and to the key
lists in `lang` (`AGENT_KEYS`, `TOOL_TABLE_KEYS`, `FILESYSTEM_KEYS`). Box Core v0.1.0 refuses
`dependency`, so `box` accepts it and leaves it out of `box.toml`. A user who wants native checks
in several profiles must select them in each profile. A plugin's keys need a translation, so the
plugin reference owns each of them, and a message from Box Core names the keys of its own table.

<a id="installation-support-does-not-expose-agent-tools"></a>
### Installation support is shared without exposing tools

Tool packs and detected local MCP servers obtain installation requirements from the same
installation layouts. Installation support follows the selected program and interpreter;
it declares no additional agent-facing tool. Supported installations need no profile filesystem
repair. An unresolved receipt dependency never grants an entire installer prefix.

**Rejected.** A dependency mode that consumes part of an ordinary tool pack: command activation
and installation discovery then share one contract. Separate MCP installation rules: each runtime
fix then needs two changes.

**Cost.** A receipt can overstate dependencies. Narrower reads do not establish a narrower
child-execution boundary.

<a id="an-installation-pack-names-a-layout"></a>
### Installation layouts are host discovery in code, and a tool names the ones that apply

`install_layout::Layout` discovers Homebrew kegs and receipts, Python environments, and npm
trees. Discovery is code, not pack data. Tools name layouts with `installation`; detected MCP
servers get every layout. The npm read boundary includes the containing `node_modules` tree so
dependencies beside the package are readable.

**Rejected.** Installation packs: matching rules add fields and patterns that can overgrant,
while a pack that only names a layout repeats its name. Per-package grants from manifests:
narrower reads require more dependency resolution logic.

**Cost.** A new layout needs a `box` change, and a reviewer audits its grants in Rust. An npm
read grant includes unrelated packages in that tree. An unmatched server reads its program's
whole folder through `directory`, and a profile cannot narrow a server's layouts.

<a id="every-profile-in-the-chain-is-trusted"></a>
### Every pack is trusted like the operator's own profile

A pack can read a host variable, run a host program, name a credential, grant a path, and open a
host. That is safe only because the operator chose each pack: `box` ships `@box/*`, and the
operator puts each other one in `~/.strands/box/packs/` or in a collection in
`~/.strands/box/external/`. A policy starter from either place is the operator's own rules in the same way. Installation layouts are code, not packs
([layouts](#an-installation-pack-names-a-layout)). A pack cannot add authored policy ([a pack adds
no policy](#a-pack-adds-no-policy)).

**Rejected.** Packs from a registry: not built. A registry needs signatures, and limits on what an
untrusted pack declares, first. [profile-language.md](profile-language.md#not-built) lists them.

**Cost.** An operator who copies a pack into `~/.strands/box/packs/`, or clones a collection into
`~/.strands/box/external/`, gives it the operator's trust, and `box` does not warn. A change to a
collection, such as a `git pull` of the team's repository, reaches each profile that lists its
packs on the next run.

<a id="a-collection-adds-scoped-names"></a>
### A collection adds names under its own scope, and never replaces a name that another place gives

The collection's folder name in `~/.strands/box/external/` is its scope, such as `@acme` for
`external/acme/`, and its packs, plugins, starters, and policy starters are `@acme/<name>`. A plain name stays the operator's own folder,
else `@box/<name>`, and `@box/` stays what `box` ships. So the names that a profile lists say
where each pack comes from, and adding a collection changes no existing profile. How a collection
changes the menus is in [starters.md](starters.md#the-starters-list).

**Rejected.** A collection whose `packs/claude` replaces `@box/claude`: a company could change the
shipped agent pack for every profile at once, but a `git pull` would then change what each existing
profile runs, and nothing in the profile would show it. A plain name that falls back to a
collection: names stay short, and a company's pack reaches profiles without an edit to each, but
which pack a name means would then depend on which collections are cloned.

**Cost.** A company that wants its own agent setup ships a starter and a pack under its scope, such
as `@acme/claude`, and each operator names it in full, as in `--with @acme/claude`. Two starters
in a menu can't share a short name, so that collection removes `@box/claude` from the menu.

<a id="only-a-profile-lists-a-plugin"></a>
### Only a profile lists a plugin, and only the profile names a reference that a plugin reads

A plugin's secret source makes Box Core run a host program outside every sandbox, with the
operator's rights and vault sign-in. So only the profile lists a plugin, in `plugins`: `packs`,
`extend`, and `include` refuse one, and no pack declares `[secret-source.<scheme>]` or an input of
a plugin. An input belongs to one plugin, and a source in the profile reads no input, so no pack
and no other plugin chooses the program that a source runs. A pack also writes no reference in a
declared scheme, so a pack cannot choose which vault item the box reads, and the profile sets one
on a pack's route. A profile file that runs by its path declares no `[secret-source.<scheme>]`, it lists no plugin whose `[inputs]` or command reads `${{ profile }}`, and in `[options]` it sets no `program` input of a plugin, and another input of a plugin only when it is a `bool` or the plugin lists its `values`. It can list a plugin from `@box/` or `~/.strands/box/plugins/`, set those inputs, and name a reference in the plugin's scheme.

**Rejected.** A `[secret-source]` table in a pack. A pack that the operator added for an agent or
a tool could then run a host program outside the box, and pick the secret that it reads. A `[secret-source]` table, or a plugin's program, in a profile file that runs by its path: a file that comes with a project then runs a host program of its choice. A `pattern` as the bound of a plugin input in such a file: a pattern limits the form of a value, not what it names, such as the folder of the program or the server that gets the vault's sign-in.

**Cost.** A pack cannot ship a vault reference for its own route. The operator writes it in the
profile, with `secret.env`. A project cannot bring its own provider. Another copy of a plugin's program needs `PATH`, or a profile in `~/.strands/box/profiles/`. A profile file that runs by its path still names which vault item goes to which host, as it names an `env://` variable. It sets a plugin input only to a value that the plugin lists, and it cannot use a plugin that finds its program beside the profile file.

<a id="box-knows-no-provider"></a>
### `box` knows no provider and no agent, so the packs say what the report and the search need

The code of `box` names no provider pack, no agent, no plugin, no input, and no route that
`resources/` holds. A new or changed provider, agent, or plugin then needs no change to `box`. The
"Next" steps of `box profile create` come from the resolved profile's routes. Each `env://`
variable gets one step, with the hosts of each route that reads it. Each route with an `aws://`
`secret.ref` gets one, and so does each route with a reference in a declared scheme, which asks
for no variable. An agent pack lists the folders where its agent
installs, in the order to try them, and one generic search finds the program
([profile-language.md](profile-language.md#program-search)). A folder layout that one installer
uses to store an agent is pack search data. Runtime dependencies come from
[installation layouts](#an-installation-pack-names-a-layout).

**Rejected.** A match on the provider name, such as a Bedrock text for `@box/bedrock`: each new
provider then needs a change to `box`. A key mint command in the report: it is specific to one
provider, so the user guide holds it. Per-agent discovery code, with each agent's install folders,
an installer's registry reader, and a `--version` check: each new agent or search location then
needs a change to `box`.

**Cost.** The report states only the hosts and a variable, or the plugin that reads the key. It
does not say how to get a key for those hosts, or how to sign in to a vault. The search never runs
the program, so the first file with the agent's name in the listed order wins, even a launcher that
is not the agent, and the report shows no agent version. A `*` takes the newest version folder,
which is not always the version that an installer selected.

<a id="a-pack-states-its-kind"></a>
### A pack states its kind, and `box` checks the kind against the pack

Each pack states `agent`, `tool`, or `support` in `[pack] kind`, and `box` refuses a kind that
the pack's keys or the packs it extends contradict. A reader then learns what a pack is from its
header, and a pack whose `[run]` holds a key of another kind stops with an error instead of
running something else.

**Rejected.** A kind inferred from the keys alone: it needs no new key, but a pack's role changes
with no error when a key moves. A `provider` kind: no rule applies to provider packs only. An
earlier `provides = ["provider"]` marker with a `[requires.provider]` slot was removed, because
the slot's default chose the model service for the operator.

**Cost.** Every pack, the operator's own too, writes `kind`. A new kind, such as one for a pack
that holds only a tool grammar, needs a change to `box`.

<a id="extend-and-include"></a>
### `extend` builds a pack on another, and `include` loads a tool pack beside it

A pack names other packs in two keys of its `[pack]` header. `extend` names the packs it builds
on, and merges them into it. An agent pack extends agent and support packs and adds to the same
agent. A tool pack extends tool and support packs. When it extends a tool pack, its tool takes
that pack's resolved tool in, and that tool is not a tool of its own: `@box/go` extends `@box/git`,
so go starts git with `@box/git`'s variables and reads, and the box has no `git` tool. A support
pack extends only support packs. `include` names tool packs to load as tools of their own, beside
the pack, as a profile's `packs` does, and merges nothing of them. `@box/npm` extends and includes
`@box/node`, so npm gets node's settings and the agent keeps a `node` tool. Each key then means one
thing for every kind: `extend` is inheritance, and `include` is a second tool.

**Rejected.** A tool pack's `extends` that only loaded the other pack, as on main: go's own git got
none of git's settings, so each pack copied `@box/git`'s, and a `@box/git` fix did not reach the copies.
Inheriting through `helpers`, by program name or by a pack name such as `helpers = ["@box/git"]`:
a helper is a program the tool starts, and inheritance is a relation between packs, so the two
concepts mixed. Keeping the extended tool as a tool of its own: `extend` then meant inheritance
and a second tool at once, unlike an agent pack's `extend`.

**Cost.** `extends` is renamed, so every pack, the operator's own too, writes `extend`. A pack that
wants both the settings and the tool writes both keys. A `dependency` on a tool that only `extend`
brings in stops the load.

<a id="one-kind-per-file"></a>
### Each kind of file that `box` reads holds one kind of thing, so a pack holds no starter

A profile is a `profile.toml`, a pack is a `pack.toml`, a policy starter is a `policy.toml` with
its `policy.dw`, and a starter is a `starter.toml`. Each kind has its own folder, its own names,
and its own loader, and no file holds the tables of another kind. A reader then learns what a
file is from its name, each loader checks one schema, and one kind changes with no change to the
loader of another kind.

**Rejected.** A `[starter]` table in the agent pack: tried first. Each pack then had at most one
starter, with the pack's name, a team starter had to be a `support` pack with no other use, and
each pack load had to drop the table.

**Cost.** An agent pack and its starter are two files, and a change to the pack's inputs can need
a change to its starter. A new kind needs its own folder beside the packs and in `~/.strands/box`, and
its own lines in each package step.

<a id="a-profile-runs-one-agent"></a>
### A profile runs one agent

A profile names one agent pack, such as `@box/claude` or a team pack that extends it. Any other
agent pack in the profile must be one that this pack extends. So `@box/claude` with `@box/kiro`
stops the load. Box Core starts one agent, and a merge of two agent packs runs one pack's
`command` with the grants, storage, and routes of both.

A team pack that extends `@box/claude` is an agent pack (`kind = "agent"`), and it adds to Claude
Code: an extra variable, a grant, or its own `command`. Two such team packs in one profile also
stop the load, because neither is the one agent pack that the profile names. A third pack that
extends both is.

**Rejected.** Merge the agent packs, and let the later `command` win, as every other list does:
the agent that runs gets grants that its own pack never asked for.

**Cost.** To combine two team packs for one agent, the operator writes a pack that extends both
and names that pack in the profile.

## Values and inputs

<a id="values-that-change-are-explicit-references"></a>
### `${{ name }}` in a string marks what `box run` fills in, and only an `env` value names a host variable directly

A value that differs between runs or hosts is a placeholder in a string, such as
`"${{ storage.tmp }}"`, and the rest of the string is literal. Each name is built in, such as
`home` or `storage.<dir>`, or is `inputs.<name>`, which a pack declares in `[inputs.<name>]`. A
reviewer finds every input in one kind of table, and any other name stops the load. [profile-language.md](profile-language.md#values) states the rules.

The one exception is an `env` value `{ from = "env:<NAME>" }`
([host variables](#the-agent-gets-only-the-host-variables-a-pack-names)). An `env` value is always a
string, so a table there is never a literal. The entry is dropped when the host does not set the
variable, which a placeholder cannot state, because an input always has a value.

**Rejected.** Reference tables anywhere else, such as `{ from = "env", name = "TERM" }` in a
command or a setting: tried first. They are verbose, and inside free-form agent settings a table
can be a literal JSON object, so a reader cannot tell a reference from a value. A programmable language such as CUE, Pkl, or Starlark:
`box` writes data, not programs.

**Cost.** The language has no expressions. A value that needs logic needs a new built-in name, or
a `bool` input and `when`. A placeholder fills in text, so a value with one is a string: a
`set` value can be a literal number, boolean, or list, but never a number from an input.

<a id="a-pack-reads-a-host-file-for-now"></a>
### Host-file values are not profile inputs

An input reads a host value from a variable, or a `program` input's `search` lists host folders
and reads each candidate's `#!` line ([program search](profile-language.md#program-search)), on
each run. A starter reads the agent's host settings files once, when it creates a profile, and
writes each answer into the profile ([detection](detection.md)). A pack can copy a host file into
storage ([copies](#a-copy-belongs-to-the-box)), and no value that a copy reads becomes an input.
The `homebrew` layout reads a bounded receipt below a keg's physical root. A receipt names other
kegs in the same prefix's `Cellar`, and `box` refuses a receipt or a `pyvenv.cfg` that a run can
write. These values select kegs; they never become commands, environment variables, or routes.

**Rejected.** A host script that computes an input, or running the agent to ask it: it would
follow any agent configuration, but it can read any file, reach the network, and read the
credentials of `box`. A file source on an input: the profile would follow the agent's settings on
each run, but it would then change under the operator.

**Cost.** A change to the agent's settings after create does not reach the profile, so the
operator creates it again with `--force`. A host settings file can choose the provider pack, and so
the route and the credential variable, of a profile that no one confirmed. A preference that its
pack does not name does not reach the box. A receipt decides which kegs of its prefix a program
reads.

<a id="the-agent-gets-only-the-host-variables-a-pack-names"></a>
### The agent gets a host variable only when a pack or the profile names it

`box` never passes the environment of `box run` to the agent. An `env` entry
`{ from = "env:<NAME>" }` copies one host variable, by name, when the host sets it, and the entry is
left out when the host does not. A later layer replaces an `env` value whole, so a profile can set
its own value, or a `{ value, when }`, over a pack's `from`. A pack names only a variable that holds no key and changes no
endpoint or provider, such as `MAX_THINKING_TOKENS` in `@box/claude`.

**Rejected.** Passing the host environment through: it carries the operator's keys, a `PATH` that
the box does not grant, and provider variables that route the agent past the box's own route. A
list of refused names in `box`: it never covers each harness and tool.

**Cost.** A variable that no pack names stays on the host until the operator adds it to the
profile's `[agent.env]`.

<a id="an-env-reference-cannot-read-a-credential"></a>
### An input or a host variable cannot read a credential that a route or a secret source uses, and detection uses only a value a pack accepts

Box Core reads a credential such as `env://AWS_BEARER_TOKEN_BEDROCK` from the environment of
`box run` and keeps it out of the workload. `box` refuses an input with `from = "env:<NAME>"`, and
an `env` entry with `from = "env:<NAME>"`, for a variable that an `env://` reference or a
`secret.env` in the merged profile names, or that a secret source passes to its program as a
credential, so a pack cannot copy a secret, or the host's value of a placeholder variable,
into the agent's environment. A starter source
refuses the same names. It writes or prints a source's value only when a choice's `equals` lists it
or an input's `pattern` or `values` accepts it, and a `bool` input gets only `true` or `false`
([detection](detection.md#what-detection-never-reads)).

**Rejected.** Detect a provider by whether its key is set: it would detect the Anthropic API,
whose only sign is its key, but a source that reads a key's presence can read its value.

**Cost.** The check knows only the variables that the profile routes as credentials, or that a
secret source passes, when the profile merges. A key that an imported MCP server reads from a variable is not among them. An input
or an entry that reads another variable that holds a secret gives that secret to the agent, and an
unrouted secret that fits an input's `pattern` is written into the profile and the report. The
Anthropic API is not detected.

<a id="an-input-in-a-command-or-route-is-bounded"></a>
### An input in `command` or in a route's host needs `pattern` or `values`

A program can parse an argument (a shell's `-c`, Codex's TOML `-c`, a JSON flag), so an unbounded
value could change what the program does. A route's host decides where a credential goes, and that
holds for a backend `url` too: a deployed service sets its URL in the host environment, and the
profile reads it from an `env:` input, so a placeholder there is allowed but needs the same bound.
A backend's `auth.aws.region`, the region an `aws://` backend auth signs for, is set the same way
and takes the same bound.
So `box` refuses an input that reaches a command or a route's host and has no `pattern` or
`values`.
[Inputs that reach `command` or a route](../../cli/packs-reference.md#inputs-that-reach-command-or-a-route)
lists the fields and the exemptions. A free-form value goes through `env`, where it is data to the
program: the indirection that GitHub Actions recommends for `run:` scripts, enforced because inputs
are typed.

**Rejected.** Detect the argument after `-c` for known shells: a heuristic that misses `sh`,
`python -c`, and wrapper scripts.

**Cost.** A pack author writes a `pattern` for each input in `command`.

<a id="a-bool-input-switches-with-when"></a>
### A condition is structured fields, never an expression

A `when` holds one fact: `macos`, `linux`, a placeholder for a `bool` input, or the table
`{ variable, equals }`. `box` parses no operator, so a reviewer reads what a condition tests, and
one pack covers each combination with no variant pack.
[profile-language.md](profile-language.md#entries-and-when) states where a `when` goes.

**Rejected.** Operators in a string, such as `==` or `&&`: each one starts an expression language,
and `box` writes data, not programs.

**Cost.** A condition on more than one fact needs a `bool` input that the operator sets. Each
condition doubles the configurations that a pack author tests.

<a id="a-when-never-drops-a-program"></a>
### A `when` never drops the program of a command or the secret of a route

`box` refuses a `when` on a part that decides what its table is, when it loads the file, on every
host and for every input value. Without element 0 of a `command`, the next element (a flag, or an
`agent-args` path that runs) is the program, and the path rule never checks it. A route without its
`secret` [opens its hosts with no credential](#a-route-with-only-destinations-opens-a-host). A `when`
on a key inside `secret` keeps the table, so Box Core still reads the route.

**Rejected.** Refuse only a first element that is not a program: `box` cannot tell a program from
a flag. Refuse only a `when` that drops element 0 in a run: the error then depends on the host and
the inputs, so a pack that works for its author fails for another operator.

**Cost.** A pack cannot choose its program with two `when` elements, one for each OS. It uses a
placeholder such as `${{ agent.<name> }}` or a `program` input. A pack that needs a credential on
one OS only writes two routes, each with its own `when`.

<a id="an-option-changes-what-the-box-allows"></a>
### An input exists only when it changes what the box allows or how it is wired

`bedrock.region` is an input, because it decides the host of the model route. `claude.host` is an
input, because it decides `CLAUDE_CODE_USE_BEDROCK`. The model is not an input, because the agent
picks it in its own settings. An input with one allowed value is not an input, so the pack writes
the value.

**Rejected.** A `model` input: it repeats the agent's own setting, and the box enforces nothing
about it. A `codex.host` with the one value `bedrock`: the operator can set nothing with it.

**Cost.** The agent's own setting must name a model that the profile's provider serves in its
region. `@box/claude` copies `model`, `ANTHROPIC_MODEL`, and the three `ANTHROPIC_DEFAULT_*_MODEL`
variables from the operator's Claude Code settings and shell, and checks none of them.
`@box/codex` imports the host's model into its private settings and preserves a saved choice.
With no configured model, Codex chooses its default.

## MCP servers

<a id="a-pack-names-where-its-agents-mcp-servers-are"></a>
### A pack names where its agent's MCP servers are, one generic reader reads them, and the profile turns import on

An agent pack names the host files that hold its agent's MCP servers, and one generic reader
reads them, so a new harness needs no change to `box`
([the reader](profile-language.md#mcp-servers)). Import is a `bool` input that is off by default.
The starter asks for it and shows its `warning`, and the answer is saved in the profile.

**Rejected.** On by default, tried first: it keeps the agent's setup with no step, but host setup
is not consent to bring those servers into a box. A consent prompt on each `box run`: it is
current for each run, but two runs of one profile then get different grants that the profile does
not record ([a run sets no input](#box-run-takes-no-option-values)).

**Cost.** A yes lets declared local servers run in the box with the keys in their configuration and the
operator's environment, and lets the agent reach each declared remote server's host. Settings are
copied even without generated policy. Any `env` keys retained in the agent's settings are readable
by the agent. A yes also covers servers added later and, for `@box/claude`, each project's local scope.
A list of server names in the profile would narrow a yes, and is not built.

<a id="mcp-import-does-not-require-generated-policy"></a>
### MCP configuration import does not require generated policy

`box` imports the operator's selected MCP settings even when it cannot generate policy for a
server. Host configuration describes what the agent uses; generated declarations describe what
Box Core can enforce for that server. Runtime support and declaration checks must not remove
the operator's settings from the import. The source-file trust checks still apply.

**Rejected.** Importing only servers with generated declarations, tried first: unsupported
commands such as `node`, `uv`, and `python3` disappear from the agent's settings.

**Cost.** Import adds no grants. A server can fail or run through existing agent, tool, and route
permissions without generated per-server MCP controls. When a final stdio declaration matches an
entry's filename and arguments, import writes the entry with the bare filename and without its
environment fields, so the agent starts the declared server. Import also omits the environment
fields of a stdio entry whose `env` holds the value of a variable that a secret source's
`pass-secret-env` entry covers, or sets such a variable, and the `args` of one whose argument,
as written, holds that value. Otherwise the entry keeps its
environment fields and its arguments, and keys in them are readable by the agent. When a profile table with a `type`
replaces such an entry, the skip line says so. A saved import keeps the fields that it was written
with until the operator refreshes it.

<a id="a-detected-server-carries-no-credential"></a>
### `box` declares a detected server as its configuration states it, and turns only a key in a variable into a placeholder

`box` declares each detected server as the operator's configuration states it, and drops or
refuses nothing in it to protect a key the host does not protect. A remote server whose key comes
from one variable gets `secret.ref = "env://<VAR>"`, so the agent holds a placeholder. A plain
header, a typed-in key included, is the agent's to send from its own configuration. A stdio
server declared from host settings gets its credential values as written, typed-in keys included, in its own sandbox
([a local server's key is in `box.toml`](#a-local-servers-key-is-in-box-toml)). A server is
left out of generated declarations when it cannot work in the box or when Box Core would refuse
the config. Its settings remain in the [import](#mcp-import-does-not-require-generated-policy). Launcher packs
set the runtime and cache environment values needed to run inside the box.

**Rejected.** A skip for a plain header whose name looks like a key, tried first: it refused
working host configurations, and it guessed from a list of names. A typed-in key put into a
variable that `box` sets for Box Core: it guesses which header holds the key, and the agent's
configuration must then send the placeholder.

**Cost.** A typed-in remote header key is in the agent's reach, and the agent can send it to any
host the box permits: its model, each route, each declared server's host, and each tool's registry
hosts. Local command arguments are also visible to the agent, including keys written there, except
the operator's value of a variable that a secret source passes as a credential: `box` leaves that
server out and removes the arguments from the agent's copy.
Argument variable references remain for the harness to handle. A local server declared from host
settings keeps its environment values in its private configuration.

<a id="a-local-servers-key-is-in-box-toml"></a>
### A local server declared from host settings keeps its key in `box.toml`

A stdio server that `box` declares from host settings gets its `env` as on the host: each variable
filled in from the operator's environment, and a pasted key copied as written. Box Core starts the server in its own
sandbox, apart from the agent, with that `env`, so the server holds its real key and the agent
cannot read it directly. `box` skips a server that reads or sets the vault's own sign-in, or the host's
value of a variable that holds the stand-in of a key from a secret source, and a server with the
vault's sign-in in an argument.

**Rejected.** A Box Core `env` value that names a host variable for Box Core to read at start:
`box.toml` would hold no key, but `env` takes only literal values, so it changes a frozen key. A
placeholder that the gateway swaps, as for a remote server: a local server names no host, so
each server would need a route first.

**Cost.** The key stays in `~/.strands/box/r/<run>/box.toml`, which the agent cannot read, until
`box clean`. The agent can plant files in the workspace, or under a `HOME` that lies in
it, that the server reads or loads at start, and so get the key.

<a id="a-detected-server-reads-its-install-directory"></a>
### A detected stdio server reads its install directory and gets the workspace as `[project] access` allows, and nothing its arguments name

A detected stdio server gets the reads that the installation layouts find for its program and
each `#!` interpreter, the workspace grants that `[project] access` gives the agent
([project access](#project-access-is-one-profile-level)), the
agent's denies, and any shipped launcher grants, but no grants from arguments.
Core's refusal kind identifies system directories that need no whole-directory grant; any other
refusal on an install directory skips the server.
Each `#!` program outside a read directory gets an exact `read_file` grant, as Core on Linux
requires ([profiles.md](profiles.md#mcp-servers)).

**Rejected.** Grants on paths in `args`: harness configuration would grant reach outside the
workspace. A local list of system roots was tried, but it can mistake another refusal under a
system path for a system-tree refusal; Core's classification gives the actual reason.

**Cost.** Application data outside the installation and workspace still needs an explicit
`[mcp.<name>.filesystem]` addition. A program that no installer layout matches reads its whole
folder, such as `/opt/homebrew/bin` for a script there. An incomplete Homebrew receipt skips the
server.

<a id="launcher-caches-are-separate-from-agent-tool-caches"></a>
### Launcher caches are separate from agent tool caches

A launcher tool pack resolves separately for agent tools and MCP servers. The agent tool uses
a workspace cache. The server uses a launcher cache in profile storage, which neither the agent
nor its tools can write, because a server can run cached code with its real keys. `box run` refuses
a write grant in the cache on any process but the servers that its launcher starts, and the box
home's forbids cover the cache, so no operator permit opens it to the Shell or Monty
([trusted directories](#a-run-cannot-write-what-a-later-run-trusts)). Servers that use
the same launcher share its cache in every workspace of the profile, as they do under one user
account outside the box.

**Rejected.** Reuse of an agent tool's cache: it lets the agent replace cached code the server runs.
One cache for each profile and workspace, which shipped first: agent storage crosses projects
already, so it isolates no project
([the profile is the unit of isolation](#storage-is-one-directory-per-profile-and-workspace)).
Per-server caches: servers that share a launcher outside the box share its cache, and `box` keeps
that sharing.

**Cost.** A server can change code that another server later runs from the shared cache, in any
project of the profile, with that server's keys. `npx` and `bunx` can select project-local
packages outside this cache, so agent-planted code can run with the server's keys
([local server key exposure](#a-local-servers-key-is-in-box-toml)). Under the experimental native
filesystem policy, the policy decides a server's own writes to its cache. The policy has one
principal and cannot tell the server from the agent, so the box home's forbid would refuse those
writes. `box run` therefore starts no launcher server that selects native checks, and names
`[mcp.<name>] native-filesystem-policy = false` as the fix.

<a id="a-tool-owns-its-state-outside-the-workspace"></a>
### A tool pack's storage belongs to the tool, and its rows copy or link host entries into it

A tool pack declares storage as an agent pack does, with `[storage] directories`, and
`${{ storage.<dir> }}` names each one. Who owns it follows from where it is declared. The agent's
directories, from a profile or an agent pack, are `<storage>/agent/<dir>`, apart from what `box`
keeps in the storage root, and get the agent's grants and the `fs:*` permits. A
tool's directories are `<storage>/tool/<tool>/<dir>`, and get neither: the tool reaches each one
through its own `read` and `write` entries, and the agent cannot name one. So what a tool installs
there, such as a private Homebrew prefix or the toolchains that rustup installs, changes only
through a tool call that policy decides, and the agent cannot read what a tool keeps there, such as
a login the tool made in the box. A tool's `[[storage.files]]` row copies or links a host path
into the tool's storage. With `mode = "copy"` the row is an agent copy row whose
target is in the tool's storage, so the agent gets no grant to the copy. With `mode = "link"` the
row makes one read-only link to the path, and each run brings it up to date. With
`mode = "link-children"` it makes a real folder with one read-only link for each entry inside the
path. A copy and a link of one tool cannot share a target or lie one inside the other, so no copy
is made through a link. A tool that needs its own settings, edited by `set`, copies them. A tool
with one home
keeps what the box installs in its storage and still uses the operator's own files: `@box/cargo`
sets `RUSTUP_HOME` to its own `rustup` directory and links in the operator's `settings.toml` and
each of their toolchains, so `cargo` outside the box never runs what a box installed.

**Rejected.** A folder in the workspace: the agent writes the workspace directly, with no tool
call, so it could change what the tool later runs with the tool's reach. A tool's directory
in the agent's `[storage] directories`, or one that a reserved name keeps apart: the agent reads
and writes those, and a convention does not stop a profile from granting one. A write grant on the
host home, such as `~/.rustup`: the host tool then runs what a box installed
([a run cannot write what a later run trusts](#a-run-cannot-write-what-a-later-run-trusts)). A
copy of a toolchain instead of a link: a toolchain is about 500 MB, and the copy goes stale. A
folder for each workspace: each project downloads and keeps its own copy of what the tool installs.

**Cost.** Project code that the tool runs, such as a `build.rs` that `cargo` runs, can change the
tool's storage, and every workspace of the profile then uses what it changed. The profile is the
unit of isolation ([storage is one folder per profile](#storage-is-one-directory-per-profile-and-workspace)),
so this reaches no further than a hook planted in the profile's agent storage. To keep two
projects apart, run them with two profiles. A program in a tool's storage lies under the tool's
write grant, so it is never a tool of its own
([a write grant never changes which program runs](#a-write-grant-never-picks-the-program)), but a
program that the tool itself starts from there, such as the `rustc` that rustup starts, is not
checked. Two boxes of one profile can run the tool at the same time with no lock from `box`. A
linked host entry is read-only, so the tool cannot update or change it in the box, and a link the
tool makes itself in a `link-children` folder lasts one run.

<a id="a-tools-row-names-its-mode"></a>
### A tool's `[[storage.files]]` row names its mode

An agent row copies when it names no `mode`. A tool's row has no default: it says
`mode = "copy"`, `"link"`, or `"link-children"`, or the load stops and names the three. A copy is
made outside the box, so it hands the tool a host file that its own grants may not reach. A link
grants nothing, and the tool still needs a read grant on the source. So a row that leaves out
`mode` neither hands out a file nor quietly picks the other kind.

**Rejected.** `copy` as the default, as in an agent row: a forgotten `mode` would copy a file,
such as a login, that the tool cannot read. `link` as the default: the same row would then copy in
the agent's table and link in a tool's.

**Cost.** Every tool row writes `mode`.

<a id="a-tool-can-have-the-gateway-upgrade-its-host"></a>
### A tool can have the gateway upgrade a host it reaches from `http://` to `https://`

A tool's `upgrade_http` lists hosts from its own `hosts` whose plain `http://` request the gateway
sends as `https://`, and `box` collects them into Box Core's `[gateway] upgrade_http`. rustup on
macOS checks certificates with the platform verifier, which cannot trust the box's certificate
authority, so `@box/cargo` lists `static.rust-lang.org` and, on macOS only, sets
`RUSTUP_DIST_SERVER` to its `http://` address. On Linux rustup trusts the box's certificate, so it
keeps `https://` and skips the plain hop. An entry not in the tool's `hosts` is dropped, so a
profile that narrows `hosts` narrows the upgrade too. The gateway decides the request as `https://` on port 443 and checks the
server's certificate, so the tool's host permits still decide it, and it adds no grant.

**Rejected.** A `[gateway]` table in the profile: each profile would have to write it, and a tool
pack could not. A host the tool does not list in `hosts`: the tool could then widen what the whole
box upgrades. `RUSTUP_USE_CURL=1` and `RUSTUP_USE_RUSTLS=0`: both still check TLS against the
platform's roots. A `file://` mirror: it needs a helper that downloads outside the box.

**Cost.** The list applies to every process in the box, not only to the tool. The hop from the
process to the gateway is plain HTTP that stays on the machine, so anything in the box that can
read that traffic can read the request. The gateway never adds a credential to an upgraded
request, so `upgrade_http` suits only a host that needs no login. rustup still checks each file
against the hash in its channel manifest.

<a id="uv-installs-into-the-uvx-tool-folder"></a>
### `@box/uv` installs tools into `@box/uvx`'s agent tool folder

`uv tool install` and `uvx` use one tool folder for the agent's tools. `@box/uv` sets
`UV_TOOL_DIR` to `${{ workspace }}/.cache/uvx/tools`, the folder that `@box/uvx`'s
`${{ cache }}/tools` gives for an agent tool. So `uvx <name>` runs a tool that
`uv tool install` added, as it does outside a box, where both read one `UV_TOOL_DIR`. Every tool
can write the workspace already, so the shared folder grants neither tool more. An MCP server's
tools stay in profile storage ([launcher caches](#launcher-caches-are-separate-from-agent-tool-caches)).

**Rejected.** A tool folder for each pack: `uvx <name>` then does not find the installed tool,
and it fetches a package of that name from PyPI, which can be unrelated code. `@box/uvx` pointed at
`@box/uv`'s folder: `@box/uvx`'s `${{ cache }}` also names an MCP server's cache, so the server's
tools would move into the workspace, which the agent can write.

**Cost.** `@box/uv` names `@box/uvx`'s folder by its path. A copy of the uvx pack under another
name, such as `acme/uvx-pinned`, gets `.cache/uvx-pinned/tools`, and a change to `@box/uvx`'s
`UV_TOOL_DIR` moves the folder. Either one breaks the link with no error, and `uvx <name>`
fetches from PyPI again. The corpus's uv tool install cell checks the link with
`uvx --offline`, but only on the corpus bench, not in pull request CI.

<a id="launcher-compatibility-claims-name-tested-versions-and-runtimes"></a>
### Launcher compatibility claims name tested versions and runtimes

Initial launcher validation has a finite scope on macOS arm64: npm 10 on Node 22, npm 11 on
Node 22/24/26, npm 12 on Node 24/26, uv 0.10/0.13 with installed Python, pnpm 10 on Node 22,
pnpm 12 on Node 24, and Bun 1.4 with Node 22. The
[engine checks](../../dev/engine-tests.md#launcher-tests) record exact versions and results.
A target is not a passing compatibility claim. Other versions, runtimes, platforms, and server
packages require their own evidence.

**Rejected.** A rolling last-N-release window or daily compatibility checks: the initial pass
has a finite test scope.

**Cost.** Upstream changes can break a pack. A targeted combination can remain unsupported;
passing baseline tests do not conceal that gap.

<a id="a-server-name-is-renamed-and-a-collision-is-skipped"></a>
### A generated declaration keeps the server's name or is omitted

Box Core takes a server name of letters, digits, `.`, `_`, and `-`. `box` omits a generated
declaration whose name holds any other character, and the report tells the operator to rename
it in the agent's configuration. The imported settings keep the original name. A declared
server has one name in the harness's configuration, in `box.toml`, and in `policy.dw`.

**Rejected.** A change of each other character to `-`, tried first: the box then knows a server by
a name its harness does not use, and each later step, such as the agent's own list of servers in
the box, must map one name to the other. A suffix such as `-2` on a collision: the name in policy
then depends on which other servers the host has.

**Cost.** A server with a name such as `my docs` gets no generated declaration until the operator
renames it.

## Policy

<a id="a-pack-adds-no-policy"></a>
### A pack adds no authored policy, and `box` generates only the policy that configuration declares

`box` writes a rule only from a typed table: a tool, a route, an MCP server, storage, or the
profile's `[project]`. The exceptions are the forbids that protect the box home, `box`'s
resources directory, each other root that a run refuses a write grant over, and `<workspace>/.box`. Other rules, such as the shell's, are in a policy starter, so
the profile's copy shows them. Only the operator's profile lists authored files in `policies`.

**Rejected.** Authored rules in packs: an imported rule can permit what no table names. Base rules
in every run: no operator file showed them, and a policy could only narrow them. A cloud metadata
floor: a list for each provider, when only the operator knows where the box runs. `@box/open`
forbids the link-local class instead. A refusal of loopback host names on a route or an http MCP
server: it read the spelling only, so `localhost4`, `2130706433`, or a name that resolves to
`127.0.0.1` passed it. `@box/open` forbids loopback by the resolved address instead.

**Cost.** A copy without the shell rule runs no command. A metadata endpoint outside link-local
stays reachable until the operator forbids it. A starter fix never reaches an existing copy. Box
Core sets `NO_PROXY` to `localhost` and `127.0.0.1`, so a route or server on those names compiles
but connects inside the box, not through the gateway.

<a id="policy-holds-no-placeholder"></a>
### `box` writes the policy rules a typed table implies, and `policy.dw` holds no placeholder

For each `[egress.<name>]` route, `box run` adds a `net:connect` permit on each destination's host
and port and an `http:request` permit on each host. For each `[mcp.<name>]` table, detected or
written by hand, it adds `mcp:call` for the name, and `shell:spawn` pinned to the program and its real path for a stdio
server, or the route permits for an http server's destinations. A profile's `forbid` narrows them.
For each storage directory, it adds `fs:read`, `fs:write`, `fs:delete`, and `fs:move` permits, and
it forbids writes, deletes, and moves in `~/.strands/box` outside the storage directories and the tools'
storage. A value reaches the policy only through these rules, as a quoted policy literal from
`render::literal`.

**Rejected.** Placeholders in `policy.dw`: a value could change the structure of a rule. A literal
model host in an agent's `policy.dw`: tried first, and the region in the policy and in the profile
had to change together.

**Cost.** The profile's authored rules cannot interpolate a host path or an input. A rule that
needs a resolved value needs a typed table that `box` turns into rules.

<a id="a-network-permit-needs-a-named-destination"></a>
### `box` writes a network permit by itself only for named destinations

`box` writes `net:connect` and `http:request` only for the `destinations` of an `[egress.<name>]`
route or an `[mcp.<name>]` table, a detected remote server's URL host included, for a tool
pack's `hosts`, and for the package registry hosts that a shipped launcher pack names, when a
detected server uses the launcher. It does not infer API hosts from the server's package name. A
stdio MCP server, a hand-written tool, or any other process whose hosts are decided at run time
reaches only the hosts the box already permits, and the operator adds any other host as a route.
Picking `@box/open` at create copies rules that reach every host into the profile's `policy.dw`
([the policy question](#the-policy-question-defaults-to-open)).

**Rejected.** A permit on every host that `box` adds by itself for such a process, or a host list
for each known MCP server: a configuration never says where a local server connects. Box Core decides a host for the
whole box, not for one process, so a host permitted for a server is permitted for the agent.

**Cost.** A stdio server that calls a web API fails until the operator adds a route, and the agent
can then reach that host too. A detected launcher also makes its package registry hosts reachable
by every process in the box, even when the agent has no package-manager tool. An operator who
picks `@box/open` makes every host but loopback and link-local reachable by every process in the box.

<a id="the-policy-question-defaults-to-open"></a>
### At a terminal, `box profile create` asks which policy starter to copy, and Enter picks `@box/open`, which reaches every host but loopback and link-local

After the agent starter's questions, `box profile create` asks which policy starter from
`[policy-starters]` the profile starts with, unless `--policy` or the starter's `[starter] policy`
answers, and copies the answer into the profile
([the copy](#a-policy-starter-is-copied-into-the-profile)). Enter picks
`default`, which `box` ships as `@box/open`: every host except a loopback or link-local address. A coding agent
researches on the web, and a box that refuses each host that no route names stops that work at its
first request.

**Rejected.** `@box/scoped` as the default, as it grants less: tried first, and
research tasks failed at once. No default, so the operator types a number: the prompt already
lists each policy with what it reaches, and Enter that does nothing reads as a hang.

**Cost.** A profile made with Enter lets the agent send project files to any host, and reach a
host on a private network.

<a id="a-policy-starter-is-copied-into-the-profile"></a>
### `box profile create` copies the policy starter into the profile, and the copy is the operator's

`box profile create` writes the picked policy starter's `policy.dw` into the profile folder as
`policy.dw`, after a header that names the starter, and lists it in `policies`. A run reads only
that copy, through the same `policies` path as any other authored file. After create, only
`box profile create --force` replaces the copy, together with `profile.toml`. An operator who wants another rule
edits the file the profile already has.

**Rejected.** A `base-policy` key that names the starter, which each run reads from `box`'s
resources: tried first. It delivers a fix to a shipped starter, such as a new loopback range, to
every profile on its next run, and it keeps the starter's name in a key that a tool can read. But
an operator must copy the rules out and switch to `policies` before changing one rule, and an
upgrade of `box` changes what an existing profile reaches without an edit to the profile.
`--force` that keeps an edited copy: `--force` replaces the profile, and a kept copy can hold rules
that the new answers do not ask for.

**Cost.** A fix to a shipped starter reaches only profiles created after it. An existing profile
gets the fix when the operator recreates the profile or edits the copy. Only the copy's header
records which starter it came from, and an edit can remove it. `--force` discards the rules an
operator added to the copy.

<a id="a-route-with-only-destinations-opens-a-host"></a>
### A route with only `destinations` opens hosts that get no credential from the box, and a pack may write one

A route whose one key is `destinations` opens hosts that get no credential from the box: an
agent's login service, and a service that the agent then reaches with its own token, such as Kiro's
in `@box/kiro` with `kiro.sign-in = "login"`. `box` writes their permits and leaves the route out of
`box.toml`. A pack may write one, because an agent that signs in inside the box cannot run until
those hosts open
([a pack makes its agent run](#a-pack-makes-an-agent-run-and-never-extends-it)).

**Rejected.** An `[agent] hosts` list, like `[tool.<name>] hosts`: `[egress]` keeps the meaning
that Box Core's docs give it, but a host moves to another table when it gains a credential. Such a
route in the profile only: no imported pack opens a host, but each operator writes the login hosts
before the first run.

**Cost.** Any process in the box can send what it reads to such a host, and an imported pack can
name one. A name on the operator's network or VPN is reachable. A sign-in inside the box leaves a
token in storage that the agent refreshes, reads, and can send to any host the policy permits, in
each project of the profile, until the operator deletes the storage. Box Core attaches only a
secret that exists before the run. `box`'s `[egress]` differs from Box Core's docs, which refuse an
entry with no secret.

<a id="an-aws-route-names-a-profile"></a>
### A bare `aws://` route signs with the host's default credential chain, and `box` adds no `~/.aws` guard

`box` accepts a `secret.ref` of `aws://` with no profile: on an `[egress.<name>]` route, on a
`[[egress.<name>.backends]]` `auth`, and on an `[mcp.<name>]` server. Box Core signs it with the AWS
SDK default credential chain, so the box carries the host's ambient identity from the environment, a
static-keys profile, a web identity, the container endpoint, or instance metadata. The "Next" list
that `box profile create` prints names an `[egress.<name>]` route that signs this way, and Box Core
warns on each request for any site that uses the bare form. `box` adds no refusal over `~/.aws`.

A bare `aws://` reads the same AWS configuration, and runs the same `credential_process` in Box
Core's trusted process, as the `aws://<profile>` form that `box` already accepts. So a bare route
adds no tampering risk that a named route did not already carry. Box Core's containment floor already
refuses a write to `~/.aws` (and `~/.ssh`, keychains, and the other credential paths) beneath every
grant, whatever a grant or rule says, so a box cannot plant a `credential_process` in the default
location. The one punch-through is a store the operator names exactly; a prefix or a parent of it
stays refused. A policy rule does not enter into it: Box Core enforces `[agent.filesystem]` grants
and this floor in the OS, below policy.

**Rejected.** Refuse the bare form, and make the operator write `aws://<profile>`. A named profile
is a narrower identity, but Box Core supports and discloses the bare form and warns on each request,
so refusing it blocks an operator whose host identity is an instance role, a container endpoint, or
a web identity, which no profile file holds.

**Rejected.** Accept the bare form, and add a `box` refusal of any write grant that reaches `~/.aws`.
Box Core's containment floor already refuses the default credential paths beneath every grant, so a
CLI guard over `~/.aws` duplicates the floor for the case the floor covers. It does not cover the
case the floor misses, a config file that `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE` moves
outside the credential paths, for example into the workspace (which every run grants). That residual
belongs to the invoker that opts into `aws://`, which keeps the moved file out of a write grant, not
to the CLI for every run. A pack that signs with a bare route by default makes the choice an input
with a `warning`, so `box profile create` shows the residual and saves the answer as the operator's
opt-in.

**Cost.** A bare route signs every matching request with the host's whole ambient identity, which
can be wider than a named profile and which the operator cannot narrow in the profile. Box Core's
floor stops a box from writing the default credential paths, but not a config file that
`AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE` moves elsewhere, nor a store the operator names
exactly; keeping those out of a write grant is the invoker's. A route that an operator adds by
editing `profile.toml`, or that a pack adds after create, is disclosed only by Box Core's warning on
each signed request, not by the create "Next" list. The shipped Bedrock packs sign with a bare
route by default, so on a cloud machine a Bedrock profile signs as the machine's own role unless the
operator picks a key.

<a id="box-never-parses-the-policy-language"></a>
### `box` never parses the policy language, so a policy error has a line only where Box Core gives one

`box` places a Box Core policy finding by Box Core's own location, and names a rule with no
location by the position and `@id` Box Core reports. A change must not add a Dogwood scanner to
turn a rule into a line.

**Rejected.** A scanner in `box`: it copies Dogwood's grammar, and a grammar change makes it point
at a wrong line with no error.

**Cost.** A finding with no location has no line: Box Core's own checks (a duplicate `@id`, a cap
written as a `permit`) and every finding in a box with a local MCP server, until Box Core reports
rule spans. Locations refer to the combined policy, without a mapping to the authored files. A
parse error past the authored text that names no rule counts as the operator's, with no line, even
in a rule that `box` writes.

## Runs

<a id="each-run-gets-its-own-box"></a>
### Each run gets its own box, unless the operator names an earlier run's box

Each `box run` creates a new instance with an empty `box_dir`, so runs of one profile can run at
the same time. `box run --box-id <id>` runs in the instance `<id>` again, from any workspace: the
run is compiled for its own workspace, so the grants follow it, and the box's history carries on.
Only `box` mints an ID, and only a run of the minting profile can reuse it.

**Rejected.** An ID reusable only in the workspace it was minted in: it refuses a subfolder, a git
worktree, and a moved project, while the agent's conversations already follow the profile. One home
`box_dir` for each profile and workspace: no ID to keep, but which history a run gets depends on
timing.

**Cost.** A run without `--box-id` starts each `when temporal` rule empty. A reused box carries its
history to every workspace: a limit counts all of them, and a gate opened in one stays open in the
next. A rule that names a path sees only events at that path. `box clean` removes kept boxes too.

<a id="box-core-uses-the-box-id"></a>
### Box Core uses the box ID that `box` mints

`box` passes its ID (`b-` and 16 lowercase hexadecimal digits) to Box Core as `RunOptions::box_id`,
so the ID that `box run` prints is also Box Core's `box_id` and the `strands.box.name` of each record. The same
ID names the run directory. Profile names stay in `profile-name`, outside the socket path, so
their length does not limit where a box can run.

**Rejected.** Let Box Core generate its own ID: nothing that `box run` prints would match the
records. The tried profile prefix in the ID made it readable, but consumed the socket path budget.

**Cost.** The ID alone does not identify the profile; `box runs list` reads the saved profile
name. Box Core still refuses a socket path that exceeds its platform limit
([run layout](profiles.md#mint-or-find-the-instance)).

<a id="box-run-replaces-itself-with-box-core"></a>
### `box run` calls Box Core once

When the run's files are written, `box run` calls `strands_box::run()`. Box Core then owns the workload, the
signals, and the exit status. At a terminal, `box` supplies a PTY through `RunOptions::terminal` and
starts its relay through `on_ready`. Without the banner, the relay forwards terminal bytes unchanged.
Both displays capture startup stderr before the agent starts. Redirected runs inherit the streams.

**Rejected.** Start Box Core as a child and wait: `box` must then forward each signal and the exit
status.

**Cost.** Box Core applies process-wide hardening and signal handling inside `box`. It permits
only one run attempt per process, even when that attempt fails.

<a id="telemetry-owns-observation-and-payload-construction"></a>
### The telemetry crate owns observation and payload construction

`strands-box-cli-telemetry` owns telemetry reads, classification, and payload construction.
New telemetry fields belong there. The CLI supplies loaded sources and resolved targets at
the run's existing stages. The telemetry crate depends on no CLI or Box Core types.

**Rejected.** A serialization-only crate with observations spread through CLI modules: each
new event would add telemetry-specific reads and calculations to run and profile code.

**Cost.** A small CLI adapter converts its types into the collector's inputs.

<a id="installation-identity-survives-box-home-changes"></a>
### Installation identity survives changes to `BOX_HOME`

Changing `BOX_HOME` and cleaning trial-build directories leave installation identity unchanged.
`~/.strands/box/installation.toml` holds one ID shared by normal and trial builds for the same operator
home. A new temporary profile directory then counts as the same installation.

**Rejected.** Identity in the selected `BOX_HOME`: preparation after each new try-build commit
or cleanup can mint another ID.

**Cost.** A trial build can read or create installation metadata under `~/.strands/box` while its
workload data stays elsewhere.

<a id="smoke-telemetry-follows-the-callers-identity"></a>
### Smoke telemetry follows the caller's installation identity

Local smoke runs must reuse the developer's existing [installation identity](#installation-identity-survives-box-home-changes).
A harness that replaces `HOME` copies `~/.strands/box/installation.toml` into its temporary home without
changing the original. CI smoke runs use the repository Actions variable `BOX_TEST_INSTALLATION_ID`
to prepare that file; the configured ID stays outside the repository.
Unit tests use synthetic fixtures and neither read developer identity nor contact the telemetry
service.

**Rejected.** A separate identity for each temporary home simplifies setup but counts one
developer as multiple installations. A product environment override adds a CLI contract for
test setup that the existing installation file supports.

**Cost.** Harnesses must distinguish local and CI runs. Local smoke activity is attributed to
the developer's installation.

<a id="telemetry-sends-from-a-thread-in-the-cli"></a>
### Telemetry sends from a thread in the CLI

`box run` sends telemetry from [one background thread](telemetry.md#delivery) in the CLI
process. At any exit, including Ctrl+C and a failed start, the CLI waits at most two seconds for
the last events and sends them in one request. The service runs in one region, and a new
connection from far away can take about a second; one request gives the final events the whole
two seconds. That final request opens a new connection, so a connection that died without notice
during the run cannot cost it. This is the pattern most CLIs with long sessions use.

**Rejected.** A detached uploader process returns to the shell without waiting, but adds a hidden
mode and a process lifetime to manage; a process that lives for the whole run had no precedent we
could find. Writing unsent events to disk for the next run delays shutdown data until that run
and leaves files to expire.

**Cost.** An exit can take up to two seconds when the service is slow, far away, or unreachable,
and events still unsent at the deadline are lost. The final request's new connection costs about
three round trips at every exit, where a warm connection would take one.

<a id="the-telemetry-choice-lives-with-the-installation-id"></a>
### The telemetry choice lives with the installation ID

`box telemetry off` saves its choice in `~/.strands/box/installation.toml`, beside the
[installation ID](#installation-identity-survives-box-home-changes), and `BOX_TELEMETRY` and
`DO_NOT_TRACK` override it for one shell. Telemetry describes an installation, so the choice
belongs to the installation and survives a change of `BOX_HOME`.

**Rejected.** A setting under `BOX_HOME` would turn telemetry back on whenever a user switches
homes. An environment variable alone gives no lasting choice. A generic name such as
`DISABLE_TELEMETRY` would also silence the agents that `box` runs.

**Cost.** Turning telemetry off writes the metadata file, though it creates no ID.

<a id="banner-failure-keeps-the-agent-running"></a>
### A banner failure keeps the agent running

`box` updates the banner separately from handling the agent's input and output. A drawing
error gets one retry after 100 ms, with the same activity history.
A successful update allows a later error to be retried. Two consecutive errors hide the banner
and give the agent the full terminal. Typing, output, and shutdown never wait for a banner update.

**Rejected.** Update the banner while handling agent input and output: a slow or failed update
could interrupt the agent. Restart the agent without a banner: Box Core allows only one attempt
to start a run in each `box` process.

**Cost.** A crash or a failure to start the banner disables it for the rest of the run.
A stuck update can leave the banner frozen. `box` shows recent errors after it restores the
terminal. Temporary output delays do not stop the agent.
Final output waits are limited so a blocked terminal cannot hold up normal shutdown indefinitely.
A disconnected terminal still stops the run.

<a id="policy-off-keeps-the-forbids-box-writes"></a>
### Policy off turns off what the operator adds, and keeps each forbid `box` writes for every box or to protect itself

Policy off installs one permit for every operation and each forbid that `box` writes for every box
or to protect itself, such as those on the box home, the folders `box` is installed in, the
profile, and `.box`, so the Shell and Monty cannot plant rules for a later run. Everything the
operator adds turns off: rule files, and the forbids of a profile's `[filesystem] deny` and
`deny_write`. Policy off works only while the banner shows it.

**Rejected.** One permit in place of the whole policy: the Shell could then append to the
profile's rule files. Keeping what the operator adds, such as the `deny_write` forbids that let
`box` accept a program under a write grant: policy off is the operator's switch for their own
choices.

**Cost.** While policy is off, the Shell and Monty can read a `deny` path and change a `deny_write`
folder, including a program a later run runs. The agent's sandbox still holds both.

<a id="box-run-takes-no-option-values"></a>
### A run's grants and rules are what the profile says, so `box run` sets no input

`box run <profile>` takes no input value, and none of its
[flags](../../cli/cli.md#box-run) changes a grant or a rule. An
operator's value lives only in the profile's `[options]`, where `box profile create --option`
writes it. `--box-id` picks only the box: `name`, `box_dir`, `${{ box }}`, the records path, and
so the history that `when temporal` rules read. When `box` shows its banner, it sets the agent's
`TERM` and `COLORTERM`.

**Rejected.** `box run --option name=value` for one run: tried first, and two runs of one profile
could then get different grants or rules with no record in the profile.

**Cost.** To try another value, the operator edits the profile or creates a second one. With the
banner, a `TERM` or `COLORTERM` that the profile sets does not reach the agent.

<a id="the-workspace-is-the-current-directory"></a>
### The workspace is the current directory, and `[project] access` decides the grants `box` adds there

`box run` sets `[agent] workspace` to the current directory, resolved through links. The
profile's `[project] access` decides the grants and permits that `box` adds there
([project access](#project-access-is-one-profile-level)), and the filesystem entries and policy of
the packs and the profile add to them. It refuses a workspace that is the home
or holds it, and a workspace that holds the run directory or lies inside it.

**Rejected.** A workspace key in the profile: one profile then serves one project. Read and
write on the workspace in every run: the earlier answer, replaced because no profile could take
it away.

**Cost.** The operator must start `box run` in the project root. A second directory needs a grant
in the profile.

<a id="project-access-is-one-profile-level"></a>
### The profile's project access is one level that sets the project grants and permits `box` adds

`[project] access` is `"none"`, `"read"`, or `"write"`. `box run` gives the agent, each tool, and
each detected stdio server the project in `filesystem.read` for `read`, and in `read` and `write`
for `write`, and writes the `project_*` permits to match. Only a profile holds the table, and a
profile without it gets `none`. A filesystem entry in a pack or the profile that names the
project still applies on top of it. `box profile create` writes the value that the picked policy
starter's `[policy] project` names, and keeps a value the profile already has.

**Rejected.** A list of `fs:*` actions: containment grants a folder none, read, or read and write,
so `["read", "write"]` without `delete` promises a limit that the agent's own file tools do not
keep. Refusing a pack's entries in the project: a pack can need part of the project, and the
operator picks the packs.

**Cost.** `write` gives the agent, each tool, and each detected stdio server direct read and write
on the whole project, which no `fs:*` rule checks
([file rules](#file-rules-decide-only-the-shell)). A pack can give more of the project than
`access` says. A profile without the table, such as one created before it, gets no project access
until the operator adds it. Without native filesystem policy, a `forbid` on delete or move alone
holds only for the Shell and Monty.

<a id="file-rules-decide-only-the-shell"></a>
### Without native filesystem policy, a file rule decides only the Shell and Monty, and `[filesystem] deny` keeps a path from every process

`box` selects Box Core's native filesystem policy only when the profile opts in, and it writes no
filesystem entry from an `fs:*` rule. Without native checks, an `fs:*` rule decides only the Shell
and Monty: the agent's own file tools, each tool, and each local MCP server reach their grants
with no decision and add no history. `[filesystem] deny` keeps a path from every process, and
`[filesystem] deny_write` keeps a folder read-only for every process that writes it. Revisit this
when every macOS release that `box` supports has native checks and the signed release carries the
Endpoint Security entitlement.

**Rejected.** Native checks for every run: they extend file rules to the supported operations of
each process that selects them, but they need macOS 27 and an entitled build, so runs on macOS 26
and earlier fail. Filesystem entries derived
from `forbid` rules: they cover literal paths, but they need a Dogwood scanner
([no parser](#box-never-parses-the-policy-language)), and no list states a delete-only, a
pattern, or a history rule.

**Cost.** Without native checks, a rule that refuses only deletes or moves, matches a pattern, or
reads history holds only for the Shell and Monty, and the user docs say so where they show a file
rule ([file-rules.md](../../cli/file-rules.md)).

<a id="file-times-follow-the-user-id"></a>
### A box sets file times unless `box` runs as root, and only the profile changes that

`box run` writes Box Core's `file-attributes = true` when its effective user ID is not 0, and
`false` when it is 0 (`Host::root`). A profile's top-level `file-attributes` replaces that default.
A pack refuses the key. On macOS the switch also lets the workload set set-ID bits, move a file's
group, and store an ACL in each write root ([Box Core](../../user/security.md#file-attributes-on-macos)).
For a non-root box, a set-user-ID file runs as the operator, who already runs the workload's code.
For a root box, it runs as root on real disk. Box Core accepts the switch at user ID 0 and leaves
the choice to the writer of `box.toml`.

**Rejected.** Off by default for every user: `touch`, `cp -p`, and `proper-lockfile` fail, and
Kiro CLI waits about 15 s at each start. A pack key: a pack that the operator did not write could
then turn the switch on for a root box. A `box run` flag: the choice belongs to the profile, so
each run of it is the same.

**Cost.** Each non-root macOS box carries the residual in every write root, the workspace included.
Part of it reaches other accounts on the Mac. A set-group-ID file with a group the operator holds,
such as `admin` or `staff`, runs with that group for each local account that can reach and run it.
An inherited ACL on a write root can give every local account access to what the operator writes
there later, outside the box. Neither is an escape from the box, and both need a second account on
the Mac. The default stays on because a single-user Mac has no such account, and because
`limitations.md` tells the operator how to find and remove both. A root operator who needs file
times sets the key in each profile.

<a id="file-watching-is-a-key-of-each-table"></a>
### File watching is a key of each process table, and a pack can set it

`file-watching` passes through to Box Core's key of the same name in `[agent]`, a `[tool.<name>]`,
or a stdio `[mcp.<name>]`, and `box` writes it only where a table sets it. An agent pack or a tool
pack sets it in its `[run]`, and the profile's table replaces the pack's value. On macOS the
process can then read FSEvents, which discloses names of paths it cannot read
([limitations.md](../../cli/limitations.md#file-watching-on-macos)).

**Rejected.** A top-level key, as for `file-attributes`: Box Core decides it for each process,
because the disclosure reaches past the process's own grants.

**Cost.** A pack that sets the key discloses names for its program in every profile that names
the pack, and the profile does not say so. The operator can see the key in `box profile show --full`
or read Box Core's startup line in the terminal run's [log](../../cli/files.md#profile-storage-and-runs).

<a id="only-a-profile-turns-off-a-tools-network-containment"></a>
### Only a profile turns off a tool's network containment

A profile's `[tool.<name>.network] contain_egress` passes through to Box Core's key of the same
name, and `box` writes the table only when it holds a value. The load refuses `[network]` and
`[tool.<name>.network]` in every pack. With `false`, Box Core gives the tool's sandbox direct
egress, and every program that the tool starts shares it. The gateway carries only HTTP and HTTPS,
so this is the only way for a client such as `git` over SSH to reach its host.

A profile is the operator's own file, and a pack is the work of its author, such as `box` for the
shipped packs. `contain_egress = false` takes the tool out of policy: it reaches any host, the
agent picks its arguments, and Box Core records one `egress:native` entry for each start and no
decision for each connection. A pack cannot write `policies`, so a pack that could turn policy off
for its tool would hold more than a pack that adds a rule. The operator makes that choice, in the
file that they read.

**Rejected.** A tool pack's `[network]`, and any pack's `[tool.<name>.network]`, as a pack's
`[mcp.<name>.network]` can: the choice then comes in through `packs`, changes when the pack
changes, and the profile does not show it. A flat key in the tool table, such as
`contain-egress`, or a top-level list of tool names: either one is a second spelling of Box
Core's table for `box` to translate.

**Cost.** A tool that needs direct egress, such as an SSH `git`, works only after the operator adds
the table to each profile, and the operator must know the tool's table name. A pack's
`[mcp.<name>.network]` still sets the same key for an MCP server, so a pack can do for a server
what it cannot do for a tool.

<a id="a-profile-can-name-launch-directories"></a>
### `box` creates no file in the workspace, except an empty `.box` on Linux

`box run` leaves the workspace as it was, apart from what the agent writes, and apart from the
empty `.box` that a Linux run creates ([Linux](#box-supports-macos-only)). The state that an
agent keeps between runs, such as its configuration directory and its temporary files, goes in
[storage](#storage-is-one-directory-per-profile-and-workspace).

**Rejected.** `[launch] directories`, which created one-name directories such as `.codex-home` in
the workspace: tried first, and each directory that a run started in got new folders.
`<workspace>/.claude-config` and `<workspace>/.tmp` failed the same way.

**Cost.** A tool pack's `CARGO_HOME`, `CARGO_TARGET_DIR`, or `npm_config_cache` are paths in
the workspace, so that tool writes there. A tool's `TMPDIR`, which `box` sets, is its own
folder `tool-tmp/<tool>` in the run's directory, beside the box folder, emptied when the run
starts. So it adds nothing to the workspace, and neither the agent, another tool, nor another run
can read or change a tool's temporary files. The agent and the tools still share the workspace.
**Updated:** 2026-11-08.

<a id="storage-is-one-directory-per-profile-and-workspace"></a>
### The profile is the unit of isolation, so the state that a box keeps between runs is one folder per profile

Each profile gets one storage folder, `~/.strands/box/storage/<profile>/default/`, for the agent's storage,
the MCP launcher caches, and each tool's state in every workspace the profile runs in. To keep two projects apart,
the operator runs them with two profiles. When a need appears, an operator-selected namespace for
each project can come beside `default`. [isolation.md](isolation.md) states the model.

**Rejected.** One storage for each profile and workspace, which shipped first: it isolates
projects by default, but the agent's settings, skills, and memory do not follow the operator to
another project or a renamed folder. A project scope for only some state, such as launcher caches:
a hook planted in shared agent storage runs in the other project and reaches its tools there
([isolation.md](isolation.md#why-no-project-scope)).

**Cost.** A box in one project can read and change the settings, hooks, instructions, memory,
sessions, and cached server code that the profile's boxes use in every other project. Two profiles share no
setup, so an operator who isolates projects keeps each profile's setup apart.

<a id="an-agent-gets-a-private-configuration-folder"></a>
### An agent's configuration folder is private to the box, and the host's folder is never granted

An agent pack points the agent at a folder in storage, such as `CLAUDE_CONFIG_DIR` for Claude Code,
and copies into it only what the pack names ([copies](#a-copy-belongs-to-the-box)). The agent
reads and writes all of its state through that one folder, so `box` grants no part of the
operator's own folder, such as `~/.claude` or `~/.claude.json`.

**Rejected.** A grant on the host folder. A grant on all of it is too wide: the folder holds the
login, the transcripts of every project, and settings that later host sessions run, such as hooks,
and the agent needs write access to save its state. A grant on only the parts a pack names is too
narrow: the agent writes all of its state through the one folder, so it cannot save it.

**Cost.** The box starts from the pack's copies, not from the operator's live folder. A setting
that the pack does not name stays on the host, and a change the agent makes in the box stays in
the box.

<a id="a-copy-belongs-to-the-box"></a>
### A copy of a host file is made once, and then belongs to the box, unless its row syncs or its pack changes or adds values

`box run` copies a `[[storage.files]]` source only when its target is absent, then rewrites only
`[[storage.files.set]]` values. A row with [`sync = true`](profile-language.md#sync) is the
exception: each run compares each host file and its copy with what `box` last copied, and a host
file that changed replaces the copy, so the host wins when both changed. A copy that only the box
changed, a file only the box has, and a file the host no longer has stay as the box left them. A [`fill`](profile-language.md#fill) row adds each `keep` value that
the copy lacks on each run, and an [MCP import](profile-language.md#mcp-servers) fills only an
absent section, because the agent creates its own configuration file before either applies. A
value or section that the copy holds, an empty one included, and unrelated settings belong to the
box. The one exception is an empty MCP section below the top level, such as a project's own
section, which the agent writes by default, so it counts as absent. Copies never write back to the host.

**Rejected.** A fresh copy on each run: it discards edits and state that resumed sessions use.
Sync on every row by default: a pack's row for state the box adds to, such as Claude Code's auto
memory, would lose it, so a row opts in. A size and modification time check in place of content
hashes: it misses an edit made in the same clock tick at the same size, and the copies are small.
The absent-file rule for MCP, tried first: agent-created files prevent later import.
Write-back to the host: a compromised box could change other projects' configuration.

**Cost.** A copy without `sync` drifts until its target or MCP section is removed. Storage is
one folder per profile, so such a copy made in one project serves every project, and a host change
does not reach a new project. A sync row loses a box edit when the host file changes. The record
of what `box` last copied sits in the storage root, which no grant reaches, and a missing or
broken record keeps each copy as the box left it. Section deletion permits reimport. A `fill` value that the box removes comes back on
the next run, and a host change to a value the copy holds does not reach it. Concurrent runs of a
profile share storage, in any project, so the last run supplies `set` values. Agents can race an
import; stop them first. MCP grants still come from trusted sources, so stored edits grant
no access and external changes can break stored servers.

<a id="the-packs-decide-what-is-copied"></a>
### The packs decide what is copied and what changes in the copy, and a copy never reads a place a box can write or a path that a secret source protects

A pack names each host file that it copies, the parts of that file that come into the box, and
each value that the copy needs changed to work in the box. So a pack brings in its agent's
instructions, skills, and preferences, and leaves out a login file and each part that holds a
credential. `box` refuses a source, or a link out of one, that reaches a place a box can write
([profile-language.md](profile-language.md#copies) lists them). `box`'s own packs are the one
place in `~/.strands/box` that a copy reads, so a shipped pack can copy a file of its own, such as
its agent's guidance. A run cannot write them
([trusted directories](#a-run-cannot-write-what-a-later-run-trusts)), and the exception does not
apply when the workspace, storage, or a write grant holds them. It also refuses one that meets a
`reads` or `deny` path of a declared secret source, because `box` makes each copy and link before
Box Core checks a grant. The exception for `box`'s own packs does not lift that refusal.

**Rejected.** A list of credential paths in `box`: it grows with each harness and tool and never
covers them all, and packs are already trusted like the profile. No link out of a source: a skill
that a tool installer links into `~/.claude/skills` then goes missing in the box without an error.

**Cost.** A pack that copies a credential, as a file or as a part of one, puts it in the box. A
link that the operator places in a copied folder, to a folder that holds a credential, is followed.

<a id="imported-hooks-are-rebuilt-on-each-run"></a>
### A hook is a command, so each run writes the imported hooks from the host file and permits each script

A hook is a command that the agent starts in the box. A command needs two things that a copied
value does not: a form that the box can run, and a policy permit for what it reads. So a
[`[[storage.hooks]]`](profile-language.md#hooks) row is not a `[[storage.files]]` copy. Each run
reads the host file once, keeps each hook whose command runs one script (`SCRIPT`, or `sh`,
`bash`, or `zsh` with `SCRIPT`), writes it in the form that the pack's `set` rows state, with the
script's real path, and generates one `fs:read` permit for that path. The permits and the hooks
come from the same read of the host file, so the copy holds exactly the hooks that this run can
run. A row whose `when` is false writes none. An inline command, a hook that `only` does not
select, a field that the row does not name, and a script in a place a box can write are each
refused and listed by `box run`, with the reason.

The pack states the layout: where the file holds its hooks, which fields a hook keeps, the form of
the imported command, and the host's off switch. The code of `box` holds the checks and no
harness's layout, as for `[[mcp-servers]]` ([`box` knows no agent](#box-knows-no-provider)). A new
harness needs a row in its pack.

**Rejected.** Copying the hooks with the other settings, through `[[storage.files]] keep`: the copy
holds the host's commands as written. A script path there has no permit, because no table declares
one, and `box` has checked no command in it. A copy made once also does not follow the host file,
and a permit must. A reader for each harness, selected by `kind`: each new harness then needs code
in `box`. A `read_file` grant for each script, with a form such as `bash <script>`: the shell alias
reads the script inside the box, so no policy decision covers the read. With a form such as
`bash -c ". <script>"`, the box's shell reads the script, the read is an `fs:read` decision, and
the generated permit is the only authority for it. Rewriting a host command into `bash -c "<command>"`: text that
the harness substitutes into the command becomes code. `box` puts only a checked script path into a
`set` value. Quoting the script path: the path is one word only when each shell that reads it agrees
on the quoting. `box` refuses a path that holds a character outside letters, digits, and `/._-+@,`.
Granting read on the folder that holds the scripts: it exposes every file there, and a link at that
folder widens the grant to the link's target. A hook as a guardrail: the agent can change its own
settings during a run.

**Cost.** A hook that runs inline text, pipes into a program, or passes arguments does not run. A
script whose real path holds a space or a quote does not run. A hook that runs a script runs it in
the box's shell, so it gets its stdin but not the variables that the harness sets for a hook, and a
program it starts reads no stdin. A `set` form that reads the script with `.` gives the script no
`$0` of its own. The agent can read each imported script, and a secret written in
one, because the permit is for the whole box. The shell alias forwards every byte of stdin, and the
box feeds the command only the first `[limits] shell.max_stdin` bytes, 64 KiB by default, and
discards the rest. Past it a hook that reads all of its event waits until its caller stops it, because
`shell.timeout` is `false` by default, or fails at the shell timeout when the profile sets one that is
shorter than the harness's hook timeout. A hook that
writes its event with a plain command, such as `cat > file` or `wc -c`, needs only `shell.max_stdin`
raised. A hook that holds the event, such as `x=$(cat)` or `jq`, or that redirects a loop or group,
such as `while read ...; done > file` or `{ cat; } > file`, is also bound by `shell.max_output`, 64
KiB by default, because the shell captures that output first, so the profile language exposes both
keys: with only `max_stdin` raised, `x=$(cat)` reads empty and `jq` fails. The run replaces the
value at the first key of the row's `key`, so a hook that the agent writes there in a box is gone on
the next run. Every other value in the copy stays, such as a plugin or a status line command, and so
does a hook in a project's own settings file, which `box` does not rewrite. A profile is one trust
zone, so while two runs share the copy, a live run can see a hook that the other run's agent wrote.
A field that a row drops has no effect in the box. Each script runs in the box's shell, so a row
states the one shell name that a hook can hold, and a hook that names another shell is refused. A `set` form with separate arguments needs a harness that honors it. The writable-place
check knows only this run's workspace and this profile's write grants, so a script in another
project's folder is imported, and that project's box can change it. A host file that sets the row's
`disable-key` reaches the copy with the option off too, because the key only takes hooks away.

<a id="a-run-cannot-write-what-a-later-run-trusts"></a>
### A run refuses write grants over `box`'s trusted directories

The protected roots are the box home (`BOX_HOME`, else `~/.strands/box`), which holds each collection in `external/`, `~/.strands/box` when `BOX_HOME` moves
the box home, `~/.local/bin`, and the directories of `box` and its shipped packs. `~/.strands/box` stays
protected because `install.sh` keeps the installed `box` in `~/.strands/box/packages`, and a later run of
that `box` trusts it.
`box run` resolves links and refuses overlapping write grants, except within the run's storage
directories and each tool's storage, and within a launcher cache on the servers that its launcher
starts. A write grant over `~/.strands` covers the protected box home
and is refused. Other Strands tools can receive write grants for their own subfolders.
It also refuses programs under write grants: existing absolute `command` files (except the
arguments of [a detected server that no profile extends](#a-detected-servers-arguments-are-not-programs)),
`exec` entries, `PATH` directories, and an `exec` folder that holds a write grant. Containment denies `<workspace>/.box`; policy forbids cover it, each box home outside the run's storage directories and each tool's storage (so each launcher cache too), the resources directory when it lies outside every box home, as with `BOX_RESOURCES`, and each other protected root outside every box home, such as `~/.local/bin` and the install root of the running `box`, so an operator permit cannot let the Shell or Monty change a root that no write grant may reach. They cover only the protected roots: a program, an `exec` entry, a `PATH` directory, and a source file are refused as write grants but get no forbid, so an operator permit reaches them.
A program inside a `deny_write` folder passes when every process that holds the write grant has that folder in its `deny_write`, as a profile's `[filesystem] deny_write` gives each of them ([below](#an-agents-deny-write-folder-is-closed-to-the-shell-and-monty)), so a tool that can write it without one still refuses the run. `box` adds forbids on `fs:write`, `fs:delete`, and `fs:move` for each `deny_write` folder, as it does for `.box`, forbids moving or deleting each folder between it and its write grant, so its path cannot change, and drops a `deny_write` folder that no agent write grant reaches.

**Rejected.** The `deny` entries alone: the Strands Shell and Monty run outside the cage, so only
the policy governs them. Protecting only `BOX_HOME` when it is set: a box could then write the
installed `box` that the operator runs next. Leaving launcher caches out of the forbids, or letting
another process's write grant reach one: an operator permit or such a grant then lets the Shell, Monty, or the agent
put code in the cache that a later run's server runs with its keys.

**Cost.** Tools can run agent-written files, so a tool grant is an agent grant. An outside process
can replace a checked directory with a link between the check and containment. The target of a
link in `~/.strands/box/packs/` or inside a collection remains unprotected. The operator keeps it outside locations a
workload can modify, because each run reads it again.

<a id="an-agents-deny-write-folder-is-closed-to-the-shell-and-monty"></a>
### A profile's `deny` and `deny_write` reach every process, and the Shell and Monty

`box` adds each folder in a profile's `[filesystem] deny_write` to the `deny_write` of every
process whose write grants reach it: the agent, each tool, and each stdio MCP server. Box Core keeps
the folder read-only there, and `box` forbids the Shell and Monty to change it, because they act for
the agent outside the cage. A program in the folder runs only when every process that can write the
folder holds it. A path in `[filesystem] deny` goes to the `deny` of every process, and `box`
forbids the Shell and Monty to read or change it. Both lists only take access away, so neither can
widen what a process reaches.

**Rejected.** A `deny_write` on each process alone, the first form: `[project] access = "write"`
gives each tool and detected MCP server the workspace, so each needed the list, and a new server
made the next run refuse. A pack that sets the list: the folder to close is the operator's choice
about one project, and a pack reaches every profile that names it. `[project] deny_write`: a folder
to close can lie under a write grant outside the project, such as a tool's cache. A profile-wide
`read` or `write`: it would hand each path to every tool and MCP server, including servers that `box`
imports, so a grant stays on the process that needs it.

**Cost.** In a profile, `[filesystem]` is every process; in an agent or tool pack, it is that
pack's own process. An installer cannot write a listed folder. Policy off lifts the forbids for the
Shell and Monty, so they can then change a program in the folder that a later run runs
([policy off](#policy-off-keeps-the-forbids-box-writes)). A hard link in a writable folder
still changes a file in it.

<a id="a-detected-servers-arguments-are-not-programs"></a>
### A run does not check the arguments of a detected server that no profile extends as programs

An unextended detected server gets the workspace grants that `[project] access` gives, its install-directory reads, the agent's
denies, and any shipped launcher grants. Its arguments are not checked as programs. Extended detected servers keep
file checks on fixed arguments; variable arguments use caller values through Core wildcards.
Hand-written servers keep their command checks.

**Rejected.** Checking every argument path catches planted code but cannot tell it from data,
so it refuses a server pointed at a project database. Freezing host-expanded variable arguments,
tried first, fixes the permitted values but fails when the harness supplies different ones.

**Cost.** The agent can steer a server through workspace files it reads. A planted file that the
server runs can reach its install directories, any launcher grants and, for an extended server,
its added grants.
Wildcard values can name such files too. An embedded variable delegates the whole argument,
including a flag prefix. A literal `${VAR}` can reach the server unchanged.

<a id="a-host-tool-that-trusts-the-workspace-gets-a-warning"></a>
### `box` guards what it runs and reads, and warns about a host tool that trusts what a box writes

`box` guards what `box run` starts or reads
([a run refuses write grants over `box`'s trusted directories](#a-run-cannot-write-what-a-later-run-trusts),
[no file a box can write is an input](#no-file-a-box-can-write-is-an-input)). A host tool that
later trusts files a box writes gets a warning in `docs/cli/limitations.md`, not a guard in `box`
for each tool: `git` hooks, `npm`, `.mcp.json`, `direnv`, and Box Core's `strands-box policy
generate-schema`, which starts stdio servers with concrete arguments from `box.toml` uncontained, in the caller's working
directory, to list the tools that per-tool policy names. Such a tool reads files in many ways
`box` cannot see, so one review of the project covers them all and a guard for each does not.

**Rejected.** A guard for `generate-schema`, such as a skip of each server whose argument names a
file a box can write: the command also trusts the working directory, directory arguments, absent
files, and `HOME`, so the guard covers one path, and it refuses valid servers such as
`mcp-server-sqlite --db-path ./data.sqlite`. A contained `generate-schema`: it needs the policy it
helps write, and it is Box Core's to change.

**Cost.** A host tool run in the project after a run, before review, runs what the box planted.

<a id="a-write-grant-never-picks-the-program"></a>
### A write grant never changes which program runs

When the program that `box` finds lies under a write grant, as written or real, `box` refuses
it and tries no other copy. A `program` input stops the run, and a tool is skipped with the reason.
A grant says what the agent can write, so it never selects the program that runs.

**Rejected.** Trying the next copy, with or without a message: a `write` entry would then decide
which binary runs, and a warning at startup is easy to miss.

**Cost.** A run stops even when a good copy comes later in the search order, until the operator
removes the grant or sets the input.

<a id="no-file-a-box-can-write-is-an-input"></a>
### No file that the profile's box can write is read as an MCP source or a starter source

An `[[mcp-servers]]` source or a starter source never reads a file in the workspace, the run's
storage, `~/.strands/box`, or a write grant of the profile's box, as written or real. What a box writes
then never chooses a later run's servers, permits, or provider. So neither the project's
`.mcp.json` nor the box's agent configuration in storage supplies MCP declarations or a starter
answer. Import reads stored configuration only to preserve its settings, insert an absent section,
and report differences from the current import, without changing declarations or permits
([profile language](profile-language.md#safety-rules)).

**Rejected.** Reading the project's MCP file: a repository's servers would come into the box with
no setup, but a prompt-injected box could then choose the servers, the programs, and the hosts of
the next run. A project file could become an input only if the box is denied write access to it.

**Cost.** A server that a repository ships in `.mcp.json` does not come into the box, and nothing
brings it in yet. Other host files that `box` reads, such as a program's `#!` line, have no such
check, and [the trusted-directory check](#a-run-cannot-write-what-a-later-run-trusts) refuses a
program under a write grant. The check knows only this profile's write grants: a box of another
profile that can write `~/.claude/settings.json` can choose what this profile reads. At create,
the starter check also knows only the write grants that it can fill before the answers
([detection](detection.md#what-detection-never-reads)), and detection reads a file under any other
grant. If detection refused every source for such a grant, the operator would answer each question
that the source answers.

## Commands

<a id="removing-state-never-starts-a-box"></a>
### A command that removes state never also starts a box

`box clean <BOX_ID>` removes one run directory, and `box clean --all` removes every run
directory whose box is not running. Neither starts a box or takes a profile. A running box keeps
its run directory, because its configuration and records are in it. `box clean <BOX_ID>` refuses a
running box before it asks. `--all` keeps each running box and names it.

**Rejected.** `box run --clean-up claude`, which cleaned up and then ran: tried first. One command
that removes old boxes and starts a new one reads as two commands. `box run --clean-up
[--box-id <BOX_ID>]`: tried next. A flag on `run` reads as a way to run, and it removed running
boxes.

**Cost.** `box clean` cannot stop a box, so the operator exits it first. A box counts as running
while its `box run` process lives, so an agent that outlives a killed `box run` is not kept.

<a id="reset-with-no-name-removes-every-profile"></a>
### Each `box profile` removal command removes one kind of state, by name or `--all`

`box profile clean` removes the boxes that a profile owns, `box profile reset` removes its storage,
and `box profile delete` removes the profile with its boxes and its storage. Each takes profile
names or `--all`, and refuses when it gets neither. A box belongs to one profile and storage is
keyed by the profile name, so `delete` removes all three together: a later profile with the same
name then cannot pick up the old boxes or storage. Each command refuses, and removes nothing, when
a box it would touch is still running.

**Rejected.** `reset` with no name removes every profile: one missing name deleted everything.
`delete --all` removes only the profiles that `box` can list: a folder that lost its `profile.toml`
stayed, and the next `box profile create` refused it.
One `box clean` for boxes beside `box profile delete`: two commands then removed boxes.

**Cost.** Each command holds one open file for each box until it finishes. A box that starts after
the last check and before the removal is not held. `delete --all` removes the whole profiles
folder, so an entry there that is not a profile goes too.

<a id="box-asks-only-at-a-terminal"></a>
### A starter answers from the host first, and `box` asks only at a terminal

A starter first answers what the agent's host settings decide, at a terminal and without one
([detection](detection.md)). `box` then asks only when stdin and stderr are terminals. With no
terminal, `box profile reset` and `box clean` refuse unless the operator gives
`--no-ask`, and a starter takes defaults or stops with the flag that answers
([starters](starters.md#without-a-terminal)). The policy question has no default there, so it
stops `box` until `--policy` answers it. A profile that runs the agent the way the host runs
it is worth more than one script writing the same profile on every machine.

**Rejected.** Remove without asking when there is no terminal: a script could then delete a
profile by accident. Detection only as the prompt's default: the operator would confirm each
detected answer at a terminal, but a script would then get a different profile than a terminal on
the same host. Earlier this entry rejected a starter that answers before it asks, because only a
prompt could name a provider; a starter's choices now name it.

**Cost.** One script writes different profiles on two hosts whose agent settings differ, and no
one confirms the detected answers. A script that removes state passes `--no-ask`, and a script
that creates a profile names each answer that has no default and that the host does not decide,
and always names `--policy`.

<a id="the-guide-for-a-coding-agent-is-a-command"></a>
### `box help` points a coding agent at `box help agent`, which prints the path of the shipped guide

A coding agent that meets `box` runs `box help` or `box --help` first. The first line of that help
is "Coding agents: run `box help agent` before you create or change a profile." An operator can
give the same pointer in one sentence, before a profile exists and after: "Run box help agent and
follow it to create a profile", or "to update profile `<name>`".

`box help agent` is a help topic, not a command with flags. The guide is one file,
`editing-box-profile.md`, that ships in the release beside the packs. The topic prints on
standard output the path of that file and a few facts that the agent needs before it reads the
guide: the version of `box`, the Box home, the profiles folder with the profile names, and the
folder of the shipped packs. The agent reads the file with its own file tool, in parts. The text
matches the installed `box`, because the guide and the binary are in one release folder. The
topic writes no file and makes no folder, and it fails when the release holds no guide.
Profile creation writes no copy of the guide, and `box profile show` and `box run` write none.
A copy that an earlier version wrote into the Box home or into a profile folder stays there, and
no command reads it.

`box help <command>` prints the same bytes as `box <command> --help`. `box` adds its own `help`
command at each level, because the `help` command that clap adds takes no topic.

**Rejected.** Writing the guide into the Box home: a help command then writes into the
configuration that a run trusts, and it needs a marker line to tell its own file from the
operator's, and link checks before each write. A separate `box profile guide` command, or a
top-level `box guide`: it is one more command, and an agent runs `box help` first, so it finds a
help topic without a hint from the operator. The guide text on standard output, with a topic
argument for one section: the whole guide is longer than some agents show from one command, and
topics add a second surface to keep aligned with the headings. A copy in each profile folder:
each copy needs a refresh, and no copy exists before the first profile. A skill: each agent has
its own skill format and location, and an install step comes before the first use. Point the
agent at the repository: it holds source and design pages, and it can differ from the installed
version.

**Cost.** The installer and each packaging script name the guide file, and an installer older
than this entry refuses a release that holds it. The guide is outside the Box home, so an agent
that asks before it reads outside its project asks for one more folder. Each help page of `box`
starts with one line that a person does not need. The guide repeats rules that `docs/cli/` also
states. Tests keep the parts a parser or the command line can check aligned, and review keeps
the rest.
