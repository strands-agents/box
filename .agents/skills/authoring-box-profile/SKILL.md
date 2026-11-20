---
name: authoring-box-profile
description: Write or edit a box profile (`~/.strands/box/profiles/<name>/profile.toml`) or a pack (`~/.strands/box/packs/<name>/pack.toml`, or `resources/packs/<name>/pack.toml` in this repository) that runs an agent in a Strands Box. Use when asked to add an agent or a model provider to box, to change what a profile grants, or to fix a profile or pack that `box profile show` or Box Core refuses. Not for Box Core's own `box.toml` or for a Dogwood policy alone (use Box Core's authoring-box-policy skill for a policy).
---

# Authoring a box profile or pack

A profile lists packs in `packs` and sets their inputs in `[options]`. A pack declares inputs in
`[inputs]` and holds the reusable tables. Write a pack that runs one agent in a box on any host,
grants only what the agent needs, and loads clean. Write a profile that holds only the operator's
values and additions.

[`docs/cli/profiles-reference.md`](../../../docs/cli/profiles-reference.md) is the reference for
every profile key and every shared rule, and
[`docs/cli/packs-reference.md`](../../../docs/cli/packs-reference.md) for every key that only a
pack writes. [`docs/cli/profiles.md`](../../../docs/cli/profiles.md) shows the common
profile changes. Read the reference before you write a profile or a pack. This page gives the
workflow and the rules that an agent breaks most often.

## Choose the file

- A change for one operator goes in their profile: a value in `[options]`, a tool table, a second
  project in `[agent.filesystem]`, a credential in `[egress.<name>.secret]`, or a rule in a
  file listed in the profile's `policies`. See
  [What a profile holds](../../../docs/cli/profiles-reference.md#what-a-profile-holds).
- A new agent or provider goes in a pack. A pack that other profiles reuse goes in
  `~/.strands/box/packs/<name>/`, or in `resources/packs/<name>/` when it ships with `box`.

## Workflow

1. **Start from a shipped pack.** Read `resources/packs/*/pack.toml`. An agent pack extends
   `@box/base`. The model for a new agent is in
   [Example: a pack of your own](../../../docs/cli/packs.md#whats-in-a-pack).
2. **Write the header.** Each pack has `[pack]` with `name`, `version`, and `kind`. `name` equals
   the import name: `@box/<folder>` for a shipped pack, the folder name for an operator pack.
   `kind` is `"agent"`, `"tool"`, or `"support"`, as
   [What a pack holds](../../../docs/cli/packs-reference.md#what-a-pack-holds) states. Add
   `engine = ">=X.Y.Z"` when the pack needs a key that an older `box` does not read. See
   [`[pack]`](../../../docs/cli/packs-reference.md#pack).
3. **Pair the agent with a provider.** A provider pack is a `support` pack that holds the route
   to a model host and its `secret.ref`, and declares nothing else. An agent pack (a pack that
   declares `[agent] command`, or extends an agent pack) declares nothing for it either: a
   profile names one agent pack and one provider beside it, and `box` does not check the
   provider.
   A setting the agent needs for one provider stays in the agent pack, behind an `<agent>.host`
   input and a `{ variable, equals }` `when`. See
   [Providers](../../../docs/cli/packs-reference.md#providers).
4. **Declare every input.** Each value from the operator or the host is an
   `[inputs.<full name>]` declaration. Give the name a prefix that is unlikely to clash, such as
   the agent's name. Add an input only when it changes what the box allows or how the box is set
   up. Read a host value with `from = "env:<NAME>"`. See
   [Inputs](../../../docs/cli/packs-reference.md#inputs).
5. **Use placeholders in fields that support them.** Use `${{ home }}`, `${{ pack }}`,
   `${{ storage.<dir> }}`, `${{ agent.<name> }}`, and `${{ inputs.<name> }}`. Do not write a path
   of your own machine.
6. **Put agent state in storage.** Declare `[storage] directories`, and point the agent's
   configuration and temporary directories at `${{ storage.<dir> }}`. Do not write files in the
   workspace. See [Storage](../../../docs/cli/packs-reference.md#storage). To bring the
   operator's own instruction files into the box, add a `[[storage.files]]` row with a `source`
   and a `target` in a storage directory. Never copy a whole file that can hold a credential. Set
   `kind` and name the parts the agent needs with `keep`
   ([Copy only part of a settings file](../../../docs/cli/packs-reference.md#copy-only-part-of-a-settings-file)),
   and use `set` for a value that has to differ in the box
   ([Set a value in the copy on every run](../../../docs/cli/packs-reference.md#set-a-value-in-the-copy-on-every-run)).
7. **Make a profile that uses the pack.** For a shipped agent pack, run
   `box profile create <name> --with <agent>,<provider>`. A short name is the operator's pack in
   `~/.strands/box/packs/<name>` when it exists, else `@box/<name>`. Write `@box/<name>` to name the
   shipped pack.
8. **Check it.** In a project directory, run `box profile show <name>` (each pack, and each input
   with its value and its source) and `box profile show --full <name>` (the same, then the
   `box.toml` and `policy.dw` of a run). Remove each grant in `--full` that the agent does not
   need.
9. **Run it and read the denials.** `box run <name>` prints the path of `records.jsonl`. Read
   each `deny` with the command in
   [The agent can't reach a file or a host](../../../docs/cli/troubleshooting.md#the-agent-cant-reach-a-file-or-a-host), and fix
   it with a filesystem entry, a route, a tool pack, or a rule in a listed policy file.
10. **Repeat steps 8 and 9** until the agent does its task and each `deny` is one you expect.

## Rules that agents break

Each rule links to the section of the reference that states it in full.

- A profile holds no `extend`, `[inputs]`, or `[pack]`. A pack holds no
  `packs`, `policies`, or `[options]`. See [What a pack holds](../../../docs/cli/packs-reference.md#what-a-pack-holds).
- `box` generates rules from profile and pack settings. Put additional rules in files listed
  in the profile's `policies`, for example `policies = ["service.dw"]`. Keep existing list entries.
  Policy paths are literal; relative paths resolve beside `profile.toml`. Keep each file and
  symbolic-link target in that folder or its subdirectories. Use separate copies, not hard links. See
  [Generated policy](../../../docs/cli/policies-reference.md#generated-policy).
- An `[options]` value is literal. It holds no placeholder, it names an input that a pack in the
  chain declares, and it passes that declaration. `box` checks it at the merge.
- An input that reaches a command or a route's host needs `pattern` or `values`.
  [Inputs that reach `command` or a route](../../../docs/cli/packs-reference.md#inputs-that-reach-command-or-a-route)
  lists the fields and the exemptions. Pass free text through `[agent.env]`.
- The value order is: the profile's `[options]`, then `from`, then `default`. See
  [Where the value comes from](../../../docs/cli/packs-reference.md#where-the-value-comes-from).
- Two packs that declare one input agree on `type`. Different defaults or `from` sources are an
  error until the profile sets the value. See
  [Two packs that declare one input](../../../docs/cli/packs-reference.md#two-packs-that-declare-one-input).
- Do not read a credential variable with `from = "env:<NAME>"`. The route's `secret.ref` holds the
  credential, and the box adds it to each request.
- A placeholder goes only in the fields that
  [Which fields take a placeholder](../../../docs/cli/profiles-reference.md#which-fields-take-a-placeholder)
  lists. Every other field is literal.
- In [path fields](../../../docs/cli/profiles-reference.md#paths) for commands, filesystem entries,
  and storage copy sources, the first piece is a placeholder or an absolute path. Each later
  placeholder fills one path component.
- An agent pack finds its agent with a `type = "program"` input that names `program` and, if
  needed, `search`. See [Inputs](../../../docs/cli/packs-reference.md#inputs).
- `when` takes `macos`, `linux`, `${{ inputs.<bool> }}`, or `{ variable, equals }`. One value,
  such as one `command` element, takes it as `{ value = ..., when = ... }`. It applies after the
  merge, so a `when` on a shared table such as `[agent.env]` removes what every layer put there.
  Put it on an entry, one value, or a table that one pack owns. See
  [`when`](../../../docs/cli/profiles-reference.md#when).
- A later layer replaces a whole `command`. To change one flag, write the complete `command`.
  See [Merge order](../../../docs/cli/profiles-reference.md#merge-order).
- Two packs cannot declare the same `[egress.<name>]`, and two packs cannot read the same
  `env://` variable. A profile names one provider.
- An `[egress.<name>]` route with an `env://` `secret.ref` puts the key on each host in
  `destinations`. Two routes of one pack, or of the profile, that read one variable need the same
  `secret.phantom_prefix`, or none on both. A route that
  holds only `destinations` opens hosts that need no credential, with no policy file. See
  [Routes and other hosts](../../../docs/cli/profiles-reference.md#routes-and-other-hosts).
- Box Core expands `${NAME}` in a `command` argument and refuses each name that is not one of its
  telemetry variables. `box` does not check this.
- Mark a filesystem entry `optional = true` when some hosts do not have the path. Box Core refuses
  a grant on a missing path when the run starts.
- A tool comes from a tool pack that names its `program`, and `box` writes the permit that starts
  it. For a program with no shipped pack, write a tool pack. See
  [Tool packs](../../../docs/cli/packs-reference.md#tool-packs).
- A tool pack can ship a Box Core tool grammar in `grammar.toml`. Box Core then decides that
  program's commands as `Tool::<name>::Action::"<action>"`, and `box` permits every action,
  `unmodeled` included. To restrict the tool, write a `forbid` on a grammar action or effect, not a
  `shell:spawn` rule, and pair it with an unconditional `forbid` on
  `Tool::<name>::Action::"unmodeled"`, because a command with one undeclared option is `unmodeled`
  and escapes the first rule. See
  [Tool grammars](../../../docs/cli/packs-reference.md#tool-grammars).
- Give each authored rule a unique `@id` across all policy files. Do not reuse an ID from
  [Generated policy](../../../docs/cli/policies-reference.md#generated-policy).
  `box profile show` refuses duplicate IDs.
- Do not put a program under a `write` grant, and do not grant `write` in `~/.strands/box` outside
  storage. `box run` refuses both.
- Every pack in the chain gets the same trust as the operator's own profile. Do not tell an
  operator to install a pack they have not read.

## When a check fails

Read the message first: most messages name the fix. For a message that does not, see
[A profile has a mistake](../../../docs/cli/troubleshooting.md#a-profile-has-a-mistake).
