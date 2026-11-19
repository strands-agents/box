# Feature - Path locations

## Overview

Today a policy can only point at a directory by spelling out its path. This design lets you give a
directory a name in `box.toml`, and write the policy against that name instead.

```toml
# box.toml
[locations]
project = ["~/src/app"]
```

```text
# policy.dw
@id("project_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.project };
```

The rule says "the agent may write anything in `project`". It doesn't say where `project` is. So the
same policy file works for every project and on every machine. Only `box.toml` changes.

A location is just a name for some directories. It doesn't give the agent access to anything.

## 1. Background

A filesystem rule today checks the path directly:

```text
when { context.input.path like "~/src/app/*" };
```

So if you want "the agent may write its project", the project's path has to be in the policy. A
different project needs a different policy.

That's a problem for any tool that sets up boxes for many directories, such as the new Box CLI.
It wants to keep one policy and run it from whatever project the operator is in. Today it has to
generate the project rules on every run. Those rules aren't in the operator's policy file, so the
operator can't see them or edit them.

Pasting the path into the policy text before Box loads it isn't a good fix. A path with the wrong
characters in it can change what a rule means, so every value would have to be escaped carefully.

## 2. What does the operator write?

```toml
[locations]
project = ["~/src/app"]
caches = ["~/.cache/my-agent", "~/.npm"]
```

- Each key is a name. Each value is a list of one or more directories.
- A name starts with a letter and holds only letters, digits and `_`, so a rule can write
  `locations.my_cache`. A name is at most 64 characters long. Cedar's reserved words, such as
  `if` and `in`, aren't allowed.
- A directory is written the way `context.input.path` spells a path: `~` for the whole home,
  `~/…` below it, and an absolute path elsewhere.
- An empty list is an error, because the name would label nothing. Listing the same directory
  twice in one location is an error too.
- Without a `[locations]` table, every file request carries an empty `locations`, and a policy
  that doesn't mention locations works as it does today.

Box doesn't resolve a directory (D6). When it loads the policy, it refuses one that no path could
match and says what to write instead:

- `/Users/dev/src/app`, under the home: write `~/src/app`.
- `/tmp/work` on macOS, through a symlink: write `/private/tmp/work`.
- `/Users`, which holds the home: add `~` to the list, because files in the home are spelled
  `~/…`.

A directory that doesn't exist yet is fine when the folder it would be created in passes the same
checks, so `~/.cache/my-agent` matches once the agent creates it. A directory Box can't check,
such as a broken symlink, a folder Box has no permission to search, or a file, stops the box from
starting, and the error names the location.

## 3. How does Box decide which locations a file is in?

A file is in a location when its `context.input.path` is one of the location's directories, or
anywhere inside one. That is exactly the rule an author would write by hand (D6).

- **Whole folder names only.** `/work-old/notes.md` is not in `/work`.
- **Same text the rule already sees.** Box compares the text in `context.input.path`, which is the
  path after following symlinks. A request and its recorded response carry the same text, so they
  always agree.
- **A file can be in several locations.** See D5.

Box works this out in one place in the policy code. The Strands Shell, Monty, and the macOS native
filesystem check all go through that place, so they all get locations with no changes of their own.

## 4. What changes in a policy?

Nothing, unless you use it. A policy that never mentions locations works as it does today.

Here's a starter policy that a tool could ship once and use for every project:

```text
@id("project_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.project };

@id("project_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.project };

@id("no_env")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.project && context.input.path like "*/.env" };
```

`context.input.locations` has one true-or-false field for each location `box.toml` declares. A
field is true when the file is in that location.

**Time-based rules.** History records `locations` with each event, so a rule can count events in
one location. This counts every write in `project`, including writes that are also in `docs`:

```text
formerly within 1h ( Box::Action::"fs:write"::response{ input.locations.project: true } )
```

**Rules that work with or without a location.** A starter may want a rule about `secrets` in
boxes that declare it, and still load in boxes that don't. Cedar's `has` does that:

```text
@id("secrets_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations has secrets && context.input.locations.secrets };
```

In a box without `secrets`, this rule loads and matches nothing. Writing `has` says the location is
optional, so Box neither refuses nor warns about it, for a `permit` or a `forbid`. A rule that must
apply leaves out `has`, so a missing or misspelled location stops the box (see D2).

## 5. What does it cost?

For each file operation, Box compares the path with each declared directory. That's a handful of
string comparisons, which is small next to evaluating the policy. We haven't measured it. A box
with no locations does no extra work.

## 6. How do we deliver it?

One PR after this doc. It adds the `[locations]` table, the `locations` field, the startup message
(see limitation 1), docs, and tests:
- A file in a nested folder gets both locations.
- `/work-old` is not in `/work`.
- A misspelled location name stops the box from starting.
- A policy that uses a location stops the box from starting when `box.toml` declares none.
- A rule on a location decides every path the same way as the two `path` comparisons it stands
  for.
- A directory under the home written as an absolute path, one through a symlink, and one that
  holds the home are each refused with the spelling to write.
- A time-based budget on `project` counts writes that are also in `docs`.
- A rule using `has` loads when the location isn't declared, and matches when it is.
- A history from the previous release opens. Its events still count toward budgets that don't name
  a location, and are outside budgets that do (limitation 2).

An existing box doesn't have to be created again. Its history records the new field the next time
it opens, the same way it records any other change to the actions.

Some parts of Box can only change with an approved design. If we accept this doc, we approve these
changes to them:
- A new `box.toml` table, `[locations]`.
- A new field, `locations`, on the five `fs:*` actions. It's an empty record unless `box.toml`
  declares locations.
- What time-based rules see: each `fs:*` event in history records `locations`.
- A newer stored record version for a box that declares locations, as other optional features do.
- In the policy crate, `Operator::with_locations`, which declares the locations and returns an
  error for a declaration Box can't use, and `Operator::locations`, which returns the directories
  as written, which the startup message prints. Two new errors name the location and the
  directory: `PolicyError::UnmatchableLocation`, for a directory no path could match, with the
  spelling to write, and `PolicyError::UnresolvableLocation`, for one Box can't check.

## 7. Key decisions

### D1. The location goes in the request's details, next to the path

In a Box rule, `principal` and `resource` are always the same, and everything about a request is in
`context.input`. For a file that's `path` and `operation`. We add `locations` beside them, so a rule
reads `context.input.locations` the same way it reads `context.input.path`.

`locations` has one true-or-false field per declared location, so a rule reads
`context.input.locations.project`. We first tried a list of names, `locations.contains(...)`.
Time-based rules can't check whether a list holds a name, only whether two lists are the same. So a
budget on `project` would count writes in `{project}` and writes in `{project, docs}` separately,
and a budget `forbid` would let through more than it says. A time-based rule can check one field,
so the field shape doesn't have this problem.

The other option was Cedar's usual way of grouping things, `resource in Box::Location::"project"`.
For that, Box would have to make each file a resource that belongs to its locations. Box decided
early on that every request uses the same resource, and this would undo that for file requests
only. It's more work and lets you write nothing you couldn't write with the field.

### D2. Box checks location names when it loads the policy

If a rule names a location that `box.toml` doesn't declare, the box doesn't start. For example,
with `project` declared, this rule is an error:

```text
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.projcet };
```

Without this check, the typo would load, and the `forbid` would quietly protect nothing. Box already
checks file operation names the same way, so `Box::FsReadOperation::"read_contnet"` is an error
too.

This also covers a policy moved to a box that has no locations. A policy written for `project`
won't start a box that doesn't say where `project` is.

A rule that should work either way says so with `has` (section 4). That's a choice the author makes
for each rule, so the default stays strict.

### D3. A location gives no access

Naming a directory as a location doesn't let the agent reach it. For example, this alone gives the
agent nothing:

```toml
[locations]
ssh = ["~/.ssh"]
```

The agent still needs the directory in its `filesystem` lists and a policy rule that allows the
operation. So a wrong location can make a rule match the wrong files, but it can't reach past what
`box.toml` already grants.

### D4. Box doesn't make the workspace a location by itself

`[agent] workspace` is not a location unless `box.toml` says so. A tool like the Box CLI writes
`project = [...]` when it writes `box.toml`. That way everything a policy can check is written down
in `box.toml`.

We also considered a simpler built-in field, `context.input.in_workspace`, that's true for files in
the workspace. It solves the project case with less work. But caches, storage folders and shared
folders would each need their own built-in field later. Named locations cover all of them.

### D5. A file in two locations is in both

Say `project` is `~/src/app` and `docs` is `~/src/app/docs`. The file `~/src/app/docs/intro.md` is
in both. A rule on `project` and a rule on `docs` both apply to it. If one is a `forbid`, the
`forbid` wins, as it always does in Box.

The other option was to give each file only the most specific location. Then declaring `docs` would
take files out of `project`, and the `project` rules would stop applying to them. With both,
adding a location never changes what an existing rule matches.

### D6. A location is shorthand for two path comparisons

`context.input.locations.project` means exactly
`context.input.path == "<root>" || context.input.path like "<root>/*"`, for each directory listed
under `project`. The directories are written the way `path` spells a path and aren't resolved, so
a location never matches more or less than the rule an author would write by hand. For example,
with `project = ["~/src/app"]`, these two rules match the same files:

```text
when { context.input.locations.project };
when { context.input.path == "~/src/app" || context.input.path like "~/src/app/*" };
```

This gives one way to think about a location. It also means a request and its recorded response
compare the same text, so they always agree.

It costs some spellings. A directory through a symlink, one under the home written as an absolute
path, or one that holds the home would match nothing, so Box refuses it when it loads the policy
and says what to write instead (section 2).

## 8. Limitations

1. **The policy alone doesn't show the paths.** Someone reviewing `policy.dw` sees `project`, not
   where it is. Box prints each location and its directories when it starts, next to the
   filesystem grants it already prints.
2. **A moved location keeps its old events.** Every record and history event still has the full
   path. `locations` is an extra field next to it, holding the names the path was in at the time.
   If a later run of the same box points `project` somewhere else, time-based rules still count
   the earlier events as `project`. In the same way, an event recorded before `project` was
   declared, including by an earlier release of Box, isn't in `project`. So a budget on a new
   location starts counting when the location is declared.
3. **Only file rules.** Containment (the `filesystem` lists in `box.toml`) still uses paths.

## 9. Open questions

1. **The name.** We picked "locations". We avoided "tags", because Dogwood and Cedar already use
   that word for other things.
2. **Denial messages.** Should the message the agent sees when it's refused list the file's
   locations, or should only the decision record have them?

## 10. Later: names for other kinds of requests

The same pattern could name other things a policy checks: a top-level `box.toml` table that maps
names to matchers, and a record of true-or-false fields on the actions they apply to. Both ideas
below are possibilities, not part of this design.

**Credentialed HTTP routes.** `[egress.<name>]` already says which destinations get which secret.
`http:request` could carry one field per egress table, true when Box attaches that table's secret:

```text
forbid (principal, action == Box::Action::"http:request", resource)
when { context.input.egress.model && context.input.method == "DELETE" };
```

The binding still grants nothing. Policy just reads what `box.toml` already declares, so a rule can
say "requests that carry the model key" without repeating its hosts.

**Named destinations.** For hosts with no secret, such as `github`, a `[destinations]` table could
use the same entry syntax as egress `destinations`, with a field on `net:connect` and
`http:request`.

Either one needs its own rules for:
- **Paths at connect time.** `net:connect` sees no path, so an entry with a path prefix can't be
  decided there. Treating it as false would let a `forbid` fail open.
- **Host matching.** Case, `*.` wildcards, and IP addresses.

We'd keep one table per kind instead of a single `[tags]` table. A name that held both paths and
hosts would land on unrelated actions.
