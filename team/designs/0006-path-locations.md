# Feature - Path locations

## Overview

Today a policy can only point at a directory by spelling out its path. This design lets you give a
directory a name in `box.toml`, and write the policy against that name instead.

```toml
# box.toml
[locations]
project = ["/Users/dev/src/app"]
```

```text
# policy.dw
@id("project_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.contains(Box::Location::"project") };
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
project = ["/Users/dev/src/app"]
caches = ["~/.cache/my-agent", "~/.npm"]
```

- Each key is a name. Each value is a list of one or more directories.
- A directory is an absolute path or starts with `~/`.
- An empty list is an error, because the name would label nothing.
- Without a `[locations]` table, nothing changes.

## 3. How does Box decide which locations a file is in?

A file is in a location when it's one of the location's directories, or anywhere inside one.

- **Whole folder names only.** `/work-old/notes.md` is not in `/work`. Box already checks paths
  this way (`a_sibling_with_a_shared_prefix_is_not_inside_the_root`).
- **Same path the rule already sees.** Box checks the path after following symlinks, the same path
  that `context.input.path` holds. So a location and a path rule never disagree about where a file
  is.
- **A file can be in several locations.** See D5.

Box works this out in one place in the policy code. The Strands Shell, Monty, and the macOS native
filesystem check all go through that place, so they all get locations with no changes of their own.

## 4. What changes in a policy?

Nothing, unless you use it. A policy that never mentions locations works as it does today.

Here's a starter policy that a tool could ship once and use for every project:

```text
@id("project_read")
permit (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.contains(Box::Location::"project") };

@id("project_write")
permit (principal, action == Box::Action::"fs:write", resource)
when { context.input.locations.contains(Box::Location::"project") };

@id("no_env")
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.contains(Box::Location::"project") &&
       context.input.path like "*/.env" };
```

`locations` sits next to `path` in the request, so time-based rules (the `when temporal` rules)
can use it too, for example to limit writes in the project to 200 an hour.

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

Some parts of Box can only change with an approved design. If we accept this doc, we approve these
changes to them:
- A new `box.toml` table, `[locations]`.
- A new field, `locations`, on the five `fs:*` actions, and a new type, `Box::Location`.
- A newer stored record version for a box that declares locations, as other optional features do.

## 7. Key decisions

### D1. The location goes in the request's details, next to the path

In a Box rule, `principal` and `resource` are always the same, and everything about a request is in
`context.input`. For a file that's `path` and `operation`. We add `locations` beside them, so a rule
reads `context.input.locations` the same way it reads `context.input.path`.

The other option was Cedar's usual way of grouping things, `resource in Box::Location::"project"`.
For that, Box would have to make each file a resource that belongs to its locations. Box decided
early on that every request uses the same resource, and this would undo that for file requests
only. It's more work and lets you write nothing you couldn't write with the field.

### D2. Box checks location names when it loads the policy

If a rule names a location that `box.toml` doesn't declare, the box doesn't start. For example,
with `project` declared, this rule is an error:

```text
forbid (principal, action == Box::Action::"fs:read", resource)
when { context.input.locations.contains(Box::Location::"projcet") };
```

Without this check, the typo would load, and the `forbid` would quietly protect nothing. Box already
checks file operation names the same way, so `Box::FsReadOperation::"read_contnet"` is an error
too.

This also covers a policy moved to a box that has no locations. A policy written for `project`
won't start a box that doesn't say where `project` is.

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

## 8. Limitations

1. **The policy alone doesn't show the paths.** Someone reviewing `policy.dw` sees `project`, not
   where it is. Box prints each location and its directories when it starts, next to the
   filesystem grants it already prints.
2. **A moved location keeps its old events.** Every record and history event still has the full
   path. `locations` is an extra field next to it, holding the names the path was in at the time.
   If a later run of the same box points `project` somewhere else, time-based rules still count
   the earlier events as `project`.
3. **Only file rules.** Containment (the `filesystem` lists in `box.toml`) still uses paths.

## 9. Open questions

1. **The name.** We picked "locations". We avoided "tags", because Dogwood and Cedar already use
   that word for other things.
2. **Changing an existing box.** Box keeps a history whose format comes from the policy's types.
   Does adding `[locations]`, or a new name, to an existing box mean it has to be created again?
3. **Denial messages.** Should the message the agent sees when it's refused list the file's
   locations, or should only the decision record have them?
