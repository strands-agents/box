# User page tests

Each `docs/cli/` page below has one reader and one test for what belongs on it. Read the page's
entry before you edit the page, and apply `belongs` to each section you add or keep: a section that
fails it goes to the page that `belongs` names. Change an entry only with the user's approval.

The tests live here, not in the pages, because strandsagents.com publishes the pages and refuses
YAML front matter.

## `cli.md`

**Reader:** Someone who knows which box command they want and needs its usage, its flags, or the output it prints.

**Belongs:** Each command, its flags, and the output a reader acts on, plus the BOX_* variables that box reads and its exit status. What a profile, pack, starter, or policy is goes to its topic page, the files under ~/.strands/box go to files.md, and a fix after an error goes to troubleshooting.md.

## `config.md`

**Reader:** Someone who changes what box does on this computer for every profile, such as the menus that box profile create shows or the activity banner, and needs the tables and keys of config.toml.

**Belongs:** Every table and key of ~/.strands/box/config.toml and of a collection's collection.toml, and what box does without the file. How to build a starter menu or a policy menu for a team goes to starters.md, a key that one profile sets goes to profiles-reference.md, and where the file sits among the other files goes to files.md.

## `file-rules.md`

**Reader:** Someone who wants the details of why a file rule in their policy doesn't stop the agent's own file tools, the tools the box starts, or MCP servers, and what the plans are for that limit.

**Belongs:** What a file rule decides and what it doesn't, how to keep a file from every process with filesystem lists, the rules that no list can match, how to try native filesystem policy, and the plan for making it the baseline. A key's full meaning goes to profiles-reference.md, how to write a rule goes to policies.md, and a fix after an error goes to troubleshooting.md.

## `files.md`

**Reader:** Someone who wants to know where Box keeps its files, where a profile, pack, starter, or policy of their own goes, what Box writes by itself, and what's safe to delete or copy.

**Belongs:** Where each file lives, who writes it, and what it's for, with a link to the page that explains what goes in it. What goes in a profile, pack, starter, or policy goes to profiles.md, packs.md, starters.md, or policies.md. Each command and flag goes to cli.md. A fix after an error goes to troubleshooting.md.

## `getting-started.md`

**Reader:** Someone new to Box who wants Claude Code running in a box in one of their own projects, and who follows the steps in order.

**Belongs:** Only the steps of that first run, Claude Code on Amazon Bedrock, and each Claude Code fact needed to finish it. Install options go to install.md, files under ~/.strands/box to files.md, other agents and providers to profiles.md, the other policies to starters.md, Claude Code's other behavior to resources/packs/claude/README.md, and fixes after the first run to troubleshooting.md.

## `install.md`

**Reader:** Someone who wants to install Box, upgrade it, pick another release, or remove it, usually before or after Get started.

**Belongs:** Installing, upgrading, pinning, and removing box, what the installer puts on the computer, and the installer's variables. Creating a profile and the first run go to getting-started.md, the rest of ~/.strands/box to files.md, the BOX_* variables that box itself reads to cli.md, and how Linux differs from a Mac to limitations.md.

## `limitations.md`

**Reader:** Someone deciding what to trust a box with, for example before turning permission prompts off.

**Belongs:** One section per thing the box leaves to you: what it leaves open, who it affects, and what to check or turn off. A key's meaning goes to its reference page. Install steps go to install.md, and a fix after an error goes to troubleshooting.md.

## `packs-reference.md`

**Reader:** Someone who writes or reads a pack, knows the key or table they want, and needs what it does and which kind of pack may hold it.

**Belongs:** A key or table that a pack writes, and the rules for it. A rarer task goes here too, under the key it uses. A key that a profile writes, and the rules that both share, such as placeholders, when, and the merge, go to profiles-reference.md. A task that most authors need for their first pack goes to packs.md, and a fix after an error goes to troubleshooting.md.

## `packs.md`

**Reader:** Someone who wants to know what a pack is, or to write one for an agent, a tool, or settings that a team shares.

**Belongs:** A section belongs here only if most authors need it for their first pack. Anything else goes to packs-reference.md, profiles-reference.md, or troubleshooting.md, and nowhere on this page.

## `plugins-reference.md`

**Reader:** Someone who writes or reads a plugin, knows the key or rule they want, and needs what it does.

**Belongs:** A key of plugin.toml, and each rule that a plugin, a profile that lists one, and a pack follow. A task goes to plugins.md, the plugins and [secret-source.<scheme>] keys of a profile go to profiles-reference.md, and a fix after an error goes to troubleshooting.md.

## `plugins.md`

**Reader:** Someone who wants the box to read a key from a password manager, or to write a plugin for a vault that Box doesn't ship.

**Belongs:** A section belongs here only if most readers need it for their first plugin. Every plugin.toml key and every rule goes to plugins-reference.md, and a fix after an error goes to troubleshooting.md.

## `policies-reference.md`

**Reader:** Someone who reads or writes policy rules and needs to know how box joins a run's policy, or what wrote the rule that the run history names.

**Belongs:** How box joins the profile's rule files with the rules it writes, and one row for each kind of rule box writes. What a policy is and how to write a rule goes to policies.md. Policy starters and the policy menu go to starters-reference.md. A fix after an error goes to troubleshooting.md.

## `policies.md`

**Reader:** Someone who wants to change what the box lets the agent do, by reading or writing policy rules, and who needs to know which rules their packs and profile already give it.

**Belongs:** What a policy checks, where a run's rules come from (your rule files, the rules box writes from pack and profile settings, and Box Core's own checks), what's in policy.dw, and how to write a rule. Policy starters and the policy menu go to starters.md. Generated rule IDs and how box joins the files go to policies-reference.md. Rule syntax goes to Box Core's policy guide. A fix after an error goes to troubleshooting.md.

## `profiles-reference.md`

**Reader:** Someone who writes or reads a profile, knows the key or table they want, and needs what it does and which file may hold it.

**Belongs:** A key or table that a profile writes, and the rules that profiles and packs share, such as placeholders, when, and the merge. A rarer task goes here too, under the key it uses. A key that only a pack writes goes to packs-reference.md, a task that most users need in their first month goes to profiles.md, and a fix after an error goes to troubleshooting.md.

## `profiles.md`

**Reader:** Someone who has a profile, usually from Get started, and wants to understand it or change it.

**Belongs:** A section belongs here only if most users need it in their first month. Anything else goes to profiles-reference.md, cli.md, or troubleshooting.md, and nowhere on this page.

## `starters-reference.md`

**Reader:** Someone who writes or reads a starter or a policy starter, knows the key they want, and needs what it does and where it goes.

**Belongs:** A key of starter.toml or policy.toml, and the rules for it. The [starters] and [policy-starters] menus in config.toml go to config.md. A task goes to starters.md, a rule in policy.dw goes to policies.md, and a fix after an error goes to troubleshooting.md.

## `starters.md`

**Reader:** Someone who makes a profile with box profile create, or who writes a starter or a policy starter so a team gets one standard setup.

**Belongs:** A section belongs here only if most readers need it to make a profile, to pick the policy it starts from, or to write their first starter or policy starter. Every key of starter.toml and policy.toml goes to starters-reference.md, the keys of [starters] and [policy-starters] go to config.md, writing a profile's rules goes to policies.md, a fix after an error goes to troubleshooting.md, and what one agent's starter asks goes to that agent's README.

## `troubleshooting.md`

**Reader:** Someone whose box run or profile command failed or did something unexpected.

**Belongs:** A section per symptom: a heading that names it, the message quoted, the cause, and the fix. Only messages that don't name their own fix. A limit with no fix goes to limitations.md. A key's meaning goes to its reference page.
