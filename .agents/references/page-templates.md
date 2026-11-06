# Page templates

Skeletons for a new page. Copy the one for the content type, and remove each section that the page
does not need. No YAML front matter.

## User guide: how-to or tutorial

````markdown
# <The task, or the thing the operator runs>

<One or two present-tense sentences: what this is and what it does for the operator.>

<One link to the reference that the operator needs next.>

> **Status.** <One line if the contract still changes. Omit it if it is stable.>

## Before you start

<Prerequisites as a list.>

## Step 1. <Imperative>

<One step. The command or the `box.toml` change, then its expected output.>

## Result

<What the operator has now, and how to check it.>

## Troubleshooting

<The likely failures: what the operator sees, the cause, and the fix.>

## See also

<One line for each sibling page, with what it gives the reader.>
````

## User guide: reference

````markdown
# <The surface: `box.toml`, the CLI, or the policy actions>

<One sentence that defines the surface.>

## <One H2 per key, verb, or action group>

| Key | Type | Default | Meaning |
|---|---|---|---|
| ... | ... | ... | ... |

<An example that uses the keys in this section.>

## Errors and exit codes

<"**Exit codes:** `0` when ...; `1` when ...". Name each failure that the operator can see.>
````

Organize a reference page by key, verb, or action, not by task. Organize a how-to guide by the
operator's steps, and link to the reference for the options.

## Design guide: explanation

Use the shape that fits the subject. A page about several parts uses the first skeleton, and a page
about one mechanism uses the second.

### A page about several parts

````markdown
# <The parts, as a noun>

<One or two sentences: what the parts are, and how they relate.>

## <The parts>

- <Each part, by its real name, in one line.>

### <Part one>

<What it is and when it runs. Then what it does for security, and why it's a separate part. One
link to the decision behind each reason.>

### <Part two>

...

## <How the parts fit together>

<A table that compares the parts, and one Mermaid diagram of the main path.>

## See also

<One line for each related page.>
````

### A page about one mechanism

````markdown
# <The mechanism or the property, as a noun>

<One or two sentences: what it is, and what it guarantees.>

## <The problem it solves>

<The tension the design resolves.>

## <How it works>

<Which process does what, on which platform. One Mermaid diagram of the main path.>

## See also

<One line for each related page.>
````

Add a section on residual risk, platform differences, or a rejected alternative only when a reader
would ask for it. Each heading in angle brackets is a placeholder: write the real heading.
