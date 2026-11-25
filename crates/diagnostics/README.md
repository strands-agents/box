# `strands-box-diagnostics`

How Box Core writes a message to stderr, and how a reader sorts one back.

## Known limitations

- **A coded line is not proof that Box wrote it.** Processes the box starts share its stderr, so
  any of them can print a line that parses as a Box message. Treat the format as a convention, not
  an authenticated channel.

## What it does

Every Box Core message is one line in the form `<source>: <severity>[<code>]: <text>`, followed by
indented lines that belong to it:

```text
policy: warning[P0201]: dogwood evaluation failed: <reason>; denying
strands-box: note[B0201]: [tool.check] interpreter aliases for configured access:
  alias       /bin/sh -> /usr/bin/dash  (interpreter spelling)
```

A Core crate names its voice once, at its root, and writes each message with `diag!`:

```rust
const DIAGNOSTIC_SOURCE: diagnostics::Source = diagnostics::Source::Policy;

diagnostics::diag!(P0201, "dogwood evaluation failed: {joined}; denying");
diagnostics::diag!(warning, "an internal failure with no code: {error}");
```

A reader sorts each line with `parse`:

```rust
match diagnostics::parse(line) {
    diagnostics::Line::Message(message) => { /* message.source, .severity, .code, .text */ }
    diagnostics::Line::Continuation(_) => { /* belongs to the message above */ }
    diagnostics::Line::Other(_) => { /* not a Box message */ }
}
```

[Message codes](../../docs/user/message-codes.md) explains each code, and
[the decision](../../docs/design/decisions.md#core-writes-stderr-only-through-diag-and-codes-each-kind)
records why every Core message takes this form.

## Public surface

The root exports `Code`, `Kind`, `Severity`, `Source`, `Line`, `Message`, and `parse`; the `diag!`
macro; and the functions it expands to: `emit`, `write`, `text`, and `stderr`. `kind!` is a hidden
helper of `diag!`.
