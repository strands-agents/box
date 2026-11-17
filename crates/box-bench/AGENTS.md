# AGENTS.md: box-bench

`box-bench` is test code. It is not published, and it is not part of the `strands-box` artifact.

- Keep it minimal: use only the standard library, add no automated tests, and add no abstraction for
  a case that does not exist yet.
- Verify a change with a smoke benchmark against a release build of Box, not with `cargo test`.
- The product rules in the root `AGENTS.md` (the interface freeze, the premises, and the doc
  obligations) do not apply here. A change to this crate changes no product code.
