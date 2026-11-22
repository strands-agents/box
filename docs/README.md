# Box documentation

Three guides. For any page, ask which product the reader uses, and whether they need the page to
**use** Box, or to **trust or change** Box.

| Guide | Answers | Reader |
|---|---|---|
| [`cli/`](./cli/) | How do I run a coding agent in a box? | Someone who uses the `box` CLI, with profiles, packs, and starters. |
| [`user/`](./user/) | How do I use Box Core? | An operator or a program that writes `box.toml` and `policy.dw` and runs Box Core directly. |
| [`design/`](./design/) | How does it work, and why should I trust it? | A security evaluator, a contributor, or someone who is curious. `design/cli/` holds the CLI's design pages. |

Each guide documents only its own product.

Technical does not mean design. The reference an operator needs to run Box, the
`box.toml` keys, the commands, and the policy vocabulary, belongs in a user guide. The
reasoning behind those same topics belongs in the design guide.

## External site publication

[`site-manifest.json`](./site-manifest.json) selects the user pages that an external
documentation site publishes. The [site manifest contract](./dev/site-manifest.md) defines its
fields, compatibility rules, stable identities and routes, and link handling.
