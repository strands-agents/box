# uvx in a box (`@box/uvx`)

The `@box/uvx` pack lets the agent run `uvx`, and lets an MCP server that `uvx` starts download
its package in the box.

## Limitations

`uvx` uses an installed Python and does not download one. An MCP server that `uvx` starts can read
`uvx`'s installation files and its Python runtimes, but that doesn't give it access to the rest of
`~/.cargo` or `~/.local`.
