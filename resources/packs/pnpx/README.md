# pnpx in a box (`@box/pnpx`)

The `@box/pnpx` pack lets the agent run `pnpx` and lets `pnpx` download packages for MCP servers
in the box.

## Limitations

With pnpm 12, `pnpx` reads `pnpm-workspace.yaml` from your project directory. It does not search
parent directories for a workspace file.
