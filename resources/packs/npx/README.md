# npx in a box (`@box/npx`)

The `@box/npx` pack lets the agent run `npx`, and lets an MCP server that `npx` starts download
its package in the box.

## Limitations

On macOS, `npx` from npm 11.19.1 fails with Node 22.22.2 and Node 24.22.1 when it refreshes
its cache lock. npm reports `ECOMPROMISED: Lock compromised`, and the server does not start.
npm 12.2.1 with Node 24.22.1 fails with the same error.
Use npm 10.9.7 with Node 22.22.2 for `npx` servers.
