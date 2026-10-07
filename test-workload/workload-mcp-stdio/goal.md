# Workload: a stdio MCP server the agent starts itself

The project directory is `{{PROJECT}}`. An MCP server named `demo` is already
configured for you. It exposes one tool, `echo`, which returns its `text`
argument prefixed with `MCP_ECHO:`.

Do all of this, in order:

1. Call the `demo` server's `echo` tool with the text `hello-mcp`.
2. Write the tool's reply, exactly as returned, into `mcp-result.txt` in the
   project.
3. Reply with that same string.

Do not reimplement the tool yourself: writing the expected string without calling
the server fails this case, because the server records every call it receives.
Touch no path outside `{{PROJECT}}`.

## Before you finish

Work through the steps above in order and actually run each one. Then check that
every file the steps name exists and is non-empty, and if one is missing, run that
step again before you reply. Do not report success for a step you did not run.
