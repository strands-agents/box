# uv in a box (`@box/uv`)

The `@box/uv` pack lets the agent run the `uv` that your `PATH` finds.

## Where uv keeps its files

uv keeps its cache and the Pythons it downloads in your project's `.cache/uv` folder, because the
box cannot write `~/.cache/uv` or `~/.local/share/uv/python`. The commands of the tools that
`uv tool install` adds go in `.cache/uv/bin`. The tools themselves go in `.cache/uvx/tools`, which
uv already git-ignores.

## Limitations

### A command that `uv tool install` adds runs through uv

When the agent runs `uv tool install`, the box doesn't start the new command by its name. The
command, such as `greet`, is a link in `.cache/uv/bin` to a short Python script in the tool's own
folder, `.cache/uvx/tools/greet/bin/greet`, and the script's first line names that folder's
`python`. The box starts a command by its name only when your profile sets that command up, and
`box` refuses to set one up in a folder the box can write, such as your project. Run the command
through `uv` instead:

```text
$ greet --help
strands-shell: greet: command not found
$ uv tool run greet --help
 Usage: greet [OPTIONS] NAME
```

If your profile also has `@box/uvx`, `uvx greet` works too, and runs the copy that
`uv tool install` added. Either way, the command runs with `uv`'s access, and the agent can change
the installed copy, so treat it as project code
([Tools in the box run project code too](../../../docs/cli/limitations.md#tools-in-the-box-run-project-code-too)).
