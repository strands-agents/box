# node in a box (`@box/node`)

The `@box/node` pack lets the agent run the `node` that your `PATH` finds. The other JavaScript
packs, such as `@box/npm`, bring it with them. node keeps its npm cache in the project's `.npm`
folder.

## Homebrew

The pack selects the `node` and `homebrew` installation types to find Node's runtime files.
Homebrew's location follows the `node` executable, so you don't need a prefix setting.
See [Root and its steps](../../../docs/cli/packs-reference.md#root-and-its-steps) for the files
each installation type makes available.
