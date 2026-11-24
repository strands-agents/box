# npm in a box (`@box/npm`)

The `@box/npm` pack lets the agent run `npm`, with the `node` of `@box/node`. Add `@box/npm` to
`packs` in your profile.

## Where npm keeps its files

npm keeps its cache in its own folder in the profile's storage,
`~/.strands/box/storage/<profile>/default/tool/npm/cache`, because the box cannot write `~/.npm`.
The agent cannot write that folder, so it cannot change a package that a later install unpacks.
Every project of the profile shares it. `node_modules` stays in the project.

## Limitations

- A package's install script runs as npm, so it can change npm's folder in storage, and every
  project of the profile then installs from what it changed. To start over, delete
  `~/.strands/box/storage/<profile>/default/tool/npm`.
- npm run straight from `node`, such as `node npm-cli.js`, uses `@box/node`'s cache in the
  project's `.npm` folder instead.
