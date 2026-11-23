# yarn in a box (`@box/yarn`)

The `@box/yarn` pack lets the agent run `yarn`, with the `node` of `@box/node`. It runs Yarn 1, or
the Corepack shim that fetches the Yarn a project's `packageManager` names. yarn keeps its store
and cache in the project's `.cache/yarn` folder.
