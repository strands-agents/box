# pnpm in a box (`@box/pnpm`)

The `@box/pnpm` pack lets the agent run `pnpm`, with the `node` of `@box/node`. pnpm keeps its store
and cache in the project's `.cache/pnpm` folder.

## Troubleshooting

### pnpm 12 stops with `Failed to read pnpm-workspace.yaml`

In a project outside your home folder, pnpm 12 stops this way when the project has no
`pnpm-workspace.yaml` at its root, because it then looks in each folder above the project, which
the box does not let it read there. An empty `pnpm-workspace.yaml` at the project's root lets it
run.
