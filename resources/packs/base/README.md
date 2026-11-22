# Shared agent settings (`@box/base`)

The `@box/base` pack supplies the terminal settings for agents in a box. The shipped agent packs
include it, so an existing profile picks up these settings on its next run.

## Terminal settings

The agent receives `TERM` and `COLORTERM` from your shell, with defaults of `xterm-256color` and
`truecolor` when they are absent. Its starting `PATH` is `/usr/bin:/bin`; another pack or your
profile can change these settings.
