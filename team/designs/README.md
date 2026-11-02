# Designs

This folder holds the design docs for Box. A design doc explains a feature before we build it: the problem, the direction we're taking, and the key decisions behind it.

There is no template. Write it in whatever shape tells the story best.

## Write it yourself

Design docs should be written by a human, because they're meant to be reviewed by humans. A design is the last gate before we hand the work to AI agents to implement, so we need to understand it deeply. Designs are how we, as owners of this codebase, stay connected to the details.

Please use AI as much as you want while you design: to vet ideas, validate assumptions, run explorations, build prototypes. But write the doc by hand.

## Keep it high level

You don't need to include every detail. A design doc communicates strategy and direction, plus the key decisions and why we made them. It isn't a low-level design. The code is where the details live.

A design doc is a snapshot of what we decided at the time. Once it merges, we don't keep it in sync with the code, so expect it to fall behind. That's on purpose.

## Adding one

Add a file named `NNNN-feature-name.md`, using the next free number, and open a pull request. The review happens on the pull request, and merging it means we accepted the design.
