#!/bin/bash
# workload-node — npm and node in their own boundaries: install a dependency from
# the registry, then run a node:test suite.
#
# Codex on Linux fails here intermittently, and the mechanism is NOT yet
# identified. What is observed, and what is not:
#
#   Observed (this suite): some runs of this cell leave test-out.txt without the
#   test summary, and the first line in it is "Could not find
#   <project>/.codex/tmp/arg0/codex-arg0XXXX/apply_patch" — the helper Codex
#   stages under CODEX_HOME and then execs to run a host binary. The model
#   afterwards improvises `rm -rf` on that scratch directory, which CODEX ITSELF
#   refuses ("rm -f style commands are not permitted"): that string is in the
#   Codex binary and in no part of strands-box, so the Strands Shell never sees
#   the command and no policy rule can reach it. That refusal is a downstream
#   symptom, not the cause. Other runs of the same cell pass unchanged.
#
#   Measured on a clean main build on the same instance: a C replica of
#   the entire staging chain — mkdir under CODEX_HOME/tmp/arg0, copy
#   /proc/self/exe, fchmod 0755, execve the copy with argv0=apply_patch —
#   succeeds at every step as the agent process, and the Linux view already
#   mounts a private /proc as scaffold, which is why it never appears in a grant
#   list or the startup disclosure. So a missing /proc is NOT the cause.
#
#   Retracted: this case previously named the cause as the view
#   lacking /proc, on the strength of a run that appeared to pass with a /proc
#   read grant. The pair generated in that run names no such grant at all — the
#   switch never took effect — so the run proved nothing and the claim is withdrawn.
#
# The cell therefore records which outcome occurred, under the neutral id
# codex-arg0-staging-intermittent, and asserts the rest of the workload, which
# does complete. A run that trips it is evidence for whoever takes the cause on.
#
# Reference: artifact section 4. Two residuals shape the Linux spelling: the box
# refuses a memory permission change that adds execution and NODE_OPTIONS is a
# refused name (F29/F64), so npm runs as `node --jitless <npm-cli.js>` rather than
# through the `npm` launcher, and the agent must spell that prefix for the table
# to select. npm runs package scripts through a shell, and /bin/sh is a link on
# Amazon Linux 2023, so npm_config_script_shell names the canonical bash.

wl_manifest() {
  cat <<EOF
tools=npm node
http=registry.npmjs.org
timeout=900
residuals_linux=F29 F64
EOF
}

wl_prepare() {
  local proj="$1"
  mkdir -p "$proj/.npm"
}

wl_checks() {
  local proj="$1"
  wl_assert_file node-package "$proj/package.json" name
  wl_assert_glob node-dependency "$proj/node_modules/left-pad"
  wl_assert_file node-module "$proj/pad.js" "left-pad"
  wl_assert_any node-test-output "$proj/test-out.txt" "# pass 1" "ok 1"
  wl_assert_journal node-journal-spawn permit "shell:spawn" node
  wl_note_codex_arg0 "$proj/test-out.txt"
}
