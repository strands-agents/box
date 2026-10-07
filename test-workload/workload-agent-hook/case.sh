#!/bin/bash
# workload-agent-hook — the agent's native hook fires inside its own boundary, and
# a delegated subtask runs in the same process.
#
# Reference: artifact section 6 (the hook and subagent half). On Amazon Linux 2023
# a hook execs /bin/sh, which is a symbolic link no grant may name, so the agent
# runs through a `#!/bin/sh` launcher whose own interpreter chain brings /bin/sh
# into the view under the spelling the child asks for (F49). On macOS /bin/sh and
# /bin/bash are files: both are exec and both are permitted, and no launcher is
# needed.
#
# Codex exec has no subagent, so the subagent assertion is Claude-only and the
# Codex row carries `codex-no-subagent` as a declared residual. Its hook route is
# unmeasured before this suite: if Codex's hook does not fire, this case FAILS with
# the host-observed evidence rather than being skipped.
#
# The Strands entry has no subagent either, so its row carries `strands-no-subagent`.
# Its hook travels as `.strands/hooks.json` under STRANDS_STATE_DIR, in Claude
# Code's vocabulary; a hook the entry does not fire FAILS `hook-fired` by measurement.
# Every fork below names its agent, and an unknown name fails with that name.

wl_manifest() {
  cat <<EOF
tools=
timeout=600
tools_allow=Glob,Grep,Read,Write,Edit,Bash,Task
agent_args_claude_linux=
spawn_macos=/bin/sh /bin/bash
agent_exec_macos=/bin/sh /bin/bash
EOF
  # Claude Code reads its hook from --settings; Codex reads it from its own
  # config.toml, which wl_prepare writes. Both files live inside the project.
  case "${WL_AGENT:-}" in
    claude)
      echo "agent_args=--settings {{PROJECT}}/hook-settings.json"
      if [ "$WL_PLATFORM" = linux ]; then
        echo "agent_program_linux={{TOOLS}}/claude-launcher.sh"
        echo "agent_read_linux={{TOOLS}}/claude-launcher.sh"
        echo "agent_exec_linux={{TOOLS}}/claude-launcher.sh"
      fi ;;
    codex)
        echo "residuals=codex-no-subagent"
        echo "agent_args=--dangerously-bypass-hook-trust"
        if [ "$WL_PLATFORM" = linux ]; then
          echo "agent_program_linux={{TOOLS}}/codex-launcher.sh"
          echo "agent_read_linux={{TOOLS}}/codex-launcher.sh"
          echo "agent_exec_linux={{TOOLS}}/codex-launcher.sh"
        fi ;;
      strands)
        echo "residuals=strands-no-subagent"
        if [ "$WL_PLATFORM" = linux ]; then
          echo "agent_program_linux={{TOOLS}}/strands-launcher.sh"
          echo "agent_read_linux={{TOOLS}}/strands-launcher.sh"
          echo "agent_exec_linux={{TOOLS}}/strands-launcher.sh"
        fi ;;
      *)
        echo "workload-agent-hook: wl_manifest has no arm for agent '${WL_AGENT:-}'" >&2
        return 1 ;;
  esac
}

wl_prepare() {
  local proj="$1"
  # The hook writes a nonce the agent cannot know: it is generated here, kept in
  # the run directory OUTSIDE the project, and never appears in the prompt. So
  # hook.txt carrying it is proof the hook ran, where a fixed marker would also be
  # satisfied by an agent that simply wrote the file the task told it to read.
  local nonce
  nonce="hook-$(date +%s)-$RANDOM$RANDOM"
  printf '%s\n' "$nonce" > "$WL_RUN_DIR/hook-nonce.txt"
  local hook="printf 'HOOK_FIRED $nonce' > $proj/hook.txt"
  case "${WL_AGENT:-}" in
      claude)
        wl_write_hook_json "$proj/hook-settings.json" "$hook"
        if [ "$WL_PLATFORM" = linux ]; then
          mkdir -p "$WL_TOOLS"
          printf '#!/bin/sh\nexec %s "$@"\n' "$WL_CLAUDE" > "$WL_TOOLS/claude-launcher.sh"
          chmod 755 "$WL_TOOLS/claude-launcher.sh"
        fi ;;
      strands)
        # The same vocabulary as Claude Code, under the state directory the box
        # composes into the entry's environment. The Linux launcher is the same
        # /bin/sh bridge the other two agents use (F49).
        wl_write_hook_json "$proj/.strands/hooks.json" "$hook"
        if [ "$WL_PLATFORM" = linux ]; then
          if [ -z "${WL_PYTHON:-}" ] || [ -z "${WL_STRANDS:-}" ]; then
            echo "workload-agent-hook: WL_PYTHON or WL_STRANDS is unresolved on this host, so the launcher cannot be written" >&2
            return 1
          fi
          mkdir -p "$WL_TOOLS"
          printf '#!/bin/sh\nexec %s %s "$@"\n' "$WL_PYTHON" "$WL_STRANDS" > "$WL_TOOLS/strands-launcher.sh"
          chmod 755 "$WL_TOOLS/strands-launcher.sh"
        fi ;;
    codex)
      # Codex reads the same hook vocabulary as Claude Code — PostToolUse, a matcher
      # and a hooks array — from its own config.toml. An earlier spelling
      # (`post_tool_use = { command = [...] }`) was accepted silently and never fired,
      # which is why this case asserts a nonce rather than a fixed marker.
      cat >> "$proj/.codex/config.toml" <<EOF

[[hooks.PostToolUse]]
matcher = ".*"

[[hooks.PostToolUse.hooks]]
type = "command"
command = "$hook"
EOF
      if [ "$WL_PLATFORM" = linux ]; then
        # The hook execs /bin/sh, a symbolic link no grant may name; the launcher's
        # own interpreter chain brings it into the view. The launcher carries the
        # agent's fixed arguments, so box.toml names the launcher alone.
        mkdir -p "$WL_TOOLS"
        CODEX_FLAGS="exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --dangerously-bypass-hook-trust"
        printf '#!/bin/sh\nexec %s %s %s %s "$@"\n' \
          "$WL_NODE" "$WL_NODE_JITLESS" "$WL_CODEX_SHIM" "$CODEX_FLAGS" > "$WL_TOOLS/codex-launcher.sh"
        chmod 755 "$WL_TOOLS/codex-launcher.sh"
      fi ;;
    *)
      echo "workload-agent-hook: wl_prepare has no arm for agent '${WL_AGENT:-}'" >&2
      return 1 ;;
  esac
}

# wl_write_hook_json <out> <command> — one PostToolUse hook on Write, in the JSON
# shape Claude Code reads from --settings and the Strands entry reads from its
# state directory.
wl_write_hook_json() {
  python3 - "$1" "$2" <<'PY'
import json, sys
out, cmd = sys.argv[1:3]
json.dump({"hooks": {"PostToolUse": [{"matcher": "Write",
          "hooks": [{"type": "command", "command": cmd}]}]}}, open(out, "w"))
PY
}

wl_checks() {
  local proj="$1"
  wl_assert_file hook-write "$proj/feature.txt" "hook workload"
  local nonce
  nonce="$(tr -d '[:space:]' < "$WL_RUN_DIR/hook-nonce.txt" 2>/dev/null)"
  if [ -z "$nonce" ]; then
    wl_check hook-fired 0 "no nonce recorded: wl_prepare did not run"
  else
    wl_assert_file hook-fired "$proj/hook.txt" "$nonce"
  fi
  case "${WL_AGENT:-}" in
    claude) wl_assert_file hook-subagent "$proj/subagent.txt" SUBAGENT_OK ;;
    codex|strands) ;; # no subagent: the manifest declares the residual by name
    *) wl_check hook-agent-known 0 "wl_checks has no arm for agent '${WL_AGENT:-}'" ;;
  esac
  wl_assert_no_denial hook-no-project-denial "$proj/feature.txt"
}
