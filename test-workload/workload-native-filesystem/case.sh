#!/bin/bash
# Native agent file tools must reach policy, preserve a protected file, and
# continue after a denial. Select this case explicitly with a signed macOS box.

wl_agents="claude codex"

wl_manifest() {
  cat <<EOF
name=wl-native-$WL_AGENT
tools=
timeout=300
native_filesystem_policy=1
policy_file=$WL_RUN_DIR/native.dw
EOF
  case "${WL_AGENT:-}" in
    claude) echo "agent_args=--tools Read,Write,Edit --max-turns 12" ;;
    codex) ;;
    *) return 1 ;;
  esac
}

wl_prepare() {
  local proj="$1"
  printf 'draft\n' > "$proj/allowed.txt"
  printf 'approved\n' > "$proj/protected.txt"
  cat > "$WL_RUN_DIR/native.dw" <<'EOF'
@id("native_runtime")
permit(principal, action in [
    Box::Action::"fs:read", Box::Action::"fs:write",
    Box::Action::"fs:move", Box::Action::"fs:delete"
], resource);

@id("protected_file")
forbid(principal, action in [
    Box::Action::"fs:write", Box::Action::"fs:move", Box::Action::"fs:delete"
], resource)
when { context.input.path == "{{TILDE_PROJECT}}/protected.txt" };
EOF
}

wl_checks() {
  python3 "$WL_SRC/test-workload/workload-native-filesystem/checks.py" \
    "$WL_RUN_DIR" "$WL_AGENT" >> "$WL_CHECKS_FILE" \
    || wl_check native-evidence-readable 0 "native evidence checker failed"
}
