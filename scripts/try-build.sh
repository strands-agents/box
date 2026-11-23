#!/usr/bin/env bash
# Run the box build that CI made for a pull request or for main, without building it.
#
#   scripts/try-build.sh <pr-number|main>                  a shell with that box first on PATH
#   scripts/try-build.sh <pr-number|main> --env [sh|fish]  shell lines that put it first here
#   scripts/try-build.sh <pr-number|main> -- <command...>  one command with that PATH
#   scripts/try-build.sh --clean                           remove every cached build
set -euo pipefail

repo="${BOX_TRY_REPO:-strands-agents/box}"
triple="aarch64-apple-darwin"
[[ -n "${TMPDIR:-}" ]] || {
  echo "try-build: TMPDIR is not set; set it to a folder that only you can write" >&2
  exit 1
}
cache="${TMPDIR%/}/box-try"

die() {
  echo "try-build: $*" >&2
  exit 1
}

usage() {
  echo "usage: scripts/try-build.sh <pr-number|main> [--env [sh|fish] | -- <command...>]" >&2
  echo "       scripts/try-build.sh --clean" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
if [[ "$1" == "--clean" ]]; then
  [[ $# -eq 1 ]] || usage
  rm -rf "$cache"
  echo "try-build: removed $cache" >&2
  exit 0
fi
target="$1"
shift
mode=shell
if [[ $# -gt 0 ]]; then
  case "$1" in
    --env)
      mode=env
      if [[ $# -eq 2 ]]; then
        case "$2" in sh | fish) syntax="$2" ;; *) usage ;; esac
      else
        [[ $# -eq 1 ]] || usage
      fi
      ;;
    --) shift; [[ $# -gt 0 ]] || usage; mode=command ;;
    *) usage ;;
  esac
fi

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] ||
  die "CI builds box for macOS on Apple silicon only; this host is $(uname -sm)"
command -v gh >/dev/null || die "needs the GitHub CLI (gh); install it with: brew install gh"

if [[ "$target" == "main" ]]; then
  sha="$(gh api "repos/$repo/commits/main" --jq .sha)" || die "cannot read main of $repo; check gh auth status"
  runs=(--event push --branch main)
  label="main"
elif [[ "$target" =~ ^[0-9]+$ ]]; then
  pr="$(gh pr view "$target" -R "$repo" --json headRefOid,isDraft --jq '"\(.headRefOid) \(.isDraft)"')" ||
    die "cannot find pull request $target in $repo"
  read -r sha draft <<<"$pr"
  runs=(--event pull_request)
  label="PR $target"
else
  usage
fi
mkdir -p -m 700 "$cache"
[[ -d "$cache" && ! -L "$cache" && -O "$cache" ]] || die "$cache is not a folder that you own"
chmod 700 "$cache"
short="${sha:0:10}"
name="box-$sha-$triple"
dir="$cache/$sha"
bin="$dir/bin"
files="$dir/bin.files"

# The build is cached when every file that its archive held is still there.
complete() {
  [[ -f "$files" && -x "$bin/box" ]] || return 1
  local entry
  while IFS= read -r entry; do
    [[ -e "$bin/$entry" ]] || return 1
  done <"$files"
}

if complete && "$bin/box" --version >/dev/null 2>&1; then
  echo "try-build: using the build for $label at $short from $dir" >&2
else
  run="$(gh run list -R "$repo" --workflow ci.yml --commit "$sha" "${runs[@]}" --limit 1 \
    --json databaseId,status,conclusion,url \
    --jq '.[0] | select(. != null) | "\(.databaseId) \(.status) \(.url) \(.conclusion)"')"
  [[ -n "$run" ]] || die "no CI run for $label at $short yet"
  read -r run_id status url conclusion <<<"$run"

  expired="$(gh api "repos/$repo/actions/runs/$run_id/artifacts?name=$name" \
    --jq '.artifacts[0] | select(. != null) | .expired')"
  if [[ -z "$expired" ]]; then
    if [[ "${draft:-false}" == "true" ]]; then
      die "$label is a draft; CI builds it once it is marked ready for review"
    fi
    if [[ "$status" != "completed" ]]; then
      die "CI for $label at $short has not uploaded its build yet ($status); try again in a few minutes: $url"
    fi
    die "CI for $label at $short uploaded no build (run conclusion: $conclusion): $url"
  fi
  [[ "$expired" == "false" ]] || die "the build for $label at $short has expired; push a commit or re-run CI to make a new one"

  mkdir -p "$dir"
  work="$(mktemp -d "$dir/download.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  echo "try-build: downloading the build for $label at $short" >&2
  gh run download "$run_id" -R "$repo" -n "$name" -D "$work/download" >/dev/null
  mkdir "$work/bin"
  tar -xzf "$work/download/box.tar.gz" -C "$work/bin"
  (cd "$work/bin" && find . -mindepth 1) >"$work/bin.files"
  "$work/bin/box" --version >/dev/null || die "the downloaded box does not start"
  rm -rf "$bin" "$files"
  mv "$work/bin" "$bin"
  mv "$work/bin.files" "$files"
fi

# A BOX_HOME in the cache is one that an earlier run of this script set, so a new build gets its own.
if [[ -n "${BOX_HOME:-}" && "$BOX_HOME" != "$cache/"* ]]; then
  box_home="$BOX_HOME"
else
  box_home="$dir/home"
fi
mkdir -p -m 700 "$box_home"
if BOX_HOME=box-try-probe BOX_RESOURCES="$bin/resources" "$bin/box" profile list >/dev/null 2>&1 </dev/null; then
  echo "try-build: this build does not read BOX_HOME, so it uses your default Box home" >&2
fi
try="$target@$short"

if [[ "$mode" == "env" ]]; then
  if [[ -z "${syntax:-}" ]]; then
    syntax=sh
    [[ "${SHELL##*/}" != "fish" ]] || syntax=fish
  fi
  if [[ "$syntax" == "fish" ]]; then
    quote() { local value="${1//\\/\\\\}"; printf "'%s'" "${value//\'/\\\'}"; }
    echo "set -gx PATH $(quote "$bin") \$PATH;"
    echo "set -gx BOX_RESOURCES $(quote "$bin/resources");"
    echo "set -gx BOX_HOME $(quote "$box_home");"
    echo "set -gx BOX_TRY $(quote "$try");"
    echo "functions -e box;"
  else
    quote() { printf "'%s'" "${1//\'/\'\\\'\'}"; }
    echo "export PATH=$(quote "$bin"):\"\$PATH\";"
    echo "export BOX_RESOURCES=$(quote "$bin/resources");"
    echo "export BOX_HOME=$(quote "$box_home");"
    echo "export BOX_TRY=$(quote "$try");"
    echo "unalias box 2>/dev/null; hash -r 2>/dev/null; true;"
  fi
  other=fish
  [[ "$syntax" == "sh" ]] || other=sh
  echo "try-build: box is $bin/box ($label at $short), with BOX_HOME $box_home." >&2
  echo "try-build: printed $syntax lines; for the other syntax, use --env $other" >&2
  exit 0
fi

export PATH="$bin:$PATH" BOX_RESOURCES="$bin/resources" BOX_HOME="$box_home" BOX_TRY="$try"
if [[ "$mode" == "command" ]]; then
  status=0
  "$@" || status=$?
  exit "$status"
fi

echo "try-build: box is $bin/box ($label at $short), with BOX_HOME $box_home. Exit the shell to leave it." >&2
echo "try-build: if \`command -v box\` names another path, your shell's startup file moved it; use --env" >&2
status=0
"${SHELL:-/bin/sh}" || status=$?
exit "$status"
