#!/usr/bin/env bash
# Install the toolchains in NEEDS that corpus.yml's setup actions (Node, Go, uv, PHP) do not.
# An install that fails warns and moves on, so the cells that need the tool are SKIP
# `no-toolchain` and the other cells still run.
# Usage: NEEDS="uv poetry ..." bench-toolchains.sh
set -uo pipefail
needs=" ${NEEDS:-} "
has() { case $needs in *" $1 "*) return 0 ;; esac; return 1; }
macos() { [ "$(uname -s)" = Darwin ]; }
path() { echo "$1" >> "${GITHUB_PATH:-/dev/null}"; export PATH="$1:$PATH"; }
install() {  # install NAME: run install_NAME, and warn if it fails
  echo "::group::$1"
  (set -e; "install_$1")  # not a condition, so set -e holds inside
  if [ $? -ne 0 ]; then echo "::warning::could not install $1; its cells are SKIP"; fi
  echo "::endgroup::"
}
apt() { sudo apt-get install -y -q "$@"; }
install_apt_index() { sudo apt-get update -q; }

install_bun() {
  npm install --global bun@1.4.4
  # Core requires a writable command to have one hard link.
  local bunx
  bunx="$(node -p 'require("fs").realpathSync(process.argv[1])' "$(command -v bunx)")"
  cp -p "$bunx" "$bunx.copy"
  mv "$bunx.copy" "$bunx"
}
install_pnpm() { npm install --global pnpm@10.18.3; }
# Yarn 4 through Corepack, as a project's `packageManager` asks. Node 25 and later ship no
# Corepack, and Corepack 0.34 fails through the box's proxy on Node 26, so the bench pins its own.
install_yarn() {
  npm install --global --prefix "$HOME/.corepack" corepack@0.36.0
  mkdir -p "$HOME/.corepack/shims"
  "$HOME/.corepack/bin/corepack" enable --install-directory "$HOME/.corepack/shims" yarn
  path "$HOME/.corepack/shims"
}
install_poetry() { pipx install --python "$(command -v python3)" poetry==2.5.1; }
install_pixi() {
  curl -fsSL https://pixi.sh/install.sh | PIXI_VERSION=v0.84.1 PIXI_NO_PATH_UPDATE=1 bash
  path "$HOME/.pixi/bin"
}
install_nvm() {
  local dir="${NVM_DIR:-$HOME/.nvm}"
  [ -s "$dir/nvm.sh" ] || git clone -q --depth 1 --branch v0.41.0 https://github.com/nvm-sh/nvm.git "$dir"
}
install_rbenv() { if macos; then HOMEBREW_NO_AUTO_UPDATE=1 brew install rbenv; else apt rbenv; fi; }
install_rails() {
  if macos; then
    gem install rails -v 8.1.4.1 --no-document
  else
    # Ubuntu's Ruby is the system's, so the gem goes in the user's own gem folder.
    gem install --user-install rails -v 8.1.4.1 --no-document
    path "$(ruby -e 'print Gem.user_dir')/bin"
  fi
}
install_psql() {
  if macos; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install libpq
    path "$(brew --prefix libpq)/bin"
  else
    apt postgresql-client
  fi
}

path "${PIPX_BIN_DIR:-$HOME/.local/bin}"
if ! macos && { has rbenv || has psql; }; then install apt_index; fi
for tool in bun pnpm yarn poetry pixi nvm rbenv rails psql; do
  if has "$tool"; then install "$tool"; fi
done
if has docker && macos; then
  echo "::notice::A hosted macOS runner cannot run Docker, so the cells that need it are SKIP."
fi
if has flutter; then
  echo "::notice::The bench does not install Flutter yet, so the cells that need it are SKIP."
fi
