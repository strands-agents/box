#!/bin/bash
# workload-rust — cargo in its own boundary, with the C linker chain the toolchain
# execs, plus a commit through the git table.
#
# Reference: artifact section 2. The measured split is the point of this case:
#   macOS   — `cargo build` and `cargo test` both finish, and the commit lands.
#   Linux   — `cargo build` finishes; `cargo test` does NOT link, because gcc
#             searches for the name `ld` and /usr/bin/ld is a symbolic link a
#             grant cannot name (F59). So this case asserts build-only on Linux
#             and build-plus-test on macOS, and records F59 on the Linux row
#             rather than failing it.
# `cargo test` links a test binary and then runs it, so on Linux the longer prefix
# selects [tool.cargo-test], which keeps its own target directory apart from the
# build's.

wl_manifest() {
  cat <<EOF
tools=cargo git
tools_linux=cargo-test
fs=delete
fs_macos=move
timeout=1200
residuals_linux=F59
EOF
}

wl_prepare() {
  local proj="$1"
  # Every path a tool table names must exist at load.
  mkdir -p "$proj/target" "$proj/target-test" "$proj/.cargo" "$proj/src"
}

wl_checks() {
  local proj="$1"
  wl_assert_file rust-manifest "$proj/Cargo.toml" boxdemo
  wl_assert_file rust-source "$proj/src/lib.rs" "pub fn add"
  wl_assert_glob rust-build-artefact "$proj/target/debug/libboxdemo.* $proj/target/debug/deps/boxdemo*"
  wl_assert_file rust-build-output "$proj/build-out.txt" "Finished"
  if [ "$WL_PLATFORM" = macos ]; then
    wl_assert_test_output rust-test-passed "$proj/test-out.txt" rust
  else
    # F59: the link step cannot complete here, so the Linux row asserts that the
    # attempt was made and left its output behind — not what that output says. The
    # first version looked for the string "cargo" in it, which the linker failure
    # does not contain, so a real Linux outcome read as a harness failure.
    wl_assert_file rust-test-attempted "$proj/test-out.txt"
  fi
  wl_assert_commits rust-commit "$proj" 1
  wl_assert_journal rust-journal-spawn permit "shell:spawn" cargo
}
