# Fuzz the tool pack shell parser

The tool pack shell parser reads an argv as one action of a pack. Its fuzz tests are in
`crates/policy/src/pack/fuzz.rs`. They build each argv from the vocabulary of each valid pack under
`crates/policy/tests/packs/`, and from the argvs of the golden corpus. Then they check these
invariants:

- The parser does not panic, and one parse that returns took less than one second. This check
  cannot stop a parse that does not return. Only the `-timeout` of the long run finds a hang.
- Two parses of one argv give the same result.
- An action, its fields, and its effects are ones that the pack declares.
- When you insert a flag that the pack does not declare and that no other word holds, the result
  is `Unmodeled`, or the flag is a field value. The parser cannot read an undeclared flag as an
  option.
- The same is true when you put an undeclared letter in a short cluster, after letters that take
  no value in any option table of the pack. After a flag that takes a value, the letters are that
  value, so the check does not apply there.

## The bounded run

`cargo test` runs the bounded run on the stable toolchain. It uses a random engine with a new
seed on each run, and takes a few seconds:

```sh
cargo test -p strands-box-policy --all-features --lib pack::fuzz
```

To run more inputs, set `BOLERO_RANDOM_ITERATIONS`. To replay a failure, set the
`BOLERO_RANDOM_SEED` that the failure message gives.

## The long run with libFuzzer

A long run uses libFuzzer with coverage feedback and AddressSanitizer. It needs a nightly
toolchain, which `rustup toolchain install nightly` installs, and `jq`.

Do not use `cargo bolero test` for this crate. That command has no `--lib` option, so it builds
each integration test of `strands-box-policy` with the coverage flags. Those test binaries do not
link the fuzzer runtime, and the link fails. Build only the library test binary, and then start
it with the variables that `cargo bolero test` sets. Run these commands from the repository root.
`FUZZ_FLAGS` reaches only the one build, so the next `cargo` command in your shell is not changed:

```sh
FUZZ_FLAGS="--cfg fuzzing --cfg fuzzing_libfuzzer -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares \
  -Zsanitizer=address -Ctarget-feature=-outline-atomics"
TARGET=$(rustc +nightly -vV | sed -n 's/^host: //p')
EXE=$(RUSTFLAGS=$FUZZ_FLAGS cargo +nightly test --target "$TARGET" --profile release \
  -p strands-box-policy --lib --target-dir target/fuzz --no-run --message-format=json \
  | jq -r 'select(.profile.test == true and .target.kind == ["lib"]) | .executable')
TEST=pack::fuzz::a_generated_argv_holds_each_parser_invariant
WORK=$PWD/target/fuzz/parser
mkdir -p "$WORK/corpus" "$WORK/crashes"
BOLERO_TEST_NAME=$TEST BOLERO_LIBTEST_HARNESS=1 \
BOLERO_LIBFUZZER_ARGS="$WORK/corpus $WORK/crashes -artifact_prefix=$WORK/crashes/ -timeout=10 -max_len=512 -max_total_time=900 -fork=4" \
  "$EXE" "$TEST" --exact --nocapture --quiet --test-threads 1
```

- `-max_total_time` is the run time in seconds. `-fork` is the number of worker processes.
- `-Ctarget-feature=-outline-atomics` is necessary on Linux on aarch64. Without it, the
  instrumented binary is too large for the linker to reach the atomic helper functions.
- On macOS, the target is `aarch64-apple-darwin`, and you can remove that flag.
- libFuzzer writes each failing input to `target/fuzz/parser/crashes/`. Each input is the byte
  string that the harness decodes into an argv. To get the argv, run the test binary with the
  file as its only libFuzzer argument. Then add the argv to the golden corpus as a case.
