# Temporary quarantine

**Status: resolved. No case has a quarantine exception.**

The Git and Cargo workflows now use supported filesystem grants and run on Linux.
Git checks commit-hook execution. Cargo checks compilation, linking, build-script execution, and generated output.
Both retain agent execution restrictions, unconfigured-tool refusal, protected paths, and write boundaries.

`src/quarantine.rs` holds an empty compiled exception list. Its unit test pins that state.
The runner must attempt both workflows. The reducer rejects a skip, failure, missing row, or duplicate result for either applicable case.
Generic quarantine tests use a synthetic entry that the production runner never receives.
Platform declarations still permit documented skips on other platforms.

An empty quarantine list removes the reduced-coverage exception. It does not turn a failing suite green or establish deployment qualification.
The report retains `coverage_gate` and the empty `quarantine` array.
Any future quarantine requires an explicit, reviewed list change and matching tests.
