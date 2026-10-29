#[test]
fn a_macos_test_failure_must_reach_the_ci_gate() {
    eprintln!("CI_GATE_PROBE_PLATFORM={}", std::env::consts::OS);
    assert_ne!(
        std::env::consts::OS,
        "macos",
        "intentional macOS failure for the CI gate probe; do not merge"
    );
}
