//! `strands_box::check_read_grant` passes a path in a credential store and says so.

#[test]
fn a_read_grant_in_a_credential_store_passes_and_says_so() {
    let home = tempfile::tempdir().expect("a home");
    let home = home.path().canonicalize().expect("a canonical home");
    let key = home.join(".ssh/id_ed25519");
    std::fs::create_dir_all(key.parent().expect("a store")).expect("a store");
    std::fs::write(&key, "").expect("a key");
    // SAFETY: this test binary holds one test, so no other thread reads the environment.
    unsafe { std::env::set_var("HOME", &home) };
    assert_eq!(strands_box::check_read_grant(&key).ok(), Some(true));
}
