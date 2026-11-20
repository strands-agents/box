//! The `Info.plist` that the macOS `box` carries for the signing service.
#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn box_carries_its_own_identifier_and_version() {
    let output = Command::new("/bin/launchctl")
        .args(["plist", "__TEXT,__info_plist", env!("CARGO_BIN_EXE_box")])
        .output()
        .expect("launchctl runs");
    let plist = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{plist}");
    assert!(
        plist.contains("\"CFBundleIdentifier\" = \"com.amazon.strands.box-cli\";"),
        "{plist}"
    );
    assert!(
        plist.contains(&format!(
            "\"CFBundleVersion\" = \"{}\";",
            env!("CARGO_PKG_VERSION")
        )),
        "{plist}"
    );
    assert!(
        plist.contains(&format!(
            "\"CFBundleShortVersionString\" = \"{}\";",
            env!("CARGO_PKG_VERSION")
        )),
        "{plist}"
    );
}
