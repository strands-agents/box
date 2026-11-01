// Referenced only inside this case's `#[cfg(target_os = "linux")]` body.
#[cfg(target_os = "linux")]
use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_i_11,
    id: "CN-I-11",
    platforms: [Linux],
    desc: "Characterization: Linux TIOCSTI results agree with independently observed test PTY input",
    run: |b| {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            use std::time::Duration;
            use support::linux::{Terminal, terminal_observation};
            let probe = support::compile(b);
            let control = b.run_sh_with_config(b.with_exec_tree(), "printf 'PTY_NATIVE_CONTROL\\n'");
            support::native_ok(&control, "PTY_NATIVE_CONTROL");
            let mut host_tty = Terminal::new();
            host_tty.control(b"before-host\n");
            let out = support::text(host_tty.launch(Command::new(&probe).arg("tty")));
            let host = terminal_observation(&out, &host_tty.input(Duration::from_millis(100)));
            host_tty.control(b"after-host\n");
            let mut box_tty = Terminal::new();
            box_tty.control(b"before-box\n");
            let r = box_tty.run_box(b, &format!("{} tty", support::q(&probe)));
            support::native_ok(&r, "TTY_ENTERED");
            let contained = terminal_observation(&r.out, &box_tty.input(Duration::from_millis(100)));
            box_tty.control(b"after-box\n");
            b.record_note(format!("CN-I-11 CHARACTERIZATION host={host} contained={contained}; observation only, not proof of terminal isolation; ioctl is allowed by the current Linux filter"));
        }
    }
}
