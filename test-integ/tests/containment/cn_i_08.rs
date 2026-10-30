use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: when_agent_signals_a_live_host_process_then_host_signal_counter_stays_unchanged,
    id: "CN-I-08",
    desc: "A native handled signal cannot change a live owned host marker's signal counter",
    run: |b| {
        let probe = support::compile(b);
        let mut marker = support::Marker::start(&probe, &b.workspace().with_file_name("signal-marker"), false);
        marker.signal_control(1);
        let r = b.run_sh_with_config(b.with_exec_tree(),
            &format!("{} signal {}", support::q(&probe), marker.pid()));
        marker.advance();
        support::native_ok(&r, "SIGNAL_ENTERED");
        r.assert_contains("SELF_PID ");
        support::require_refusal(&r.out, "SIGNAL", &[1, 3]);
        assert_eq!(marker.count(), 1, "contained signal reached host marker");
        marker.signal_control(2);
    }
}
