// Referenced only inside this case's `#[cfg(target_os = "linux")]` body.
#[cfg(target_os = "linux")]
use crate::phase3 as support;
use strands_det_harness::det_case;

det_case! {
    name: cn_i_12,
    id: "CN-I-12",
    platforms: [Linux],
    desc: "A native shared-memory attach cannot read the host's test-owned System V segment",
    run: |b| {
        #[cfg(target_os = "linux")]
        {
            let probe = support::compile(b);
            let memory = support::linux::SharedMemory::new();
            let id = memory.id.to_string();
            let control = support::host(&probe, &["shm", &id]);
            assert!(control.contains("SHM_REACHED PHASE3_SHM_OWNED"), "DET_ERROR: shared memory control: {control}");
            let r = b.run_sh_with_config(b.with_exec_tree(),
                &format!("{} shm {id}", support::q(&probe)));
            support::native_ok(&r, "SHM_ENTERED");
            r.assert_contains("LOCAL_MEMORY_OK");
            support::require_refusal(&r.out, "SHM", &[1, 13, 22]);
            r.assert_absent("PHASE3_SHM_OWNED");
            memory.unchanged();
            let after = support::host(&probe, &["shm", &id]);
            assert!(after.contains("SHM_REACHED PHASE3_SHM_OWNED"), "DET_ERROR: shared memory observer after: {after}");
        }
    }
}
