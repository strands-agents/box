//! Run lifetime: the ordered path from a `ProcessSpec` to a contained process.
//!
//! | Step | Module | Produces |
//! |---|---|---|
//! | 1 | [`executable`] | the one path the profile permits `process-exec` on |
//! | 2 | [`boundary`] | containment, the selected phantoms, and the process's environment |
//! | 2 | [`runtime_minimum`] | what any process on this operating system loads and runs |
//! | 3 | [`trampoline`] | the launched helper that applies containment and execs |
//! | 4 | [`supervise`] | the child's process group and exit code |
//! | 4 | [`terminal`] | handing the controlling terminal over, and back |

pub(crate) mod boundary;
pub(crate) mod executable;
pub(crate) mod masked_proc;
pub(crate) mod runtime_minimum;
pub(crate) mod supervise;
pub(crate) mod terminal;
pub(crate) mod trampoline;
