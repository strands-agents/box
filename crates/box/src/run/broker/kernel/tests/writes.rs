//! A Call's content writes reach history before the Call answers.

use std::sync::Arc;

use box_shell::ShellKernel;
use strands_shell::Shell;

use super::{adapter, backend, policy, run};
use crate::run::broker::program::Program;

/// Permit every command and write, until one content write has completed in the last hour.
const BUDGET_OF_ONE: &str = r#"
permit(principal == Box::Agent::"self", action == Box::Action::"shell:exec", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:read", resource);
permit(principal == Box::Agent::"self", action == Box::Action::"fs:write", resource);
@id("write_budget")
forbid (principal, action == Box::Action::"fs:write", resource)
when { context.input.operation == Box::FsWriteOperation::"write_content" }
when temporal {
  exists (total: Long). (
    (count for (t: Timepoint). where (
      formerly within 1h (
        Box::Action::"fs:write"::response{ input.path: _, input.operation: Box::FsWriteOperation::"write_content", output.result: Box::FsResponseResult::"completed" } && tp(t)
      )
    )) == total && total >= 1
  )
};
"#;

/// A Program on its own kernel over `policy`, as one connection builds it.
fn program(policy: &Arc<policy::PolicyEngine>) -> Program {
    let kernel = Arc::new(ShellKernel::over(backend(&[]), adapter(Arc::clone(policy))));
    let shell = Shell::with_kernel(Arc::clone(&kernel) as Arc<dyn strands_shell::os::Kernel>);
    let hosted = crate::run::broker::shell::HostedShell { shell, kernel };
    let (program, _output, _control) = Program::adopt(
        hosted,
        None,
        crate::record::config::limits::DEFAULT_SHELL_MAX_STDIN,
    )
    .expect("a program");
    program
}

/// A write in one Call is counted before a Call on another connection is decided.
#[test]
fn a_calls_last_write_counts_before_the_next_connection_decides() {
    let policy = policy(BUDGET_OF_ONE);
    let (first, second) = run(async {
        let mut first = program(&policy);
        let mut second = program(&policy);
        let written = first.call("printf x > /tmp/a.txt").await.status;
        let refused = second.call("printf y > /tmp/b.txt").await.status;
        (written, refused)
    });
    assert_eq!(first, 0, "the first write is within the budget");
    assert_ne!(
        second, 0,
        "the first Call's write is counted before the second Call"
    );
}
