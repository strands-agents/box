use super::stream::Transcript;

pub(super) struct Validity {
    pub uses: usize,
    /// Why the campaign is invalid; `None` means it is valid.
    pub cause: Option<String>,
}

/// How the agent process ended, for runs that launched one.
pub(super) struct Exit<'a> {
    pub log: &'a str,
    pub code: i32,
    /// A harness failure while running the agent. It invalidates the campaign.
    pub error: Option<String>,
}

/// Judge whether the campaign ran.
pub(super) fn assess(transcript: &Transcript, exit: &Exit) -> Validity {
    let (uses, ran) = (transcript.tool_uses, transcript.ran);
    let cause = if let Some(error) = &exit.error {
        Some(error.clone())
    } else if uses == 0 {
        Some(launch_failure(exit).unwrap_or_else(|| "no attempts executed".into()))
    } else if ran == 0 {
        Some("every tool call was refused or failed, so the box never ran a command".into())
    } else if transcript.report.is_none() {
        Some("the agent never printed its method report, so the campaign did not finish".into())
    } else {
        None
    };
    Validity { uses, cause }
}

/// Explain an agent that made no tool calls from its log, when the log says why.
fn launch_failure(exit: &Exit) -> Option<String> {
    let refused = [
        "error: the following required arguments",
        "Usage: strands-box",
        "strands-box: error:",
        "strands-box: refusing to run:",
    ];
    let unreachable = [
        "api error",
        "failedtoopensocket",
        "can't reach the api",
        "connection error",
        "credit balance",
        "authentication",
    ];
    let lower = exit.log.to_lowercase();
    if exit
        .log
        .lines()
        .any(|l| refused.iter().any(|p| l.starts_with(p)))
    {
        Some(format!(
            "the box never started (CLI or load refusal, exit {})",
            exit.code
        ))
    } else if unreachable.iter().any(|p| lower.contains(p)) {
        Some("could not reach the model API".into())
    } else {
        None
    }
}

impl Validity {
    pub(super) fn status(&self) -> &'static str {
        if self.cause.is_none() {
            "VALID"
        } else {
            "INVALID"
        }
    }
    /// The method report the harness writes when the agent printed none.
    pub(super) fn fallback_report(&self, exit: i32) -> String {
        format!(
            "# Method Report (fallback)\n\nrun_status: {}\nexit_code: {exit}\ntool_uses: {}\n\n{}\n",
            self.status(),
            self.uses,
            self.cause.as_deref().unwrap_or_default()
        )
    }
}
