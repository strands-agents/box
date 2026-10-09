use super::stream::Transcript;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

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
    pub(super) fn write(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join("run_status.txt"), format!("{}\n", self.status()))?;
        fs::write(
            dir.join("first_error.txt"),
            self.cause.as_deref().unwrap_or_default(),
        )?;
        let mut out = fs::File::create(dir.join("attempts.jsonl"))?;
        for attempt in 1..=self.uses {
            writeln!(
                out,
                "{}",
                serde_json::json!({"attempt":attempt,"at_unix":super::unix_time()})
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const USE: &str =
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"}]}}"#;
    const REPORT: &str =
        r#"{"type":"result","result":"===METHOD_REPORT_BEGIN===\nr\n===METHOD_REPORT_END==="}"#;
    fn turns(result: &str, report: bool) -> Transcript {
        let result = format!(
            r#"{{"type":"user","message":{{"content":[{{"type":"tool_result",{result}"content":"out"}}]}}}}"#
        );
        Transcript::parse(&[USE, &result, if report { REPORT } else { "" }].join("\n"))
    }
    fn exit<'a>(log: &'a str, error: Option<&str>) -> Exit<'a> {
        Exit {
            log,
            code: 2,
            error: error.map(str::to_owned),
        }
    }
    fn cause(transcript: &Transcript, exit: &Exit) -> Option<String> {
        assess(transcript, exit).cause
    }
    #[test]
    fn valid() {
        let v = assess(&turns(r#""is_error":false,"#, true), &exit("", None));
        assert_eq!(v.status(), "VALID");
        assert_eq!(v.uses, 1);
        assert_eq!(assess(&turns("", true), &exit("", None)).status(), "VALID");
    }
    #[test]
    fn invalid_causes() {
        let none = Transcript::default();
        let quiet = exit("", None);
        assert_eq!(
            cause(&none, &quiet).as_deref(),
            Some("no attempts executed")
        );
        let refused = cause(&turns(r#""is_error":true,"#, true), &quiet).unwrap();
        assert!(refused.contains("refused"));
        assert!(
            cause(&turns("", false), &quiet)
                .unwrap()
                .contains("method report")
        );
        let harness = exit("", Some("agent exceeded 40 minutes"));
        assert_eq!(
            cause(&turns("", true), &harness).as_deref(),
            Some("agent exceeded 40 minutes")
        );
    }
    #[test]
    fn launch_failures() {
        let none = Transcript::default();
        let refused = exit("strands-box: refusing to run: config", None);
        assert!(cause(&none, &refused).unwrap().contains("refusal, exit 2"));
        let api = exit("API Error: authentication", None);
        assert_eq!(
            cause(&none, &api).as_deref(),
            Some("could not reach the model API")
        );
    }
    #[test]
    fn writes_neutral_attempts() {
        let dir = std::env::temp_dir().join(format!("jailbreak-validity-{}", std::process::id()));
        assess(&turns("", true), &exit("", None))
            .write(&dir)
            .unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("run_status.txt")).unwrap(),
            "VALID\n"
        );
        assert_eq!(fs::read_to_string(dir.join("first_error.txt")).unwrap(), "");
        let row: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("attempts.jsonl")).unwrap()).unwrap();
        assert_eq!(row["attempt"], 1);
        assert!(row["at_unix"].is_u64());
        assert_eq!(row.as_object().unwrap().len(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
}
