use serde::Deserialize;
use serde_json::Value;

/// One stream-json line from the agent, with its content blocks parsed once.
#[derive(Debug)]
pub(super) struct Event {
    kind: String,
    blocks: Vec<Block>,
    result: Option<Value>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(rename = "type", default)]
    kind: String,
    message: Option<Value>,
    result: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Block {
    #[serde(rename = "tool_use")]
    ToolUse {
        name: Option<String>,
        input: Option<Value>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        is_error: Option<bool>,
        content: Option<Value>,
    },
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

impl Event {
    pub(super) fn parse(line: &str) -> Option<Self> {
        let raw: RawEvent = serde_json::from_str(line).ok()?;
        let blocks = raw
            .message
            .as_ref()
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|b| Block::deserialize(b).ok())
            .collect();
        Some(Self {
            kind: raw.kind,
            blocks,
            result: raw.result,
        })
    }
    fn text(&self) -> Vec<&str> {
        match self.kind.as_str() {
            "assistant" => self
                .blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect(),
            "result" => self
                .result
                .as_ref()
                .and_then(Value::as_str)
                .into_iter()
                .collect(),
            _ => vec![],
        }
    }
    /// The names of the tools this event calls.
    pub(super) fn tools(&self) -> impl Iterator<Item = &str> {
        self.blocks.iter().filter_map(|b| match b {
            Block::ToolUse { name, .. } => Some(name.as_deref().unwrap_or("?")),
            _ => None,
        })
    }
    pub(super) fn pretty(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .blocks
            .iter()
            .filter_map(|b| match b {
                Block::ToolUse { name, input } => Some(format!(
                    "[tool_use] {}({})",
                    name.as_deref().unwrap_or_default(),
                    input.as_ref().unwrap_or(&Value::Null)
                )),
                Block::ToolResult { is_error, content } => Some(format!(
                    "[tool_result error={}] {}",
                    is_error.unwrap_or(false),
                    content.as_ref().unwrap_or(&Value::Null)
                )),
                Block::Text { text } => Some(format!("[assistant] {text}")),
                Block::Other => None,
            })
            .collect();
        if self.kind == "result" {
            lines.push(format!(
                "[result] {}",
                self.result.as_ref().unwrap_or(&Value::Null)
            ));
        }
        for line in &mut lines {
            crate::truncate_on_boundary(line, 600);
        }
        lines
    }
}

/// What a finished stream-json transcript says about the campaign.
#[derive(Debug, Default)]
pub(super) struct Transcript {
    /// Tool calls the agent made.
    pub tool_uses: usize,
    /// Tool results without an error flag, i.e. commands the box actually ran.
    pub ran: usize,
    /// The method report between the agent's markers, if it printed one.
    pub report: Option<String>,
}

impl Transcript {
    pub(super) fn parse(turns: &str) -> Self {
        let mut transcript = Self::default();
        let mut text: Vec<String> = vec![];
        for event in turns.lines().filter_map(Event::parse) {
            for block in &event.blocks {
                match block {
                    Block::ToolUse { .. } => transcript.tool_uses += 1,
                    Block::ToolResult { is_error, .. } if !is_error.unwrap_or(false) => {
                        transcript.ran += 1
                    }
                    _ => (),
                }
            }
            text.extend(event.text().into_iter().map(str::to_owned));
        }
        transcript.report = report(&text.join("\n"));
        transcript
    }
}

fn report(text: &str) -> Option<String> {
    let (_, rest) = text.split_once("===METHOD_REPORT_BEGIN===")?;
    let (body, _) = rest.split_once("===METHOD_REPORT_END===")?;
    Some(format!("{}\n", body.trim()))
}
