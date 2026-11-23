//! Output formats shared by read-only CLI commands.

use std::io::{self, Write};

use clap::ValueEnum;
use serde::Serialize;

/// The representation of a read-only command's output.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Text for reading in a terminal.
    #[default]
    Text,
    /// JSON for scripts.
    Json,
}

pub(crate) fn json(output: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(output, value).map_err(|error| {
        io::Error::new(error.io_error_kind().unwrap_or(io::ErrorKind::Other), error)
    })
}

/// Writes `value` to `output` as one line of JSON, and takes a closed pipe as success.
pub fn json_line<W: Write + ?Sized>(output: &mut W, value: &impl Serialize) -> io::Result<()> {
    let mut output = output;
    match json(&mut output, value).and_then(|()| writeln!(output)) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An output that refuses each write with its kind.
    struct Refusing(io::ErrorKind);

    impl Write for Refusing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_json_line_fails_on_a_write_error_and_not_on_a_closed_reader() {
        let document = serde_json::json!({"profile": "probe"});
        let mut written = Vec::new();
        json_line(&mut written, &document).unwrap();
        assert_eq!(written, b"{\"profile\":\"probe\"}\n");
        let error = json_line(&mut Refusing(io::ErrorKind::StorageFull), &document).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        json_line(&mut Refusing(io::ErrorKind::BrokenPipe), &document).unwrap();
    }
}
