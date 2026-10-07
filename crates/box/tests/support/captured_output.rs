use std::io::{Read, Result};
use std::thread::JoinHandle;

pub struct CapturedOutput {
    reader: Option<JoinHandle<Result<Vec<u8>>>>,
}

impl CapturedOutput {
    pub fn start(mut stream: impl Read + Send + 'static) -> Self {
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        Self {
            reader: Some(reader),
        }
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.reader
            .take()
            .expect("collect output once")
            .join()
            .expect("join the output reader")
            .expect("read process output")
    }
}
