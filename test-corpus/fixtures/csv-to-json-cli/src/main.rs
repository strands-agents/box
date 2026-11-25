use std::error::Error;
use std::fs::File;
use std::io::Read;

use clap::Parser;
use serde_json::{Map, Value};

/// Convert a CSV file to a JSON array with one object per row.
#[derive(Parser)]
struct Args {
    /// The CSV file to read.
    input: String,
}

fn convert(reader: impl Read) -> Result<String, Box<dyn Error>> {
    let mut csv = csv::Reader::from_reader(reader);
    let headers = csv.headers()?.clone();
    let mut rows = Vec::new();
    for record in csv.records() {
        let record = record?;
        let row: Map<String, Value> = headers
            .iter()
            .zip(record.iter())
            .map(|(key, value)| (key.to_string(), Value::String(value.to_string())))
            .collect();
        rows.push(Value::Object(row));
    }
    Ok(serde_json::to_string(&rows)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    println!("{}", convert(File::open(args.input)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::convert;

    #[test]
    fn each_row_becomes_an_object() {
        let json = convert("name,revenue\nacme,100.5\n".as_bytes()).unwrap();
        assert_eq!(json, r#"[{"name":"acme","revenue":"100.5"}]"#);
    }
}
