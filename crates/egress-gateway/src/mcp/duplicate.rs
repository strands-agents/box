//! The refusal of a JSON text that repeats a key inside one object, at any depth.

use std::collections::HashSet;
use std::fmt;
use std::io;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// The most characters of a repeated key that a refusal quotes.
const QUOTED_KEY_CHARS: usize = 64;

/// Refuse `text` when one of its objects names a key twice; leave every other text to its parser.
pub(crate) fn refuse_duplicate_keys(text: &[u8]) -> io::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(text);
    match UniqueKeys.deserialize(&mut deserializer) {
        Err(error) if error.is_data() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "an MCP frame with a duplicate object key is refused: servers disagree on which \
                 copy counts, so the box cannot judge it ({error})"
            ),
        )),
        _ => Ok(()),
    }
}

struct UniqueKeys;

impl<'de> DeserializeSeed<'de> for UniqueKeys {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element_seed(UniqueKeys)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if keys.contains(&key) {
                let quoted: String = key.chars().take(QUOTED_KEY_CHARS).collect();
                return Err(de::Error::custom(format_args!("duplicate key {quoted:?}")));
            }
            map.next_value_seed(UniqueKeys)?;
            keys.insert(key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use super::*;

    fn refused(text: &str) -> bool {
        refuse_duplicate_keys(text.as_bytes()).is_err()
    }

    #[test]
    fn a_key_repeated_at_any_depth_is_refused() {
        for text in [
            r#"{"method":"tools/call","method":"ping"}"#,
            r#"{"params":{"name":"a","name":"b"}}"#,
            r#"{"params":{"arguments":{"path":"/x","path":"/y"}}}"#,
            r#"{"a":[{"b":{"c":1,"c":1}}]}"#,
            r#"[{"k":1,"k":2}]"#,
            r#"{"name":"a","name":"b"}"#,
            r#"{"id":1,"id":1}"#,
            r#"{"name":"a","n\u0061me":"b"}"#,
        ] {
            let error = refuse_duplicate_keys(text.as_bytes()).expect_err(text);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{text}");
            assert!(error.to_string().contains("duplicate"), "{text}: {error}");
        }
    }

    #[test]
    fn a_key_in_two_sibling_objects_is_not_a_duplicate() {
        for text in [
            r#"{"a":{"k":1},"b":{"k":2}}"#,
            r#"[{"k":1},{"k":2}]"#,
            r#"{"k":{"k":{"k":[]}}}"#,
            r#"{"params":{"name":"a","_meta":{"name":"b"}}}"#,
            r#"{}"#,
            r#""text""#,
        ] {
            assert!(!refused(text), "{text}");
        }
    }

    #[test]
    fn a_text_that_is_not_json_is_left_to_its_parser() {
        for text in ["", "not json", "{", r#"{"a":1}{"a":2}"#, "[1,"] {
            assert!(!refused(text), "{text:?}");
        }
    }

    #[test]
    fn the_refusal_bounds_the_key_it_quotes() {
        let key = "k\u{202e}".repeat(500);
        let text = format!(r#"{{"{key}":1,"{key}":2}}"#);
        let message = refuse_duplicate_keys(text.as_bytes())
            .expect_err("a repeated long key is refused")
            .to_string();
        assert!(message.len() < 600, "{}", message.len());
        assert!(!message.contains('\u{202e}'), "{message}");
    }

    struct Draw(u64);

    impl Draw {
        fn next(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }
    }

    const KEYS: [&str; 6] = ["method", "name", "a", "id", "é", "\"q\""];

    fn value(draw: &mut Draw, depth: usize) -> Value {
        match draw.next(if depth == 0 { 4 } else { 6 }) {
            0 => Value::Null,
            1 => Value::from(draw.next(1000)),
            2 => Value::from(KEYS[draw.next(KEYS.len())]),
            3 => Value::Bool(draw.next(2) == 1),
            4 => Value::Array((0..draw.next(4)).map(|_| value(draw, depth - 1)).collect()),
            _ => Value::Object(
                (0..draw.next(KEYS.len()))
                    .map(|index| (KEYS[index].to_string(), value(draw, depth - 1)))
                    .collect::<Map<String, Value>>(),
            ),
        }
    }

    /// Repeat the first key of one object in the text, chosen by `draw`, or `None` when it has none.
    fn with_a_repeated_key(text: &str, draw: &mut Draw) -> Option<String> {
        let positions: Vec<usize> = text
            .match_indices("{\"")
            .map(|(position, _)| position + 1)
            .collect();
        if positions.is_empty() {
            return None;
        }
        let start = positions[draw.next(positions.len())];
        let mut key = serde_json::Deserializer::from_str(&text[start..]).into_iter::<String>();
        key.next()?.ok()?;
        let end = start + key.byte_offset();
        Some(format!(
            "{}{}:null,{}",
            &text[..start],
            &text[start..end],
            &text[start..]
        ))
    }

    #[test]
    fn generated_json_is_refused_exactly_when_an_object_repeats_a_key() {
        let mut draw = Draw(0x9E37_79B9_7F4A_7C15);
        let mut repeated = 0;
        for _ in 0..20_000 {
            let text = value(&mut draw, 5).to_string();
            assert!(!refused(&text), "{text}");
            if let Some(duplicated) = with_a_repeated_key(&text, &mut draw) {
                assert!(
                    serde_json::from_str::<Value>(&duplicated).is_ok(),
                    "{duplicated}"
                );
                assert!(refused(&duplicated), "{duplicated}");
                repeated += 1;
            }
        }
        assert!(repeated > 3_000, "{repeated}");
    }
}
