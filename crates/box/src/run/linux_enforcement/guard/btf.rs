//! Kernel type information used to bind the entry checks.
use std::io;

struct Type {
    name: String,
    kind: u32,
    size: u32,
    count: usize,
    flags: bool,
    tail: Vec<u8>,
}
pub(super) struct Btf {
    strings: Vec<u8>,
    types: Vec<Type>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported kernel type information",
    )
}
fn word(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn text(strings: &[u8], at: u32) -> io::Result<String> {
    let value = strings.get(at as usize..).ok_or_else(invalid)?;
    let end = value.iter().position(|b| *b == 0).ok_or_else(invalid)?;
    String::from_utf8(value[..end].to_vec()).map_err(|_| invalid())
}
impl Btf {
    pub(super) fn read() -> io::Result<Self> {
        Self::parse(&std::fs::read("/sys/kernel/btf/vmlinux")?)
    }
    fn parse(blob: &[u8]) -> io::Result<Self> {
        if blob.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err(invalid());
        }
        let header = word(blob, 4)? as usize;
        let types_start = header
            .checked_add(word(blob, 8)? as usize)
            .ok_or_else(invalid)?;
        let types_end = types_start
            .checked_add(word(blob, 12)? as usize)
            .ok_or_else(invalid)?;
        let strings_start = header
            .checked_add(word(blob, 16)? as usize)
            .ok_or_else(invalid)?;
        let strings_end = strings_start
            .checked_add(word(blob, 20)? as usize)
            .ok_or_else(invalid)?;
        let strings = blob
            .get(strings_start..strings_end)
            .ok_or_else(invalid)?
            .to_vec();
        let data = blob.get(types_start..types_end).ok_or_else(invalid)?;
        let mut types = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let name = text(&strings, word(data, at)?)?;
            let info = word(data, at + 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 0xffff) as usize;
            let length = match kind {
                1 | 14 | 17 => 4,
                2 | 7..=12 | 16 | 18 => 0,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                _ => return Err(invalid()),
            };
            let end = at + 12 + length;
            types.push(Type {
                name,
                kind,
                size: word(data, at + 8)?,
                count,
                flags: info >> 31 != 0,
                tail: data.get(at + 12..end).ok_or_else(invalid)?.to_vec(),
            });
            at = end;
        }
        Ok(Self { strings, types })
    }
    fn find(&self, name: &str, kind: u32) -> io::Result<(usize, &Type)> {
        self.types
            .iter()
            .enumerate()
            .find(|(_, t)| t.name == name && t.kind == kind)
            .ok_or_else(invalid)
    }
    pub(super) fn hook(&self, name: &str, arguments: usize) -> io::Result<u32> {
        let (id, function) = self.find(name, 12)?;
        let prototype = self
            .types
            .get(function.size.checked_sub(1).ok_or_else(invalid)? as usize)
            .ok_or_else(invalid)?;
        if prototype.kind != 13 || prototype.count != arguments {
            return Err(invalid());
        }
        Ok(id as u32 + 1)
    }
    pub(super) fn member(&self, name: &str, field: &str) -> io::Result<i32> {
        let (_, description) = self.find(name, 4)?;
        for member in description.tail.as_chunks::<12>().0 {
            if text(&self.strings, word(member, 0)?)? == field {
                let offset = word(member, 8)?;
                if description.flags && offset >> 24 != 0 || offset % 8 != 0 {
                    return Err(invalid());
                }
                return i32::try_from(offset / 8).map_err(|_| invalid());
            }
        }
        Err(invalid())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncated_kernel_type_data_is_refused() {
        for bytes in [&[][..], &[0x9f, 0xeb, 1, 0][..], &[0; 24][..]] {
            assert!(Btf::parse(bytes).is_err());
        }

        // One structure member, a one-argument prototype, and its function.
        let words = [
            1_u32,
            (4 << 24) | 1,
            8,
            8,
            0,
            8,
            0,
            (13 << 24) | 1,
            0,
            0,
            0,
            14,
            12 << 24,
            2,
        ];
        let types: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let blob = |types: &[u8]| {
            let strings = b"\0sample\0field\0hook\0";
            let mut bytes = vec![0x9f, 0xeb, 1, 0];
            for word in [
                24,
                0,
                types.len() as u32,
                types.len() as u32,
                strings.len() as u32,
            ] {
                bytes.extend(word.to_le_bytes());
            }
            bytes.extend(types);
            bytes.extend(strings);
            bytes
        };
        let parsed = Btf::parse(&blob(&types)).unwrap();
        assert_eq!(parsed.member("sample", "field").unwrap(), 1);
        assert_eq!(parsed.hook("hook", 1).unwrap(), 3);
        assert!(parsed.hook("hook", 2).is_err());
        for length in [1, 11, 12, 23, 25, 35, 43, 45, 55] {
            assert!(
                Btf::parse(&blob(&types[..length])).is_err(),
                "type bytes={length}"
            );
        }
    }
}
