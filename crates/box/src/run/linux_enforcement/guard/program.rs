//! Entry identity checks executed at the Linux security hooks.
use super::btf::Btf;
use std::{collections::HashMap, io};

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Instruction {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}
struct Program {
    code: Vec<Instruction>,
    labels: HashMap<&'static str, usize>,
    jumps: Vec<(usize, &'static str)>,
}
impl Program {
    fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: HashMap::new(),
            jumps: Vec::new(),
        }
    }
    fn add(&mut self, code: u8, destination: u8, source: u8, offset: i16, immediate: i32) {
        self.code.push(Instruction {
            code,
            registers: destination | (source << 4),
            offset,
            immediate,
        });
    }
    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.code.len());
    }
    fn jump(
        &mut self,
        code: u8,
        destination: u8,
        source: u8,
        immediate: i32,
        target: &'static str,
    ) {
        self.jumps.push((self.code.len(), target));
        self.add(code, destination, source, 0, immediate);
    }
    fn constant(&mut self, register: u8, value: i32) {
        self.add(0xb7, register, 0, 0, value);
    }
    fn register(&mut self, destination: u8, source: u8) {
        self.add(0xbf, destination, source, 0, 0);
    }
    fn load(&mut self, destination: u8, source: u8, offset: i16, word: bool) {
        self.add(
            if word { 0x61 } else { 0x79 },
            destination,
            source,
            offset,
            0,
        );
    }
    fn read_kernel(&mut self, destination: u8, pointer: u8, offset: i32, word: bool) {
        self.register(3, pointer);
        self.add(0x07, 3, 0, 0, offset);
        self.register(1, 10);
        self.add(0x07, 1, 0, 0, -16);
        self.constant(2, if word { 4 } else { 8 });
        self.add(0x85, 0, 0, 0, 113);
        self.jump(0x55, 0, 0, 0, "deny");
        self.load(destination, 10, -16, word);
    }
    fn compare(&mut self, register: u8, expected: i16, btf: &Btf) -> io::Result<()> {
        self.register(9, register);
        self.jump(0x15, 9, 0, 0, "deny");
        self.read_kernel(2, 9, btf.member("inode", "i_ino")?, false);
        self.load(3, 7, expected, false);
        self.jump(0x5d, 2, 3, 0, "deny");
        self.read_kernel(2, 9, btf.member("inode", "i_sb")?, false);
        self.read_kernel(2, 2, btf.member("super_block", "s_dev")?, true);
        self.load(3, 7, expected + 8, false);
        self.jump(0x5d, 2, 3, 0, "deny");
        Ok(())
    }
    fn finish(mut self) -> io::Result<Vec<Instruction>> {
        for (index, label) in self.jumps {
            let target = *self
                .labels
                .get(label)
                .ok_or_else(|| io::Error::other("missing guard branch"))?;
            self.code[index].offset =
                i16::try_from(target as isize - index as isize - 1).map_err(io::Error::other)?;
        }
        Ok(self.code)
    }
}
pub(super) fn build(btf: &Btf, map: i32, operation: i32) -> io::Result<Vec<Instruction>> {
    let rename = operation == 2;
    let mut p = Program::new();
    p.register(6, 1);
    p.load(0, 6, if rename { 32 } else { 16 }, false);
    p.jump(0x55, 0, 0, 0, "exit");
    p.add(0x85, 0, 0, 0, 158);
    p.register(2, 0);
    p.add(0x18, 1, 1, 0, map);
    p.add(0, 0, 0, 0, 0);
    p.constant(3, 0);
    p.constant(4, 0);
    p.add(0x85, 0, 0, 0, 156);
    p.jump(0x15, 0, 0, 0, "allow");
    p.register(7, 0);
    p.load(1, 7, 0, false);
    p.jump(0x55, 1, 0, 1, "deny");
    p.add(0x7a, 7, 0, 0, 0);
    p.load(1, 7, 8, false);
    p.jump(0x55, 1, 0, operation, "deny");
    p.load(1, 6, 0, false);
    p.compare(1, 16, btf)?;
    p.load(1, 6, 8, false);
    p.read_kernel(1, 1, btf.member("dentry", "d_inode")?, false);
    p.compare(1, 32, btf)?;
    if rename {
        p.load(1, 6, 16, false);
        p.compare(1, 48, btf)?;
        p.load(1, 6, 24, false);
        p.read_kernel(1, 1, btf.member("dentry", "d_inode")?, false);
        p.jump(0x15, 1, 0, 0, "absent");
        p.compare(1, 64, btf)?;
        p.jump(0x05, 0, 0, 0, "allow");
        p.label("absent");
        p.load(2, 7, 64, false);
        p.jump(0x55, 2, 0, 0, "deny");
    }
    p.label("allow");
    p.constant(0, 0);
    p.jump(0x05, 0, 0, 0, "exit");
    p.label("deny");
    p.constant(0, -libc::EACCES);
    p.label("exit");
    p.add(0x95, 0, 0, 0, 0);
    p.finish()
}
