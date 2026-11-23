#[derive(Clone, Copy, Default)]
pub(super) struct Mouse {
    pub(super) tracking: u16,
    pub(super) format: u16,
}

impl Mouse {
    pub(super) fn accepts(self, click: &Click) -> bool {
        let motion = click.button & 32 != 0;
        match self.tracking {
            1000 => !motion,
            1002 => !motion || click.button & 3 != 3,
            1003 => true,
            _ => false,
        }
    }

    pub(super) fn forward(self, click: &Click, bytes: &[u8], agent: &mut Vec<u8>) {
        if !self.accepts(click) {
            return;
        }
        if self.format == 1006 {
            agent.extend_from_slice(bytes);
            return;
        }
        let button = if click.release {
            (click.button & 0x1c) | 3
        } else {
            click.button
        };
        let limit = match self.format {
            0 => 223,
            1005 => 2015,
            _ => return,
        };
        let values = [button, click.column, click.row];
        if values.iter().any(|&value| value > limit) {
            return;
        }
        agent.extend_from_slice(b"\x1b[M");
        for value in values {
            if self.format == 1005 {
                agent.extend_from_slice(
                    char::from_u32(value + 32)
                        .unwrap()
                        .encode_utf8(&mut [0; 4])
                        .as_bytes(),
                );
            } else {
                agent.push((value + 32) as u8);
            }
        }
    }
}

pub(super) struct Click {
    button: u32,
    pub(super) column: u32,
    pub(super) row: u32,
    pub(super) release: bool,
}

impl Click {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?.strip_prefix("\x1b[<")?;
        let release = text.ends_with('m');
        let text = text.strip_suffix(['M', 'm'])?;
        let mut fields = text.split(';');
        let click = Self {
            button: fields.next()?.parse().ok()?,
            column: fields.next()?.parse().ok()?,
            row: fields.next()?.parse().ok()?,
            release,
        };
        fields.next().is_none().then_some(click)
    }

    pub(super) fn left_press(&self) -> bool {
        self.button == 0 && !self.release
    }

    pub(super) fn left_drag(&self) -> bool {
        self.button & !0x1c == 32 && !self.release
    }

    pub(super) fn left_release(&self) -> bool {
        self.button & !0x1c == 0 && self.release
    }

    pub(super) fn scroll(&self) -> Option<i32> {
        if self.release {
            return None;
        }
        match self.button & !0x1c {
            64 => Some(3),
            65 => Some(-3),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_reports_preserve_event_bits_and_drop_unrepresentable_values() {
        for (format, bytes, expected) in [
            (0, b"\x1b[<0;1;1m".as_slice(), b"\x1b[M#!!".as_slice()),
            (0, b"\x1b[<28;1;1m", b"\x1b[M?!!"),
            (1005, b"\x1b[<28;1;1m", b"\x1b[M?!!"),
            (0, b"\x1b[<32;1;1M", b"\x1b[M@!!"),
            (0, b"\x1b[<35;1;1M", b"\x1b[MC!!"),
            (0, b"\x1b[<68;1;1M", b"\x1b[Md!!"),
            (1005, b"\x1b[<128;128;1M", b"\x1b[M\xc2\xa0\xc2\xa0!"),
            (0, b"\x1b[<0;223;223M", b"\x1b[M \xff\xff"),
            (0, b"\x1b[<0;224;1M", b""),
            (0, b"\x1b[<0;1;224M", b""),
            (0, b"\x1b[<224;1;1M", b""),
            (1005, b"\x1b[<0;2015;2015M", b"\x1b[M \xdf\xbf\xdf\xbf"),
            (1005, b"\x1b[<0;2016;1M", b""),
            (1005, b"\x1b[<0;1;2016M", b""),
            (1005, b"\x1b[<2016;1;1M", b""),
        ] {
            let mouse = Mouse {
                tracking: 1003,
                format,
            };
            let mut agent = b"prefix".to_vec();
            mouse.forward(&Click::parse(bytes).unwrap(), bytes, &mut agent);
            assert_eq!(
                agent,
                [b"prefix".as_slice(), expected].concat(),
                "{format}: {bytes:?}"
            );
        }
    }
}
