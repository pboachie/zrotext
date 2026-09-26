use crate::{Error, Result, SensitiveLine};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct Builder {
    line: SensitiveLine,
    limit: usize,
}
impl Builder {
    pub(crate) fn new(limit: usize) -> Result<Self> {
        if !(1..=128).contains(&limit) {
            return Err(Error::Rejected);
        }
        Ok(Self {
            line: SensitiveLine {
                bytes: Zeroizing::new([0; 128]),
                length: 0,
            },
            limit,
        })
    }
    /// Returns true for Enter. Caller never releases the result before cleanup.
    pub(crate) fn key(
        &mut self,
        down: bool,
        character: u16,
        virtual_key: u16,
        repeat: u16,
    ) -> Result<bool> {
        if !down {
            return Ok(false);
        }
        if repeat == 0 {
            return Err(Error::Rejected);
        }
        if character == 0 && matches!(virtual_key, 0x10..=0x14 | 0xa0..=0xa5 | 0x90..=0x91) {
            return Ok(false);
        }
        match character {
            3 | 27 => Err(Error::Cancelled),
            13 if repeat == 1 && self.line.length > 0 => Ok(true),
            8 => {
                let removed = usize::from(repeat).min(self.line.length);
                let start = self.line.length - removed;
                self.line.bytes[start..self.line.length].zeroize();
                self.line.length = start;
                Ok(false)
            }
            32..=126 => {
                let count = usize::from(repeat);
                if count > self.limit - self.line.length {
                    return Err(Error::Rejected);
                }
                let end = self.line.length + count;
                self.line.bytes[self.line.length..end].fill(character as u8);
                self.line.length = end;
                Ok(false)
            }
            _ => Err(Error::Rejected),
        }
    }
    pub(crate) fn finish(self) -> SensitiveLine {
        self.line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_ascii_and_backspace_are_bounded_and_redacted() {
        let mut line = Builder::new(4).unwrap();
        assert!(!line.key(true, b'A' as u16, 0, 4).unwrap());
        assert!(!line.key(true, 8, 0, 2).unwrap());
        assert_eq!(&line.line.bytes[2..4], &[0, 0]);
        assert!(!line.key(true, b' ' as u16, 0, 1).unwrap());
        assert!(line.key(true, 13, 0, 1).unwrap());
        let line = line.finish();
        assert_eq!(line.expose_ascii(), b"AA ");
        assert_eq!(format!("{line:?}"), "SensitiveLine([REDACTED])");
    }
    #[test]
    fn overflow_unicode_controls_empty_and_zero_repeats_are_rejected() {
        assert!(Builder::new(0).is_err());
        assert!(Builder::new(129).is_err());
        for character in [0, 9, 10, 13, 26, 127, 233, 0xd800, 0xdc00] {
            assert_eq!(
                Builder::new(1).unwrap().key(true, character, 0, 1),
                Err(Error::Rejected)
            );
        }
        assert_eq!(
            Builder::new(1).unwrap().key(true, 65, 0, 2),
            Err(Error::Rejected)
        );
        assert_eq!(
            Builder::new(1).unwrap().key(true, 65, 0, 0),
            Err(Error::Rejected)
        );
        for character in [3, 27] {
            assert_eq!(
                Builder::new(1).unwrap().key(true, character, 0, 1),
                Err(Error::Cancelled)
            );
        }
    }
    #[test]
    fn key_up_and_modifier_events_never_add_input() {
        let mut line = Builder::new(1).unwrap();
        assert!(!line.key(false, 65, 0, 1).unwrap());
        assert!(!line.key(true, 0, 0x10, 1).unwrap());
        assert!(line.finish().expose_ascii().is_empty());
    }
}
