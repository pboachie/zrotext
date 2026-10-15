//! Local template content contract. No network, save, encryption or send effects.
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    v: u8,
    template: String,
    values: BTreeMap<String, String>,
}
pub struct TemplateContent {
    content: Content,
    canonical: Vec<u8>,
}
fn key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && !matches!(s, "__proto__" | "prototype" | "constructor")
        && s.bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit())
}
fn units(s: &str) -> usize {
    s.encode_utf16().count()
}
fn tokens(s: &str, mut visit: impl FnMut(&str, &str) -> Result<(), Error>) -> Result<(), Error> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut offset = 0;
    while i < bytes.len() {
        if bytes[i] == b'}' {
            return Err(Error::Shape);
        };
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        if !s[i..].starts_with("{{") {
            return Err(Error::Shape);
        };
        let end = s[i + 2..].find("}}").ok_or(Error::Shape)? + i + 2;
        let name = &s[i + 2..end];
        if !key(name) {
            return Err(Error::Shape);
        };
        visit(&s[offset..i], name)?;
        i = end + 2;
        offset = i;
    }
    visit(&s[offset..], "")
}
impl TemplateContent {
    pub fn new(template: &str, values: &BTreeMap<String, String>) -> Result<Self, Error> {
        if units(template) > 4096 || values.len() > 32 {
            return Err(Error::Shape);
        };
        tokens(template, |_, _| Ok(()))?;
        let mut total = 0;
        for (k, v) in values {
            if !key(k) || units(v) > 512 {
                return Err(Error::Shape);
            };
            if total > 0 {
                total += 1
            };
            total += k.len() + 1 + units(v);
            if total > 4096 {
                return Err(Error::Shape);
            }
        }
        let content = Content {
            v: 1,
            template: template.into(),
            values: values.clone(),
        };
        let canonical = serde_json::to_vec(&content).map_err(|_| Error::Shape)?;
        Ok(Self { content, canonical })
    }
    /// Only exact canonical UTF-8 storage bytes are accepted.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > 65536 {
            return Err(Error::Shape);
        };
        let c: Content = serde_json::from_slice(raw).map_err(|_| Error::Shape)?;
        if c.v != 1 {
            return Err(Error::Shape);
        };
        let out = Self::new(&c.template, &c.values)?;
        if raw != out.canonical {
            return Err(Error::Shape);
        };
        Ok(out)
    }
    pub fn canonical(&self) -> Vec<u8> {
        self.canonical.clone()
    }
    pub fn digest(&self) -> String {
        Sha256::digest(&self.canonical)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub fn values(&self) -> BTreeMap<String, String> {
        self.content.values.clone()
    }
    pub fn preview(&self) -> Result<(String, SegmentEstimate), Error> {
        let mut out = String::new();
        let mut count = 0;
        tokens(&self.content.template, |prefix, name| {
            let value = if name.is_empty() {
                ""
            } else {
                self.content.values.get(name).ok_or(Error::Shape)?
            };
            count += units(prefix) + units(value);
            if count > 8192 {
                return Err(Error::Shape);
            };
            out.push_str(prefix);
            out.push_str(value);
            Ok(())
        })?;
        let estimate = estimate_segments(&out)?;
        Ok((out, estimate))
    }
}
#[derive(Serialize)]
pub struct SegmentEstimate {
    pub encoding: &'static str,
    pub parts: usize,
    #[serde(rename = "perPart")]
    pub per_part: usize,
    pub length: usize,
    pub empty: bool,
}
const GSM_DEFAULT: &str = "@\u{a3}$\u{a5}\u{e8}\u{e9}\u{f9}\u{ec}\u{f2}\u{c7}\n\u{d8}\u{f8}\r\u{c5}\u{e5}\u{394}_\u{3a6}\u{393}\u{39b}\u{3a9}\u{3a0}\u{3a8}\u{3a3}\u{398}\u{39e}\u{c6}\u{e6}\u{df}\u{c9} !\"#\u{a4}%&'()*+,-./0123456789:;<=>?\u{a1}ABCDEFGHIJKLMNOPQRSTUVWXYZ\u{c4}\u{d6}\u{d1}\u{dc}\u{a7}\u{bf}abcdefghijklmnopqrstuvwxyz\u{e4}\u{f6}\u{f1}\u{fc}\u{e0}";
const GSM_EXTENSION: &str = "\u{c}^{}\\[~]|\u{20ac}";
/// Bounded composition estimate; the selected device must check real parts.
pub fn estimate_segments(text: &str) -> Result<SegmentEstimate, Error> {
    let mut out = SegmentEstimate {
        encoding: "gsm",
        parts: 1,
        per_part: 160,
        length: 0,
        empty: text.is_empty(),
    };
    let mut septets = 0;
    for c in text.chars() {
        if c < ' ' && !matches!(c, '\n' | '\r' | '\u{c}') {
            return Err(Error::Shape);
        };
        if GSM_EXTENSION.contains(c) {
            septets += 2
        } else if GSM_DEFAULT.contains(c) {
            septets += 1
        } else {
            out.encoding = "ucs2"
        }
    }
    if out.encoding == "gsm" {
        out.length = septets;
        if septets > 160 {
            out.per_part = 153
        }
    } else {
        out.length = units(text);
        out.per_part = if out.length <= 70 { 70 } else { 67 }
    };
    if out.length > out.per_part {
        out.parts = out.length.div_ceil(out.per_part)
    };
    if out.parts > 6 {
        return Err(Error::Shape);
    };
    Ok(out)
}
