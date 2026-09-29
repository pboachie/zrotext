// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn text(bytes: &[u8]) -> Result<&str, BodyTextError> {
    validate_body_text(bytes)
}

#[test]
fn accepts_one_byte_and_multibyte_strict_utf8() {
    assert_eq!(text(b"A").ok(), Some("A"));
    assert_eq!(text("Ā".as_bytes()).ok(), Some("Ā"));
    assert_eq!(text("😀".as_bytes()).ok(), Some("😀"));
    assert_eq!(text(&[0x41, 0xef, 0xbb, 0xbf]).ok(), Some("A\u{feff}"));
}

#[test]
fn rejects_empty_and_overlength_bodies() {
    assert_eq!(text(&[]), Err(BodyTextError::Length));
    let exact = vec![b'x'; MAX_BODY_TEXT_BYTES];
    let opened = text(&exact).expect("the exact bound opens");
    assert_eq!(opened.len(), MAX_BODY_TEXT_BYTES);
    assert!(opened.chars().all(|c| c == 'x'));
    let over = vec![b'x'; MAX_BODY_TEXT_BYTES + 1];
    assert_eq!(text(&over), Err(BodyTextError::Length));
}

#[test]
fn rejects_nul_and_leading_bom() {
    assert_eq!(text(&[0x41, 0x00, 0x42]), Err(BodyTextError::Nul));
    assert_eq!(text(&[0x00]), Err(BodyTextError::Nul));
    assert_eq!(text(&[0xef, 0xbb, 0xbf, 0x41]), Err(BodyTextError::Bom));
}

#[test]
fn rejects_non_strict_utf8_encodings() {
    assert_eq!(text(&[0xc0, 0x80]), Err(BodyTextError::Utf8));
    assert_eq!(text(&[0xe2, 0x88]), Err(BodyTextError::Utf8));
    assert_eq!(text(&[0xed, 0xa0, 0x80]), Err(BodyTextError::Utf8));
    assert_eq!(text(&[0xf4, 0x90, 0x80, 0x80]), Err(BodyTextError::Utf8));
}

#[test]
fn length_is_checked_before_decode_so_no_early_utf8_error() {
    // An over-length body whose bytes are also invalid UTF-8 reports the
    // stable length error, not a decoding error.
    let mut over = vec![0xff; MAX_BODY_TEXT_BYTES + 1];
    over[0] = 0xef;
    assert_eq!(text(&over), Err(BodyTextError::Length));
}
