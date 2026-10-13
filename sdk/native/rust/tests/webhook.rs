use zrotext_webhook::{VerificationError::*, verify};
const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const BODY: &[u8] = br#"{"event":"test"}"#;
const SIG: &str = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405";
#[test]
fn server_vector_and_inclusive_symmetric_window() {
    for now in [1_700_000_000, 1_700_000_300, 1_699_999_700] {
        assert_eq!(verify(KEY, "1700000000", SIG, BODY, now, 300), Ok(()));
    }
    for now in [1_700_000_301, 1_699_999_699, u64::MAX] {
        assert_eq!(
            verify(KEY, "1700000000", SIG, BODY, now, 300),
            Err(TimestampOutOfWindow)
        );
    }
}
#[test]
fn exact_body_key_and_timestamp_are_bound() {
    for (key, ts, body) in [
        (KEY, "1700000000", b"{}".as_slice()),
        (b"wrong".as_slice(), "1700000000", BODY),
        (KEY, "1700000001", BODY),
    ] {
        assert_eq!(
            verify(key, ts, SIG, body, 1_700_000_000, 300),
            Err(SignatureMismatch)
        );
    }
}
#[test]
fn malformed_headers_fail_closed() {
    for ts in [
        "",
        "01700000000",
        "1700000000.0",
        "-1",
        "1e9",
        "1700000000\n",
        "99999999999999999",
        "nonascii",
    ] {
        assert_eq!(
            verify(KEY, ts, SIG, BODY, 1_700_000_000, 300),
            Err(BadTimestamp)
        );
    }
    for sig in [
        "",
        "v1=aa",
        &SIG.to_uppercase(),
        &format!("{SIG}\n"),
        &format!("v2={}", &SIG[3..]),
    ] {
        assert_eq!(
            verify(KEY, "1700000000", sig, BODY, 1_700_000_000, 300),
            Err(BadSignatureFormat)
        );
    }
}
