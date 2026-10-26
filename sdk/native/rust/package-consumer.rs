use zrotext_webhook::{VerificationError, verify};

#[test]
fn shared_raw_vectors_and_unsigned_clock_boundary() {
    let path = std::env::var("ZROTEXT_WEBHOOK_VECTOR_FILE").expect("pinned shared vector path");
    let rows = std::fs::read_to_string(path).unwrap();
    let mut verified = 0;
    let mut typed_refusals = 0;
    for row in rows.lines().skip(1) {
        let cells: Vec<_> = row.split('\t').collect();
        assert_eq!(cells.len(), 6);
        let now = match cells[4].parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                assert_eq!(cells[0], "clock_overflow_negative");
                assert_eq!(cells[4], "-9223372036854775808");
                typed_refusals += 1;
                continue;
            }
        };
        let body: Vec<u8> = cells[3]
            .as_bytes()
            .as_chunks::<2>().0.iter()
            .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
            .collect();
        let result = verify(
            b"0123456789abcdef0123456789abcdef",
            cells[1],
            cells[2],
            &body,
            now,
            300,
        );
        let actual = match result {
            Ok(()) => "ok",
            Err(VerificationError::BadTimestamp) => "bad_timestamp",
            Err(VerificationError::BadSignatureFormat) => "bad_signature_format",
            Err(VerificationError::TimestampOutOfWindow) => "timestamp_out_of_window",
            Err(VerificationError::SignatureMismatch) => "signature_mismatch",
        };
        assert_eq!(actual, cells[5], "{}", cells[0]);
        verified += 1;
    }
    assert_eq!((verified, typed_refusals), (16, 1));
}
