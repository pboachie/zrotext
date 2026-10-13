use std::io::{self, Read};
use zrotext_hpke_candidate::envelope::verify_envelope;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn main() {
    let mut input = String::new();
    io::stdin()
        .take(1_000_001)
        .read_to_string(&mut input)
        .unwrap();
    assert!(input.len() <= 1_000_000);
    let mut rows = 0;
    let mut previous = String::new();
    let mut index = 0;
    for line in input.lines() {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 9);
        if f[0] != previous {
            index = 0;
            previous = f[0].into();
        }
        let mut b = hex(f[2]);
        let signer = hex(f[3]);
        let profile = f[1].parse::<u8>().unwrap();
        assert!(verify_envelope(&b, &signer, 5 - profile).is_err());
        let token = verify_envelope(&b, &signer, profile).unwrap();
        assert_eq!(token.body_aad(), hex(f[4]));
        let (info, aad) = token.wrap_transcript(index).unwrap();
        assert_eq!(info, hex(f[7]));
        assert_eq!(aad, hex(f[8]));
        assert!(token.wrap_transcript(8).is_err());
        let digest = token.unsigned_digest();
        let original = b.clone();
        if profile == 3 {
            let mut zero = b.clone();
            zero[26..42].fill(0);
            assert!(matches!(
                verify_envelope(&zero, &signer, profile),
                Err(zrotext_hpke_candidate::Error::Shape)
            ));
        }
        b.fill(0);
        assert_eq!(token.unsigned_digest(), digest);
        let mut high = original.clone();
        let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let start = high.len() - 32;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let delta = order[i] as i16 - high[start + i] as i16 - borrow;
            high[start + i] = delta as u8;
            borrow = i16::from(delta < 0);
        }
        assert!(verify_envelope(&high, &signer, profile).is_err());
        for at in 0..original.len() {
            let mut bad = original.clone();
            bad[at] ^= 0x80;
            assert!(
                verify_envelope(&bad, &signer, profile).is_err(),
                "mutation {at}"
            );
        }
        for len in [0, 10, 425, original.len() - 1] {
            assert!(verify_envelope(&original[..len], &signer, profile).is_err());
        }
        let mut extra = original.clone();
        extra.push(0);
        assert!(verify_envelope(&extra, &signer, profile).is_err());
        let mut wrong = signer.clone();
        wrong[0] = 2;
        assert!(verify_envelope(&original, &wrong, profile).is_err());
        rows += 1;
        index += 1;
    }
    assert_eq!(rows, 6);
    println!("6 envelope rows plus syntax/signature/alias negatives passed");
}
