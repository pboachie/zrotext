use std::io::{self, Read};
use zrotext_hpke_candidate::manifest::{enroll_root, verify_manifest};
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
    let d: serde_json::Value = serde_json::from_str(&input).unwrap();
    let now = d["nowMs"].as_u64().unwrap();
    let pin = hex(d["rootPinHex"].as_str().unwrap());
    let fingerprint = hex(d["rootFingerprintHex"].as_str().unwrap());
    let root = enroll_root(&pin, &fingerprint).unwrap();
    let row = |name: &str| hex(d["manifests"][name]["signedHex"].as_str().unwrap());
    let p = verify_manifest(&row("prior02"), &root, None, 2, now).unwrap();
    let next = verify_manifest(&row("successor03"), &root, Some(&p), 3, now).unwrap();
    let after = verify_manifest(&row("after03"), &root, Some(&next), 3, now).unwrap();
    let alternate =
        verify_manifest(&row("alternateSignature03"), &root, Some(&next), 3, now).unwrap();
    assert_eq!(next.digest(), alternate.digest());
    assert_eq!(after.version(), 3);
    for (name, token) in [("prior02", &p), ("successor03", &next), ("after03", &after)] {
        assert_eq!(
            token.digest().as_slice(),
            hex(d["manifests"][name]["semanticDigestHex"].as_str().unwrap())
        );
    }
    for name in ["successor03", "genesis03ContractOnly"] {
        assert!(verify_manifest(&row(name), &root, None, 3, now).is_err());
    }
    for name in ["sameVersionFork03", "prior02"] {
        assert!(
            verify_manifest(
                &row(name),
                &root,
                Some(&next),
                if name == "prior02" { 2 } else { 3 },
                now
            )
            .is_err()
        );
    }
    assert!(verify_manifest(&row("after03"), &root, Some(&p), 3, now).is_err());
    assert!(verify_manifest(&row("successor03"), &root, Some(&p), 3, now - 1).is_err());
    assert!(verify_manifest(&row("successor03"), &root, Some(&p), 2, now).is_err());
    for time in [0, now + 86400001, u64::MAX] {
        assert!(verify_manifest(&row("successor03"), &root, Some(&p), 3, time).is_err());
    }
    let original = row("successor03");
    let mut captured = original.clone();
    let token = verify_manifest(&captured, &root, Some(&p), 3, now).unwrap();
    captured.fill(0);
    assert_eq!(token.signed_bytes(), original);
    for at in 0..original.len() {
        let mut bad = original.clone();
        bad[at] ^= 128;
        assert!(
            verify_manifest(&bad, &root, Some(&p), 3, now).is_err(),
            "mutation {at}"
        );
    }
    for len in [0, 4, 363, original.len() - 1] {
        assert!(verify_manifest(&original[..len], &root, Some(&p), 3, now).is_err());
    }
    let mut extra = original.clone();
    extra.push(0);
    assert!(verify_manifest(&extra, &root, Some(&p), 3, now).is_err());
    for at in 0..pin.len() {
        let mut bad = pin.clone();
        bad[at] ^= 128;
        assert!(enroll_root(&bad, &fingerprint).is_err());
    }
    println!(
        "manifest roots,02/03 chain,current semantic identity,fork,gap,downgrade,clock and corruption controls passed"
    );
}
