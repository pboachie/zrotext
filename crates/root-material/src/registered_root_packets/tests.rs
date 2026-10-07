use super::*;
use p256::{SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};

const ACCOUNT: [u8; 16] = [0xaa; 16];
const NOW: u64 = 1_700_000_100_000;

fn pin() -> [u8; 94] {
    let secret = SecretKey::from_slice(&Sha256::digest(b"synthetic packet root")).unwrap();
    let mut pin = [0_u8; 94];
    pin[..5].copy_from_slice(b"ZTRP\x02");
    pin[5..21].copy_from_slice(&ACCOUNT);
    pin[21..29].copy_from_slice(&1_u64.to_be_bytes());
    pin[29..].copy_from_slice(secret.public_key().to_sec1_point(false).as_bytes());
    pin
}
fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}
fn expected() -> Expected {
    Expected {
        account: ACCOUNT,
        origin: "https://account.invalid".into(),
        root_pin: pin(),
        backup_digest: digest("backup"),
        card_digest: digest("card"),
        archive_id: digest("archive"),
        issued_ms: NOW - 3_600_000,
        expires_ms: NOW + 3_600_000,
    }
}
fn packet(phase: Phase, stamp_ms: u64) -> Packet {
    let e = expected();
    Packet {
        phase,
        account: e.account,
        origin: e.origin,
        root_pin: e.root_pin,
        root_fingerprint: root_fingerprint(&e.root_pin, &e.account).unwrap(),
        backup_digest: e.backup_digest,
        card_digest: e.card_digest,
        archive_id: e.archive_id,
        issued_ms: e.issued_ms,
        expires_ms: e.expires_ms,
        stamp_ms,
        artifact_digest: match phase {
            Phase::Prepare => None,
            Phase::Custody => Some(digest("custody")),
            Phase::Manifest => Some(digest("unsigned manifest")),
        },
    }
}
fn trio() -> [Vec<u8>; 3] {
    [
        encode(&packet(Phase::Prepare, NOW - 3_000)).unwrap(),
        encode(&packet(Phase::Custody, NOW - 2_000)).unwrap(),
        encode(&packet(Phase::Manifest, NOW - 1_000)).unwrap(),
    ]
}
fn review(t: &[Vec<u8>; 3], e: &Expected, now: u64) -> Result<[Packet; 3]> {
    review_sequence(&t[0], &t[1], &t[2], e, now)
}
fn edit(bytes: &[u8], f: impl FnOnce(String) -> String) -> Vec<u8> {
    f(String::from_utf8(bytes.to_vec()).unwrap()).into_bytes()
}

#[test]
fn matched_sequence_round_trips_and_reviews() {
    let t = trio();
    let reviewed = review(&t, &expected(), NOW).unwrap();
    assert_eq!(reviewed[0], packet(Phase::Prepare, NOW - 3_000));
    for (bytes, phase) in t
        .iter()
        .zip([Phase::Prepare, Phase::Custody, Phase::Manifest])
    {
        assert_eq!(encode(&decode(bytes, phase).unwrap()).unwrap(), *bytes);
    }
}

#[test]
fn duplicate_unknown_missing_and_reordered_fields_refuse() {
    let m = &trio()[2];
    let dup = edit(m, |s| {
        s.replace("card_digest=", "backup_digest=").to_owned()
    });
    assert_eq!(decode(&dup, Phase::Manifest), Err(Refusal::Duplicate));
    let extra = edit(m, |s| format!("{s}extra=1\n"));
    assert_eq!(decode(&extra, Phase::Manifest), Err(Refusal::Unknown));
    let twice = edit(m, |s| format!("{s}signed_ms=1\n"));
    assert_eq!(decode(&twice, Phase::Manifest), Err(Refusal::Duplicate));
    let missing = edit(m, |s| {
        s.lines().take(10).map(|l| format!("{l}\n")).collect()
    });
    assert_eq!(decode(&missing, Phase::Manifest), Err(Refusal::Shape));
    let swapped = edit(m, |s| {
        let mut l: Vec<&str> = s.lines().collect();
        l.swap(2, 3);
        l.join("\n") + "\n"
    });
    assert_eq!(decode(&swapped, Phase::Manifest), Err(Refusal::Shape));
}

#[test]
fn framing_phase_and_value_shapes_refuse() {
    let m = &trio()[2];
    assert_eq!(
        decode(&m[..m.len() - 1], Phase::Manifest),
        Err(Refusal::Framing)
    );
    assert_eq!(
        decode(&edit(m, |s| s.replace('\n', "\r\n")), Phase::Manifest),
        Err(Refusal::Framing)
    );
    assert_eq!(
        decode(&[b'a'; MAX_PACKET + 1], Phase::Manifest),
        Err(Refusal::Framing)
    );
    assert_eq!(decode(b"", Phase::Manifest), Err(Refusal::Framing));
    assert_eq!(decode(m, Phase::Custody), Err(Refusal::Phase));
    assert_eq!(decode(m, Phase::Prepare), Err(Refusal::Phase));
    let upper = edit(m, |s| {
        s.replacen(&HEXLOWER.encode(&ACCOUNT), &"AA".repeat(16), 1)
    });
    assert_eq!(decode(&upper, Phase::Manifest), Err(Refusal::Value));
    let zero_pad = edit(m, |s| s.replacen("expires_ms=", "expires_ms=0", 1));
    assert_eq!(decode(&zero_pad, Phase::Manifest), Err(Refusal::Value));
    let plus = edit(m, |s| s.replacen("issued_ms=", "issued_ms=+", 1));
    assert_eq!(decode(&plus, Phase::Manifest), Err(Refusal::Value));
    let origin = edit(m, |s| {
        s.replace("https://account.invalid", "http://account.invalid")
    });
    assert_eq!(decode(&origin, Phase::Manifest), Err(Refusal::Value));
    let mut bad = packet(Phase::Manifest, NOW - 1_000);
    bad.root_fingerprint = digest("wrong fingerprint");
    assert_eq!(encode(&bad), Err(Refusal::Value));
}

#[test]
fn artifact_presence_and_reuse_refuse() {
    let mut p = packet(Phase::Prepare, NOW);
    p.artifact_digest = Some(digest("unexpected"));
    assert_eq!(encode(&p), Err(Refusal::Artifact));
    let mut c = packet(Phase::Custody, NOW);
    c.artifact_digest = None;
    assert_eq!(encode(&c), Err(Refusal::Artifact));
    c.artifact_digest = Some([0; 32]);
    assert_eq!(encode(&c), Err(Refusal::Artifact));
    let mut t = trio();
    t[1] = encode(&Packet {
        artifact_digest: Some(digest("unsigned manifest")),
        ..packet(Phase::Custody, NOW - 2_000)
    })
    .unwrap();
    assert_eq!(review(&t, &expected(), NOW), Err(Refusal::Artifact));
}

#[test]
fn every_independent_identity_field_must_match() {
    let t = trio();
    assert!(review(&t, &expected(), NOW).is_ok());
    let mut cases = Vec::new();
    let mut e = expected();
    e.account = [0xbb; 16];
    cases.push(e);
    let mut e = expected();
    e.origin = "https://other.invalid".into();
    cases.push(e);
    let mut e = expected();
    e.root_pin[93] ^= 1;
    cases.push(e);
    for f in 0..3 {
        let mut e = expected();
        [&mut e.backup_digest, &mut e.card_digest, &mut e.archive_id][f][0] ^= 1;
        cases.push(e);
    }
    let mut e = expected();
    e.issued_ms -= 1;
    cases.push(e);
    let mut e = expected();
    e.expires_ms += 1;
    cases.push(e);
    for e in cases {
        assert_eq!(review(&t, &e, NOW), Err(Refusal::Identity));
    }
    // A packet that drifts from its siblings is refused even if self-consistent.
    let mut t = trio();
    t[1] = encode(&Packet {
        archive_id: digest("other archive"),
        ..packet(Phase::Custody, NOW - 2_000)
    })
    .unwrap();
    assert_eq!(review(&t, &expected(), NOW), Err(Refusal::Identity));
}

#[test]
fn signing_times_must_be_ordered_fresh_and_within_validity() {
    let ok = |a, b, c, now| {
        review(
            &[
                encode(&packet(Phase::Prepare, a)).unwrap(),
                encode(&packet(Phase::Custody, b)).unwrap(),
                encode(&packet(Phase::Manifest, c)).unwrap(),
            ],
            &expected(),
            now,
        )
    };
    assert!(ok(NOW - 3, NOW - 2, NOW - 1, NOW).is_ok());
    assert!(ok(NOW - 3, NOW - 3, NOW - 3, NOW - 3).is_ok());
    assert_eq!(ok(NOW - 2, NOW - 3, NOW - 1, NOW), Err(Refusal::Time));
    assert_eq!(ok(NOW - 3, NOW - 1, NOW - 2, NOW), Err(Refusal::Time));
    assert_eq!(ok(NOW - 3, NOW - 2, NOW - 1, NOW - 2), Err(Refusal::Time));
    assert!(ok(NOW - 3, NOW - 2, NOW - 1, NOW - 1 + MAX_SIGNING_AGE_MS).is_ok());
    assert_eq!(
        ok(NOW - 3, NOW - 2, NOW - 1, NOW + MAX_SIGNING_AGE_MS),
        Err(Refusal::Time)
    );
    assert_eq!(
        encode(&packet(Phase::Manifest, expected().expires_ms)),
        Err(Refusal::Value)
    );
    assert_eq!(
        encode(&packet(Phase::Manifest, expected().issued_ms - 1)),
        Err(Refusal::Value)
    );
    let mut long = packet(Phase::Manifest, NOW);
    long.expires_ms = long.issued_ms + MAX_INTERVAL_MS + 1;
    assert_eq!(encode(&long), Err(Refusal::Value));
}
