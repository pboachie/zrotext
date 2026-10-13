use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    election::{
        ElectionEvidence, ElectionRecord, require_current_election03, verify_accepted_election03,
    },
    manifest::{enroll_root, verify_manifest},
};
fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let f: serde_json::Value = serde_json::from_str(&text).unwrap();
    let b = |name: &str| STANDARD.decode(f[name].as_str().unwrap()).unwrap();
    let record = |name: &str| {
        let mut r = ElectionRecord::default();
        for (k, v) in f[name].as_object().unwrap() {
            if let Some(s) = v.as_str() {
                r.bytes.insert(k.clone(), STANDARD.decode(s).unwrap());
            } else {
                r.numbers.insert(k.clone(), v.as_u64().unwrap());
            }
        }
        r
    };
    let root = enroll_root(&b("rootPin"), &b("fingerprint")).unwrap();
    let prior = verify_manifest(&b("signed02"), &root, None, 2, 10000).unwrap();
    let verify = |bundle: &[u8], core: &[u8], a: &ElectionRecord| {
        verify_accepted_election03(ElectionEvidence {
            bundle,
            expected_core: core,
            accepted: a,
            predecessor: &prior,
            signed02: &b("signed02"),
            signed03: &b("signed03"),
            device_point: &b("deviceSigningPoint"),
            owner_point: &b("ownerApprovalPoint"),
        })
    };
    let proof = verify(&b("bundle"), &b("core"), &record("accepted")).unwrap();
    require_current_election03(
        &proof,
        proof.accepted_manifest(),
        &record("authority"),
        30000,
    )
    .unwrap();
    let mut count = 1;
    for name in record("accepted").bytes.keys() {
        if name == "newBindingId" {
            continue;
        }
        let mut a = record("accepted");
        a.bytes.get_mut(name).unwrap()[0] ^= 1;
        assert!(verify(&b("bundle"), &b("core"), &a).is_err());
        count += 1;
    }
    for name in record("accepted").numbers.keys() {
        let mut a = record("accepted");
        a.numbers.insert(name.clone(), 0);
        assert!(verify(&b("bundle"), &b("core"), &a).is_err());
        count += 1;
    }
    for name in record("authority").bytes.keys() {
        let mut a = record("authority");
        a.bytes.get_mut(name).unwrap()[0] ^= 1;
        assert!(require_current_election03(&proof, proof.accepted_manifest(), &a, 30000).is_err());
        count += 1;
    }
    for name in record("authority").numbers.keys() {
        let mut a = record("authority");
        a.numbers.insert(name.clone(), 0);
        assert!(require_current_election03(&proof, proof.accepted_manifest(), &a, 30000).is_err());
        count += 1;
    }
    for at in [500, 564] {
        let mut bundle = b("bundle");
        bundle[at] ^= 1;
        let mut a = record("accepted");
        a.bytes.insert(
            "electionBundleSha256".into(),
            Sha256::digest(&bundle).to_vec(),
        );
        assert!(verify(&bundle, &b("core"), &a).is_err());
        count += 1;
    }
    for now in [
        0,
        9999,
        record("authority").numbers["permissionExpiresAtMs"],
        0x8000000000000000,
    ] {
        assert!(
            require_current_election03(
                &proof,
                proof.accepted_manifest(),
                &record("authority"),
                now
            )
            .is_err()
        );
        count += 1;
    }
    let mut a = record("accepted");
    a.bytes.insert("extra".into(), vec![0; 16]);
    assert!(verify(&b("bundle"), &b("core"), &a).is_err());
    count += 1;

    use zrotext_hpke_candidate::elected_reader::{ElectedContext, open_software_elected03};
    let message: [u8; 16] = b("message").try_into().unwrap();
    let context = ElectedContext {
        message: &message,
        peer: "+12",
        now: 30000,
    };
    let opened = open_software_elected03(
        &b("envelope"),
        proof.accepted_manifest(),
        &proof,
        &record("authority"),
        &b("readerScalar"),
        &context,
    )
    .unwrap();
    assert_eq!(opened.as_str(), f["bodyText"].as_str().unwrap());
    count += 1;
    let raw = b("envelope");
    for i in 0..raw.len() {
        let mut mutated = raw.clone();
        mutated[i] ^= 1;
        assert!(
            open_software_elected03(
                &mutated,
                proof.accepted_manifest(),
                &proof,
                &record("authority"),
                &b("readerScalar"),
                &context
            )
            .is_err()
        );
    }
    let mut wrong_message = message;
    wrong_message[0] ^= 1;
    let wrong = ElectedContext {
        message: &wrong_message,
        peer: "+12",
        now: 30000,
    };
    assert!(
        open_software_elected03(
            &raw,
            proof.accepted_manifest(),
            &proof,
            &record("authority"),
            &b("readerScalar"),
            &wrong
        )
        .is_err()
    );
    count += 1;
    let wrong = ElectedContext {
        message: &message,
        peer: "+13",
        now: 30000,
    };
    assert!(
        open_software_elected03(
            &raw,
            proof.accepted_manifest(),
            &proof,
            &record("authority"),
            &b("readerScalar"),
            &wrong
        )
        .is_err()
    );
    count += 1;
    println!("native accepted/current election {count} controls passed");
}
