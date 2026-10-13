use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    elected_reader::{ElectedContext, open_software_elected03},
    election::{ElectionEvidence, ElectionRecord, verify_accepted_election03},
    envelope::verify_envelope,
    manifest::{enroll_root, verify_manifest},
};
fn main() {
    let mut text = String::new();
    io::stdin().take(1000001).read_to_string(&mut text).unwrap();
    assert!(text.len() <= 1000000);
    let batch: serde_json::Value = serde_json::from_str(&text).unwrap();
    let cases = batch["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for f in cases {
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
        let proof = verify_accepted_election03(ElectionEvidence {
            bundle: &b("bundle"),
            expected_core: &b("core"),
            accepted: &record("accepted"),
            predecessor: &prior,
            signed02: &b("signed02"),
            signed03: &b("signed03"),
            device_point: &b("deviceSigningPoint"),
            owner_point: &b("ownerApprovalPoint"),
        })
        .unwrap();
        let envelope = b("envelope");
        // Invalid cryptographic fixtures cannot count as expected authority refusals.
        verify_envelope(&envelope, &b("signerPoint"), 3).unwrap();
        let message: [u8; 16] = b("message").try_into().unwrap();
        let result = open_software_elected03(
            &envelope,
            proof.accepted_manifest(),
            &proof,
            &record("authority"),
            &b("readerScalar"),
            &ElectedContext {
                message: &message,
                peer: "+12",
                now: f["now"].as_u64().unwrap(),
            },
        );
        assert_eq!(
            result.is_ok(),
            f["accept"].as_bool().unwrap(),
            "{}",
            f["name"]
        );
        if let Ok(value) = result {
            assert_eq!(value.as_str(), f["bodyText"].as_str().unwrap());
        }
    }
    println!("14 authenticated native reader time-policy cases passed");
}
