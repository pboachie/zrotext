use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    original_reply::{
        OriginalAuthority, OriginalRead, OriginalScope, open_software_original_reply02,
        verify_original_reply_selection02,
    },
};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let f: serde_json::Value = serde_json::from_str(&input).unwrap();
    let b = |name: &str| STANDARD.decode(f[name].as_str().unwrap()).unwrap();
    let root = enroll_root(&b("rootPin"), &b("fingerprint")).unwrap();
    let prior = verify_manifest(&b("predecessor"), &root, None, 2, 10000).unwrap();
    let active = verify_manifest(&b("activation"), &root, Some(&prior), 2, 10000).unwrap();
    let successor = verify_manifest(&b("successor"), &root, Some(&active), 2, 10000).unwrap();
    let revoked = verify_manifest(&b("revoked"), &root, Some(&active), 2, 10000).unwrap();
    let scope = OriginalScope {
        account: b("account").try_into().unwrap(),
        device: b("device").try_into().unwrap(),
        line: b("line").try_into().unwrap(),
        interval: b("interval").try_into().unwrap(),
        connector: b("connector").try_into().unwrap(),
        read_grant: b("readGrant").try_into().unwrap(),
        reader: b("originalReader").try_into().unwrap(),
        peer: "+12".into(),
    };
    let event = b("event").try_into().unwrap();
    let mut raw = b("selection");
    let mut approval = b("approval");
    let mut installation = b("installation");
    let selection =
        verify_original_reply_selection02(&raw, &approval, &installation, &active, 10000, &scope)
            .unwrap();
    for i in 0..raw.len() {
        let mut bad = raw.clone();
        bad[i] ^= 1;
        assert!(
            verify_original_reply_selection02(
                &bad,
                &approval,
                &installation,
                &active,
                10000,
                &scope
            )
            .is_err()
        );
    }
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let order: Vec<u8> = order
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    for which in [false, true] {
        let mut sig = if which {
            installation.clone()
        } else {
            approval.clone()
        };
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let n = i16::from(order[i]) - i16::from(sig[32 + i]) - borrow;
            sig[32 + i] = n as u8;
            borrow = i16::from(n < 0);
        }
        let (a, z) = if which {
            (&approval, &sig)
        } else {
            (&sig, &installation)
        };
        assert!(verify_original_reply_selection02(&raw, a, z, &active, 10000, &scope).is_err());
    }
    for now in [0, 20000, u64::MAX] {
        assert!(
            verify_original_reply_selection02(&raw, &approval, &installation, &active, now, &scope)
                .is_err()
        );
    }
    assert!(
        verify_original_reply_selection02(&raw, &approval, &installation, &prior, 10000, &scope)
            .is_err()
    );
    let mut wrong = scope.clone();
    wrong.connector[0] ^= 1;
    assert!(
        verify_original_reply_selection02(&raw, &approval, &installation, &active, 10000, &wrong)
            .is_err()
    );
    let read = OriginalRead {
        event,
        scope: &scope,
        historical: &active,
        selection: &selection,
    };
    for m in [&active, &successor] {
        let mut calls = 0;
        let value =
            open_software_original_reply02(&b("inbound"), &read, &b("originalScalar"), || {
                calls += 1;
                Ok(OriginalAuthority {
                    scope: scope.clone(),
                    revision: "1".into(),
                    now: 10000,
                    expires: 20000,
                    manifest: m,
                })
            })
            .unwrap();
        assert_eq!(value.as_str(), f["text"].as_str().unwrap());
        assert_eq!(calls, 2);
    }
    for mutation in 0..7 {
        let mut calls = 0;
        let result =
            open_software_original_reply02(&b("inbound"), &read, &b("originalScalar"), || {
                calls += 1;
                let mut a = OriginalAuthority {
                    scope: scope.clone(),
                    revision: "1".into(),
                    now: 10000,
                    expires: 20000,
                    manifest: &active,
                };
                if calls == 2 {
                    match mutation {
                        0 => a.revision = "2".into(),
                        1 => a.now = 9999,
                        2 => a.now = 20000,
                        3 => a.expires = 10000,
                        4 => a.scope.read_grant[0] ^= 1,
                        5 => a.manifest = &successor,
                        _ => a.manifest = &revoked,
                    }
                }
                Ok(a)
            });
        assert!(result.is_err());
        assert_eq!(calls, 2);
    }
    for name in ["archiveOnly", "inbound"] {
        let mut calls = 0;
        let m = if name == "inbound" { &revoked } else { &active };
        assert!(
            open_software_original_reply02(&b(name), &read, &b("originalScalar"), || {
                calls += 1;
                Ok(OriginalAuthority {
                    scope: scope.clone(),
                    revision: "1".into(),
                    now: 10000,
                    expires: 20000,
                    manifest: m,
                })
            })
            .is_err()
        );
        assert_eq!(calls, 1);
    }
    let mut calls = 0;
    let mut wrong_scalar = [0; 32];
    wrong_scalar[31] = 11;
    assert!(
        open_software_original_reply02(&b("inbound"), &read, &wrong_scalar, || {
            calls += 1;
            Ok(OriginalAuthority {
                scope: scope.clone(),
                revision: "1".into(),
                now: 10000,
                expires: 20000,
                manifest: &active,
            })
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    let mut bad_event = event;
    bad_event[0] ^= 1;
    let bad_read = OriginalRead {
        event: bad_event,
        ..read
    };
    assert!(
        open_software_original_reply02(&b("inbound"), &bad_read, &b("originalScalar"), || panic!(
            "wrong event reached authority"
        ))
        .is_err()
    );
    raw[0] ^= 1;
    approval[0] ^= 1;
    installation[0] ^= 1;
    let value = open_software_original_reply02(&b("inbound"), &read, &b("originalScalar"), || {
        Ok(OriginalAuthority {
            scope: scope.clone(),
            revision: "1".into(),
            now: 10000,
            expires: 20000,
            manifest: &active,
        })
    })
    .unwrap();
    assert_eq!(value.as_str(), f["text"].as_str().unwrap());
    println!(
        "Rust native original role3 selection, maintained ciphertext, current/final refusal and immutable proof controls passed"
    );
}
