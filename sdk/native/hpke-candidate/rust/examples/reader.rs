use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    reader::{ArchiveContext, open_protected_archive02, open_software_archive02},
};
fn main() {
    let mut input = String::new();
    io::stdin()
        .take(1_000_001)
        .read_to_string(&mut input)
        .unwrap();
    assert!(input.len() <= 1_000_000);
    let d: serde_json::Value = serde_json::from_str(&input).unwrap();
    let bytes = |name: &str| STANDARD.decode(d[name].as_str().unwrap()).unwrap();
    let root = enroll_root(&bytes("rootPin"), &bytes("fingerprint")).unwrap();
    let now = d["now"].as_u64().unwrap();
    let manifest = verify_manifest(&bytes("manifest"), &root, None, 2, now).unwrap();
    let account = bytes("account").try_into().unwrap();
    let device = bytes("device").try_into().unwrap();
    let line = bytes("line").try_into().unwrap();
    let reader = bytes("reader").try_into().unwrap();
    let mut c = ArchiveContext {
        account: &account,
        device: &device,
        line: &line,
        reader: &reader,
        peer: "+12",
        now,
    };
    let scalar = bytes("archiveScalar");
    let raw = bytes("inbound");
    assert_eq!(
        open_software_archive02(&raw, &manifest, &manifest, &scalar, &c)
            .unwrap()
            .as_str(),
        d["text"].as_str().unwrap()
    );
    let live = verify_manifest(&bytes("liveSuccessor"), &root, Some(&manifest), 2, now).unwrap();
    assert_eq!(
        open_software_archive02(&raw, &manifest, &live, &scalar, &c)
            .unwrap()
            .as_str(),
        d["text"].as_str().unwrap()
    );
    let rotated =
        verify_manifest(&bytes("rotatedSuccessor"), &root, Some(&manifest), 2, now).unwrap();
    assert!(open_software_archive02(&raw, &manifest, &rotated, &scalar, &c).is_err());
    assert!(matches!(
        open_software_archive02(&raw, &manifest, &rotated, &[0; 32], &c),
        Err(zrotext_hpke_candidate::Error::Authentication)
    ));
    c.peer = "+13";
    assert!(open_software_archive02(&raw, &manifest, &manifest, &scalar, &c).is_err());
    c.peer = "+12";
    for time in [0, now - 1, 100000, u64::MAX] {
        c.now = time;
        assert!(open_software_archive02(&raw, &manifest, &manifest, &scalar, &c).is_err());
    }
    c.now = now;
    let wrong = [0; 16];
    for index in 0..3 {
        let mut bad = ArchiveContext {
            account: &account,
            device: &device,
            line: &line,
            reader: &reader,
            peer: "+12",
            now,
        };
        if index == 0 {
            bad.account = &wrong
        } else if index == 1 {
            bad.device = &wrong
        } else {
            bad.line = &wrong
        };
        assert!(open_software_archive02(&raw, &manifest, &manifest, &scalar, &bad).is_err());
    }
    assert!(
        open_software_archive02(&bytes("outbound"), &manifest, &manifest, &scalar, &c).is_err()
    );
    assert!(open_software_archive02(&raw, &manifest, &manifest, &[0; 32], &c).is_err());
    assert!(open_protected_archive02().is_err());
    for at in 0..raw.len() {
        let mut bad = raw.clone();
        bad[at] ^= 128;
        assert!(
            open_software_archive02(&bad, &manifest, &manifest, &scalar, &c).is_err(),
            "corruption {at}"
        );
    }
    println!(
        "actual maintained TS inbound opens natively; routing/time/profile/custody and all-byte corruption refuse"
    );
}
