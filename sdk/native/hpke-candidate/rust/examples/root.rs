use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    process::{Command, Stdio},
};
use zrotext_hpke_candidate::{
    journal::{Journal, JournalError},
    manifest::{enroll_root, verify_manifest, verify_root_transition02},
    reader::{ArchiveContext, open_software_archive02},
};
fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let f: serde_json::Value = serde_json::from_str(&text).unwrap();
    let b = |n: &str| STANDARD.decode(f[n].as_str().unwrap()).unwrap();
    let roots = BTreeMap::from([(2, b("newPoint").try_into().unwrap())]);
    let open = |p: &std::path::Path| {
        Journal::open_with_transitions(p, &b("rootPin"), &b("fingerprint"), &roots).unwrap()
    };
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 {
        let path = std::path::Path::new(&args[2]);
        if args[1] == "crash" {
            let mut c = rusqlite::Connection::open(path).unwrap();
            let tx = c.transaction().unwrap();
            tx.execute(
                "INSERT INTO manifests VALUES(2,11000,?1)",
                [b("newManifest")],
            )
            .unwrap();
            std::process::exit(17)
        };
        match open(path).append_transition02(&b("transition"), &b("newManifest"), 1, 11000) {
            Ok(2) => println!("committed"),
            Err(JournalError::Conflict) => println!("conflict"),
            e => panic!("child result {e:?}"),
        };
        return;
    }
    let root = enroll_root(&b("rootPin"), &b("fingerprint")).unwrap();
    let old = verify_manifest(&b("manifest"), &root, None, 2, 10000).unwrap();
    let next_root =
        verify_root_transition02(&b("transition"), &old, &b("newPoint"), 11000).unwrap();
    let next = verify_manifest(&b("newManifest"), &next_root, None, 2, 11000).unwrap();
    assert_eq!(next.generation(), 2);
    for name in ["highOld", "highNew"] {
        assert!(verify_root_transition02(&b(name), &old, &b("newPoint"), 11000).is_err());
    }
    for i in 0..343 {
        let mut bad = b("transition");
        bad[i] ^= 1;
        assert!(verify_root_transition02(&bad, &old, &b("newPoint"), 11000).is_err());
    }
    for now in [0, 9999, 90000] {
        assert!(verify_root_transition02(&b("transition"), &old, &b("newPoint"), now).is_err());
    }
    assert!(verify_root_transition02(&b("transition"), &old, &b("rootPin")[29..], 11000).is_err());
    assert!(verify_root_transition02(&b("transition"), &next, &b("newPoint"), 11000).is_err());
    assert!(verify_manifest(&b("newManifest"), &root, None, 2, 11000).is_err());
    assert!(verify_manifest(&b("manifest"), &next_root, None, 2, 11000).is_err());
    let v = |n: &str| STANDARD.decode(f["rotation"][n].as_str().unwrap()).unwrap();
    let now = f["rotation"]["now_ms"].as_u64().unwrap();
    let public = enroll_root(&v("old_root_pin_b64"), &v("old_root_fingerprint_b64")).unwrap();
    let prior = verify_manifest(&v("old_manifest_b64"), &public, None, 2, now).unwrap();
    let public_next =
        verify_root_transition02(&v("transition_b64"), &prior, &v("new_root_point_b64"), now)
            .unwrap();
    verify_manifest(&v("new_manifest_b64"), &public_next, None, 2, now).unwrap();
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!("zrotext-root-{:x}", u128::from_le_bytes(random)));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("checkpoint.db");
    let j = open(&path);
    assert_eq!(
        j.append_manifest(&b("manifest"), 0, 10000, None).unwrap(),
        1
    );
    drop(j);
    let child = |mode: &str| {
        let mut c = Command::new(std::env::current_exe().unwrap())
            .args([mode, path.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        c
    };
    assert_eq!(child("crash").wait().unwrap().code(), Some(17));
    assert_eq!(open(&path).snapshot(11000, None).unwrap().revision, 1);
    let a = child("race");
    let c = child("race");
    let mut values = Vec::new();
    for p in [a, c] {
        let o = p.wait_with_output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        values.push(String::from_utf8(o.stdout).unwrap());
    }
    values.sort();
    assert_eq!(values, vec!["committed\n", "conflict\n"]);
    let j = open(&path);
    let snapshot = j.snapshot(11000, None).unwrap();
    assert_eq!(snapshot.revision, 2);
    let current = snapshot.manifest.unwrap();
    assert_eq!(current.generation(), 2);
    let account = b("account");
    let device = b("device");
    let line = b("line");
    let reader = b("reader");
    let context = ArchiveContext {
        account: account.as_slice().try_into().unwrap(),
        device: device.as_slice().try_into().unwrap(),
        line: line.as_slice().try_into().unwrap(),
        reader: reader.as_slice().try_into().unwrap(),
        peer: "+12",
        now: 11000,
    };
    let opened = open_software_archive02(
        &b("newInbound"),
        &current,
        &current,
        &b("archiveScalar"),
        &context,
    )
    .unwrap();
    assert_eq!(opened.as_str(), f["text"].as_str().unwrap());
    assert!(
        open_software_archive02(&b("inbound"), &old, &current, &b("archiveScalar"), &context)
            .is_err()
    );
    assert_eq!(
        j.append_manifest(&b("newSuccessor"), 2, 11000, None)
            .unwrap(),
        3
    );
    let latest = j.snapshot(11000, None).unwrap().manifest.unwrap();
    assert_eq!(
        open_software_archive02(
            &b("newInbound"),
            &current,
            &latest,
            &b("archiveScalar"),
            &context
        )
        .unwrap()
        .as_str(),
        f["text"].as_str().unwrap()
    );
    assert!(j.snapshot(10999, None).is_err());
    drop(j);
    let plain = Journal::open(&path, &b("rootPin"), &b("fingerprint")).unwrap();
    assert!(plain.snapshot(11000, None).is_err());
    drop(plain);
    let wrong = Journal::open_with_transitions(
        &path,
        &b("rootPin"),
        &b("fingerprint"),
        &BTreeMap::from([(2, [0; 65])]),
    )
    .unwrap();
    assert!(wrong.snapshot(11000, None).is_err());
    drop(wrong);
    let c = rusqlite::Connection::open(&path).unwrap();
    let mut bad = b("transition");
    bad[215] ^= 1;
    c.execute("UPDATE transitions SET signed=?1", [bad])
        .unwrap();
    drop(c);
    let j = open(&path);
    assert!(j.snapshot(11000, None).is_err());
    drop(j);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE transitions SET signed=?1", [b("transition")])
        .unwrap();
    c.pragma_update(None, "user_version", 1).unwrap();
    drop(c);
    assert!(
        Journal::open_with_transitions(&path, &b("rootPin"), &b("fingerprint"), &roots).is_err()
    );
    std::fs::remove_dir_all(dir).unwrap();
    println!(
        "Rust root transitions, public vectors, atomic crash/CAS restore and current reader passed"
    );
}
