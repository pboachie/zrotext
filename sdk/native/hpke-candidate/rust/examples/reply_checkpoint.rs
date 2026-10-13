use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    original_checkpoint::OriginalReplyCheckpoint,
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

    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--crash" {
        let mut c = rusqlite::Connection::open(&args[2]).unwrap();
        let tx = c.transaction().unwrap();
        tx.execute("UPDATE state SET comparison=12000", []).unwrap();
        tx.execute("DELETE FROM manifests WHERE version=2", [])
            .unwrap();
        std::process::exit(19);
    }
    if args.len() == 3 && args[1] == "--reopen" {
        let j = OriginalReplyCheckpoint::open(&args[2], &b("rootPin"), &b("fingerprint"), &scope)
            .unwrap();
        j.snapshot(&scope, 11000).unwrap();
        assert!(j.snapshot(&scope, 10000).is_err());
        return;
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "zrotext-reply-checkpoint-{:x}",
        u128::from_le_bytes(random)
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("reply.db");
    let open = || OriginalReplyCheckpoint::open(&path, &b("rootPin"), &b("fingerprint"), &scope);
    assert!(open().is_err());
    assert!(
        OriginalReplyCheckpoint::create(
            &path,
            &b("rootPin"),
            &b("fingerprint"),
            &scope,
            &[&active],
            10000
        )
        .is_err()
    );
    let j = OriginalReplyCheckpoint::create(
        &path,
        &b("rootPin"),
        &b("fingerprint"),
        &scope,
        &[&prior, &active],
        10000,
    )
    .unwrap();
    assert!(
        OriginalReplyCheckpoint::create(
            &path,
            &b("rootPin"),
            &b("fingerprint"),
            &scope,
            &[&prior, &active],
            10000
        )
        .is_err()
    );
    let mut wrong = scope.clone();
    wrong.connector[0] ^= 1;
    assert!(
        OriginalReplyCheckpoint::open(&path, &b("rootPin"), &b("fingerprint"), &wrong).is_err()
    );
    let mut badpin = b("rootPin");
    badpin[5] ^= 1;
    assert!(OriginalReplyCheckpoint::open(&path, &badpin, &b("fingerprint"), &scope).is_err());
    let s = j.snapshot(&scope, 10000).unwrap();
    assert_eq!((s.revision, s.history.len()), (1, 2));
    assert!(
        j.accept(
            &scope,
            &[&prior, &active, &successor],
            1,
            11000,
            |_, _| Err(zrotext_hpke_candidate::journal::JournalError::Refused)
        )
        .is_err()
    );
    let s = j.snapshot(&scope, 10000).unwrap();
    assert_eq!((s.revision, s.history.len()), (1, 2));
    let s = j
        .accept(&scope, &[&prior, &active, &successor], 1, 10000, |_, _| {
            Ok(11000)
        })
        .unwrap();
    assert_eq!((s.revision, s.comparison, s.history.len()), (2, 11000, 3));
    assert!(
        j.accept(&scope, &[&prior, &active, &revoked], 2, 11000, |_, n| Ok(n))
            .is_err()
    );
    assert!(
        j.accept(&scope, &[&prior, &active], 2, 11000, |_, n| Ok(n))
            .is_err()
    );
    assert!(matches!(
        j.accept(&scope, &[&prior, &active, &successor], 1, 11000, |_, n| Ok(
            n
        )),
        Err(zrotext_hpke_candidate::journal::JournalError::Conflict)
    ));
    drop(j);
    let j = open().unwrap();
    let child = |mode: &str| {
        use std::io::Write;
        let mut p = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(mode)
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        p.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        p.wait().unwrap()
    };
    assert!(child("--reopen").success());
    let other = open().unwrap();
    let barrier = std::sync::Barrier::new(2);
    let compete = |db: &OriginalReplyCheckpoint| {
        barrier.wait();
        db.accept(&scope, &[&prior, &active, &successor], 2, 11000, |_, n| {
            Ok(n)
        })
    };
    let (a, z) = std::thread::scope(|threads| {
        let a = threads.spawn(|| compete(&j));
        let z = threads.spawn(|| compete(&other));
        (a.join().unwrap(), z.join().unwrap())
    });
    assert_eq!(usize::from(a.is_ok()) + usize::from(z.is_ok()), 1);
    assert!(
        matches!(
            a,
            Err(zrotext_hpke_candidate::journal::JournalError::Conflict)
        ) || matches!(
            z,
            Err(zrotext_hpke_candidate::journal::JournalError::Conflict)
        )
    );
    assert_eq!(child("--crash").code(), Some(19));
    let state = j.snapshot(&scope, 11000).unwrap();
    assert_eq!(state.comparison, 11000);
    let selection = verify_original_reply_selection02(
        &b("selection"),
        &b("approval"),
        &b("installation"),
        &state.history[1],
        10000,
        &scope,
    )
    .unwrap();
    let current = || {
        let snap = j
            .snapshot(&scope, 11000)
            .map_err(|_| zrotext_hpke_candidate::Error::Authentication)?;
        j.accept(
            &scope,
            &snap.history.iter().collect::<Vec<_>>(),
            snap.revision,
            11000,
            |_, n| Ok(n),
        )
        .map_err(|_| zrotext_hpke_candidate::Error::Authentication)?;
        Ok(OriginalAuthority {
            scope: scope.clone(),
            revision: "synthetic-current".into(),
            now: 11000,
            expires: 19000,
            manifest: &state.history[2],
        })
    };
    let value = open_software_original_reply02(
        &b("inbound"),
        &OriginalRead {
            event: b("event").try_into().unwrap(),
            scope: &scope,
            historical: &state.history[1],
            selection: &selection,
        },
        &b("originalScalar"),
        current,
    )
    .unwrap();
    assert_eq!(value.as_str(), f["text"].as_str().unwrap());
    drop(j);
    drop(other);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute(
            "UPDATE manifests SET signed=zeroblob(length(signed)) WHERE version=2",
            [],
        )
        .unwrap();
    }
    assert!(open().is_err());
    std::fs::remove_dir_all(dir).unwrap();
    println!(
        "Original checkpoint restart, CAS, crash rollback, scope, signed-history and restored reader passed"
    );
}
