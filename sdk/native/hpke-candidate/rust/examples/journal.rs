use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::Write;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use zrotext_hpke_candidate::election::ElectionRecord;
use zrotext_hpke_candidate::journal::{ElectionExpectations, Journal, JournalError};
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

    let expected = || ElectionExpectations {
        core: b("core"),
        accepted: record("accepted"),
        device_point: b("deviceSigningPoint"),
        owner_point: b("ownerApprovalPoint"),
    };
    let open =
        |path: &std::path::Path| Journal::open(path, &b("rootPin"), &b("fingerprint")).unwrap();
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 {
        let path = std::path::Path::new(&args[2]);
        if args[1] == "crash" {
            let mut c = rusqlite::Connection::open(path).unwrap();
            let tx = c.transaction().unwrap();
            tx.execute("INSERT INTO manifests VALUES(2,10000,?1)", [b("signed03")])
                .unwrap();
            std::process::exit(17);
        }
        match open(path).append_election(&b("signed03"), &b("bundle"), 1, &expected()) {
            Ok(2) => println!("committed"),
            Err(JournalError::Conflict) => println!("conflict"),
            _ => panic!("child append"),
        };
        return;
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let dir =
        std::env::temp_dir().join(format!("zrotext-journal-{:x}", u128::from_le_bytes(random)));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("journal.db");
    let j = open(&path);
    assert_eq!(
        j.append_manifest(&b("signed02"), 0, 10000, None).unwrap(),
        1
    );
    assert!(j.append_manifest(&b("signed03"), 1, 10000, None).is_err());
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
    let j = open(&path);
    assert_eq!(j.snapshot(10000, None).unwrap().revision, 1);
    drop(j);
    let a = child("race");
    let bchild = child("race");
    let mut results = Vec::new();
    for c in [a, bchild] {
        let out = c.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        results.push(String::from_utf8(out.stdout).unwrap().trim().to_owned());
    }
    results.sort();
    assert_eq!(results, ["committed", "conflict"]);
    let j = open(&path);
    let snapshot = j.snapshot(30000, Some(&expected())).unwrap();
    assert_eq!(snapshot.revision, 2);
    use zrotext_hpke_candidate::elected_reader::{ElectedContext, open_software_elected03};
    let message: [u8; 16] = b("message").try_into().unwrap();
    let opened = open_software_elected03(
        &b("envelope"),
        snapshot.manifest.as_ref().unwrap(),
        snapshot.proof.as_ref().unwrap(),
        &record("authority"),
        &b("readerScalar"),
        &ElectedContext {
            message: &message,
            peer: "+12",
            now: 30000,
        },
    )
    .unwrap();
    assert_eq!(opened.as_str(), f["bodyText"].as_str().unwrap());
    assert!(j.snapshot(30000, None).is_err());
    for now in [0, 9999, 100000, 1 << 63] {
        assert!(j.snapshot(now, Some(&expected())).is_err());
    }
    for kind in ["core", "accepted", "device", "owner"] {
        let mut e = expected();
        match kind {
            "core" => e.core[0] ^= 1,
            "accepted" => e.accepted.bytes.get_mut("newBindingId").unwrap()[0] ^= 1,
            "device" => e.device_point[1] ^= 1,
            _ => e.owner_point[1] ^= 1,
        };
        assert!(j.snapshot(30000, Some(&e)).is_err());
    }
    assert!(matches!(
        j.append_election(&b("signed03"), &b("bundle"), 1, &expected()),
        Err(JournalError::Conflict)
    ));
    drop(j);
    let mutate = |sql: &str, value: Option<Vec<u8>>| {
        let c = rusqlite::Connection::open(&path).unwrap();
        if let Some(value) = value {
            c.execute(sql, [value]).unwrap();
        } else {
            c.execute_batch(sql).unwrap();
        }
    };
    let mut bad = b("bundle");
    bad[500] ^= 1;
    mutate("UPDATE elections SET bundle=?1", Some(bad));
    let j = open(&path);
    assert!(j.snapshot(30000, Some(&expected())).is_err());
    drop(j);
    mutate("UPDATE elections SET bundle=?1", Some(b("bundle")));
    mutate("UPDATE identity SET fingerprint=zeroblob(32)", None);
    assert!(Journal::open(&path, &b("rootPin"), &b("fingerprint")).is_err());
    mutate("UPDATE identity SET fingerprint=?1", Some(b("fingerprint")));
    mutate("PRAGMA user_version=2", None);
    assert!(Journal::open(&path, &b("rootPin"), &b("fingerprint")).is_err());
    mutate("PRAGMA user_version=1", None);
    let empty = dir.join("empty.db");
    std::fs::write(&empty, []).unwrap();
    assert!(Journal::open(&empty, &b("rootPin"), &b("fingerprint")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
    println!(
        "native journal: crash rollback, two-process CAS, actual ciphertext restore and refusal controls passed"
    );
}
