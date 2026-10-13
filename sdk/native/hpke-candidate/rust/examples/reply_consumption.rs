use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    original_checkpoint::OriginalReplyCheckpoint,
    original_current::OriginalCurrentClient,
    original_http::{HttpError, OriginalHttp},
    original_reply::OriginalScope,
};
fn main() {
    let v: serde_json::Value = serde_json::from_reader(io::stdin()).unwrap();
    let f = &v["Fixture"];
    let b = |n: &str| STANDARD.decode(f[n].as_str().unwrap()).unwrap();
    let root = enroll_root(&b("rootPin"), &b("fingerprint")).unwrap();
    let prior = verify_manifest(&b("predecessor"), &root, None, 2, 10000).unwrap();
    let active = verify_manifest(&b("activation"), &root, Some(&prior), 2, 10000).unwrap();
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
    let folder = std::path::Path::new(v["Directory"].as_str().unwrap());
    let path = folder.join("reply.db");
    let checkpoint = Arc::new(if v["Resume"] == true {
        OriginalReplyCheckpoint::open(&path, &b("rootPin"), &b("fingerprint"), &scope).unwrap()
    } else {
        OriginalReplyCheckpoint::create(
            &path,
            &b("rootPin"),
            &b("fingerprint"),
            &scope,
            &[&prior, &active],
            10000,
        )
        .unwrap()
    });
    let transport = OriginalHttp::new(
        v["Origin"].as_str().unwrap(),
        Duration::from_secs(1),
        v["Roots"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    let client = OriginalCurrentClient::new(
        transport,
        checkpoint.clone(),
        &b("rootPin"),
        &b("fingerprint"),
        scope.clone(),
        10000,
    )
    .unwrap();
    let mut event = [0; 16];
    event.copy_from_slice(&b("event"));
    let mut request = [0; 16];
    if v["Invalid"] != true {
        request[15] = 1
    };
    let mut active = [0; 16];
    active[15] = 2;
    let file = folder.join("intent.bin");
    let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    let mut out = serde_json::json!({"ok":false,"unknown":false});
    let result = (|| {
        if v["Resume"] != true {
            let intent = client.prepare_owner_review(
                event,
                request,
                if v["Active"] == true {
                    Some(active)
                } else {
                    None
                },
            )?;
            let original = intent.bytes();
            let mut copy = intent.bytes();
            copy[0] ^= 1;
            assert_eq!(intent.bytes(), original);
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)
                .unwrap();
            f.write_all(&original).unwrap();
            f.sync_all().unwrap();
        }
        let mut raw = std::fs::read(&file).unwrap();
        let corrupt = v["Corrupt"].as_i64().unwrap();
        if corrupt >= 0 {
            raw[usize::try_from(corrupt).unwrap()] ^= 1
        } else if corrupt == -2 {
            raw.pop();
        }
        let intent = client.restore_owner_review_intent(&raw)?;
        out["record"] = hex(&intent.bytes()).into();
        let times = v["Clock"].as_array().unwrap();
        let at = AtomicUsize::new(0);
        let clock = || {
            let index = at.fetch_add(1, Ordering::SeqCst);
            times[index.min(times.len() - 1)].as_u64().unwrap()
        };
        if v["Status"] == true {
            client.status_owner_review(v["Grant"].as_str().unwrap(), &intent, clock)
        } else {
            client.consume_owner_review(v["Grant"].as_str().unwrap(), &intent, clock)
        }
    })();
    match result {
        Ok(value) => {
            out["ok"] = true.into();
            out["event"] = hex(&value.event).into();
            out["consumption"] = hex(&value.consumption).into();
            out["active"] = value
                .active_request
                .map(|v| serde_json::Value::String(hex(&v)))
                .unwrap_or(serde_json::Value::Null);
            out["now"] = value.authority.authority().now.into();
        }
        Err(e) => {
            out["unknown"] = (e == HttpError::Unknown).into();
            out["error"] = e.to_string().into();
        }
    }
    let saved = checkpoint.snapshot(&scope, 50000).unwrap();
    out["revision"] = saved.revision.into();
    out["floor"] = saved.comparison.into();
    println!("{out}");
}
