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
    original_http::OriginalHttp,
    original_page::OriginalReplyCursor,
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
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let dir =
        std::env::temp_dir().join(format!("zrotext-current-{:x}", u128::from_le_bytes(random)));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("reply.db");
    let checkpoint = Arc::new(
        OriginalReplyCheckpoint::create(
            &path,
            &b("rootPin"),
            &b("fingerprint"),
            &scope,
            &[&prior, &active],
            10000,
        )
        .unwrap(),
    );
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
    let times = v["Clock"].as_array().unwrap();
    let at = AtomicUsize::new(0);
    let cursor = if v["Cursor"].is_null() {
        None
    } else {
        Some(OriginalReplyCursor {
            accepted_at_ms: v["Cursor"]["AcceptedAt"].as_u64().unwrap(),
            event: serde_json::from_value(v["Cursor"]["Event"].clone()).unwrap(),
        })
    };
    let result = client.page(
        v["Grant"].as_str().unwrap(),
        cursor,
        v["Limit"].as_u64().unwrap().try_into().unwrap(),
        || {
            let index = at.fetch_add(1, Ordering::SeqCst);
            if v["Conflict"] == true && index == 2 {
                let saved = checkpoint.snapshot(&scope, 10000).unwrap();
                checkpoint
                    .accept(
                        &scope,
                        &saved.history.iter().collect::<Vec<_>>(),
                        saved.revision,
                        10000,
                        |_, n| Ok(n),
                    )
                    .unwrap();
            }
            times[index.min(times.len() - 1)].as_u64().unwrap()
        },
    );
    let mut out = serde_json::json!({"ok":result.is_ok()});
    if let Ok(current) = result {
        let a = current.authority.authority();
        let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
        out["events"]=current.events.iter().map(|r|serde_json::json!({"event":hex(&r.event),"at":r.accepted_at_ms,"observed":r.observed_at_ms,"historical":r.historical_manifest_version,"activation":r.activation_manifest_version,"disposition":r.disposition,"requests":r.active_request_ids.iter().map(|v|hex(v)).collect::<Vec<_>>()})).collect::<Vec<_>>().into();
        out["next"] = current
            .next
            .map(|c| serde_json::json!({"event":hex(&c.event),"at":c.accepted_at_ms}))
            .unwrap_or(serde_json::Value::Null);
        out["now"] = a.now.into();
        out["version"] = a.manifest.version().into()
    }
    if v["Retry"] == true {
        out["stale_refused"] = client
            .current(v["Grant"].as_str().unwrap(), || 10000)
            .is_err()
            .into()
    }
    drop(client);
    drop(checkpoint);
    let checkpoint =
        OriginalReplyCheckpoint::open(&path, &b("rootPin"), &b("fingerprint"), &scope).unwrap();
    let saved = checkpoint.snapshot(&scope, 50000).unwrap();
    out["revision"] = saved.revision.into();
    out["floor"] = saved.comparison.into();
    out["history"] = saved.history.len().into();
    out["rollback_refused"] = checkpoint
        .snapshot(&scope, saved.comparison - 1)
        .is_err()
        .into();
    drop(checkpoint);
    std::fs::remove_dir_all(dir).unwrap();
    println!("{out}");
}
