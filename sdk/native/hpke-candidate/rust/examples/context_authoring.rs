use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Read;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::sync_channel,
    },
    time::{Duration, Instant},
};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    owner_template::{context::authoring::*, *},
};
fn b(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
// Lone surrogate escapes cannot form UTF-8; the maintained JSON layers
// replace them with U+FFFD, so rewrite them before parsing.
fn sanitize_surrogates(input: &str) -> String {
    let raw = input.as_bytes();
    let escape_at = |at: usize| -> Option<u16> {
        (at + 6 <= raw.len() && raw[at] == b'\\' && raw[at + 1] == b'u')
            .then(|| u16::from_str_radix(std::str::from_utf8(&raw[at + 2..at + 6]).ok()?, 16).ok())
            .flatten()
    };
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if let Some(v) = escape_at(i) {
            if (0xD800..=0xDBFF).contains(&v) {
                let paired = escape_at(i + 6).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo));
                if paired {
                    out.extend_from_slice(&raw[i..i + 12]);
                    i += 12;
                } else {
                    out.extend_from_slice(b"\\uFFFD");
                    i += 6;
                }
                continue;
            }
            if (0xDC00..=0xDFFF).contains(&v) {
                out.extend_from_slice(b"\\uFFFD");
                i += 6;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}
fn main() {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).unwrap();
    let input: Value = serde_json::from_str(&sanitize_surrogates(&raw)).unwrap();
    let f = &input["Fixture"];
    let root = enroll_root(&b(&f["rootPin"]), &b(&f["fingerprint"])).unwrap();
    let manifest = Arc::new(verify_manifest(&b(&f["manifest"]), &root, None, 2, 10000).unwrap());
    let v = &f["binding"];
    let binding = OwnerBinding {
        account: b(&v["account"]).try_into().unwrap(),
        device: b(&v["device"]).try_into().unwrap(),
        line: b(&v["line"]).try_into().unwrap(),
        interval: b(&v["interval"]).try_into().unwrap(),
        session: b(&v["session"]).try_into().unwrap(),
        generation: v["generation"].as_u64().unwrap(),
        peer: v["peer"].as_str().unwrap().into(),
        phone_reader: b(&v["phoneReader"]).try_into().unwrap(),
        archive_reader: b(&v["archiveReader"]).try_into().unwrap(),
    };
    let context: [u8; 16] = b(&f["scope"]["contextId"]).try_into().unwrap();
    let now = f["now"].as_u64().unwrap();
    let expires = f["scope"]["expiresMs"].as_u64().unwrap();
    let currents = Arc::new(AtomicUsize::new(0));
    let sessions = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Mutex::new((
        input["CSRF"].as_str().unwrap().to_string(),
        input["Revision"].as_u64().unwrap_or(1),
    )));
    let c = currents.clone();
    let a = input.clone();
    let bind = binding.clone();
    let current: AuthoringCurrentSource = Arc::new(move || {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        if n as u64 == a["CurrentFailAt"].as_u64().unwrap_or(0) {
            return Err(OwnerError::OwnerChanged);
        }
        let mut selected = bind.clone();
        if a["Mode"] == "binding" {
            selected.session[0] ^= 1
        };
        Ok(ContextAuthoringCurrent {
            binding: selected,
            manifest: manifest.clone(),
            now,
            owner_session_live: a["Mode"] != "owner-dead",
            consent_live: a["Mode"] != "consent-dead",
        })
    });
    let c = sessions.clone();
    let a = input.clone();
    let state = shared.clone();
    let session: AuthoringSessionSource = Arc::new(move || {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        let mut csrf = state.lock().unwrap().0.clone();
        if n as u64 == a["SessionChangeAt"].as_u64().unwrap_or(0) {
            csrf.push_str("-changed")
        };
        Ok(OwnerSession {
            origin: a["Origin"].as_str().unwrap().into(),
            cookie: a["Cookie"].as_str().unwrap().into(),
            csrf,
        })
    });
    let state = shared.clone();
    let revision_default = input["Revision"].as_u64().unwrap_or(1);
    let epoch_default = input["Epoch"].as_u64().unwrap_or(1);
    let draft: AuthoringDraftSource = Arc::new(move || {
        let revision = state.lock().unwrap().1;
        Ok(ContextDraftState {
            epoch: epoch_default,
            revision,
            custody_live: true,
        })
    });
    let (entered, entered_wait) = sync_channel(1);
    let (release, release_wait) = sync_channel::<()>(1);
    let release_wait = Arc::new(Mutex::new(release_wait));
    let reviews = Arc::new(AtomicUsize::new(0));
    let count = reviews.clone();
    let a = input.clone();
    let state = shared.clone();
    let review: AuthoringReviewer = Arc::new(move |_: &ContextAuthoringReview| {
        let _ = count.fetch_add(1, Ordering::SeqCst);
        if a["ReviewBlock"] == true {
            let _ = entered.send(());
            let _ = release_wait.lock().unwrap().recv();
        }
        if a["ReviewFail"] == true {
            return Ok(false);
        }
        let mut guard = state.lock().unwrap();
        if a["Rotate"] == true {
            guard.0.push_str("-rotated");
        }
        if a["DraftChange"] == true {
            guard.1 += 1;
        }
        Ok(true)
    });
    let authoring = OwnerContextAuthoring::new(ContextAuthoringOptions {
        origin: input["Origin"].as_str().unwrap().into(),
        binding,
        context,
        expires,
        enabled: input["Enabled"].as_bool().unwrap(),
        timeout: Duration::from_millis(input["TimeoutMS"].as_u64().unwrap_or(4000)),
        observation: Duration::from_millis(input["ValidForMS"].as_u64().unwrap_or(10000)),
        additional_roots: input["Roots"].as_str().unwrap().as_bytes().to_vec(),
        current,
        session,
        draft,
        review,
    })
    .ok();
    let epoch = input["Epoch"].as_u64().unwrap_or(1);
    let revision = revision_default;
    let text = input["Text"]
        .as_str()
        .unwrap_or("Synthetic reviewed facts 🌱")
        .to_string();
    let start = Instant::now();
    let mut results = vec![];
    for (i, op) in input["Ops"].as_array().unwrap().iter().enumerate() {
        std::thread::sleep(Duration::from_millis(
            input["DelayMS"][i].as_u64().unwrap_or(0),
        ));
        let mut row = json!({"phase":"closed","pending":false,"source":false,"reviews":0});
        match op.as_str().unwrap() {
            "author" => {
                if let Some(authoring) = &authoring {
                    row["phase"] = json!(authoring.author(&text, epoch, revision).phase);
                }
            }
            "retry" => {
                if let Some(authoring) = &authoring {
                    row["phase"] = json!(authoring.retry_unknown().phase);
                }
            }
            "verify" => {
                if let Some(authoring) = &authoring {
                    row["phase"] = json!(authoring.verify_unknown().phase);
                }
            }
            "close" => {
                if let Some(authoring) = &authoring {
                    authoring.close()
                }
            }
            "author-close-review" => {
                let blocked = authoring.clone().unwrap();
                let text = text.clone();
                let worker_author = blocked.clone();
                let worker =
                    std::thread::spawn(move || worker_author.author(&text, epoch, revision).phase);
                entered_wait
                    .recv_timeout(Duration::from_secs(3))
                    .expect("review not entered");
                blocked.close();
                let _ = release.send(());
                row["phase"] = json!(worker.join().unwrap());
            }
            _ => panic!("bad operation"),
        }
        if let Some(authoring) = &authoring {
            let state = authoring.state();
            row["phase"] = json!(state.phase);
            row["pending"] = json!(state.pending.is_some());
            row["source"] = json!(authoring.saved_source().is_some());
        }
        row["reviews"] = json!(reviews.load(Ordering::SeqCst));
        results.push(row);
    }
    let elapsed = start.elapsed().as_secs_f64();
    if let Some(authoring) = &authoring {
        authoring.close()
    };
    std::thread::sleep(Duration::from_millis(
        input["SettleMS"].as_u64().unwrap_or(0),
    ));
    println!(
        "{}",
        json!({"results":results,"elapsed":elapsed,"currentCalls":currents.load(Ordering::SeqCst),"sessionCalls":sessions.load(Ordering::SeqCst),"reviewCalls":reviews.load(Ordering::SeqCst)})
    );
}
