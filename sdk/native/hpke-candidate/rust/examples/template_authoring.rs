use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use zrotext_hpke_candidate::{
    manifest::{enroll_root, verify_manifest},
    owner_template::save::OwnerTemplateClient,
    owner_template::save::authoring::*,
    owner_template::*,
};
fn b(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn main() {
    let input: Value = serde_json::from_reader(std::io::stdin()).unwrap();
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
    let client_slot = Arc::new(std::sync::Mutex::new(None::<OwnerTemplateClient>));
    let selected_client = client_slot.clone();
    let reviewed = Arc::new(AtomicUsize::new(0));
    let metadata = Arc::new(AtomicUsize::new(0));
    let currents = Arc::new(AtomicUsize::new(0));
    let sessions = Arc::new(AtomicUsize::new(0));
    let c = currents.clone();
    let a = input.clone();
    let bind = binding.clone();
    let rv = reviewed.clone();
    let current: CurrentSource = Arc::new(move |_| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        if n as u64 == a["ClientCloseAt"].as_u64().unwrap_or(0)
            && let Some(client) = selected_client.lock().unwrap().as_ref()
        {
            client.close()
        }
        if n as u64 == a["CurrentSleepAt"].as_u64().unwrap_or(0) {
            std::thread::sleep(Duration::from_millis(a["SleepMS"].as_u64().unwrap()))
        };
        if n as u64 == a["CurrentFailAt"].as_u64().unwrap_or(0) {
            return Err(OwnerError::OwnerChanged);
        };
        let times = a["Now"].as_array().unwrap();
        let mut selected = bind.clone();
        if a["Mode"] == "binding" {
            selected.session[0] ^= 1
        };
        Ok(OwnerAuthority {
            binding: selected,
            manifest: manifest.clone(),
            now: times[(n - 1).min(times.len() - 1)].as_u64().unwrap(),
            valid_for: Duration::from_millis(a["ValidForMS"].as_u64().unwrap()),
            owner_session_live: a["Mode"] != "owner-dead"
                && !(a["OwnerLost"] == true && rv.load(Ordering::SeqCst) > 0),
            consent_live: a["Mode"] != "consent-dead",
            active: a["Mode"] != "inactive",
        })
    });
    let c = sessions.clone();
    let a = input.clone();
    let rv = reviewed.clone();
    let session: SessionSource = Arc::new(move |_| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        let origin = if a["SessionOrigin"].as_str().unwrap_or("").is_empty() {
            a["Origin"].as_str().unwrap()
        } else {
            a["SessionOrigin"].as_str().unwrap()
        };
        let mut csrf = a["CSRF"].as_str().unwrap().to_string();
        if n as u64 == a["SessionChangeAt"].as_u64().unwrap_or(0)
            || (a["CSRFChanged"] == true && rv.load(Ordering::SeqCst) > 0)
        {
            csrf.push_str("-changed")
        };
        Ok(OwnerSession {
            origin: origin.into(),
            cookie: a["Cookie"].as_str().unwrap().into(),
            csrf,
        })
    });
    let make_options = || OwnerOptions {
        origin: input["Origin"].as_str().unwrap().into(),
        binding: binding.clone(),
        template: b(&f["scope"]["templateId"]).try_into().unwrap(),
        enabled: input["Enabled"].as_bool().unwrap(),
        timeout: Duration::from_millis(input["TimeoutMS"].as_u64().unwrap()),
        additional_roots: input["Roots"].as_str().unwrap().as_bytes().to_vec(),
        current: current.clone(),
        session: session.clone(),
    };

    let count = metadata.clone();
    let rv = reviewed.clone();
    let a = input.clone();
    let draft: DraftSource = Arc::new(move |_| {
        let changed = rv.load(Ordering::SeqCst) > 0;
        Ok(TemplateDraftState {
            epoch: if changed && a["EpochChanged"] == true {
                2
            } else {
                1
            },
            revision: if changed && a["RevisionChanged"] == true {
                2
            } else {
                1
            },
            custody_live: a["CustodyLive"] == true && !(changed && a["CustodyLost"] == true),
        })
    });
    let rv = reviewed.clone();
    let a = input.clone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let barrier_worker = barrier.clone();
    let review: DraftReviewer = Arc::new(move |_, _| {
        rv.fetch_add(1, Ordering::SeqCst);
        if a["ReviewBlock"] == true {
            barrier_worker.wait();
        }
        std::thread::sleep(Duration::from_millis(
            a["ReviewSleepMS"].as_u64().unwrap_or(0),
        ));
        Ok(a["Decision"] == true)
    });
    let author = OwnerTemplateAuthoring::new(
        make_options(),
        Arc::new(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        draft,
        review,
    )
    .unwrap();
    *client_slot.lock().unwrap() = Some(author.client());
    let wire = b(&f["envelope"]);
    let n = |at: usize| u64::from_be_bytes(wire[at..at + 8].try_into().unwrap());
    let selected = zrotext_hpke_candidate::template_crypto::EncryptedTemplateScope {
        account: wire[6..22].try_into().unwrap(),
        device: wire[22..38].try_into().unwrap(),
        line: wire[38..54].try_into().unwrap(),
        interval: wire[54..70].try_into().unwrap(),
        template: wire[70..86].try_into().unwrap(),
        binding_generation: n(86),
        revision: n(94),
        expires: n(102),
        trust_generation: n(110),
        manifest_version: n(118),
        peer_digest: wire[126..158].try_into().unwrap(),
        reader: wire[158..190].try_into().unwrap(),
        manifest_digest: wire[190..222].try_into().unwrap(),
    };

    let content = zrotext_hpke_candidate::template::TemplateContent::new(
        input["Template"].as_str().unwrap(),
        &serde_json::from_value(input["Values"].clone()).unwrap(),
    );
    let mut ticket = None;
    if input["PriorSaved"] == true || input["PriorUnknown"] == true {
        ticket = Some(
            author
                .client()
                .prepare_save(
                    selected.clone(),
                    "00000000-0000-0000-0000-000000000041",
                    0,
                    &wire,
                )
                .unwrap(),
        );
        if input["PriorUnknown"] == true {
            assert!(
                author
                    .client()
                    .commit(ticket.as_ref().unwrap())
                    .unwrap_err()
                    .unknown
            )
        }
    }
    let start = Instant::now();
    let mut results = vec![];
    if input["ReviewBlock"] == true {
        let content = content.unwrap();
        let scope = selected.clone();
        let a = author.clone();
        let done = std::thread::spawn(move || {
            a.prepare(
                "00000000-0000-0000-0000-000000000041",
                0,
                scope,
                &content,
                1,
                1,
            )
        });
        while reviewed.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(1))
        }
        let again = zrotext_hpke_candidate::template::TemplateContent::new(
            input["Template"].as_str().unwrap(),
            &serde_json::from_value(input["Values"].clone()).unwrap(),
        )
        .unwrap();
        if input["ForeignReview"] == true {
            ticket = Some(
                author
                    .client()
                    .prepare_save(
                        selected.clone(),
                        "00000000-0000-0000-0000-000000000041",
                        0,
                        &wire,
                    )
                    .unwrap(),
            )
        } else {
            assert!(
                author
                    .prepare(
                        "00000000-0000-0000-0000-000000000041",
                        0,
                        selected.clone(),
                        &again,
                        1,
                        1
                    )
                    .is_err()
            );
        }
        barrier.wait();
        let result = done.join().unwrap();
        results.push(result.is_ok());
        if result.is_ok() {
            ticket = result.ok();
        }
    } else {
        for _ in 0..input["Repeat"].as_u64().unwrap() {
            let result = match &content {
                Ok(c) => author
                    .prepare(
                        "00000000-0000-0000-0000-000000000041",
                        0,
                        selected.clone(),
                        c,
                        1,
                        1,
                    )
                    .ok(),
                Err(_) => None,
            };
            results.push(result.is_some());
            if result.is_some() {
                ticket = result
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_millis(
        input["DelayMS"].as_u64().unwrap_or(0),
    ));
    let ack = if input["Commit"] == true {
        ticket.as_ref().is_some_and(|t| {
            if input["PriorUnknown"] == true {
                author.client().retry_unknown(t).is_ok()
            } else {
                author.client().commit(t).is_ok()
            }
        })
    } else {
        false
    };
    let (fresh, read) = if input["ProbeExpired"] == true {
        (
            author
                .client()
                .prepare_save(selected, "00000000-0000-0000-0000-000000000042", 0, &wire)
                .is_ok(),
            author.client().read_latest().is_ok(),
        )
    } else {
        (false, false)
    };
    std::thread::sleep(Duration::from_millis(
        input["SettleMS"].as_u64().unwrap_or(0),
    ));
    author.close();
    *client_slot.lock().unwrap() = None;
    println!(
        "{}",
        json!({"accepted":results,"ack":ack,"fresh":fresh,"read":read,"reviewed":reviewed.load(Ordering::SeqCst),"metadata":metadata.load(Ordering::SeqCst),"currentCalls":currents.load(Ordering::SeqCst),"elapsed":elapsed})
    );
}
