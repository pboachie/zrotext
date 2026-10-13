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
    owner_template::save::*,
    owner_template::*,
    template_crypto::EncryptedTemplateScope,
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
    let (current_entered, current_wait) = std::sync::mpsc::sync_channel(1);
    let (current_release, current_resume) = std::sync::mpsc::sync_channel::<()>(1);
    let current_resume = std::sync::Mutex::new(current_resume);
    let currents = Arc::new(AtomicUsize::new(0));
    let sessions = Arc::new(AtomicUsize::new(0));
    let c = currents.clone();
    let a = input.clone();
    let bind = binding.clone();
    let current: CurrentSource = Arc::new(move |_| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        if n as u64 == a["CurrentBlockAt"].as_u64().unwrap_or(0) {
            current_entered.send(()).unwrap();
            current_resume.lock().unwrap().recv().unwrap();
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
            owner_session_live: a["Mode"] != "owner-dead",
            consent_live: a["Mode"] != "consent-dead",
            active: a["Mode"] != "inactive",
        })
    });
    let c = sessions.clone();
    let a = input.clone();
    let session: SessionSource = Arc::new(move |_| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
        let origin = if a["SessionOrigin"].as_str().unwrap_or("").is_empty() {
            a["Origin"].as_str().unwrap()
        } else {
            a["SessionOrigin"].as_str().unwrap()
        };
        let mut csrf = a["CSRF"].as_str().unwrap().to_string();
        if n as u64 == a["SessionChangeAt"].as_u64().unwrap_or(0) {
            csrf.push_str("-changed")
        };
        Ok(OwnerSession {
            origin: origin.into(),
            cookie: a["Cookie"].as_str().unwrap().into(),
            csrf,
        })
    });
    let race = input["Ops"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "race-prepare");
    let (entered, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel::<()>(1);
    let resume = std::sync::Mutex::new(resume);
    let reviews = Arc::new(AtomicUsize::new(0));
    let count = reviews.clone();
    let config = input.clone();
    let review: CiphertextReviewer = Arc::new(move |_, _| {
        let n = count.fetch_add(1, Ordering::SeqCst);
        if race && n == 0 {
            entered.send(()).unwrap();
            resume.lock().unwrap().recv().unwrap();
        }
        std::thread::sleep(Duration::from_millis(
            config["ReviewSleepMS"].as_u64().unwrap_or(0),
        ));
        if config["ReviewFail"] == true {
            Err(OwnerError::InvalidRequest)
        } else {
            Ok(())
        }
    });
    let reader = OwnerTemplateClient::new(
        OwnerOptions {
            origin: input["Origin"].as_str().unwrap().into(),
            binding,
            template: b(&f["scope"]["templateId"]).try_into().unwrap(),
            enabled: input["Enabled"].as_bool().unwrap(),
            timeout: Duration::from_millis(input["TimeoutMS"].as_u64().unwrap()),
            additional_roots: input["Roots"].as_str().unwrap().as_bytes().to_vec(),
            current,
            session,
        },
        review,
    );
    let start = Instant::now();
    let mut results = vec![];
    let mut wire = if input["Envelope"].as_str().unwrap_or("").is_empty() {
        b(&f["envelope"])
    } else {
        b(&input["Envelope"])
    };
    let n = |at: usize| u64::from_be_bytes(wire[at..at + 8].try_into().unwrap());
    let selected = EncryptedTemplateScope {
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
    let mut ticket = None;
    for (i, op) in input["Ops"].as_array().unwrap().iter().enumerate() {
        std::thread::sleep(Duration::from_millis(
            input["DelayMS"][i].as_u64().unwrap_or(0),
        ));
        let mut result = json!({"accepted":false,"unknown":false,"ack":false,"matches":false});
        let value = match &reader {
            Err(e) => Err(TemplateSaveError {
                code: *e,
                unknown: false,
            }),
            Ok(r) => (|| {
                match op.as_str().unwrap() {
                    "race-prepare" => {
                        let client = r.clone();
                        let scope = selected.clone();
                        let worker_wire = wire.clone();
                        let request = input["RequestID"].as_str().unwrap().to_string();
                        let expected = input["Expected"].as_u64().unwrap() as u8;
                        let worker = std::thread::spawn(move || {
                            client.prepare_save(scope, &request, expected, &worker_wire)
                        });
                        waiting.recv_timeout(Duration::from_secs(3)).unwrap();
                        assert!(
                            r.prepare_save(
                                selected.clone(),
                                input["RequestID"].as_str().unwrap(),
                                expected,
                                &wire
                            )
                            .is_err()
                        );
                        release.send(()).unwrap();
                        ticket = Some(worker.join().unwrap()?);
                    }
                    "prepare" => {
                        let next = r.prepare_save(
                            selected.clone(),
                            input["RequestID"].as_str().unwrap(),
                            input["Expected"].as_u64().unwrap() as u8,
                            &wire,
                        )?;
                        ticket = Some(next)
                    }
                    "close-commit" => {
                        let client = r.clone();
                        let t = ticket.as_ref().unwrap().clone();
                        let worker = std::thread::spawn(move || client.commit(&t));
                        current_wait.recv_timeout(Duration::from_secs(3)).unwrap();
                        r.close();
                        current_release.send(()).unwrap();
                        worker.join().unwrap()?;
                    }
                    "commit" | "retry" => {
                        let t = ticket.as_ref().ok_or(TemplateSaveError {
                            code: OwnerError::InvalidRequest,
                            unknown: r.pending().is_some(),
                        })?;
                        let ack = if op == "commit" {
                            r.commit(t)?
                        } else {
                            r.retry_unknown(t)?
                        };
                        result["ack"] = json!(true);
                        result["digest"] = json!(ack.pending.encrypted_digest)
                    }
                    "read" | "verify" => {
                        let s = if op == "read" {
                            r.read_latest()?
                        } else {
                            r.verify_unknown(ticket.as_ref().ok_or(TemplateSaveError {
                                code: OwnerError::InvalidRequest,
                                unknown: r.pending().is_some(),
                            })?)?
                        };
                        result["matches"] = json!(s.matches_pending());
                        result["digest"] = json!(s.encrypted_digest());
                        result["ack"] = json!(s.request_acknowledged())
                    }
                    "mutate" => {
                        let last = wire.len() - 1;
                        wire[last] ^= 1
                    }
                    "close" => r.close(),
                    _ => panic!("bad operation"),
                };
                Ok(())
            })(),
        };
        match value {
            Ok(()) => result["accepted"] = json!(true),
            Err(e) => {
                result["unknown"] = json!(e.unknown);
                result["code"] = json!(format!("{:?}", e.code))
            }
        }
        if let Ok(r) = &reader {
            let pending = r.pending();
            result["pending"] = json!(pending.is_some());
            if let Some(p) = pending {
                result["pendingID"] = json!(p.request_id);
                result["pendingDigest"] = json!(p.encrypted_digest)
            }
        }
        results.push(result);
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_millis(
        input["SettleMS"].as_u64().unwrap_or(0),
    ));
    if let Ok(r) = reader {
        r.close()
    };
    println!(
        "{}",
        json!({"results":results,"elapsed":elapsed,"currentCalls":currents.load(Ordering::SeqCst),"sessionCalls":sessions.load(Ordering::SeqCst),"reviewCalls":reviews.load(Ordering::SeqCst)})
    );
}
