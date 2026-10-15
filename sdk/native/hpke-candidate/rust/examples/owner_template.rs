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
    let currents = Arc::new(AtomicUsize::new(0));
    let sessions = Arc::new(AtomicUsize::new(0));
    let c = currents.clone();
    let a = input.clone();
    let bind = binding.clone();
    let current: CurrentSource = Arc::new(move |_| {
        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
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
    let reader = OwnerTemplateReader::new(OwnerOptions {
        origin: input["Origin"].as_str().unwrap().into(),
        binding,
        template: b(&f["scope"]["templateId"]).try_into().unwrap(),
        enabled: input["Enabled"].as_bool().unwrap(),
        timeout: Duration::from_millis(input["TimeoutMS"].as_u64().unwrap()),
        additional_roots: input["Roots"].as_str().unwrap().as_bytes().to_vec(),
        current,
        session,
    });
    let start = Instant::now();
    let mut results = vec![];
    for _ in 0..input["Reads"].as_u64().unwrap() {
        let value = match &reader {
            Ok(r) => r.read_latest(),
            Err(e) => Err(*e),
        };
        results.push(match value {Ok(s)=>{let mut copy=s.envelope();copy[0]^=1;assert_ne!(copy[0],s.envelope()[0]);json!({"accepted":true,"digest":s.encrypted_digest(),"ack":s.request_acknowledged(),"pending":s.matches_pending()})},Err(e)=>json!({"accepted":false,"unknown":e==OwnerError::ResponseUnknown,"code":format!("{e:?}")})})
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
        json!({"results":results,"elapsed":elapsed,"currentCalls":currents.load(Ordering::SeqCst),"sessionCalls":sessions.load(Ordering::SeqCst)})
    );
}
