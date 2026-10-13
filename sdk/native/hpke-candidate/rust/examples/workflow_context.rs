mod context_custody;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use zrotext_hpke_candidate::{
    Error,
    manifest::{enroll_root, verify_manifest},
    workflow_context::{WorkflowContextRole, WorkflowContextScope, bounded},
};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn scope(v: &Value) -> WorkflowContextScope {
    WorkflowContextScope {
        kind: v["kind"].as_u64().unwrap().try_into().unwrap(),
        account: bytes(&v["accountId"]).try_into().unwrap(),
        device: bytes(&v["deviceId"]).try_into().unwrap(),
        line: bytes(&v["lineId"]).try_into().unwrap(),
        interval: bytes(&v["intervalId"]).try_into().unwrap(),
        context: bytes(&v["contextId"]).try_into().unwrap(),
        binding_generation: v["bindingGeneration"].as_u64().unwrap(),
        revision: v["revision"].as_u64().unwrap(),
        expires: v["expiresMs"].as_u64().unwrap(),
        trust_generation: v["trustGeneration"].as_u64().unwrap(),
        manifest_version: v["manifestVersion"].as_u64().unwrap(),
        peer_digest: bytes(&v["peerDigest"]).try_into().unwrap(),
        reader: bytes(&v["readerId"]).try_into().unwrap(),
        manifest_digest: bytes(&v["manifestDigest"]).try_into().unwrap(),
    }
}
fn main() {
    let session = context_custody::Session::new();
    let input: Value = serde_json::from_reader(std::io::stdin()).unwrap();
    let f = &input["Fixture"];
    let root = enroll_root(&bytes(&f["rootPin"]), &bytes(&f["fingerprint"])).unwrap();
    let m = std::sync::Arc::new(
        verify_manifest(&bytes(&f["manifest"]), &root, None, 2, 10000).unwrap(),
    );
    let scalar = zeroize::Zeroizing::new(if f["selectedScalar"].is_string() {
        bytes(&f["selectedScalar"])
    } else {
        vec![]
    });
    let mut results = vec![];
    for c in input["Cases"].as_array().unwrap() {
        let s = scope(&c["Scope"]);
        let role = match c["Role"].as_u64().unwrap() {
            2 => WorkflowContextRole::Owner,
            3 => WorkflowContextRole::Integration,
            _ => panic!("role"),
        };
        let clocks = c["Clock"].as_array().unwrap().clone();
        let fail = c["FailFinal"] == true;
        let m = m.clone();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let source = move || {
            let calls = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if fail && calls > 1 {
                return Err(Error::Authentication);
            };
            Ok((
                m.clone(),
                clocks[(calls - 1).min(clocks.len() - 1)].as_u64().unwrap(),
            ))
        };
        let mut result = json!({"accepted":false});
        if c["Mode"] == "seal" {
            let content = zeroize::Zeroizing::new(bytes(&c["Canonical"]));
            if let Ok(wire) = bounded::seal(
                &bounded::Cancellation::default(),
                source,
                s.clone(),
                role,
                &content,
            ) {
                result = json!({"accepted":true,"envelope":STANDARD.encode(wire)})
            }
        } else if let Ok(content) = session.open(
            source,
            &s,
            role,
            &scalar,
            &bytes(&c["Envelope"]),
            c["ProviderMode"].as_u64().unwrap_or(0) as u8,
        ) {
            result = json!({"accepted":true,"canonical":STANDARD.encode(content.as_slice())})
        }
        result["calls"] = json!(calls.load(std::sync::atomic::Ordering::SeqCst));
        results.push(result);
    }
    println!("{}", json!({"cases":results}));
}
