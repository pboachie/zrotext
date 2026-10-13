mod template_custody;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use zrotext_hpke_candidate::{
    Error,
    manifest::{enroll_root, verify_manifest},
    template::TemplateContent,
    template_crypto::{EncryptedTemplateScope, seal_current_encrypted_template},
};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn scope(v: &Value) -> EncryptedTemplateScope {
    EncryptedTemplateScope {
        account: bytes(&v["accountId"]).try_into().unwrap(),
        device: bytes(&v["deviceId"]).try_into().unwrap(),
        line: bytes(&v["lineId"]).try_into().unwrap(),
        interval: bytes(&v["intervalId"]).try_into().unwrap(),
        template: bytes(&v["templateId"]).try_into().unwrap(),
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
    let session = template_custody::Session::new();
    let input: Value = serde_json::from_reader(std::io::stdin()).unwrap();
    let f = &input["Fixture"];
    let root = enroll_root(&bytes(&f["rootPin"]), &bytes(&f["fingerprint"])).unwrap();
    let m = verify_manifest(&bytes(&f["manifest"]), &root, None, 2, 10000).unwrap();
    let scalar = zeroize::Zeroizing::new(if f["archiveScalar"].is_string() {
        bytes(&f["archiveScalar"])
    } else {
        vec![]
    });
    let mut results = vec![];
    for c in input["Cases"].as_array().unwrap() {
        let s = scope(&c["Scope"]);
        let clocks = c["Clock"].as_array().unwrap();
        let mut calls = 0usize;
        let mut source = || {
            calls += 1;
            if c["FailFinal"] == true && calls > 1 {
                return Err(Error::Authentication);
            };
            Ok((
                &m,
                clocks[(calls - 1).min(clocks.len() - 1)].as_u64().unwrap(),
            ))
        };
        let mut result = json!({"accepted":false});
        if c["Mode"] == "seal" {
            let content = TemplateContent::parse(&bytes(&c["Canonical"])).unwrap();
            if let Ok(wire) = seal_current_encrypted_template(&mut source, &s, &content) {
                result = json!({"accepted":true,"envelope":STANDARD.encode(wire)})
            }
        } else if let Ok(content) = session.open(&mut source, &s, &scalar, &bytes(&c["Envelope"])) {
            result = json!({"accepted":true,"canonical":STANDARD.encode(content.canonical())})
        }
        result["calls"] = json!(calls);
        results.push(result);
    }
    println!("{}", json!({"cases":results}));
}
