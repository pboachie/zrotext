use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use zrotext_hpke_candidate::template::{TemplateContent, estimate_segments};
fn main() {
    let input: Value = serde_json::from_reader(std::io::stdin()).unwrap();
    let mut cases = vec![];
    for c in input["cases"].as_array().unwrap() {
        let raw = STANDARD.decode(c["raw"].as_str().unwrap()).unwrap();
        let mut result = json!({"accepted":false});
        if let Ok(content) = TemplateContent::parse(&raw) {
            result = json!({"accepted":true,"canonical":STANDARD.encode(content.canonical()),"digest":content.digest(),"preview":null});
            if let Ok((text, estimate)) = content.preview() {
                result["preview"] = json!({"text":text,"estimate":estimate})
            };
            let mut copy = content.canonical();
            copy[0] ^= 1;
            let mut values = content.values();
            values.insert("injected".into(), "changed".into());
            assert_ne!(copy, content.canonical());
            assert_ne!(values.len(), content.values().len());
        };
        cases.push(result);
    }
    let segments: Vec<Value> = input["segments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let units: Vec<u16> = case["units"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u16::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            String::from_utf16(&units)
                .ok()
                .and_then(|s| estimate_segments(&s).ok())
                .map(|e| serde_json::to_value(e).unwrap())
                .unwrap_or(Value::Null)
        })
        .collect();
    println!("{}", json!({"cases":cases,"segments":segments}));
}
