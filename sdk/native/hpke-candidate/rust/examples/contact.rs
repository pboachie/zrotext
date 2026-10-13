//! Public synthetic interoperability probe; no service or custody effects.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{self, Read};
use zrotext_hpke_candidate::{contact::*, manifest::*};
fn decode(v: &Value) -> Result<Vec<u8>, ()> {
    STANDARD.decode(v.as_str().ok_or(())?).map_err(|_| ())
}
fn array<const N: usize>(v: &Value) -> Result<[u8; N], ()> {
    decode(v)?.try_into().map_err(|_| ())
}
fn run(r: &Value) -> Result<Value, ()> {
    let mode = r["operation"].as_str().ok_or(())?;
    if mode == "origin" {
        return Ok(json!({"accepted":validate_origin01(r["origin"].as_str().ok_or(())?).is_ok()}));
    }
    let f = &r["fixture"];
    let root = enroll_root(&decode(&f["rootPin"])?, &decode(&f["fingerprint"])?).map_err(|_| ())?;
    let mut m = verify_manifest(&decode(&f["manifest"])?, &root, None, 2, 10000).map_err(|_| ())?;
    let selected = r["statement"].as_str().unwrap_or("statement");
    if selected == "nextStatement" {
        m = verify_manifest(&decode(&f["nextManifest"])?, &root, Some(&m), 2, 10000)
            .map_err(|_| ())?
    }
    let st = verify_statement02(
        &decode(&f[selected])?,
        &m,
        &decode(&f["account"])?,
        f["origin"].as_str().ok_or(())?,
        &decode(&f["fingerprint"])?,
    )
    .map_err(|_| ())?;
    if mode == "statement" {
        return Ok(json!({"accepted":true}));
    }
    let expected = Expected {
        account: array(&f["account"])?,
        origin: f["origin"].as_str().ok_or(())?.into(),
        root_fingerprint: array(&f["fingerprint"])?,
        contact: array(&f["contact"])?,
        routing_digest: array(&f["routing"])?,
    };
    let b = decode(&f[r["field"].as_str().unwrap_or("name")])?;
    if mode == "verify" {
        let field = verify_field01(&b, &st, &expected).map_err(|_| ())?;
        return Ok(json!({"accepted":true,"bytes":STANDARD.encode(field.signed_bytes())}));
    }
    if b.len() < 396 {
        return Err(());
    }
    let input = FieldInput {
        kind: b[5],
        seal_revision: u64::from_be_bytes(b[38..46].try_into().map_err(|_| ())?),
        request_id: b[198..214].try_into().map_err(|_| ())?,
        encapsulation: b[246..311].try_into().map_err(|_| ())?,
        ciphertext: b[315..b.len() - 64].to_vec(),
    };
    let mut scalar = vec![0; 32];
    scalar[31] = 7;
    if r["scalar"].is_string() {
        scalar = decode(&r["scalar"])?
    }
    let cancel = Cancellation::default();
    if r["cancel"] == true {
        cancel.cancel()
    }
    let result =
        produce_software_field01(&scalar, &st, &expected, &input, &cancel).map_err(|_| ())?;
    Ok(json!({"accepted":true,"bytes":STANDARD.encode(result.signed_bytes())}))
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("stdin");
    let rows: Vec<Value> = serde_json::from_str(&input).expect("public fixture JSON");
    let results: Vec<Value> = rows
        .iter()
        .map(|r| run(r).unwrap_or_else(|_| json!({"accepted":false})))
        .collect();
    println!("{}", serde_json::to_string(&results).expect("results"))
}
