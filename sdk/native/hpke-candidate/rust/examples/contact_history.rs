//! Public synthetic historical transition probe. No service effects.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, BufRead},
    sync::Arc,
};
use zrotext_hpke_candidate::{contact::mutation::history::LocalToken, journal::Journal};
use zrotext_hpke_candidate::{
    contact::{
        mutation::{
            self, Transition,
            history::{History, OpenMode},
        },
        *,
    },
    manifest::*,
};
fn decode(v: &Value) -> Result<Vec<u8>, ()> {
    STANDARD.decode(v.as_str().ok_or(())?).map_err(|_| ())
}
fn array<const N: usize>(v: &Value) -> Result<[u8; N], ()> {
    decode(v)?.try_into().map_err(|_| ())
}
struct Fixture<'a> {
    wire: &'a Value,
    st: Statement,
    next: Statement,
    expected: Expected,
    fields: [Field; 3],
}
impl<'a> Fixture<'a> {
    fn new(f: &'a Value) -> Result<Self, ()> {
        let root =
            enroll_root(&decode(&f["rootPin"])?, &decode(&f["fingerprint"])?).map_err(|_| ())?;
        let m = verify_manifest(&decode(&f["manifest"])?, &root, None, 2, 10000).map_err(|_| ())?;
        let n = verify_manifest(&decode(&f["nextManifest"])?, &root, Some(&m), 2, 10000)
            .map_err(|_| ())?;
        let st = verify_statement02(
            &decode(&f["statement"])?,
            &m,
            &decode(&f["account"])?,
            f["origin"].as_str().ok_or(())?,
            &decode(&f["fingerprint"])?,
        )
        .map_err(|_| ())?;
        let next = verify_statement02(
            &decode(&f["nextStatement"])?,
            &n,
            &decode(&f["account"])?,
            f["origin"].as_str().ok_or(())?,
            &decode(&f["fingerprint"])?,
        )
        .map_err(|_| ())?;
        let expected = Expected {
            account: array(&f["account"])?,
            origin: f["origin"].as_str().ok_or(())?.into(),
            root_fingerprint: array(&f["fingerprint"])?,
            contact: array(&f["contact"])?,
            routing_digest: array(&f["routing"])?,
        };
        let name = verify_field01(&decode(&f["name"])?, &st, &expected).map_err(|_| ())?;
        let notes = verify_field01(&decode(&f["notes"])?, &st, &expected).map_err(|_| ())?;
        let replacement =
            verify_field01(&decode(&f["replacement"])?, &next, &expected).map_err(|_| ())?;
        Ok(Self {
            wire: f,
            st,
            next,
            expected,
            fields: [name, notes, replacement],
        })
    }
    fn statement(&self, k: &str) -> &Statement {
        if ["update", "clear"].contains(&k) {
            &self.next
        } else {
            &self.st
        }
    }
    fn replacements(&self, k: &str) -> Vec<Field> {
        match k {
            "create" | "converted" => self.fields[..2].to_vec(),
            "update" => vec![self.fields[2].clone()],
            _ => vec![],
        }
    }
    fn transition(&self, k: &str) -> Result<Option<Transition>, ()> {
        if k == "none" {
            return Ok(None);
        };
        if !["create", "update", "clear", "converted"].contains(&k) {
            return Err(());
        }
        let previous = if k == "update" || k == "clear" {
            self.transition(if k == "clear" { "update" } else { "create" })?
        } else {
            None
        };
        let next = mutation::verify_mutation01(
            &decode(&self.wire[k])?,
            self.statement(k),
            &self.expected,
            legacy(k),
        )
        .map_err(|_| ())?;
        Ok(Some(
            mutation::verify_transition01(previous.as_ref(), &next, &self.replacements(k))
                .map_err(|_| ())?,
        ))
    }
}
fn legacy(k: &str) -> u64 {
    if k == "converted" { 7 } else { 0 }
}
fn run(
    c: &Value,
    hs: &mut BTreeMap<String, History>,
    ts: &mut BTreeMap<String, Arc<LocalToken>>,
) -> Result<Value, ()> {
    let op = c["operation"].as_str().ok_or(())?;
    let f = &c["fixture"];
    if op == "root" {
        let j = Journal::open(
            c["root"].as_str().ok_or(())?,
            &decode(&f["rootPin"])?,
            &decode(&f["fingerprint"])?,
        )
        .map_err(|_| ())?;
        j.append_manifest(&decode(&f["manifest"])?, 0, 10000, None)
            .map_err(|_| ())?;
        j.append_manifest(&decode(&f["nextManifest"])?, 1, 10000, None)
            .map_err(|_| ())?;
        return Ok(json!({"accepted":true}));
    }
    let name = c["adapter"].as_str().ok_or(())?;
    if op == "open" {
        if hs.contains_key(name) {
            return Err(());
        };
        let h = History::open(
            c["path"].as_str().ok_or(())?,
            c["root"].as_str().ok_or(())?,
            &decode(&f["rootPin"])?,
            &decode(&f["fingerprint"])?,
            c["origin"]
                .as_str()
                .or_else(|| f["origin"].as_str())
                .ok_or(())?,
            c["maximum"].as_u64().ok_or(())? as usize,
            if c["create"] == true {
                OpenMode::Create
            } else if c["reduction"] == true {
                OpenMode::LocalReduction
            } else {
                OpenMode::Existing
            },
        )
        .map_err(|_| ())?;
        hs.insert(name.to_string(), h);
        return Ok(json!({"accepted":true}));
    }
    if op == "close-keep" {
        hs.get(name).ok_or(())?.close();
        return Ok(json!({"accepted":true}));
    }
    if op == "close" {
        hs.remove(name).ok_or(())?.close();
        return Ok(json!({"accepted":true}));
    }
    let h = hs.get(name).ok_or(())?;
    let expected = c["expected"].as_str().and_then(|x| ts.get(x));
    let r = match op {
        "lookup" => h.lookup(array(&f["contact"])?),
        "accept" => {
            let fixture = Fixture::new(f)?;
            let k = c["mutation"].as_str().ok_or(())?;
            h.accept(
                expected,
                &fixture.transition(k)?.ok_or(())?,
                fixture.statement(k),
            )
        }
        "stop" => h.mark_unavailable(expected.ok_or(())?),
        _ => return Err(()),
    }
    .map_err(|_| ())?;
    let mut out = json!({"accepted":true,"kind":r.kind,"reason":r.reason});
    if let (Some(name), Some(t)) = (c["save"].as_str(), r.token) {
        ts.insert(name.to_string(), t);
    }
    if let Some(m) = r.metadata {
        out["revision"] = json!(m.revision);
        out["digest"] = json!(STANDARD.encode(m.digest));
        out["name"] = json!(STANDARD.encode(m.name.digest));
        out["notes"] = json!(STANDARD.encode(m.notes.digest));
    }
    Ok(out)
}
fn main() {
    let mut histories = BTreeMap::new();
    let mut tokens = BTreeMap::new();
    for line in io::stdin().lock().lines() {
        let line = line.expect("synthetic input");
        assert!(line.len() <= 1000000);
        let result = serde_json::from_str(&line)
            .map_err(|_| ())
            .and_then(|c| run(&c, &mut histories, &mut tokens))
            .unwrap_or_else(|_| json!({"accepted":false}));
        println!("{}", result);
    }
}
