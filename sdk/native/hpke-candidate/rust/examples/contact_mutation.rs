//! Public synthetic historical transition probe. No service effects.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::{self, Read};
use zrotext_hpke_candidate::{
    contact::{
        mutation::{self, Input, Proposal, Slot, Transition},
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
        if !["create", "update"].contains(&k) {
            return Err(());
        }
        let previous = if k == "update" {
            self.transition("create")?
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
fn input(b: &[u8]) -> Result<Input, ()> {
    if b.len() != 368 {
        return Err(());
    };
    let number = |at| u64::from_be_bytes(b[at..at + 8].try_into().expect("bounded"));
    let slot = |at| Slot {
        tag: b[at],
        seal_revision: number(at + 1),
        digest: b[at + 9..at + 41].try_into().expect("bounded"),
    };
    Ok(Input {
        operation: b[5],
        expected_revision: number(38),
        revision: number(46),
        legacy_generation: number(214),
        request_id: b[54..70].try_into().map_err(|_| ())?,
        previous_digest: b[70..102].try_into().map_err(|_| ())?,
        name: slot(222),
        notes: slot(263),
    })
}
fn run(r: &Value) -> Result<Value, ()> {
    let f = Fixture::new(&r["fixture"])?;
    let mode = r["operation"].as_str().ok_or(())?;
    if mode == "produce-chain" {
        let mut out = serde_json::Map::new();
        let mut previous: Option<Transition> = None;
        let mut ps = None;
        for k in ["create", "update", "clear", "converted"] {
            if k == "converted" {
                previous = None;
                ps = None
            };
            let mut i = input(&decode(&f.wire[k])?)?;
            if let Some(p) = &previous {
                i.previous_digest = p.mutation().digest()
            }
            let p = Proposal {
                statement: f.statement(k).clone(),
                expected: f.expected.clone(),
                input: i,
                expected_legacy: legacy(k),
                previous: previous.clone(),
                previous_statement: ps,
                replacements: f.replacements(k),
            };
            let mut scalar = [0; 32];
            scalar[31] = 7;
            let produced =
                mutation::produce_software_mutation01(&scalar, &p, &Cancellation::default())
                    .map_err(|_| ())?;
            out.insert(k.into(), json!(STANDARD.encode(produced.signed_bytes())));
            previous = Some(produced.verified().clone());
            ps = Some(f.statement(k).clone());
        }
        return Ok(json!({"accepted":true,"mutationVerified":false,"mutations":out}));
    }
    let k = r["mutation"].as_str().unwrap_or("create");
    let expected_legacy = r["legacy"].as_u64().unwrap_or(legacy(k));
    let selected = match r["statement"].as_str() {
        Some("statement") => &f.st,
        Some("nextStatement") => &f.next,
        _ => f.statement(k),
    };
    let prior = r["previous"].as_str().unwrap_or(match k {
        "update" => "create",
        "clear" => "update",
        _ => "none",
    });
    let previous = f.transition(prior)?;
    let mut replacements = f.replacements(k);
    if let Some(names) = r["replacements"].as_array() {
        replacements = names
            .iter()
            .map(|name| match name.as_str() {
                Some("name") => Ok(f.fields[0].clone()),
                Some("notes") => Ok(f.fields[1].clone()),
                Some("replacement") => Ok(f.fields[2].clone()),
                _ => Err(()),
            })
            .collect::<Result<_, _>>()?
    }
    if mode == "produce" {
        let mut ps = previous.as_ref().map(|_| f.statement(prior).clone());
        match r["previousStatement"].as_str() {
            Some("none") => ps = None,
            Some("statement") => ps = Some(f.st.clone()),
            Some("nextStatement") => ps = Some(f.next.clone()),
            _ => {}
        }
        let p = Proposal {
            statement: selected.clone(),
            expected: f.expected.clone(),
            input: input(&decode(&f.wire[k])?)?,
            expected_legacy,
            previous,
            previous_statement: ps,
            replacements,
        };
        let mut scalar = vec![0; 32];
        scalar[31] = 7;
        if r["scalar"].is_string() {
            scalar = decode(&r["scalar"])?
        };
        let cancel = Cancellation::default();
        if r["cancel"] == true {
            cancel.cancel()
        }
        let result = mutation::produce_software_mutation01(&scalar, &p, &cancel).map_err(|_| ())?;
        return Ok(
            json!({"accepted":true,"mutationVerified":false,"bytes":STANDARD.encode(result.signed_bytes())}),
        );
    }
    let m =
        mutation::verify_mutation01(&decode(&f.wire[k])?, selected, &f.expected, expected_legacy)
            .map_err(|_| ())?;
    if mode == "verify" {
        return Ok(json!({"accepted":true,"mutationVerified":true}));
    }
    let Ok(t) = mutation::verify_transition01(previous.as_ref(), &m, &replacements) else {
        return Ok(json!({"accepted":false,"mutationVerified":true}));
    };
    let mut fields = serde_json::Map::new();
    for (i, k) in ["name", "notes"].iter().enumerate() {
        if let Some(field) = t.field(i as u8 + 1) {
            fields.insert((*k).into(), json!(STANDARD.encode(field.signed_bytes())));
        }
    }
    Ok(json!({"accepted":true,"mutationVerified":true,"fields":fields}))
}
fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).expect("input");
    let rows: Vec<Value> = serde_json::from_str(&s).expect("synthetic JSON");
    let out: Vec<_> = rows
        .iter()
        .map(|r| run(r).unwrap_or_else(|_| json!({"accepted":false,"mutationVerified":false})))
        .collect();
    println!("{}", serde_json::to_string(&out).expect("output"));
}
