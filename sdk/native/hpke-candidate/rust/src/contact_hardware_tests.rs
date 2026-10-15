//! Fixture-only root provisioning. Private signing internals stay unexported.
use super::*;
use crate::{contact::*, manifest::*};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

fn node(path: &Path, args: &[&str], payload: Option<Value>) -> Value {
    let mut command = Command::new("node");
    command
        .arg(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("synthetic oracle");
    if let Some(payload) = payload {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(serde_json::to_string(&payload).unwrap().as_bytes())
            .unwrap()
    }
    let out = child.wait_with_output().expect("oracle exit");
    assert!(out.status.success(), "synthetic oracle failed");
    serde_json::from_slice(&out.stdout).expect("oracle JSON")
}
fn bytes(f: &Value, key: &str) -> Vec<u8> {
    STANDARD
        .decode(f[key].as_str().expect("fixture string"))
        .expect("fixture base64")
}
fn put(f: &mut Value, key: &str, b: &[u8]) {
    f[key] = json!(STANDARD.encode(b))
}
struct Owned {
    key: Arc<ContactRootSigner>,
    receipt: File,
}
impl Drop for Owned {
    fn drop(&mut self) {
        if self.key.delete_created().is_err() {
            if std::thread::panicking() {
                eprintln!("owned contact cleanup failed");
                return;
            } else {
                panic!("owned contact cleanup failed")
            }
        }
        self.receipt.set_len(0).expect("receipt truncate");
        self.receipt.seek(SeekFrom::Start(0)).expect("receipt seek");
        self.receipt
            .write_all(b"{\"state\":\"deleted\"}")
            .expect("receipt mark");
        self.receipt.sync_all().expect("receipt sync");
    }
}
#[test]
#[ignore = "explicit Windows PCP and clean synthetic fixture checkout required"]
fn contact_hardware_fields() {
    let source = std::env::var("ZROTEXT_CONTACT_FIXTURE_ROOT").expect("explicit fixture checkout");
    let source = Path::new(&source);
    let interop = source.join("sdk/native/sealed-candidate/python/contact-producer-interop.mjs");
    let mut f = node(
        &source.join("sdk/native/sealed-candidate/python/contact-interop.mjs"),
        &[],
        None,
    );
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let suffix: String = random.iter().map(|v| format!("{v:02x}")).collect();
    let mut receipt = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(std::env::temp_dir().join(format!("zrotext-contact-pending-{suffix}.json")))
        .expect("private receipt");
    let key = ContactRootSigner::create(|alias| {
        receipt
            .write_all(
                serde_json::to_string(&json!({"alias":alias,"state":"pending"}))
                    .unwrap()
                    .as_bytes(),
            )
            .map_err(|_| refused("receipt"))?;
        receipt.sync_all().map_err(|_| refused("receipt sync"))
    })
    .expect("protected provider qualification");
    let owner = Owned {
        key: Arc::new(key),
        receipt,
    };
    let point = owner.key.public_point().unwrap();
    let alias = owner.key.alias().unwrap();
    assert!(
        HardwareSigner::open(&alias, &point).is_err(),
        "contact alias crossed envelope capability"
    );
    let template = node(
        &interop,
        &["--root-template"],
        Some(json!({"fixture":f,"point":STANDARD.encode(&point)})),
    );
    f["rootPin"] = template["rootPin"].clone();
    f["fingerprint"] = template["fingerprint"].clone();
    let setup_sign = |domain: &str, unsigned: &[u8]| {
        let digest = Sha256::digest(transcript(domain, unsigned));
        let guard = owner.key.signer.state.lock().unwrap();
        [
            unsigned,
            signer_digest(&guard.0, &digest)
                .expect("test enrollment signature")
                .as_slice(),
        ]
        .concat()
    };
    let unsigned = bytes(&template, "manifestUnsigned");
    put(
        &mut f,
        "manifest",
        &setup_sign("ZTSE/manifest/v2", &unsigned),
    );
    let mut next = unsigned.clone();
    next[29..37].copy_from_slice(&2u64.to_be_bytes());
    next[53..85].copy_from_slice(&Sha256::digest(&unsigned));
    put(
        &mut f,
        "nextManifest",
        &setup_sign("ZTSE/manifest/v2", &next),
    );
    let statements = node(
        &interop,
        &["--statement-template"],
        Some(json!({"fixture":f})),
    );
    put(
        &mut f,
        "statement",
        &setup_sign(
            "ZT/contact-reader/authorization/v1",
            &bytes(&statements, "statementUnsigned"),
        ),
    );
    put(
        &mut f,
        "nextStatement",
        &setup_sign(
            "ZT/contact-reader/authorization/v1",
            &bytes(&statements, "nextStatementUnsigned"),
        ),
    );
    let root = enroll_root(&bytes(&f, "rootPin"), &bytes(&f, "fingerprint")).unwrap();
    let first = verify_manifest(&bytes(&f, "manifest"), &root, None, 2, 10000).unwrap();
    let second =
        verify_manifest(&bytes(&f, "nextManifest"), &root, Some(&first), 2, 10000).unwrap();
    let mut outputs = Vec::new();
    let mut fields = std::collections::BTreeMap::new();
    let mut statements_by_name = std::collections::BTreeMap::new();
    for (name, which, m) in [
        ("name", "statement", &first),
        ("notes", "statement", &first),
        ("replacement", "nextStatement", &second),
    ] {
        let st = verify_statement02(
            &bytes(&f, which),
            m,
            &bytes(&f, "account"),
            f["origin"].as_str().unwrap(),
            &bytes(&f, "fingerprint"),
        )
        .unwrap();
        let b = bytes(&f, name);
        let field = FieldInput {
            kind: b[5],
            seal_revision: u64::from_be_bytes(b[38..46].try_into().unwrap()),
            request_id: b[198..214].try_into().unwrap(),
            encapsulation: b[246..311].try_into().unwrap(),
            ciphertext: b[315..b.len() - 64].to_vec(),
        };
        let expected = Expected {
            account: bytes(&f, "account").try_into().unwrap(),
            origin: f["origin"].as_str().unwrap().into(),
            root_fingerprint: bytes(&f, "fingerprint").try_into().unwrap(),
            contact: bytes(&f, "contact").try_into().unwrap(),
            routing_digest: bytes(&f, "routing").try_into().unwrap(),
        };
        if name == "name" {
            let guard = owner.key.signer.state.lock().unwrap();
            let (key, st, e, input) = (
                owner.key.clone(),
                st.clone(),
                expected.clone(),
                field.clone(),
            );
            let cancel = Cancellation::default();
            let stop = cancel.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = produce_protected_field01(key, &st, &e, &input, &cancel);
                tx.send(result.is_err()).unwrap()
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop.cancel();
            let settled = rx.recv_timeout(std::time::Duration::from_secs(1));
            drop(guard);
            assert_eq!(settled, Ok(true), "provider lookup escaped deadline");
            worker.join().unwrap();
        }
        let result = produce_protected_field01(
            owner.key.clone(),
            &st,
            &expected,
            &field,
            &Cancellation::default(),
        )
        .unwrap();
        fields.insert(name, result.verified().clone());
        statements_by_name.insert(which, st.clone());
        outputs.push(json!({"bytes":STANDARD.encode(result.signed_bytes()),"statement":which}));
        let reopened = Arc::new(ContactRootSigner::open(&alias, &point).unwrap());
        reopened.close().unwrap();
        assert!(
            produce_protected_field01(reopened, &st, &expected, &field, &Cancellation::default())
                .is_err()
        );
    }
    let oracle = Path::new(env!("CARGO_MANIFEST_DIR")).join("../contact-field-interop.mjs");
    let report = node(
        &oracle,
        &[source.to_str().unwrap(), "--consume"],
        Some(json!({"fixture":f,"outputs":outputs})),
    );
    assert_eq!(report, json!({"verified":true,"fields":3}));
    use crate::contact::mutation::{Input, Proposal, Slot, produce_protected_mutation01};
    let expected = Expected {
        account: bytes(&f, "account").try_into().unwrap(),
        origin: f["origin"].as_str().unwrap().into(),
        root_fingerprint: bytes(&f, "fingerprint").try_into().unwrap(),
        contact: bytes(&f, "contact").try_into().unwrap(),
        routing_digest: bytes(&f, "routing").try_into().unwrap(),
    };
    let slot = |name| {
        let field = &fields[name];
        Slot {
            tag: 1,
            seal_revision: u64::from_be_bytes(field.signed_bytes()[38..46].try_into().unwrap()),
            digest: field.digest(),
        }
    };
    let mut previous: Option<crate::contact::mutation::Transition> = None;
    let mut previous_statement: Option<crate::contact::Statement> = None;
    let mut mutations = serde_json::Map::new();
    for name in ["create", "update", "clear", "converted"] {
        let st = &statements_by_name[if ["update", "clear"].contains(&name) {
            "nextStatement"
        } else {
            "statement"
        }];
        let b = bytes(&f, name);
        let number = |at| u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
        let mut input = Input {
            operation: b[5],
            expected_revision: number(38),
            revision: number(46),
            legacy_generation: number(214),
            request_id: b[54..70].try_into().unwrap(),
            previous_digest: [0; 32],
            name: Slot {
                tag: 0,
                seal_revision: 0,
                digest: [0; 32],
            },
            notes: slot("replacement"),
        };
        let replacements = match name {
            "create" | "converted" => {
                previous = None;
                previous_statement = None;
                input.name = slot("name");
                input.notes = slot("notes");
                vec![fields["name"].clone(), fields["notes"].clone()]
            }
            "update" => {
                input.name = slot("name");
                vec![fields["replacement"].clone()]
            }
            _ => vec![],
        };
        if let Some(p) = &previous {
            input.previous_digest = p.mutation().digest()
        }
        let expected_legacy = input.legacy_generation;
        let proposal = Proposal {
            statement: st.clone(),
            expected: expected.clone(),
            input,
            expected_legacy,
            previous: previous.clone(),
            previous_statement: previous_statement.clone(),
            replacements,
        };
        let result =
            produce_protected_mutation01(owner.key.clone(), &proposal, &Cancellation::default())
                .unwrap();
        mutations.insert(name.into(), json!(STANDARD.encode(result.signed_bytes())));
        let closed = Arc::new(ContactRootSigner::open(&alias, &point).unwrap());
        closed.close().unwrap();
        assert!(produce_protected_mutation01(closed, &proposal, &Cancellation::default()).is_err());
        previous = Some(result.verified().clone());
        previous_statement = Some(st.clone());
    }
    let produced_fields: serde_json::Map<String, Value> = fields
        .iter()
        .map(|(name, field)| ((*name).into(), json!(STANDARD.encode(field.signed_bytes()))))
        .collect();
    let verified = node(
        &interop,
        &[],
        Some(json!({"fixture":f,"fields":produced_fields,"mutations":mutations})),
    );
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["transitions"], 4);
    println!(
        "4 actual protected mutation transitions independently verified; closed mutation provider refused"
    );
    drop(owner);
    assert!(
        ContactRootSigner::open(&alias, &point).is_err(),
        "deleted key reopened"
    );
    println!(
        "3 actual protected fields independently verified; closed provider, envelope alias, deleted reopen refused"
    );
}
