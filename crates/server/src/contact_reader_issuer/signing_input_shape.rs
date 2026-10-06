// SPDX-License-Identifier: AGPL-3.0-only
//! The real issuer serializer must emit exactly the closed key sets that the
//! offline signing command parses. `protocol/v1/tests/test_contact_reader_signing_input_shape.py`
//! checks the same shared vector against that command's source. Synthetic
//! values; this proves key-set agreement only, not signature or history
//! acceptance, and does not execute the Windows parser.
use super::model::*;
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/contact-reader-signing-input-shape.json"
    ))
    .expect("shared vector parses")
}
fn expected(v: &Value) -> BTreeSet<String> {
    v.as_array()
        .expect("key list")
        .iter()
        .map(|k| k.as_str().expect("key").to_owned())
        .collect()
}
fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .expect("object")
        .keys()
        .map(|k| k.to_owned())
        .collect()
}
fn id() -> Id {
    Id(Uuid::from_bytes([5; 16]))
}
fn record() -> KeyView {
    KeyView {
        key_id_b64: Fixed([1; 32]),
        public_point_b64: Fixed([2; 65]),
        from_ms: Number(0),
        until_ms: Number(9),
    }
}
fn current(phase: &'static str) -> Current {
    let tuple = phase != "empty";
    Current {
        phase,
        mutation_revision: Number(2),
        allocation_generation: Number(1),
        observed_ms: Number(3),
        authorization: tuple.then(id),
        generation: tuple.then_some(Number(1)),
        statement_digest: tuple.then_some(Fixed([4; 32])),
    }
}
fn pending(current: Current) -> PendingView {
    PendingView {
        kind: "pending",
        create_input_digest: Fixed([6; 32]),
        create_request: id(),
        authorization: id(),
        generation: Number(1),
        creation_expected_revision: Number(0),
        allocated_revision: Number(1),
        unsigned_digest: Fixed([7; 32]),
        unsigned: Packed(vec![8; 250]),
        issued_ms: Number(1),
        expires_ms: Number(2),
        until_ms: Number(3),
        created_by_user: id(),
        created_session: id(),
        creation_source: CreationSource {
            kind: "historical_creation_source",
            account_id: id(),
            root_pin_b64: Fixed([9; 94]),
            root_fingerprint_b64: Fixed([10; 32]),
            trust_generation: Number(1),
            manifest_version: Number(1),
            manifest_digest_b64: Fixed([11; 32]),
            manifest_b64: Packed(vec![12; 364]),
            observed_ms: Number(1),
            manifest_issued_ms: Number(1),
            manifest_expires_ms: Number(5),
            signed_until_ms: Number(5),
            reader: record(),
            root_writer: record(),
        },
        current,
    }
}

#[test]
fn serialized_pending_and_current_keys_match_the_shared_signing_input_vector() {
    let v = vector();
    for phase in ["empty", "active", "withdrawn"] {
        let bytes = encode(&pending(current(phase))).expect("encodes");
        let p: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(keys(&p), expected(&v["pending"]), "{phase} pending");
        assert_eq!(keys(&p["creation_source"]), expected(&v["creation_source"]));
        assert_eq!(
            keys(&p["creation_source"]["reader"]),
            expected(&v["record"])
        );
        assert_eq!(
            keys(&p["creation_source"]["root_writer"]),
            expected(&v["record"])
        );
        assert_eq!(p["current"]["phase"], phase);
        assert_eq!(keys(&p["current"]), expected(&v["current"][phase]));
    }
}

#[test]
fn serialized_prior_keys_and_original_create_keys_match_the_shared_vector() {
    let v = vector();
    let priors = [
        ("empty", Prior::Empty {}),
        (
            "active",
            Prior::Active {
                authorization: id(),
                generation: Number(1),
                digest: Fixed([4; 32]),
            },
        ),
        (
            "withdrawn",
            Prior::Withdrawn {
                authorization: id(),
                generation: Number(1),
                digest: Fixed([4; 32]),
            },
        ),
    ];
    for (phase, prior) in priors {
        let p = serde_json::to_value(&prior).expect("json");
        assert_eq!(p["phase"], phase);
        assert_eq!(keys(&p), expected(&v["prior"][phase]));
        // The original CREATE is request-only; its parser must accept the
        // exact key set the shared vector says the command expects.
        let create = serde_json::json!({
            "create_request": id(),
            "expected_revision": Number(0),
            "prior": prior,
            "selected_reader_id": Fixed([2; 32]),
            "compared_root_fingerprint": Fixed([3; 32]),
            "requested_until_ms": Number(700),
        });
        assert_eq!(keys(&create), expected(&v["create"]));
        let parsed: Result<Create, _> = parse(create.to_string().as_bytes());
        assert!(parsed.is_ok(), "{phase} create must parse");
    }
}
