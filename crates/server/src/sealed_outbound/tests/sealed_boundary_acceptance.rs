// SPDX-License-Identifier: AGPL-3.0-only
// Integrated downgrade and leakage acceptance layer of the sealed boundary
// harness (issue #632). This lane EXTENDS the cross-client chain: the
// TypeScript SDK composes real envelopes carrying a synthetic marker in the
// plaintext content, the strict http_sealed route admits or refuses them
// through the production router, PostgreSQL persists the results, and a
// canary fixture handoff feeds the Android reader leg. Everything here needs
// a disposable PostgreSQL and a built SDK, so it is feature-gated exactly
// like cross_client_interop and never runs in the ordinary workspace test.
use super::*;
use crate::sealed_marker::{Marker, present};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
use tower::ServiceExt;

/// Directory under the Git-ignored repository `target/` that receives the
/// Android inputs for this lane; distinct from the cross-client lane's.
const OUTPUT_DIR: &str = "zrotext-sealed-boundary";
const SEALED_TYPE: &str = crate::http_sealed::SEALED_CONTENT_TYPE;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(value: &Value, name: &str) -> Vec<u8> {
    let text = value[name].as_str().expect("hex field");
    assert!(text.len() <= 2 * 36_864, "hex field exceeds envelope bound");
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Compose real envelopes through the TypeScript production modules. Setup
/// arrives on stdin and the fixture leaves on stdout; no path is
/// caller-chosen and no file is opened by the generator itself.
async fn compose_via_sdk(setup: &Value) -> Value {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut child = Command::new("node")
        .arg(repo.join("sdk/typescript/test/support/generate-cross-client.mjs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec_pretty(setup).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "generator: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.len() <= 256 * 1024, "fixture size bound");
    serde_json::from_slice(&result.stdout).unwrap()
}

/// The pinned setup every leg of this lane shares. The harness root and the
/// outbound signer are the fixture's own keys, so every returned manifest is
/// signed by exactly the root the fixture provisioned, and the marker rides
/// in the plaintext content of every generated envelope.
async fn sdk_fixture(f: &TestCase, marker: &Marker) -> Value {
    let clock = now(&f.db).await;
    let previous_digest = Sha256::digest(&f.bytes[..f.bytes.len() - 64]);
    let setup = json!({
        "now": clock, "account": hex(f.account.as_bytes()),
        "device": hex(f.device.as_bytes()), "line": hex(f.line.as_bytes()),
        "message": hex(Uuid::new_v4().as_bytes()),
        "event": hex(Uuid::new_v4().as_bytes()),
        "rootPin": hex(&f.pin), "rootScalar": hex(&f.root.to_bytes()),
        "outboundSignerScalar": hex(&f.event_signer.to_bytes()),
        "previousVersion": 1, "previousDigest": hex(&previous_digest),
        "contentText": marker.as_str(),
    });
    let fixture = compose_via_sdk(&setup).await;
    // Positive control: the marker must genuinely be the client-side
    // plaintext. Without this, every absence assertion below could pass
    // vacuously because the generator ignored the content override.
    assert_eq!(fixture["expectedText"].as_str(), Some(marker.as_str()));
    fixture
}

/// The SDK manifest's version, semantic digest and the reader/signer
/// identities the envelopes composed under it must reference.
struct SdkAuthority {
    manifest: Vec<u8>,
    version: u64,
    digest: [u8; 32],
    signer_id: [u8; 32],
    readers: [(u8, [u8; 32]); 2],
}

fn sdk_authority(fixture: &Value) -> SdkAuthority {
    let manifest = bytes(fixture, "manifest");
    let digest: [u8; 32] = Sha256::digest(&manifest[..manifest.len() - 64]).into();
    SdkAuthority {
        version: u64::from_be_bytes(manifest[29..37].try_into().unwrap()),
        digest,
        signer_id: bytes(fixture, "signerKeyId").try_into().unwrap(),
        readers: [
            (1, bytes(fixture, "deviceKeyId").try_into().unwrap()),
            (2, bytes(fixture, "archiveKeyId").try_into().unwrap()),
        ],
        manifest,
    }
}

fn boundary_router(f: &TestCase, billing_enabled: bool) -> axum::Router {
    let state = crate::http_sealed::SealedHttpState::new(
        // Assembled at runtime; never a literal that could look credential-shaped.
        format!("{}?options=-csearch_path%3D{}", f.url, f.schema),
        Arc::new(TokenHasher::new(crate::test_keys::key(76)).unwrap()),
        "manifest-test".into(),
        1,
        billing_enabled,
    )
    .unwrap();
    crate::http_sealed::router(state)
}

fn disabled_router(f: &TestCase) -> axum::Router {
    crate::http_sealed::router(crate::http_sealed::SealedHttpState::disabled(
        format!("{}?options=-csearch_path%3D{}", f.url, f.schema),
        Arc::new(TokenHasher::new(crate::test_keys::key(76)).unwrap()),
    ))
}

fn sealed_submit(token: &str, content_type: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/messages")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap()
}

async fn respond(response: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Accepted {
    message_id: Uuid,
    created: bool,
}

async fn route_admit(
    app: &axum::Router,
    token: &str,
    body: Vec<u8>,
) -> Result<Accepted, (StatusCode, Vec<u8>)> {
    let (status, body) = respond(
        app.clone()
            .oneshot(sealed_submit(token, SEALED_TYPE, body))
            .await
            .unwrap(),
    )
    .await;
    match status {
        StatusCode::ACCEPTED => Ok(serde_json::from_slice(&body).unwrap()),
        _ => Err((status, body)),
    }
}

/// Refuse one input through the live router and prove the refusal speaks a
/// stable code and nothing else: the body must equal the exact JSON for that
/// code, so no fragment of the submitted bytes can ever ride back.
async fn expect_code(
    app: &axum::Router,
    token: &str,
    content_type: &str,
    body: Vec<u8>,
    status: StatusCode,
    code: &str,
    name: &str,
) {
    let (seen, body_out) = respond(
        app.clone()
            .oneshot(sealed_submit(token, content_type, body))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(seen, status, "{name}: status");
    let mut expected = br#"{"code":""#.to_vec();
    expected.extend_from_slice(code.as_bytes());
    expected.extend_from_slice(br#""}"#);
    assert_eq!(body_out, expected, "{name}: codes only, never input bytes");
}

/// The variable parts of a route-level envelope: everything except the
/// fixture-bound account, line and wrap points.
struct Composed<'a> {
    device: Uuid,
    id: Uuid,
    keyset_version: u64,
    manifest_digest: [u8; 32],
    signer_id: [u8; 32],
    recipients: &'a [(u8, [u8; 32])],
    observed: i64,
    lifetime: i64,
}

/// A route-level outbound envelope composed in Rust so single fields can be
/// varied while the signature stays valid. Layout mirrors the shared
/// SQL-composition fixture; it is not a decryption claim.
fn composed_envelope(f: &TestCase, spec: &Composed<'_>) -> Vec<u8> {
    let mut b = b"ZTSE\x02\x01\0\0".to_vec();
    b.extend(157u16.to_be_bytes());
    b.extend(f.account.as_bytes());
    b.extend(spec.id.as_bytes());
    b.extend(spec.device.as_bytes());
    b.extend(f.line.as_bytes());
    b.extend(spec.keyset_version.to_be_bytes());
    b.extend(spec.manifest_digest);
    b.extend(spec.signer_id);
    b.extend((spec.observed as u64).to_be_bytes());
    b.extend(((spec.observed + spec.lifetime) as u64).to_be_bytes());
    b.extend([1, 3]);
    b.extend(b"+12");
    b.extend([4; 12]);
    b.extend(17u32.to_be_bytes());
    b.extend([7; 17]);
    b.push(spec.recipients.len() as u8);
    for (role, key_id) in spec.recipients {
        b.push(*role);
        b.extend_from_slice(key_id);
        b.extend(f.root.verifying_key().to_sec1_point(false).as_bytes());
        b.extend([9; 48]);
    }
    b.extend([0; 64]);
    signed(f, &mut b);
    b
}

async fn install_manifest(f: &TestCase, manifest: &[u8]) {
    let digest = Sha256::digest(&manifest[..manifest.len() - 64]);
    let version = u64::from_be_bytes(manifest[29..37].try_into().unwrap()) as i64;
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET version=$2,semantic_digest=$3,manifest=$4 WHERE account_id=$1",
        &[&f.account, &version, &digest.as_slice(), &manifest],
    ).await.unwrap();
}

/// The next link of the manifest chain: same root and records, version
/// bumped, anchored on the current semantic digest, re-signed by the
/// fixture root (the same root the SDK used).
fn advanced_manifest(f: &TestCase, source: &[u8]) -> Vec<u8> {
    let mut next = source.to_vec();
    let version = u64::from_be_bytes(next[29..37].try_into().unwrap());
    next[29..37].copy_from_slice(&(version + 1).to_be_bytes());
    let digest = Sha256::digest(&source[..source.len() - 64]);
    next[53..85].copy_from_slice(&digest);
    let unsigned = next.len() - 64;
    let signature: Signature = f.root.sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned as u32).to_be_bytes(),
            &next[..unsigned],
        ]
        .concat(),
    );
    next[unsigned..].copy_from_slice(&signature.normalize_s().to_bytes());
    next
}

/// A second root-ceremony fork: every record stays, the header root point
/// and the root-role record point move to `root`, and the whole manifest is
/// re-signed by that root and pinned to that root's own pin. Internally
/// self-consistent — exactly the competing authority a split ceremony would
/// produce, not malformed input.
fn forked_authority(
    source: &[u8],
    root: &SigningKey,
    account: Uuid,
    generation: u64,
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let point = root.verifying_key().to_sec1_point(false);
    let mut forked = source.to_vec();
    forked[85..150].copy_from_slice(point.as_bytes());
    let count = forked[150] as usize;
    let mut offset = 151usize;
    let mut root_record = None;
    for _ in 0..count {
        if forked[offset] == 6 {
            root_record = Some(offset);
        }
        offset += 149;
    }
    let root_record = root_record.expect("root role record in manifest");
    forked[root_record + 33..root_record + 98].copy_from_slice(point.as_bytes());
    let mut pin = b"ZTRP\x02".to_vec();
    pin.extend(account.as_bytes());
    pin.extend(generation.to_be_bytes());
    pin.extend(point.as_bytes());
    let unsigned = forked.len() - 64;
    let signature: Signature = root.sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned as u32).to_be_bytes(),
            &forked[..unsigned],
        ]
        .concat(),
    );
    forked[unsigned..].copy_from_slice(&signature.normalize_s().to_bytes());
    let fingerprint: [u8; 32] =
        Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat()).into();
    (forked, pin, fingerprint)
}

async fn insert_scoped_credential(f: &TestCase, text: &str, scope: &str) {
    let id = Uuid::new_v4();
    let pepper = crate::test_keys::key(76);
    let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
    mac.update(b"api-key-v1\0");
    mac.update(text.as_bytes());
    let token_hash = mac.finalize().into_bytes().to_vec();
    f.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) VALUES($1,$2,$3,$4,$5,ARRAY[$6],$7)",
        &[&id,&f.account,&f.user,&&text[4..16],&token_hash,&scope,&f.device]).await.unwrap();
}

/// Scan every binary and character column the fixture schema persists for
/// the marker. This is the same content a logical backup of the schema would
/// carry, so one scan covers the database and backup surfaces at once.
/// Returns every "table.column" containing the needle.
async fn scan_schema_for(f: &TestCase, needle: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    let rows =
        f.db.query(
            "SELECT table_name,column_name,udt_name FROM information_schema.columns \
         WHERE table_schema=$1 AND udt_name IN ('bytea','text','varchar') ORDER BY 1,2",
            &[&f.schema],
        )
        .await
        .unwrap();
    assert!(
        !rows.is_empty(),
        "schema column scan found nothing to inspect"
    );
    for row in &rows {
        let table: String = row.get(0);
        let column: String = row.get(1);
        let kind: String = row.get(2);
        let values =
            f.db.query(&format!(r#"SELECT "{column}" FROM "{table}""#), &[])
                .await
                .unwrap();
        for value in &values {
            let found = if kind == "bytea" {
                present(
                    value
                        .get::<_, Option<Vec<u8>>>(0)
                        .as_deref()
                        .unwrap_or_default(),
                    needle,
                )
            } else {
                present(
                    value
                        .get::<_, Option<String>>(0)
                        .as_deref()
                        .map(str::as_bytes)
                        .unwrap_or_default(),
                    needle,
                )
            };
            if found {
                hits.push(format!("{table}.{column}"));
            }
        }
    }
    hits
}

#[tokio::test]
#[ignore = "requires PostgreSQL, a built TypeScript SDK and no stale target/zrotext-sealed-boundary directory; run the cross-client CI command"]
async fn downgrade_inputs_are_refused_across_every_admission_flag_state() {
    let marker = Marker::generate("downgrade");
    let f = TestCase::new().await;
    let fixture = sdk_fixture(&f, &marker).await;
    let authority = sdk_authority(&fixture);
    let app = boundary_router(&f, true);
    let clock = now(&f.db).await;

    // Phase 1: the fixture's own manifest is the current authority, so a
    // valid Rust-composed envelope is admitted once and every refusal below
    // is measured against a live, working route.
    let digest: [u8; 32] = Sha256::digest(&f.bytes[..f.bytes.len() - 64]).into();
    let residents: Vec<(u8, [u8; 32])> = f.readers.iter().map(|r| (r.role, r.key_id)).collect();
    let resident = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: Uuid::new_v4(),
            keyset_version: 1,
            manifest_digest: digest,
            signer_id: f.signer,
            recipients: &residents,
            observed: clock,
            lifetime: 60_000,
        },
    );
    assert!(
        route_admit(&app, &f.token, resident.clone())
            .await
            .unwrap()
            .created
    );

    // Unsupported device: a different, validly signed envelope naming a
    // device the credential is not bound to and the account never enrolled.
    let foreign = composed_envelope(
        &f,
        &Composed {
            device: Uuid::new_v4(),
            id: Uuid::new_v4(),
            keyset_version: 1,
            manifest_digest: digest,
            signer_id: f.signer,
            recipients: &residents,
            observed: clock,
            lifetime: 60_000,
        },
    );
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        foreign,
        StatusCode::FORBIDDEN,
        "forbidden",
        "unsupported device",
    )
    .await;

    // Writer flag state: with billing binding off and a billed customer, the
    // route fails closed instead of admitting without a reservation. The
    // customer row is then removed so the mounted-flag phases below measure
    // the plain unbilled-account path.
    f.db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_boundaryTest')",
        &[&f.account],
    )
    .await
    .unwrap();
    let unbilled = boundary_router(&f, false);
    let fresh = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: Uuid::new_v4(),
            keyset_version: 1,
            manifest_digest: digest,
            signer_id: f.signer,
            recipients: &residents,
            observed: clock,
            lifetime: 60_000,
        },
    );
    expect_code(
        &unbilled,
        &f.token,
        SEALED_TYPE,
        fresh,
        StatusCode::SERVICE_UNAVAILABLE,
        "billing_pending",
        "billing writer flag off",
    )
    .await;
    f.db.execute(
        "DELETE FROM billing_customers WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();

    // Phase 2: install the SDK manifest as the current authority, exactly as
    // the real inbound admission advance would have stored it, and prove the
    // production composer's own bytes still clear the live route.
    install_manifest(&f, &authority.manifest).await;
    let production = bytes(&fixture, "outboundProductionEnvelope");
    let production_message = Uuid::from_slice(&bytes(&fixture, "productionMessage")).unwrap();
    let accepted = route_admit(&app, &f.token, production.clone())
        .await
        .unwrap();
    assert!(accepted.created);
    assert_eq!(accepted.message_id, production_message);

    // Adversarial SDK vectors through the real route.
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        bytes(&fixture, "outboundDowngradeV1"),
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "downgraded profile byte",
    )
    .await;
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        bytes(&fixture, "outboundWrongAccount"),
        StatusCode::FORBIDDEN,
        "forbidden",
        "foreign account",
    )
    .await;
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        bytes(&fixture, "outboundWrongSignature"),
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "tampered signature",
    )
    .await;

    // Plaintext fallback under the sealed media type: parser refusal.
    let mut plaintext = marker.as_bytes().to_vec();
    plaintext.resize(500, b' ');
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        plaintext,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "plaintext fallback",
    )
    .await;
    expect_code(
        &app,
        &f.token,
        "application/json",
        production.clone(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        "json media type",
    )
    .await;
    expect_code(
        &app,
        "",
        SEALED_TYPE,
        production.clone(),
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing bearer",
    )
    .await;

    // Read-only credential: authorization, not parse.
    let read_only = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    insert_scoped_credential(&f, &read_only, "messages:read").await;
    expect_code(
        &app,
        &read_only,
        SEALED_TYPE,
        production.clone(),
        StatusCode::FORBIDDEN,
        "forbidden",
        "read-only scope",
    )
    .await;

    // Phase 3: stale authority. The chain advances under the same root; the
    // already-admitted production bytes reference the previous digest and
    // must now fail closed. The route answers at the verification fence with
    // its stable invalid_request code and no detail about which binding
    // failed, so a stale caller learns nothing beyond the refusal.
    let advanced = advanced_manifest(&f, &authority.manifest);
    install_manifest(&f, &advanced).await;
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        production.clone(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "stale authority",
    )
    .await;

    // Phase 4: forked authority. A second ceremony with a different root is
    // fully self-consistent — its manifest verifies under its own pin — but
    // it can neither replace the provisioned trust anchor nor enter through
    // the real inbound admission transaction, so nothing composed under it
    // can ever be admitted. Both refusals are the fail-closed outcome.
    let fork_root = SigningKey::generate_from_rng(&mut rand::rng());
    let (forked, fork_pin, fork_fingerprint) =
        forked_authority(&advanced, &fork_root, f.account, 1);
    let fork_digest = Sha256::digest(&forked[..forked.len() - 64])
        .as_slice()
        .to_vec();
    let swap = f.db.execute(
        "UPDATE sealed_manifest_authorities SET root_pin=$2,root_fingerprint=$3,manifest=$4,semantic_digest=$5 WHERE account_id=$1",
        &[&f.account, &fork_pin, &fork_fingerprint.as_slice(), &forked, &fork_digest],
    ).await;
    let swap_error = swap.unwrap_err();
    let guard = swap_error.as_db_error().unwrap();
    assert_eq!(
        guard.code().code(),
        "23514",
        "trust-anchor swap must violate the authority guard"
    );
    assert!(
        guard.message().contains("cannot change trust"),
        "guard message: {}",
        guard.message()
    );
    let inbound_envelope = bytes(&fixture, "inboundEnvelope");
    let fork_ingest = crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &forked,
        &inbound_envelope,
    )
    .await;
    assert!(
        matches!(
            fork_ingest,
            Err(crate::sealed_inbound::ingest::IngestError::Authority(_))
        ),
        "a self-consistent fork manifest must fail closed at real admission"
    );

    // Phase 5: a revoked credential fails closed on the mounted route, and
    // the unmounted flag state fails closed for every input shape whatever
    // else the request gets right.
    f.db.execute(
        "UPDATE api_keys SET revoked_at=now() WHERE account_id=$1 AND public_prefix=$2",
        &[&f.account, &&f.token[4..16]],
    )
    .await
    .unwrap();
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        production.clone(),
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "revoked credential",
    )
    .await;
    let dark = disabled_router(&f);
    for (name, content_type, body) in [
        ("valid bytes", SEALED_TYPE, production.clone()),
        (
            "plaintext fallback",
            SEALED_TYPE,
            marker.as_bytes().to_vec(),
        ),
        ("wrong media type", "application/json", production.clone()),
        ("no bearer", SEALED_TYPE, production.clone()),
    ] {
        let token: &str = if name == "no bearer" {
            ""
        } else {
            f.token.as_str()
        };
        let (status, body_out) = respond(
            dark.clone()
                .oneshot(sealed_submit(token, content_type, body))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unmounted route, {name}");
        assert_eq!(
            body_out, br#"{"code":"not_found"}"#,
            "unmounted route, {name}"
        );
        assert!(!present(&body_out, marker.as_bytes()));
    }

    // Exactly the two deliberate admissions were stored; every refusal
    // left no row, no job and no reservation behind.
    assert_eq!(counts(&f).await, (2, 2, 2));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL, a built TypeScript SDK and no stale target/zrotext-sealed-boundary directory; run the cross-client CI command"]
async fn marker_content_never_reaches_storage_digests_or_error_surfaces() {
    let marker = Marker::generate("leakage");
    let f = TestCase::new().await;
    let fixture = sdk_fixture(&f, &marker).await;
    let authority = sdk_authority(&fixture);
    let app = boundary_router(&f, true);
    let clock = now(&f.db).await;

    // The full journey: inbound ingest through the real admission
    // transaction (which also advances the stored authority), internal
    // outbound queueing, and production-path admission through the router.
    let inbound = bytes(&fixture, "inboundEnvelope");
    let accepted_inbound = crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &authority.manifest,
        &inbound,
    )
    .await
    .unwrap();
    assert!(accepted_inbound.created);
    let outbound = bytes(&fixture, "outboundEnvelope");
    assert!(f.admit(&outbound).await.unwrap().created);
    let production = bytes(&fixture, "outboundProductionEnvelope");
    let production_message = Uuid::from_slice(&bytes(&fixture, "productionMessage")).unwrap();
    assert!(
        route_admit(&app, &f.token, production.clone())
            .await
            .unwrap()
            .created
    );

    // Opaque bytes are preserved exactly on every persisted surface.
    let row =
        f.db.query_one(
            "SELECT (SELECT envelope FROM sealed_inbound_events WHERE account_id=$1 AND id=$2), \
         (SELECT transport_payload FROM messages WHERE account_id=$1 AND id=$3), \
         (SELECT transport_payload FROM messages WHERE account_id=$1 AND id=$4), \
         (SELECT request_digest FROM messages WHERE account_id=$1 AND id=$4), \
         (SELECT unsigned_digest FROM sealed_inbound_events WHERE account_id=$1 AND id=$2)",
            &[
                &f.account,
                &accepted_inbound.event_id,
                &Uuid::from_slice(&bytes(&fixture, "message")).unwrap(),
                &production_message,
            ],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), inbound);
    assert_eq!(row.get::<_, Vec<u8>>(1), outbound);
    assert_eq!(row.get::<_, Vec<u8>>(2), production);
    let request_digest: Vec<u8> = row.get(3);
    let unsigned_digest: Vec<u8> = row.get(4);
    // Digests cover ciphertext-bearing bytes only.
    assert_eq!(
        request_digest.as_slice(),
        bytes(&fixture, "outboundProductionFreshDigest")
    );
    assert_eq!(
        request_digest.as_slice(),
        Sha256::digest(&production[..production.len() - 64]).as_slice()
    );
    assert_eq!(unsigned_digest, bytes(&fixture, "inboundUnsignedDigest"));
    assert!(!present(&request_digest, marker.as_bytes()));

    // The database scan must be empty for the marker, and its positive
    // control must fire: a probe row planted with the marker is found in the
    // very next scan, so the all-clear above cannot be vacuous.
    assert!(
        scan_schema_for(&f, marker.as_bytes()).await.is_empty(),
        "marker reached a persisted column"
    );
    f.db.execute("CREATE TABLE marker_probe(probe bytea)", &[])
        .await
        .unwrap();
    f.db.execute(
        "INSERT INTO marker_probe(probe) VALUES($1)",
        &[&marker.as_bytes().to_vec()],
    )
    .await
    .unwrap();
    let probe_hits = scan_schema_for(&f, marker.as_bytes()).await;
    assert_eq!(
        probe_hits,
        vec!["marker_probe.probe".to_string()],
        "positive control must find the planted marker"
    );
    f.db.execute("DROP TABLE marker_probe", &[]).await.unwrap();

    // Error, retry and replay surfaces: every response body must equal the
    // exact stable JSON for that outcome, so neither the marker nor any
    // envelope fragment can ride back. There is no logging in the sealed
    // path (the crate has no logging dependency), which makes responses and
    // persisted values the complete observable surface.
    let replay = app
        .clone()
        .oneshot(sealed_submit(&f.token, SEALED_TYPE, production.clone()))
        .await
        .unwrap();
    let (replay_status, replay_body) = respond(replay).await;
    assert_eq!(replay_status, StatusCode::ACCEPTED);
    assert_eq!(
        replay_body,
        serde_json::to_vec(&Accepted {
            message_id: production_message,
            created: false
        })
        .unwrap()
    );
    let conflicting = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: production_message,
            keyset_version: authority.version,
            manifest_digest: authority.digest,
            signer_id: authority.signer_id,
            recipients: &authority.readers,
            observed: clock + 1000,
            lifetime: 60_000,
        },
    );
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        conflicting,
        StatusCode::CONFLICT,
        "idempotency_conflict",
        "conflicting replay",
    )
    .await;
    let mut tampered = production.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        tampered,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "tampered retry",
    )
    .await;
    let mut plaintext = marker.as_bytes().to_vec();
    plaintext.resize(500, b' ');
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        plaintext,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "plaintext retry",
    )
    .await;
    expect_code(
        &app,
        &f.token,
        "text/plain",
        production.clone(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
        "wrong media retry",
    )
    .await;
    let oversized = [production.as_slice(), &[0u8; 36_865][..]].concat();
    let oversize_response = app
        .clone()
        .oneshot(sealed_submit(&f.token, SEALED_TYPE, oversized))
        .await
        .unwrap();
    assert_eq!(
        respond(oversize_response).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // Hand the persisted canary ciphertext to the Android reader leg.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let build = repo.join("target");
    fs::create_dir_all(&build).unwrap();
    let out = build.join(OUTPUT_DIR);
    fs::create_dir(&out).expect("remove the previous target/zrotext-sealed-boundary directory");
    let canary_fixture = json!({
        "fixtureVersion": 1,
        "manifest": fixture["manifest"], "canaryText": marker.as_str(),
        "persistedInboundEnvelope": hex(&inbound),
        "persistedOutboundEnvelope": hex(&outbound),
        "persistedProductionEnvelope": hex(&production),
    });
    let canary_context = json!({
        "now": clock, "accountId": hex(f.account.as_bytes()),
        "deviceId": hex(f.device.as_bytes()), "lineId": hex(f.line.as_bytes()),
        "peer": "+12", "rootPin": fixture["rootPin"], "rootFingerprint": fixture["rootFingerprint"],
        "generation": 1, "previousVersion": 1, "previousDigest": fixture["previousDigest"],
        "signerKeyId": fixture["signerKeyId"], "deviceKeyId": fixture["deviceKeyId"],
        "archiveKeyId": fixture["archiveKeyId"], "devicePoint": fixture["devicePoint"],
        "devicePrivateScalar": fixture["devicePrivateScalar"],
        "messageId": fixture["message"], "productionMessageId": fixture["productionMessage"],
        "unsignedDigest": fixture["outboundUnsignedDigest"],
        "productionUnsignedDigest": fixture["outboundProductionFreshDigest"],
        "canaryText": marker.as_str(),
    });
    fs::write(
        out.join("canary-fixture.json"),
        serde_json::to_vec_pretty(&canary_fixture).unwrap(),
    )
    .unwrap();
    fs::write(
        out.join("canary-context.json"),
        serde_json::to_vec_pretty(&canary_context).unwrap(),
    )
    .unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL, a built TypeScript SDK and no stale target/zrotext-sealed-boundary directory; run the cross-client CI command"]
async fn stored_sealed_bytes_survive_restart_replay_conflict_and_revocation() {
    let marker = Marker::generate("durability");
    let f = TestCase::new().await;
    let fixture = sdk_fixture(&f, &marker).await;
    let authority = sdk_authority(&fixture);
    let app = boundary_router(&f, true);
    let clock = now(&f.db).await;
    install_manifest(&f, &authority.manifest).await;

    // Persist through the first router instance.
    let production = bytes(&fixture, "outboundProductionEnvelope");
    let production_message = Uuid::from_slice(&bytes(&fixture, "productionMessage")).unwrap();
    assert!(
        route_admit(&app, &f.token, production.clone())
            .await
            .unwrap()
            .created
    );
    async fn stored(f: &TestCase, message: Uuid) -> Vec<u8> {
        f.db.query_one(
            "SELECT transport_payload FROM messages WHERE account_id=$1 AND id=$2",
            &[&f.account, &message],
        )
        .await
        .unwrap()
        .get::<_, Vec<u8>>(0)
    }
    assert_eq!(stored(&f, production_message).await, production);

    // Restart: a brand-new state and router over the same database replay
    // the exact bytes as created:false and never rewrite them.
    let restarted = boundary_router(&f, true);
    let replay = route_admit(&restarted, &f.token, production.clone())
        .await
        .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.message_id, production_message);
    assert_eq!(stored(&f, production_message).await, production);

    // A conflicting digest under the same identity refuses and leaves the
    // original bytes untouched.
    let conflicting = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: production_message,
            keyset_version: authority.version,
            manifest_digest: authority.digest,
            signer_id: authority.signer_id,
            recipients: &authority.readers,
            observed: clock + 1000,
            lifetime: 60_000,
        },
    );
    expect_code(
        &restarted,
        &f.token,
        SEALED_TYPE,
        conflicting,
        StatusCode::CONFLICT,
        "idempotency_conflict",
        "different digest replay",
    )
    .await;
    assert_eq!(stored(&f, production_message).await, production);

    // Key loss: revoking the manifest authority fails every later admission
    // closed — new identities and exact replays alike — while the stored
    // opaque bytes stay byte-for-byte intact.
    f.db.execute(
        "UPDATE sealed_manifest_authorities SET revoked_at=now() WHERE account_id=$1",
        &[&f.account],
    )
    .await
    .unwrap();
    let fresh = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: Uuid::new_v4(),
            keyset_version: authority.version,
            manifest_digest: authority.digest,
            signer_id: authority.signer_id,
            recipients: &authority.readers,
            observed: now(&f.db).await,
            lifetime: 60_000,
        },
    );
    expect_code(
        &restarted,
        &f.token,
        SEALED_TYPE,
        fresh,
        StatusCode::FORBIDDEN,
        "forbidden",
        "admission after authority revocation",
    )
    .await;
    expect_code(
        &restarted,
        &f.token,
        SEALED_TYPE,
        production.clone(),
        StatusCode::FORBIDDEN,
        "forbidden",
        "replay after authority revocation",
    )
    .await;
    assert_eq!(stored(&f, production_message).await, production);
    assert_eq!(counts(&f).await, (1, 1, 1));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run the cross-client CI command"]
async fn expired_authority_refuses_admission_and_preserves_stored_bytes() {
    let f = TestCase::with_manifest_lifetime(2500).await;
    let app = boundary_router(&f, true);
    let digest: [u8; 32] = Sha256::digest(&f.bytes[..f.bytes.len() - 64]).into();
    let residents: Vec<(u8, [u8; 32])> = f.readers.iter().map(|r| (r.role, r.key_id)).collect();
    let clock = now(&f.db).await;

    let id = Uuid::new_v4();
    let original = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id,
            keyset_version: 1,
            manifest_digest: digest,
            signer_id: f.signer,
            recipients: &residents,
            observed: clock,
            lifetime: 60_000,
        },
    );
    assert!(
        route_admit(&app, &f.token, original.clone())
            .await
            .unwrap()
            .created
    );
    let stored =
        f.db.query_one("SELECT transport_payload FROM messages WHERE id=$1", &[&id])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0);
    assert_eq!(stored, original);

    let deadline = u64::from_be_bytes(f.bytes[45..53].try_into().unwrap()) as i64;
    reach_clock(&f.db, deadline + 1).await;
    let fresh = composed_envelope(
        &f,
        &Composed {
            device: f.device,
            id: Uuid::new_v4(),
            keyset_version: 1,
            manifest_digest: digest,
            signer_id: f.signer,
            recipients: &residents,
            observed: now(&f.db).await,
            lifetime: 60_000,
        },
    );
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        fresh,
        StatusCode::FORBIDDEN,
        "forbidden",
        "admission after authority expiry",
    )
    .await;
    expect_code(
        &app,
        &f.token,
        SEALED_TYPE,
        original.clone(),
        StatusCode::FORBIDDEN,
        "forbidden",
        "replay after authority expiry",
    )
    .await;
    let stored =
        f.db.query_one("SELECT transport_payload FROM messages WHERE id=$1", &[&id])
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0);
    assert_eq!(
        stored, original,
        "expired authority must preserve opaque bytes"
    );
    f.cleanup().await;
}
