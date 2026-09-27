// SPDX-License-Identifier: AGPL-3.0-only
// Explicit cross-client CI lane; no production entry point or radio effect.
use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

/// Directory under the Git-ignored repository `target/` that receives the Android inputs.
const OUTPUT_DIR: &str = "zrotext-sealed-interop";

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

#[tokio::test]
#[ignore = "requires PostgreSQL, built TypeScript SDK and no stale target/zrotext-sealed-interop directory; run the cross-client CI command"]
async fn actual_sdk_ciphertext_verifies_persists_and_replays_without_extra_effects() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    // A fixed location derived only from the compile-time manifest directory, never from an
    // environment variable or argument. `/target/` is ignored by Git, so the synthetic keys
    // cannot be committed. Exclusive creation refuses a directory left by an earlier run, so
    // a stale fixture can never be handed to the Android step.
    let build = repo.join("target");
    fs::create_dir_all(&build).unwrap();
    let out = build.join(OUTPUT_DIR);
    fs::create_dir(&out).expect("remove the previous target/zrotext-sealed-interop directory");
    let f = TestCase::new().await;
    let message = Uuid::new_v4();
    let event = Uuid::new_v4();
    let clock = now(&f.db).await;
    let previous_digest = Sha256::digest(&f.bytes[..f.bytes.len() - 64]);
    // These routing selectors and trust inputs come from test setup, never parsed ciphertext.
    let setup = json!({
        "now": clock, "account": hex(f.account.as_bytes()),
        "device": hex(f.device.as_bytes()), "line": hex(f.line.as_bytes()),
        "message": hex(message.as_bytes()), "event": hex(event.as_bytes()),
        "rootPin": hex(&f.pin), "rootScalar": hex(&f.root.to_bytes()),
        "outboundSignerScalar": hex(&f.event_signer.to_bytes()),
        "previousVersion": 1, "previousDigest": hex(&previous_digest),
    });
    // Setup goes to the generator on stdin and the fixture returns on stdout.
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
        .write_all(&serde_json::to_vec_pretty(&setup).unwrap())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "generator: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stdout.len() <= 256 * 1024,
        "generated fixture exceeds size bound"
    );
    let mut fixture: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(fixture["fixtureVersion"], 1);
    let manifest = bytes(&fixture, "manifest");
    let inbound = bytes(&fixture, "inboundEnvelope");
    let outbound = bytes(&fixture, "outboundEnvelope");
    let wrong_signature = bytes(&fixture, "outboundWrongSignature");
    let accepted = crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &manifest,
        &inbound,
    )
    .await
    .unwrap();
    assert!(accepted.created);
    assert_eq!(accepted.event_id, event);
    let replay = crate::sealed_inbound::ingest::ingest_candidate02(
        &mut f.connect().await,
        f.session(),
        f.line,
        1,
        &manifest,
        &inbound,
    )
    .await
    .unwrap();
    assert!(!replay.created);
    let row = f.db.query_one("SELECT envelope,unsigned_digest FROM sealed_inbound_events WHERE account_id=$1 AND id=$2", &[&f.account,&event]).await.unwrap();
    let persisted_inbound: Vec<u8> = row.get(0);
    assert_eq!(persisted_inbound, inbound);
    assert_eq!(
        row.get::<_, Vec<u8>>(1),
        bytes(&fixture, "inboundUnsignedDigest")
    );

    assert!(matches!(
        f.admit(&wrong_signature).await,
        Err(AdmitError::Verification(_))
    ));
    assert_eq!(counts(&f).await, (0, 0, 0));
    assert!(f.admit(&outbound).await.unwrap().created);
    assert!(!f.admit(&outbound).await.unwrap().created);
    assert_eq!(counts(&f).await, (1, 1, 1));
    let row=f.db.query_one("SELECT transport_mode,transport_payload,sealed_binding_generation,request_digest FROM messages WHERE account_id=$1 AND id=$2", &[&f.account,&message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "sealed_candidate02");
    let persisted_outbound: Vec<u8> = row.get(1);
    assert_eq!(persisted_outbound, outbound);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(
        row.get::<_, Vec<u8>>(3),
        bytes(&fixture, "outboundUnsignedDigest")
    );
    fixture["persistedOutboundEnvelope"] = json!(hex(&persisted_outbound));
    fixture["persistedInboundEnvelope"] = json!(hex(&persisted_inbound));
    fixture["persistedOutboundSha256"] = json!(hex(&Sha256::digest(&persisted_outbound)));
    fixture["persistedInboundSha256"] = json!(hex(&Sha256::digest(&persisted_inbound)));
    fs::write(
        out.join("persisted-fixture.json"),
        serde_json::to_vec_pretty(&fixture).unwrap(),
    )
    .unwrap();
    let context = json!({
        "now": clock, "accountId": setup["account"], "deviceId": setup["device"],
        "lineId": setup["line"], "messageId": setup["message"], "peer": "+12",
        "rootPin": setup["rootPin"], "rootFingerprint": fixture["rootFingerprint"],
        "generation": 1, "previousVersion": 1, "previousDigest": setup["previousDigest"],
        "signerKeyId": fixture["signerKeyId"], "deviceKeyId": fixture["deviceKeyId"],
        "archiveKeyId": fixture["archiveKeyId"], "devicePoint": fixture["devicePoint"],
        "devicePrivateScalar": fixture["devicePrivateScalar"],
        "unsignedDigest": fixture["outboundUnsignedDigest"], "expectedText": fixture["expectedText"],
    });
    fs::write(
        out.join("expected-context.json"),
        serde_json::to_vec_pretty(&context).unwrap(),
    )
    .unwrap();
    f.cleanup().await;
}
