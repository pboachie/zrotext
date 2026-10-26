// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic public frames and maintained MFA enrollment boundaries.
use super::*;
use crate::http_owner_conversations::{
    ConversationConsent, activation, enable_conversation, revoke_conversation,
};
use p256::ecdsa::{Signature, signature::Signer};

// All signatures here are synthetic test data. Neither these core calls nor
// the unsigned proposal producer prove phone provenance or private root custody.
pub(super) fn signed(c: &GenuineCase, unsigned: &[u8]) -> Vec<u8> {
    let signature: Signature = c.root.sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned.len() as u32).to_be_bytes(),
            unsigned,
        ]
        .concat(),
    );
    [unsigned, signature.normalize_s().to_bytes().as_slice()].concat()
}
pub(super) async fn configured(remaining_ms: u64) -> (GenuineCase, Vec<u8>, ConversationConsent) {
    configured_at(remaining_ms, 0).await
}
pub(super) async fn configured_at(
    remaining_ms: u64,
    issued_age_ms: u64,
) -> (GenuineCase, Vec<u8>, ConversationConsent) {
    let c = GenuineCase::new().await;
    let now = c.now().await as u64;
    let (_, _, _, mut unsigned) = framed(&c, now.checked_sub(issued_age_ms).unwrap());
    unsigned[45..53].copy_from_slice(&(now + remaining_ms).to_be_bytes());
    for record in unsigned[151..].as_chunks_mut::<149>().0.iter_mut() {
        record[140..148].copy_from_slice(&(now + remaining_ms).to_be_bytes());
    }
    let before = signed(&c, &unsigned);
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let admission = crate::sealed_manifest_store::admit(&tx, c.session(), c.line, 1, &before)
        .await
        .unwrap();
    drop(admission);
    tx.commit().await.unwrap();
    drop(db);
    let consent = ConversationConsent {
        device_id: c.device,
        line_id: c.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: "conversation-content-v1".into(),
        content_transfer_confirmed: true,
    };
    (c, before, consent)
}
fn successor(before: &[u8], now: u64) -> Vec<u8> {
    let mut unsigned = before[..before.len() - 64].to_vec();
    let version = u64::from_be_bytes(unsigned[29..37].try_into().unwrap()) + 1;
    unsigned[29..37].copy_from_slice(&version.to_be_bytes());
    unsigned[37..45].copy_from_slice(&now.to_be_bytes());
    unsigned[53..85].copy_from_slice(&Sha256::digest(&before[..before.len() - 64]));
    unsigned
}
fn scope(c: &GenuineCase, magic: &[u8], interval: Option<Uuid>, before: &[u8]) -> Vec<u8> {
    let p = &c.owner.principal;
    let mut out = magic.to_vec();
    out.extend(p.tenant.account_id().as_bytes());
    out.extend(p.session_id.as_bytes());
    if let Some(interval) = interval {
        out.extend(interval.as_bytes());
    }
    out.extend(c.device.as_bytes());
    out.extend(c.line.as_bytes());
    out.extend(1u64.to_be_bytes());
    out.push(3);
    out.extend(b"+12");
    out.extend((ORIGIN.len() as u16).to_be_bytes());
    out.extend(ORIGIN.as_bytes());
    out.extend(
        zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &c.pin,
            p.tenant.account_id().as_bytes(),
        )
        .unwrap(),
    );
    out.extend(&before[29..37]);
    out.extend(Sha256::digest(&before[..before.len() - 64]));
    out
}
fn roles(before: &[u8], kind: u8) -> Vec<u8> {
    before[151..before.len() - 64]
        .as_chunks::<149>()
        .0
        .iter()
        .find(|record| record[0] == kind)
        .unwrap()[1..33]
        .to_vec()
}
fn sized(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u16).to_be_bytes());
    out.extend(bytes);
}
pub(super) fn activation_packet(c: &GenuineCase, before: &[u8], now: u64) -> Vec<u8> {
    let mut packet = scope(c, b"ZTCA\x01", None, before);
    for role in [1, 2, 4] {
        packet.extend(roles(before, role));
    }
    packet.extend(now.to_be_bytes());
    sized(&mut packet, before);
    sized(&mut packet, &successor(before, now));
    packet
}
pub(super) fn refresh_packet(c: &GenuineCase, before: &[u8], interval: Uuid, now: u64) -> Vec<u8> {
    let until = (now + 60000).min(u64::from_be_bytes(before[45..53].try_into().unwrap()));
    let point = point();
    let signer = id(5, &point);
    let mut next = successor(before, now);
    next[150] += 1;
    let record = [
        &[5][..],
        &signer,
        &point,
        &[0; 16],
        c.line.as_bytes(),
        &1u16.to_be_bytes(),
        &now.to_be_bytes(),
        &until.to_be_bytes(),
        &[1],
    ]
    .concat();
    // Role5 precedes the existing role6 owner record in canonical role order.
    let at = 151 + 3 * 149;
    next.splice(at..at, record);
    let mut packet = scope(c, b"ZTCF\x01", Some(interval), before);
    for role in [1, 2] {
        packet.extend(roles(before, role));
    }
    packet.extend(signer);
    packet.extend(point);
    packet.extend(until.to_be_bytes());
    sized(&mut packet, before);
    sized(&mut packet, &next);
    packet
}
pub(super) async fn activate(
    c: &GenuineCase,
    before: &[u8],
    consent: &ConversationConsent,
    pending: Option<&[u8]>,
) -> (Vec<u8>, Uuid) {
    let next = successor(before, c.now().await as u64);
    let manifest = signed(c, &next);
    let mut db = c.f.connect().await;
    let statement = activation::begin(&mut db, &c.owner.principal, consent, &manifest)
        .await
        .unwrap();
    if let Some(packet) = pending {
        let rows = c.rows().await;
        assert_eq!(context_of(c, 4, packet).await.0, StatusCode::CONFLICT);
        assert_eq!(c.rows().await, rows);
    }
    for (domain, install) in [
        (activation::statement::APPROVE_DOMAIN, false),
        (activation::statement::INSTALL_DOMAIN, true),
    ] {
        let signature: Signature = c.paired.sign(&statement.transcript(domain).unwrap());
        let signature = signature.normalize_s().to_bytes();
        if install {
            activation::installed(
                &mut db,
                c.session(),
                &statement.encode().unwrap(),
                &signature,
            )
            .await
            .unwrap();
        } else {
            activation::approve(
                &mut db,
                c.session(),
                &statement.encode().unwrap(),
                &signature,
            )
            .await
            .unwrap();
        }
    }
    (manifest, statement.interval)
}
pub(super) async fn issue(
    c: &GenuineCase,
    kind: i16,
    packet: &[u8],
) -> (StatusCode, serde_json::Value) {
    request(
        c,
        PATH,
        &serde_json::json!({"kind":kind,"proposal_b64":STANDARD.encode(packet),
        "expected_session_id":c.owner.principal.session_id}),
    )
    .await
}
pub(super) async fn context_of(
    c: &GenuineCase,
    kind: i16,
    packet: &[u8],
) -> (StatusCode, serde_json::Value) {
    let before = c.now().await;
    let result = request(
        c,
        CONTEXT_PATH,
        &serde_json::json!({"kind":kind,
        "proposal_sha256_hex":hex_bytes(&Sha256::digest(packet)),
        "expected_session_id":c.owner.principal.session_id}),
    )
    .await;
    let after = c.now().await;
    if result.0 == StatusCode::OK {
        assert!((before..=after).contains(&decimal(&result.1["server_now_ms"])));
    }
    result
}
fn assert_context(
    c: &GenuineCase,
    kind: i16,
    packet: &[u8],
    got: &serde_json::Value,
    receipt: &serde_json::Value,
) {
    let fields = [
        "v",
        "kind",
        "account_id",
        "user_id",
        "session_id",
        "origin",
        "root_fingerprint_hex",
        "proposal_sha256_hex",
        "proposal_b64",
        "expected_context",
        "server_now_ms",
        "expires_ms",
    ];
    let object = got.as_object().unwrap();
    assert_eq!(object.len(), 12);
    assert!(fields.iter().all(|key| object.contains_key(*key)));
    assert_eq!(got["v"], 1);
    assert_eq!(got["kind"], kind);
    for (name, id) in [
        ("account_id", c.owner.principal.tenant.account_id()),
        ("user_id", c.owner.principal.user_id),
        ("session_id", c.owner.principal.session_id),
    ] {
        assert_eq!(got[name], id.to_string());
    }
    assert_eq!(got["origin"], ORIGIN);
    assert_eq!(got["proposal_b64"], STANDARD.encode(packet));
    assert_eq!(
        got["proposal_sha256_hex"],
        hex_bytes(&Sha256::digest(packet))
    );
    assert_eq!(
        got["root_fingerprint_hex"],
        hex_bytes(
            &zrotext_root_material::sealed_root_enrollment::root_fingerprint(
                &c.pin,
                c.owner.principal.tenant.account_id().as_bytes()
            )
            .unwrap()
        )
    );
    assert_eq!(got["expires_ms"], receipt["expires_ms"]);
    assert!(decimal(&got["server_now_ms"]) < decimal(&got["expires_ms"]));
    assert!(got["expected_context"].is_object());
    assert_eq!(got["expected_context"]["scope"]["origin"], ORIGIN);
    assert_eq!(
        got["expected_context"]["scope"]["session"],
        hex_bytes(c.owner.principal.session_id.as_bytes())
    );
}
fn expected(
    c: &GenuineCase,
    kind: i16,
    packet: &[u8],
    before: &[u8],
    interval: Option<Uuid>,
) -> serde_json::Value {
    let fingerprint = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
        &c.pin,
        c.owner.principal.tenant.account_id().as_bytes(),
    )
    .unwrap();
    let mut scope = serde_json::json!({"account":hex_bytes(c.owner.principal.tenant.account_id().as_bytes()),
        "session":hex_bytes(c.owner.principal.session_id.as_bytes()),"device":hex_bytes(c.device.as_bytes()),
        "line":hex_bytes(c.line.as_bytes()),"line_generation":1,"peer":"+12","origin":ORIGIN,
        "fingerprint":hex_bytes(&fingerprint),"predecessor_version":u64::from_be_bytes(before[29..37].try_into().unwrap()),
        "predecessor_digest":hex_bytes(&Sha256::digest(&before[..before.len()-64])),
        "phone_reader":hex_bytes(&roles(before,1)),"archive_reader":hex_bytes(&roles(before,2))});
    // Independently assembled test wire offsets; no expected values are copied
    // from server context or its packet validation/serialization helpers.
    let base = 5 + 16 * 4 + 8 + 1 + 3 + 2 + ORIGIN.len() + 32 + 8 + 32;
    if kind == 4 {
        scope["phone_signer"] = serde_json::json!(hex_bytes(&roles(before, 4)));
        scope["issued_ms"] = serde_json::json!(u64::from_be_bytes(
            packet[base + 96..base + 104].try_into().unwrap()
        ));
    } else {
        let at = base + 16 + 64;
        scope["interval"] = serde_json::json!(hex_bytes(interval.unwrap().as_bytes()));
        scope["signer"] = serde_json::json!(hex_bytes(&packet[at..at + 32]));
        scope["point"] = serde_json::json!(hex_bytes(&packet[at + 32..at + 97]));
        scope["until_ms"] = serde_json::json!(u64::from_be_bytes(
            packet[at + 97..at + 105].try_into().unwrap()
        ));
    }
    serde_json::json!({"scope":scope})
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; synthetic core activation prerequisites"]
async fn activation_and_refresh_producers_preserve_exact_context_retry_and_consent() {
    let (c, before, consent) = configured(120000).await;
    let packet = activation_packet(&c, &before, c.now().await as u64);
    assert_eq!(issue(&c, 4, &packet).await.0, StatusCode::FORBIDDEN);
    assert!(c.rows().await.is_empty());
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let (status, receipt) = issue(&c, 4, &packet).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let rows = c.rows().await;
    assert_eq!(receipt.as_object().unwrap().len(), 5);
    assert_eq!(
        issue(&c, 4, &packet).await,
        (StatusCode::OK, receipt.clone())
    );
    assert_eq!(c.rows().await, rows);
    let (status, got) = context_of(&c, 4, &packet).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_context(&c, 4, &packet, &got, &receipt);
    assert_eq!(c.rows().await, rows);
    assert_eq!(
        got["expected_context"],
        expected(&c, 4, &packet, &before, None)
    );
    for name in ["phone_export_b64", "encrypted_archive_b64"] {
        for value in [serde_json::Value::Null, serde_json::json!("YQ==")] {
            let mut extra = serde_json::json!({"kind":4,"proposal_b64":STANDARD.encode(&packet),
                "expected_session_id":c.owner.principal.session_id});
            extra[name] = value;
            assert_eq!(request(&c, PATH, &extra).await.0, StatusCode::BAD_REQUEST);
            assert_eq!(c.rows().await, rows);
        }
    }
    let (before, interval) = activate(&c, &before, &consent, Some(&packet)).await;
    assert_eq!(context_of(&c, 4, &packet).await.0, StatusCode::FORBIDDEN);
    assert_eq!(c.rows().await, rows);
    let packet = refresh_packet(&c, &before, interval, c.now().await as u64);
    let (status, receipt) = issue(&c, 5, &packet).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let rows = c.rows().await;
    assert_eq!(
        issue(&c, 5, &packet).await,
        (StatusCode::OK, receipt.clone())
    );
    let (status, got) = context_of(&c, 5, &packet).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_context(&c, 5, &packet, &got, &receipt);
    assert_eq!(
        got["expected_context"],
        expected(&c, 5, &packet, &before, Some(interval))
    );
    for name in ["phone_export_b64", "encrypted_archive_b64"] {
        let mut extra = serde_json::json!({"kind":5,"proposal_b64":STANDARD.encode(&packet),
            "expected_session_id":c.owner.principal.session_id});
        extra[name] = serde_json::Value::Null;
        assert_eq!(request(&c, PATH, &extra).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(c.rows().await, rows);
    }
    assert_eq!(
        got["expected_context"]["scope"]["interval"],
        hex_bytes(interval.as_bytes())
    );
    assert_eq!(c.rows().await, rows);
    revoke_conversation(&mut c.f.connect().await, &c.owner.principal)
        .await
        .unwrap();
    assert_eq!(context_of(&c, 5, &packet).await.0, StatusCode::FORBIDDEN);
    assert_eq!(issue(&c, 5, &packet).await.0, StatusCode::FORBIDDEN);
    assert_eq!(c.rows().await, rows);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; independently live current and creator sessions"]
async fn refresh_refuses_lost_original_creator_even_with_another_live_owner_login() {
    let (mut c, before, consent) = configured(120000).await;
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let (before, interval) = activate(&c, &before, &consent, None).await;
    let original = c.owner.principal.session_id;
    let db = c.f.connect().await;
    c.owner.credentials = auth::login(&db, &c.hasher, &c.owner.email, &c.owner.password)
        .await
        .unwrap();
    c.owner.principal = auth::authenticate_session(&db, &c.hasher, &c.owner.credentials.token)
        .await
        .unwrap();
    assert_ne!(original, c.owner.principal.session_id);
    let packet = refresh_packet(&c, &before, interval, c.now().await as u64);
    assert_eq!(issue(&c, 5, &packet).await.0, StatusCode::OK);
    assert_eq!(context_of(&c, 5, &packet).await.0, StatusCode::OK);
    let rows = c.rows().await;
    db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&original],
    )
    .await
    .unwrap();
    assert!(
        auth::authenticate_session(&db, &c.hasher, &c.owner.credentials.token)
            .await
            .is_ok()
    );
    assert_eq!(context_of(&c, 5, &packet).await.0, StatusCode::FORBIDDEN);
    assert_eq!(issue(&c, 5, &packet).await.0, StatusCode::FORBIDDEN);
    assert_eq!(c.rows().await, rows);
    drop(db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; account-wide synthetic competing line"]
async fn activation_refuses_an_active_interval_on_another_line_of_the_same_account() {
    let (mut c, before, consent) = configured(120000).await;
    enable_conversation(&mut c.f.connect().await, &c.owner.principal, &consent)
        .await
        .unwrap();
    let (before, interval) = activate(&c, &before, &consent, None).await;
    let old_line = c.line;
    revoke_conversation(&mut c.f.connect().await, &c.owner.principal)
        .await
        .unwrap();
    // A second explicitly synthetic approved phone/line is selected; the
    // first interval remains an actual core-constructed active historical row.
    c.device = Uuid::new_v4();
    c.line = Uuid::new_v4();
    c.paired = SigningKey::generate_from_rng(&mut rand::rng());
    let account = c.owner.principal.tenant.account_id();
    let point = c
        .paired
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    c.f.db
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
            &[&c.device, &account],
        )
        .await
        .unwrap();
    c.f.db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&c.device,&account,&point,&Sha256::digest(&point).to_vec()]).await.unwrap();
    c.f.db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,'manifest-test','fixture',1,1,clock_timestamp()+interval '10 minutes')",&[&c.device,&account]).await.unwrap();
    c.f.db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'active',now(),1,1)",&[&c.line,&account]).await.unwrap();
    c.f.db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,owner_approval_digest,device_confirmation_digest,activated_at,purpose) VALUES($1,$2,$3,1,'active',$4,$5,now(),'sealed')",&[&account,&c.line,&c.device,&vec![2u8;32],&vec![3u8;32]]).await.unwrap();
    let (_, _, _, mut unsigned) = framed(&c, c.now().await as u64);
    unsigned[29..37].copy_from_slice(&3u64.to_be_bytes());
    unsigned[45..53].copy_from_slice(&before[45..53]);
    unsigned[53..85].copy_from_slice(&Sha256::digest(&before[..before.len() - 64]));
    let before = signed(&c, &unsigned);
    let mut db = c.f.connect().await;
    let tx = db.transaction().await.unwrap();
    let admission = crate::sealed_manifest_store::admit(&tx, c.session(), c.line, 1, &before)
        .await
        .unwrap();
    drop(admission);
    tx.commit().await.unwrap();
    let consent = ConversationConsent {
        device_id: c.device,
        line_id: c.line,
        binding_generation: 1,
        peer: "+12".into(),
        disclosure_version: "conversation-content-v1".into(),
        content_transfer_confirmed: true,
    };
    enable_conversation(&mut db, &c.owner.principal, &consent)
        .await
        .unwrap();
    let row =
        c.f.db
            .query_one(
                "SELECT line_id,phase FROM conversation_intervals WHERE account_id=$1 AND id=$2",
                &[&account, &interval],
            )
            .await
            .unwrap();
    assert_eq!(row.get::<_, Uuid>(0), old_line);
    assert_ne!(old_line, c.line);
    assert_eq!(row.get::<_, String>(1), "active");
    let packet = activation_packet(&c, &before, c.now().await as u64);
    assert_eq!(issue(&c, 4, &packet).await.0, StatusCode::CONFLICT);
    assert!(c.rows().await.is_empty());
    // Same selected bytes succeed when that account-wide competing interval
    // is no longer live, proving the refusal did not come from the new line.
    c.f.db.execute("UPDATE conversation_intervals SET phase='history',closed_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&interval]).await.unwrap();
    assert_eq!(issue(&c, 4, &packet).await.0, StatusCode::OK);
    drop(db);
    c.cleanup().await;
}

fn point() -> Vec<u8> {
    SigningKey::generate_from_rng(&mut rand::rng())
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}
fn id(role: u8, point: &[u8]) -> Vec<u8> {
    let algorithms = if role <= 3 { [0, 16] } else { [1, 1] };
    Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithms, point].concat()).to_vec()
}
pub(super) fn framed(c: &GenuineCase, now: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let account = c.owner.principal.tenant.account_id();
    let root = &c.pin[29..];
    let fp =
        zrotext_root_material::sealed_root_enrollment::root_fingerprint(&c.pin, account.as_bytes())
            .unwrap();
    let reader = point();
    let archive_reader = point();
    let signer = c
        .paired
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let signer_fp = Sha256::digest(&signer);
    let until = now + 240000;
    // Public framing consistency only: neither a phone attestation nor decryptable backup.
    let mut phone = b"ZTPK\x01".to_vec();
    phone.extend(account.as_bytes());
    phone.extend(c.device.as_bytes());
    phone.extend(c.line.as_bytes());
    phone.extend(signer_fp);
    phone.extend(1u64.to_be_bytes());
    phone.extend(&reader);
    phone.extend(&signer);
    let mut archive = b"ZTAB\x01\x01".to_vec();
    archive.extend(Uuid::new_v4().as_bytes());
    archive.extend(account.as_bytes());
    archive.extend(1u64.to_be_bytes());
    archive.extend(fp);
    archive.extend(id(2, &archive_reader));
    archive.extend(&archive_reader);
    archive.extend((ORIGIN.len() as u16).to_be_bytes());
    archive.extend(ORIGIN.as_bytes());
    let at = archive.len();
    archive.resize(at + 156, 0);
    archive[at + 104..at + 108].copy_from_slice(&48u32.to_be_bytes());
    let mut unsigned = [
        b"ZTMA\x02".as_slice(),
        account.as_bytes(),
        &1u64.to_be_bytes(),
        &1u64.to_be_bytes(),
        &now.to_be_bytes(),
        &until.to_be_bytes(),
        &[0; 32],
        root,
        &[4],
    ]
    .concat();
    for (role, key, bits) in [
        (1, reader.as_slice(), 4u16),
        (2, archive_reader.as_slice(), 12),
        (4, signer.as_slice(), 2),
        (6, root, 0),
    ] {
        unsigned.push(role);
        unsigned.extend(id(role, key));
        unsigned.extend(key);
        unsigned.extend(if matches!(role, 1 | 4) {
            c.device.as_bytes()
        } else {
            &[0; 16]
        });
        unsigned.extend(if matches!(role, 1 | 4) {
            c.line.as_bytes()
        } else {
            &[0; 16]
        });
        unsigned.extend(bits.to_be_bytes());
        unsigned.extend(now.to_be_bytes());
        unsigned.extend(until.to_be_bytes());
        unsigned.push(1);
    }
    let packet = [
        b"ZTCG\x01".as_slice(),
        account.as_bytes(),
        c.owner.principal.session_id.as_bytes(),
        c.device.as_bytes(),
        c.line.as_bytes(),
        &signer_fp,
        &1u64.to_be_bytes(),
        &[3],
        b"+12",
        &(ORIGIN.len() as u16).to_be_bytes(),
        ORIGIN.as_bytes(),
        &fp,
        &c.pin,
        &now.to_be_bytes(),
        &until.to_be_bytes(),
        &(unsigned.len() as u16).to_be_bytes(),
        &unsigned,
    ]
    .concat();
    (packet, phone, archive, unsigned)
}

pub(super) fn inputs(c: &GenuineCase, now: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (packet, phone, archive, _) = framed(c, now);
    (packet, phone, archive)
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; maintained MFA enrollment"]
async fn enrolled_owner_requires_mfa_and_revokes_another_ordinary_login_session() {
    use crate::auth::mfa::{self, MfaCipher};
    use totp_rs::{Builder, Secret};
    let c = GenuineCase::new().await;
    let mut db = c.f.connect().await;
    let secondary = auth::login(&db, &c.hasher, &c.owner.email, &c.owner.password)
        .await
        .unwrap();
    let cipher = MfaCipher::new(crate::test_keys::key(94)).unwrap();
    let pending = mfa::begin_enrollment(&mut db, &cipher, &c.owner.principal, &c.owner.password)
        .await
        .unwrap();
    let code = Builder::new()
        .with_secret(Secret::try_from_base32(&pending.secret_base32).unwrap())
        .build()
        .unwrap()
        .generate_current()
        .to_string();
    let recovery = mfa::confirm_enrollment(&mut db, &cipher, &c.hasher, &c.owner.principal, &code)
        .await
        .unwrap();
    assert!(!recovery.codes.is_empty());
    assert!(
        matches!(auth::login(&db,&c.hasher,&c.owner.email,&c.owner.password).await,
        Err(AuthError::MfaRequired { account_id,user_id })
        if account_id==c.owner.principal.tenant.account_id() && user_id==c.owner.principal.user_id)
    );
    assert!(matches!(
        auth::authenticate_session(&db, &c.hasher, &secondary.token).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        auth::authenticate_session(&db, &c.hasher, &c.owner.credentials.token)
            .await
            .is_ok()
    );
    assert!(c.rows().await.is_empty());
    drop(db);
    c.cleanup().await;
}

fn decimal(value: &serde_json::Value) -> i64 {
    let text = value.as_str().expect("canonical decimal string");
    let number: i64 = text.parse().unwrap();
    assert!(number > 0);
    assert_eq!(text, number.to_string());
    number
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic prerequisites"]
async fn maintained_owner_login_registers_exact_immutable_context_without_installing_authority() {
    let c = GenuineCase::new().await;
    let now = c.now().await;
    let (packet, phone, archive) = inputs(&c, now as u64);
    let body = registration(&c, &packet, &phone, &archive);
    let (status, receipt) = request(&c, PATH, &body).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let expected_receipt = serde_json::json!({"v":1,"kind":3,
        "proposal_sha256_hex":hex_bytes(&Sha256::digest(&packet)),
        "owner_session_id":c.owner.principal.session_id,"expires_ms":(now+240000).to_string()});
    assert_eq!(receipt, expected_receipt);
    let rows = c.rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        request(&c, PATH, &body).await,
        (StatusCode::OK, receipt.clone())
    );
    assert_eq!(c.rows().await, rows);
    let before = c.now().await;
    let (status, got) = request(&c, CONTEXT_PATH, &context(&c, &packet)).await;
    let after = c.now().await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let object = got.as_object().unwrap();
    let fields = [
        "v",
        "kind",
        "account_id",
        "user_id",
        "session_id",
        "origin",
        "root_fingerprint_hex",
        "proposal_sha256_hex",
        "proposal_b64",
        "expected_context",
        "server_now_ms",
        "expires_ms",
    ];
    assert_eq!(object.len(), fields.len());
    assert!(fields.iter().all(|key| object.contains_key(*key)));
    assert_eq!(got["v"], 1);
    assert_eq!(got["kind"], 3);
    for (field, id) in [
        ("account_id", c.owner.principal.tenant.account_id()),
        ("user_id", c.owner.principal.user_id),
        ("session_id", c.owner.principal.session_id),
    ] {
        assert_eq!(got[field].as_str(), Some(id.to_string().as_str()));
    }
    let fp = zrotext_root_material::sealed_root_enrollment::root_fingerprint(
        &c.pin,
        c.owner.principal.tenant.account_id().as_bytes(),
    )
    .unwrap();
    assert_eq!(got["origin"], ORIGIN);
    assert_eq!(got["root_fingerprint_hex"], hex_bytes(&fp));
    assert_eq!(
        got["proposal_sha256_hex"],
        hex_bytes(&Sha256::digest(&packet))
    );
    assert_eq!(got["proposal_b64"], STANDARD.encode(&packet));
    assert!(got["expected_context"].is_object());
    assert_eq!(got["expected_context"]["scope"]["origin"], ORIGIN);
    let expected = serde_json::json!({"scope":{
        "account":hex_bytes(c.owner.principal.tenant.account_id().as_bytes()),
        "session":hex_bytes(c.owner.principal.session_id.as_bytes()),
        "device":hex_bytes(c.device.as_bytes()),"line":hex_bytes(c.line.as_bytes()),
        "device_signing_fingerprint":hex_bytes(&Sha256::digest(c.paired.verifying_key().to_sec1_point(false).as_bytes())),
        "generation":1,"peer":"+12","origin":ORIGIN,"fingerprint":hex_bytes(&fp),
        "issued_ms":now,"expires_ms":now+240000},"root_pin":hex_bytes(&c.pin),
        "phone_reader":hex_bytes(&phone[93..158]),"archive_reader":hex_bytes(&archive[110..175]),
        "phone_signer":hex_bytes(&phone[158..223]),"archive_backup_sha256":hex_bytes(&Sha256::digest(&archive))});
    assert_eq!(got["expected_context"], expected);
    assert_eq!(
        got["expected_context"]["archive_backup_sha256"],
        hex_bytes(&Sha256::digest(&archive))
    );
    let returned_now = decimal(&got["server_now_ms"]);
    assert!((before..=after).contains(&returned_now));
    assert_eq!(decimal(&got["expires_ms"]), now + 240000);
    assert_eq!(c.rows().await, rows);
    let account = c.owner.principal.tenant.account_id();
    let version: i64 =
        c.f.db
            .query_one(
                "SELECT version FROM sealed_manifest_authorities WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(version, 0);
    let intervals: i64 =
        c.f.db
            .query_one(
                "SELECT count(*) FROM conversation_intervals WHERE account_id=$1",
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
    assert_eq!(intervals, 0);
    c.cleanup().await;
}

#[tokio::test]
async fn unauthenticated_and_bearer_requests_refuse_before_polling_body() {
    let state = OwnerConversationsState {
        database_url: "invalid".into(),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(93)).unwrap()),
        canonical_origin: ORIGIN.into(),
    };
    for path in [PATH, CONTEXT_PATH] {
        for bearer in [false, true] {
            let mut request = Request::post(path);
            if bearer {
                request = request.header("authorization", "Bearer invalid");
            }
            let body = Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::io::Error>,
            >());
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                router(state.clone()).oneshot(request.body(body).unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }
}
