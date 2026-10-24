// SPDX-License-Identifier: AGPL-3.0-only
//! Real public ordinary-runtime enrollment/control fixture. No phone or provider
//! hardware is claimed; temporary private keys exist only in this test process.
use super::*;
use crate::{auth, enrollment, sealed_payload_election03::test_database::Fixture};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::EncodePublicKey,
};
use sha2::{Digest, Sha256};

async fn request(
    db: &mut tokio_postgres::Client,
    state: &DeviceSocketState,
    actor: actor::SocketActor,
    origin: &[u8; 32],
    body: serde_json::Value,
) -> serde_json::Value {
    let frame = parse(&body.to_string()).unwrap().unwrap();
    admit(db, state, actor, frame.kind).await.unwrap();
    let tx = runtime_db::begin_native(db).await.unwrap();
    lock(&tx, actor, state).await.unwrap();
    let (reply, deadline) = apply(&tx, state, actor, origin, frame).await.unwrap();
    lock(&tx, actor, state).await.unwrap();
    if let Some(deadline) = deadline {
        let now = tx.query_one("SELECT pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await.unwrap().get::<_,i64>(0);
        assert!(u64::try_from(now).unwrap() < deadline);
    }
    tx.commit().await.unwrap();
    reply
}
fn raw(value: &serde_json::Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn approved_pairing_and_real_socket_proof_can_install_metadata_before_any_genesis() {
    let mut f = Fixture::runtime().await;
    crate::device_protection_storage::require(&f.reader)
        .await
        .unwrap();
    let hasher = Arc::new(auth::TokenHasher::new(crate::test_keys::key(31)).unwrap());
    let enrollment_hasher =
        Arc::new(enrollment::EnrollmentHasher::new(crate::test_keys::key(32)).unwrap());
    let password = format!("synthetic-{}", Uuid::new_v4());
    let signup = auth::register(
        &mut f.reader,
        &hasher,
        "protection-owner@example.test",
        &password,
    )
    .await
    .unwrap();
    assert!(
        auth::verify_email(&mut f.reader, &hasher, &signup.verification_token)
            .await
            .unwrap()
    );
    let credentials = auth::login(
        &f.reader,
        &hasher,
        "protection-owner@example.test",
        &password,
    )
    .await
    .unwrap();
    let principal = auth::authenticate_session(&f.reader, &hasher, &credentials.token)
        .await
        .unwrap();
    let device_key = SigningKey::generate_from_rng(&mut rand::rng());
    let ticket = enrollment::create_pairing(
        &f.reader,
        &enrollment_hasher,
        &principal,
        "Synthetic original enrolled device",
    )
    .await
    .unwrap();
    let public = device_key.verifying_key().to_public_key_der().unwrap();
    let claim = enrollment::claim_pairing(
        &mut f.reader,
        &enrollment_hasher,
        ticket.id,
        &ticket.token,
        public.as_bytes(),
    )
    .await
    .unwrap();
    let point = device_key.verifying_key().to_sec1_point(false);
    let fingerprint: [u8; 32] = Sha256::digest(point.as_bytes()).into();
    let signature: Signature = device_key.sign(&enrollment::enrollment_challenge_bytes(
        signup.account_id,
        ticket.id,
        &fingerprint,
        &claim.challenge_nonce,
    ));
    assert!(
        enrollment::prove_pairing_key(
            &mut f.reader,
            &enrollment_hasher,
            ticket.id,
            &claim.challenge_nonce,
            signature.to_der().as_bytes()
        )
        .await
        .unwrap()
    );
    let device = enrollment::approve_pairing(
        &mut f.reader,
        &principal,
        ticket.id,
        &claim.comparison_code,
        &claim.key_fingerprint,
    )
    .await
    .unwrap();
    f.owner
        .batch_execute("INSERT INTO public.sites(site_id) VALUES('origin-test')")
        .await
        .unwrap();
    let state = DeviceSocketState {
        database_url: String::new(),
        site_id: "origin-test".into(),
        instance_id: "origin-test-instance".into(),
        deployment_epoch: 1,
        enrollment_hasher,
        auth_hasher: hasher,
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        line_readiness_enabled: false,
        mms_spike_policy: Arc::new(mms_spike_policy::MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let challenge = enrollment::issue_socket_challenge(
        &state.enrollment_hasher,
        signup.account_id,
        device,
        enrollment::unix_now_ms(),
    );
    let signature: Signature = device_key.sign(&enrollment::device_challenge_bytes(&challenge));
    let verified = enrollment::authenticate_socket_actor(
        &f.reader,
        &state.enrollment_hasher,
        &challenge,
        signature.to_der().as_bytes(),
        enrollment::unix_now_ms(),
    )
    .await
    .unwrap();
    let actor = actor::claim(
        &mut f.reader,
        verified,
        &state,
        line_activation_v2::LineProtocol::Legacy,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(actor.current(&f.reader, &state).await.unwrap());
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.sealed_manifest_authorities WHERE account_id=$1",
                &[&signup.account_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let origin = conversation::Policy::new("wss://example.test")
        .unwrap()
        .protection_origin_digest();
    let setup = Uuid::new_v4();
    let opening = Uuid::new_v4();
    let command = Uuid::new_v4();
    let epoch = actor.session().connection_epoch;
    let body = serde_json::json!({"v":1,"type":"protection_origin_open","connection_epoch":epoch,"setup_id":setup,"opening_id":opening,"command_id":command});
    let opened = request(&mut f.reader, &state, actor, &origin, body.clone()).await;
    // Actual committed opening precedes all synthetic provider result generation.
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.device_protection_associations",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let retry = request(&mut f.reader, &state, actor, &origin, body).await;
    assert_eq!(opened, retry);
    let mut context = Vec::new();
    for id in [
        signup.account_id,
        device,
        setup,
        opening,
        command,
        ticket.id,
    ] {
        context.extend(id.as_bytes());
    }
    context.extend(origin);
    context.extend(verified.signing_key_id());
    context.extend(raw(&opened["opening"]["opening_nonce"]));
    assert_eq!(context.len(), 192);
    let mut hmac =
        <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&rand::random::<[u8; 32]>()).unwrap();
    hmac::Mac::update(
        &mut hmac,
        &crate::sealed_manifest03::framed(b"ZT/protection/hmac-probe/v1\0", &context).unwrap(),
    );
    let tag = hmac::Mac::finalize(hmac).into_bytes();
    let mut aes_probe = Vec::new();
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    for name in ["journal", "withdrawal"] {
        let aes = Aes256Gcm::new_from_slice(&rand::random::<[u8; 32]>()).unwrap();
        let nonce = rand::random::<[u8; 12]>();
        let plaintext = crate::sealed_manifest03::sha(
            &crate::sealed_manifest03::framed(
                format!("ZT/protection/aes-plaintext/{name}/v1\0").as_bytes(),
                &context,
            )
            .unwrap(),
        );
        let aad = crate::sealed_manifest03::framed(
            format!("ZT/protection/aes-probe/{name}/v1\0").as_bytes(),
            &context,
        )
        .unwrap();
        let ciphertext = aes
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(
            aes.decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad
                }
            )
            .unwrap(),
            plaintext
        );
        aes_probe.extend(nonce);
        aes_probe.extend(ciphertext);
    }
    let canary = SigningKey::generate_from_rng(&mut rand::rng());
    let mut association = b"ZTPA\x01\x01\0\0".to_vec();
    association.extend(&context[..160]);
    association.extend(Sha256::digest(&context[160..]));
    association.extend(tag);
    association.extend(Sha256::digest(&aes_probe));
    association.extend(canary.verifying_key().to_sec1_point(false).as_bytes());
    assert_eq!(association.len(), 329);
    let proof_request = Uuid::new_v4();
    let body = serde_json::json!({"v":1,"type":"protection_origin_proof_open","connection_epoch":epoch,"setup_id":setup,"opening_id":opening,"command_id":command,"proof_request_id":proof_request,"association":URL_SAFE_NO_PAD.encode(&association),"aes_probe":URL_SAFE_NO_PAD.encode(&aes_probe),"previous_attempt_id":null,"previous_core_sha256":null,"previous_bundle_sha256":null});
    let challenge = request(&mut f.reader, &state, actor, &origin, body).await;
    let core = raw(&challenge["core"]);
    let ds: Signature = device_key.sign(
        &crate::sealed_manifest03::framed(b"ZT/protection/first-origin-device/v1\0", &core)
            .unwrap(),
    );
    let ds = ds.normalize_s().to_bytes();
    let mut second = core.clone();
    second.extend(Sha256::digest(ds));
    let cs: Signature = canary.sign(
        &crate::sealed_manifest03::framed(b"ZT/protection/first-origin-canary/v1\0", &second)
            .unwrap(),
    );
    let bundle = [core.as_slice(), &ds, &cs.normalize_s().to_bytes()].concat();
    let body = serde_json::json!({"v":1,"type":"protection_origin_proof","connection_epoch":epoch,"setup_id":setup,"opening_id":opening,"command_id":command,"proof_request_id":proof_request,"attempt_id":challenge["attempt_id"],"bundle":URL_SAFE_NO_PAD.encode(bundle)});
    let accepted = request(&mut f.reader, &state, actor, &origin, body).await;
    let body = serde_json::json!({"v":1,"type":"protection_origin_status_request","connection_epoch":epoch,"request_id":Uuid::new_v4(),"setup_id":setup,"opening_id":opening,"command_id":command,"proof_request_id":proof_request});
    let status = request(&mut f.reader, &state, actor, &origin, body).await;
    assert_eq!(status["status"], "accepted");
    assert_eq!(status["receipt"], accepted["receipt"]);
    assert!(status.to_string().len() <= MAX_FRAME_BYTES);
    let fresh_challenge = enrollment::issue_socket_challenge(
        &state.enrollment_hasher,
        signup.account_id,
        device,
        enrollment::unix_now_ms(),
    );
    let fresh_signature: Signature =
        device_key.sign(&enrollment::device_challenge_bytes(&fresh_challenge));
    let fresh_verified = enrollment::authenticate_socket_actor(
        &f.reader,
        &state.enrollment_hasher,
        &fresh_challenge,
        fresh_signature.to_der().as_bytes(),
        enrollment::unix_now_ms(),
    )
    .await
    .unwrap();
    let later = actor::claim(
        &mut f.reader,
        fresh_verified,
        &state,
        line_activation_v2::LineProtocol::Legacy,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(later.session().connection_epoch > epoch);
    let later_status = serde_json::json!({"v":1,"type":"protection_origin_status_request","connection_epoch":later.session().connection_epoch,"request_id":Uuid::new_v4(),"setup_id":setup,"opening_id":opening,"command_id":command,"proof_request_id":proof_request});
    let resumed = request(&mut f.reader, &state, later, &origin, later_status).await;
    assert_eq!(resumed["receipt"], accepted["receipt"]);
    assert_eq!(resumed["opening"], opened["opening"]);
    // Actual A->B->A is a permanently retired origin, even though the restored
    // A point again matches the genuine socket signature witness.
    let replacement = SigningKey::generate_from_rng(&mut rand::rng());
    let replacement_point = replacement.verifying_key().to_sec1_point(false);
    let replacement_fp: [u8; 32] = Sha256::digest(replacement_point.as_bytes()).into();
    f.owner.execute("UPDATE public.device_keys SET signing_key_sec1=$3,fingerprint=$4 WHERE account_id=$1 AND device_id=$2", &[&signup.account_id,&device,&replacement_point.as_bytes(),&&replacement_fp[..]]).await.unwrap();
    f.owner.execute("UPDATE public.device_keys SET signing_key_sec1=$3,fingerprint=$4 WHERE account_id=$1 AND device_id=$2", &[&signup.account_id,&device,&point.as_bytes(),&&fingerprint[..]]).await.unwrap();
    assert!(
        admit(&mut f.reader, &state, later, Kind::Status)
            .await
            .is_err()
    );
    assert_eq!(
        f.reader
            .query_one(
                "SELECT count(*) FROM public.device_protection_receipts WHERE account_id=$1",
                &[&signup.account_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        f.reader
            .query_one("SELECT count(*) FROM public.payload_profile_elections", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}
