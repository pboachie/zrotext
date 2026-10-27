// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    alpha_policy::AlphaPolicy,
    auth::TokenHasher,
    enrollment::{self, EnrollmentHasher},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::Notify;
use tokio_postgres::NoTls;
use uuid::Uuid;

// This isolated historical schema qualifies the session claim itself. The
// first-origin business adapter separately requires the full public capability.
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn verified_point_must_survive_claim_and_remain_current_for_renewal() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable PostgreSQL");
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("socket_actor_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    for sql in [
        include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!(
            "../../../../../deploy/compose/migrations/095_device_session_line_activation_version.sql"
        ),
    ] {
        client.batch_execute(sql).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let key_a = SigningKey::generate_from_rng(&mut rand::rng());
    let key_b = SigningKey::generate_from_rng(&mut rand::rng());
    let point_a = key_a.verifying_key().to_sec1_point(false);
    let point_b = key_b.verifying_key().to_sec1_point(false);
    let fp_a = Sha256::digest(point_a.as_bytes()).to_vec();
    let fp_b = Sha256::digest(point_b.as_bytes()).to_vec();
    client
        .batch_execute("INSERT INTO sites(site_id) VALUES('actor-site')")
        .await
        .unwrap();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic actor')",
            &[&device, &account],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",&[&device,&account,&point_a.as_bytes(),&fp_a]).await.unwrap();
    let state = DeviceSocketState {
        database_url: url,
        site_id: "actor-site".into(),
        instance_id: "actor-instance".into(),
        deployment_epoch: 1,
        enrollment_hasher: Arc::new(EnrollmentHasher::new(crate::test_keys::key(77)).unwrap()),
        auth_hasher: Arc::new(TokenHasher::new(crate::test_keys::key(78)).unwrap()),
        alpha_policy: Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
        dispatch_runtime_enabled: false,
        sealed_dispatch_enabled: false,
        inbound_pilot_enabled: false,
        line_opt_out_enabled: false,
        sms_line_activation_enabled: false,
        line_readiness_enabled: false,
        mms_spike_policy: Arc::new(super::super::mms_spike_policy::MmsSpikePolicy::disabled()),
        draining: Arc::new(AtomicBool::new(false)),
        drain_notify: Arc::new(Notify::new()),
    };
    let challenge = enrollment::issue_socket_challenge(
        &state.enrollment_hasher,
        account,
        device,
        enrollment::unix_now_ms(),
    );
    let signature: Signature = key_a.sign(&enrollment::device_challenge_bytes(&challenge));
    let proof_a = enrollment::authenticate_socket_actor(
        &client,
        &state.enrollment_hasher,
        &challenge,
        signature.to_der().as_bytes(),
        enrollment::unix_now_ms(),
    )
    .await
    .unwrap();
    // A valid proof cannot authorize a different key installed before claim.
    client
        .execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&device, &point_b.as_bytes(), &fp_b],
        )
        .await
        .unwrap();
    assert!(
        claim(
            &mut client,
            proof_a,
            &state,
            line_activation_v2::LineProtocol::Legacy
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM device_sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let signature_b: Signature = key_b.sign(&enrollment::device_challenge_bytes(&challenge));
    let proof_b = enrollment::authenticate_socket_actor(
        &client,
        &state.enrollment_hasher,
        &challenge,
        signature_b.to_der().as_bytes(),
        enrollment::unix_now_ms(),
    )
    .await
    .unwrap();
    // Authenticating B then restoring A is not proof of A's possession.
    client
        .execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&device, &point_a.as_bytes(), &fp_a],
        )
        .await
        .unwrap();
    assert!(
        claim(
            &mut client,
            proof_b,
            &state,
            line_activation_v2::LineProtocol::Legacy
        )
        .await
        .unwrap()
        .is_none()
    );
    let actor = claim(
        &mut client,
        proof_a,
        &state,
        line_activation_v2::LineProtocol::Legacy,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(actor.current(&client, &state).await.unwrap());
    assert!(actor.renew(&client, &state).await.unwrap());
    client
        .execute(
            "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
            &[&device, &point_b.as_bytes(), &fp_b],
        )
        .await
        .unwrap();
    assert!(!actor.current(&client, &state).await.unwrap());
    assert!(!actor.renew(&client, &state).await.unwrap());
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
