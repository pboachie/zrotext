// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::sealed_line_setup::{self, tests::Case};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
fn observation() -> SimObservation {
    SimObservation {
        android_api_level: 31,
        active_subscription_count: 1,
        selected_subscription_id: 7,
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn activation_final_receipt_write_wait_cannot_outlive_owner_authority() {
    let c = Case::new().await;
    let registration = c.register(1).await;
    let (ch, _) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        registration,
    )
    .await
    .unwrap();
    let sig = proof(&c, &ch).await;
    let bytes = owner_line_statement(&device_line_statement(&ch, observation()).unwrap(), &sig);
    let signature: Signature = c.approval.sign(&bytes);
    let der = signature.to_der().as_bytes().to_vec();
    c.owner.f.db.batch_execute("CREATE FUNCTION scoped_activation_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.activated_ms IS NOT NULL THEN PERFORM pg_advisory_xact_lock(737,3); END IF; RETURN NEW; END $$; CREATE TRIGGER scoped_activation_wait BEFORE UPDATE ON sealed_line_key_receipts FOR EACH ROW EXECUTE FUNCTION scoped_activation_wait()").await.unwrap();
    let mut blocker = c.owner.f.connect().await;
    let held = blocker.transaction().await.unwrap();
    held.query_one("SELECT pg_advisory_xact_lock(737,3)", &[])
        .await
        .unwrap();
    c.owner
        .f
        .db
        .execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
            &[&c.owner.principal.session_id],
        )
        .await
        .unwrap();
    let mut db = c.owner.f.connect().await;
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let p = c.owner.principal.clone();
    let line = c.line;
    let pending = tokio::spawn(async move { approve(&mut db, &p, line, ch.id, &der).await });
    tokio::time::timeout(std::time::Duration::from_secs(2),async{loop{if c.owner.f.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",&[&pid]).await.unwrap().get::<_,bool>(0){break;}assert!(!pending.is_finished(),"activation ended before final receipt write wait");tokio::time::sleep(std::time::Duration::from_millis(10)).await;}}).await.unwrap();
    loop {
        if c.owner
            .f
            .db
            .query_one(
                "SELECT expires_at<=clock_timestamp() FROM sessions WHERE id=$1",
                &[&c.owner.principal.session_id],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    held.commit().await.unwrap();
    assert!(pending.await.unwrap().is_err());
    let r=c.owner.f.db.query_one("SELECT b.state,b.activated_at IS NULL,r.activated_ms IS NULL,c.consumed_at IS NULL FROM sealed_line_key_receipts r JOIN sealed_line_activation_exchanges e ON (e.account_id,e.registration_id)=(r.account_id,r.registration_id) JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(e.account_id,e.line_id,e.device_id,e.generation) JOIN line_activation_challenges c ON c.id=e.challenge_id WHERE r.registration_id=$1",&[&registration]).await.unwrap();
    assert_eq!(r.get::<_, String>(0), "pending");
    for n in 1..4 {
        assert!(r.get::<_, bool>(n));
    }
    c.cleanup().await;
}
fn signature(c: &Case, ch: &LineChallenge, obs: SimObservation) -> Vec<u8> {
    let s: Signature = c.paired.sign(&device_line_statement(ch, obs).unwrap());
    s.to_der().as_bytes().to_vec()
}
async fn proof(c: &Case, ch: &LineChallenge) -> Vec<u8> {
    let sig = signature(c, ch, observation());
    assert!(
        record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: observation(),
                signature_der: &sig
            }
        )
        .await
        .unwrap()
    );
    sig
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn sealed_setup_commits_once_reconciles_restart_and_requires_exact_phone_ack() {
    let c = Case::new().await;
    let registration = c.register(1).await;
    let (ch, expiry) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        registration,
    )
    .await
    .unwrap();
    let (retry, retry_expiry) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        registration,
    )
    .await
    .unwrap();
    assert_eq!(ch.id, retry.id);
    assert_eq!(ch.nonce, retry.nonce);
    assert_eq!(expiry, retry_expiry);
    let pushed = next_challenge(&mut c.owner.f.connect().await, c.session())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pushed.challenge_id, ch.id);
    let sig = proof(&c, &ch).await;
    assert!(
        record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: observation(),
                signature_der: &sig
            }
        )
        .await
        .unwrap()
    );
    let before = view(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        ch.id,
    )
    .await
    .unwrap();
    assert_eq!(before.status, ExchangeStatus::AwaitingOwner);
    assert!(!before.phone_acknowledged);
    let owner: Signature = c.approval.sign(&before.owner_statement.unwrap());
    let der = owner.to_der().as_bytes().to_vec();
    approve(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        ch.id,
        &der,
    )
    .await
    .unwrap();
    assert!(
        approve(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            ch.id,
            &der
        )
        .await
        .is_err()
    );
    let receipt = registration::receipt(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        registration,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!receipt["activated_ms"].is_null());
    // Reconnect after committed activation: original delivery tuple is immutable,
    // whereas historical ACK uses the same signer under a fresh current lease.
    c.owner
        .f
        .db
        .execute(
            "UPDATE device_sessions SET connection_epoch=2 WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap();
    c.owner.f.db.execute("UPDATE sealed_manifest_authorities SET revoked_at=clock_timestamp() WHERE account_id=$1",&[&c.owner.principal.tenant.account_id()]).await.unwrap();
    assert!(
        next_ack(&mut c.owner.f.connect().await, c.session(), &[])
            .await
            .unwrap()
            .is_none()
    );
    let current = InboundSession {
        connection_epoch: 2,
        ..c.session()
    };
    let ack = next_ack(&mut c.owner.f.connect().await, current, &[])
        .await
        .unwrap()
        .unwrap();
    let mut wrong = ack;
    wrong.device_statement_sha256[0] ^= 1;
    assert!(
        !confirm_ack(&mut c.owner.f.connect().await, current, wrong)
            .await
            .unwrap()
    );
    assert!(
        confirm_ack(&mut c.owner.f.connect().await, current, ack)
            .await
            .unwrap()
    );
    assert!(
        confirm_ack(&mut c.owner.f.connect().await, current, ack)
            .await
            .unwrap()
    );
    assert!(
        next_ack(&mut c.owner.f.connect().await, current, &[])
            .await
            .unwrap()
            .is_none()
    );
    let after = view(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        ch.id,
    )
    .await
    .unwrap();
    assert_eq!(after.status, ExchangeStatus::Activated);
    assert!(after.phone_acknowledged);
    let stored=c.owner.f.db.query_one("SELECT proof_connection_epoch,nonce IS NULL FROM sealed_line_activation_exchanges WHERE challenge_id=$1",&[&ch.id]).await.unwrap();
    assert_eq!(stored.get::<_, i64>(0), 1);
    assert!(stored.get::<_, bool>(1));
    let inventory =
        sealed_line_setup::lifecycle::inventory(&mut c.owner.f.connect().await, &c.owner.principal)
            .await
            .unwrap();
    assert_eq!(inventory["registrations"].as_array().unwrap().len(), 1);
    assert_eq!(inventory["exchanges"][0]["phone_acknowledged"], true);
    assert!(inventory["exchanges"][0].get("nonce").is_none());
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn sealed_phone_proof_rejects_sms_domain_api30_multi_sim_account_and_lease_substitution() {
    let c = Case::new().await;
    let registration = c.register(1).await;
    let (ch, _) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        registration,
    )
    .await
    .unwrap();
    let mut obs = observation();
    let sms = super::super::sms_device_line_statement(&ch, obs).unwrap();
    let sig: Signature = c.paired.sign(&sms);
    let der = sig.to_der().as_bytes().to_vec();
    assert!(
        !record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: obs,
                signature_der: &der
            }
        )
        .await
        .unwrap()
    );
    let valid = signature(&c, &ch, obs);
    obs.android_api_level = 30;
    assert!(
        !record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: obs,
                signature_der: &valid
            }
        )
        .await
        .unwrap()
    );
    obs = observation();
    obs.active_subscription_count = 2;
    assert!(
        !record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: obs,
                signature_der: &valid
            }
        )
        .await
        .unwrap()
    );
    for session in [
        InboundSession {
            account_id: c.owner.f.account,
            ..c.session()
        },
        InboundSession {
            connection_epoch: 2,
            ..c.session()
        },
        InboundSession {
            device_id: Uuid::new_v4(),
            ..c.session()
        },
    ] {
        assert!(
            !record_device_proof(
                &mut c.owner.f.connect().await,
                session,
                DeviceProof {
                    challenge_id: ch.id,
                    observation: observation(),
                    signature_der: &valid
                }
            )
            .await
            .unwrap()
        );
    }
    let revoked = c
        .owner
        .f
        .db
        .execute(
            "UPDATE device_keys SET revoked_at=clock_timestamp() WHERE device_id=$1",
            &[&c.device],
        )
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    assert!(
        !record_device_proof(
            &mut c.owner.f.connect().await,
            c.session(),
            DeviceProof {
                challenge_id: ch.id,
                observation: observation(),
                signature_der: &valid
            }
        )
        .await
        .unwrap()
    );
    assert!(c.owner.f.db.query_one("SELECT device_signature_der IS NULL FROM sealed_line_activation_exchanges WHERE challenge_id=$1",&[&ch.id]).await.unwrap().get::<_,bool>(0));
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn replacement_retires_old_pending_binding_and_burns_generation_without_reactivation() {
    let mut c = Case::new().await;
    let first = c.register(1).await;
    let (ch, _) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        first,
    )
    .await
    .unwrap();
    let _sig = proof(&c, &ch).await;
    let previous_key = c.approval.clone();
    c.approval = SigningKey::generate_from_rng(&mut rand::rng());
    let second = c.register(2).await;
    let row=c.owner.f.db.query_one("SELECT b.state,r.retired_ms IS NOT NULL FROM device_line_bindings b JOIN sealed_line_key_receipts r ON (r.account_id,r.line_id,r.device_id,r.generation)=(b.account_id,b.line_id,b.device_id,b.generation) WHERE r.registration_id=$1",&[&first]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "revoked");
    assert!(row.get::<_, bool>(1));
    let statement =
        owner_line_statement(&device_line_statement(&ch, observation()).unwrap(), &_sig);
    let old: Signature = previous_key.sign(&statement);
    assert!(
        approve(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            ch.id,
            old.to_der().as_bytes()
        )
        .await
        .is_err()
    );
    let (new, _) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        second,
    )
    .await
    .unwrap();
    assert_eq!(new.generation, 2);
    assert_ne!(new.nonce, ch.nonce);
    assert_eq!(cleanup(&c.owner.f.db, 100).await.unwrap(), 1);
    assert!(
        c.owner
            .f
            .db
            .query_one(
                "SELECT nonce IS NULL FROM sealed_line_activation_exchanges WHERE challenge_id=$1",
                &[&ch.id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn first_activation_checks_revoked_historical_activations_and_cannot_expand_account_authority()
 {
    let c = Case::new().await;
    let registration = c.register(1).await;
    // Historical SEALED activation in this account, even subsequently revoked,
    // closes this first-only setup gate before any new line/challenge writes.
    let history = Uuid::new_v4();
    let account = c.owner.principal.tenant.account_id();
    c.owner.f.db.execute("INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) VALUES($1,$2,'revoked',clock_timestamp(),1,1)",&[&history,&account]).await.unwrap();
    c.owner.f.db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,activated_at,owner_approval_digest,device_confirmation_digest) VALUES($1,$2,$3,1,'revoked','sealed',clock_timestamp(),$4,$5)",&[&account,&history,&c.device,&vec![1u8;32],&vec![2u8;32]]).await.unwrap();
    assert!(
        open(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            c.device,
            registration
        )
        .await
        .is_err()
    );
    assert_eq!(
        c.owner
            .f
            .db
            .query_one("SELECT count(*) FROM sealed_line_activation_exchanges", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    c.cleanup().await;
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registration_absolute_expiry_is_not_reset_by_line_issuance_or_retry() {
    let c = Case::new().await;
    let statement = c.issue(1).await;
    let mut scope = statement.scope().clone();
    scope.expires_ms = scope.issued_ms + 1200;
    let short = zrotext_root_material::line_key_registration::Statement::new(
        scope,
        *statement.root_pin(),
        *statement.root_fingerprint(),
        *statement.approval_point(),
    )
    .unwrap();
    let (bytes, root, approval) = c.signatures(&short);
    let id = Uuid::from_bytes(short.scope().challenge);
    c.owner
        .f
        .db
        .execute(
            "UPDATE sealed_line_key_challenges SET transcript=$2,expires_ms=$3 WHERE account_id=$1",
            &[
                &c.owner.principal.tenant.account_id(),
                &bytes,
                &(short.scope().expires_ms as i64),
            ],
        )
        .await
        .unwrap();
    let factor = c.factor().await;
    registration::complete(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        crate::http_owner_conversations::sealed_line_setup::tests::ORIGIN,
        &c.owner.hasher,
        &c.owner.cipher,
        id,
        registration::Completion {
            unsigned: &bytes,
            root_signature: &root,
            approval_signature: &approval,
            factor: &factor,
        },
    )
    .await
    .unwrap();
    let (ch, expires) = open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        id,
    )
    .await
    .unwrap();
    assert!(expires <= short.scope().expires_ms as i64);
    tokio::time::sleep(std::time::Duration::from_millis(1250)).await;
    assert!(
        open(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            c.device,
            id
        )
        .await
        .is_err()
    );
    assert!(
        next_challenge(&mut c.owner.f.connect().await, c.session())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        view(
            &mut c.owner.f.connect().await,
            &c.owner.principal,
            c.line,
            ch.id
        )
        .await
        .unwrap()
        .status,
        ExchangeStatus::Closed
    );
    assert_eq!(cleanup(&c.owner.f.db, 100).await.unwrap(), 1);
    assert_eq!(registration::cleanup(&c.owner.f.db, 100).await.unwrap(), 1);
    assert!(
        registration::receipt(&mut c.owner.f.connect().await, &c.owner.principal, id)
            .await
            .unwrap()
            .is_some()
    );
    c.cleanup().await;
}
