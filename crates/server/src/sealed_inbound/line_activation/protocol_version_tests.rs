// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_owner_conversations::sealed_line_setup::tests::Case;
use crate::sealed_manifest_store::tests::Fixture;
use p256::ecdsa::{Signature, signature::Signer};
use tokio_postgres::error::SqlState;

const VERSION_MIGRATION: &str = include_str!(
    "../../../../../deploy/compose/migrations/094_line_activation_protocol_version.sql"
);

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn challenge_version_migration_preserves_legacy_rows_and_forbids_relabeling() {
    let f = Fixture::without_authority().await;
    let legacy = Uuid::new_v4();
    let nonce_digest = rand::random::<[u8; 32]>();
    f.db.execute(
        "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,expires_at,consumed_at) \
         VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '5 minutes',clock_timestamp())",
        &[
            &legacy,
            &f.account,
            &f.line,
            &f.device,
            &nonce_digest.as_slice(),
        ],
    )
    .await
    .unwrap();
    let before =
        f.db.query_one(
            "SELECT nonce_digest,expires_at::text,consumed_at::text \
         FROM line_activation_challenges WHERE id=$1",
            &[&legacy],
        )
        .await
        .unwrap();
    f.db.batch_execute(VERSION_MIGRATION).await.unwrap();
    let after =
        f.db.query_one(
            "SELECT protocol_version,nonce_digest,expires_at::text,consumed_at::text \
         FROM line_activation_challenges WHERE id=$1",
            &[&legacy],
        )
        .await
        .unwrap();
    assert_eq!(after.get::<_, i16>(0), 1);
    assert_eq!(before.get::<_, Vec<u8>>(0), after.get::<_, Vec<u8>>(1));
    assert_eq!(before.get::<_, String>(1), after.get::<_, String>(2));
    assert_eq!(before.get::<_, String>(2), after.get::<_, String>(3));

    let defaulted = Uuid::new_v4();
    let second_digest = rand::random::<[u8; 32]>();
    f.db.execute(
        "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,expires_at) \
         VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '5 minutes')",
        &[
            &defaulted,
            &f.account,
            &f.line,
            &f.device,
            &second_digest.as_slice(),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.query_one(
            "SELECT protocol_version FROM line_activation_challenges WHERE id=$1",
            &[&defaulted],
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );

    for id in [legacy, defaulted] {
        let error =
            f.db.execute(
                "UPDATE line_activation_challenges SET protocol_version=2 WHERE id=$1",
                &[&id],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
    // Adding the version guard must preserve the original immutable challenge
    // and one-way consumption guards, including on pre-migration rows.
    for sql in [
        "UPDATE line_activation_challenges SET nonce_digest=decode(repeat('00',32),'hex') WHERE id=$1",
        "UPDATE line_activation_challenges SET expires_at=expires_at+interval '1 second' WHERE id=$1",
        "UPDATE line_activation_challenges SET consumed_at=NULL WHERE id=$1",
    ] {
        let error = f.db.execute(sql, &[&legacy]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
    for version in [-1i16, 0, 3] {
        let id = Uuid::new_v4();
        let nonce_digest = rand::random::<[u8; 32]>();
        let error =
            f.db.execute(
                "INSERT INTO line_activation_challenges \
             (id,account_id,line_id,device_id,generation,nonce_digest,expires_at,protocol_version) \
             VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '5 minutes',$6)",
                &[
                    &id,
                    &f.account,
                    &f.line,
                    &f.device,
                    &nonce_digest.as_slice(),
                    &version,
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
    let future = Uuid::new_v4();
    let future_digest = rand::random::<[u8; 32]>();
    f.db.execute(
        "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,expires_at,protocol_version) \
         VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '5 minutes',2)",
        &[
            &future,
            &f.account,
            &f.line,
            &f.device,
            &future_digest.as_slice(),
        ],
    )
    .await
    .unwrap();
    let error =
        f.db.execute(
            "UPDATE line_activation_challenges SET protocol_version=1 WHERE id=$1",
            &[&future],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    f.cleanup().await;
}

// This constructs an unsupported future-version challenge as adversarial SQL
// input. It never issues a v2 capability or activates its binding. Real enrolled
// keys, owner registration and leases otherwise satisfy the legacy transaction.
async fn future_challenge(c: &Case, purpose: LinePurpose) -> LineChallenge {
    let registration = if purpose == LinePurpose::Sealed {
        Some(c.register(1).await)
    } else {
        let point = c.approval.verifying_key().to_sec1_point(false);
        c.owner
            .f
            .db
            .execute(
                "INSERT INTO sms_line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) \
             VALUES($1,$2,$3)",
                &[
                    &c.owner.principal.tenant.account_id(),
                    &digest(point.as_bytes()).as_slice(),
                    &point.as_bytes(),
                ],
            )
            .await
            .unwrap();
        None
    };
    let challenge = LineChallenge {
        id: Uuid::new_v4(),
        account_id: c.owner.principal.tenant.account_id(),
        line_id: c.line,
        device_id: c.device,
        generation: 1,
        nonce: rand::random(),
    };
    c.owner
        .f
        .db
        .execute(
            "INSERT INTO phone_lines(id,account_id,last_issued_generation) VALUES($1,$2,1)",
            &[&c.line, &challenge.account_id],
        )
        .await
        .unwrap();
    c.owner
        .f
        .db
        .execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) \
         VALUES($1,$2,$3,1,$4)",
            &[&challenge.account_id, &c.line, &c.device, &purpose.label()],
        )
        .await
        .unwrap();
    c.owner
        .f
        .db
        .execute(
            "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,expires_at,protocol_version) \
         VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '5 minutes',2)",
            &[
                &challenge.id,
                &challenge.account_id,
                &c.line,
                &c.device,
                &digest(&challenge.nonce).as_slice(),
            ],
        )
        .await
        .unwrap();
    if let Some(registration) = registration {
        c.owner
            .f
            .db
            .execute(
                "UPDATE sealed_line_key_receipts SET assigned_challenge_id=$3 \
             WHERE account_id=$1 AND registration_id=$2",
                &[&challenge.account_id, &registration, &challenge.id],
            )
            .await
            .unwrap();
        c.owner
            .f
            .db
            .execute(
                "INSERT INTO sealed_line_activation_exchanges \
             (registration_id,challenge_id,account_id,line_id,device_id,generation,nonce, \
              initiating_user_id,initiating_session_id,owner_fingerprint,device_fingerprint) \
             SELECT $1,$2,account_id,line_id,device_id,generation,$3,user_id,session_id, \
                    approval_fingerprint,paired_fingerprint \
             FROM sealed_line_key_receipts WHERE account_id=$4 AND registration_id=$1",
                &[
                    &registration,
                    &challenge.id,
                    &challenge.nonce.as_slice(),
                    &challenge.account_id,
                ],
            )
            .await
            .unwrap();
    } else {
        c.owner
            .f
            .db
            .execute(
                "INSERT INTO sms_line_activation_exchanges \
             (challenge_id,account_id,line_id,device_id,generation,nonce) VALUES($1,$2,$3,$4,1,$5)",
                &[
                    &challenge.id,
                    &challenge.account_id,
                    &c.line,
                    &c.device,
                    &challenge.nonce.as_slice(),
                ],
            )
            .await
            .unwrap();
    }
    challenge
}

async fn legacy_refuses_future_challenge(c: &Case, purpose: LinePurpose) {
    let challenge = future_challenge(c, purpose).await;
    let observation = SimObservation {
        android_api_level: 33,
        active_subscription_count: 1,
        selected_subscription_id: 7,
    };
    let statement = line_statement(&challenge, observation, purpose).unwrap();
    let device_signature: Signature = c.paired.sign(&statement);
    let device_der = device_signature.to_der();
    let owner_bytes = owner_statement(&statement, device_der.as_bytes(), purpose);
    let owner_signature: Signature = c.approval.sign(&owner_bytes);
    let owner_der = owner_signature.to_der();
    let mut db = c.owner.f.connect().await;
    match purpose {
        LinePurpose::Sms => {
            assert!(
                exchange::next_challenge(&db, c.session())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                exchange::view(&db, &c.owner.principal, c.line, challenge.id).await,
                Err(exchange::ExchangeError::NotFound)
            ));
            exchange::mark_challenge_pushed(&db, c.session(), challenge.id)
                .await
                .unwrap();
            assert!(db.query_one(
                "SELECT pushed_connection_epoch IS NULL FROM sms_line_activation_exchanges WHERE challenge_id=$1",
                &[&challenge.id],
            ).await.unwrap().get::<_, bool>(0));
            assert!(
                !exchange::record_device_proof(
                    &mut db,
                    c.session(),
                    exchange::DeviceProof {
                        challenge_id: challenge.id,
                        observation,
                        signature_der: device_der.as_bytes(),
                    }
                )
                .await
                .unwrap()
            );
        }
        LinePurpose::Sealed => {
            assert!(
                sealed_exchange::next_challenge(&mut db, c.session())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                sealed_exchange::view(&mut db, &c.owner.principal, c.line, challenge.id).await,
                Err(sealed_exchange::ExchangeError::NotFound)
            ));
            assert!(
                !sealed_exchange::record_device_proof(
                    &mut db,
                    c.session(),
                    sealed_exchange::DeviceProof {
                        challenge_id: challenge.id,
                        observation,
                        signature_der: device_der.as_bytes(),
                    }
                )
                .await
                .unwrap()
            );
        }
    }
    let result = activate_for_purpose(
        &mut db,
        &c.owner.principal,
        c.session(),
        c.line,
        1,
        LineActivationProof {
            challenge_id: challenge.id,
            nonce: challenge.nonce,
            observation,
            device_signature_der: device_der.as_bytes(),
            owner_signature_der: owner_der.as_bytes(),
        },
        ActivationScope {
            purpose,
            registration: None,
        },
    )
    .await;
    assert!(matches!(result, Err(LineActivationError::Unavailable)));
    let row = db.query_one(
        "SELECT b.state,b.activated_at IS NULL,c.consumed_at IS NULL, \
                l.current_binding_generation,l.last_issued_generation \
         FROM device_line_bindings b JOIN line_activation_challenges c ON \
           (c.account_id,c.line_id,c.device_id,c.generation)=(b.account_id,b.line_id,b.device_id,b.generation) \
         JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE c.id=$1",
        &[&challenge.id],
    ).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    assert!(row.get::<_, bool>(1) && row.get::<_, bool>(2));
    assert_eq!((row.get::<_, i64>(3), row.get::<_, i64>(4)), (0, 1));
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn sms_legacy_exchange_and_signed_activation_refuse_v2_challenge() {
    let c = Case::without_root().await;
    legacy_refuses_future_challenge(&c, LinePurpose::Sms).await;
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn sealed_legacy_exchange_and_signed_activation_refuse_v2_challenge() {
    let c = Case::new().await;
    legacy_refuses_future_challenge(&c, LinePurpose::Sealed).await;
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn registered_legacy_issuance_keeps_version_one_and_existing_schema_validation() {
    let c = Case::new().await;
    let registration = c.register(1).await;
    let (challenge, _) = sealed_exchange::open(
        &mut c.owner.f.connect().await,
        &c.owner.principal,
        c.line,
        c.device,
        registration,
    )
    .await
    .unwrap();
    assert_eq!(
        c.owner
            .f
            .db
            .query_one(
                "SELECT protocol_version FROM line_activation_challenges WHERE id=$1",
                &[&challenge.id],
            )
            .await
            .unwrap()
            .get::<_, i16>(0),
        1
    );
    assert!(
        sealed_exchange::next_challenge(&mut c.owner.f.connect().await, c.session())
            .await
            .unwrap()
            .is_some()
    );
    crate::http_owner_conversations::sealed_line_setup::lifecycle::require_installed(&c.owner.f.db)
        .await
        .unwrap();
    c.cleanup().await;
}
