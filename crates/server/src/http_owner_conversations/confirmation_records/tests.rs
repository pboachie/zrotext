// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::{
        ConversationConsent, DISCLOSURE_VERSION, activation, tests::prepared,
    },
    sealed_manifest_store::{self, tests::Fixture},
};
use p256::ecdsa::{Signature, signature::Signer};
use tokio_postgres::error::SqlState;

struct Case {
    f: Fixture,
    owner: SessionPrincipal,
    interval: activation::Statement,
}
impl Case {
    async fn new() -> Self {
        let (mut f, owner) = prepared().await;
        let mut db = f.connect().await;
        let tx = db.transaction().await.unwrap();
        let mut admitted = sealed_manifest_store::admit(&tx, f.session(), f.line, 1, &f.bytes)
            .await
            .unwrap();
        admitted.context(&f.wanted()).await.unwrap();
        drop(admitted);
        tx.commit().await.unwrap();
        f.advance();
        let interval = activation::begin(
            &mut db,
            &owner,
            &ConversationConsent {
                device_id: f.device,
                line_id: f.line,
                binding_generation: 1,
                peer: "+12".into(),
                disclosure_version: DISCLOSURE_VERSION.into(),
                content_transfer_confirmed: true,
            },
            &f.bytes,
        )
        .await
        .unwrap();
        let sign = |domain| {
            let signature: Signature = f.event_signer.sign(&interval.transcript(domain).unwrap());
            signature.normalize_s().to_bytes().to_vec()
        };
        activation::approve(
            &mut db,
            f.session(),
            &interval.encode().unwrap(),
            &sign(activation::statement::APPROVE_DOMAIN),
        )
        .await
        .unwrap();
        activation::installed(
            &mut db,
            f.session(),
            &interval.encode().unwrap(),
            &sign(activation::statement::INSTALL_DOMAIN),
        )
        .await
        .unwrap();
        Self { f, owner, interval }
    }
    async fn record(&self, expired: bool) -> Uuid {
        let message = Uuid::new_v4();
        self.f.db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+12',$4,'synthetic_alpha',$5,$4,'queued',clock_timestamp()+interval '1 hour')", &[&message,&self.f.account,&self.f.device,&vec![1u8;32],&vec![2u8;32]]).await.unwrap();
        let expires: i64 = self
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint+$1::bigint",
                &[&if expired { -1i64 } else { 3_600_000i64 }],
            )
            .await
            .unwrap()
            .get(0);
        self.f.db.execute("INSERT INTO conversation_confirmation_records(account_id,message_id,interval_id,initiating_session_id,device_id,line_id,binding_generation,trust_generation,manifest_version,manifest_digest,signer_key_id,reader_key_id,body_digest,expires_at_ms,envelope_digest,confirmation_digest,signature_digest,confirmation,signature) VALUES($1,$2,$3,$4,$5,$6,1,1,1,$7,$7,$7,$7,$8,$7,$7,$7,$9,$10)", &[&self.f.account,&message,&self.interval.interval,&self.owner.session_id,&self.f.device,&self.f.line,&vec![3u8;32],&expires,&vec![4u8;297],&vec![5u8;64]]).await.unwrap();
        message
    }
    async fn retained(&self, message: Uuid) -> bool {
        self.f.db.query_one("SELECT confirmation IS NOT NULL FROM conversation_confirmation_records WHERE account_id=$1 AND message_id=$2", &[&self.f.account,&message]).await.unwrap().get(0)
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn proof_identity_is_immutable_and_redaction_is_irreversible() {
    let c = Case::new().await;
    let message = c.record(false).await;
    assert!(validate(&c.f.db).await.unwrap());
    for assignment in [
        "manifest_version=2",
        "expires_at_ms=expires_at_ms+1",
        "signature=decode(repeat('06',64),'hex')",
        "confirmation=NULL",
    ] {
        let error = c
            .f
            .db
            .execute(
                &format!(
                    "UPDATE conversation_confirmation_records SET {assignment} WHERE message_id=$1"
                ),
                &[&message],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
    c.f.db.execute("UPDATE conversation_confirmation_records SET confirmation=NULL,signature=NULL WHERE message_id=$1", &[&message]).await.unwrap();
    let error = c.f.db.execute("UPDATE conversation_confirmation_records SET confirmation=$2,signature=$3 WHERE message_id=$1", &[&message,&vec![4u8;297],&vec![5u8;64]]).await.unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    assert!(!c.retained(message).await);
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expiry_and_revocation_redact_proof_without_deleting_identity() {
    let c = Case::new().await;
    let expired = c.record(true).await;
    let live = c.record(false).await;
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 1);
    assert!(!c.retained(expired).await);
    assert!(c.retained(live).await);
    c.f.db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.owner.session_id],
        )
        .await
        .unwrap();
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 1);
    assert!(!c.retained(live).await);
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 0);
    assert!(matches!(
        inventory(&mut c.f.connect().await, &c.owner, None).await,
        Err(ConversationError::Forbidden)
    ));
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn inventory_is_bounded_owner_scoped_and_contains_no_proof_bytes() {
    let c = Case::new().await;
    for _ in 0..101 {
        c.record(false).await;
    }
    let first = inventory(&mut c.f.connect().await, &c.owner, None)
        .await
        .unwrap();
    assert_eq!(first.records.len(), 100);
    assert!(first.truncated);
    let cursor = first.next_cursor.unwrap();
    let second = inventory(&mut c.f.connect().await, &c.owner, Some(cursor))
        .await
        .unwrap();
    assert_eq!(second.records.len(), 1);
    assert!(!second.truncated);
    assert!(
        !first
            .records
            .iter()
            .any(|r| r.message_id == second.records[0].message_id)
    );
    let serialized = serde_json::to_value(first).unwrap();
    let record = &serialized["records"][0];
    for field in [
        "confirmation",
        "signature",
        "peer",
        "envelope",
        "body_digest",
    ] {
        assert!(record.get(field).is_none());
    }
    assert!(matches!(
        inventory(&mut c.f.connect().await, &c.owner, Some(Uuid::new_v4())).await,
        Err(ConversationError::NotFound)
    ));
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn closed_interval_proof_retains_identity_without_retaining_peer_statement() {
    let c = Case::new().await;
    let message = c.record(false).await;
    c.f.db.execute("UPDATE conversation_intervals SET phase='history',closed_at=clock_timestamp()-interval '40 days' WHERE account_id=$1 AND id=$2", &[&c.f.account,&c.interval.interval]).await.unwrap();
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 1);
    super::super::lifecycle::activation::prune(&mut c.f.connect().await, 30, 100)
        .await
        .unwrap();
    let row = c.f.db.query_one("SELECT phase,statement IS NULL FROM conversation_intervals WHERE account_id=$1 AND id=$2", &[&c.f.account,&c.interval.interval]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "withdrawn");
    assert!(row.get::<_, bool>(1));
    assert!(!c.retained(message).await);
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn malformed_inventory_column_type_returns_unavailable_without_decoding_rows() {
    let c = Case::new().await;
    c.record(false).await;
    c.f.db.batch_execute("ALTER TABLE conversation_confirmation_records ALTER COLUMN manifest_version TYPE integer USING manifest_version::integer").await.unwrap();
    assert!(!validate(&c.f.db).await.unwrap());
    assert!(matches!(
        inventory(&mut c.f.connect().await, &c.owner, None).await,
        Err(ConversationError::Unavailable)
    ));
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn malformed_nullable_inventory_column_returns_error_without_panicking() {
    let c = Case::new().await;
    c.record(false).await;
    c.f.db.batch_execute("DROP TRIGGER conversation_confirmation_before_update ON conversation_confirmation_records; ALTER TABLE conversation_confirmation_records ALTER COLUMN manifest_version DROP NOT NULL; UPDATE conversation_confirmation_records SET manifest_version=NULL").await.unwrap();
    assert!(validate(&c.f.db).await.unwrap());
    assert!(matches!(
        inventory(&mut c.f.connect().await, &c.owner, None).await,
        Err(ConversationError::Database(_))
    ));
    c.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn account_disablement_redacts_proof_without_removing_replay_identity() {
    let c = Case::new().await;
    let message = c.record(false).await;
    c.f.db
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&c.f.account],
        )
        .await
        .unwrap();
    assert!(matches!(
        inventory(&mut c.f.connect().await, &c.owner, None).await,
        Err(ConversationError::Forbidden)
    ));
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 1);
    assert!(!c.retained(message).await);
    assert_eq!(redact(&c.f.db, 100).await.unwrap(), 0);
    c.f.cleanup().await;
}
