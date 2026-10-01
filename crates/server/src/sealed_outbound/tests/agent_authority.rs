// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    agent_authority::{Action, store},
    auth::agent_grants,
};

struct AgentCase {
    base: TestCase,
    token: String,
    grant: Uuid,
}
impl AgentCase {
    async fn new(message_limit: i32, turn_limit: i32) -> Self {
        let (base, connector, connector_key) = TestCase::with_agent_connector().await;
        let key = Uuid::new_v4();
        let grant = Uuid::new_v4();
        let token = format!("ztk_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let mut mac = Hmac::<Sha256>::new_from_slice(&crate::test_keys::key(76)).unwrap();
        mac.update(b"api-key-v1\0");
        mac.update(token.as_bytes());
        let hash = mac.finalize().into_bytes();
        let current = now(&base.db).await;
        base.db.execute("INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id,expires_at) VALUES($1,$2,$3,$4,$5,ARRAY['messages:send'],$6,to_timestamp($7::bigint::double precision/1000))",&[&key,&base.account,&base.user,&&token[4..16],&hash.as_slice(),&base.device,&(current+120_000)]).await.unwrap();
        let recipient = base.hasher.agent_recipient_digest(base.account, "+12");
        base.db.execute("INSERT INTO agent_authority_grants(account_id,grant_id,api_key_id,connector_id,connector_key_id,signer_key_id,device_id,line_id,binding_generation,recipient_digest,metadata_allowed,content_allowed,draft_allowed,send_allowed,owner_self_notification,created_by_user,created_session,created_ms,expires_ms,message_limit,turn_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,false,false,false,true,true,$10,$11,$12,$13,$14,$15)",&[&base.account,&grant,&key,&connector,&connector_key.as_slice(),&base.signer.as_slice(),&base.device,&base.line,&recipient.as_slice(),&base.user,&Uuid::new_v4(),&current,&(current+120_000),&message_limit,&turn_limit]).await.unwrap();
        Self { base, token, grant }
    }
    async fn approve(&self, action_id: Uuid, bytes: &[u8]) -> Action {
        let mut db = self.base.connect().await;
        let tx = db.transaction().await.unwrap();
        let action = store::validate_owner_action(
            &tx,
            &self.base.hasher,
            self.base.account,
            self.grant,
            action_id,
            bytes,
            now(&self.base.db).await,
        )
        .await
        .unwrap();
        tx.execute("INSERT INTO agent_authority_approvals(account_id,action_id,grant_id,message_id,device_id,line_id,binding_generation,recipient_digest,unsigned_digest,action_digest,not_before_ms,expires_ms,approved_by_user,approved_session,approved_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,floor(extract(epoch FROM clock_timestamp())*1000)::bigint)",&[&action.account,&action.action,&action.grant,&action.message,&action.device,&action.line,&action.binding_generation,&action.recipient.as_slice(),&action.unsigned_envelope.as_slice(),&action.digest().as_slice(),&action.not_before_ms,&action.expires_ms,&self.base.user,&Uuid::new_v4()]).await.unwrap();
        tx.commit().await.unwrap();
        action
    }
    async fn send(&self, bytes: &[u8], action: Uuid) -> Result<AcceptOutcome, AdmitError> {
        let mut db = self.base.connect().await;
        let agent = agent_grants::authenticate_agent(&db, &self.base.hasher, &self.token)
            .await
            .map_err(|_| AdmitError::Forbidden)?;
        admit_agent_candidate02(
            &mut db,
            &agent,
            &self.base.hasher,
            self.base.writer(),
            bytes,
            action,
        )
        .await
    }
    async fn reservations(&self) -> (i32, i32, i64) {
        let row=self.base.db.query_one("SELECT messages_reserved,turns_consumed,(SELECT count(*) FROM agent_authority_actions WHERE account_id=$1) FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2",&[&self.base.account,&self.grant]).await.unwrap();
        (row.get(0), row.get(1), row.get(2))
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn exact_agent_action_replay_consumes_one_reservation_and_has_no_normal_api_downgrade() {
    let case = AgentCase::new(1, 1).await;
    let bytes = case.base.envelope(Uuid::new_v4()).await;
    let action = case.approve(Uuid::new_v4(), &bytes).await;
    assert!(
        auth::authenticate_api_key(&case.base.db, &case.base.hasher, &case.token)
            .await
            .is_err()
    );
    assert!(case.send(&bytes, action.action).await.unwrap().created);
    assert!(!case.send(&bytes, action.action).await.unwrap().created);
    assert_eq!(case.reservations().await, (1, 1, 1));
    assert_eq!(counts(&case.base).await, (1, 1, 1));
    let provenance: Uuid = case
        .base
        .db
        .query_one(
            "SELECT agent_grant_id FROM messages WHERE account_id=$1 AND id=$2",
            &[&case.base.account, &action.message],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(provenance, case.grant);
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn independent_agent_budget_race_accepts_only_one_exact_owner_action() {
    let case = AgentCase::new(1, 1).await;
    let first = case.base.envelope(Uuid::new_v4()).await;
    let second = case.base.envelope(Uuid::new_v4()).await;
    let a = case.approve(Uuid::new_v4(), &first).await;
    let b = case.approve(Uuid::new_v4(), &second).await;
    let (left, right) = tokio::join!(case.send(&first, a.action), case.send(&second, b.action));
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert_eq!(case.reservations().await, (1, 1, 1));
    assert_eq!(counts(&case.base).await, (1, 1, 1));
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn edited_ciphertext_and_owner_messages_cannot_be_adopted_as_approved_agent_work() {
    let case = AgentCase::new(2, 2).await;
    let bytes = case.base.envelope(Uuid::new_v4()).await;
    let action = case.approve(Uuid::new_v4(), &bytes).await;
    let mut edited = bytes.clone();
    edited[170] ^= 1;
    signed(&case.base, &mut edited);
    assert!(matches!(
        case.send(&edited, action.action).await,
        Err(AdmitError::Forbidden)
    ));
    assert_eq!(case.reservations().await, (0, 0, 0));
    assert!(case.base.admit(&bytes).await.unwrap().created);
    assert!(matches!(
        case.send(&bytes, action.action).await,
        Err(AdmitError::Forbidden)
    ));
    assert_eq!(case.reservations().await, (0, 0, 0));
    assert_eq!(counts(&case.base).await, (1, 1, 1));
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn revocation_and_takeover_stop_queued_agent_work_without_erasing_its_provenance() {
    for takeover in [false, true] {
        let case = AgentCase::new(1, 1).await;
        let bytes = case.base.envelope(Uuid::new_v4()).await;
        let action = case.approve(Uuid::new_v4(), &bytes).await;
        assert!(case.send(&bytes, action.action).await.unwrap().created);
        case.base.db.execute(if takeover {"UPDATE agent_authority_grants SET taken_over_ms=1 WHERE account_id=$1 AND grant_id=$2"}else{"UPDATE agent_authority_grants SET revoked_ms=1 WHERE account_id=$1 AND grant_id=$2"},&[&case.base.account,&case.grant]).await.unwrap();
        assert!(
            case.base
                .db
                .query_one(
                    "SELECT require_live_agent_action($1,$2)",
                    &[&case.base.account, &action.message]
                )
                .await
                .is_err()
        );
        assert!(
            case.base
                .db
                .execute(
                    "UPDATE messages SET agent_grant_id=NULL WHERE id=$1",
                    &[&action.message]
                )
                .await
                .is_err()
        );
        assert!(case.send(&bytes, action.action).await.is_err());
        assert_eq!(case.reservations().await, (1, 1, 1));
        case.base.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn suppression_and_off_channel_withdrawal_stop_already_queued_agent_actions() {
    for owner_hold in [false, true] {
        let case = AgentCase::new(1, 1).await;
        let bytes = case.base.envelope(Uuid::new_v4()).await;
        let action = case.approve(Uuid::new_v4(), &bytes).await;
        assert!(case.send(&bytes, action.action).await.unwrap().created);
        case.base
            .db
            .query_one(
                "SELECT require_live_agent_action($1,$2)",
                &[&case.base.account, &action.message],
            )
            .await
            .unwrap();
        if owner_hold {
            case.base.db.execute("INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) VALUES($1,$2,'+12','email','opt_out',clock_timestamp(),$3)", &[&Uuid::new_v4(), &case.base.account, &case.base.user]).await.unwrap();
        } else {
            let event = Uuid::new_v4();
            case.base.db.execute("INSERT INTO line_opt_out_events(id,account_id,device_id,line_id,binding_generation,device_sequence,recipient_e164,classification,observed_at,event_digest,signature_der) VALUES($1,$2,$3,$4,1,1,'+12','opt_out',clock_timestamp(),$5,$6)", &[&event, &case.base.account, &case.base.device, &case.base.line, &vec![8u8;32], &vec![9u8;8]]).await.unwrap();
            case.base.db.execute("INSERT INTO recipient_suppressions(account_id,recipient_e164,source_unsolicited_event_id,source_observed_at,source) VALUES($1,'+12',$2,clock_timestamp(),'sms_unsolicited_keyword')", &[&case.base.account, &event]).await.unwrap();
        }
        let error = case
            .base
            .db
            .query_one(
                "SELECT require_live_agent_action($1,$2)",
                &[&case.base.account, &action.message],
            )
            .await
            .unwrap_err();
        assert_eq!(error.as_db_error().unwrap().code().code(), "23514");
        assert!(case.send(&bytes, action.action).await.is_err());
        assert_eq!(case.reservations().await, (1, 1, 1));
        assert_eq!(counts(&case.base).await, (1, 1, 1));
        case.base.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn action_expiry_is_rechecked_after_waiting_for_the_grant_authority_lock() {
    let case = AgentCase::new(1, 1).await;
    let bytes = envelope(&case.base, Uuid::new_v4(), now(&case.base.db).await, 4_000);
    let action = case.approve(Uuid::new_v4(), &bytes).await;
    assert!(case.send(&bytes, action.action).await.unwrap().created);
    let mut blocker = case.base.connect().await;
    let lock = blocker.transaction().await.unwrap();
    lock.query_one("SELECT grant_id FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2 FOR UPDATE", &[&case.base.account, &case.grant]).await.unwrap();
    let waiter = case.base.connect().await;
    let pid: i32 = waiter
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let account = case.base.account;
    let message = action.message;
    let waiting = tokio::spawn(async move {
        waiter
            .query_one(
                "SELECT require_live_agent_action($1,$2)",
                &[&account, &message],
            )
            .await
    });
    let mut blocked = false;
    for _ in 0..40 {
        blocked = case.base.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", &[&pid]).await.unwrap().get(0);
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        blocked,
        "the authority check must actually wait for the grant lock"
    );
    let remaining = action
        .expires_ms
        .saturating_sub(now(&case.base.db).await)
        .max(0) as u64;
    tokio::time::sleep(Duration::from_millis(remaining + 25)).await;
    lock.commit().await.unwrap();
    let error = waiting.await.unwrap().unwrap_err();
    assert_eq!(error.as_db_error().unwrap().code().code(), "23514");
    assert_eq!(case.reservations().await, (1, 1, 1));
    case.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn cancelled_and_scrubbed_agent_work_keeps_its_consumed_budget_and_cannot_authorize_an_effect()
 {
    let case = AgentCase::new(1, 1).await;
    let bytes = case.base.envelope(Uuid::new_v4()).await;
    let action = case.approve(Uuid::new_v4(), &bytes).await;
    assert!(case.send(&bytes, action.action).await.unwrap().created);
    let mut db = case.base.connect().await;
    assert!(
        DeliveryStore::new(&mut db)
            .cancel(case.base.account, action.message)
            .await
            .unwrap()
    );
    case.base
        .db
        .execute(
            "UPDATE messages SET recipient_e164=NULL,transport_payload=NULL WHERE id=$1",
            &[&action.message],
        )
        .await
        .unwrap();
    assert!(
        case.base
            .db
            .query_one(
                "SELECT require_live_agent_action($1,$2)",
                &[&case.base.account, &action.message]
            )
            .await
            .is_err()
    );
    assert_eq!(case.reservations().await, (1, 1, 1));
    let refunds: i64 = case.base.db.query_one("SELECT count(*) FROM usage_ledger WHERE account_id=$1 AND message_id=$2 AND entry_kind='refund'", &[&case.base.account, &action.message]).await.unwrap().get(0);
    assert_eq!(refunds, 1);
    case.base.cleanup().await;
}

async fn assert_authority_wait(case: &AgentCase, pid: i32) {
    for _ in 0..80 {
        let blocked: bool = case.base.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", &[&pid]).await.unwrap().get(0);
        if blocked {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("authority withdrawal and effect validation must serialize");
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn ordinary_key_and_connector_withdrawal_serialize_with_new_agent_effect_authority() {
    let withdrawals = [
        "UPDATE api_keys SET revoked_at=clock_timestamp() WHERE account_id=$1 AND id=(SELECT api_key_id FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2)",
        "UPDATE connector_grants SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint,revoked_by_user=(SELECT created_by_user FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2) WHERE account_id=$1 AND kind='send' AND connector_id=(SELECT connector_id FROM agent_authority_grants WHERE account_id=$1 AND grant_id=$2)",
    ];
    for withdrawal in withdrawals {
        for effect_first in [false, true] {
            let case = AgentCase::new(1, 1).await;
            let bytes = case.base.envelope(Uuid::new_v4()).await;
            let action = case.approve(Uuid::new_v4(), &bytes).await;
            assert!(case.send(&bytes, action.action).await.unwrap().created);
            let mut first = case.base.connect().await;
            let tx = first.transaction().await.unwrap();
            let other = case.base.connect().await;
            let pid: i32 = other
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let account = case.base.account;
            let grant = case.grant;
            let message = action.message;
            if effect_first {
                tx.query_one(
                    "SELECT require_live_agent_action($1,$2)",
                    &[&account, &message],
                )
                .await
                .unwrap();
                let pending =
                    tokio::spawn(
                        async move { other.execute(withdrawal, &[&account, &grant]).await },
                    );
                assert_authority_wait(&case, pid).await;
                tx.commit().await.unwrap();
                assert_eq!(pending.await.unwrap().unwrap(), 1);
            } else {
                assert_eq!(
                    tx.execute(withdrawal, &[&account, &grant]).await.unwrap(),
                    1
                );
                let pending = tokio::spawn(async move {
                    other
                        .query_one(
                            "SELECT require_live_agent_action($1,$2)",
                            &[&account, &message],
                        )
                        .await
                });
                assert_authority_wait(&case, pid).await;
                tx.commit().await.unwrap();
                assert_eq!(
                    pending
                        .await
                        .unwrap()
                        .unwrap_err()
                        .as_db_error()
                        .unwrap()
                        .code()
                        .code(),
                    "23514"
                );
            }
            assert!(
                case.base
                    .db
                    .query_one(
                        "SELECT require_live_agent_action($1,$2)",
                        &[&account, &message]
                    )
                    .await
                    .is_err()
            );
            assert_eq!(case.reservations().await, (1, 1, 1));
            case.base.cleanup().await;
        }
    }
}
