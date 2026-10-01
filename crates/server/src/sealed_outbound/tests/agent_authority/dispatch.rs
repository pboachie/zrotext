// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    alpha_policy::AlphaPolicy,
    sealed_dispatch::{
        self,
        wire::{self, Fetch, GrantFrame, Ready},
    },
};
use p256::{
    ecdsa::{SigningKey, signature::Signer},
    elliptic_curve::Generate,
};
use zrotext_delivery_store::{RadioEvent, SessionRecord};

struct DispatchCase {
    agent: AgentCase,
    enrollment: SigningKey,
    session: SessionRecord,
    ready: Ready,
    policy: AlphaPolicy,
    message: Uuid,
    bytes: Vec<u8>,
}
impl DispatchCase {
    async fn new() -> Self {
        let agent = AgentCase::new(1, 1).await;
        agent
            .base
            .db
            .batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
            .await
            .unwrap();
        let enrollment = SigningKey::generate_from_rng(&mut rand::rng());
        let point = enrollment.verifying_key().to_sec1_point(false);
        let fingerprint: [u8; 32] = Sha256::digest(point.as_bytes()).into();
        agent
            .base
            .db
            .execute(
                "UPDATE device_keys SET signing_key_sec1=$2,fingerprint=$3 WHERE device_id=$1",
                &[
                    &agent.base.device,
                    &point.as_bytes(),
                    &fingerprint.as_slice(),
                ],
            )
            .await
            .unwrap();
        let message = Uuid::new_v4();
        let bytes = agent.base.envelope(message).await;
        let action = agent.approve(Uuid::new_v4(), &bytes).await;
        assert!(agent.send(&bytes, action.action).await.unwrap().created);
        let session = SessionRecord {
            account_id: agent.base.account,
            device_id: agent.base.device,
            site_id: "manifest-test".into(),
            instance_id: "fixture".into(),
            epoch: 1,
            deployment_epoch: 1,
        };
        let ready = Ready {
            grant_version: 1,
            connection_epoch: 1,
            line_id: agent.base.line,
            binding_generation: 1,
            reader_key_id: URL_SAFE_NO_PAD.encode(agent.base.readers[0].key_id),
        };
        let policy = AlphaPolicy::parse(
            Some("true"),
            Some(&agent.base.account.to_string()),
            Some("+12"),
        )
        .unwrap();
        Self {
            agent,
            enrollment,
            session,
            ready,
            policy,
            message,
            bytes,
        }
    }
    async fn grant(&self) -> Result<Option<GrantFrame>, sealed_dispatch::Error> {
        sealed_dispatch::grant(
            &mut self.agent.base.connect().await,
            &self.session,
            &self.ready,
            &self.policy,
        )
        .await
    }
    fn request(&self, grant: GrantFrame) -> Fetch {
        let signature: Signature = self
            .enrollment
            .sign(&wire::fetch_transcript(&grant).unwrap());
        Fetch {
            grant,
            signature_der: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        }
    }
    async fn fetch(&self, frame: GrantFrame) -> Result<Vec<u8>, sealed_dispatch::Error> {
        sealed_dispatch::fetch(
            &mut self.agent.base.connect().await,
            &self.request(frame),
            "manifest-test",
            1,
            &self.policy,
        )
        .await
    }
    async fn intent(&self, frame: &GrantFrame) -> RadioEvent {
        RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: frame.account_id,
            device_id: frame.device_id,
            message_id: frame.message_id,
            attempt_id: frame.attempt_id,
            evidence: zrotext_domain::Evidence::DurableSubmitIntent,
            observed_at_ms: now(&self.agent.base.db).await,
            segment_index: None,
            segment_count: None,
        }
    }
    async fn withdraw(&self, kind: &str) {
        if kind == "grant" {
            self.agent.base.db.execute("UPDATE agent_authority_grants SET revoked_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE grant_id=$1",&[&self.agent.grant]).await.unwrap();
        } else {
            self.agent.base.db.execute("UPDATE api_keys SET revoked_at=clock_timestamp() WHERE id=(SELECT api_key_id FROM agent_authority_grants WHERE grant_id=$1)",&[&self.agent.grant]).await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated signed agent dispatch schema"]
async fn admitted_agent_work_negotiates_exact_signed_fetch_and_one_use_durable_intent() {
    let case = DispatchCase::new().await;
    let frame = case.grant().await.unwrap().unwrap();
    assert_eq!(frame.segment_count, 1);
    assert_eq!(frame.message_id, case.message);
    assert_eq!(
        wire::digest(&frame.envelope_sha256).unwrap(),
        <[u8; 32]>::from(Sha256::digest(&case.bytes))
    );
    assert!(case.grant().await.unwrap().is_none());
    assert_eq!(case.fetch(frame.clone()).await.unwrap(), case.bytes);
    assert_eq!(case.fetch(frame.clone()).await.unwrap(), case.bytes);
    let intent = case.intent(&frame).await;
    let mut db = case.agent.base.connect().await;
    let mut store = DeliveryStore::new(&mut db);
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        zrotext_domain::MessageState::Submitting
    );
    assert!(case.fetch(frame).await.is_err());
    assert_eq!(case.agent.reservations().await, (1, 1, 1));
    let count: i64 = case
        .agent
        .base
        .db
        .query_one(
            "SELECT count(*) FROM message_events WHERE evidence_code='durable_intent'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    case.agent.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated signed agent dispatch schemas"]
async fn agent_grant_and_ordinary_key_withdrawal_stop_negotiation_fetch_and_intent() {
    for kind in ["grant", "key"] {
        for operation in ["grant", "fetch", "intent"] {
            let case = DispatchCase::new().await;
            let frame = if operation == "grant" {
                None
            } else {
                Some(case.grant().await.unwrap().unwrap())
            };
            if operation == "intent" {
                assert_eq!(
                    case.fetch(frame.clone().unwrap()).await.unwrap(),
                    case.bytes
                );
            }
            case.withdraw(kind).await;
            match operation {
                "grant" => assert!(!matches!(case.grant().await, Ok(Some(_)))),
                "fetch" => assert!(case.fetch(frame.clone().unwrap()).await.is_err()),
                _ => {
                    let intent = case.intent(frame.as_ref().unwrap()).await;
                    let mut db = case.agent.base.connect().await;
                    assert!(
                        DeliveryStore::new(&mut db)
                            .record_radio_event(intent)
                            .await
                            .is_err()
                    );
                }
            }
            let row=case.agent.base.db.query_one("SELECT state,(SELECT count(*) FROM message_attempts),(SELECT count(*) FROM message_events WHERE evidence_code='durable_intent') FROM messages WHERE id=$1",&[&case.message]).await.unwrap();
            assert_eq!(
                row.get::<_, String>(0),
                if operation == "grant" {
                    "queued"
                } else {
                    "claimed"
                }
            );
            assert_eq!(row.get::<_, i64>(1), i64::from(operation != "grant"));
            assert_eq!(row.get::<_, i64>(2), 0);
            assert_eq!(case.agent.reservations().await, (1, 1, 1));
            case.agent.base.cleanup().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated signed agent dispatch schema"]
async fn agent_key_expiry_during_final_intent_write_rolls_back_every_new_effect() {
    let case = DispatchCase::new().await;
    let frame = case.grant().await.unwrap().unwrap();
    assert_eq!(case.fetch(frame.clone()).await.unwrap(), case.bytes);
    case.agent.base.db.batch_execute("CREATE SEQUENCE agent_intent_delays; CREATE FUNCTION delay_agent_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('agent_intent_delays'); PERFORM pg_sleep(6); RETURN NEW; END $$; CREATE TRIGGER delay_agent_intent BEFORE UPDATE OF outcome ON dispatch_fences FOR EACH ROW WHEN (NEW.outcome='submitting') EXECUTE FUNCTION delay_agent_intent()").await.unwrap();
    let intent = case.intent(&frame).await;
    case.agent.base.db.execute("UPDATE api_keys SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=(SELECT api_key_id FROM agent_authority_grants WHERE grant_id=$1)",&[&case.agent.grant]).await.unwrap();
    let mut db = case.agent.base.connect().await;
    assert!(
        DeliveryStore::new(&mut db)
            .record_radio_event(intent)
            .await
            .is_err()
    );
    let row=case.agent.base.db.query_one("SELECT state,(SELECT outcome FROM dispatch_fences WHERE message_id=$1),(SELECT count(*) FROM message_events WHERE id=$2) FROM messages WHERE id=$1",&[&case.message,&intent.event_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "claimed");
    assert_eq!(row.get::<_, String>(1), "granted");
    assert_eq!(row.get::<_, i64>(2), 0);
    assert!(now(&case.agent.base.db).await < frame.expires_at_ms);
    let delayed: bool = case
        .agent
        .base
        .db
        .query_one("SELECT is_called FROM agent_intent_delays", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        delayed,
        "the regression must reach the final fence-write delay"
    );

    assert_eq!(case.agent.reservations().await, (1, 1, 1));
    case.agent.base.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated signed agent dispatch schema"]
async fn signed_agent_fetch_rechecks_grant_expiry_after_waiting_for_unchanged_key_authority() {
    let case = DispatchCase::new().await;
    let frame = case.grant().await.unwrap().unwrap();
    let request = case.request(frame.clone());
    let mut blocker = case.agent.base.connect().await;
    let held_key = blocker.transaction().await.unwrap();
    assert_eq!(held_key.execute("UPDATE api_keys SET expires_at=expires_at WHERE id=(SELECT api_key_id FROM agent_authority_grants WHERE grant_id=$1)", &[&case.agent.grant]).await.unwrap(), 1);
    let mut fetch_connection = case.agent.base.connect().await;
    fetch_connection
        .batch_execute("SET statement_timeout='45s'")
        .await
        .unwrap();
    let pid: i32 = fetch_connection
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let execute = sealed_dispatch::fetch(
        &mut fetch_connection,
        &request,
        "manifest-test",
        1,
        &case.policy,
    );
    let release = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let blocked: bool = case.agent.base.db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", &[&pid]).await.unwrap().get(0);
                if blocked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("signed fetch must reach the actual key-authority lock wait");
        tokio::time::timeout(Duration::from_secs(40), async {
            while now(&case.agent.base.db).await <= frame.expires_at_ms {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the unmodified sealed grant must expire while fetch waits");
        let live: bool = case.agent.base.db.query_one("SELECT g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.expires_at>clock_timestamp() AND p.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM agent_authority_grants g JOIN api_keys k ON k.id=g.api_key_id JOIN agent_authority_approvals p ON p.account_id=g.account_id AND p.grant_id=g.grant_id WHERE g.grant_id=$1", &[&case.agent.grant]).await.unwrap().get(0);
        assert!(
            live,
            "only the sealed dispatch grant may expire in this regression"
        );
        held_key.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(execute, release);
    assert!(
        matches!(result, Err(sealed_dispatch::Error::Refused)),
        "{result:?}"
    );
    let row = case.agent.base.db.query_one("SELECT state,(SELECT count(*) FROM message_attempts),(SELECT count(*) FROM dispatch_fences),(SELECT count(*) FROM message_events WHERE evidence_code='durable_intent') FROM messages WHERE id=$1", &[&case.message]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "claimed");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, i64>(3), 0);
    assert_eq!(case.agent.reservations().await, (1, 1, 1));
    case.agent.base.cleanup().await;
}
