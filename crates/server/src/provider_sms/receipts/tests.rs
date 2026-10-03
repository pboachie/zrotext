// SPDX-License-Identifier: AGPL-3.0-only
use super::{test_support::*, *};
use tokio_postgres::NoTls;

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
}
struct Fixture {
    admin: Client,
    url: String,
    schema: String,
    account: Uuid,
    attempt: Uuid,
}
impl Fixture {
    async fn new(proposal: bool) -> (Self, Client) {
        let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("use a disposable PostgreSQL test database");
        let admin = connect(&base).await;
        let schema = format!("provider_receipt_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let client = connect(&url).await;
        client
            .batch_execute(include_str!(
                "../../../../../deploy/compose/migrations/001_foundation.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../../../deploy/compose/migrations/002_auth.sql"
            ))
            .await
            .unwrap();
        if proposal {
            client.batch_execute(PROPOSAL).await.unwrap();
        }
        let account = Uuid::new_v4();
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        client
            .execute("INSERT INTO sites(site_id) VALUES($1)", &[&SITE])
            .await
            .unwrap();
        (
            Self {
                admin,
                url,
                schema,
                account,
                attempt: Uuid::new_v4(),
            },
            client,
        )
    }
    fn permit(&self) -> ElectedWriterPermit {
        ElectedWriterPermit::synthetic(self.account, SITE, 1)
    }
    async fn seed(&self, client: &Client) {
        seed(client, self.account, self.attempt).await;
    }
    async fn finish(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn absent_proposal_and_unknown_correlations_cannot_create_an_attempt() {
    let (f, mut client) = Fixture::new(false).await;
    let event = receipt(&request(f.account), Uuid::new_v4(), "sent");
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event).await,
        Err(Error::Unavailable)
    );
    client.batch_execute(PROPOSAL).await.unwrap();
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event).await,
        Err(Error::Uncorrelated)
    );
    let count: i64 = client
        .query_one("SELECT count(*) FROM provider_receipt_attempts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    f.seed(&client).await;
    let other = ElectedWriterPermit::synthetic(Uuid::new_v4(), SITE, 1);
    assert_eq!(
        record_known_receipt(&mut client, &other, &event).await,
        Err(Error::Authority)
    );
    let unknown = receipt_for_message(&request(f.account), Uuid::new_v4(), "sent", Uuid::new_v4());
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &unknown).await,
        Err(Error::Uncorrelated)
    );
    let mut changed = request(f.account);
    changed.route.revision += 1;
    assert_eq!(
        record_known_receipt(
            &mut client,
            &f.permit(),
            &receipt(&changed, Uuid::new_v4(), "sent")
        )
        .await,
        Err(Error::Uncorrelated)
    );
    let mut changed = request(f.account);
    changed.digest = [9; 32];
    assert_eq!(
        record_known_receipt(
            &mut client,
            &f.permit(),
            &receipt(&changed, Uuid::new_v4(), "sent")
        )
        .await,
        Err(Error::Evidence(Rejection::RequestConflict))
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn receipt_restart_replay_and_semantic_conflict_preserve_sticky_delivery() {
    let (f, mut client) = Fixture::new(true).await;
    f.seed(&client).await;
    let req = request(f.account);
    let event_id = Uuid::new_v4();
    let event = receipt(&req, event_id, "delivered");
    let outcome = record_known_receipt(&mut client, &f.permit(), &event)
        .await
        .unwrap();
    assert_eq!(outcome.state, MessageState::Delivered);
    assert_eq!(outcome.version, 1);
    drop(client); // fresh process/connection state comes entirely from PostgreSQL
    let mut client = connect(&f.url).await;
    let duplicate = record_known_receipt(&mut client, &f.permit(), &event)
        .await
        .unwrap();
    assert_eq!(duplicate.effect, ReceiptEffect::Duplicate);
    assert_eq!(duplicate.version, 1);
    let conflict = receipt(&req, event_id, "delivery_failed");
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &conflict).await,
        Err(Error::Evidence(Rejection::EventConflict))
    );
    let negative = receipt(&req, Uuid::new_v4(), "delivery_failed");
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &negative).await,
        Err(Error::Evidence(Rejection::EvidenceConflict))
    );
    let later = receipt(&req, Uuid::new_v4(), "sent");
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &later)
            .await
            .unwrap()
            .state,
        MessageState::Delivered
    );
    let row = client
        .query_one(
            "SELECT state,event_count FROM provider_receipt_attempts WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "delivered");
    assert_eq!(row.get::<_, i16>(1), 2);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn concurrent_receipts_have_an_exact_durable_capacity_and_no_eviction() {
    let (f, mut client) = Fixture::new(true).await;
    f.seed(&client).await;
    let mut jobs = tokio::task::JoinSet::new();
    for worker in 0..8u128 {
        let url = f.url.clone();
        let account = f.account;
        jobs.spawn(async move {
            let mut db = connect(&url).await;
            let permit = ElectedWriterPermit::synthetic(account, SITE, 1);
            let mut accepted = 0;
            for offset in 0..10u128 {
                let event = receipt(
                    &request(account),
                    Uuid::from_u128(100 + worker * 10 + offset),
                    "future_status",
                );
                match record_known_receipt(&mut db, &permit, &event).await {
                    Ok(_) => accepted += 1,
                    Err(Error::Evidence(Rejection::EventCapacity)) => {}
                    other => panic!("unexpected closed receipt result: {other:?}"),
                }
            }
            accepted
        });
    }
    let mut accepted = 0;
    while let Some(result) = jobs.join_next().await {
        accepted += result.unwrap();
    }
    assert_eq!(accepted, 64);
    let row=client.query_one("SELECT event_count,state_version,state FROM provider_receipt_attempts WHERE account_id=$1",&[&f.account]).await.unwrap();
    assert_eq!(row.get::<_, i16>(0), 64);
    assert_eq!(row.get::<_, i64>(1), 64);
    assert_eq!(row.get::<_, String>(2), "submitting");
    let event_id: Uuid = client
        .query_one(
            "SELECT event_id FROM provider_receipt_events WHERE account_id=$1 LIMIT 1",
            &[&f.account],
        )
        .await
        .unwrap()
        .get(0);
    let duplicate = receipt(&request(f.account), event_id, "future_status");
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &duplicate)
            .await
            .unwrap()
            .effect,
        ReceiptEffect::Duplicate
    );
    assert_eq!(
        record_known_receipt(
            &mut client,
            &f.permit(),
            &receipt(&request(f.account), Uuid::new_v4(), "delivered")
        )
        .await,
        Err(Error::Evidence(Rejection::EventCapacity))
    );
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM provider_receipt_events WHERE account_id=$1",
                &[&f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        64
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn writer_fences_refuse_while_disabled_account_can_resolve_old_evidence() {
    let (f, mut client) = Fixture::new(true).await;
    f.seed(&client).await;
    let event = receipt(&request(f.account), Uuid::new_v4(), "sent");
    let stale = ElectedWriterPermit::synthetic(f.account, SITE, 2);
    assert_eq!(
        record_known_receipt(&mut client, &stale, &event).await,
        Err(Error::Authority)
    );
    for sql in [
        "UPDATE sites SET enabled=false WHERE site_id=$1",
        "UPDATE sites SET draining=true WHERE site_id=$1",
    ] {
        client.execute(sql, &[&SITE]).await.unwrap();
        assert_eq!(
            record_known_receipt(&mut client, &f.permit(), &event).await,
            Err(Error::Authority)
        );
        client
            .execute(
                "UPDATE sites SET enabled=true,draining=false WHERE site_id=$1",
                &[&SITE],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&f.account],
        )
        .await
        .unwrap();
    client
        .batch_execute("UPDATE deployment_authority SET dispatch_enabled=false")
        .await
        .unwrap();
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event)
            .await
            .unwrap()
            .state,
        MessageState::Submitted
    );
    // Evidence resolution does not clear the account disable or open dispatch.
    assert!(
        client
            .query_one(
                "SELECT disabled_at IS NOT NULL FROM accounts WHERE id=$1",
                &[&f.account]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        !client
            .query_one("SELECT dispatch_enabled FROM deployment_authority", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn erase_receipt_keeps_only_an_identity_fence_and_replay_cannot_recreate_it() {
    let (f, mut client) = Fixture::new(true).await;
    f.seed(&client).await;
    let event = receipt(&request(f.account), Uuid::new_v4(), "sent");
    record_known_receipt(&mut client, &f.permit(), &event)
        .await
        .unwrap();
    assert!(
        erase_receipt_attempt(&mut client, &f.permit(), f.attempt)
            .await
            .unwrap()
    );
    drop(client);
    let mut client = connect(&f.url).await;
    assert!(
        !erase_receipt_attempt(&mut client, &f.permit(), f.attempt)
            .await
            .unwrap()
    );
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event).await,
        Err(Error::Uncorrelated)
    );
    let row = client
        .query_one(
            "SELECT erased_at IS NOT NULL,route_fingerprint IS NULL,request_digest IS NULL, \
        provider_message_id IS NULL,state IS NULL,delivery_failed IS NULL,accepted_at IS NULL, \
        updated_at IS NULL,created_epoch IS NULL,event_count,state_version \
        FROM provider_receipt_attempts WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap();
    for field in 0..9 {
        assert!(row.get::<_, bool>(field));
    }
    assert_eq!(row.get::<_, i16>(9), 0);
    assert_eq!(row.get::<_, i64>(10), 2);
    assert!(
        client
            .execute(
                "UPDATE provider_receipt_attempts SET erased_at=NULL WHERE account_id=$1",
                &[&f.account]
            )
            .await
            .is_err()
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM provider_receipt_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn persisted_count_inconsistency_and_version_overflow_refuse_without_effect() {
    let (f, mut client) = Fixture::new(true).await;
    let req = request(f.account);
    let event = receipt(&req, Uuid::new_v4(), "sent");
    // Synthetic initial committed-intent fixture can start at a supplied version;
    // no runtime correlation creator is exposed.
    client.execute("INSERT INTO provider_receipt_attempts(account_id,attempt_id,provider,route_fingerprint,request_digest, \
        provider_message_id,state,delivery_failed,accepted_at,updated_at,created_epoch,state_version) \
        VALUES($1,$2,'telnyx_sms_v2',$3,$4,$5,'submitting',false,now(),now(),1,$6)",
        &[&f.account,&f.attempt,&route_fingerprint(&req).as_slice(),&req.digest().as_slice(),&Uuid::from_u128(4),&i64::MAX]).await.unwrap();
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event).await,
        Err(Error::VersionExhausted)
    );
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM provider_receipt_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    client.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) \
        VALUES($1,$2,$3,$4,'unrecognized',1)",&[&f.account,&f.attempt,&Uuid::new_v4(),&[1u8;32].as_slice()]).await.unwrap();
    assert_eq!(
        record_known_receipt(&mut client, &f.permit(), &event).await,
        Err(Error::Inconsistent)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn restarted_negative_and_unconfirmed_orders_preserve_existing_reducer_semantics() {
    for statuses in [
        ["delivery_failed", "delivery_unconfirmed", "sent"],
        ["delivery_unconfirmed", "delivery_failed", "sent"],
    ] {
        let (f, mut client) = Fixture::new(true).await;
        f.seed(&client).await;
        for status in statuses {
            record_known_receipt(
                &mut client,
                &f.permit(),
                &receipt(&request(f.account), Uuid::new_v4(), status),
            )
            .await
            .unwrap();
            drop(client);
            client = connect(&f.url).await;
        }
        let row = client
            .query_one(
                "SELECT state,delivery_failed,event_count FROM provider_receipt_attempts",
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            row.get::<_, String>(0).as_str(),
            "submitted" | "delivery_unconfirmed"
        ));
        assert!(row.get::<_, bool>(1));
        assert_eq!(row.get::<_, i16>(2), 3);
        assert_eq!(
            record_known_receipt(
                &mut client,
                &f.permit(),
                &receipt(&request(f.account), Uuid::new_v4(), "delivered")
            )
            .await,
            Err(Error::Evidence(Rejection::EvidenceConflict))
        );
        f.finish().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn competing_failed_and_delivered_receipts_commit_only_one_consistent_outcome() {
    let (f, client) = Fixture::new(true).await;
    f.seed(&client).await;
    let mut jobs = tokio::task::JoinSet::new();
    for status in ["sending_failed", "delivered"] {
        let url = f.url.clone();
        let account = f.account;
        jobs.spawn(async move {
            let mut db = connect(&url).await;
            record_known_receipt(
                &mut db,
                &ElectedWriterPermit::synthetic(account, SITE, 1),
                &receipt(&request(account), Uuid::new_v4(), status),
            )
            .await
        });
    }
    let mut successes = 0;
    let mut conflicts = 0;
    while let Some(result) = jobs.join_next().await {
        match result.unwrap() {
            Ok(_) => successes += 1,
            Err(Error::Evidence(Rejection::EvidenceConflict)) => conflicts += 1,
            other => panic!("unexpected closed receipt result: {other:?}"),
        }
    }
    assert_eq!((successes, conflicts), (1, 1));
    let row = client
        .query_one(
            "SELECT state,event_count,state_version FROM provider_receipt_attempts",
            &[],
        )
        .await
        .unwrap();
    assert!(matches!(
        row.get::<_, String>(0).as_str(),
        "failed" | "delivered"
    ));
    assert_eq!(row.get::<_, i16>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM provider_receipt_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn maximum_version_allows_exact_duplicate_but_refuses_new_evidence() {
    let (f, mut client) = Fixture::new(true).await;
    let req = request(f.account);
    let event = receipt(&req, Uuid::new_v4(), "future_status");
    // Test-only committed correlation already contains one exact event at the
    // version limit. Production has no API that can seed either row.
    client.execute("INSERT INTO provider_receipt_attempts(account_id,attempt_id,provider,route_fingerprint,request_digest, \
        provider_message_id,state,delivery_failed,accepted_at,updated_at,created_epoch,state_version,event_count) \
        VALUES($1,$2,'telnyx_sms_v2',$3,$4,$5,'submitting',false,now(),now(),1,$6,1)",
        &[&f.account,&f.attempt,&route_fingerprint(&req).as_slice(),&req.digest().as_slice(),&event.message_id,&i64::MAX]).await.unwrap();
    client.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) \
        VALUES($1,$2,$3,$4,'unrecognized',1)", &[&f.account,&f.attempt,&event.event_id,&event.identity.as_slice()]).await.unwrap();
    let duplicate = record_known_receipt(&mut client, &f.permit(), &event)
        .await
        .unwrap();
    assert_eq!(duplicate.effect, ReceiptEffect::Duplicate);
    assert_eq!(duplicate.version, i64::MAX);
    assert_eq!(
        record_known_receipt(
            &mut client,
            &f.permit(),
            &receipt(&req, Uuid::new_v4(), "sent")
        )
        .await,
        Err(Error::VersionExhausted)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; disposable PostgreSQL only"]
async fn inconsistent_persisted_facts_and_event_versions_fail_closed() {
    for (fact, event_version) in [("delivered", 1_i64), ("unrecognized", 2_i64)] {
        let (f, mut client) = Fixture::new(true).await;
        f.seed(&client).await;
        // Valid SQL domains are insufficient to prove reducer consistency.
        // Construct damaged test-only storage without bypassing its constraints.
        client.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) \
            VALUES($1,$2,$3,$4,$5,$6)", &[&f.account,&f.attempt,&Uuid::new_v4(),&[1_u8;32].as_slice(),&fact,&event_version]).await.unwrap();
        client.execute("UPDATE provider_receipt_attempts SET event_count=1,state_version=1 WHERE account_id=$1", &[&f.account]).await.unwrap();
        assert_eq!(
            record_known_receipt(
                &mut client,
                &f.permit(),
                &receipt(&request(f.account), Uuid::new_v4(), "sent")
            )
            .await,
            Err(Error::Inconsistent)
        );
        assert!(client.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) \
            VALUES($1,$2,$3,$4,'unrecognized',3)", &[&f.account,&f.attempt,&Uuid::new_v4(),&[1_u8;31].as_slice()]).await.is_err());
        assert_eq!(
            client
                .query_one("SELECT count(*) FROM provider_receipt_events", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        f.finish().await;
    }
}
