// SPDX-License-Identifier: AGPL-3.0-only
//! Storage fixtures exercise immutable records, not valid signing or consent.
use super::*;
use crate::http_owner_conversations::{android_proposal::lifecycle, tests::prepared};
use crate::sealed_manifest_store::tests::Fixture;

async fn observed_inventory(f: &Fixture) -> Result<serde_json::Value, ConversationError> {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let result = lifecycle::inventory(&tx, f.account).await;
    tx.rollback().await.unwrap();
    result
}
async fn observed_prune(f: &Fixture, limit: i64) -> Result<u64, ConversationError> {
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let result = lifecycle::prune(&tx, limit).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    result
}

fn record(issued: i64) -> Record {
    Record {
        kind: 3,
        packet: vec![9; 16],
        expected: serde_json::json!({"scope":{"origin":"https://example.test"}}),
        issued,
        expires: issued + 100000,
        interval: None,
    }
}

async fn fixture() -> (Fixture, SessionPrincipal, Current, Selection, Record) {
    let (f, p) = prepared().await;
    f.db.batch_execute(include_str!(
        "../../../../../../deploy/compose/migrations/097_owner_android_proposals.sql"
    ))
    .await
    .unwrap();
    let now: i64 =
        f.db.query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let point = f
        .event_signer
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let c = Current {
        pin: f.pin.clone().try_into().unwrap(),
        fingerprint: [2; 32],
        version: 0,
        digest: None,
        manifest: None,
        high_water: 0,
        paired_point: point,
        paired_fingerprint: [3; 32],
        connection_epoch: 1,
        deployment_epoch: 1,
        site: "fixture".into(),
        instance: "fixture".into(),
    };
    let s = Selection {
        device: f.device,
        line: f.line,
        generation: 1,
        peer: "+12".into(),
    };
    (f, p, c, s, record(now))
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn identical_retry_preserves_deadline_and_context_is_original_session_bound() {
    let (f, p, c, s, r) = fixture().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let hash = save(&tx, &p, &s, &c, &r).await.unwrap();
    assert_eq!(save(&tx, &p, &s, &c, &r).await.unwrap(), hash);
    let stored = load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
        .await
        .unwrap();
    assert_eq!(stored.expires, r.expires);
    assert_eq!(stored.packet, r.packet);
    let renewed = Record {
        expires: r.expires + 1,
        ..r
    };
    assert!(matches!(
        save(&tx, &p, &s, &c, &renewed).await,
        Err(ConversationError::Conflict)
    ));
    assert!(
        load(&tx, &p, &s, &c, 3, &[0; 32], "https://example.test")
            .await
            .is_err()
    );
    assert!(
        load(&tx, &p, &s, &c, 3, &hash, "https://other.test")
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    let inventory = observed_inventory(&f).await.unwrap();
    assert_eq!(inventory["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(
        inventory["proposals"][0]["proposal_b64"],
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &stored.packet)
    );
    assert_eq!(
        inventory["proposals"][0]["expected_context"],
        stored.expected
    );
    assert!(
        f.db.execute(
            "UPDATE owner_android_proposals SET expires_ms=expires_ms+1",
            &[]
        )
        .await
        .is_err()
    );
    assert_eq!(observed_prune(&f, 100).await.unwrap(), 0);
    f.db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&p.session_id],
    )
    .await
    .unwrap();
    // Revocation remains the HTTP authority's responsibility; expiry cannot be
    // rewritten by the store. Account/session deletion removes pending intent.
    f.db.execute("DELETE FROM sessions WHERE id=$1", &[&p.session_id])
        .await
        .unwrap();
    assert!(
        observed_inventory(&f).await.unwrap()["proposals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    f.cleanup().await;
}

#[test]
fn record_refuses_unbounded_deadlines_and_invalid_pending_shapes() {
    let mut r = record(1);
    r.expires = 300001;
    assert!(encode_record(&r).is_ok());
    assert!(live(&r, 1).is_ok());
    assert!(live(&r, 300000).is_ok());
    assert!(live(&r, 0).is_err());
    assert!(live(&r, 300001).is_err());
    for expires in [1, 0, -1, 300002, i64::MAX] {
        r.expires = expires;
        assert!(encode_record(&r).is_err());
    }
    r = record(1);
    r.issued = i64::MIN;
    r.expires = i64::MAX;
    assert!(encode_record(&r).is_err());
    r = record(1);
    for kind in [1, 2, 6, i16::MAX] {
        r.kind = kind;
        assert!(encode_record(&r).is_err());
    }
    r.kind = 5;
    assert!(encode_record(&r).is_err());
    r.interval = Some(Uuid::nil());
    assert!(encode_record(&r).is_err());
    r.interval = Some(Uuid::new_v4());
    assert!(encode_record(&r).is_ok());
    r.kind = 4;
    assert!(encode_record(&r).is_err());
    r = record(1);
    r.packet.clear();
    assert!(encode_record(&r).is_err());
    r.packet = vec![9; 20481];
    assert!(encode_record(&r).is_err());
    r = record(1);
    for expected in [
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!({"scope":{"origin":""}}),
        serde_json::json!({"scope":{"origin":"x".repeat(513)}}),
        serde_json::json!({"scope":{"origin":"https://example.test"},"extra":"x".repeat(4096)}),
    ] {
        r.expected = expected;
        assert!(encode_record(&r).is_err());
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn retry_and_load_refuse_changed_original_session_and_current_scope() {
    let (f, mut p, mut c, mut s, r) = fixture().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let hash = save(&tx, &p, &s, &c, &r).await.unwrap();
    let session = p.session_id;
    p.session_id = Uuid::new_v4();
    assert!(matches!(
        save(&tx, &p, &s, &c, &r).await,
        Err(ConversationError::Conflict)
    ));
    assert!(
        load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
            .await
            .is_err()
    );
    p.session_id = session;
    let user = p.user_id;
    p.user_id = Uuid::new_v4();
    assert!(matches!(
        save(&tx, &p, &s, &c, &r).await,
        Err(ConversationError::Conflict)
    ));
    assert!(
        load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
            .await
            .is_err()
    );
    p.user_id = user;
    for changed in 0..11 {
        match changed {
            0 => s.device = Uuid::new_v4(),
            1 => s.line = Uuid::new_v4(),
            2 => s.generation += 1,
            3 => s.peer = "+13".into(),
            4 => c.fingerprint = [4; 32],
            5 => c.paired_fingerprint = [4; 32],
            6 => c.connection_epoch += 1,
            7 => c.deployment_epoch += 1,
            8 => c.site = "other".into(),
            9 => c.instance = "other".into(),
            10 => {
                c.version = 1;
                c.digest = Some([4; 32]);
            }
            _ => unreachable!(),
        }
        assert!(save(&tx, &p, &s, &c, &r).await.is_err());
        assert!(
            load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
                .await
                .is_err()
        );
        s.device = f.device;
        s.line = f.line;
        s.generation = 1;
        s.peer = "+12".into();
        c.fingerprint = [2; 32];
        c.paired_fingerprint = [3; 32];
        c.connection_epoch = 1;
        c.deployment_epoch = 1;
        c.site = "fixture".into();
        c.instance = "fixture".into();
        c.version = 0;
        c.digest = None;
    }
    assert_eq!(save(&tx, &p, &s, &c, &r).await.unwrap(), hash);
    tx.commit().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn immutable_update_aborts_transaction_and_preserves_original_record() {
    let (f, p, c, s, r) = fixture().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    let hash = save(&tx, &p, &s, &c, &r).await.unwrap();
    tx.commit().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let error = tx
        .execute(
            "UPDATE owner_android_proposals SET expires_ms=expires_ms+1 WHERE account_id=$1",
            &[&f.account],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::RAISE_EXCEPTION)
    );
    assert_eq!(
        tx.query_one("SELECT 1", &[]).await.unwrap_err().code(),
        Some(&tokio_postgres::error::SqlState::IN_FAILED_SQL_TRANSACTION)
    );
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let original = load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
        .await
        .unwrap();
    assert_eq!(original.issued, r.issued);
    assert_eq!(original.expires, r.expires);
    assert_eq!(original.packet, r.packet);
    tx.commit().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn expired_replacement_rollback_and_locked_prune_preserve_pending_identity() {
    let (f, p, c, s, r) = fixture().await;
    let hash: [u8; 32] = Sha256::digest(&r.packet).into();
    let encoded = encode_record(&r).unwrap();
    // Insert an already-expired synthetic storage row. No elapsed-time or
    // authenticated ceremony acceptance is inferred from this fixture.
    f.db.execute("INSERT INTO owner_android_proposals(account_id,kind,user_id,session_id,proposal_sha256,proposal,expected_context,origin,root_fingerprint,checkpoint_version,device_id,line_id,binding_generation,peer,paired_fingerprint,connection_epoch,deployment_epoch,site_id,instance_id,issued_ms,expires_ms) VALUES($1,3,$2,$3,$4,$5,$6::text::jsonb,'https://example.test',$7,0,$8,$9,1,'+12',$10,1,1,'fixture','fixture',1,2)", &[&f.account,&p.user_id,&p.session_id,&hash.as_slice(),&r.packet,&encoded,&c.fingerprint.as_slice(),&s.device,&s.line,&c.paired_fingerprint.as_slice()]).await.unwrap();
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(
        load(&tx, &p, &s, &c, 3, &hash, "https://example.test")
            .await
            .is_err()
    );
    assert_eq!(observed_prune(&f, 1).await.unwrap(), 0);
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert_eq!(save(&tx, &p, &s, &c, &r).await.unwrap(), hash);
    tx.rollback().await.unwrap();
    let retained = f.db.query_one("SELECT issued_ms,expires_ms,proposal FROM owner_android_proposals WHERE account_id=$1 AND kind=3", &[&f.account]).await.unwrap();
    assert_eq!(retained.get::<_, i64>(0), 1);
    assert_eq!(retained.get::<_, i64>(1), 2);
    assert_eq!(retained.get::<_, Vec<u8>>(2), r.packet);
    assert_eq!(observed_prune(&f, 0).await.unwrap(), 1);
    assert_eq!(observed_prune(&f, i64::MAX).await.unwrap(), 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn missing_original_session_owner_or_binding_aborts_insert_without_pending_rows() {
    let (f, mut p, c, mut s, r) = fixture().await;
    let mut db = f.connect().await;
    let session = p.session_id;
    let user = p.user_id;
    for missing in 0..3 {
        match missing {
            0 => p.session_id = Uuid::new_v4(),
            1 => p.user_id = Uuid::new_v4(),
            2 => s.generation = 2,
            _ => unreachable!(),
        }
        let tx = db.transaction().await.unwrap();
        let error = save(&tx, &p, &s, &c, &r).await.err().unwrap();
        let ConversationError::Database(error) = error else {
            panic!("expected original authority foreign key refusal");
        };
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION)
        );
        assert_eq!(
            tx.query_one("SELECT 1", &[]).await.unwrap_err().code(),
            Some(&tokio_postgres::error::SqlState::IN_FAILED_SQL_TRANSACTION)
        );
        tx.rollback().await.unwrap();
        p.session_id = session;
        p.user_id = user;
        s.generation = 1;
        assert_eq!(
            f.db.query_one("SELECT count(*) FROM owner_android_proposals", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual conversation inventory and isolated synthetic schema"]
async fn conversation_inventory_contains_account_proposals_and_refuses_schema_drift() {
    let (f, p, c, selected, r) = fixture().await;
    let mut db = f.connect().await;
    let tx = db.transaction().await.unwrap();
    save(&tx, &p, &selected, &c, &r).await.unwrap();
    tx.commit().await.unwrap();
    let expected = observed_inventory(&f).await.unwrap();
    let inventory = crate::http_owner_conversations::lifecycle::inventory(&mut db, &p, None, None)
        .await
        .unwrap();
    assert_eq!(inventory.android_proposals, expected);
    assert_eq!(
        inventory.android_proposals["proposals"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let other_account = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&other_account])
        .await
        .unwrap();
    let stranger = crate::http_owner_conversations::tests::owner_for(&f, other_account).await;
    let other =
        crate::http_owner_conversations::lifecycle::inventory(&mut db, &stranger, None, None)
            .await
            .unwrap();
    assert_eq!(
        other.android_proposals,
        serde_json::json!({"installed":true,"proposals":[]})
    );
    f.db.batch_execute("DROP INDEX owner_android_proposals_expiry")
        .await
        .unwrap();
    assert!(
        crate::http_owner_conversations::lifecycle::inventory(&mut db, &p, None, None,)
            .await
            .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; actual opt-in retention worker and synthetic storage records"]
async fn setup_retention_worker_prunes_expired_proposals_and_preserves_live_pending() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let (f, p, c, selected, r) = fixture().await;
    let encoded = encode_record(&r).unwrap();
    let hash: [u8; 32] = Sha256::digest(&r.packet).into();
    // Storage-only rows deliberately use fixed expired times. They do not
    // establish valid signed proposal issuance or phone/root provenance.
    f.db.execute("INSERT INTO owner_android_proposals(account_id,kind,user_id,session_id,proposal_sha256,proposal,expected_context,origin,root_fingerprint,checkpoint_version,device_id,line_id,binding_generation,peer,paired_fingerprint,connection_epoch,deployment_epoch,site_id,instance_id,issued_ms,expires_ms) VALUES($1,3,$2,$3,$4,$5,$6::text::jsonb,'https://example.test',$7,0,$8,$9,1,'+12',$10,1,1,'fixture','fixture',1,2)", &[&f.account,&p.user_id,&p.session_id,&hash.as_slice(),&r.packet,&encoded,&c.fingerprint.as_slice(),&selected.device,&selected.line,&c.paired_fingerprint.as_slice()]).await.unwrap();
    f.db.execute("INSERT INTO owner_android_proposals SELECT account_id,4,user_id,session_id,proposal_sha256,proposal,expected_context,origin,root_fingerprint,1,$2,device_id,line_id,binding_generation,peer,paired_fingerprint,connection_epoch,deployment_epoch,site_id,instance_id,NULL,$3,$4 FROM owner_android_proposals WHERE account_id=$1 AND kind=3", &[&f.account,&vec![2u8;32],&r.issued,&r.expires]).await.unwrap();
    let separator = if f.url.contains('?') { '&' } else { '?' };
    let url = format!("{}{separator}options=-csearch_path%3D{}", f.url, f.schema);
    let draining = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(tokio::sync::Notify::new());
    let worker = tokio::spawn(
        crate::http_owner_conversations::sealed_line_setup::Retention::new(url)
            .run(draining.clone(), notify.clone()),
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut pruned = false;
    while tokio::time::Instant::now() < deadline {
        let kinds =
            f.db.query(
                "SELECT kind FROM owner_android_proposals WHERE account_id=$1 ORDER BY kind",
                &[&f.account],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<_, i16>(0))
            .collect::<Vec<_>>();
        if kinds == vec![4] {
            pruned = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    draining.store(true, Ordering::Release);
    notify.notify_waiters();
    tokio::time::timeout(std::time::Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        pruned,
        "the actual opted-in worker must prune expired pending intent"
    );
    assert_eq!(
        observed_inventory(&f).await.unwrap()["proposals"][0]["kind"],
        4
    );
    f.cleanup().await;
}
