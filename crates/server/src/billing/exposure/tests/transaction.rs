// SPDX-License-Identifier: AGPL-3.0-only
//! Sequential SQL observations of the private TEST preparation boundary.
//! These synthetic approvals are not provider or plaintext disclosure grants.
use super::*;
use tokio_postgres::GenericClient;

type ReservationRow = (
    Uuid,
    Uuid,
    i64,
    Vec<u8>,
    Uuid,
    i64,
    String,
    Option<Uuid>,
    Option<i64>,
);
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    deployment: (i64, i64),
    scopes: Vec<(String, Uuid, i64, i64, i64)>,
    reservations: Vec<ReservationRow>,
    bindings: Vec<(Uuid, String, Uuid, i64)>,
}
async fn snapshot(db: &(impl GenericClient + Sync), f: &Fixture) -> Snapshot {
    let account = f.action.account_id;
    let deployment = db
        .query_one(
            "SELECT outstanding_units,finalized_units FROM exposure_deployment_budgets WHERE id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap();
    let scopes = db.query(
        "SELECT scope_kind,scope_id,version,outstanding_units,finalized_units FROM exposure_scope_budgets WHERE account_id=$1 ORDER BY scope_kind,scope_id,version",
        &[&account],
    ).await.unwrap().into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3),r.get(4))).collect();
    let reservations = db.query(
        "SELECT id,action_id,revision,binding_digest,route_policy_id,maximum_units,state,lease_id,lease_until_ms FROM exposure_reservations WHERE account_id=$1 ORDER BY id",
        &[&account],
    ).await.unwrap().into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3),r.get(4),r.get(5),r.get(6),r.get(7),r.get(8))).collect();
    let bindings = db.query(
        "SELECT reservation_id,scope_kind,scope_id,version FROM exposure_reservation_scopes WHERE account_id=$1 ORDER BY reservation_id,scope_kind,scope_id,version",
        &[&account],
    ).await.unwrap().into_iter().map(|r| (r.get(0),r.get(1),r.get(2),r.get(3))).collect();
    Snapshot {
        deployment: (deployment.get(0), deployment.get(1)),
        scopes,
        reservations,
        bindings,
    }
}
fn assert_empty(s: &Snapshot) {
    assert_eq!(s.deployment, (0, 0));
    assert_eq!(s.scopes.len(), 6);
    assert!(s.scopes.iter().all(|r| r.3 == 0 && r.4 == 0));
    assert!(s.reservations.is_empty());
    assert!(s.bindings.is_empty());
}
fn assert_reserved(s: &Snapshot, f: &Fixture, id: Uuid) {
    assert_eq!(s.deployment, (1, 0));
    assert_eq!(s.scopes.len(), 6);
    assert!(s.scopes.iter().all(|r| r.3 == 1 && r.4 == 0));
    // Independently retained fixture keys, not helper-returned scope metadata.
    let mut keys = vec![
        (
            "campaign".to_owned(),
            Uuid::parse_str(&f.case.descriptor.routine_id).unwrap(),
            1,
        ),
        ("device".to_owned(), f.case.base.f.device, 1),
        ("route".to_owned(), f.route, 1),
        ("tenant".to_owned(), f.action.account_id, 1),
        ("turn".to_owned(), f.action.action_id, 1),
        ("workflow".to_owned(), f.case.base.h.context, 1),
    ];
    keys.sort();
    assert_eq!(
        s.scopes
            .iter()
            .map(|r| (r.0.clone(), r.1, r.2))
            .collect::<Vec<_>>(),
        keys
    );
    assert_eq!(
        s.bindings,
        keys.into_iter()
            .map(|(kind, key, version)| (id, kind, key, version))
            .collect::<Vec<_>>()
    );
    assert_eq!(s.reservations.len(), 1);
    let r = &s.reservations[0];
    assert_eq!((r.0, r.1, r.2), (id, f.action.action_id, f.action.revision));
    assert_eq!(r.3.as_slice(), f.action.binding_digest.as_slice());
    assert_eq!((r.4, r.5), (f.route, 1));
}
async fn assert_intent(
    tx: &Transaction<'_>,
    f: &Fixture,
    id: Uuid,
    intent: &TestIntent,
    before_ms: i64,
) -> Snapshot {
    let s = snapshot(tx, f).await;
    assert_reserved(&s, f, id);
    let r = &s.reservations[0];
    assert_eq!(r.6, "executing");
    assert_eq!(intent.account, f.action.account_id);
    assert_eq!(intent.reservation, id);
    assert!(!intent.nonce.is_nil());
    assert_eq!(r.7, Some(intent.nonce));
    let until = r.8.unwrap();
    let after_ms = store::now(tx).await.unwrap();
    assert!(until > before_ms);
    assert!(until <= after_ms.checked_add(15_000).unwrap());
    // Read the original immutable authority and period ceilings directly.
    let action_end: i64 = tx.query_one(
        "SELECT expires_at_ms FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4",
        &[&f.action.account_id,&f.action.action_id,&f.action.revision,&&f.action.binding_digest[..]],
    ).await.unwrap().get(0);
    let deployment_end: i64 = tx
        .query_one(
            "SELECT period_end_ms FROM exposure_deployment_budgets WHERE id=$1",
            &[&f.deployment],
        )
        .await
        .unwrap()
        .get(0);
    let scope_end: i64 = tx.query_one(
        "SELECT min(b.period_end_ms) FROM exposure_reservation_scopes s JOIN exposure_scope_budgets b USING(account_id,scope_kind,scope_id,version) WHERE s.account_id=$1 AND s.reservation_id=$2",
        &[&f.action.account_id,&id],
    ).await.unwrap().get(0);
    assert!(until <= action_end && until <= deployment_end && until <= scope_end);
    s
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn borrowed_reservation_and_intent_rollback_without_publication() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    let mut db = f.case.base.f.connect().await;
    let before = snapshot(&db, &f).await;
    assert_empty(&before);
    let tx = db.transaction().await.unwrap();
    let reserved = engine
        .reserve_in_tx(&tx, &f.case.base.owner, f.action, f.route, id)
        .await
        .unwrap();
    assert_eq!(reserved.id, id);
    assert!(reserved.created);
    let prepared = snapshot(&tx, &f).await;
    assert_reserved(&prepared, &f, id);
    assert_eq!(prepared.reservations[0].6, "reserved");
    assert_eq!(
        (prepared.reservations[0].7, prepared.reservations[0].8),
        (None, None)
    );
    let before_ms = store::now(&tx).await.unwrap();
    let intent = engine
        .first_test_intent_in_tx(&tx, &f.case.base.owner, f.action, id)
        .await
        .unwrap();
    assert_intent(&tx, &f, id, &intent, before_ms).await;
    tx.rollback().await.unwrap();
    // The rolled-back intent is never used for settlement or returned.
    assert_eq!(snapshot(&db, &f).await, before);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn borrowed_reservation_and_intent_commit_once() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    // Establish this observer before taking any authority or budget locks.
    let observer = f.case.base.f.connect().await;
    let mut db = f.case.base.f.connect().await;
    let before = snapshot(&observer, &f).await;
    assert_empty(&before);
    let tx = db.transaction().await.unwrap();
    engine
        .reserve_in_tx(&tx, &f.case.base.owner, f.action, f.route, id)
        .await
        .unwrap();
    let before_ms = store::now(&tx).await.unwrap();
    let intent = engine
        .first_test_intent_in_tx(&tx, &f.case.base.owner, f.action, id)
        .await
        .unwrap();
    let prepared = assert_intent(&tx, &f, id, &intent, before_ms).await;
    // Plain MVCC reads, no new lock/write/approval or concurrent operation.
    assert_eq!(snapshot(&observer, &f).await, before);
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&observer, &f).await, prepared);
    assert_eq!(snapshot(&db, &f).await, prepared);
    // No synthetic settlement or public intent return is attempted.
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn failed_first_intent_rolls_back_prepared_reservation() {
    let f = Fixture::new(2).await;
    // Existing approval API produces a distinct approved synthetic action.
    // It must complete before this transaction locks the account/actions.
    let other = f.another_action().await;
    assert_ne!(other.action_id, f.action.action_id);
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    let mut db = f.case.base.f.connect().await;
    let before = snapshot(&db, &f).await;
    assert_eq!(before.deployment, (0, 0));
    assert!(before.reservations.is_empty() && before.bindings.is_empty());
    assert!(before.scopes.iter().all(|r| r.3 == 0 && r.4 == 0));
    let tx = db.transaction().await.unwrap();
    engine
        .reserve_in_tx(&tx, &f.case.base.owner, f.action, f.route, id)
        .await
        .unwrap();
    assert_eq!(snapshot(&tx, &f).await.reservations.len(), 1);
    assert!(matches!(
        engine
            .first_test_intent_in_tx(&tx, &f.case.base.owner, other, id)
            .await,
        Err(Error::Conflict)
    ));
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&db, &f).await, before);
    f.case.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
async fn borrowed_exact_replay_preserves_original_reservation() {
    let f = Fixture::new(2).await;
    let engine = TestExposure::synthetic_candidate();
    let id = Uuid::new_v4();
    let first = f.reserve(&engine, id).await.unwrap();
    assert_eq!(first.id, id);
    assert!(first.created);
    let mut db = f.case.base.f.connect().await;
    let before = snapshot(&db, &f).await;
    assert_reserved(&before, &f, id);
    assert_eq!(before.reservations[0].6, "reserved");
    assert_eq!(
        (before.reservations[0].7, before.reservations[0].8),
        (None, None)
    );
    let tx = db.transaction().await.unwrap();
    let replay = engine
        .reserve_in_tx(&tx, &f.case.base.owner, f.action, f.route, id)
        .await
        .unwrap();
    assert_eq!(
        (replay.id, replay.maximum_units, replay.state.as_str()),
        (id, 1, "reserved")
    );
    assert!(!replay.created);
    assert_eq!(snapshot(&tx, &f).await, before);
    tx.rollback().await.unwrap();
    assert_eq!(snapshot(&db, &f).await, before);
    f.case.cleanup().await;
}
