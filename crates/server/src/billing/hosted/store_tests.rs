// SPDX-License-Identifier: AGPL-3.0-only
//! Isolated PostgreSQL acceptance. No provider calls or production migrations.
use super::{
    Refusal,
    namespace::{Gate, Marker, Mode, Namespace, ProviderIdentity, Scope},
    policy::{FailureEvidence, Observation, Phase, Plan, Purpose, SubscriptionStatus},
    store::{self, StoreError},
};
use tokio_postgres::Client;
use uuid::Uuid;

struct Fixture {
    db: Client,
    url: String,
    schema: String,
    gate: Gate,
    scope: Scope,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
            .expect("ZT_AUTH_TEST_DATABASE_URL is required for isolated PostgreSQL tests");
        let schema = format!("hosted_fixture_{}", Uuid::new_v4().simple());
        let db = Self::connection(&url).await;
        db.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
        db.batch_execute(include_str!("store_fixture.sql"))
            .await
            .unwrap();
        let namespace = Namespace::new([1; 16], Mode::Test, "acct_fixture").unwrap();
        let marker = Marker {
            namespace: namespace.clone(),
            policy_revision: 1,
            enabled: true,
        };
        let gate = Gate::verify(
            true,
            &namespace,
            1,
            &marker,
            &ProviderIdentity {
                mode: Mode::Test,
                provider_account: "acct_fixture".into(),
            },
        )
        .unwrap();
        let scope = Scope::new(namespace, [2; 16], "cus_fixture", "sub_fixture").unwrap();
        db.execute(
            "INSERT INTO hosted_billing_namespaces VALUES ($1,'test','acct_fixture',1,true,true)",
            &[&Uuid::from_bytes(scope.namespace().id())],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO hosted_billing_projections VALUES ($1,$2,'cus_fixture','sub_fixture',1,0,0,0,false,false,'pending',0,0,0,0,NULL,NULL)",
            &[&Uuid::from_bytes(scope.namespace().id()), &Uuid::from_bytes(scope.owner())]).await.unwrap();
        Self {
            db,
            url,
            schema,
            gate,
            scope,
        }
    }

    async fn connection(url: &str) -> Client {
        let (db, connection) = zrotext_postgres_connection::connect(url).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        db
    }

    async fn connect(&self) -> Client {
        let db = Self::connection(&self.url).await;
        db.batch_execute(&format!("SET search_path TO {}", self.schema))
            .await
            .unwrap();
        db
    }

    async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }

    fn plan(&self) -> Plan {
        Plan::new("price_fixture", 10, 2, 60).unwrap()
    }

    async fn active(&mut self) -> super::policy::Projection {
        let plan = self.plan();
        let tx = self.db.transaction().await.unwrap();
        let claim = store::claim_read(&tx, &self.gate, &self.scope)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let tx = self.db.transaction().await.unwrap();
        let now: i64 = tx
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let observed = Observation {
            scope: self.scope.clone(),
            policy_revision: 1,
            generation: claim.generation(),
            complete: true,
            nonterminal_subscriptions: 1,
            status: SubscriptionStatus::Active,
            price: "price_fixture".into(),
            invoice: "in_fixture".into(),
            period_start: now - 1,
            period_end: now + 3600,
            revalidate_at: now + 300,
            failure: None,
        };
        let projected =
            store::commit_observation(&tx, &self.gate, &self.scope, &claim, &observed, &plan)
                .await
                .unwrap();
        tx.commit().await.unwrap();
        projected
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn persisted_projection_survives_new_connection_and_admits_exact_caps() {
    let mut f = Fixture::new().await;
    let projected = f.active().await;
    let mut restarted = f.connect().await;
    let tx = restarted.transaction().await.unwrap();
    let loaded = store::load_locked(&tx, &f.gate, &f.scope).await.unwrap();
    assert_eq!(loaded.projection.unwrap(), projected);
    store::admit_locked(
        &tx,
        &f.gate,
        &f.scope,
        Purpose::Outbound {
            units: 1,
            consumed: 9,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        store::admit_locked(
            &tx,
            &f.gate,
            &f.scope,
            Purpose::Outbound {
                units: 1,
                consumed: 10
            }
        )
        .await,
        Err(StoreError::Refused(Refusal::QuotaExceeded))
    ));
    assert!(matches!(
        store::admit_locked(
            &tx,
            &f.gate,
            &f.scope,
            Purpose::EnrollDevice { active_devices: 2 }
        )
        .await,
        Err(StoreError::Refused(Refusal::DeviceCapExceeded))
    ));
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn namespace_owner_customer_and_subscription_isolation_refuse_foreign_state() {
    let mut f = Fixture::new().await;
    f.active().await;
    let tx = f.db.transaction().await.unwrap();
    let foreign_owner = Scope::new(
        f.scope.namespace().clone(),
        [3; 16],
        "cus_fixture",
        "sub_fixture",
    )
    .unwrap();
    assert!(matches!(
        store::load_locked(&tx, &f.gate, &foreign_owner).await,
        Err(StoreError::Refused(Refusal::Pending))
    ));
    let foreign_customer = Scope::new(
        f.scope.namespace().clone(),
        f.scope.owner(),
        "cus_other",
        "sub_fixture",
    )
    .unwrap();
    assert!(matches!(
        store::load_locked(&tx, &f.gate, &foreign_customer).await,
        Err(StoreError::Refused(Refusal::TenantMismatch))
    ));
    let live = Namespace::new(f.scope.namespace().id(), Mode::Live, "acct_fixture").unwrap();
    let foreign_mode = Scope::new(live, f.scope.owner(), "cus_fixture", "sub_fixture").unwrap();
    assert!(matches!(
        store::load_locked(&tx, &f.gate, &foreign_mode).await,
        Err(StoreError::Refused(Refusal::NamespaceMismatch))
    ));
    tx.rollback().await.unwrap();
    // A TEST row cannot be relabeled LIVE beneath persisted projections.
    assert!(
        f.db.execute("UPDATE hosted_billing_namespaces SET mode='live'", &[])
            .await
            .is_err()
    );
    assert!(
        f.db.execute(
            "UPDATE hosted_billing_namespaces SET provider_account='acct_other'",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        f.db.execute(
            "UPDATE hosted_billing_projections SET customer_id='cus_other'",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        f.db.execute(
            "UPDATE hosted_billing_projections SET subscription_id='sub_other'",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        f.db.execute(
            "UPDATE hosted_billing_projections SET account_id=$1",
            &[&Uuid::from_bytes([3; 16])]
        )
        .await
        .is_err()
    );
    let live_id = Uuid::from_bytes([4; 16]);
    f.db.execute(
        "INSERT INTO hosted_billing_namespaces VALUES ($1,'live','acct_other',1,true,true)",
        &[&live_id],
    )
    .await
    .unwrap();
    assert!(
        f.db.execute(
            "UPDATE hosted_billing_projections SET namespace_id=$1",
            &[&live_id]
        )
        .await
        .is_err()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn fresh_read_immediately_invalidates_admission_and_obsolete_claim_cannot_commit() {
    let mut f = Fixture::new().await;
    f.active().await;
    let plan = f.plan();
    let tx = f.db.transaction().await.unwrap();
    let old = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    assert!(matches!(
        store::admit_locked(
            &tx,
            &f.gate,
            &f.scope,
            Purpose::Outbound {
                units: 1,
                consumed: 0
            }
        )
        .await,
        Err(StoreError::Refused(Refusal::Pending))
    ));
    let new = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    assert!(new.generation() > old.generation());
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let observed = Observation {
        scope: f.scope.clone(),
        policy_revision: 1,
        generation: old.generation(),
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::Active,
        price: "price_fixture".into(),
        invoice: "in_fixture".into(),
        period_start: now - 1,
        period_end: now + 1000,
        revalidate_at: now + 100,
        failure: None,
    };
    assert!(matches!(
        store::commit_observation(&tx, &f.gate, &f.scope, &old, &observed, &plan).await,
        Err(StoreError::Refused(Refusal::StaleObservation))
    ));
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn local_holds_operator_pause_and_unfenced_binary_refuse_cached_authority() {
    let mut f = Fixture::new().await;
    f.active().await;
    f.db.execute(
        "UPDATE hosted_billing_projections SET payment_hold=true",
        &[],
    )
    .await
    .unwrap();
    let tx = f.db.transaction().await.unwrap();
    assert!(matches!(
        store::admit_locked(
            &tx,
            &f.gate,
            &f.scope,
            Purpose::Outbound {
                units: 1,
                consumed: 0
            }
        )
        .await,
        Err(StoreError::Refused(Refusal::Restricted))
    ));
    tx.rollback().await.unwrap();
    f.db.execute(
        "UPDATE hosted_billing_projections SET payment_hold=false",
        &[],
    )
    .await
    .unwrap();
    let tx = f.db.transaction().await.unwrap();
    assert!(
        matches!(
            store::admit_locked(
                &tx,
                &f.gate,
                &f.scope,
                Purpose::Outbound {
                    units: 1,
                    consumed: 0
                }
            )
            .await,
            Err(StoreError::Refused(Refusal::Pending))
        ),
        "clearing a hold requires a fresh authoritative provider read"
    );
    tx.rollback().await.unwrap();
    f.db.execute("UPDATE hosted_billing_namespaces SET enabled=false", &[])
        .await
        .unwrap();
    let tx = f.db.transaction().await.unwrap();
    assert!(matches!(
        store::load_locked(&tx, &f.gate, &f.scope).await,
        Err(StoreError::Refused(Refusal::Disabled))
    ));
    tx.rollback().await.unwrap();
    f.db.execute(
        "UPDATE hosted_billing_namespaces SET enabled=true, old_binary_fenced=false",
        &[],
    )
    .await
    .unwrap();
    let tx = f.db.transaction().await.unwrap();
    assert!(matches!(
        store::load_locked(&tx, &f.gate, &f.scope).await,
        Err(StoreError::OldBinaryNotFenced)
    ));
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn caller_rollback_discards_read_claim_and_projection_write() {
    let mut f = Fixture::new().await;
    let plan = f.plan();
    let tx = f.db.transaction().await.unwrap();
    let first = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    tx.rollback().await.unwrap();
    let tx = f.db.transaction().await.unwrap();
    let retried = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    assert_eq!(first.generation(), retried.generation());
    assert_eq!(first.sequence(), retried.sequence());
    // Rollback can reuse counters, but an earlier read token must not become
    // authoritative again merely because the next claim has the same number.
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let observed = Observation {
        scope: f.scope.clone(),
        policy_revision: 1,
        generation: first.generation(),
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::Active,
        price: "price_fixture".into(),
        invoice: "in_fixture".into(),
        period_start: now - 1,
        period_end: now + 1000,
        revalidate_at: now + 100,
        failure: None,
    };
    assert!(matches!(
        store::commit_observation(&tx, &f.gate, &f.scope, &first, &observed, &plan).await,
        Err(StoreError::Refused(Refusal::StaleObservation))
    ));
    store::commit_observation(&tx, &f.gate, &f.scope, &retried, &observed, &plan)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn persisted_first_failure_survives_hold_clear_new_invoice_and_reconnect() {
    let mut f = Fixture::new().await;
    let plan = f.plan();
    f.db.execute(
        "UPDATE hosted_billing_projections SET payment_hold=true",
        &[],
    )
    .await
    .unwrap();
    let tx = f.db.transaction().await.unwrap();
    let held_claim = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    tx.commit().await.unwrap();
    let tx = f.db.transaction().await.unwrap();
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let first_failure = now - 10;
    let mut observed = Observation {
        scope: f.scope.clone(),
        policy_revision: 1,
        generation: held_claim.generation(),
        complete: true,
        nonterminal_subscriptions: 1,
        status: SubscriptionStatus::PastDue,
        price: "price_fixture".into(),
        invoice: "in_fixture".into(),
        period_start: now - 100,
        period_end: now + 1000,
        revalidate_at: now + 100,
        failure: Some(FailureEvidence {
            scope: f.scope.clone(),
            invoice: "in_fixture".into(),
            occurred_at: first_failure,
        }),
    };
    let held = store::commit_observation(&tx, &f.gate, &f.scope, &held_claim, &observed, &plan)
        .await
        .unwrap();
    assert_eq!(held.phase(), Phase::Restricted);
    assert_eq!(held.outbound_limit(), 0);
    assert_eq!(held.first_failure_at(), Some(first_failure));
    tx.commit().await.unwrap();
    f.db.execute(
        "UPDATE hosted_billing_projections SET payment_hold=false",
        &[],
    )
    .await
    .unwrap();
    let tx = f.db.transaction().await.unwrap();
    let recovery_claim = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    tx.commit().await.unwrap();
    observed.generation = recovery_claim.generation();
    observed.invoice = "in_next".into();
    observed.failure = Some(FailureEvidence {
        scope: f.scope.clone(),
        invoice: "in_next".into(),
        occurred_at: now - 1,
    });
    let tx = f.db.transaction().await.unwrap();
    let recovered =
        store::commit_observation(&tx, &f.gate, &f.scope, &recovery_claim, &observed, &plan)
            .await
            .unwrap();
    assert_eq!(recovered.phase(), Phase::Grace);
    assert_eq!(recovered.valid_until(), first_failure + 60);
    tx.commit().await.unwrap();
    let mut restarted = f.connect().await;
    let tx = restarted.transaction().await.unwrap();
    assert_eq!(
        store::load_locked(&tx, &f.gate, &f.scope)
            .await
            .unwrap()
            .projection
            .unwrap(),
        recovered
    );
    tx.rollback().await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated hosted billing schema"]
async fn concurrent_read_claims_serialize_under_the_same_tenant_lock() {
    let mut f = Fixture::new().await;
    let mut competing = f.connect().await;
    let gate = f.gate.clone();
    let scope = f.scope.clone();
    let tx = f.db.transaction().await.unwrap();
    let first = store::claim_read(&tx, &f.gate, &f.scope).await.unwrap();
    let mut task = tokio::spawn(async move {
        let tx = competing.transaction().await.unwrap();
        let claim = store::claim_read(&tx, &gate, &scope).await.unwrap();
        tx.commit().await.unwrap();
        claim
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut task)
            .await
            .is_err(),
        "a second read cannot advance the locked tenant before the first transaction commits"
    );
    tx.commit().await.unwrap();
    let second = task.await.unwrap();
    assert_eq!(second.generation(), first.generation() + 1);
    assert_eq!(second.sequence(), first.sequence() + 1);
    f.cleanup().await;
}
