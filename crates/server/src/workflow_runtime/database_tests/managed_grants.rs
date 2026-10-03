// SPDX-License-Identifier: AGPL-3.0-only
//! Real PostgreSQL/owner/archive/MFA fixtures; no production reader/policy issuer.
use super::*;
use crate::managed_ai::{
    self, GrantRequest as ManagedRequest, ManagedGrants, OwnerCeremony, PolicyIdentity, Selection,
    SourceKind,
};
use serde_json::json;

const PROPOSAL: &str =
    include_str!("../../../../../deploy/compose/migration-candidates/managed_reader_grants.sql");
struct ManagedCase {
    case: Case,
    service: ManagedGrants,
    request: ManagedRequest,
}
impl ManagedCase {
    async fn new() -> Self {
        Self::with_lifetime(None).await
    }
    async fn with_lifetime(lifetime: Option<i64>) -> Self {
        let case = Case::for_customer_routine(None).await;
        case.f.db.batch_execute(PROPOSAL).await.unwrap();
        let expires = if let Some(lifetime) = lifetime {
            let now: i64 = case
                .f
                .db
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            (now + lifetime).min(case.header.expires_ms)
        } else {
            case.header.expires_ms
        };
        let reader = Uuid::new_v4();
        let policy = Uuid::new_v4();
        let digest: [u8; 32] = Sha256::digest(policy.as_bytes()).into();
        let point = case.reader_key.verifying_key().to_sec1_point(false);
        let key_id = crate::sealed_manifest::key_id(3, point.as_bytes());
        case.f.db.execute("INSERT INTO managed_reader_keys(account_id,id,generation,key_id,key_point,expires_ms) VALUES($1,$2,1,$3,$4,$5)", &[&case.f.account,&reader,&key_id.as_slice(),&point.as_bytes(),&expires]).await.unwrap();
        case.f.db.execute("INSERT INTO managed_reader_policies(account_id,id,version,digest,reader_id,reader_generation,provider_id,provider_version,provider_digest,budget_id,budget_version,budget_digest,expires_ms,max_calls,max_input_bytes,max_cost_microunits) VALUES($1,$2,1,$3,$4,1,$5,1,$3,$6,1,$3,$7,8,65536,1000000)", &[&case.f.account,&policy,&digest.as_slice(),&reader,&Uuid::new_v4(),&Uuid::new_v4(),&expires]).await.unwrap();
        case.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','grant','manual_entry',clock_timestamp(),$4)", &[&Uuid::new_v4(),&case.f.account,&case.request.contact,&case.owner.user_id]).await.unwrap();
        let bytes: Vec<u8> = case.f.db.query_one("SELECT envelope FROM workflow_context_versions WHERE account_id=$1 AND context_id=$2 AND revision=1", &[&case.f.account,&case.header.context]).await.unwrap().get(0);
        let request = ManagedRequest {
            policy: PolicyIdentity {
                id: policy,
                version: 1,
                digest,
                reader,
                reader_generation: 1,
            },
            contact: case.request.contact,
            purpose: Purpose::Operational,
            instruction_digest: Sha256::digest(Uuid::new_v4().as_bytes()).into(),
            expires_ms: case.request.expires_ms.min(expires),
            max_calls: 4,
            max_input_bytes: 32768,
            max_cost_microunits: 500000,
            selections: vec![Selection {
                kind: SourceKind::WorkflowContextV1,
                id: case.header.context,
                version: 1,
                digest: Sha256::digest(bytes).into(),
            }],
        };
        Self {
            case,
            service: ManagedGrants::synthetic_candidate(),
            request,
        }
    }
    async fn issue(&self) -> Result<Uuid, managed_ai::Error> {
        self.service
            .create(
                &mut self.case.f.connect().await,
                &self.ceremony(),
                &self.request,
            )
            .await
    }
    fn ceremony(&self) -> OwnerCeremony<'_> {
        OwnerCeremony {
            owner: &self.case.owner,
            hasher: &self.case.hasher,
            cipher: &self.case.cipher,
            password: self.case.password(),
            factor: &self.case.factor,
        }
    }
    async fn count(&self, table: &str) -> i64 {
        self.case
            .f
            .db
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&self.case.f.account],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn cleanup(self) {
        self.case.f.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_default_constructor_and_absent_proposal_are_unavailable() {
    let mut c = ManagedCase::new().await;
    c.service = ManagedGrants::default();
    assert!(matches!(
        c.issue().await,
        Err(managed_ai::Error::Unavailable)
    ));
    assert_eq!(c.count("managed_reader_grants").await, 0);
    c.cleanup().await;
    let mut case = Case::new().await;
    let tx = case.f.db.transaction().await.unwrap();
    assert!(!managed_ai::lifecycle::installed(&tx).await.unwrap());
    tx.rollback().await.unwrap();
    let export =
        managed_ai::lifecycle::export(&mut case.f.connect().await, &case.owner, Default::default())
            .await
            .unwrap();
    assert!(
        serde_json::to_value(export).unwrap()["grants"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_bind_exact_source_policy_and_immutable_audit() {
    let c = ManagedCase::new().await;
    let id = c.issue().await.unwrap();
    assert_eq!(c.count("managed_reader_events").await, 1);
    for table in [
        "managed_reader_events",
        "managed_reader_selections",
        "managed_reader_grant_versions",
        "managed_reader_policies",
    ] {
        let error = c
            .case
            .f
            .db
            .execute(
                &format!("UPDATE {table} SET account_id=account_id WHERE account_id=$1"),
                &[&c.case.f.account],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code().unwrap().code(), "23514", "{table}");
    }
    let wrong = Uuid::new_v4();
    let error=c.case.f.db.execute("INSERT INTO managed_reader_selections(account_id,id,grant_id,grant_version,kind,source_id,source_version,digest) VALUES($1,$2,$3,1,'workflow_context_v1',$4,1,$5)", &[&wrong,&Uuid::new_v4(),&id,&Uuid::new_v4(),&c.request.selections[0].digest.as_slice()]).await.unwrap_err();
    assert_eq!(error.code().unwrap().code(), "23503");
    let export = managed_ai::lifecycle::export(
        &mut c.case.f.connect().await,
        &c.case.owner,
        Default::default(),
    )
    .await
    .unwrap();
    let export = serde_json::to_value(export).unwrap();
    assert_eq!(export["grants"]["items"][0]["id"], id.to_string());
    assert_eq!(export["selections"]["items"][0]["source_version"], 1);
    assert_eq!(
        export["versions"]["items"][0]["binding"],
        serde_json::to_value(&c.request).unwrap()
    );
    // Exact owner erasure plan works child-first and transaction rollback keeps
    // every grant/version/event intact. The privileged role can DELETE.
    let mut db = c.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &c.case.owner)
        .await
        .unwrap();
    for &(table, sql) in crate::http_owner_erasure::DELETE_PLAN {
        if managed_ai::lifecycle::TABLES.contains(&table) {
            assert_eq!(
                tx.execute(sql, &[&c.case.f.account]).await.unwrap(),
                1,
                "{table}"
            );
        }
    }
    tx.rollback().await.unwrap();
    assert_eq!(c.count("managed_reader_grants").await, 1);
    assert_eq!(c.count("managed_reader_events").await, 1);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_reject_changed_head_digest_purpose_and_missing_ceremony() {
    let mut c = ManagedCase::new().await;
    let original = c.request.clone();
    c.request.selections[0].digest = Sha256::digest(Uuid::new_v4().as_bytes()).into();
    assert!(c.issue().await.is_err());
    c.request = original.clone();
    c.request.selections[0].version = 2;
    assert!(c.issue().await.is_err());
    c.request = original.clone();
    c.request.purpose = Purpose::Marketing;
    assert!(c.issue().await.is_err());
    c.request = original.clone();
    c.request.policy.reader_generation = 2;
    assert!(c.issue().await.is_err());
    c.request = original;
    let good = c.case.factor.clone();
    let verified_before: i64 = c
        .case
        .f
        .db
        .query_one(
            "SELECT last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&c.case.f.account],
        )
        .await
        .unwrap()
        .get(0);
    let failures_before = auth::abuse_limits::failures_in_window(
        &c.case.f.db,
        &c.case.hasher,
        auth::abuse_limits::Limit::MfaStepUp,
        &c.case.owner.user_id.to_string(),
    )
    .await
    .unwrap();
    c.case.factor = "invalid-factor".into();
    assert!(c.issue().await.is_err());
    assert_eq!(c.count("managed_reader_grants").await, 0);
    assert_eq!(c.count("managed_reader_grant_versions").await, 0);
    assert_eq!(c.count("managed_reader_events").await, 0);
    let failures_after = auth::abuse_limits::failures_in_window(
        &c.case.f.db,
        &c.case.hasher,
        auth::abuse_limits::Limit::MfaStepUp,
        &c.case.owner.user_id.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(failures_after, failures_before + 1);
    let verified_after: i64 = c
        .case
        .f
        .db
        .query_one(
            "SELECT last_verified_ms FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&c.case.f.account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        verified_after, verified_before,
        "bad factor must not persist archive high-water changes"
    );
    c.case.factor = good;
    c.issue().await.unwrap();
    assert!(
        c.issue().await.is_err(),
        "MFA cannot be replayed for another grant"
    );
    assert_eq!(c.count("managed_reader_grants").await, 1);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_reduce_after_source_purge_key_revocation_and_expiry() {
    let c = ManagedCase::new().await;
    let id = c.issue().await.unwrap();
    c.case.f.db.execute("UPDATE workflow_context_versions SET envelope=NULL WHERE account_id=$1 AND context_id=$2", &[&c.case.f.account,&c.case.header.context]).await.unwrap();
    c.case.f.db.execute("UPDATE workflow_contexts SET purged_at=clock_timestamp() WHERE account_id=$1 AND id=$2", &[&c.case.f.account,&c.case.header.context]).await.unwrap();
    c.case
        .f
        .db
        .execute(
            "UPDATE managed_reader_keys SET revoked_ms=1 WHERE account_id=$1 AND id=$2",
            &[&c.case.f.account, &c.request.policy.reader],
        )
        .await
        .unwrap();
    let mut narrow = c.request.clone();
    narrow.expires_ms = 1;
    narrow.max_calls = 0;
    narrow.selections.clear();
    assert_eq!(
        c.service
            .narrow(&mut c.case.f.connect().await, &c.case.owner, id, 1, &narrow)
            .await
            .unwrap(),
        2
    );
    c.service
        .revoke(&mut c.case.f.connect().await, &c.case.owner, id)
        .await
        .unwrap();
    c.service
        .revoke(&mut c.case.f.connect().await, &c.case.owner, id)
        .await
        .unwrap();
    assert_eq!(c.count("managed_reader_events").await, 3);
    assert!(
        c.service
            .narrow(&mut c.case.f.connect().await, &c.case.owner, id, 2, &narrow)
            .await
            .is_err()
    );
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_narrow_cannot_replace_identity_or_exceed_old_limits() {
    let c = ManagedCase::new().await;
    let id = c.issue().await.unwrap();
    for mut changed in [
        c.request.clone(),
        c.request.clone(),
        c.request.clone(),
        c.request.clone(),
        c.request.clone(),
    ]
    .into_iter()
    .enumerate()
    {
        match changed.0 {
            0 => changed.1.instruction_digest = Sha256::digest(Uuid::new_v4().as_bytes()).into(),
            1 => changed.1.policy.id = Uuid::new_v4(),
            2 => changed.1.selections[0].version += 1,
            3 => changed.1.max_calls += 1,
            _ => changed.1.expires_ms += 1,
        }
        assert!(
            c.service
                .narrow(
                    &mut c.case.f.connect().await,
                    &c.case.owner,
                    id,
                    1,
                    &changed.1
                )
                .await
                .is_err()
        );
    }
    assert_eq!(c.count("managed_reader_grant_versions").await, 1);
    c.case
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&c.case.owner.session_id],
        )
        .await
        .unwrap();
    assert!(
        c.service
            .revoke(&mut c.case.f.connect().await, &c.case.owner, id)
            .await
            .is_err()
    );
    assert_eq!(c.count("managed_reader_events").await, 1);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_new_head_or_instruction_identity_requires_fresh_owner_mfa() {
    let mut c = ManagedCase::new().await;
    let id = c.issue().await.unwrap();
    let mut header = c.case.header.clone();
    header.revision = 2;
    let bytes:Vec<u8>=c.case.f.db.query_one("SELECT envelope FROM workflow_context_versions WHERE account_id=$1 AND context_id=$2 AND revision=1", &[&c.case.f.account,&header.context]).await.unwrap().get(0);
    let mut newer = header.aad().unwrap();
    newer.extend_from_slice(&bytes[wire::AAD_LEN..]);
    context::write(
        &mut c.case.f.connect().await,
        &c.case.owner,
        Uuid::new_v4(),
        1,
        &newer,
    )
    .await
    .unwrap();
    c.request.selections[0].version = 2;
    c.request.selections[0].digest = Sha256::digest(newer).into();
    c.request.instruction_digest = Sha256::digest(Uuid::new_v4().as_bytes()).into();
    assert!(
        c.service
            .narrow(
                &mut c.case.f.connect().await,
                &c.case.owner,
                id,
                1,
                &c.request
            )
            .await
            .is_err()
    );
    assert!(
        c.service
            .replace(
                &mut c.case.f.connect().await,
                &c.ceremony(),
                id,
                1,
                &c.request
            )
            .await
            .is_err()
    );
    c.case.fresh_factor().await;
    c.service
        .replace(
            &mut c.case.f.connect().await,
            &c.ceremony(),
            id,
            1,
            &c.request,
        )
        .await
        .unwrap();
    assert_eq!(c.count("managed_reader_grant_versions").await, 2);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_consent_hook_withdrawal_rolls_back_and_never_reactivates_ids() {
    let mut c = ManagedCase::new().await;
    let id = c.issue().await.unwrap();
    let mut db = c.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &c.case.owner)
        .await
        .unwrap();
    tx.query_one(
        "SELECT id FROM contacts WHERE account_id=$1 AND id=$2 FOR UPDATE",
        &[&c.case.f.account, &c.request.contact],
    )
    .await
    .unwrap();
    super::super::lifecycle::consent::withdraw(
        &tx,
        c.case.f.account,
        c.request.contact,
        "operational",
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(c.count("managed_reader_events").await, 1);
    let tx = db.transaction().await.unwrap();
    crate::http_owner_conversations::lock_owner(&tx, &c.case.owner)
        .await
        .unwrap();
    super::super::lifecycle::consent::withdraw(
        &tx,
        Uuid::new_v4(),
        c.request.contact,
        "operational",
    )
    .await
    .unwrap();
    super::super::lifecycle::consent::withdraw(
        &tx,
        c.case.f.account,
        c.request.contact,
        "marketing",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(c.count("managed_reader_events").await, 1);
    // Exercise the actual mounted consent writer and its same-transaction hook.
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    c.case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&Uuid::new_v4(),&c.case.f.account,&c.case.owner.user_id,&digest(b"session-v1",&token).as_slice(),&digest(b"csrf-v1",&csrf).as_slice()]).await.unwrap();
    let separator = if c.case.f.url.contains('?') { '&' } else { '?' };
    let app = crate::http_owner_contacts::router(crate::http_owner_contacts::OwnerContactsState {
        database_url: format!(
            "{}{separator}options=-csearch_path%3D{}",
            c.case.f.url, c.case.f.schema
        ),
        auth_hasher: std::sync::Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap()),
        canonical_origin: "https://owner.example.test".into(),
        vault: None,
    });
    use tower::ServiceExt;
    for action in ["withdraw", "grant"] {
        let now: i64 = c
            .case
            .f
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let response=app.clone().oneshot(axum::http::Request::builder().method("POST").uri(format!("/v1/owner/contacts/{}/consents",c.request.contact)).header("origin","https://owner.example.test").header("cookie",format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}")).header("x-zrotext-csrf",&csrf).header("content-type","application/json").body(axum::body::Body::from(serde_json::to_vec(&json!({"purpose":"operational","action":action,"source":"manual_entry","effective_at_ms":now})).unwrap())).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    }
    let row=c.case.f.db.query_one("SELECT revoked_ms IS NOT NULL,revocation_generation FROM managed_reader_grants WHERE account_id=$1 AND id=$2", &[&c.case.f.account,&id]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(c.count("managed_reader_events").await, 2);
    c.case.fresh_factor().await;
    let fresh = c.issue().await.unwrap();
    assert_ne!(id, fresh);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_expired_key_policy_and_version_cap_still_allow_revocation() {
    let c = ManagedCase::with_lifetime(Some(5000)).await;
    let id = c.issue().await.unwrap();
    let started = tokio::time::Instant::now();
    loop {
        let expired:bool=c.case.f.db.query_one("SELECT expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM managed_reader_policies WHERE account_id=$1 AND id=$2",&[&c.case.f.account,&c.request.policy.id]).await.unwrap().get(0);
        if expired {
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(6));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut narrower = c.request.clone();
    narrower.expires_ms = 1;
    narrower.selections.clear();
    narrower.max_calls = 0;
    let mut client = c.case.f.connect().await;
    for expected in 1..128 {
        assert_eq!(
            c.service
                .narrow(&mut client, &c.case.owner, id, expected, &narrower)
                .await
                .unwrap(),
            expected + 1
        );
    }
    assert!(
        c.service
            .narrow(&mut client, &c.case.owner, id, 128, &narrower)
            .await
            .is_err()
    );
    c.service
        .revoke(&mut client, &c.case.owner, id)
        .await
        .unwrap();
    assert_eq!(c.count("managed_reader_grant_versions").await, 128);
    assert_eq!(c.count("managed_reader_events").await, 129);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated managed grant schema"]
async fn managed_grants_current_owner_cannot_substitute_a_revoked_activation_creator() {
    let mut c = ManagedCase::new().await;
    let original = c.case.owner.session_id;
    let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    c.case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&Uuid::new_v4(),&c.case.f.account,&c.case.owner.user_id,&digest(b"session-v1",&token).as_slice(),&digest(b"csrf-v1",&Uuid::new_v4().to_string()).as_slice()]).await.unwrap();
    c.case.owner = auth::authenticate_session(&c.case.f.db, &c.case.hasher, &token)
        .await
        .unwrap();
    c.case
        .f
        .db
        .execute(
            "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&original],
        )
        .await
        .unwrap();
    assert!(c.issue().await.is_err());
    assert_eq!(c.count("managed_reader_grants").await, 0);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated observed managed grant wait schema"]
async fn managed_grants_observed_account_wait_refences_expiry_and_owner_before_any_effect() {
    for replacing in [false, true] {
        for revoke_owner in [false, true] {
            let mut c =
                ManagedCase::with_lifetime(if revoke_owner { None } else { Some(2500) }).await;
            let existing = if replacing {
                Some(c.issue().await.unwrap())
            } else {
                None
            };
            if replacing {
                c.case.fresh_factor().await;
                c.request.instruction_digest = Sha256::digest(Uuid::new_v4().as_bytes()).into();
            }
            let account = c.case.f.account;
            let session = c.case.owner.session_id;
            let deadline = c.request.expires_ms;
            let unused_before:i64=c.case.f.db.query_one("SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND used_at IS NULL",&[&account]).await.unwrap().get(0);
            let failures_before = auth::abuse_limits::failures_in_window(
                &c.case.f.db,
                &c.case.hasher,
                auth::abuse_limits::Limit::MfaStepUp,
                &c.case.owner.user_id.to_string(),
            )
            .await
            .unwrap();
            let mut blocker = c.case.f.connect().await;
            let tx = blocker.transaction().await.unwrap();
            tx.query_one(
                "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
                &[&account],
            )
            .await
            .unwrap();
            let observer = c.case.f.connect().await;
            let mut granting = c.case.f.connect().await;
            let pid: i32 = granting
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let issued = tokio::spawn(async move {
                let result = if let Some(id) = existing {
                    c.service
                        .replace(&mut granting, &c.ceremony(), id, 1, &c.request)
                        .await
                        .map(|_| id)
                } else {
                    c.service
                        .create(&mut granting, &c.ceremony(), &c.request)
                        .await
                };
                (c, result)
            });
            let started = tokio::time::Instant::now();
            loop {
                let waiting:bool=observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%FOR UPDATE OF a FOR SHARE OF m,u,s%')",&[&pid]).await.unwrap().get(0);
                if waiting {
                    break;
                }
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(2),
                    "grant must reach the observed account lock"
                );
                tokio::task::yield_now().await;
            }
            if revoke_owner {
                tx.execute(
                    "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
                    &[&session],
                )
                .await
                .unwrap();
            } else {
                let now: i64 = observer
                    .query_one(
                        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                assert!(
                    now < deadline,
                    "deadline must pass during the observed wait"
                );
                loop {
                    let expired:bool=observer.query_one("SELECT $1::bigint<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[&deadline]).await.unwrap().get(0);
                    if expired {
                        break;
                    }
                    assert!(started.elapsed() < std::time::Duration::from_secs(3));
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            tx.commit().await.unwrap();
            let (c, result) = issued.await.unwrap();
            assert!(
                matches!(
                    result,
                    Err(managed_ai::Error::Forbidden
                        | managed_ai::Error::Archive(
                            crate::http_owner_conversations::ConversationError::Forbidden
                        ))
                ),
                "fresh authority must refuse, rather than merely timing out: {result:?}"
            );
            let expected = i64::from(replacing);
            for table in [
                "managed_reader_grants",
                "managed_reader_grant_versions",
                "managed_reader_events",
            ] {
                assert_eq!(c.count(table).await, expected, "{table}");
            }
            let unused_after:i64=c.case.f.db.query_one("SELECT count(*) FROM owner_mfa_recovery_codes WHERE account_id=$1 AND used_at IS NULL",&[&account]).await.unwrap().get(0);
            assert_eq!(unused_after, unused_before);
            let failures_after = auth::abuse_limits::failures_in_window(
                &c.case.f.db,
                &c.case.hasher,
                auth::abuse_limits::Limit::MfaStepUp,
                &c.case.owner.user_id.to_string(),
            )
            .await
            .unwrap();
            assert_eq!(failures_after, failures_before);
            c.cleanup().await;
        }
    }
}
