// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

mod owner_expiry;

struct OwnerRoute {
    app: Router,
    cookie: String,
    csrf: String,
    contact: Uuid,
    application: String,
    session: Uuid,
}
impl OwnerRoute {
    async fn new(case: &Case) -> Self {
        let token = format!("zts_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let csrf = format!("ztc_{}", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
        let session = Uuid::new_v4();
        case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&session,&case.f.account,&case.owner.user_id,&auth_hash(b"session-v1",&token),&auth_hash(b"csrf-v1",&csrf)]).await.unwrap();
        let separator = if case.f.url.contains('?') { '&' } else { '?' };
        let application = format!("consent-test-{}", Uuid::new_v4());
        Self {
            app: crate::http_owner_contacts::router(
                crate::http_owner_contacts::OwnerContactsState {
                    database_url: format!(
                        "{}{separator}options=-csearch_path%3D{}&application_name={application}",
                        case.f.url, case.f.schema
                    ),
                    auth_hasher: Arc::new(
                        crate::auth::TokenHasher::new(crate::test_keys::key(84)).unwrap(),
                    ),
                    canonical_origin: "https://owner.example.test".into(),
                    vault: None,
                },
            ),
            cookie: format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
            csrf,
            contact: case.request.contact,
            application,
            session,
        }
    }
    async fn consent(&self, action: &str) -> StatusCode {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        self.app.clone().oneshot(Request::builder().method("POST")
            .uri(format!("/v1/owner/contacts/{}/consents", self.contact))
            .header("origin", "https://owner.example.test")
            .header("cookie", &self.cookie).header("x-zrotext-csrf", &self.csrf)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({"purpose":"operational", "action":action,"source":"manual_entry","effective_at_ms":now})).unwrap())).unwrap()).await.unwrap().status()
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable consent and workflow schema"]
async fn owner_consent_withdrawal_permanently_fences_bound_authority_without_refunding_calls() {
    let (mut case, input, policy, invocation) = prepared().await;
    let first = admit(&mut case.f.connect().await, &input, invocation.clone())
        .await
        .unwrap();
    assert!(first.execute_once);
    let tx = case.f.db.transaction().await.unwrap();
    crate::workflow_runtime::lifecycle::consent::withdraw(
        &tx,
        Uuid::new_v4(),
        case.request.contact,
        "operational",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        super::super::super::read_context_content(
            &mut case.f.connect().await,
            &input,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_ok(),
        "another account cannot withdraw this authority"
    );
    let other_contact = Uuid::new_v4();
    let other_contact_grant = Uuid::new_v4();
    case.f
        .db
        .execute(
            "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,'+15550109999')",
            &[&other_contact, &case.f.account],
        )
        .await
        .unwrap();
    case.f.db.execute("INSERT INTO workflow_integration_grants SELECT (jsonb_populate_record(NULL::workflow_integration_grants,to_jsonb(g)||jsonb_build_object('grant_id',$2::uuid,'contact_id',$3::uuid,'credential_hash',decode(md5($2::uuid::text)||md5($2::uuid::text),'hex')))).* FROM workflow_integration_grants g WHERE g.account_id=$1 AND g.grant_id=$4", &[&case.f.account,&other_contact_grant,&other_contact,&input.grant_id()]).await.unwrap();
    // A separate purpose on the same contact remains independent authority.
    case.request.purpose = crate::workflow_runtime::Purpose::Transactional;
    let other = case.issue_another().await;
    let other = authenticate(&case.f.db, &case.hasher, &other.token)
        .await
        .unwrap();
    case.request.purpose = crate::workflow_runtime::Purpose::Operational;
    let route = OwnerRoute::new(&case).await;
    let output = Uuid::new_v4();
    let output_grant = Uuid::new_v4();
    // Relational lifecycle fixture only: cloned archive bytes never convey
    // reader or send authority and are never decrypted or executed.
    case.f.db.execute("INSERT INTO workflow_contexts SELECT (jsonb_populate_record(NULL::workflow_contexts,to_jsonb(c)||jsonb_build_object('id',$2::uuid))).* FROM workflow_contexts c WHERE c.account_id=$1 AND c.id=$3",&[&case.f.account,&output,&case.header.context]).await.unwrap();
    case.f.db.execute("INSERT INTO workflow_context_versions SELECT (jsonb_populate_record(NULL::workflow_context_versions,to_jsonb(v)||jsonb_build_object('context_id',$2::uuid,'id',$2::uuid,'request_id',$2::uuid))).* FROM workflow_context_versions v WHERE v.account_id=$1 AND v.context_id=$3 AND v.revision=1",&[&case.f.account,&output,&case.header.context]).await.unwrap();
    case.f
        .db
        .execute(
            "INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$2,1)",
            &[&case.f.account, &output],
        )
        .await
        .unwrap();
    case.f.db.execute("INSERT INTO workflow_integration_grants SELECT (jsonb_populate_record(NULL::workflow_integration_grants,to_jsonb(g)||jsonb_build_object('grant_id',$2::uuid,'context_id',$3::uuid,'credential_hash',decode(md5($2::uuid::text)||md5($2::uuid::text),'hex')))).* FROM workflow_integration_grants g WHERE g.account_id=$1 AND g.grant_id=$4",&[&case.f.account,&output_grant,&output,&input.grant_id()]).await.unwrap();
    case.f.db.execute("INSERT INTO workflow_routine_calls(account_id,id,policy_id,request_digest,units,phase,created_ms,produced_digest,output_grant_id,output_context_id,output_revision,output_digest,publication_request,publication_digest,published_by_user,published_session) VALUES($1,$2,$3,decode(repeat('ab',32),'hex'),1,'published',1,decode(repeat('ab',32),'hex'),$4,$2,1,decode(repeat('ab',32),'hex'),$2,decode(repeat('ab',32),'hex'),$5,$6)",&[&case.f.account,&output,&policy.policy_id,&output_grant,&case.owner.user_id,&case.owner.session_id]).await.unwrap();
    assert_eq!(route.consent("withdraw").await, StatusCode::OK);
    assert!(case.f.db.query_one("SELECT revoked_ms IS NULL FROM workflow_integration_grants WHERE account_id=$1 AND grant_id=$2", &[&case.f.account,&other_contact_grant]).await.unwrap().get::<_,bool>(0));
    assert!(case.f.db.query_one("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2", &[&case.f.account,&output]).await.unwrap().get::<_,bool>(0));
    assert!(!case.f.db.query_one("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2", &[&case.f.account,&policy.routine_id]).await.unwrap().get::<_,bool>(0), "shared input routine is preserved");
    let row = case.f.db.query_one("SELECT g.revoked_ms IS NOT NULL,e.envelope IS NULL,p.withdrawn_ms IS NOT NULL FROM workflow_integration_grants g JOIN workflow_connector_context_envelopes e USING(account_id,grant_id) JOIN workflow_routine_policies p ON (p.account_id,p.input_grant_id)=(g.account_id,g.grant_id) WHERE g.account_id=$1 AND g.grant_id=$2", &[&case.f.account,&input.grant_id()]).await.unwrap();
    assert!(row.get::<_, bool>(0) && row.get::<_, bool>(1) && row.get::<_, bool>(2));
    assert!(case.f.db.query_one("SELECT envelope IS NOT NULL FROM workflow_context_versions WHERE account_id=$1 AND context_id=$2 AND revision=1", &[&case.f.account,&case.header.context]).await.unwrap().get::<_,bool>(0), "owner archive bytes retain their independent lifecycle");
    assert!(
        super::super::super::read_context_content(
            &mut case.f.connect().await,
            &input,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_err()
    );
    assert_eq!(route.consent("grant").await, StatusCode::OK);
    assert!(matches!(
        admit(&mut case.f.connect().await, &input, invocation).await,
        Err(AuthError::Forbidden)
    ));
    assert!(
        super::super::super::read_context_content(
            &mut case.f.connect().await,
            &other,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_ok()
    );
    let row = case.f.db.query_one("SELECT phase,(SELECT calls FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT units FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1),(SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1) FROM workflow_routine_calls WHERE account_id=$1 AND id=$2", &[&case.f.account,&first.call_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "unknown");
    assert_eq!(
        (
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3),
            row.get::<_, i64>(4)
        ),
        (1, 5, 1, 1)
    );
    // A later consent grant can support fresh authority, never the withdrawn policy.
    let issued = case.issue_another().await;
    let fresh = authenticate(&case.f.db, &case.hasher, &issued.token)
        .await
        .unwrap();
    let mut next = policy.clone();
    next.policy_id = Uuid::new_v4();
    next.request_id = Uuid::new_v4();
    configure(&mut case.f.connect().await, &case.owner, &fresh, next)
        .await
        .unwrap();
    assert!(matches!(
        configure(&mut case.f.connect().await, &case.owner, &fresh, policy).await,
        Err(AuthError::Conflict)
    ));
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM message_attempts", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable concurrent consent and workflow schema"]
async fn waiting_withdrawal_fences_concurrent_execution_before_any_debit() {
    let (mut case, input, _, invocation) = prepared().await;
    let route = OwnerRoute::new(&case).await;
    let application = route.application.clone();
    let observer = case.f.connect().await;
    let mut executor = case.f.connect().await;
    let tx = case.f.db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&case.f.account],
    )
    .await
    .unwrap();
    let withdrawal = tokio::spawn(async move { route.consent("withdraw").await });
    let started = tokio::time::Instant::now();
    loop {
        let waiting = observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%FOR NO KEY UPDATE%')", &[&application]).await.unwrap().get::<_,bool>(0);
        if waiting {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "withdrawal must reach the observed account lock"
        );
        tokio::task::yield_now().await;
    }
    let execution = tokio::spawn(async move { admit(&mut executor, &input, invocation).await });
    tx.commit().await.unwrap();
    assert_eq!(withdrawal.await.unwrap(), StatusCode::OK);
    assert!(matches!(
        execution.await.unwrap(),
        Err(AuthError::Forbidden)
    ));
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_calls),(SELECT count(*) FROM workflow_routine_period_debits),(SELECT count(*) FROM workflow_routine_admission_tombstones)",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 0, 0)
    );
    case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; disposable consent and workflow schema"]
async fn failed_workflow_withdrawal_rolls_back_consent_and_existing_authority() {
    let (case, input, _, _) = prepared().await;
    let route = OwnerRoute::new(&case).await;
    case.f.db.batch_execute("CREATE FUNCTION reject_consent_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic refusal'; END $$; CREATE TRIGGER reject_consent_policy BEFORE UPDATE ON workflow_routine_policies FOR EACH ROW EXECUTE FUNCTION reject_consent_policy()").await.unwrap();
    assert_eq!(
        route.consent("withdraw").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let row=case.f.db.query_one("SELECT (SELECT count(*) FROM contact_consent_records WHERE action='withdraw'),(SELECT count(*) FROM workflow_integration_grants WHERE revoked_ms IS NOT NULL),(SELECT count(*) FROM workflow_routine_policies WHERE withdrawn_ms IS NOT NULL)",&[]).await.unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 0, 0)
    );
    assert!(
        super::super::super::read_context_content(
            &mut case.f.connect().await,
            &input,
            Uuid::new_v4(),
            case.header.context
        )
        .await
        .is_ok()
    );
    case.f.cleanup().await;
}
