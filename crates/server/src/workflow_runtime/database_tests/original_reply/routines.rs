// SPDX-License-Identifier: AGPL-3.0-only
use super::network::{Driver, Https, capture, configuration, jwk, run_driver};
use super::*;
use crate::auth::AuthError;
use crate::workflow_runtime::routines::tests::service::scratch::Scratch;
use crate::workflow_runtime::routines::{
    self,
    contracts::{OriginalAdmit, Policy},
};
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
mod acceptance;
mod authentication_profile;
mod diagnostics;
mod planning;
mod sequential;
mod transport;
use diagnostics::{deadline_diagnostic, refusal_class};

struct RoutineCase {
    f: OriginalCase,
    scratch: Scratch,
    read: service::IssuedCredential,
    input: IntegrationPrincipal,
    policy: Policy,
    invocation: OriginalAdmit,
    network_input: Option<Value>,
    input_token: zeroize::Zeroizing<String>,
}
impl RoutineCase {
    async fn new() -> Self {
        Self::with_crypto_context(false).await
    }
    async fn with_crypto_context(real: bool) -> Self {
        let mut f = OriginalCase::new().await;
        let scratch = Scratch::create().unwrap();
        let event = Uuid::new_v4();
        let mut seed = configuration(&f, event).await;
        capture(&f, &mut seed, &scratch, event).await;
        let read = f.issue().await;
        f.bind_workflow_request(read.grant_id).await;
        f.case.request.permissions =
            Permissions::new(&[Operation::ContextContent, Operation::ContextMetadata]).unwrap();
        let mut network_input = None;
        let mut installation = None;
        if real {
            f.case.header.context = Uuid::new_v4();
            f.case.request.context = f.case.header.context;
            let h = &f.case.header;
            let mut config = configuration(&f, event).await;
            config["phase"] = json!("seed_context");
            config["role3_private_jwk"] = jwk(&f.case.reader_key);
            config["archive_reader_id"] = json!(decisions::descriptor::hex(&h.reader));
            config["routine_scope"] = json!({"kind":h.kind,"account_id":h.account,"device_id":h.device,"line_id":h.line,
              "interval_id":h.interval,"context_id":h.context,"binding_generation":h.binding_generation.to_string(),
              "revision":h.revision.to_string(),"expires_ms":h.expires_ms.to_string(),"trust_generation":h.trust_generation.to_string(),
              "manifest_version":h.manifest_version.to_string(),"peer_digest":decisions::descriptor::hex(&h.peer_digest),
              "reader_id":decisions::descriptor::hex(&f.statement.integration_readers[0].key_id),"manifest_digest":decisions::descriptor::hex(&h.manifest_digest)});
            let seeded = run_driver(config.clone(), &scratch.path, Driver::OriginalRoutine).await;
            let archive = STANDARD
                .decode(seeded["archive_b64"].as_str().unwrap())
                .unwrap();
            context::write(
                &mut f.case.f.connect().await,
                &f.case.owner,
                Uuid::new_v4(),
                0,
                &archive,
            )
            .await
            .unwrap();
            f.case.request.content_envelope = Some(
                STANDARD
                    .decode(seeded["projection_b64"].as_str().unwrap())
                    .unwrap(),
            );
            installation = Some((
                seeded["adapter_id"].as_str().unwrap().to_owned(),
                seeded["artifact_digest"].as_str().unwrap().to_owned(),
            ));
            network_input = Some(config);
        } else {
            f.case.request.content_envelope = Some(f.case.projection().await);
        }
        let credential = f.case.issue_another().await;
        let input = authenticate(&f.case.f.db, &f.case.hasher, &credential.token)
            .await
            .unwrap();
        // Owner execution policy does not supply contact consent. Establish the
        // same independent synthetic operational consent as ordinary routines.
        let consent = Uuid::new_v4();
        assert_eq!(f.case.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','grant','manual_entry',clock_timestamp(),$4)",
            &[&consent,&f.case.f.account,&f.case.request.contact,&f.case.owner.user_id]).await.unwrap(),1);
        let latest = f.case.f.db.query_one("SELECT id,action FROM contact_consent_records WHERE account_id=$1 AND contact_id=$2 AND purpose='operational' ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1",
            &[&f.case.f.account,&f.case.request.contact]).await.unwrap();
        assert_eq!(latest.get::<_, Uuid>(0), consent);
        assert_eq!(latest.get::<_, String>(1), "grant");
        let clock=f.case.f.db.query_one("WITH moment(t) AS (SELECT clock_timestamp()) SELECT to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD'),extract(hour FROM t AT TIME ZONE 'UTC')::integer*60+extract(minute FROM t AT TIME ZONE 'UTC')::integer FROM moment",&[]).await.unwrap();
        let minute: i32 = clock.get(1);
        let mut policy:Policy=serde_json::from_value(json!({
            "request_id":Uuid::new_v4(),"policy_id":Uuid::new_v4(),"context_id":f.case.header.context,
            "routine_id":Uuid::new_v4(),"generation":3,"kind":"faq","executor":"local_process",
            "adapter_id":"synthetic_customer","artifact_digest":"ab".repeat(32),
            "original_input":{"grant_id":read.grant_id},"period":"utc_day",
            "expires_ms":f.case.request.expires_ms,"call_limit":10,"unit_limit":100,
            "units_per_call":4,"turn_limit":3,"timeout_ms":10000,
            "window":{"timezone":"UTC","first_local_date":clock.get::<_,String>(0),
                "opens_minute":minute.saturating_sub(1),"closes_minute":(minute+30)%1440,
                "repeat_every_days":null,"max_occurrences":1,"pacing_seconds":60}
        })).unwrap();
        if let Some((adapter, digest)) = installation {
            policy.adapter_id = Some(adapter);
            policy.artifact_digest = Some(digest);
        }
        let principal = service::authenticate(&f.case.f.db, &f.case.hasher, &read.token)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let configured = routines::configure_with_original(
            &mut f.case.f.connect().await,
            &f.case.owner,
            &input,
            Some(&principal),
            policy.clone(),
        )
        .await;
        if configured.is_err() {
            let diagnostic = deadline_diagnostic(
                &f,
                read.grant_id,
                &input,
                None,
                &policy,
                "configure",
                started,
            )
            .await;
            panic!(
                "routine fixture refused: class={} {diagnostic}",
                refusal_class(&configured)
            );
        }
        configured.unwrap();
        let event_digest: Vec<u8> = f
            .case
            .f
            .db
            .query_one(
                "SELECT sha256(envelope) FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
                &[&f.case.f.account, &event],
            )
            .await
            .unwrap()
            .get(0);
        let invocation=OriginalAdmit {
            request_id:Uuid::new_v4(),policy_id:policy.policy_id,context_id:policy.context_id,
            input_revision:f.case.header.revision,input_source_digest:decisions::descriptor::hex(&f.case.f.db.query_one("SELECT sha256(envelope) FROM workflow_context_versions WHERE account_id=$1 AND context_id=$2 AND revision=$3",&[&f.case.f.account,&f.case.header.context,&f.case.header.revision]).await.unwrap().get::<_,Vec<u8>>(0)),
            event_id:event,accepted_manifest_version:f.case.header.manifest_version,
            event_envelope_digest:decisions::descriptor::hex(&event_digest),
        };
        Self {
            f,
            scratch,
            read,
            input,
            policy,
            invocation,
            network_input,
            input_token: credential.token,
        }
    }
    async fn admit(&self, v: OriginalAdmit) -> Result<routines::contracts::Call, AuthError> {
        let principal =
            service::authenticate(&self.f.case.f.db, &self.f.case.hasher, &self.read.token)
                .await
                .unwrap();
        routines::admit_original(
            &mut self.f.case.f.connect().await,
            &self.input,
            &principal,
            v,
        )
        .await
    }
    async fn current(&self, call: Uuid) -> Result<routines::contracts::Call, AuthError> {
        let principal =
            service::authenticate(&self.f.case.f.db, &self.f.case.hasher, &self.read.token)
                .await
                .unwrap();
        routines::current_original(
            &mut self.f.case.f.connect().await,
            &self.input,
            &principal,
            call,
        )
        .await
    }
    async fn owner_publish_and_propose(&mut self, call: Uuid) -> decisions::ActionKey {
        let mut header = self.f.case.header.clone();
        header.context = call;
        let ephemeral = SigningKey::generate_from_rng(&mut rand::rng());
        let mut archive = header.aad().unwrap();
        archive.extend(ephemeral.verifying_key().to_sec1_point(false).as_bytes());
        archive.extend(33u32.to_be_bytes());
        archive.extend([88; 33]);
        self.owner_publish_archive_and_propose(call, header, archive, None)
            .await
    }
    async fn owner_publish_real_and_propose(
        &mut self,
        call: Uuid,
        archive: Vec<u8>,
        projection: Vec<u8>,
    ) -> decisions::ActionKey {
        let header = wire::parse(&archive).unwrap();
        assert_eq!(header.context, call);
        assert_eq!(header.revision, 1);
        assert_eq!(header.account, self.f.case.header.account);
        assert_eq!(header.interval, self.f.case.header.interval);
        assert_eq!(header.peer_digest, self.f.case.header.peer_digest);
        self.owner_publish_archive_and_propose(call, header, archive, Some(projection))
            .await
    }
    async fn owner_publish_archive_and_propose(
        &mut self,
        call: Uuid,
        header: wire::Header,
        archive: Vec<u8>,
        projection: Option<Vec<u8>>,
    ) -> decisions::ActionKey {
        let hash = decisions::descriptor::hex(&Sha256::digest(&archive));
        let original =
            service::authenticate(&self.f.case.f.db, &self.f.case.hasher, &self.read.token)
                .await
                .unwrap();
        routines::produced_with_original(
            &mut self.f.case.f.connect().await,
            &self.input,
            Some(&original),
            self.policy.context_id,
            call,
            hash.clone(),
        )
        .await
        .unwrap();
        context::write(
            &mut self.f.case.f.connect().await,
            &self.f.case.owner,
            Uuid::new_v4(),
            0,
            &archive,
        )
        .await
        .unwrap();
        self.f.case.header = header;
        self.f.case.request.context = call;
        self.f.case.request.permissions =
            Permissions::new(&[Operation::ContextContent, Operation::Propose]).unwrap();
        self.f.case.request.content_envelope = Some(match projection {
            Some(envelope) => envelope,
            None => self.f.case.projection().await,
        });
        self.f.case.request.expires_ms = self
            .f
            .case
            .request
            .expires_ms
            .min(self.f.case.header.expires_ms);
        self.f.bind_workflow_request(self.read.grant_id).await;
        let credential = self.f.case.issue_another().await;
        let output = authenticate(&self.f.case.f.db, &self.f.case.hasher, &credential.token)
            .await
            .unwrap();
        let binding = routines::contracts::OutputBinding {
            request_id: Uuid::new_v4(),
            call_id: call,
            output_context_id: call,
            output_revision: 1,
            output_source_digest: hash.clone(),
            produced_digest: hash,
        };
        let started = std::time::Instant::now();
        let bound = routines::bind_with_original(
            &mut self.f.case.f.connect().await,
            &self.f.case.owner,
            &self.input,
            &output,
            Some(&original),
            binding,
        )
        .await;
        if bound.is_err() {
            let diagnostic = deadline_diagnostic(
                &self.f,
                self.read.grant_id,
                &self.input,
                Some(&output),
                &self.policy,
                "bind",
                started,
            )
            .await;
            panic!(
                "routine fixture refused: class={} {diagnostic}",
                refusal_class(&bound)
            );
        }
        bound.unwrap();
        let proposed = routines::resume_with_original(
            &mut self.f.case.f.connect().await,
            &self.input,
            &output,
            Some(&original),
            call,
        )
        .await
        .unwrap();
        assert_eq!(proposed.action_id, Some(call));
        let row=self.f.case.f.db.query_one("SELECT revision,binding_digest FROM workflow_actions WHERE account_id=$1 AND id=$2",&[&self.f.case.f.account,&call]).await.unwrap();
        decisions::ActionKey {
            account_id: self.f.case.f.account,
            action_id: call,
            revision: row.get(0),
            binding_digest: row.get::<_, Vec<u8>>(1).try_into().unwrap(),
        }
    }
    async fn finish(self) {
        self.scratch.remove().unwrap();
        self.f.case.f.cleanup().await;
    }
    async fn approve(&self, key: decisions::ActionKey) -> decisions::ActionState {
        let current = decisions::read(&mut self.f.case.f.connect().await, &self.f.case.owner, key)
            .await
            .unwrap();
        assert_eq!(current.key, key);
        decisions::decide(
            &mut self.f.case.f.connect().await,
            &self.f.case.owner,
            Uuid::new_v4(),
            current.record_version,
            current.key,
            decisions::model::Decision::Approve,
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original routine disposable authority schema"]
async fn first_original_question_admits_without_outbound_request_and_replays_without_execution() {
    let f = RoutineCase::new().await;
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM original_reply_requests WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let call = f.admit(f.invocation.clone()).await.unwrap();
    assert!(call.execute_once);
    let replay = f.admit(f.invocation.clone()).await.unwrap();
    assert!(!replay.execute_once);
    assert_eq!(call.call_id, replay.call_id);
    assert!(!f.current(call.call_id).await.unwrap().execute_once);
    let mut different = f.invocation.clone();
    different.request_id = Uuid::new_v4();
    assert!(matches!(f.admit(different).await, Err(AuthError::Conflict)));
    let row=f.f.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1),(SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT sum(units)::bigint FROM workflow_routine_period_debits WHERE account_id=$1),(SELECT turns FROM workflow_routine_turn_debits WHERE account_id=$1 AND context_id=$2)",&[&f.f.case.f.account,&f.policy.context_id]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Option<i64>>(1), Some(1));
    assert_eq!(row.get::<_, Option<i64>>(2), Some(4));
    assert_eq!(row.get::<_, i64>(3), 1);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original proposal and owner decision source fences"]
async fn original_source_erasure_refuses_preparation_even_after_exact_owner_approval() {
    let mut f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let key = f.owner_publish_and_propose(call.call_id).await;
    let approved = f.approve(key).await;
    assert_eq!(approved.key, key);
    f.f.case
        .f
        .db
        .execute(
            "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
            &[&f.f.case.f.account, &f.invocation.event_id],
        )
        .await
        .unwrap();
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    assert!(matches!(
        decisions::lock_approved(&tx, &f.f.case.owner, key).await,
        Err(ConversationError::Forbidden)
    ));
    tx.rollback().await.unwrap();
    assert!(
        !f.f.case
            .f
            .db
            .query_one(
                "SELECT workflow_routine_original_action_current($1,$2)",
                &[&f.f.case.f.account, &key.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original source retains exact contact consent"]
async fn original_source_current_refuses_latest_contact_withdrawal_without_refunding_unknown_work()
{
    let f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    assert!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT workflow_routine_original_current($1,$2)",
                &[&f.f.case.f.account, &call.call_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.f.case.f.db.execute("INSERT INTO contact_consent_records(id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) VALUES($1,$2,$3,'operational','withdraw','manual_entry',clock_timestamp(),$4)",&[&Uuid::new_v4(),&f.f.case.f.account,&f.f.case.request.contact,&f.f.case.owner.user_id]).await.unwrap();
    assert!(
        !f.f.case
            .f
            .db
            .query_one(
                "SELECT workflow_routine_original_current($1,$2)",
                &[&f.f.case.f.account, &call.call_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(matches!(
        f.current(call.call_id).await,
        Err(AuthError::Forbidden)
    ));
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, Option<i64>>(0),
        Some(1)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; genuine original routine to original reply lineage"]
async fn original_reply_child_keeps_first_question_source_fence_after_genuine_issued_output() {
    let mut f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let first = f.owner_publish_and_propose(call.call_id).await;
    let approved = f.approve(first).await;
    let precursors = f.f.case.f.db.query_one(
        "SELECT workflow_routine_original_current($1,$2),workflow_routine_original_action_current($1,$2),original_reply_source_current($1,$2),original_reply_grant_current($1,$3)",
        &[&f.f.case.f.account,&first.action_id,&f.read.grant_id],
    ).await.unwrap();
    assert!(
        precursors.get::<_, bool>(0),
        "original routine source must be current before issuing its output"
    );
    assert!(
        precursors.get::<_, bool>(1),
        "original output action must be current before issuing its output"
    );
    assert!(
        precursors.get::<_, bool>(2),
        "original output lineage must be current before issuing its output"
    );
    assert!(
        precursors.get::<_, bool>(3),
        "original reader grant must be current before issuing its output"
    );
    let request = super::network::issued_request(&mut f.f, approved).await;
    let second_event = Uuid::new_v4();
    let mut seed = configuration(&f.f, second_event).await;
    seed["local_sequence"] = json!("2");
    capture(&f.f, &mut seed, &f.scratch, second_event).await;
    let second_read = f.f.issue().await;
    f.f.bind_workflow_request(second_read.grant_id).await;
    let credential = f.f.case.issue_another().await;
    let output = authenticate(&f.f.case.f.db, &f.f.case.hasher, &credential.token)
        .await
        .unwrap();
    let original = service::authenticate(&f.f.case.f.db, &f.f.case.hasher, &second_read.token)
        .await
        .unwrap();
    let mut descriptor = f.f.case.descriptor().await;
    descriptor.routine_id = call.call_id.to_string();
    let deadline:i64=f.f.case.f.db.query_one("SELECT LEAST(g.expires_ms,r.expires_ms) FROM original_reply_grants g JOIN original_reply_requests r ON r.account_id=g.account_id WHERE g.account_id=$1 AND g.grant_id=$2 AND r.request_id=$3",&[&f.f.case.f.account,&second_read.grant_id,&request]).await.unwrap().get(0);
    descriptor.expires_at = deadline / 1000;
    let child = service::consumption::consume(
        &mut f.f.case.f.connect().await,
        &original,
        f.invocation.accepted_manifest_version,
        service::consumption::Request {
            request_id: Uuid::new_v4(),
            event_id: second_event,
            active_request_id: Some(request),
            descriptor: Some(descriptor),
        },
        Some(&output),
    )
    .await
    .unwrap()
    .action
    .unwrap();
    assert!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&f.f.case.f.account, &child.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.f.case
        .f
        .db
        .execute(
            "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
            &[&f.f.case.f.account, &f.invocation.event_id],
        )
        .await
        .unwrap();
    assert!(f.f.case.f.db.query_one("SELECT original_reply_grant_current($1,$2) AND original_reply_grant_current($1,$3)",&[&f.f.case.f.account,&f.read.grant_id,&second_read.grant_id]).await.unwrap().get::<_,bool>(0));
    assert!(
        !f.f.case
            .f
            .db
            .query_one(
                "SELECT original_reply_source_current($1,$2)",
                &[&f.f.case.f.account, &child.action_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, built SDK and Node; actual original routine HTTPS/crypto/process/PG"]
async fn first_original_question_runs_pinned_customer_process_over_https_and_restart_never_executes_twice()
 {
    let mut f = RoutineCase::with_crypto_context(true).await;
    let database_url = transport::database_url_with_schema(&f.f.case.f.url, &f.f.case.f.schema)
        .expect("valid owned fixture database URL");
    let hasher = std::sync::Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let workflow = crate::workflow_runtime::http::WorkflowHttpState {
        database_url: database_url.clone(),
        hasher: hasher.clone(),
    };
    let app = service::http::router(
        service::http::StateData {
            database_url,
            hasher,
        },
        true,
    )
    .merge(crate::workflow_runtime::http::router(
        workflow.clone(),
        true,
    ))
    .merge(routines::http::router_with_original(workflow, true, true));
    let tls = Https::start(app).await;
    let port = tls.origin.rsplit_once(':').unwrap().1;
    let mut config = f.network_input.take().unwrap();
    config["origin"] = json!(format!("https://localhost:{port}"));
    config["ca_pem"] = json!(tls.ca);
    config["read_credential"] = json!(f.read.token.as_str());
    config["input_credential"] = json!(f.input_token.as_str());
    config["routine_policy"] = serde_json::to_value(&f.policy).unwrap();
    config["request_id"] = json!(f.invocation.request_id);
    config["phase"] = json!("exercise_original");
    let executed = run_driver(config.clone(), &f.scratch.path, Driver::OriginalRoutine).await;
    assert_eq!(executed["state"], "awaiting_owner_publication");
    assert_eq!(
        executed["call"]["call_id"],
        f.invocation.request_id.to_string()
    );
    config["phase"] = json!("recover_original");
    let replay = run_driver(config, &f.scratch.path, Driver::OriginalRoutine).await;
    assert_eq!(replay["call"]["call_id"], executed["call"]["call_id"]);
    assert_eq!(replay["call"]["execute_once"], false);
    let row = f.f.case.f.db.query_one("SELECT (SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1), (SELECT count(*) FROM workflow_routine_calls WHERE account_id=$1), (SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1), (SELECT sum(units)::bigint FROM workflow_routine_period_debits WHERE account_id=$1), (SELECT count(*) FROM workflow_actions WHERE account_id=$1), (SELECT count(*) FROM messages WHERE account_id=$1), (SELECT count(*) FROM message_attempts WHERE account_id=$1)", &[&f.f.case.f.account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, Option<i64>>(2), Some(1));
    assert_eq!(row.get::<_, Option<i64>>(3), Some(4));
    for index in 4..7 {
        assert_eq!(row.get::<_, i64>(index), 0);
    }
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT phase FROM workflow_routine_calls WHERE account_id=$1 AND id=$2",
                &[&f.f.case.f.account, &f.invocation.request_id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "produced"
    );
    tls.close().await;
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original routine disposable authority schema"]
async fn original_admission_requires_explicit_policy_and_exact_ciphertext_identity() {
    let f = RoutineCase::new().await;
    assert!(matches!(
        routines::configure(
            &mut f.f.case.f.connect().await,
            &f.f.case.owner,
            &f.input,
            f.policy.clone()
        )
        .await,
        Err(AuthError::Forbidden)
    ));
    let ordinary = routines::contracts::Invocation {
        request_id: Uuid::new_v4(),
        policy_id: f.policy.policy_id,
        context_id: f.policy.context_id,
        input_revision: f.invocation.input_revision,
        input_source_digest: f.invocation.input_source_digest.clone(),
        direction: routines::contracts::Direction::OwnerDeclared,
    };
    assert!(matches!(
        routines::admit(&mut f.f.case.f.connect().await, &f.input, ordinary).await,
        Err(AuthError::Forbidden)
    ));
    let mut wrong = f.invocation.clone();
    wrong.event_envelope_digest = "cd".repeat(32);
    assert!(matches!(f.admit(wrong).await, Err(AuthError::Forbidden)));
    let mut wrong = f.invocation.clone();
    wrong.input_source_digest = "cd".repeat(32);
    assert!(matches!(f.admit(wrong).await, Err(AuthError::Forbidden)));
    let mut wrong = f.invocation.clone();
    wrong.accepted_manifest_version = f.invocation.accepted_manifest_version + 1;
    assert!(matches!(f.admit(wrong).await, Err(AuthError::Forbidden)));
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_admission_tombstones WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(f.admit(f.invocation.clone()).await.unwrap().execute_once);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original routine disposable authority schema"]
async fn original_event_cannot_reexecute_under_a_new_owner_policy_generation() {
    let f = RoutineCase::new().await;
    assert!(f.admit(f.invocation.clone()).await.unwrap().execute_once);
    let principal = service::authenticate(&f.f.case.f.db, &f.f.case.hasher, &f.read.token)
        .await
        .unwrap();
    let mut policy = f.policy.clone();
    policy.request_id = Uuid::new_v4();
    policy.policy_id = Uuid::new_v4();
    policy.routine_id = Uuid::new_v4();
    policy.generation = 4;
    routines::configure_with_original(
        &mut f.f.case.f.connect().await,
        &f.f.case.owner,
        &f.input,
        Some(&principal),
        policy.clone(),
    )
    .await
    .unwrap();
    let mut invocation = f.invocation.clone();
    invocation.policy_id = policy.policy_id;
    invocation.request_id = Uuid::new_v4();
    assert!(matches!(
        f.admit(invocation).await,
        Err(AuthError::Conflict)
    ));
    assert_eq!(
        f.f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_routine_calls WHERE account_id=$1",
                &[&f.f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original routine disposable authority schema"]
async fn deleted_original_ciphertext_refuses_current_produced_and_retains_unknown_debit() {
    let f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    f.f.case
        .f
        .db
        .execute(
            "UPDATE sealed_inbound_events SET envelope=NULL WHERE account_id=$1 AND id=$2",
            &[&f.f.case.f.account, &f.invocation.event_id],
        )
        .await
        .unwrap();
    assert!(matches!(
        f.current(call.call_id).await,
        Err(AuthError::Forbidden)
    ));
    let principal = service::authenticate(&f.f.case.f.db, &f.f.case.hasher, &f.read.token)
        .await
        .unwrap();
    assert!(matches!(
        routines::produced_with_original(
            &mut f.f.case.f.connect().await,
            &f.input,
            Some(&principal),
            f.policy.context_id,
            call.call_id,
            "ab".repeat(32)
        )
        .await,
        Err(AuthError::Forbidden)
    ));
    let row=f.f.case.f.db.query_one("SELECT phase,(SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1) FROM workflow_routine_calls WHERE account_id=$1 AND id=$2",&[&f.f.case.f.account,&call.call_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "unknown");
    assert_eq!(row.get::<_, Option<i64>>(1), Some(1));
    let tx = f.f.case.f.connect().await;
    assert_eq!(
        tx.query_one(
            "SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1",
            &[&f.f.case.f.account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original routine disposable authority schema"]
async fn original_source_tombstone_survives_metadata_erasure_and_rejects_standalone_deletion() {
    let f = RoutineCase::new().await;
    let call = f.admit(f.invocation.clone()).await.unwrap();
    let mut db = f.f.case.f.connect().await;
    let tx = db.transaction().await.unwrap();
    tx.execute(
        "DELETE FROM workflow_routine_original_sources WHERE account_id=$1",
        &[&f.f.case.f.account],
    )
    .await
    .unwrap();
    let failure = tx.commit().await.unwrap_err();
    assert_eq!(
        failure.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    let tx = db.transaction().await.unwrap();
    routines::lifecycle::erase_context(&tx, f.f.case.f.account, f.policy.context_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM workflow_routine_original_sources WHERE account_id=$1",
            &[&f.f.case.f.account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert!(
        !db.query_one(
            "SELECT workflow_routine_original_current($1,$2)",
            &[&f.f.case.f.account, &call.call_id]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert_eq!(
        db.query_one(
            "SELECT sum(calls)::bigint FROM workflow_routine_period_debits WHERE account_id=$1",
            &[&f.f.case.f.account]
        )
        .await
        .unwrap()
        .get::<_, Option<i64>>(0),
        Some(1)
    );
    f.finish().await;
}
