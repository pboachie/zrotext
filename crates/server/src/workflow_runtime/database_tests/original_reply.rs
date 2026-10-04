// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    http_owner_conversations::{
        ConversationConsent, ConversationError, activation, context::decisions,
    },
    original_reply as service,
};
struct OriginalCase {
    case: Case,
    statement: activation::Statement,
    read_grant: Uuid,
}
impl OriginalCase {
    async fn new() -> Self {
        Self::with_conversation_key_deadline(None).await
    }
    async fn with_conversation_key_deadline(role: Option<u8>) -> Self {
        let mut case = Case::for_original_reply().await;
        // This new fixture exercises the full account-erasure table plan and
        // genuine execution-issued source messages, unlike older partial cases.
        case.f
            .db
            .batch_execute(include_str!(
                "../../../../../deploy/compose/migrations/082_conversation_execution_records.sql"
            ))
            .await
            .unwrap();
        activation::close(
            &mut case.f.connect().await,
            &case.owner,
            case.header.interval,
            false,
        )
        .await
        .unwrap();
        let row=case.f.db.query_one("SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 AND kind='read'",&[&case.f.account,&case.request.connector]).await.unwrap();
        let read_grant: Uuid = row.get(0);
        let reader:[u8;32]=case.f.db.query_one("SELECT key_id FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",&[&case.f.account,&case.request.connector]).await.unwrap().get::<_,Vec<u8>>(0).try_into().unwrap();
        case.f.advance();
        if let Some(role) = role {
            assert!(matches!(role, 2 | 4));
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
            let at = (0..usize::from(case.f.bytes[150]))
                .map(|index| 151 + 149 * index)
                .find(|at| case.f.bytes[*at] == role)
                .unwrap();
            case.f.bytes[at + 140..at + 148]
                .copy_from_slice(&((now + 60_000) as u64).to_be_bytes());
            case.f.resign();
        }
        let consent = ConversationConsent {
            device_id: case.f.device,
            line_id: case.f.line,
            binding_generation: 1,
            peer: "+12".into(),
            disclosure_version: crate::http_owner_conversations::DISCLOSURE_VERSION.into(),
            content_transfer_confirmed: true,
        };
        let statement = activation::begin_selected(
            &mut case.f.connect().await,
            &case.owner,
            &consent,
            &case.f.bytes,
            &[activation::SelectedReader {
                connector_id: case.request.connector,
                read_grant_id: read_grant,
                key_id: reader,
            }],
        )
        .await
        .unwrap();
        activate(&case.f, &statement).await;
        let root=case.f.db.query_one("SELECT version,semantic_digest FROM sealed_manifest_authorities WHERE account_id=$1",&[&case.f.account]).await.unwrap();
        case.header.context = Uuid::new_v4();
        case.header.interval = statement.interval;
        case.header.manifest_version = root.get(0);
        case.header.manifest_digest = root.get::<_, Vec<u8>>(1).try_into().unwrap();
        case.request.context = case.header.context;
        let mut archive = case.header.aad().unwrap();
        let ephemeral = SigningKey::generate_from_rng(&mut rand::rng());
        archive.extend(ephemeral.verifying_key().to_sec1_point(false).as_bytes());
        archive.extend(33u32.to_be_bytes());
        archive.extend([88; 33]);
        context::write(
            &mut case.f.connect().await,
            &case.owner,
            Uuid::new_v4(),
            0,
            &archive,
        )
        .await
        .unwrap();
        // The private reader key corresponds to the independently registered manifest point.
        let actual = case.reader_key.verifying_key().to_sec1_point(false);
        let stored:Vec<u8>=case.f.db.query_one("SELECT key_point FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",&[&case.f.account,&case.request.connector]).await.unwrap().get(0);
        assert_eq!(actual.as_bytes(), stored);
        Self {
            case,
            statement,
            read_grant,
        }
    }
    async fn issue(&mut self) -> service::IssuedCredential {
        self.issue_with_lifetime(60000).await
    }
    async fn bind_workflow_request(&mut self, original: Uuid) {
        self.case.request.original_grant_id = Some(original);
        let expires: i64 = self
            .case
            .f
            .db
            .query_one(
                "SELECT expires_ms FROM original_reply_grants WHERE account_id=$1 AND grant_id=$2",
                &[&self.case.f.account, &original],
            )
            .await
            .unwrap()
            .get(0);
        self.case.request.expires_ms = self.case.request.expires_ms.min(expires);
    }
    async fn issue_with_lifetime(&mut self, lifetime: i64) -> service::IssuedCredential {
        let reader = self.statement.integration_readers[0].key_id;
        let now: i64 = self
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
        let code = self.case.fresh_factor().await;
        service::issue(
            &mut self.case.f.connect().await,
            &self.case.owner,
            &self.case.hasher,
            &self.case.cipher,
            &self.case.password,
            &code,
            &service::GrantRequest {
                interval_id: self.statement.interval,
                connector_id: self.case.request.connector,
                read_grant_id: self.read_grant,
                reader_key_id: reader,
                expires_at_ms: now + lifetime,
            },
        )
        .await
        .unwrap()
    }
}
#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original reader disposable schema"]
async fn original_reader_uses_phone_selected_grant_and_withdrawal_cannot_reissue_authority() {
    let mut f = OriginalCase::new().await;
    let issued = f.issue().await;
    let p = service::authenticate(&f.case.f.db, &f.case.hasher, &issued.token)
        .await
        .unwrap();
    let version: i64 = f
        .case
        .f
        .db
        .query_one(
            "SELECT version FROM sealed_manifest_authorities WHERE account_id=$1",
            &[&f.case.f.account],
        )
        .await
        .unwrap()
        .get(0);
    let proof = service::current(&mut f.case.f.connect().await, &p, version)
        .await
        .unwrap();
    assert_eq!(proof.interval_id, f.statement.interval);
    assert_eq!(proof.read_grant_id, f.read_grant);
    assert_eq!(
        proof.reader_id,
        context::decisions::descriptor::hex(&f.statement.integration_readers[0].key_id)
    );
    service::withdraw(
        &mut f.case.f.connect().await,
        &f.case.owner,
        issued.grant_id,
    )
    .await
    .unwrap();
    assert!(matches!(
        service::current(&mut f.case.f.connect().await, &p, version).await,
        Err(ConversationError::Forbidden)
    ));
    assert!(f.case.f.db.execute("UPDATE original_reply_grants SET revoked_ms=NULL WHERE account_id=$1 AND grant_id=$2",&[&f.case.f.account,&issued.grant_id]).await.is_err());
    let export = service::lifecycle::export(
        &mut f.case.f.connect().await,
        &f.case.owner,
        service::lifecycle::Section::Grants,
        None,
    )
    .await
    .unwrap();
    let bytes = serde_json::to_string(&export).unwrap();
    assert!(!bytes.contains("credential_hash"));
    assert!(!bytes.contains(issued.token.as_str()));
    assert_eq!(export.items.len(), 1);
    f.case.f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; original reader disposable schema"]
async fn original_source_tombstones_refuse_partial_source_and_action_deletion() {
    let f = OriginalCase::new().await;
    let descriptor = f.case.descriptor().await;
    let action = decisions::register(
        &mut f.case.f.connect().await,
        &f.case.owner,
        Uuid::new_v4(),
        descriptor,
    )
    .await
    .unwrap();
    f.case.f.db.execute("INSERT INTO original_reply_sources(account_id,action_id,revision,binding_digest,source_grant_id,source_event_id,request_id,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",&[&f.case.f.account,&action.key.action_id,&action.key.revision,&action.key.binding_digest.as_slice(),&Uuid::new_v4(),&Uuid::new_v4(),&Uuid::new_v4(),&f.case.header.expires_ms]).await.unwrap();
    let mut client = f.case.f.connect().await;
    let tx = client.transaction().await.unwrap();
    assert_eq!(
        tx.execute(
            "DELETE FROM original_reply_sources WHERE account_id=$1",
            &[&f.case.f.account]
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        tx.commit().await.unwrap_err().code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM original_reply_sources WHERE account_id=$1",
                &[&f.case.f.account]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    // Even deleting the associated action cannot shed provenance while the account lives.
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "DELETE FROM original_reply_sources WHERE account_id=$1",
        &[&f.case.f.account],
    )
    .await
    .unwrap();
    for table in [
        "workflow_action_mutations",
        "workflow_action_versions",
        "workflow_actions",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE account_id=$1"),
            &[&f.case.f.account],
        )
        .await
        .unwrap();
    }
    assert_eq!(
        tx.commit().await.unwrap_err().code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert_eq!(
        f.case
            .f
            .db
            .query_one(
                "SELECT count(*) FROM workflow_actions WHERE account_id=$1 AND id=$2",
                &[&f.case.f.account, &action.key.action_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    f.case.f.cleanup().await;
}

mod network;

mod join_order;
mod races;
mod registry_binding;
mod routines;

mod join_order;
mod key_deadlines;
