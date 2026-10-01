// SPDX-License-Identifier: AGPL-3.0-only
use super::super::*;
use crate::auth::{self, ApiKeyLifetime, SessionPrincipal};
use tokio_postgres::NoTls;

struct Fixture {
    setup: Client,
    db: Client,
    schema: String,
    hasher: TokenHasher,
    owner: SessionPrincipal,
    password: String,
    device: Uuid,
    line: Uuid,
    connector: Uuid,
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn owner_session_expiry_during_withdrawal_rolls_back_grant_and_key() {
    let mut outcomes = Vec::new();
    for takeover in [false, true] {
        let mut f = Fixture::new().await;
        let key = f.key().await;
        let grant = f.attach(key.id, 60_000).await;
        f.db.batch_execute("CREATE FUNCTION delay_agent_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER delay_agent_withdrawal BEFORE UPDATE ON agent_authority_grants FOR EACH ROW EXECUTE FUNCTION delay_agent_withdrawal();").await.unwrap();
        f.db.execute(
            "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
            &[&f.owner.session_id],
        )
        .await
        .unwrap();
        let result = revoke(
            &mut f.db,
            None,
            &f.hasher,
            OwnerProof {
                owner: &f.owner,
                password: &f.password,
                code: None,
            },
            grant,
            takeover,
        )
        .await;
        let unchanged = f.db.query_one("SELECT g.revoked_ms IS NULL AND g.taken_over_ms IS NULL AND k.revoked_at IS NULL FROM agent_authority_grants g JOIN api_keys k ON k.id=g.api_key_id WHERE g.grant_id=$1", &[&grant]).await.unwrap().get::<_, bool>(0);
        outcomes.push((
            takeover,
            matches!(result, Err(AuthError::Unauthorized)),
            unchanged,
        ));
        f.close().await;
    }
    assert!(
        outcomes
            .iter()
            .all(|(_, denied, unchanged)| *denied && *unchanged),
        "every expired withdrawal must roll back: {outcomes:?}"
    );
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn owner_session_expiry_during_inventory_read_withholds_grant_history() {
    let mut f = Fixture::new().await;
    let key = f.key().await;
    f.attach(key.id, 60_000).await;
    let held = f.setup.transaction().await.unwrap();
    held.batch_execute(&format!(
        "LOCK TABLE {}.agent_authority_grants IN ACCESS EXCLUSIVE MODE",
        f.schema
    ))
    .await
    .unwrap();
    f.db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1",
        &[&f.owner.session_id],
    )
    .await
    .unwrap();
    let read = list(&f.db, &f.owner, None);
    let release = async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        held.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(read, release);
    let denied = matches!(result, Err(AuthError::Unauthorized));
    f.close().await;
    assert!(
        denied,
        "the delayed inventory must not release grants after owner session expiry"
    );
}
impl Fixture {
    async fn new() -> Self {
        let base =
            std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable database required");
        let (setup, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("agent_credential_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        crate::auth::test_schema::apply(&db).await;
        let hasher = TokenHasher::new(crate::test_keys::key(77)).unwrap();
        let password = Uuid::new_v4().to_string();
        let signup = auth::register(&mut db, &hasher, "agent-owner@example.test", &password)
            .await
            .unwrap();
        auth::verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let credentials = auth::login(&db, &hasher, "agent-owner@example.test", &password)
            .await
            .unwrap();
        let owner = auth::authenticate_session(&db, &hasher, &credentials.token)
            .await
            .unwrap();
        let account = owner.tenant.account_id();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        let connector = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic')",
            &[&device, &account],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
            &[&line, &account],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) VALUES($1,$2,$3,1,'sealed')",&[&account,&line,&device]).await.unwrap();
        let now: i64 = db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        db.execute("INSERT INTO connector_registrations(account_id,connector_id,display_name,state,key_point,key_id,manifest_generation,manifest_version,manifest_digest,proposed_by_user,proposed_session,proposed_ms,expires_ms) VALUES($1,$2,'synthetic','pending',$3,$4,1,1,$4,$5,$6,$7,$8)",&[&account,&connector,&vec![4u8;65],&vec![1u8;32],&owner.user_id,&owner.session_id,&now,&(now+60_000)]).await.unwrap();
        Self {
            setup,
            db,
            schema,
            hasher,
            owner,
            password,
            device,
            line,
            connector,
        }
    }
    async fn key(&mut self) -> auth::ApiKeyCredentials {
        auth::create_api_key(
            &mut self.db,
            &self.hasher,
            &self.owner,
            &[Scope::MessagesSend, Scope::MessagesRead],
            Some(self.device),
            ApiKeyLifetime::Days(1),
        )
        .await
        .unwrap()
    }
    async fn attach(&self, key: Uuid, expiry_offset: i64) -> Uuid {
        let grant = Uuid::new_v4();
        let account = self.owner.tenant.account_id();
        let now: i64 = self
            .db
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let created = now - 120_000;
        self.db.execute("INSERT INTO agent_authority_grants(account_id,grant_id,api_key_id,connector_id,connector_key_id,signer_key_id,device_id,line_id,binding_generation,recipient_digest,metadata_allowed,content_allowed,draft_allowed,send_allowed,owner_self_notification,created_by_user,created_session,created_ms,expires_ms,message_limit,turn_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$5,true,false,false,false,true,$9,$10,$11,$12,1,1)",&[&account,&grant,&key,&self.connector,&vec![1u8;32],&vec![2u8;32],&self.device,&self.line,&self.owner.user_id,&self.owner.session_id,&created,&(now+expiry_offset)]).await.unwrap();
        grant
    }
    async fn close(self) {
        drop(self.db);
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn linked_agent_key_never_downgrades_to_ordinary_api_authority() {
    let mut f = Fixture::new().await;
    let key = f.key().await;
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key.token)
            .await
            .is_ok()
    );
    let grant = f.attach(key.id, 60_000).await;
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key.token)
            .await
            .is_err()
    );
    let agent = authenticate_agent(&f.db, &f.hasher, &key.token)
        .await
        .unwrap();
    assert_eq!(agent.grant_id(), grant);
    assert_eq!(agent.device_id(), f.device);
    assert!(agent.require(Operation::Metadata).is_ok());
    for operation in [Operation::ReadContent, Operation::Draft, Operation::Send] {
        assert!(agent.require(operation).is_err());
    }
    f.db.execute(
        "UPDATE agent_authority_grants SET revoked_ms=1 WHERE grant_id=$1",
        &[&grant],
    )
    .await
    .unwrap();
    assert!(
        authenticate_agent(&f.db, &f.hasher, &key.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key.token)
            .await
            .is_err()
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses an isolated disposable schema"]
async fn expired_taken_over_and_stale_owner_agent_credentials_are_rejected() {
    let mut f = Fixture::new().await;
    let expired = f.key().await;
    f.attach(expired.id, -1).await;
    assert!(
        authenticate_agent(&f.db, &f.hasher, &expired.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &expired.token)
            .await
            .is_err()
    );
    let key = f.key().await;
    let grant = f.attach(key.id, 60_000).await;
    let wrong = auth::random_token("ztk_");
    assert!(authenticate_agent(&f.db, &f.hasher, &wrong).await.is_err());
    revoke(
        &mut f.db,
        None,
        &f.hasher,
        OwnerProof {
            owner: &f.owner,
            password: &f.password,
            code: None,
        },
        grant,
        true,
    )
    .await
    .unwrap();
    assert!(
        authenticate_agent(&f.db, &f.hasher, &key.token)
            .await
            .is_err()
    );
    assert!(
        auth::authenticate_api_key(&f.db, &f.hasher, &key.token)
            .await
            .is_err()
    );
    let fresh = f.key().await;
    f.attach(fresh.id, 60_000).await;
    f.db.execute(
        "UPDATE users SET email_verified_at=NULL WHERE id=$1",
        &[&f.owner.user_id],
    )
    .await
    .unwrap();
    assert!(
        authenticate_agent(&f.db, &f.hasher, &fresh.token)
            .await
            .is_err()
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; uses isolated disposable schemas"]
async fn grant_pages_are_bounded_complete_keyset_ordered_and_tenant_bound() {
    let mut f = Fixture::new().await;
    for _ in 0..101 {
        let key = f.key().await;
        f.attach(key.id, 60_000).await;
    }
    let expected: Vec<Uuid> = f.db.query("SELECT grant_id FROM agent_authority_grants WHERE account_id=$1 ORDER BY created_ms DESC,grant_id DESC", &[&f.owner.tenant.account_id()]).await.unwrap().into_iter().map(|row| row.get(0)).collect();
    let first = list(&f.db, &f.owner, None).await.unwrap().unwrap();
    assert_eq!(first.grants.len(), 100);
    assert!(first.truncated);
    assert_eq!(first.next_cursor, Some(expected[99]));
    assert_eq!(
        first
            .grants
            .iter()
            .map(|grant| grant.grant_id)
            .collect::<Vec<_>>(),
        expected[..100]
    );
    let second = list(&f.db, &f.owner, first.next_cursor)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.grants.len(), 1);
    assert_eq!(second.grants[0].grant_id, expected[100]);
    assert!(!second.truncated);
    assert!(second.next_cursor.is_none());
    let empty = list(&f.db, &f.owner, Some(expected[100]))
        .await
        .unwrap()
        .unwrap();
    assert!(empty.grants.is_empty());
    assert!(!empty.truncated);
    assert!(
        list(&f.db, &f.owner, Some(Uuid::new_v4()))
            .await
            .unwrap()
            .is_none()
    );
    let mut foreign = Fixture::new().await;
    let foreign_key = foreign.key().await;
    let foreign_grant = foreign.attach(foreign_key.id, 60_000).await;
    assert!(
        list(&f.db, &f.owner, Some(foreign_grant))
            .await
            .unwrap()
            .is_none()
    );
    let encoded = serde_json::to_value(first).unwrap();
    for view in encoded["grants"].as_array().unwrap() {
        for field in ["token", "recipient", "recipient_digest", "token_hash"] {
            assert!(view.get(field).is_none());
        }
    }
    foreign.close().await;
    f.close().await;
}
