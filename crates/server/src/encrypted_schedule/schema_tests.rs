// SPDX-License-Identifier: AGPL-3.0-only
//! Focused tests execute the actual migration against dependency interfaces.
//! The false decision predicate cannot authorize effects. These focused
//! schema tests do not establish real authorization or runtime readiness.
use super::policy::WindowPolicy;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

struct Schema {
    db: Client,
    name: String,
}
impl Schema {
    async fn new() -> Self {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("disposable database");
        let (db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let name = format!("schedule_schema_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!("CREATE SCHEMA {name}; SET search_path TO {name};"))
            .await
            .unwrap();
        db.batch_execute("CREATE TABLE accounts(id uuid PRIMARY KEY,disabled_at timestamptz);
            CREATE TABLE users(id uuid,email_verified_at timestamptz);
            CREATE TABLE memberships(account_id uuid,user_id uuid,role text,revoked_at timestamptz);
            CREATE TABLE sessions(id uuid,account_id uuid,user_id uuid,revoked_at timestamptz,expires_at timestamptz);
            CREATE TABLE message_attempts(account_id uuid,message_id uuid);
            CREATE TABLE dispatch_fences(account_id uuid,message_id uuid);
            CREATE TABLE message_events(account_id uuid,message_id uuid,evidence_code text);
            CREATE TABLE workflow_context_versions(account_id uuid,context_id uuid,revision bigint,PRIMARY KEY(account_id,context_id,revision));
            CREATE TABLE workflow_routines(account_id uuid,id uuid,PRIMARY KEY(account_id,id));
            CREATE TABLE workflow_actions(account_id uuid,id uuid,revision bigint,binding_digest bytea,context_id uuid,routine_id uuid,phase text);
            CREATE TABLE workflow_action_versions(account_id uuid,action_id uuid,revision bigint,binding_digest bytea,content_version bigint,authority_generation bigint,not_before_ms bigint,expires_at_ms bigint,UNIQUE(account_id,action_id,revision,binding_digest));
            CREATE TABLE workflow_message_links(account_id uuid,action_id uuid,revision bigint,binding_digest bytea,message_id uuid,dispatch_id uuid);
            CREATE TABLE messages(account_id uuid,id uuid,workflow_action_id uuid);
            CREATE FUNCTION workflow_effect_current(uuid,uuid) RETURNS boolean LANGUAGE sql AS 'SELECT false';")
            .await.unwrap();
        db.batch_execute(include_str!(
            "../../../../deploy/compose/migrations/077_encrypted_schedule.sql"
        ))
        .await
        .unwrap();
        Self { db, name }
    }
    async fn cleanup(self) {
        self.db
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.name))
            .await
            .unwrap();
    }
    async fn policy(
        &self,
        account: Uuid,
        p: &WindowPolicy,
        identity: &str,
    ) -> Result<u64, tokio_postgres::Error> {
        self.db.execute("INSERT INTO workflow_schedule_policies(account_id,id,timezone,first_local_date,opens_minute,closes_minute,repeat_every_days,max_occurrences,pacing_seconds) VALUES($1,$2,$3,$4::text::date,$5,$6,$7,$8,$9)",
            &[&account,&identity,&p.timezone,&p.first_local_date,&(p.opens_minute as i16),&(p.closes_minute as i16),&p.repeat_every_days.map(|v|v as i16),&(p.max_occurrences as i16),&(p.pacing_seconds as i32)]).await
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated synthetic schema"]
async fn stored_policy_matches_canonical_identity_and_cannot_be_changed() {
    let f = Schema::new().await;
    let account = Uuid::new_v4();
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    let p = WindowPolicy {
        timezone: Some("UTC".into()),
        first_local_date: "2027-01-01".into(),
        opens_minute: 540,
        closes_minute: 1020,
        repeat_every_days: Some(1),
        max_occurrences: 3,
        pacing_seconds: 60,
    };
    let identity = p.identity().unwrap();
    f.policy(account, &p, &identity).await.unwrap();
    let changed = WindowPolicy {
        pacing_seconds: 61,
        ..p.clone()
    };
    assert_eq!(
        f.policy(account, &changed, &identity)
            .await
            .unwrap_err()
            .code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    assert!(
        f.db.execute(
            "UPDATE workflow_schedule_policies SET timezone='Europe/London' WHERE account_id=$1",
            &[&account]
        )
        .await
        .is_err()
    );
    assert!(
        !f.db
            .query_one(
                "SELECT workflow_effect_current($1,$2)",
                &[&account, &Uuid::new_v4()]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    f.db.execute("DELETE FROM accounts WHERE id=$1", &[&account])
        .await
        .unwrap();
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM workflow_schedule_policies", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated synthetic schema"]
async fn occurrence_identity_and_terminal_state_cannot_be_reused_or_reactivated() {
    let f = Schema::new().await;
    let account = Uuid::new_v4();
    let context = Uuid::new_v4();
    let routine = Uuid::new_v4();
    let action = Uuid::new_v4();
    let series = Uuid::new_v4();
    let occurrence = Uuid::new_v4();
    let request = Uuid::new_v4();
    let dispatch = Uuid::new_v4();
    let digest = vec![3u8; 32];
    f.db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    f.db.execute(
        "INSERT INTO workflow_context_versions VALUES($1,$2,1)",
        &[&account, &context],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO workflow_routines VALUES($1,$2)",
        &[&account, &routine],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO workflow_actions VALUES($1,$2,1,$3,$4,$5,'approved')",
        &[&account, &action, &digest, &context, &routine],
    )
    .await
    .unwrap();
    f.db.execute(
        "INSERT INTO workflow_action_versions VALUES($1,$2,1,$3,1,1,1,2)",
        &[&account, &action, &digest],
    )
    .await
    .unwrap();
    let p = WindowPolicy {
        timezone: Some("UTC".into()),
        first_local_date: "2027-01-01".into(),
        opens_minute: 540,
        closes_minute: 1020,
        repeat_every_days: Some(1),
        max_occurrences: 3,
        pacing_seconds: 60,
    };
    let policy = p.identity().unwrap();
    f.policy(account, &p, &policy).await.unwrap();
    f.db.execute("INSERT INTO workflow_schedule_series(account_id,id,policy_id,context_id,context_revision,routine_id,routine_generation) VALUES($1,$2,$3,$4,1,$5,1)", &[&account,&series,&policy,&context,&routine]).await.unwrap();
    let insert = "INSERT INTO workflow_schedule_occurrences(account_id,id,series_id,ordinal,action_id,action_revision,binding_digest,request_id,request_digest,dispatch_id,not_before_ms,expires_at_ms,phase,actor_kind,actor_id,owner_session_id) VALUES($1,$2,$3,0,$4,1,$5,$6,$5,$7,1,2,'expired','owner',$6,$7)";
    f.db.execute(
        insert,
        &[
            &account,
            &occurrence,
            &series,
            &action,
            &digest,
            &request,
            &dispatch,
        ],
    )
    .await
    .unwrap();
    assert!(
        f.db.execute(
            insert,
            &[
                &account,
                &Uuid::new_v4(),
                &series,
                &action,
                &digest,
                &request,
                &dispatch
            ]
        )
        .await
        .is_err()
    );
    assert_eq!(f.db.execute("UPDATE workflow_schedule_occurrences SET phase='waiting_window',opens_at_ms=1,closes_at_ms=2 WHERE account_id=$1",&[&account]).await.unwrap_err().code(),Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION));
    assert!(
        f.db.execute(
            "UPDATE workflow_schedule_series SET routine_generation=2 WHERE account_id=$1",
            &[&account]
        )
        .await
        .is_err()
    );
    f.db.execute("INSERT INTO workflow_schedule_audit(account_id,id,occurrence_id,request_id,request_digest,actor_kind,actor_id,operation,result) VALUES($1,$2,$3,$2,$4,'system',NULL,'expire','expired')",&[&account,&Uuid::new_v4(),&occurrence,&digest]).await.unwrap();
    assert!(
        f.db.execute(
            "UPDATE workflow_schedule_audit SET result='claimed' WHERE account_id=$1",
            &[&account]
        )
        .await
        .is_err()
    );
    f.db.execute("DELETE FROM accounts WHERE id=$1", &[&account])
        .await
        .unwrap();
    for table in [
        "workflow_schedule_occurrences",
        "workflow_schedule_series",
        "workflow_schedule_policies",
        "workflow_schedule_audit",
    ] {
        assert_eq!(
            f.db.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    f.cleanup().await;
}
