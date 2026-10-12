// SPDX-License-Identifier: AGPL-3.0-only
//! Storage-contract controls only. Synthetic bytes are not verified signatures,
//! authenticated transport admissions or observations of real SIM hardware.
use super::*;
use tokio_postgres::error::SqlState;

struct Case {
    setup: Client,
    schema: String,
    url: String,
    db: Client,
    account: Uuid,
    user: Uuid,
    session: Uuid,
    device: Uuid,
    line: Uuid,
}

impl Case {
    async fn new(purpose: &str, before_versioned_schema: bool) -> Self {
        let last = before_versioned_schema.then_some("094_line_activation_protocol_version.sql");
        let (setup, schema, url, mut db) = migrated_schema_through("line_schema", last).await;
        let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
        let owner = owner(&mut db, &hasher, "schema-owner@example.test").await;
        let row = db
            .query_one(
                "SELECT id,user_id FROM sessions WHERE account_id=$1",
                &[&owner.account_id],
            )
            .await
            .unwrap();
        let device = Uuid::new_v4();
        let line = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic schema device')",
            &[&device, &owner.account_id],
        ).await.unwrap();
        db.execute(
            "INSERT INTO phone_lines(id,account_id,last_issued_generation) VALUES($1,$2,1)",
            &[&line, &owner.account_id],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) VALUES($1,$2,$3,1,$4)",
            &[&owner.account_id, &line, &device, &purpose],
        ).await.unwrap();
        db.batch_execute("INSERT INTO sites(site_id) VALUES('schema-site')")
            .await
            .unwrap();
        db.execute(
            "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES($1,$2,'schema-site','schema-instance',1,clock_timestamp()+interval '10 minutes',1)",
            &[&device, &owner.account_id],
        ).await.unwrap();
        Self {
            setup,
            schema,
            url,
            db,
            account: owner.account_id,
            user: row.get(1),
            session: row.get(0),
            device,
            line,
        }
    }

    async fn challenge(&self, version: i16) -> Uuid {
        let id = Uuid::new_v4();
        let nonce = digest(id.as_bytes());
        self.db.execute(
            "INSERT INTO line_activation_challenges(id,account_id,line_id,device_id,generation,nonce_digest,expires_at,protocol_version) VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '10 minutes',$6)",
            &[&id, &self.account, &self.line, &self.device, &&nonce[..], &version],
        ).await.unwrap();
        id
    }

    fn pending(&self, challenge: Uuid, opening: Uuid, purpose: &str) -> String {
        self.pending_registered(challenge, opening, purpose, None)
    }

    fn pending_registered(
        &self,
        challenge: Uuid,
        opening: Uuid,
        purpose: &str,
        registration: Option<Uuid>,
    ) -> String {
        let registration = registration.map_or_else(|| "NULL".to_owned(), |id| format!("'{id}'"));
        format!(
            "INSERT INTO line_activation_v2_pending(challenge_id,purpose,opening_id,account_id,line_id,device_id,generation,initiating_user_id,initiating_session_id,registration_id,site_id,instance_id,connection_epoch,deployment_epoch,device_fingerprint,owner_fingerprint,nonce,expires_at) SELECT '{challenge}','{purpose}','{opening}','{}','{}','{}',1,'{}','{}',{registration},'schema-site','schema-instance',1,1,decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),expires_at FROM line_activation_challenges WHERE id='{challenge}'",
            self.account, self.line, self.device, self.user, self.session
        )
    }

    async fn registration(&self) -> Uuid {
        let id = Uuid::new_v4();
        self.db.execute("INSERT INTO line_owner_approval_keys(account_id,fingerprint,signing_key_sec1) VALUES($1,decode(repeat('22',32),'hex'),decode(repeat('01',65),'hex'))", &[&self.account]).await.unwrap();
        // Storage-only receipt: none of these synthetic bytes are crypto proofs.
        self.db.execute("INSERT INTO sealed_line_key_receipts(account_id,registration_id,user_id,session_id,device_id,line_id,generation,transcript,root_signature,approval_signature,approval_point,approval_fingerprint,paired_fingerprint,issued_ms,expires_ms,completed_ms) VALUES($1,$2,$3,$4,$5,$6,1,decode('01','hex'),decode(repeat('01',64),'hex'),decode(repeat('02',64),'hex'),decode(repeat('01',65),'hex'),decode(repeat('22',32),'hex'),decode(repeat('11',32),'hex'),1000,2000,1500)", &[&self.account,&id,&self.user,&self.session,&self.device,&self.line]).await.unwrap();
        id
    }

    async fn pending_sms(&self) -> Uuid {
        let id = self.challenge(2).await;
        self.db
            .batch_execute(&self.pending(id, Uuid::new_v4(), "sms"))
            .await
            .unwrap();
        id
    }

    fn observation(challenge: Uuid) -> String {
        format!(
            "INSERT INTO line_activation_v2_observations(challenge_id,purpose,account_id,line_id,device_id,generation,observation,device_signature_der,device_statement_sha256,device_signature_sha256,confirmation_digest,device_fingerprint,proof_site_id,proof_instance_id,proof_connection_epoch,proof_deployment_epoch) SELECT challenge_id,purpose,account_id,line_id,device_id,generation,decode(repeat('44',121),'hex'),decode(repeat('55',8),'hex'),decode(repeat('66',32),'hex'),decode(repeat('77',32),'hex'),decode(repeat('88',32),'hex'),device_fingerprint,site_id,instance_id,connection_epoch,deployment_epoch FROM line_activation_v2_pending WHERE challenge_id='{challenge}'"
        )
    }

    async fn cleanup(self) {
        // Only reached after a known completed control, never from Drop/panic.
        drop(self.db);
        self.setup
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

async fn rejects(db: &Client, sql: &str, code: &SqlState) {
    let error = db.batch_execute(sql).await.unwrap_err();
    assert_eq!(error.code(), Some(code), "{sql}");
}

async fn legacy_constraints(db: &Client) -> Vec<(String, String)> {
    db.query(
        "SELECT conrelid::regclass::text,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid IN(to_regclass('sms_line_activation_exchanges'),to_regclass('sealed_line_activation_exchanges'),to_regclass('line_activation_challenges')) ORDER BY conrelid::regclass::text,conname",
        &[],
    ).await.unwrap().into_iter().map(|r| (r.get(0), r.get(1))).collect()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; actual migration upgrade in isolated schema"]
async fn versioned_schema_upgrade_preserves_legacy_rows_defaults_and_contracts() {
    let c = Case::new("sms", true).await;
    let challenge = c.challenge(1).await;
    let before = legacy_constraints(&c.db).await;
    for (name, sql) in TEST_MIGRATIONS {
        if name.starts_with("095_") || name.starts_with("096_") {
            c.db.batch_execute(sql).await.unwrap();
        }
    }
    assert_eq!(legacy_constraints(&c.db).await, before);
    assert_eq!(
        c.db.query_one(
            "SELECT line_activation_version FROM device_sessions WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );
    assert_eq!(
        c.db.query_one(
            "SELECT protocol_version FROM line_activation_challenges WHERE id=$1",
            &[&challenge]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        1
    );
    for (table, columns, checks, foreign, unique, indexes, triggers) in [
        (
            "line_activation_v2_pending",
            24i64,
            14i64,
            4i64,
            2i64,
            5i64,
            2i64,
        ),
        ("line_activation_v2_observations", 18, 11, 1, 0, 1, 1),
    ] {
        let row = c.db.query_one(
            "SELECT (SELECT count(*) FROM pg_attribute WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped),(SELECT count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='c'),(SELECT count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='f'),(SELECT count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='u'),(SELECT count(*) FROM pg_index WHERE indrelid=to_regclass($1)),(SELECT count(*) FROM pg_trigger WHERE tgrelid=to_regclass($1) AND NOT tgisinternal)",
            &[&table],
        ).await.unwrap();
        for (position, expected) in [columns, checks, foreign, unique, indexes, triggers]
            .into_iter()
            .enumerate()
        {
            assert_eq!(row.get::<_, i64>(position), expected, "{table}");
        }
        assert_eq!(
            c.db.query_one(&format!("SELECT count(*) FROM {table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    let lease = c.db.query_one(
        "SELECT a.atttypid='smallint'::regtype,a.attnotnull,pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=to_regclass('device_sessions') AND a.attname='line_activation_version'",
        &[],
    ).await.unwrap();
    assert!(lease.get::<_, bool>(0) && lease.get::<_, bool>(1));
    assert!(matches!(
        lease.get::<_, String>(2).as_str(),
        "1" | "1::smallint"
    ));
    c.cleanup().await;
    // A second independent fixture replays every actual migration through096.
    Case::new("sms", false).await.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated versioned session schema"]
async fn session_version_changes_require_a_strictly_new_connection_epoch() {
    let c = Case::new("sms", false).await;
    for sql in [
        "UPDATE device_sessions SET line_activation_version=2",
        "UPDATE device_sessions SET line_activation_version=2,connection_epoch=1",
        "UPDATE device_sessions SET line_activation_version=2,connection_epoch=0",
        "UPDATE device_sessions SET line_activation_version=0",
        "UPDATE device_sessions SET line_activation_version=3",
    ] {
        rejects(&c.db, sql, &SqlState::CHECK_VIOLATION).await;
    }
    rejects(
        &c.db,
        "UPDATE device_sessions SET line_activation_version=NULL",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    rejects(
        &c.db,
        "UPDATE device_sessions SET line_activation_version=NULL,connection_epoch=2",
        &SqlState::NOT_NULL_VIOLATION,
    )
    .await;
    c.db.batch_execute("UPDATE device_sessions SET line_activation_version=2,connection_epoch=2; UPDATE device_sessions SET lease_until=clock_timestamp()+interval '20 minutes'").await.unwrap();
    let omitted_claim = format!(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES('{}','{}','schema-site','legacy-claim',1,clock_timestamp()+interval '10 minutes',1) ON CONFLICT(device_id) DO UPDATE SET connection_epoch=device_sessions.connection_epoch+1,lease_until=EXCLUDED.lease_until",
        c.device, c.account
    );
    c.db.batch_execute(&omitted_claim).await.unwrap();
    assert_eq!(
        c.db.query_one(
            "SELECT line_activation_version FROM device_sessions WHERE device_id=$1",
            &[&c.device]
        )
        .await
        .unwrap()
        .get::<_, i16>(0),
        2
    );
    rejects(
        &c.db,
        "UPDATE device_sessions SET line_activation_version=1",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    rejects(
        &c.db,
        "UPDATE device_sessions SET line_activation_version=1,connection_epoch=1",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    c.db.batch_execute("UPDATE device_sessions SET line_activation_version=1,connection_epoch=4")
        .await
        .unwrap();
    let sql = format!(
        "INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) VALUES('{}','{}','schema-site','legacy-claim',1,clock_timestamp()+interval '10 minutes',1) ON CONFLICT(device_id) DO UPDATE SET connection_epoch=device_sessions.connection_epoch+1,lease_until=EXCLUDED.lease_until",
        c.device, c.account
    );
    c.db.batch_execute(&sql).await.unwrap();
    let row = c.db.query_one("SELECT line_activation_version,connection_epoch FROM device_sessions WHERE device_id=$1", &[&c.device]).await.unwrap();
    assert_eq!(row.get::<_, i16>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 5);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated pending exchange schema"]
async fn pending_admission_binds_version_scope_original_session_and_opening() {
    let c = Case::new("sms", false).await;
    let legacy = c.challenge(1).await;
    rejects(
        &c.db,
        &c.pending(legacy, Uuid::new_v4(), "sms"),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    let challenge = c.challenge(2).await;
    let opening = Uuid::new_v4();
    let sql = c.pending(challenge, opening, "sms");
    for altered in [
        sql.replace(&c.line.to_string(), &Uuid::new_v4().to_string()),
        sql.replace(&c.account.to_string(), &Uuid::new_v4().to_string()),
        sql.replace(&c.device.to_string(), &Uuid::new_v4().to_string()),
        sql.replace("'sms'", "'sealed'"),
        sql.replace("expires_at FROM", "expires_at+interval '1 second' FROM"),
        sql.replace("decode(repeat('11',32)", "decode(repeat('11',31)"),
    ] {
        rejects(&c.db, &altered, &SqlState::CHECK_VIOLATION).await;
    }
    rejects(
        &c.db,
        &sql.replace(&c.session.to_string(), &Uuid::new_v4().to_string()),
        &SqlState::FOREIGN_KEY_VIOLATION,
    )
    .await;
    c.db.batch_execute(&sql).await.unwrap();
    rejects(&c.db, &sql, &SqlState::UNIQUE_VIOLATION).await;
    let second = c.challenge(2).await;
    rejects(
        &c.db,
        &c.pending(second, opening, "sms"),
        &SqlState::UNIQUE_VIOLATION,
    )
    .await;
    c.db.execute(
        "UPDATE line_activation_challenges SET consumed_at=clock_timestamp() WHERE id=$1",
        &[&second],
    )
    .await
    .unwrap();
    rejects(
        &c.db,
        &c.pending(second, Uuid::new_v4(), "sms"),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    let hasher = TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap();
    let (mut other_db, connection) = tokio_postgres::connect(&c.url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let other = owner(&mut other_db, &hasher, "other-schema-owner@example.test").await;
    let other_session = other_db
        .query_one(
            "SELECT id,user_id FROM sessions WHERE account_id=$1",
            &[&other.account_id],
        )
        .await
        .unwrap();
    let other_device = Uuid::new_v4();
    let other_line = Uuid::new_v4();
    let other_challenge = Uuid::new_v4();
    other_db.execute("INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'other synthetic device')", &[&other_device,&other.account_id]).await.unwrap();
    other_db
        .execute(
            "INSERT INTO phone_lines(id,account_id,last_issued_generation) VALUES($1,$2,1)",
            &[&other_line, &other.account_id],
        )
        .await
        .unwrap();
    other_db.execute("INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) VALUES($1,$2,$3,1,'sms')", &[&other.account_id,&other_line,&other_device]).await.unwrap();
    other_db.execute("INSERT INTO line_activation_challenges(id,account_id,line_id,device_id,generation,nonce_digest,expires_at,protocol_version) VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '10 minutes',2)", &[&other_challenge,&other.account_id,&other_line,&other_device,&&digest(other_challenge.as_bytes())[..]]).await.unwrap();
    let other_sql = c
        .pending(other_challenge, opening, "sms")
        .replace(&c.account.to_string(), &other.account_id.to_string())
        .replace(&c.line.to_string(), &other_line.to_string())
        .replace(&c.device.to_string(), &other_device.to_string())
        .replace(
            &c.user.to_string(),
            &other_session.get::<_, Uuid>(1).to_string(),
        )
        .replace(
            &c.session.to_string(),
            &other_session.get::<_, Uuid>(0).to_string(),
        );
    other_db.batch_execute(&other_sql).await.unwrap();
    drop(other_db);
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated immutable pending storage"]
async fn pending_identity_approval_and_retirement_cannot_be_replaced_or_reversed() {
    let c = Case::new("sms", false).await;
    let id = c.pending_sms().await;
    for sql in [
        "DELETE FROM line_activation_v2_pending",
        "UPDATE line_activation_v2_pending SET instance_id='replacement'",
        "UPDATE line_activation_v2_pending SET nonce=decode(repeat('99',32),'hex')",
        "UPDATE line_activation_v2_pending SET nonce=NULL",
        "UPDATE line_activation_v2_pending SET approved_at=clock_timestamp()",
        "UPDATE line_activation_v2_pending SET installed_at=clock_timestamp(),nonce=NULL",
    ] {
        rejects(&c.db, sql, &SqlState::CHECK_VIOLATION).await;
    }
    c.db.batch_execute("UPDATE line_activation_v2_pending SET approved_at=clock_timestamp(),owner_signature_sha256=decode(repeat('aa',32),'hex')").await.unwrap();
    for sql in [
        "UPDATE line_activation_v2_pending SET approved_at=approved_at+interval '1 second'",
        "UPDATE line_activation_v2_pending SET owner_signature_sha256=decode(repeat('bb',32),'hex')",
        "UPDATE line_activation_v2_pending SET installed_at=clock_timestamp(),nonce=NULL",
    ] {
        rejects(&c.db, sql, &SqlState::CHECK_VIOLATION).await;
    }
    c.db.batch_execute(
        "UPDATE line_activation_v2_pending SET retired_at=clock_timestamp(),nonce=NULL",
    )
    .await
    .unwrap();
    for sql in [
        "UPDATE line_activation_v2_pending SET nonce=decode(repeat('33',32),'hex')",
        "UPDATE line_activation_v2_pending SET retired_at=NULL",
        "UPDATE line_activation_v2_pending SET retired_at=retired_at+interval '1 second'",
        "UPDATE line_activation_v2_pending SET approved_at=NULL,owner_signature_sha256=NULL",
    ] {
        rejects(&c.db, sql, &SqlState::CHECK_VIOLATION).await;
    }
    assert_eq!(c.db.query_one("SELECT count(*) FROM line_activation_v2_pending WHERE challenge_id=$1 AND nonce IS NULL AND retired_at IS NOT NULL", &[&id]).await.unwrap().get::<_, i64>(0), 1);
    c.cleanup().await;
    let sealed = Case::new("sealed", false).await;
    let challenge = sealed.challenge(2).await;
    rejects(
        &sealed.db,
        &sealed.pending(challenge, Uuid::new_v4(), "sealed"),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    rejects(
        &sealed.db,
        &sealed.pending_registered(challenge, Uuid::new_v4(), "sealed", Some(Uuid::new_v4())),
        &SqlState::FOREIGN_KEY_VIOLATION,
    )
    .await;
    let registration = sealed.registration().await;
    sealed
        .db
        .batch_execute(&sealed.pending_registered(
            challenge,
            Uuid::new_v4(),
            "sealed",
            Some(registration),
        ))
        .await
        .unwrap();
    rejects(
        &sealed.db,
        "UPDATE line_activation_v2_pending SET installed_at=clock_timestamp(),nonce=NULL",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    sealed.db.batch_execute("UPDATE line_activation_v2_pending SET approved_at=clock_timestamp(),owner_signature_sha256=decode(repeat('aa',32),'hex'); UPDATE line_activation_v2_pending SET installed_at=clock_timestamp(),nonce=NULL").await.unwrap();
    rejects(
        &sealed.db,
        "UPDATE line_activation_v2_pending SET installed_at=NULL",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    rejects(
        &sealed.db,
        "UPDATE line_activation_v2_pending SET nonce=decode(repeat('33',32),'hex')",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    sealed.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated observation storage scope"]
async fn observation_admission_requires_live_pending_original_tuple_and_bounded_bytes() {
    let c = Case::new("sms", false).await;
    let id = c.pending_sms().await;
    let sql = Case::observation(id);
    for altered in [
        sql.replace("device_fingerprint,site_id,instance_id,connection_epoch,deployment_epoch FROM", "decode(repeat('99',32),'hex'),site_id,instance_id,connection_epoch,deployment_epoch FROM"),
        sql.replace("device_fingerprint,site_id,instance_id,connection_epoch,deployment_epoch FROM", "device_fingerprint,'other-site',instance_id,connection_epoch,deployment_epoch FROM"),
        sql.replace("device_fingerprint,site_id,instance_id,connection_epoch,deployment_epoch FROM", "device_fingerprint,site_id,'other-instance',connection_epoch,deployment_epoch FROM"),
        sql.replace("instance_id,connection_epoch,deployment_epoch FROM", "instance_id,connection_epoch+1,deployment_epoch FROM"),
        sql.replace("instance_id,connection_epoch,deployment_epoch FROM", "instance_id,connection_epoch,deployment_epoch+1 FROM"),
        sql.replace("repeat('44',121)", "repeat('44',120)"),
        sql.replace("repeat('55',8)", "repeat('55',7)"),
        sql.replace("repeat('66',32)", "repeat('66',31)"),
    ] {
        rejects(&c.db, &altered, &SqlState::CHECK_VIOLATION).await;
    }
    rejects(
        &c.db,
        &sql.replace(
            "SELECT challenge_id,purpose",
            "SELECT challenge_id,'sealed'",
        ),
        &SqlState::FOREIGN_KEY_VIOLATION,
    )
    .await;
    c.db.batch_execute(&sql).await.unwrap();
    let retired = c.pending_sms().await;
    c.db.execute("UPDATE line_activation_v2_pending SET retired_at=clock_timestamp(),nonce=NULL WHERE challenge_id=$1", &[&retired]).await.unwrap();
    rejects(
        &c.db,
        &Case::observation(retired),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    let approved = c.pending_sms().await;
    c.db.execute("UPDATE line_activation_v2_pending SET approved_at=clock_timestamp(),owner_signature_sha256=decode(repeat('aa',32),'hex') WHERE challenge_id=$1", &[&approved]).await.unwrap();
    rejects(
        &c.db,
        &Case::observation(approved),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    let consumed = c.pending_sms().await;
    c.db.execute(
        "UPDATE line_activation_challenges SET consumed_at=clock_timestamp() WHERE id=$1",
        &[&consumed],
    )
    .await
    .unwrap();
    rejects(
        &c.db,
        &Case::observation(consumed),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    let expired = Uuid::new_v4();
    c.db.execute("INSERT INTO line_activation_challenges(id,account_id,line_id,device_id,generation,nonce_digest,created_at,expires_at,protocol_version) VALUES($1,$2,$3,$4,1,$5,clock_timestamp()-interval '20 minutes',clock_timestamp()-interval '10 minutes',2)", &[&expired,&c.account,&c.line,&c.device,&&digest(expired.as_bytes())[..]]).await.unwrap();
    // Pending storage is permitted for an expired challenge; proof admission is not.
    c.db.batch_execute(&c.pending(expired, Uuid::new_v4(), "sms"))
        .await
        .unwrap();
    rejects(
        &c.db,
        &Case::observation(expired),
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    c.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated immutable observation history"]
async fn observation_history_survives_pending_retirement_and_refuses_replay_or_mutation() {
    let c = Case::new("sms", false).await;
    let id = c.pending_sms().await;
    let sql = Case::observation(id);
    c.db.batch_execute(&sql).await.unwrap();
    let before: Vec<u8> = c.db.query_one("SELECT convert_to(row_to_json(o)::text,'UTF8') FROM line_activation_v2_observations o WHERE challenge_id=$1", &[&id]).await.unwrap().get(0);
    rejects(&c.db, &sql, &SqlState::UNIQUE_VIOLATION).await;
    rejects(
        &c.db,
        "UPDATE line_activation_v2_observations SET proof_instance_id='replacement'",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    rejects(
        &c.db,
        "DELETE FROM line_activation_v2_observations",
        &SqlState::CHECK_VIOLATION,
    )
    .await;
    c.db.batch_execute(
        "UPDATE line_activation_v2_pending SET retired_at=clock_timestamp(),nonce=NULL",
    )
    .await
    .unwrap();
    let after: Vec<u8> = c.db.query_one("SELECT convert_to(row_to_json(o)::text,'UTF8') FROM line_activation_v2_observations o WHERE challenge_id=$1", &[&id]).await.unwrap().get(0);
    assert_eq!(after, before);
    c.cleanup().await;
}
