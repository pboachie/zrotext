// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use tokio_postgres::{Config, NoTls, error::SqlState};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn writer_installation_refuses_unreviewed_preexisting_graph_without_blessing_or_partial_ledger()
 {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    let (admin, connection) = config.connect(NoTls).await.unwrap();
    let admin_driver = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let database = format!("zt_writer_install_{suffix}");
    let role = format!("zt_writer_install_owner_{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",escape_identifier(&role),escape_literal(&verifier))).await.unwrap();
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {} OWNER {}",
            escape_identifier(&database),
            escape_identifier(&role)
        ))
        .await
        .unwrap();
    config.dbname(&database).user(&role).password(&password);
    let (mut owner, connection) = config.connect(NoTls).await.unwrap();
    let owner_driver = tokio::spawn(connection);
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let all_migrations = read_migrations(&directory).unwrap();
    let position = all_migrations
        .iter()
        .position(|migration| migration.version == 108)
        .unwrap();
    assert_eq!(
        apply_locked(&mut owner, &all_migrations[..position], false)
            .await
            .unwrap()
            .last()
            .unwrap()
            .version,
        107
    );
    let migrations = &all_migrations[..=position];
    let original_budget =
        include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql").replace(
            "CREATE FUNCTION auth_abuse_consume(",
            "CREATE OR REPLACE FUNCTION public.auth_abuse_consume(",
        );
    let changed_budget = original_budget.replace("RETURN true;", "RETURN false;");
    assert_ne!(original_budget, changed_budget);
    let mut mutations=vec![
        ("CREATE TABLE public.unknown_writer(id uuid)".to_owned(),"DROP TABLE public.unknown_writer".to_owned()),
        ("ALTER TABLE public.devices ADD COLUMN unreviewed boolean".to_owned(),"ALTER TABLE public.devices DROP COLUMN unreviewed".to_owned()),
        ("ALTER TABLE public.devices ADD CONSTRAINT unreviewed CHECK(true)".to_owned(),"ALTER TABLE public.devices DROP CONSTRAINT unreviewed".to_owned()),
        ("ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY".to_owned(),"ALTER TABLE public.devices DISABLE ROW LEVEL SECURITY".to_owned()),
        ("CREATE INDEX unreviewed ON public.devices(display_name)".to_owned(),"DROP INDEX public.unreviewed".to_owned()),
        ("ALTER TABLE public.payload_profile_account_anchors DISABLE TRIGGER payload_profile_anchor_before_change".to_owned(),"ALTER TABLE public.payload_profile_account_anchors ENABLE TRIGGER payload_profile_anchor_before_change".to_owned()),
        ("GRANT UPDATE ON public.devices TO PUBLIC".to_owned(),"REVOKE ALL ON public.devices FROM PUBLIC".to_owned()),
    ];
    // Change one stored body only. PostgreSQL must retain the changed bytes;
    // client line-ending conversion must not turn this into an unchanged control.
    mutations.push((r#"DO $mutation$
DECLARE original_definition text; original_body text; changed_body text; stored_body text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(p.oid), p.prosrc
      INTO original_definition, original_body
      FROM pg_catalog.pg_proc p
     WHERE p.oid='public.auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)'::regprocedure;
    IF pg_catalog.strpos(original_body, pg_catalog.chr(13)) > 0 THEN
        changed_body := pg_catalog.replace(original_body, pg_catalog.chr(13)||pg_catalog.chr(10), pg_catalog.chr(10));
    ELSE
        changed_body := pg_catalog.replace(original_body, pg_catalog.chr(10), pg_catalog.chr(13)||pg_catalog.chr(10));
    END IF;
    IF original_body=changed_body THEN RAISE EXCEPTION 'mixed-ending control did not change body'; END IF;
    EXECUTE pg_catalog.replace(original_definition,original_body,changed_body);
    SELECT prosrc INTO stored_body FROM pg_catalog.pg_proc
     WHERE oid='public.auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)'::regprocedure;
    IF stored_body<>changed_body THEN RAISE EXCEPTION 'mixed-ending control was not retained'; END IF;
END $mutation$"#.to_owned(), original_budget.clone()));
    mutations.push((r#"DO $mutation$
DECLARE original_definition text; original_body text; changed_body text;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(p.oid), p.prosrc
      INTO original_definition, original_body
      FROM pg_catalog.pg_proc p
     WHERE p.oid='public.auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)'::regprocedure;
    changed_body := pg_catalog.replace(original_body,'global budget exhausted','global'||pg_catalog.chr(13)||' budget exhausted');
    IF original_body=changed_body THEN RAISE EXCEPTION 'quoted-CR control did not change body'; END IF;
    EXECUTE pg_catalog.replace(original_definition,original_body,changed_body);
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc
        WHERE oid='public.auth_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)'::regprocedure
          AND pg_catalog.strpos(prosrc,'global'||pg_catalog.chr(13)||' budget exhausted')>0)
    THEN RAISE EXCEPTION 'quoted-CR control was not retained'; END IF;
END $mutation$"#.to_owned(), original_budget.clone()));
    mutations.push((changed_budget, original_budget));
    for (mutation, restore) in mutations {
        owner.batch_execute(&mutation).await.unwrap();
        let error = apply_locked(&mut owner, migrations, false)
            .await
            .unwrap_err();
        assert!(
            matches!(error,MigrationError::Database(ref db) if db.code()==Some(&SqlState::CHECK_VIOLATION)),
            "{error}"
        );
        assert!(
            owner
                .query_one(
                    "SELECT max(version)=107 AND count(*)=107 FROM public.schema_migrations",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        assert!(owner.query_one("SELECT pg_catalog.to_regprocedure('public.payload_profile_writer_json(json)') IS NULL AND pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NULL", &[]).await.unwrap().get::<_,bool>(0));
        owner.batch_execute(&restore).await.unwrap();
    }
    assert_eq!(
        apply_locked(&mut owner, migrations, false)
            .await
            .unwrap()
            .last()
            .unwrap()
            .version,
        108
    );
    assert!(
        apply_locked(&mut owner, migrations, false)
            .await
            .unwrap()
            .is_empty()
    );
    let original_ready: String = owner.query_one("SELECT pg_catalog.pg_get_functiondef('public.payload_profile_writer_ready()'::regprocedure)", &[]).await.unwrap().get(0);
    let provision:String=owner.query_one("SELECT pg_catalog.pg_get_functiondef('public.review_workspace_provision(uuid,uuid,uuid,bigint,bytea,bytea,text)'::regprocedure)", &[]).await.unwrap().get(0);
    let changed_provision = provision.replacen("user_id uuid", "user_id text", 1);
    assert_ne!(changed_provision, provision);
    let changed_provision = format!(
        "DROP FUNCTION public.review_workspace_provision(uuid,uuid,uuid,bigint,bytea,bytea,text); {changed_provision}; REVOKE ALL ON FUNCTION public.review_workspace_provision(uuid,uuid,uuid,bigint,bytea,bytea,text) FROM PUBLIC"
    );
    for (mutation, restore) in [
        ("CREATE RULE unreviewed AS ON UPDATE TO public.devices DO INSTEAD NOTHING".to_owned(),"DROP RULE unreviewed ON public.devices".to_owned()),
        ("CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'".to_owned(),original_ready),
        (changed_provision,format!("DROP FUNCTION public.review_workspace_provision(uuid,uuid,uuid,bigint,bytea,bytea,text); {provision}; REVOKE ALL ON FUNCTION public.review_workspace_provision(uuid,uuid,uuid,bigint,bytea,bytea,text) FROM PUBLIC")),
    ] {
        owner.batch_execute(&mutation).await.unwrap();
        let error=apply_locked(&mut owner,&all_migrations,false).await.unwrap_err();
        assert!(matches!(error,MigrationError::Database(ref db) if db.code()==Some(&SqlState::CHECK_VIOLATION)),"{error}");
        assert!(owner.query_one("SELECT max(version)=108 AND count(*)=108 FROM public.schema_migrations", &[]).await.unwrap().get::<_,bool>(0));
        assert!(owner.query_one("SELECT pg_catalog.to_regprocedure('public.payload_profile_v2_ready()') IS NULL AND pg_catalog.to_regclass('public.payload_profile_v2_activation_receipts') IS NULL", &[]).await.unwrap().get::<_,bool>(0));
        owner.batch_execute(&restore).await.unwrap();
    }
    assert_eq!(
        apply_locked(&mut owner, &all_migrations, false)
            .await
            .unwrap()
            .last()
            .unwrap()
            .version,
        109
    );
    assert!(
        apply_locked(&mut owner, &all_migrations, false)
            .await
            .unwrap()
            .is_empty()
    );
    drop(owner);
    tokio::time::timeout(std::time::Duration::from_secs(5), owner_driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    admin
        .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&database)))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("DROP ROLE {}", escape_identifier(&role)))
        .await
        .unwrap();
    drop(admin);
    tokio::time::timeout(std::time::Duration::from_secs(5), admin_driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
