// SPDX-License-Identifier: AGPL-3.0-only
//! Actual numbered migrations and distinct ordinary login roles in public.
//! On panic, retain the unique fixture rather than force-drop unknown sessions.
use super::{LineActivationError, schema};
use std::{path::Path, time::Duration};
use tokio::{task::JoinHandle, time::timeout};
use tokio_postgres::{Client, Config, Error, NoTls};
use uuid::Uuid;

const FUNCTIONS: [&str; 3] = [
    "device_session_line_activation_version_guard",
    "line_activation_v2_pending_guard",
    "line_activation_v2_observation_guard",
];

async fn connect(config: &Config) -> (Client, JoinHandle<std::result::Result<(), Error>>) {
    let (db, connection) = config.connect(NoTls).await.unwrap();
    (db, tokio::spawn(connection))
}

async fn close(db: Client, driver: JoinHandle<std::result::Result<(), Error>>) {
    drop(db);
    timeout(Duration::from_secs(10), driver)
        .await
        .expect("fixture connection must finish before cleanup")
        .unwrap()
        .unwrap();
}

async fn identities(db: &Client) -> Vec<(u32, u32, Option<String>, bool, String)> {
    db.query(
        "SELECT oid,proowner,proacl::text,prosecdef,prosrc FROM pg_proc
         WHERE pronamespace='public'::regnamespace AND proname=ANY($1)
         ORDER BY proname",
        &[&&FUNCTIONS[..]],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
    .collect()
}

async fn ledger(db: &Client) -> String {
    db.query_one(
        "SELECT json_agg(m ORDER BY version)::text FROM public.schema_migrations m",
        &[],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster"]
async fn real_migrator_and_runtime_roles_accept_only_equivalent_guard_paths() {
    let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
    let mut config: Config = raw.parse().unwrap();
    config.connect_timeout(Duration::from_secs(10));
    let (admin, admin_driver) = connect(&config).await;
    let suffix = Uuid::new_v4().simple().to_string();
    // All interpolated identifiers and passwords are generated hex, never input.
    let name = format!("zt_guard_{suffix}");
    let migrator = format!("zt_guard_m_{suffix}");
    let runtime = format!("zt_guard_r_{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    // Send only a salted SCRAM verifier in DDL; the raw secret stays in the
    // connection configuration, never SQL text, logs or activity displays.
    let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
    assert!(verifier.starts_with("SCRAM-SHA-256$") && verifier != password);
    for role in [&migrator, &runtime] {
        admin
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN PASSWORD '{verifier}'
                 NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
            ))
            .await
            .unwrap();
        let stored: String = admin
            .query_one(
                "SELECT rolpassword FROM pg_authid WHERE rolname=$1",
                &[role],
            )
            .await
            .unwrap()
            .get(0);
        assert!(
            stored.starts_with("SCRAM-SHA-256$") && stored != password,
            "fixture credential must be stored as a SCRAM verifier"
        );
    }
    admin
        .batch_execute(&format!("CREATE DATABASE {name} OWNER {migrator}"))
        .await
        .unwrap();
    config.dbname(&name).user(&migrator).password(&password);
    let (mut owner, owner_driver) = connect(&config).await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    zrotext_migrator::apply(&mut owner, &directory, false)
        .await
        .unwrap();
    assert_eq!(
        owner
            .query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "public"
    );
    owner
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA public TO {runtime};
             GRANT SELECT ON public.payload_profile_writer_catalog,public.payload_profile_writer_global_fences TO {runtime};
             GRANT EXECUTE ON FUNCTION public.payload_profile_writer_json(json),public.payload_profile_writer_graph(),public.payload_profile_writer_version() TO {runtime}"
        ))
        .await
        .unwrap();
    config.user(&runtime);
    let (reader, reader_driver) = connect(&config).await;
    reader
        .batch_execute("SET search_path TO pg_catalog, public")
        .await
        .unwrap();
    for (db, expected) in [(&owner, &migrator), (&reader, &runtime)] {
        let row = db
            .query_one(
                "SELECT current_user::text,rolsuper,rolcreatedb,rolcreaterole
             FROM pg_roles WHERE rolname=current_user",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), *expected);
        assert!(!row.get::<_, bool>(1));
        assert!(!row.get::<_, bool>(2));
        assert!(!row.get::<_, bool>(3));
    }
    let installed = identities(&owner).await;
    assert_eq!(installed.len(), FUNCTIONS.len());
    let installed_ledger = ledger(&owner).await;
    let paths = owner
        .query(
            "SELECT proconfig FROM pg_proc WHERE pronamespace='public'::regnamespace
         AND proname=ANY($1)",
            &[&&FUNCTIONS[..]],
        )
        .await
        .unwrap();
    assert_eq!(paths.len(), FUNCTIONS.len());
    for row in paths {
        assert_eq!(row.get::<_, Vec<String>>(0), ["search_path=public"]);
    }
    schema::require_installed(&reader).await.unwrap();
    for function in FUNCTIONS {
        owner
            .batch_execute(&format!(
                "ALTER FUNCTION public.{function}() SET search_path TO pg_catalog, public"
            ))
            .await
            .unwrap();
        schema::require_lease(&reader).await.unwrap();
        schema::require_installed(&reader).await.unwrap();
        assert_eq!(identities(&owner).await, installed);
        assert_eq!(ledger(&owner).await, installed_ledger);
        let denied = reader
            .batch_execute(&format!(
                "ALTER FUNCTION public.{function}() SET search_path TO public"
            ))
            .await
            .unwrap_err();
        assert_eq!(
            denied.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
        );

        for setting in [
            "SET search_path TO pg_catalog, public, pg_temp",
            "SET search_path TO pg_catalog, public, foreign_schema",
            "SET search_path TO pg_catalog, foreign_schema",
            "SET search_path TO public, pg_catalog",
            "SET search_path TO pg_temp, public",
            "RESET search_path",
            "SET statement_timeout='1s'",
            "SECURITY DEFINER",
        ] {
            // Commit each mutation so the separate runtime login observes it.
            owner
                .batch_execute(&format!("ALTER FUNCTION public.{function}() {setting}"))
                .await
                .unwrap();
            assert!(
                matches!(
                    schema::require_installed(&reader).await,
                    Err(LineActivationError::Unavailable)
                ),
                "{function}: {setting}"
            );
            owner
                .batch_execute(&format!(
                    "ALTER FUNCTION public.{function}() RESET ALL;
                 ALTER FUNCTION public.{function}() SECURITY INVOKER;
                 ALTER FUNCTION public.{function}() SET search_path TO pg_catalog, public"
                ))
                .await
                .unwrap();
            schema::require_installed(&reader).await.unwrap();
            assert_eq!(identities(&owner).await, installed);
        }
    }
    assert_eq!(ledger(&owner).await, installed_ledger);
    // Running validation must neither canonicalize settings nor alter metadata.
    let paths = owner
        .query(
            "SELECT proconfig FROM pg_proc WHERE pronamespace='public'::regnamespace
         AND proname=ANY($1)",
            &[&&FUNCTIONS[..]],
        )
        .await
        .unwrap();
    for row in paths {
        assert_eq!(
            row.get::<_, Vec<String>>(0),
            ["search_path=pg_catalog, public"]
        );
    }
    close(reader, reader_driver).await;
    close(owner, owner_driver).await;
    // No FORCE and no backend termination: a remaining session retains fixture.
    admin
        .batch_execute(&format!("DROP DATABASE {name}"))
        .await
        .unwrap();
    for role in [&runtime, &migrator] {
        admin
            .batch_execute(&format!("DROP ROLE {role}"))
            .await
            .unwrap();
    }
    close(admin, admin_driver).await;
}
