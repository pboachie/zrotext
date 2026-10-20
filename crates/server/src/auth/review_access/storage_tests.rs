// SPDX-License-Identifier: AGPL-3.0-only
//! Real numbered migrations and distinct ordinary LOGIN roles. A failed test
//! preserves its uniquely owned fixture; cleanup never terminates active work.
use super::*;
use postgres_protocol::escape::{escape_identifier, escape_literal};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, NoTls};
#[path = "http_tests.rs"]
mod http;
#[path = "race_tests.rs"]
mod races;
#[path = "retention_tests.rs"]
mod retention;

async fn connect(config: &Config) -> (Client, JoinHandle<()>) {
    let (client, driver) = config.connect(NoTls).await.unwrap();
    (client, tokio::spawn(async move { driver.await.unwrap() }))
}
async fn close(client: Client, driver: JoinHandle<()>) {
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .unwrap()
        .unwrap();
}
struct Fixture {
    admin: Client,
    admin_driver: JoinHandle<()>,
    owner: Client,
    owner_driver: JoinHandle<()>,
    database: String,
    owner_role: String,
    runtime_role: String,
    access: Arc<ReviewAccess>,
    password: String,
}
impl Fixture {
    async fn create() -> Self {
        let raw = std::env::var("ZT_AUTH_TEST_DATABASE_URL").expect("ZT_AUTH_TEST_DATABASE_URL");
        let config: Config = raw.parse().unwrap();
        let (admin, admin_driver) = connect(&config).await;
        let suffix = Uuid::new_v4().simple().to_string();
        let database = format!("zt_review_access_{suffix}");
        let owner_role = format!("zt_review_m_{suffix}");
        let runtime_role = format!("zt_review_r_{suffix}");
        let owner_password = Uuid::new_v4().simple().to_string();
        let runtime_password = Uuid::new_v4().simple().to_string();
        for (role, password) in [
            (&owner_role, &owner_password),
            (&runtime_role, &runtime_password),
        ] {
            let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
            admin.batch_execute(&format!("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",escape_identifier(role),escape_literal(&verifier))).await.unwrap();
        }
        admin
            .batch_execute(&format!(
                "CREATE DATABASE {} OWNER {}",
                escape_identifier(&database),
                escape_identifier(&owner_role)
            ))
            .await
            .unwrap();
        let mut owner_config = config.clone();
        owner_config
            .dbname(&database)
            .user(&owner_role)
            .password(&owner_password);
        let (mut owner, owner_driver) = connect(&owner_config).await;
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
        let applied = zrotext_migrator::apply(&mut owner, &directory, false)
            .await
            .unwrap();
        assert_eq!(applied.last().unwrap().version, 113);
        let realm = Uuid::new_v4();
        let database_identity = Uuid::new_v4();
        let principal = Uuid::new_v4();
        let credential = Uuid::new_v4();
        let scope = Scope {
            realm,
            database: Sha256::digest(database_identity.as_bytes()).into(),
            origin: "https://review.invalid".into(),
            config: [3; 32],
            config_revision: 1,
            key: Sha256::digest([7; 32]).into(),
        };
        owner.execute("INSERT INTO public.review_realm_installation(realm_id,database_id,origin,deployment_digest,service_digest,auth_key_digest,enrollment_key_digest,reauthentication_key_digest,grant_key_digest,mfa_key_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&realm,&database_identity,&scope.origin,&&[21u8;32][..],&&[22u8;32][..],&&scope.key[..],&&[24u8;32][..],&&[25u8;32][..],&&[26u8;32][..],&&[27u8;32][..]]).await.unwrap();
        owner.execute("UPDATE public.review_realm_installation SET active_config_digest=$1,active_config_revision=1",&[&&scope.config[..]]).await.unwrap();
        let password = crate::test_keys::password(178);
        let verifier = super::super::super::password_work::hash(&password)
            .await
            .unwrap();
        owner.execute("INSERT INTO public.review_brokers(id,realm_id,credential_id,credential_revision,password_verifier) VALUES($1,$2,$3,1,$4)",
            &[&principal,&realm,&credential,&verifier]).await.unwrap();
        // Actual unprivileged LOGIN service. These explicit test grants mirror
        // the narrow wrapper boundary; provisioner rerun has separate tests.
        let runtime_identifier = escape_identifier(&runtime_role);
        owner.batch_execute(&format!("GRANT USAGE ON SCHEMA public TO {runtime_identifier};
            GRANT SELECT,INSERT,UPDATE ON public.auth_abuse_counters TO {runtime_identifier};
            GRANT SELECT ON public.review_realm_installation,public.review_brokers,public.review_broker_sessions,
                public.review_bootstrap_attempts,public.review_workspaces,public.review_access_preparations,
                public.review_access_sessions,public.review_access_authentications,public.review_access_root_reauth,
                public.review_access_locators,public.sealed_manifest_authorities,public.sealed_root_challenges,
                public.sealed_root_receipts,public.sealed_root_custody,public.sealed_root_enrollments,
                public.known_signing_point_reservations,public.known_signing_role_claims TO {runtime_identifier}" )).await.unwrap();
        // Exact fixed source signatures: no catalog-provided DDL fragment.
        for signature in [
            "public.review_access_prune()",
            "public.review_access_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)",
            "public.review_access_browser(uuid,bytea,text,bytea,bytea,bigint,bytea,bigint,bigint,boolean)",
            "public.review_access_guard_lock(uuid,bytea,text,bytea,bytea,bigint,bytea)",
            "public.review_access_prepare(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,bigint,bigint,bigint,bytea)",
            "public.review_access_transition(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,text)",
            "public.review_access_login(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,uuid,uuid,bigint,text,uuid,uuid,bytea,bytea,uuid,uuid,uuid,bytea,bytea,bytea,bigint)",
            "public.review_access_broker_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,boolean)",
            "public.review_access_owner_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,boolean)",
            "public.review_access_owner_settlement(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,text,uuid,uuid,bigint,bytea,bytea,bytea)",
            "public.review_access_root_commit(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,uuid,uuid,bigint,bytea,jsonb,uuid,uuid,bigint,text,bigint)",
        ] {
            owner
                .batch_execute(&format!(
                    "GRANT EXECUTE ON FUNCTION {signature} TO {runtime_identifier}"
                ))
                .await
                .unwrap();
        }
        let mut url = url::Url::parse(&raw).expect("fixture requires PostgreSQL URL");
        url.set_username(&runtime_role).unwrap();
        url.set_password(Some(&runtime_password)).unwrap();
        url.set_path(&database);
        let access = Arc::new(
            ReviewAccess::unmounted(
                url.to_string(),
                scope,
                [7; 32],
                Aliases::new([("pilot".into(), principal)]).unwrap(),
            )
            .unwrap(),
        );
        Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            database,
            owner_role,
            runtime_role,
            access,
            password,
        }
    }
    async fn count(&self, table: &str) -> i64 {
        // Only fixed test literals enter this identifier position.
        self.owner
            .query_one(
                &format!("SELECT count(*) FROM public.{}", escape_identifier(table)),
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn prepared(&self, alias: &str) -> Preparation {
        self.prepared_with_browser(alias).await.1
    }
    async fn prepared_with_browser(&self, alias: &str) -> (Browser, Preparation) {
        let (browser, _, fresh) = self.access.browser_prepare(None).await.unwrap();
        assert!(fresh);
        self.access.browser_confirm(&browser).await.unwrap();
        let prep = self
            .access
            .prepare_login(&browser, Uuid::new_v4(), alias.into(), false)
            .await
            .unwrap();
        assert_eq!(
            self.access.transition(&prep, "confirm").await.unwrap(),
            "confirmed"
        );
        (browser, prep)
    }
    async fn cleanup(self) {
        let Self {
            admin,
            admin_driver,
            owner,
            owner_driver,
            database,
            owner_role,
            runtime_role,
            access,
            password: _,
        } = self;
        drop(access);
        close(owner, owner_driver).await;
        // The successful test has joined all work. Only exact fixture runtime
        // pool sockets may remain, and only idle ones may be retired. Active or
        // foreign sessions cause refusal/preservation instead of force-drop.
        for _ in 0..100 {
            let active:bool=admin.query_one("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1 AND (usename<>$2 OR state IS DISTINCT FROM 'idle'))",
                &[&database,&runtime_role]).await.unwrap().get(0);
            if !active {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!admin.query_one("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1 AND (usename<>$2 OR state IS DISTINCT FROM 'idle'))",
            &[&database,&runtime_role]).await.unwrap().get::<_,bool>(0),"preserve fixture with non-idle work");
        admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND state='idle'",
            &[&database,&runtime_role]).await.unwrap();
        admin
            .batch_execute(&format!("DROP DATABASE {}", escape_identifier(&database)))
            .await
            .unwrap();
        admin
            .batch_execute(&format!("DROP ROLE {}", escape_identifier(&runtime_role)))
            .await
            .unwrap();
        admin
            .batch_execute(&format!("DROP ROLE {}", escape_identifier(&owner_role)))
            .await
            .unwrap();
        close(admin, admin_driver).await;
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; real ordinary LOGIN actors"]
async fn actual_password_claim_commits_only_original_workspace_and_cascades_erasure() {
    let f = Fixture::create().await;
    let runtime = f.access.connect().await.unwrap();
    let row=runtime.query_one("SELECT current_user::text,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname=current_user",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), f.runtime_role);
    for index in 1..5 {
        assert!(!row.get::<_, bool>(index));
    }
    drop(runtime);
    let unknown = f.prepared("other").await;
    let counter = crate::auth::tests::PASSWORD_VERIFICATIONS.with(Arc::clone);
    let before = counter.load(std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        f.access.login(&unknown, f.password.as_str()).await,
        Err(AccessError::Rejected)
    ));
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        before + 1
    );
    assert_eq!(f.count("accounts").await, 0);
    assert_eq!(f.count("review_broker_sessions").await, 0);
    let (browser, prep) = f.prepared_with_browser("pilot").await;
    assert!(prep.identities.principal.is_nil());
    assert!(prep.identities.credential.is_nil());
    assert_eq!(prep.identities.revision, 0);
    let before = counter.load(std::sync::atomic::Ordering::SeqCst);
    let result = f.access.login(&prep, f.password.as_str()).await.unwrap();
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        before + 1
    );
    assert_eq!(result.get::<_, Uuid>("account_id"), prep.identities.account);
    assert_eq!(result.get::<_, Uuid>("user_id"), prep.identities.user);
    assert_eq!(
        result.get::<_, Uuid>("owner_session_id"),
        prep.identities.owner_session
    );
    for table in [
        "accounts",
        "users",
        "memberships",
        "review_workspaces",
        "review_access_sessions",
        "review_access_authentications",
        "review_access_locators",
    ] {
        assert_eq!(f.count(table).await, 1, "{table}");
    }
    for table in ["sessions", "owner_mfa"] {
        assert_eq!(f.count(table).await, 0);
    }
    let row=f.owner.query_one("SELECT password_hash,email_verified_at IS NULL,mfa_enabled FROM public.users WHERE id=$1",&[&prep.identities.user]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "!");
    assert!(row.get::<_, bool>(1));
    assert!(!row.get::<_, bool>(2));
    let before = counter.load(std::sync::atomic::Ordering::SeqCst);
    assert!(f.access.login(&prep, f.password.as_str()).await.is_err());
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), before);
    assert_eq!(f.count("accounts").await, 1);
    let guard=f.owner.query_one("SELECT state,active_broker_generation,active_owner_generation,locator_pending FROM public.review_access_preparations WHERE browser_digest=$1",&[&&prep.browser[..]]).await.unwrap();
    assert_eq!(guard.get::<_, String>(0), "committed");
    assert_eq!(guard.get::<_, i64>(1), prep.generation as i64);
    assert_eq!(guard.get::<_, i64>(2), prep.generation as i64);
    assert!(guard.get::<_, bool>(3));
    let credentials = f
        .access
        .credentials(
            prep.identities.broker_session,
            &prep.candidates.broker,
            &prep.candidates.broker_csrf,
            prep.identities.owner_session,
            &prep.candidates.owner,
            &prep.candidates.owner_csrf,
        )
        .unwrap();
    let request = Uuid::new_v4();
    let context = f
        .access
        .context(&browser, &credentials, request)
        .await
        .unwrap();
    assert_eq!(context.request_id, request);
    assert_eq!(context.account, prep.identities.account);
    assert!(!context.locator_retained);
    assert!(matches!(
        context.root_state,
        crate::http_review_access::dto::RootState::NoRootHistory
    ));
    let original_last_use: i64 = f
        .owner
        .query_one(
            "SELECT last_used_ms FROM public.review_access_sessions WHERE id=$1",
            &[&prep.identities.owner_session],
        )
        .await
        .unwrap()
        .get(0);
    f.access.login_status(&prep).await.unwrap();
    f.access
        .acknowledge(
            &browser,
            &credentials,
            prep.id,
            prep.request,
            prep.generation,
            &prep.candidates.csrf,
        )
        .await
        .unwrap();
    // Exact lost-ACK reconciliation is repeatable, never issuance or time refresh.
    f.access
        .acknowledge(
            &browser,
            &credentials,
            prep.id,
            prep.request,
            prep.generation,
            &prep.candidates.csrf,
        )
        .await
        .unwrap();
    let selector = frames::LocatorSelector::from_initial(
        &prep,
        &browser,
        &f.access.key,
        &f.access.scope,
        context.server_now_ms.0,
    )
    .unwrap()
    .seal(&f.access.key, &f.access.scope, context.server_now_ms.0)
    .unwrap();
    let selector_hash: [u8; 32] = Sha256::digest(selector.as_bytes()).into();
    let ack = Uuid::new_v4();
    assert!(
        !f.access
            .locator_retention(
                &browser,
                &credentials,
                crate::auth::review_access::current::LocatorObservation {
                    phase: super::super::current::LocatorPhase::Context,
                    preparation: prep.id,
                    request: ack,
                    selector_hash: &selector_hash,
                    selector_value: Some(&selector)
                },
            )
            .await
            .unwrap()
    );
    assert!(
        f.access
            .locator_retention(
                &browser,
                &credentials,
                crate::auth::review_access::current::LocatorObservation {
                    phase: super::super::current::LocatorPhase::Confirm,
                    preparation: prep.id,
                    request: ack,
                    selector_hash: &selector_hash,
                    selector_value: Some(&selector)
                },
            )
            .await
            .unwrap()
    );
    assert!(
        f.access
            .locator_retention(
                &browser,
                &credentials,
                crate::auth::review_access::current::LocatorObservation {
                    phase: super::super::current::LocatorPhase::Status,
                    preparation: prep.id,
                    request: ack,
                    selector_hash: &selector_hash,
                    selector_value: None
                },
            )
            .await
            .unwrap()
    );
    assert!(
        f.access
            .locator_retention(
                &browser,
                &credentials,
                crate::auth::review_access::current::LocatorObservation {
                    phase: super::super::current::LocatorPhase::Status,
                    preparation: prep.id,
                    request: Uuid::new_v4(),
                    selector_hash: &selector_hash,
                    selector_value: None
                },
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.owner
            .query_one(
                "SELECT last_used_ms FROM public.review_access_sessions WHERE id=$1",
                &[&prep.identities.owner_session]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        original_last_use
    );
    assert!(
        f.access
            .context(&browser, &credentials, Uuid::new_v4())
            .await
            .unwrap()
            .locator_retained
    );
    // Same-browser history cannot silently bootstrap another owner even after ACK.
    assert!(
        f.access
            .prepare_login(&browser, Uuid::new_v4(), "pilot".into(), false)
            .await
            .is_err()
    );
    f.owner
        .execute(
            "DELETE FROM public.users WHERE id=$1",
            &[&prep.identities.user],
        )
        .await
        .unwrap();
    for table in [
        "review_bootstrap_attempts",
        "review_workspaces",
        "review_access_sessions",
        "review_access_authentications",
        "review_access_root_reauth",
        "review_access_locators",
    ] {
        assert_eq!(f.count(table).await, 0, "{table}");
    }
    // Account-free guard retains no account/user/session pointers after erasure.
    assert_eq!(f.count("review_access_preparations").await, 2);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with superuser on a disposable PostgreSQL cluster; ordinary-role operator-shadow qualification"]
async fn review_checkout_excludes_owned_operator_overloads_before_any_clock_read() {
    let f = Fixture::create().await;
    f.owner
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {} TO {}",
            escape_identifier(&f.database),
            escape_identifier(&f.runtime_role)
        ))
        .await
        .unwrap();
    let mut url = url::Url::parse(&f.access.database_url).unwrap();
    url.query_pairs_mut().append_pair(
        "options",
        "-csearch_path=review_clock_shadow,pg_catalog,public",
    );
    let raw = runtime_db::connect(url.as_str()).await.unwrap();
    raw.batch_execute("CREATE SCHEMA review_clock_shadow")
        .await
        .unwrap();
    // The ordinary LOGIN owns only this disposable schema. This is an actual
    // exact-argument operator overload, not a pg_temp/string-only assertion.
    raw.batch_execute("CREATE FUNCTION review_clock_shadow.clock_product(numeric,integer) RETURNS numeric \
        LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog AS 'SELECT 9000000000000::numeric'; \
        CREATE OPERATOR review_clock_shadow.* (LEFTARG=numeric,RIGHTARG=integer,FUNCTION=review_clock_shadow.clock_product)").await.unwrap();
    raw.batch_execute(&format!(
        "GRANT USAGE ON SCHEMA review_clock_shadow TO {}",
        escape_identifier(&f.owner_role)
    ))
    .await
    .unwrap();
    let forged = clock(&*raw, 0).await.unwrap();
    assert_eq!(forged, 9_000_000_000_000);
    drop(raw);
    // Even catalog-first + public is insufficient against a more exact public
    // numeric,int4 overload. The production fix excludes public entirely.
    f.owner.batch_execute("CREATE OPERATOR public.* (LEFTARG=numeric,RIGHTARG=integer,FUNCTION=review_clock_shadow.clock_product)").await.unwrap();
    let raw = runtime_db::connect(url.as_str()).await.unwrap();
    raw.batch_execute("SET search_path TO pg_catalog,public")
        .await
        .unwrap();
    assert_eq!(clock(&*raw, 0).await.unwrap(), forged);
    drop(raw);
    let principal: Uuid = f
        .owner
        .query_one("SELECT id FROM public.review_brokers", &[])
        .await
        .unwrap()
        .get(0);
    let access = ReviewAccess::unmounted(
        url.to_string(),
        f.access.scope.clone(),
        [7; 32],
        Aliases::new([("pilot".into(), principal)]).unwrap(),
    )
    .unwrap();
    let client = access.connect().await.unwrap();
    assert_eq!(
        client
            .query_one("SHOW search_path", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "pg_catalog"
    );
    let actual = clock(&*client, 0).await.unwrap();
    assert!(actual < forged);
    assert!(clock(&*client, forged).await.is_err());
    drop(client);
    let (browser, _, _) = access.browser_prepare(None).await.unwrap();
    access.browser_confirm(&browser).await.unwrap();
    let prep = access
        .prepare_login(&browser, Uuid::new_v4(), "pilot".into(), false)
        .await
        .unwrap();
    access.transition(&prep, "confirm").await.unwrap();
    access.login(&prep, f.password.as_str()).await.unwrap();
    let c = access
        .credentials(
            prep.identities.broker_session,
            &prep.candidates.broker,
            &prep.candidates.broker_csrf,
            prep.identities.owner_session,
            &prep.candidates.owner,
            &prep.candidates.owner_csrf,
        )
        .unwrap();
    let context = access.context(&browser, &c, Uuid::new_v4()).await.unwrap();
    assert!(context.server_now_ms.0 >= actual && context.server_now_ms.0 < forged);
    assert_eq!(context.account, prep.identities.account);
    drop(access);
    f.cleanup().await;
}
