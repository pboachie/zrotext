// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::http_auth::{self, AuthHttpState, DisabledVerificationDispatcher};
use crate::workflow_runtime::http::{WorkflowHttpState, router};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

#[tokio::test]
#[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL, Python, Node 22+, built SDK and OpenSSL; real guided HTTPS setup"]
async fn guided_setup_retains_creator_after_teardown_and_recovery_fences_current_credentials() {
    // The dedicated read-only connector job requires the actual installed
    // launcher with its optional SDK and disposable OS custody. It cannot skip
    // or fall back when this explicit fixture mode is selected.
    let verify_installed = match std::env::var("ZT_GUIDED_VERIFY_TEST") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => true,
        _ => panic!("invalid guided verification fixture mode"),
    };
    let mut case = Case::for_customer_routine(None).await;
    let login_factor = case.fresh_factor().await;
    let grant_factor = case.fresh_factor().await;
    let recovery_login_factor = case.fresh_factor().await;
    let second_grant_factor = case.fresh_factor().await;
    let unknown_grant_factor = case.fresh_factor().await;
    let final_login_factor = case.fresh_factor().await;
    let email: String = case
        .f
        .db
        .query_one(
            "SELECT email FROM users WHERE id=$1",
            &[&case.owner.user_id],
        )
        .await
        .unwrap()
        .get(0);
    let foreign_user = Uuid::new_v4();
    let foreign_session = Uuid::new_v4();
    case.f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'foreign-guided@example.test',password_hash,now() FROM users WHERE id=$2", &[&foreign_user,&case.owner.user_id]).await.unwrap();
    case.f
        .db
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&case.f.account, &foreign_user],
        )
        .await
        .unwrap();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&foreign_session,&case.f.account,&foreign_user,&vec![71u8;32],&vec![72u8;32]]).await.unwrap();
    let foreign_account = Uuid::new_v4();
    let other_account_user = Uuid::new_v4();
    case.f.db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,'other-account-guided@example.test',password_hash,now() FROM users WHERE id=$2", &[&other_account_user,&case.owner.user_id]).await.unwrap();
    let other_account_session = Uuid::new_v4();
    case.f
        .db
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&foreign_account])
        .await
        .unwrap();
    case.f
        .db
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'owner')",
            &[&foreign_account, &other_account_user],
        )
        .await
        .unwrap();
    case.f.db.execute("INSERT INTO sessions(id,account_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour')", &[&other_account_session,&foreign_account,&other_account_user,&vec![73u8;32],&vec![74u8;32]]).await.unwrap();
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy_port = reserved.local_addr().unwrap().port();
    let separator = if case.f.url.contains('?') { '&' } else { '?' };
    let database_url = format!(
        "{}{separator}options=-csearch_path%3D{}",
        case.f.url, case.f.schema
    );
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(84)).unwrap());
    let state = AuthHttpState::new(
        database_url.clone(),
        hasher.clone(),
        format!("https://localhost:{proxy_port}"),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap()
    .with_workflow_grants_enabled(true)
    .with_mfa_cipher(Arc::new(
        mfa::MfaCipher::new(crate::test_keys::key(89)).unwrap(),
    ));
    let app = axum::Router::new()
        .nest("/v1/auth", http_auth::router(state))
        .merge(router(
            WorkflowHttpState {
                database_url,
                hasher,
            },
            true,
        ));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = json!({"verify_installed":verify_installed,"upstream":format!("http://{address}"),"proxy_port":proxy_port,"email":email,"password":case.password.as_str(),
        "login_factor":login_factor,"grant_factor":grant_factor,"recovery_login_factor":recovery_login_factor,
        "second_grant_factor":second_grant_factor,"unknown_grant_factor":unknown_grant_factor,"final_login_factor":final_login_factor,
        "foreign_session":foreign_session,"other_account_session":other_account_session,
        "broker":root.join("sdk/mcp/secret-broker.mjs"),
        "scope":{"connector_id":case.request.connector,"context_id":case.request.context,"contact_id":case.request.contact,"purpose":"operational","expires_at_ms":case.request.expires_ms}});
    drop(reserved);
    let result = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("python")
            .arg(root.join("scripts/test_service_guided_setup.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let stage = value["failed"]["stage"]
            .as_str()
            .filter(|v| {
                matches!(
                    *v,
                    "start"
                        | "login"
                        | "install"
                        | "teardown"
                        | "teardown_readiness"
                        | "bootstrap"
                        | "installed_verify"
                        | "timeout_verify"
                        | "revoked_verify"
                        | "recovery_login"
                        | "missing_csrf"
                        | "foreign_revoke"
                        | "creator_recovery"
                        | "disconnect"
                        | "second_create"
                        | "creator_logout"
                        | "unknown_login"
                        | "unknown_create"
                        | "unknown_replay"
                        | "unknown_recovery"
                )
            })
            .unwrap_or("unknown");
        let operation = value["failed"]["operation"]
            .as_str()
            .filter(|v| {
                matches!(
                    *v,
                    "none"
                        | "login"
                        | "login_mfa"
                        | "session"
                        | "logout"
                        | "grant"
                        | "session_revoke"
                        | "grant_revoke"
                        | "readiness"
                )
            })
            .unwrap_or("unknown");
        let status = value["failed"]["status"]
            .as_u64()
            .filter(|v| *v <= 599)
            .unwrap_or(0);
        let verification = value["failed"]["verification"]
            .as_str()
            .filter(|value| {
                matches!(
                    *value,
                    "deadline_exceeded"
                        | "connection_unknown"
                        | "unauthorized"
                        | "owned_launcher_still_running"
                        | "owned_node_still_running"
                        | "metadata_not_waiting"
                        | "timeout_too_slow"
                )
            })
            .unwrap_or("unknown");
        assert!(
            output.status.success(),
            "guided HTTPS fixture refused at {stage} ({operation}:{status}, {verification})"
        );
        value
    })
    .await;
    server.abort();
    let _ = server.await;
    let result = result.unwrap();
    assert_eq!(result["after_teardown"], true);
    assert_eq!(result["bootstrap_current"], true);
    assert_eq!(result["installed_verified"], verify_installed);
    if verify_installed {
        println!("GUIDED_INSTALLED_CONNECTOR_METADATA_VERIFIED");
    }
    assert_eq!(result["recovery_fenced"], true);
    assert_eq!(result["creator_logout_fenced"], true);
    assert_eq!(result["unknown_recovered"], true);
    assert!(
        !case
            .f
            .db
            .query_one(
                "SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1",
                &[&foreign_session]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        !case
            .f
            .db
            .query_one(
                "SELECT revoked_at IS NOT NULL FROM sessions WHERE id=$1",
                &[&other_account_session]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM workflow_integration_grants", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    assert_eq!(
        case.f
            .db
            .query_one("SELECT count(*) FROM messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    case.f.cleanup().await;
}
