// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit, bounded re-encryption of endpoint signing secrets during an
//! operator-coordinated webhook KEK rotation. This binary never sends webhooks.

use base64::{Engine, engine::general_purpose::STANDARD};
use std::{env, error::Error};
use tokio_postgres::NoTls;
use zeroize::Zeroizing;
use zrotext_server::webhook_worker::{
    WebhookSecretVault, check_runtime_keys, rewrap_endpoint_secrets,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mode = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [mode] if mode == "--check" || mode == "--apply" => mode.clone(),
        _ => return Err("usage: zrotext-webhook-kek-rewrap --check|--apply".into()),
    };
    let database_url = env::var("DATABASE_URL")?;
    let active_version: i32 = env::var("WEBHOOK_KEK_VERSION")?.parse()?;
    let secondary_version: i32 = env::var("WEBHOOK_KEK_SECONDARY_VERSION")?.parse()?;
    let active_encoded = Zeroizing::new(env::var("WEBHOOK_KEK_B64")?);
    let secondary_encoded = Zeroizing::new(env::var("WEBHOOK_KEK_SECONDARY_B64")?);
    let active_key = Zeroizing::new(STANDARD.decode(active_encoded.as_bytes())?);
    let secondary_key = Zeroizing::new(STANDARD.decode(secondary_encoded.as_bytes())?);
    let vault = WebhookSecretVault::with_secondary(
        active_version,
        active_key,
        Some((secondary_version, secondary_key)),
    )?;
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let locked: bool = db
        .query_one(
            "SELECT pg_try_advisory_lock(hashtext('zrotext-webhook-kek-rewrap-v1'))",
            &[],
        )
        .await?
        .get(0);
    if !locked {
        return Err("another webhook key rewrap is running".into());
    }
    check_runtime_keys(&mut db, &vault).await?;
    let unknown: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_endpoints
             WHERE signing_secret_key_version NOT IN ($1,$2)",
            &[&active_version, &secondary_version],
        )
        .await?
        .get(0);
    if unknown != 0 {
        return Err(format!("{unknown} endpoints use an unconfigured key version").into());
    }
    let before: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_endpoints WHERE signing_secret_key_version<>$1",
            &[&active_version],
        )
        .await?
        .get(0);
    if mode == "--check" {
        println!("endpoints requiring rewrap: {before}");
        return Ok(());
    }
    loop {
        let batch = rewrap_endpoint_secrets(&mut db, &vault, 100).await?;
        if batch == 0 {
            break;
        }
    }
    let remaining: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_endpoints WHERE signing_secret_key_version<>$1",
            &[&active_version],
        )
        .await?
        .get(0);
    if remaining != 0 {
        return Err(format!("{remaining} endpoints still require rewrap; retry").into());
    }
    println!("endpoint signing-secret rewrap complete for key version {active_version}");
    Ok(())
}
