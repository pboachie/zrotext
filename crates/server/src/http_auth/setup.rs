// SPDX-License-Identifier: AGPL-3.0-only
//! Current owner setup observations. No browser cache, secret, signature or
//! checkout return is a completion receipt. Existing ceremonies keep their
//! original session and device lease requirements.
use super::*;
use sha2::Digest;

const PAGE: i64 = 50;

pub fn router(state: AuthHttpState) -> Router {
    Router::new()
        .route("/setup", get(read))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(state))
}

/// Deterministic public identifiers let tabs converge on one default phone
/// line. They confer no permission; normal v2 owner and phone proofs apply.
fn locator(domain: &[u8], ids: &[Uuid], generation: i64) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(domain);
    for id in ids {
        hash.update(id.as_bytes());
    }
    hash.update(generation.to_be_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

async fn read(
    State(s): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthHttpError> {
    require_owner_read_headers(&headers)?;
    let mut db = connect(&s.database_url).await?;
    let p = require_owner_read(&db, &s.hasher, &headers).await?;
    let tx = db
        .transaction()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let account = p.tenant.account_id();
    let standby: bool = tx
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .get(0);
    if standby {
        return Err(AuthHttpError::Unavailable);
    }
    let current=tx.query_opt("SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL FOR SHARE OF s,u,m,a",&[&p.session_id,&account,&p.user_id]).await.map_err(|_|AuthHttpError::Unavailable)?;
    if current.is_none() {
        return Err(AuthHttpError::Unauthorized);
    }
    let rows=tx.query("SELECT p.id,p.display_name,(extract(epoch FROM p.created_at)*1000)::bigint,(extract(epoch FROM p.expires_at)*1000)::bigint,p.device_id,p.comparison_code,p.key_fingerprint,p.cancelled_at IS NOT NULL,p.expires_at<=clock_timestamp(),p.claimed_at IS NOT NULL,p.proof_verified_at IS NOT NULL,p.challenge_consumed_at IS NOT NULL,p.approval_failures>=5,((p.device_id IS NOT NULL AND (d.id IS NULL OR k.device_id IS NULL)) OR COALESCE(d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL,FALSE)) FROM pairing_requests p LEFT JOIN devices d ON (d.account_id,d.id)=(p.account_id,p.device_id) LEFT JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) WHERE p.account_id=$1 ORDER BY p.created_at DESC,p.id DESC LIMIT $2",&[&account,&(PAGE+1)]).await.map_err(|_|AuthHttpError::Unavailable)?;
    let mut truncated = rows.len() as i64 > PAGE;
    let pairings:Vec<_>=rows.into_iter().take(PAGE as usize).map(|r|{
        let device:Option<Uuid>=r.get(4);let verified:bool=r.get(10);
        let status=if r.get::<_,bool>(13){"revoked"}else if device.is_some(){"approved"}else if r.get(7){"cancelled"}else if r.get(8){"expired"}else if r.get::<_,bool>(12)||(!verified&&r.get(11)){"proof_rejected"}else if verified{"awaiting_approval"}else if r.get(9){"awaiting_proof"}else{"pending_claim"};
        let fingerprint:Option<Vec<u8>>=r.get(6);
        serde_json::json!({"pairing_id":r.get::<_,Uuid>(0),"display_name":r.get::<_,String>(1),"created_at_ms":r.get::<_,i64>(2),"expires_at_ms":r.get::<_,i64>(3),"status":status,"approved_device_id":if status=="approved"{device}else{None},"comparison_code":if status=="awaiting_approval"{r.get::<_,Option<String>>(5)}else{None},"key_fingerprint":if status=="awaiting_approval"{fingerprint.map(|b|b.iter().map(|v|format!("{v:02X}")).collect::<String>())}else{None}})
    }).collect();
    let mut lines = Vec::new();
    if s.sms_line_activation_enabled {
        let rows=tx.query("SELECT p.line_id,p.challenge_id,p.opening_id,p.device_id,p.generation,(extract(epoch FROM p.expires_at)*1000)::bigint,p.initiating_session_id=$2,p.approved_at IS NOT NULL,p.retired_at IS NOT NULL,p.expires_at<=clock_timestamp(),b.state,d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL OR l.state='revoked',EXISTS(SELECT 1 FROM line_activation_v2_observations o WHERE o.challenge_id=p.challenge_id),COALESCE(ds.line_activation_version=2 AND ds.site_id=p.site_id AND ds.instance_id=p.instance_id AND ds.connection_epoch=p.connection_epoch AND ds.deployment_epoch=p.deployment_epoch AND ds.lease_until>clock_timestamp() AND ds.deployment_epoch=da.epoch AND st.enabled AND NOT st.draining,FALSE) FROM line_activation_v2_pending p JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation) JOIN phone_lines l ON (l.account_id,l.id)=(p.account_id,p.line_id) JOIN devices d ON (d.account_id,d.id)=(p.account_id,p.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) LEFT JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(p.account_id,p.device_id) LEFT JOIN sites st ON st.site_id=ds.site_id LEFT JOIN deployment_authority da ON da.singleton=TRUE WHERE p.account_id=$1 AND p.purpose='sms' AND p.generation=l.last_issued_generation ORDER BY p.created_at DESC,p.challenge_id DESC LIMIT $3",&[&account,&p.session_id,&(PAGE+1)]).await.map_err(|_|AuthHttpError::Unavailable)?;
        truncated |= rows.len() as i64 > PAGE;
        for r in rows.into_iter().take(PAGE as usize) {
            let same: bool = r.get(6);
            let state: String = r.get(10);
            let status = if r.get::<_, bool>(11) || state == "revoked" {
                "revoked"
            } else if r.get::<_, bool>(7) && state == "active" {
                "approved"
            } else if r.get(8) {
                "retired"
            } else if r.get(9) {
                "expired"
            } else if !same {
                "session_changed"
            } else if !r.get::<_, bool>(13) {
                "connection_changed"
            } else if r.get(12) {
                "awaiting_owner"
            } else {
                "awaiting_device"
            };
            lines.push(serde_json::json!({"line_id":r.get::<_,Uuid>(0),"challenge_id":r.get::<_,Uuid>(1),"opening_id":r.get::<_,Uuid>(2),"device_id":r.get::<_,Uuid>(3),"generation":r.get::<_,i64>(4).to_string(),"expires_at_ms":r.get::<_,i64>(5),"same_session":same,"status":status}));
        }
    }
    let rows=tx.query("SELECT d.id,k.source_pairing_id,COALESCE(d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL,FALSE),k.fingerprint,CASE WHEN d.revoked_at IS NULL AND k.revoked_at IS NULL AND ds.lease_until>clock_timestamp() AND ds.deployment_epoch=da.epoch AND st.enabled AND NOT st.draining THEN ds.line_activation_version ELSE NULL END FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) LEFT JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(d.account_id,d.id) LEFT JOIN sites st ON st.site_id=ds.site_id LEFT JOIN deployment_authority da ON da.singleton=TRUE WHERE d.account_id=$1 ORDER BY d.created_at DESC,d.id DESC LIMIT $2",&[&account,&(PAGE+1)]).await.map_err(|_|AuthHttpError::Unavailable)?;
    truncated |= rows.len() as i64 > PAGE;
    let mut devices = Vec::new();
    for r in rows.into_iter().take(PAGE as usize) {
        let device: Uuid = r.get(0);
        let default_line = locator(b"zrotext-default-sms-line-v1\0", &[account, device], 0);
        let existing = if s.sms_line_activation_enabled {
            tx.query_opt("SELECT b.line_id,l.last_issued_generation FROM device_line_bindings b JOIN phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id) WHERE b.account_id=$1 AND b.device_id=$2 AND b.purpose='sms' AND l.state<>'revoked' ORDER BY b.created_at DESC,b.generation DESC LIMIT 1",&[&account,&device]).await.map_err(|_|AuthHttpError::Unavailable)?
        } else {
            None
        };
        let (line, generation) = existing
            .map(|v| (v.get(0), v.get::<_, i64>(1)))
            .unwrap_or((default_line, 0));
        devices.push(serde_json::json!({"device_id":device,"line_activation_version":if s.sms_line_activation_enabled{r.get::<_,Option<i16>>(4)}else{None},"pairing_id":r.get::<_,Option<Uuid>>(1),"revoked":r.get::<_,bool>(2),"key_fingerprint":r.get::<_,Vec<u8>>(3).iter().map(|b|format!("{b:02X}")).collect::<String>(),"setup_line_id":line,"setup_opening_id":locator(b"zrotext-default-sms-opening-v1\0",&[account,device,p.session_id,line],generation.saturating_add(1))}));
    }
    let observed = final_session_observation(&tx, p.session_id).await?;
    tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(Json(
        serde_json::json!({"schema_version":1,"account_id":account,"session_id":p.session_id,"observed_at_ms":observed,"sms_line_activation_available":s.sms_line_activation_enabled,"pairings":pairings,"line_activations":lines,"devices":devices,"truncated":truncated}),
    ))
}

async fn final_session_observation(
    tx: &tokio_postgres::Transaction<'_>,
    session: Uuid,
) -> Result<i64, AuthHttpError> {
    tx.query_opt("SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint FROM sessions WHERE id=$1 AND expires_at>clock_timestamp() AND revoked_at IS NULL",&[&session])
        .await.map_err(|_|AuthHttpError::Unavailable)?.map(|row|row.get(0)).ok_or(AuthHttpError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_locators_converge_and_fence_each_scope() {
        let a = Uuid::from_bytes([1; 16]);
        let b = Uuid::from_bytes([2; 16]);
        let value = locator(b"scope", &[a, b], 1);
        assert_eq!(value, locator(b"scope", &[a, b], 1));
        assert_ne!(value, locator(b"scope", &[b, a], 1));
        assert_ne!(value, locator(b"scope", &[a, b], 2));
        assert_ne!(value, locator(b"other", &[a, b], 1));
    }
    #[tokio::test]
    #[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated session classification fixture"]
    async fn final_session_read_distinguishes_expiry_from_storage_uncertainty() {
        let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
        let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let schema = format!("setup_session_{}", Uuid::new_v4().simple());
        db.batch_execute(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema}; CREATE TABLE sessions(id uuid PRIMARY KEY,expires_at timestamptz,revoked_at timestamptz)")).await.unwrap();
        let id = Uuid::new_v4();
        db.execute(
            "INSERT INTO sessions VALUES($1,clock_timestamp()-interval '1 second',NULL)",
            &[&id],
        )
        .await
        .unwrap();
        let tx = db.transaction().await.unwrap();
        assert!(matches!(
            final_session_observation(&tx, id).await,
            Err(AuthHttpError::Unauthorized)
        ));
        tx.rollback().await.unwrap();
        db.batch_execute("DROP TABLE sessions").await.unwrap();
        let tx = db.transaction().await.unwrap();
        assert!(matches!(
            final_session_observation(&tx, id).await,
            Err(AuthHttpError::Unavailable)
        ));
        tx.rollback().await.unwrap();
        db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
