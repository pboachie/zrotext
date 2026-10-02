// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded public proof inventory; no approval private key, factor or body storage.
use crate::{
    auth::SessionPrincipal,
    sealed_root_ceremony::{self, CeremonyError},
};
use base64::{Engine, engine::general_purpose::STANDARD as B};
use tokio_postgres::Client;
pub async fn inventory(
    client: &mut Client,
    p: &SessionPrincipal,
) -> Result<serde_json::Value, CeremonyError> {
    if !client.query_one("SELECT to_regclass('sealed_line_key_receipts') IS NOT NULL AND to_regclass('sealed_line_activation_exchanges') IS NOT NULL",&[]).await?.get::<_,bool>(0) {return Ok(serde_json::json!({"installed":false,"registrations":[],"exchanges":[]}));}
    let tx = sealed_root_ceremony::begin(client).await?;
    super::super::lock_owner(&tx, p)
        .await
        .map_err(|_| CeremonyError::Rejected("owner export unavailable"))?;
    let rows=tx.query("SELECT registration_id,transcript,root_signature,approval_signature,completed_ms,assigned_challenge_id,retired_ms,activated_ms FROM sealed_line_key_receipts WHERE account_id=$1 ORDER BY completed_ms LIMIT 16",&[&p.tenant.account_id()]).await?;
    let registrations:Vec<_>=rows.into_iter().map(|r|serde_json::json!({"registration_id":r.get::<_,uuid::Uuid>(0),"unsigned_statement":B.encode(r.get::<_,Vec<u8>>(1)),"root_signature":B.encode(r.get::<_,Vec<u8>>(2)),"approval_signature":B.encode(r.get::<_,Vec<u8>>(3)),"completed_ms":r.get::<_,i64>(4).to_string(),"assigned_challenge_id":r.get::<_,Option<uuid::Uuid>>(5),"retired_ms":r.get::<_,Option<i64>>(6).map(|n|n.to_string()),"activated_ms":r.get::<_,Option<i64>>(7).map(|n|n.to_string())})).collect();
    let rows=tx.query("SELECT challenge_id,registration_id,line_id,device_id,generation,device_statement_digest,device_signature_der,ack_sent_at IS NOT NULL FROM sealed_line_activation_exchanges WHERE account_id=$1 ORDER BY created_at LIMIT 16",&[&p.tenant.account_id()]).await?;
    let exchanges:Vec<_>=rows.into_iter().map(|r|serde_json::json!({"challenge_id":r.get::<_,uuid::Uuid>(0),"registration_id":r.get::<_,uuid::Uuid>(1),"line_id":r.get::<_,uuid::Uuid>(2),"device_id":r.get::<_,uuid::Uuid>(3),"binding_generation":r.get::<_,i64>(4).to_string(),"device_statement_digest":r.get::<_,Option<Vec<u8>>>(5).map(|b|B.encode(b)),"device_signature_der":r.get::<_,Option<Vec<u8>>>(6).map(|b|B.encode(b)),"phone_acknowledged":r.get::<_,bool>(7)})).collect();
    super::super::fresh_owner(&tx, p)
        .await
        .map_err(|_| CeremonyError::Rejected("owner export unavailable"))?;
    tx.commit().await?;
    Ok(serde_json::json!({"installed":true,"registrations":registrations,"exchanges":exchanges}))
}
