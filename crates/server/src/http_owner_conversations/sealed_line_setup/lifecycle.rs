// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded public proof inventory; no approval private key, factor or body storage.
use crate::{
    auth::SessionPrincipal,
    sealed_root_ceremony::{self, CeremonyError},
};
use base64::{Engine, engine::general_purpose::STANDARD as B};
use tokio_postgres::{Client, GenericClient, types::Type};
fn invalid() -> CeremonyError {
    CeremonyError::Rejected("sealed setup schema unavailable")
}
/// Every table must be absent or present as a complete contract. A partially
/// installed or malformed proposal cannot masquerade as an optional absence.
pub(crate) async fn validate<C: GenericClient + Sync>(db: &C) -> Result<bool, CeremonyError> {
    let row=db.query_one("SELECT to_regclass('sealed_line_key_challenges') IS NOT NULL,to_regclass('sealed_line_key_receipts') IS NOT NULL,to_regclass('sealed_line_activation_exchanges') IS NOT NULL",&[]).await?;
    let present = [row.try_get::<_, bool>(0)?, row.try_get(1)?, row.try_get(2)?];
    if present == [false; 3] {
        return Ok(false);
    }
    if present != [true; 3] {
        return Err(invalid());
    }
    type ColumnContract = (&'static str, Type, bool);
    type TableContract<'a> = (&'static str, &'a [ColumnContract]);
    let contracts: [TableContract<'_>; 3] = [
        (
            "sealed_line_key_challenges",
            &[
                ("account_id", Type::UUID, true),
                ("challenge_id", Type::UUID, true),
                ("user_id", Type::UUID, true),
                ("session_id", Type::UUID, true),
                ("device_id", Type::UUID, true),
                ("line_id", Type::UUID, true),
                ("generation", Type::INT8, true),
                ("transcript", Type::BYTEA, true),
                ("issued_ms", Type::INT8, true),
                ("expires_ms", Type::INT8, true),
                ("completed_ms", Type::INT8, false),
            ],
        ),
        (
            "sealed_line_key_receipts",
            &[
                ("account_id", Type::UUID, true),
                ("registration_id", Type::UUID, true),
                ("user_id", Type::UUID, true),
                ("session_id", Type::UUID, true),
                ("device_id", Type::UUID, true),
                ("line_id", Type::UUID, true),
                ("generation", Type::INT8, true),
                ("transcript", Type::BYTEA, true),
                ("root_signature", Type::BYTEA, true),
                ("approval_signature", Type::BYTEA, true),
                ("approval_point", Type::BYTEA, true),
                ("approval_fingerprint", Type::BYTEA, true),
                ("paired_fingerprint", Type::BYTEA, true),
                ("issued_ms", Type::INT8, true),
                ("expires_ms", Type::INT8, true),
                ("completed_ms", Type::INT8, true),
                ("assigned_challenge_id", Type::UUID, false),
                ("retired_ms", Type::INT8, false),
                ("activated_ms", Type::INT8, false),
            ],
        ),
        (
            "sealed_line_activation_exchanges",
            &[
                ("registration_id", Type::UUID, true),
                ("challenge_id", Type::UUID, true),
                ("account_id", Type::UUID, true),
                ("line_id", Type::UUID, true),
                ("device_id", Type::UUID, true),
                ("generation", Type::INT8, true),
                ("initiating_user_id", Type::UUID, true),
                ("initiating_session_id", Type::UUID, true),
                ("owner_fingerprint", Type::BYTEA, true),
                ("device_fingerprint", Type::BYTEA, true),
                ("device_statement_digest", Type::BYTEA, false),
                ("nonce", Type::BYTEA, false),
                ("pushed_connection_epoch", Type::INT8, false),
                ("android_api_level", Type::INT4, false),
                ("active_subscription_count", Type::INT2, false),
                ("selected_subscription_id", Type::INT4, false),
                ("device_signature_der", Type::BYTEA, false),
                ("proof_site_id", Type::TEXT, false),
                ("proof_instance_id", Type::TEXT, false),
                ("proof_connection_epoch", Type::INT8, false),
                ("proof_deployment_epoch", Type::INT8, false),
                ("proof_received_at", Type::TIMESTAMPTZ, false),
                ("ack_sent_at", Type::TIMESTAMPTZ, false),
                ("created_at", Type::TIMESTAMPTZ, true),
            ],
        ),
    ];
    for (table, expected) in contracts {
        let statement = db
            .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
            .await?;
        let rows=db.query("SELECT a.attname,a.attnotnull FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE a.attrelid=to_regclass($1) AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p') ORDER BY a.attnum",&[&table]).await?;
        if statement.columns().len() != expected.len() || rows.len() != expected.len() {
            return Err(invalid());
        }
        for ((column, row), (name, ty, notnull)) in
            statement.columns().iter().zip(rows.iter()).zip(expected)
        {
            if column.name() != *name
                || column.type_() != ty
                || row.try_get::<_, String>(0)? != *name
                || row.try_get::<_, bool>(1)? != *notnull
            {
                return Err(invalid());
            }
        }
    }
    Ok(true)
}
pub async fn inventory(
    client: &mut Client,
    p: &SessionPrincipal,
) -> Result<serde_json::Value, CeremonyError> {
    let tx = sealed_root_ceremony::begin(client).await?;
    super::super::lock_owner(&tx, p)
        .await
        .map_err(|_| invalid())?;
    if !validate(&tx).await? {
        super::super::fresh_owner(&tx, p)
            .await
            .map_err(|_| invalid())?;
        tx.commit().await?;
        return Ok(serde_json::json!({"installed":false,"registrations":[],"exchanges":[]}));
    }
    let rows=tx.query("SELECT registration_id,transcript,root_signature,approval_signature,completed_ms,assigned_challenge_id,retired_ms,activated_ms FROM sealed_line_key_receipts WHERE account_id=$1 ORDER BY completed_ms LIMIT 16 FOR SHARE",&[&p.tenant.account_id()]).await?;
    let registrations=rows.into_iter().map(|r|Ok::<_,tokio_postgres::Error>(serde_json::json!({"registration_id":r.try_get::<_,uuid::Uuid>(0)?,"unsigned_statement":B.encode(r.try_get::<_,Vec<u8>>(1)?),"root_signature":B.encode(r.try_get::<_,Vec<u8>>(2)?),"approval_signature":B.encode(r.try_get::<_,Vec<u8>>(3)?),"completed_ms":r.try_get::<_,i64>(4)?.to_string(),"assigned_challenge_id":r.try_get::<_,Option<uuid::Uuid>>(5)?,"retired_ms":r.try_get::<_,Option<i64>>(6)?.map(|n|n.to_string()),"activated_ms":r.try_get::<_,Option<i64>>(7)?.map(|n|n.to_string())}))).collect::<Result<Vec<_>,_>>()?;
    let rows=tx.query("SELECT challenge_id,registration_id,line_id,device_id,generation,device_statement_digest,device_signature_der,ack_sent_at IS NOT NULL FROM sealed_line_activation_exchanges WHERE account_id=$1 ORDER BY created_at LIMIT 16 FOR SHARE",&[&p.tenant.account_id()]).await?;
    let exchanges=rows.into_iter().map(|r|Ok::<_,tokio_postgres::Error>(serde_json::json!({"challenge_id":r.try_get::<_,uuid::Uuid>(0)?,"registration_id":r.try_get::<_,uuid::Uuid>(1)?,"line_id":r.try_get::<_,uuid::Uuid>(2)?,"device_id":r.try_get::<_,uuid::Uuid>(3)?,"binding_generation":r.try_get::<_,i64>(4)?.to_string(),"device_statement_digest":r.try_get::<_,Option<Vec<u8>>>(5)?.map(|b|B.encode(b)),"device_signature_der":r.try_get::<_,Option<Vec<u8>>>(6)?.map(|b|B.encode(b)),"phone_acknowledged":r.try_get::<_,bool>(7)?}))).collect::<Result<Vec<_>,_>>()?;
    super::super::fresh_owner(&tx, p)
        .await
        .map_err(|_| invalid())?;
    tx.commit().await?;
    Ok(serde_json::json!({"installed":true,"registrations":registrations,"exchanges":exchanges}))
}
