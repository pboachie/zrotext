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

/// Startup accepts only the complete installed proposal. Ordinary migration
/// ownership remains authoritative; this read-only gate checks required
/// key/FK shapes, validated CHECK presence, indexes and exact immutable guards.
pub(crate) async fn require_installed<C: GenericClient + Sync>(
    db: &C,
) -> Result<(), CeremonyError> {
    if !validate(db).await? {
        return Err(invalid());
    }
    for (table, counts, required) in [
        (
            "sealed_line_key_challenges",
            [5i64, 1, 1, 1],
            &[
                "p:account_id:::",
                "u:challenge_id:::",
                "f:account_id:accounts:id:c",
            ][..],
        ),
        (
            "sealed_line_key_receipts",
            [11, 1, 1, 3],
            &[
                "p:account_id,registration_id:::",
                "u:account_id,approval_fingerprint:::",
                "f:account_id:accounts:id:c",
                "f:assigned_challenge_id:line_activation_challenges:id:a",
                "f:account_id,approval_fingerprint:line_owner_approval_keys:account_id,fingerprint:a",
            ][..],
        ),
        (
            "sealed_line_activation_exchanges",
            [15, 1, 0, 3],
            &[
                "p:challenge_id:::",
                "f:challenge_id:line_activation_challenges:id:a",
                "f:account_id,registration_id:sealed_line_key_receipts:account_id,registration_id:a",
                "f:account_id,line_id,device_id,generation:device_line_bindings:account_id,line_id,device_id,generation:a",
            ][..],
        ),
    ] {
        let row=db.query_one("SELECT count(*) FILTER(WHERE contype='c'),count(*) FILTER(WHERE contype='p'),count(*) FILTER(WHERE contype='u'),count(*) FILTER(WHERE contype='f'),bool_and(convalidated) FROM pg_constraint WHERE conrelid=to_regclass($1)",&[&table]).await?;
        for (n, expected) in counts.iter().enumerate() {
            if row.try_get::<_, i64>(n)? != *expected {
                return Err(invalid());
            }
        }
        if row.try_get::<_, Option<bool>>(4)? != Some(true) {
            return Err(invalid());
        }
        let rows=db.query("SELECT c.contype::text,ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n,pos) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.pos),CASE WHEN c.contype='f' THEN c.confrelid::regclass::text ELSE '' END,ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n,pos) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY k.pos),CASE WHEN c.contype='f' THEN c.confdeltype::text ELSE '' END FROM pg_constraint c WHERE c.conrelid=to_regclass($1) AND c.contype IN ('p','u','f')",&[&table]).await?;
        let actual = rows
            .into_iter()
            .map(|r| {
                Ok::<_, tokio_postgres::Error>(format!(
                    "{}:{}:{}:{}:{}",
                    r.try_get::<_, String>(0)?,
                    r.try_get::<_, Vec<String>>(1)?.join(","),
                    r.try_get::<_, String>(2)?,
                    r.try_get::<_, Vec<String>>(3)?.join(","),
                    r.try_get::<_, String>(4)?
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if required.iter().any(|r| !actual.iter().any(|a| a == r)) {
            return Err(invalid());
        }
    }
    for name in [
        "sealed_line_key_challenges_expiry",
        "sealed_line_key_receipts_challenge",
        "sealed_line_key_receipts_pending",
        "sealed_line_activation_exchanges_device",
        "sealed_line_activation_exchanges_registration",
        "sealed_line_activation_exchanges_binding",
    ] {
        let row=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass($1) AND indisvalid AND indisready)",&[&name]).await?;
        if !row.try_get::<_, bool>(0)? {
            return Err(invalid());
        }
    }
    for (table, trigger, function, events, source) in [
        (
            "sealed_line_key_receipts",
            "sealed_line_key_receipt_before_update",
            "sealed_line_key_receipt_guard",
            19i16,
            include_str!(
                "../../../../../deploy/compose/migrations/086_sealed_line_key_registration.sql"
            ),
        ),
        (
            "sealed_line_activation_exchanges",
            "sealed_line_activation_exchange_before_update",
            "sealed_line_activation_exchange_guard",
            19i16,
            include_str!(
                "../../../../../deploy/compose/migrations/087_sealed_line_activation_exchanges.sql"
            ),
        ),
        (
            "sealed_line_activation_exchanges",
            "sealed_line_activation_exchange_before_delete",
            "sealed_line_activation_exchange_guard",
            11i16,
            include_str!(
                "../../../../../deploy/compose/migrations/087_sealed_line_activation_exchanges.sql"
            ),
        ),
    ] {
        let body = source
            .split("AS $$")
            .nth(1)
            .and_then(|s| s.split("$$;").next())
            .ok_or_else(invalid)?;
        let row=db.query_opt("SELECT p.prosrc,p.prosecdef,l.lanname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang WHERE t.tgrelid=to_regclass($1) AND t.tgname=$2 AND t.tgtype=$3 AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND p.proname=$4 AND p.pronargs=0 AND p.prorettype='trigger'::regtype",&[&table,&trigger,&events,&function]).await?.ok_or_else(invalid)?;
        if row.try_get::<_, String>(0)?.replace("\r\n", "\n") != body.replace("\r\n", "\n")
            || row.try_get::<_, bool>(1)?
            || row.try_get::<_, String>(2)? != "plpgsql"
        {
            return Err(invalid());
        }
    }
    Ok(())
}
