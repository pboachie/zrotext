// SPDX-License-Identifier: AGPL-3.0-only
//! Closed original-receipt storage, never signature or current-permission proof.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/109_original_sealed_activation_receipts.sql");

#[derive(Debug, thiserror::Error)]
pub enum ReceiptSchemaError {
    #[error("original activation receipt schema unavailable")]
    Invalid,
    #[error("original activation receipt writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("original activation receipt storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ReceiptSchemaError>;

fn body(name: &str) -> Result<&'static str> {
    zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        MIGRATION,
        name,
        "$function$",
    )
    .ok_or(ReceiptSchemaError::Invalid)
}

async fn functions<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for (name, arguments, result, set, definer, volatility, configuration) in [
        (
            "payload_profile_v2_capture",
            "uuid, uuid, bytea, bytea, bytea, bytea, bytea, bytea",
            "record",
            true,
            true,
            "v",
            vec!["search_path=pg_catalog", "lock_timeout=3s"],
        ),
        (
            "payload_profile_v2_receipt_guard",
            "",
            "trigger",
            false,
            true,
            "v",
            vec!["search_path=pg_catalog", "lock_timeout=3s"],
        ),
        (
            "payload_profile_v2_receipt_complete",
            "",
            "trigger",
            false,
            true,
            "v",
            vec!["search_path=pg_catalog"],
        ),
        (
            "payload_profile_v2_ready",
            "",
            "boolean",
            false,
            false,
            "s",
            vec!["search_path=pg_catalog"],
        ),
    ] {
        let rows=db.query("SELECT p.prosrc,pg_catalog.oidvectortypes(p.proargtypes),pg_catalog.format_type(p.prorettype,NULL),p.proretset,p.prosecdef,p.provolatile::text,p.proconfig,p.proisstrict,p.proparallel::text,p.prokind::text,p.pronargdefaults::integer,p.proowner=c.relowner,l.lanname,p.proargnames,p.proargmodes::text[],ARRAY(SELECT pg_catalog.format_type(t,NULL) FROM unnest(p.proallargtypes) t) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1", &[&name]).await?;
        if rows.len() != 1 {
            return Err(ReceiptSchemaError::Invalid);
        }
        let row = &rows[0];
        let configuration = configuration
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        if row.try_get::<_, String>(0)? != body(name)?
            || row.try_get::<_, String>(1)? != arguments
            || row.try_get::<_, String>(2)? != result
            || row.try_get::<_, bool>(3)? != set
            || row.try_get::<_, bool>(4)? != definer
            || row.try_get::<_, String>(5)? != volatility
            || row.try_get::<_, Option<Vec<String>>>(6)?.as_ref() != Some(&configuration)
            || row.try_get::<_, bool>(7)?
            || row.try_get::<_, String>(8)? != "u"
            || row.try_get::<_, String>(9)? != "f"
            || row.try_get::<_, i32>(10)? != 0
            || !row.try_get::<_, bool>(11)?
        {
            return Err(ReceiptSchemaError::Invalid);
        }
        if row.try_get::<_, String>(12)?
            != if name == "payload_profile_v2_ready" {
                "sql"
            } else {
                "plpgsql"
            }
        {
            return Err(ReceiptSchemaError::Invalid);
        }
        if set {
            let expected_names = [
                "account",
                "challenge",
                "device_statement",
                "device_der",
                "owner_statement",
                "owner_der",
                "device_point",
                "owner_point",
                "binding_id",
                "accepted_ms",
            ];
            let expected_modes = ["i", "i", "i", "i", "i", "i", "i", "i", "t", "t"];
            let expected_types = [
                "uuid", "uuid", "bytea", "bytea", "bytea", "bytea", "bytea", "bytea", "uuid",
                "bigint",
            ];
            let expected_names = expected_names.map(str::to_owned);
            let expected_modes = expected_modes.map(str::to_owned);
            if row.try_get::<_, Option<Vec<String>>>(13)?.as_deref()
                != Some(expected_names.as_slice())
                || row.try_get::<_, Option<Vec<String>>>(14)?.as_deref()
                    != Some(expected_modes.as_slice())
                || row.try_get::<_, Vec<String>>(15)? != expected_types.map(str::to_owned)
            {
                return Err(ReceiptSchemaError::Invalid);
            }
        } else if row.try_get::<_, Option<Vec<String>>>(13)?.is_some()
            || row.try_get::<_, Option<Vec<String>>>(14)?.is_some()
            || !row.try_get::<_, Vec<String>>(15)?.is_empty()
        {
            return Err(ReceiptSchemaError::Invalid);
        }
    }
    Ok(())
}

/// Legacy resolved installations without109 retain their original v2 behavior,
/// never a Profile03 upgrade promise. Partial or changed109 installations refuse.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let resolved = db.query_one("SELECT coalesce((SELECT n.nspname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('line_activation_v2_pending')),'public')", &[]).await?.try_get::<_,String>(0)?;
    let row=db.query_one("SELECT pg_catalog.to_regclass(pg_catalog.format('%I.payload_profile_v2_activation_receipts',$1::text)) IS NOT NULL,EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname::text=$1::text AND p.proname LIKE 'payload_profile_v2_%')", &[&resolved]).await?;
    if !row.try_get::<_, bool>(0)? {
        if row.try_get::<_, bool>(1)? {
            return Err(ReceiptSchemaError::Invalid);
        }
        if resolved=="public" && db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL", &[]).await?.try_get::<_,bool>(0)? {
            crate::payload_profile_writer::optional(db,"public.line_activation_v2_pending").await?;
            let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton", &[]).await?.try_get(0)?;
            if version!=108 { return Err(ReceiptSchemaError::Invalid); }
        }
        return Ok(false);
    }
    if resolved != "public" {
        return Err(ReceiptSchemaError::Invalid);
    }
    if !crate::payload_profile_writer::optional(db, "public.line_activation_v2_pending").await? {
        return Err(ReceiptSchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 109..=116) {
        return Err(ReceiptSchemaError::Invalid);
    }
    functions(db).await?;
    if db.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname LIKE 'payload_profile_v2_%' AND a.grantee=0)", &[]).await?.try_get::<_,bool>(0)? {
        return Err(ReceiptSchemaError::Invalid);
    }
    Ok(true)
}

/// Schema and ordinary-runtime capability only. Every consumer must independently
/// verify original signatures and current authority in its actual held transaction.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db).await?
        || !db
            .query_one("SELECT public.payload_profile_v2_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(ReceiptSchemaError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
