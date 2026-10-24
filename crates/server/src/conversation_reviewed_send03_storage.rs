// SPDX-License-Identifier: AGPL-3.0-only
//! Closed original reviewed03 admission storage, never authentication or signature proof.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/114_conversation_reviewed_sends03.sql");

#[derive(Debug, thiserror::Error)]
pub enum ReviewedSendSchemaError {
    #[error("reviewed message admission schema unavailable")]
    Invalid,
    #[error("reviewed message admission writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("original activation receipt unavailable")]
    Receipt(#[from] crate::payload_profile_v2_receipts::ReceiptSchemaError),
    #[error("accepted election unavailable")]
    Election(#[from] crate::payload_profile_elections::ElectionSchemaError),
    #[error("physical selection schema unavailable")]
    Selection(#[from] crate::payload_profile_selections::SelectionSchemaError),
    #[error("manifest successor schema unavailable")]
    Manifest(#[from] crate::payload_profile_manifests::ManifestSchemaError),
    #[error("conversation interval schema unavailable")]
    Interval(#[from] crate::conversation_profile03_storage::ConversationSchemaError),
    #[error("reviewed message admission storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ReviewedSendSchemaError>;
fn body(name: &str, version: i64) -> Result<&'static str> {
    let source = if version == 118
        && matches!(
            name,
            "payload_profile_writer_policy"
                | "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "conversation_reviewed_send03_v2_ready"
        ) {
        include_str!("../../../deploy/compose/migrations/118_device_protection_origins.sql")
    } else if matches!(version, 117..=118)
        && matches!(
            name,
            "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "conversation_reviewed_send03_parse"
                | "conversation_reviewed_send03_scope"
                | "conversation_reviewed_send03_admit"
                | "conversation_reviewed_send03_rows_guard"
                | "conversation_reviewed_send03_message_redact"
                | "conversation_reviewed_send03_writer"
                | "conversation_reviewed_send03_ready"
                | "conversation_reviewed_send03_v2_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/117_explicit_reviewed_intent_v2.sql")
    } else if matches!(version, 116..=118)
        && matches!(
            name,
            "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "payload_profile_writer_guard"
        )
    {
        include_str!(
            "../../../deploy/compose/migrations/116_hosted_native_transaction_identity.sql"
        )
    } else if matches!(version, 115..=118)
        && matches!(
            name,
            "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "payload_profile_writer_policy"
                | "conversation_reviewed_send03_admit"
        )
    {
        include_str!("../../../deploy/compose/migrations/115_conversation_profile03_grants.sql")
    } else {
        MIGRATION
    };
    zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        source,
        name,
        "$function$",
    )
    .ok_or(ReviewedSendSchemaError::Invalid)
}
async fn functions<C: GenericClient + Sync>(db: &C, version: i64) -> Result<()> {
    for (name, args, result, language, volatility, strict, definer, set, config, names) in [
        (
            "conversation_reviewed_send03_parse",
            "bytea",
            "public.conversation_reviewed_sends03",
            "plpgsql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["intent"] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_envelope",
            "public.conversation_reviewed_sends03, bytea",
            "void",
            "plpgsql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["row", "envelope"] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_scope",
            "uuid, bytea, bytea, bigint, bigint",
            "public.conversation_reviewed_sends03",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "intent",
                "signature",
                "permission_deadline_ms",
                "admitted_ms",
            ] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_admit",
            "uuid, uuid, uuid, bytea, bytea, bytea, bigint",
            "public.conversation_reviewed_sends03",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "interval",
                "message",
                "intent",
                "signature",
                "envelope",
                "permission_deadline_ms",
            ] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_rows_guard",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_erasure_fence",
            "uuid",
            "void",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account"] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_writer",
            "uuid, bigint, text, text, jsonb, jsonb",
            "void",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "epoch",
                "relation_name",
                "operation",
                "old_row",
                "new_row",
            ] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_complete",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_message_redact",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_policy",
            "uuid, bigint, text, text, jsonb, jsonb",
            "void",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[
                "account",
                "epoch",
                "relation_name",
                "operation",
                "old_row",
                "new_row",
            ] as &[&str]),
        ),
        (
            "payload_profile_writer_version",
            "",
            "boolean",
            "sql",
            "s",
            false,
            true,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_ready",
            "",
            "boolean",
            "sql",
            "s",
            false,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "conversation_reviewed_send03_ready",
            "",
            "boolean",
            "sql",
            "s",
            false,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
        ),
    ]
    .into_iter()
    .chain(matches!(version, 117..=118).then_some((
        "conversation_reviewed_send03_v2_ready",
        "",
        "boolean",
        "sql",
        "s",
        false,
        false,
        false,
        (&["search_path=pg_catalog"] as &[&str]),
        (&[] as &[&str]),
    ))) {
        // Composite argument display names depend on the caller's search_path.
        // Resolve the exact qualified signature instead of trusting that display.
        let args = args
            .split(", ")
            .filter(|argument| !argument.is_empty())
            .map(|argument| {
                if argument == "bigint" {
                    "pg_catalog.int8".to_owned()
                } else if argument.starts_with("public.") {
                    argument.to_owned()
                } else {
                    format!("pg_catalog.{argument}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let signature = format!("public.{name}({args})");
        let rows=db.query("SELECT p.prosrc,coalesce(p.oid=pg_catalog.to_regprocedure($3::text),false),p.prorettype=$2::text::pg_catalog.regtype,l.lanname,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes IS NULL,p.proallargtypes IS NULL,p.proparallel='u',p.prokind='f',p.pronargdefaults=0,p.proowner=c.relowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1",&[&name,&result,&signature]).await?;
        if rows.len() != 1 {
            return Err(ReviewedSendSchemaError::Invalid);
        }
        let row = &rows[0];
        let config = config.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let names = names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        if row.try_get::<_, String>(0)? != body(name, version)?
            || !row.try_get::<_, bool>(1)?
            || !row.try_get::<_, bool>(2)?
            || row.try_get::<_, String>(3)? != language
            || row.try_get::<_, String>(4)? != volatility
            || row.try_get::<_, bool>(5)? != strict
            || row.try_get::<_, bool>(6)? != definer
            || row.try_get::<_, bool>(7)? != set
            || row.try_get::<_, Option<Vec<String>>>(8)?.as_ref() != Some(&config)
            || row.try_get::<_, Option<Vec<String>>>(9)?.as_deref()
                != if names.is_empty() {
                    None
                } else {
                    Some(names.as_slice())
                }
            || !(10..16).all(|i| row.try_get::<_, bool>(i).unwrap_or(false))
        {
            return Err(ReviewedSendSchemaError::Invalid);
        }
    }
    Ok(())
}
/// Availability/schema only. A resolved legacy fixture without114 has no03
/// reviewed admission storage promise; missing, partial, altered and polluted114 always refuse.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let namespace:String=db.query_one("SELECT coalesce((SELECT n.nspname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('line_activation_v2_pending')),'public')",&[]).await?.try_get(0)?;
    let present=db.query_one("SELECT pg_catalog.to_regclass(pg_catalog.format('%I.conversation_reviewed_sends03',$1::text)) IS NOT NULL,EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname::text=$1::text AND p.proname LIKE 'conversation_reviewed_send03_%')",&[&namespace]).await?;
    let table: bool = present.try_get(0)?;
    let helper: bool = present.try_get(1)?;
    if !table && !helper {
        if namespace=="public" && db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?.try_get::<_,bool>(0)? {
       crate::payload_profile_writer::optional(db,"public.line_activation_v2_pending").await?;
       let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get(0)?;
       if !matches!(version,108..=113){return Err(ReviewedSendSchemaError::Invalid);}
      }
        return Ok(false);
    }
    if namespace != "public"
        || !table
        || !helper
        || !crate::payload_profile_writer::optional(db, "public.line_activation_v2_pending").await?
        || !crate::payload_profile_v2_receipts::optional(db).await?
        || !crate::payload_profile_elections::optional(db).await?
        || !crate::payload_profile_selections::optional(db).await?
        || !crate::payload_profile_manifests::optional(db).await?
        || !crate::conversation_profile03_storage::optional(db).await?
    {
        return Err(ReviewedSendSchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 114..=118) {
        return Err(ReviewedSendSchemaError::Invalid);
    }
    functions(db, version).await?;
    if db.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::pg_catalog.regnamespace AND(p.proname LIKE 'conversation_reviewed_send03_%') AND a.grantee=0)",&[]).await?.try_get::<_,bool>(0)? {return Err(ReviewedSendSchemaError::Invalid);}
    Ok(true)
}
/// Ordinary non-owning runtime capability only. The actual adapter separately
/// verifies original signatures, live owner/device selection and genuine MFA.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db).await?
        || !db
            .query_one("SELECT public.conversation_reviewed_send03_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(ReviewedSendSchemaError::Invalid);
    }
    Ok(())
}
/// Explicit V2 installation capability only. Old reviewed admission readiness
/// cannot supply this promise; actual signatures and live permission are separate.
pub async fn require_v2<C: GenericClient + Sync>(db: &C) -> Result<()> {
    require(db).await?;
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 117..=118)
        || !db
            .query_one("SELECT public.conversation_reviewed_send03_v2_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(ReviewedSendSchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "conversation_reviewed_send03_storage/v2_tests.rs"]
mod v2_tests;
