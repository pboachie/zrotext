// SPDX-License-Identifier: AGPL-3.0-only
//! Closed original conversation03 interval storage, never authentication or signature proof.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/113_conversation_profile03_intervals.sql");

#[derive(Debug, thiserror::Error)]
pub enum ConversationSchemaError {
    #[error("conversation interval schema unavailable")]
    Invalid,
    #[error("conversation interval writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("original activation receipt unavailable")]
    Receipt(#[from] crate::payload_profile_v2_receipts::ReceiptSchemaError),
    #[error("accepted election unavailable")]
    Election(#[from] crate::payload_profile_elections::ElectionSchemaError),
    #[error("physical selection schema unavailable")]
    Selection(#[from] crate::payload_profile_selections::SelectionSchemaError),
    #[error("manifest successor schema unavailable")]
    Manifest(#[from] crate::payload_profile_manifests::ManifestSchemaError),
    #[error("conversation interval storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ConversationSchemaError>;
fn body(name: &str, version: i64) -> Result<&'static str> {
    let source = if version == 114
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        ) {
        include_str!("../../../deploy/compose/migrations/114_conversation_reviewed_sends03.sql")
    } else {
        MIGRATION
    };
    source
        .split_once(&format!("FUNCTION public.{name}("))
        .and_then(|(_, sql)| sql.split_once("AS $function$"))
        .and_then(|(_, sql)| sql.split_once("$function$;"))
        .map(|(body, _)| body)
        .ok_or(ConversationSchemaError::Invalid)
}
async fn functions<C: GenericClient + Sync>(db: &C, version: i64) -> Result<()> {
    for (name, args, result, language, volatility, strict, definer, set, config, names) in [
        (
            "conversation_profile03_key_until",
            "bytea, integer, bytea, uuid, uuid, bigint",
            "bigint",
            "plpgsql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["manifest", "role", "key_id", "device", "line", "checked_ms"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_lock",
            "uuid, uuid",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "interval"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_reserve",
            "uuid, uuid, uuid, uuid, uuid, uuid, bytea, bigint",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "opening",
                "user_id",
                "owner_session",
                "interval",
                "receipt",
                "statement",
                "owner_deadline_ms",
            ] as &[&str]),
        ),
        (
            "conversation_profile03_interval_request",
            "uuid, uuid, uuid, bytea, bigint",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "opening",
                "interval",
                "owner_signature",
                "factor_deadline_ms",
            ] as &[&str]),
        ),
        (
            "conversation_profile03_interval_approve",
            "uuid, uuid, bytea",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "interval", "signature"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_install",
            "uuid, uuid, bytea",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "interval", "signature"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_stop",
            "uuid, uuid, uuid, uuid",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "interval", "user_id", "owner_session"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_device_actor",
            "uuid, uuid, uuid, text, text, bigint, bigint, bytea",
            "bytea",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "interval",
                "device",
                "site",
                "instance",
                "connection_epoch",
                "deployment_epoch",
                "statement_sha256",
            ] as &[&str]),
        ),
        (
            "conversation_profile03_interval_device_stop",
            "uuid, uuid, uuid, text, text, bigint, bigint, bytea",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "interval",
                "device",
                "site",
                "instance",
                "connection_epoch",
                "deployment_epoch",
                "statement_sha256",
            ] as &[&str]),
        ),
        (
            "conversation_profile03_interval_parse",
            "bytea",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["statement"] as &[&str]),
        ),
        (
            "conversation_profile03_interval_scope",
            "uuid, uuid, uuid, bytea, boolean",
            "public.conversation_profile03_intervals",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "user_id",
                "owner_session",
                "statement",
                "require_setup",
            ] as &[&str]),
        ),
        (
            "conversation_profile03_interval_rows_guard",
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
            "conversation_profile03_interval_complete",
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
            "conversation_profile03_interval_ready",
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
    ] {
        let rows=db.query("SELECT p.prosrc,pg_catalog.oidvectortypes(p.proargtypes),p.prorettype=$2::text::pg_catalog.regtype,l.lanname,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes IS NULL,p.proallargtypes IS NULL,p.proparallel='u',p.prokind='f',p.pronargdefaults=0,p.proowner=c.relowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1",&[&name,&result]).await?;
        if rows.len() != 1 {
            return Err(ConversationSchemaError::Invalid);
        }
        let row = &rows[0];
        let config = config.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let names = names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        if row.try_get::<_, String>(0)? != body(name, version)?
            || row.try_get::<_, String>(1)? != args
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
            return Err(ConversationSchemaError::Invalid);
        }
    }
    Ok(())
}
/// Availability/schema only. A resolved legacy fixture without113 has no03
/// content-consent storage promise; missing, partial, altered and polluted113 always refuse.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let namespace:String=db.query_one("SELECT coalesce((SELECT n.nspname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('line_activation_v2_pending')),'public')",&[]).await?.try_get(0)?;
    let present=db.query_one("SELECT pg_catalog.to_regclass(pg_catalog.format('%I.conversation_profile03_intervals',$1::text)) IS NOT NULL,EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname::text=$1::text AND p.proname LIKE 'conversation_profile03_%')",&[&namespace]).await?;
    let table: bool = present.try_get(0)?;
    let helper: bool = present.try_get(1)?;
    if !table && !helper {
        if namespace=="public" && db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?.try_get::<_,bool>(0)? {
       crate::payload_profile_writer::optional(db,"public.line_activation_v2_pending").await?;
       let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get(0)?;
       if !matches!(version,108..=112){return Err(ConversationSchemaError::Invalid);}
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
    {
        return Err(ConversationSchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 113..=114) {
        return Err(ConversationSchemaError::Invalid);
    }
    functions(db, version).await?;
    if db.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::pg_catalog.regnamespace AND(p.proname LIKE 'conversation_profile03_%') AND a.grantee=0)",&[]).await?.try_get::<_,bool>(0)? {return Err(ConversationSchemaError::Invalid);}
    Ok(true)
}
/// Ordinary non-owning runtime capability only. The actual adapter separately
/// verifies original signatures, live owner/device selection and genuine MFA.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db).await?
        || !db
            .query_one("SELECT public.conversation_profile03_interval_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(ConversationSchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
