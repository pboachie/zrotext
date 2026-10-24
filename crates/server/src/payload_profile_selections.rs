// SPDX-License-Identifier: AGPL-3.0-only
//! Closed physical-selection storage, never authentication or signature proof.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/111_payload_profile_selection_refresh.sql");

#[derive(Debug, thiserror::Error)]
pub enum SelectionSchemaError {
    #[error("physical selection schema unavailable")]
    Invalid,
    #[error("physical selection writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("original activation receipt unavailable")]
    Receipt(#[from] crate::payload_profile_v2_receipts::ReceiptSchemaError),
    #[error("accepted election unavailable")]
    Election(#[from] crate::payload_profile_elections::ElectionSchemaError),
    #[error("physical selection storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, SelectionSchemaError>;
fn body(name: &str, version: i64) -> Result<&'static str> {
    let source = if version == 119
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        ) {
        include_str!("../../../deploy/compose/migrations/119_conversation_profile03_effects.sql")
    } else if version == 118
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/118_device_protection_origins.sql")
    } else if matches!(version, 117..=119)
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/117_explicit_reviewed_intent_v2.sql")
    } else if matches!(version, 116..=119)
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
    } else if matches!(version, 115..=119)
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/115_conversation_profile03_grants.sql")
    } else if version == 114
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/114_conversation_reviewed_sends03.sql")
    } else if version == 113
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        include_str!("../../../deploy/compose/migrations/113_conversation_profile03_intervals.sql")
    } else if matches!(version, 112..=119)
        && matches!(
            name,
            "payload_profile_selection_scope"
                | "payload_profile_selection_same_scope"
                | "payload_profile_writer_version"
                | "payload_profile_writer_ready"
        )
    {
        include_str!(
            "../../../deploy/compose/migrations/112_payload_profile_manifest_successors.sql"
        )
    } else {
        MIGRATION
    };
    zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        source,
        name,
        "$function$",
    )
    .ok_or(SelectionSchemaError::Invalid)
}
async fn functions<C: GenericClient + Sync>(db: &C, version: i64) -> Result<()> {
    for (name, args, result, language, volatility, strict, definer, set, config, names) in [
        (
            "payload_profile_selection_scope",
            "uuid, uuid, uuid, bytea",
            "public.payload_profile_selection_challenges",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "owner_user", "owner_session", "core"] as &[&str]),
        ),
        (
            "payload_profile_selection_owner",
            "uuid, uuid, uuid",
            "bigint",
            "plpgsql",
            "v",
            false,
            true,
            false,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "owner_user", "owner_session"] as &[&str]),
        ),
        (
            "payload_profile_selection_observation",
            "bytea, integer",
            "void",
            "plpgsql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["observation", "selected_subscription"] as &[&str]),
        ),
        (
            "payload_profile_selection_reserve",
            "uuid, uuid, uuid, uuid, bytea, bigint",
            "public.payload_profile_selection_challenges",
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
                "core",
                "factor_deadline_ms",
            ] as &[&str]),
        ),
        (
            "payload_profile_selection_device_proof",
            "uuid, uuid, bytea, bytea",
            "public.payload_profile_selection_challenges",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "refresh", "observation", "signature"] as &[&str]),
        ),
        (
            "payload_profile_selection_approve",
            "uuid, uuid, uuid, bytea, bigint",
            "public.payload_profile_selection_receipts",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[
                "account",
                "opening",
                "refresh",
                "bundle",
                "factor_deadline_ms",
            ] as &[&str]),
        ),
        (
            "payload_profile_selection_install",
            "uuid, uuid, bytea, bytea",
            "public.payload_profile_selection_receipts",
            "plpgsql",
            "v",
            false,
            true,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "refresh", "bundle_sha256", "signature"] as &[&str]),
        ),
        (
            "payload_profile_selection_same_scope",
            "jsonb, jsonb",
            "boolean",
            "sql",
            "i",
            true,
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["older", "newer"] as &[&str]),
        ),
        (
            "payload_profile_selection_rows_guard",
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
            "payload_profile_selection_complete",
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
            "payload_profile_selection_ready",
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
            return Err(SelectionSchemaError::Invalid);
        }
        let row = &rows[0];
        let config = config.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let names = names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        if row.try_get::<_, String>(0)? != body(name, version)?
            || row.try_get::<_, String>(1)? != args
            || !row.try_get::<_, bool>(2)?
            || row.try_get::<_, String>(3)? != language
            || row.try_get::<_, String>(4)?
                != if matches!(version, 112..=119) && name == "payload_profile_selection_same_scope"
                {
                    "s"
                } else {
                    volatility
                }
            || row.try_get::<_, bool>(5)? != strict
            || row.try_get::<_, bool>(6)?
                != (definer
                    || matches!(version, 112..=119)
                        && name == "payload_profile_selection_same_scope")
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
            return Err(SelectionSchemaError::Invalid);
        }
    }
    Ok(())
}
/// Availability/schema only. A resolved legacy fixture without111 has no03
/// upgrade promise; missing, partial, altered and polluted111 always refuse.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let namespace:String=db.query_one("SELECT coalesce((SELECT n.nspname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('line_activation_v2_pending')),'public')",&[]).await?.try_get(0)?;
    let present=db.query_one("SELECT pg_catalog.to_regclass(pg_catalog.format('%I.payload_profile_selection_challenges',$1::text)) IS NOT NULL,pg_catalog.to_regclass(pg_catalog.format('%I.payload_profile_selection_receipts',$1::text)) IS NOT NULL,EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname::text=$1::text AND(p.proname LIKE 'payload_profile_selection_%'))",&[&namespace]).await?;
    let challenge: bool = present.try_get(0)?;
    let accepted: bool = present.try_get(1)?;
    let helper: bool = present.try_get(2)?;
    if !challenge && !accepted && !helper {
        if namespace=="public" && db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?.try_get::<_,bool>(0)? {
   crate::payload_profile_writer::optional(db,"public.line_activation_v2_pending").await?;
   let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get(0)?;
   if !matches!(version,108..=110){return Err(SelectionSchemaError::Invalid);}
  }
        return Ok(false);
    }
    if namespace != "public"
        || !challenge
        || !accepted
        || !helper
        || !crate::payload_profile_writer::optional(db, "public.line_activation_v2_pending").await?
        || !crate::payload_profile_v2_receipts::optional(db).await?
        || !crate::payload_profile_elections::optional(db).await?
    {
        return Err(SelectionSchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 111..=119) {
        return Err(SelectionSchemaError::Invalid);
    }
    functions(db, version).await?;
    if db.query_one("SELECT EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::pg_catalog.regnamespace AND(p.proname LIKE 'payload_profile_selection_%') AND a.grantee=0)",&[]).await?.try_get::<_,bool>(0)? {return Err(SelectionSchemaError::Invalid);}
    Ok(true)
}
/// Ordinary non-owning runtime capability only. The actual adapter separately
/// verifies original signatures, live owner/device selection and genuine MFA.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db).await?
        || !db
            .query_one("SELECT public.payload_profile_selection_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(SelectionSchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
