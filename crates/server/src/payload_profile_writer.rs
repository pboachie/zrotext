// SPDX-License-Identifier: AGPL-3.0-only
//! Closed writer-schema verification, never root/election/effect authentication.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/108_payload_profile_writer_fences.sql");
const MANIFEST_MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/112_payload_profile_manifest_successors.sql");
const SELECTION_MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/111_payload_profile_selection_refresh.sql");
const ELECTION_MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/110_payload_profile_elections.sql");
const RECEIPT_MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/109_original_sealed_activation_receipts.sql");

#[derive(Debug, thiserror::Error)]
pub enum WriterSchemaError {
    #[error("mandatory writer schema unavailable")]
    Invalid,
    #[error("mandatory writer schema storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, WriterSchemaError>;

fn body(name: &str, marker: &str, version: i64) -> Result<&'static str> {
    let source = if version == 116
        && matches!(
            name,
            "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "payload_profile_writer_guard"
        ) {
        include_str!(
            "../../../deploy/compose/migrations/116_hosted_native_transaction_identity.sql"
        )
    } else if matches!(version, 115..=116)
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
    } else if version == 112
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        MANIFEST_MIGRATION
    } else if version == 111
        && matches!(
            name,
            "payload_profile_writer_version" | "payload_profile_writer_ready"
        )
    {
        SELECTION_MIGRATION
    } else if matches!(version, 110..=116)
        && matches!(
            name,
            "payload_profile_writer_guard"
                | "user_membership_freshness_guard"
                | "payload_profile_writer_version"
                | "payload_profile_writer_ready"
        )
    {
        ELECTION_MIGRATION
    } else if matches!(version, 109..=116)
        && matches!(
            name,
            "payload_profile_writer_graph"
                | "payload_profile_writer_version"
                | "payload_profile_writer_ready"
        )
    {
        RECEIPT_MIGRATION
    } else {
        MIGRATION
    };
    source
        .split_once(&format!("FUNCTION public.{name}("))
        .and_then(|(_, sql)| sql.split_once(&format!("AS {marker}")))
        .and_then(|(_, sql)| sql.split_once(&format!("{marker};")))
        .map(|(body, _)| body)
        .ok_or(WriterSchemaError::Invalid)
}

async fn functions<C: GenericClient + Sync>(db: &C, version: i64) -> Result<()> {
    for (name, args, result, language, volatility, strict, definer, config, marker) in [
        (
            "payload_profile_writer_json",
            "json",
            "text",
            "plpgsql",
            "i",
            true,
            false,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "payload_profile_writer_guard",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            true,
            vec!["search_path=pg_catalog", "lock_timeout=3s"],
            "$function$",
        ),
        (
            "payload_profile_writer_global_guard",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            false,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "payload_profile_writer_catalog_guard",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            false,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "payload_profile_writer_graph",
            "",
            "bytea",
            "sql",
            "s",
            false,
            false,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "payload_profile_writer_version",
            "",
            "boolean",
            "sql",
            "s",
            false,
            true,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "payload_profile_writer_ready",
            "",
            "boolean",
            "sql",
            "s",
            false,
            false,
            vec!["search_path=pg_catalog"],
            "$function$",
        ),
        (
            "user_membership_freshness_guard",
            "",
            "trigger",
            "plpgsql",
            "v",
            false,
            true,
            vec!["search_path=pg_catalog", "lock_timeout=3s"],
            "$function$",
        ),
        (
            "auth_abuse_consume",
            "text, bytea, bytea, integer, integer, integer, integer",
            "boolean",
            "plpgsql",
            "v",
            false,
            false,
            vec!["search_path=pg_catalog"],
            "$$",
        ),
    ] {
        let rows = db.query(
            "SELECT p.prosrc,pg_catalog.oidvectortypes(p.proargtypes),pg_catalog.format_type(p.prorettype,NULL),l.lanname,p.provolatile::text,p.proisstrict,p.prosecdef,p.proconfig,p.proretset,p.proparallel::text,p.proowner=c.relowner
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
             JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass
             WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1",
            &[&name],
        ).await?;
        if rows.len() != 1 {
            return Err(WriterSchemaError::Invalid);
        }
        let row = &rows[0];
        if row.try_get::<_, String>(0)? != body(name, marker, version)?
            || row.try_get::<_, String>(1)? != args
            || row.try_get::<_, String>(2)? != result
            || row.try_get::<_, String>(3)? != language
            || row.try_get::<_, String>(4)? != volatility
            || row.try_get::<_, bool>(5)? != strict
            || row.try_get::<_, bool>(6)? != definer
            || row.try_get::<_, Option<Vec<String>>>(7)?.as_deref()
                != Some(
                    config
                        .iter()
                        .map(|s| (*s).to_owned())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
            || row.try_get::<_, bool>(8)?
            || row.try_get::<_, String>(9)? != "u"
            || !row.try_get::<_, bool>(10)?
        {
            return Err(WriterSchemaError::Invalid);
        }
    }
    Ok(())
}

/// Preserve legacy installations and isolated fixtures without108. Once the
/// exact resolved table has this migration, every known body and the entire
/// installed graph must match; extra/disabled/changed objects never get a pass.
pub(crate) async fn optional<C: GenericClient + Sync>(db: &C, table: &str) -> Result<bool> {
    let row = db.query_opt(
        "SELECT n.nspname::text,
          EXISTS(SELECT FROM pg_catalog.pg_class x WHERE x.relnamespace=c.relnamespace AND x.relname='payload_profile_writer_catalog' AND x.relkind='r'),
          EXISTS(SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname='zz_payload_profile_writer_before_change')
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass($1)",
        &[&table],
    ).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !row.try_get::<_, bool>(1)? {
        return if row.try_get::<_, bool>(2)? {
            Err(WriterSchemaError::Invalid)
        } else {
            Ok(false)
        };
    }
    if row.try_get::<_, String>(0)? != "public" || !row.try_get::<_, bool>(2)? {
        return Err(WriterSchemaError::Invalid);
    }
    let schemas: Vec<String> = db
        .query_one("SELECT pg_catalog.current_schemas(false)::text[]", &[])
        .await?
        .try_get(0)?;
    if !matches!(schemas.as_slice(), [a] if a=="public" || a=="pg_catalog")
        && !matches!(schemas.as_slice(), [a,b] if a=="pg_catalog" && b=="public")
    {
        return Err(WriterSchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if !matches!(version, 108..=116) {
        return Err(WriterSchemaError::Invalid);
    }
    functions(db, version).await?;
    let valid: bool = db.query_one(
        "SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=$1 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
         AND (SELECT count(*)=12 AND bool_and(revision>=0) FROM public.payload_profile_writer_global_fences)
         AND NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::pg_catalog.regnamespace AND t.tgisinternal AND t.tgenabled<>'O')
         AND NOT EXISTS(SELECT FROM pg_catalog.pg_proc p CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname LIKE 'payload_profile_writer_%' AND a.grantee=0 AND a.privilege_type='EXECUTE')
         AND NOT EXISTS(SELECT FROM pg_catalog.pg_class c CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::pg_catalog.regnamespace AND c.relkind IN ('r','p') AND a.grantee=0)
         AND NOT EXISTS(SELECT FROM pg_catalog.pg_attribute c JOIN pg_catalog.pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL pg_catalog.aclexplode(c.attacl) a WHERE r.relnamespace='public'::pg_catalog.regnamespace AND a.grantee=0)",
        &[&version],
    ).await?.try_get(0)?;
    if !valid {
        return Err(WriterSchemaError::Invalid);
    }
    Ok(true)
}

/// Required for a future production03 adapter. This additionally refuses
/// privileged/copied-role/direct-DML callers. It conveys no signed authority.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db, "public.accounts").await?
        || !db
            .query_one("SELECT public.payload_profile_writer_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(WriterSchemaError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
