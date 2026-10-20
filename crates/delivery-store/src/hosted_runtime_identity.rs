// SPDX-License-Identifier: AGPL-3.0-only
//! Native-entry schema capability, never HMAC, owner or message authentication.
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/116_hosted_native_transaction_identity.sql");
#[derive(Debug, thiserror::Error)]
pub enum IdentitySchemaError {
    #[error("native hosted identity schema unavailable")]
    Invalid,
    #[error("native hosted identity storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, IdentitySchemaError>;
/// Extract one canonical, line-anchored SQL function declaration from reviewed
/// migration source. This is source metadata only, never runtime authority.
#[doc(hidden)]
pub fn declared_function_body<'a>(source: &'a str, name: &str, marker: &str) -> Option<&'a str> {
    let plain = format!("CREATE FUNCTION public.{name}(");
    let replacement = format!("CREATE OR REPLACE FUNCTION public.{name}(");
    let mut declaration = None;
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if line.starts_with(&plain) || line.starts_with(&replacement) {
            if declaration.is_some() {
                return None;
            }
            declaration = Some(offset);
        }
        offset += line.len();
    }
    source[declaration?..]
        .split_once(&format!("AS {marker}"))
        .and_then(|(_, after)| after.split_once(&format!("{marker};")))
        .map(|(body, _)| body)
}

fn body(name: &str) -> Result<&'static str> {
    let source = match name {
        "payload_profile_writer_json"
        | "payload_profile_writer_global_guard"
        | "payload_profile_writer_catalog_guard" => {
            include_str!("../../../deploy/compose/migrations/108_payload_profile_writer_fences.sql")
        }
        "payload_profile_writer_graph" => include_str!(
            "../../../deploy/compose/migrations/109_original_sealed_activation_receipts.sql"
        ),
        "hosted_runtime_schema_ready"
        | "hosted_runtime_role_safe"
        | "hosted_runtime_projection" => {
            include_str!("../../../deploy/compose/migrations/106_hosted_runtime.sql")
        }
        _ => MIGRATION,
    };
    declared_function_body(source, name, "$function$").ok_or(IdentitySchemaError::Invalid)
}
async fn functions<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for (
        name,
        signature,
        result,
        language,
        volatility,
        strict,
        definer,
        configuration,
        names,
        original_hashes,
    ) in [
        (
            "hosted_runtime_native_start",
            "public.hosted_runtime_native_start()",
            "pg_catalog.timestamptz",
            "plpgsql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_native_schema_valid",
            "public.hosted_runtime_native_schema_valid()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_identity_ready",
            "public.hosted_runtime_identity_ready()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_scope",
            "public.hosted_runtime_scope()",
            "pg_catalog.void",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_marker",
            "public.hosted_runtime_marker()",
            "public.hosted_billing_namespaces",
            "plpgsql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_request_apply",
            "public.hosted_runtime_request_apply()",
            "pg_catalog.trigger",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_request_remove",
            "public.hosted_runtime_request_remove()",
            "pg_catalog.trigger",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_challenge",
            "public.hosted_runtime_challenge(uuid, bigint)",
            "pg_catalog.bytea",
            "sql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["ns", "rev"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_bind",
            "public.hosted_runtime_bind(uuid, bigint, bytea)",
            "pg_catalog.bool",
            "sql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["ns", "rev", "proof"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_enter",
            "public.hosted_runtime_enter(uuid, bigint)",
            "pg_catalog.int8",
            "sql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["ns", "rev"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_verified",
            "public.hosted_runtime_verified(uuid, bigint)",
            "pg_catalog.bool",
            "sql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["ns", "rev"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_expiry",
            "public.hosted_runtime_expiry(uuid, bigint)",
            "pg_catalog.int8",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["ns", "rev"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "conversation_profile03_grant_billing",
            "public.conversation_profile03_grant_billing(uuid, uuid)",
            "pg_catalog.int8",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&["account", "message"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_guard",
            "public.payload_profile_writer_guard()",
            "pg_catalog.trigger",
            "plpgsql",
            "v",
            false,
            true,
            (&["search_path=pg_catalog", "lock_timeout=3s"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_version",
            "public.payload_profile_writer_version()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            true,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_ready",
            "public.payload_profile_writer_ready()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_json",
            "public.payload_profile_writer_json(json)",
            "text",
            "plpgsql",
            "i",
            true,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&["value"] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_global_guard",
            "public.payload_profile_writer_global_guard()",
            "pg_catalog.trigger",
            "plpgsql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_catalog_guard",
            "public.payload_profile_writer_catalog_guard()",
            "pg_catalog.trigger",
            "plpgsql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "payload_profile_writer_graph",
            "public.payload_profile_writer_graph()",
            "pg_catalog.bytea",
            "sql",
            "s",
            false,
            false,
            (&["search_path=pg_catalog"] as &[&str]),
            (&[] as &[&str]),
            (&[] as &[&str]),
        ),
        (
            "hosted_runtime_schema_ready",
            "public.hosted_runtime_schema_ready()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            false,
            (&["search_path=pg_catalog, public, pg_temp"] as &[&str]),
            (&[] as &[&str]),
            (&[
                "7aa17580ac81a8f630b55797daee4fd22b178b236605f71c21491cb85e30865b",
                "f4317324a9ba8ed8799696d4944d9382a847eaa98251e8d147353b159433102b",
            ] as &[&str]),
        ),
        (
            "hosted_runtime_role_safe",
            "public.hosted_runtime_role_safe()",
            "pg_catalog.bool",
            "sql",
            "s",
            false,
            true,
            (&["search_path=pg_catalog, public, pg_temp"] as &[&str]),
            (&[] as &[&str]),
            (&[
                "898ddd403142d0b048b0e528c2b2ab9832ed3197ca86f1dc271e7d0ed7a26b9b",
                "3aa8eb73d8355243b5181d500582d38609e5f5effe681bd14a8c8383f5db48c3",
            ] as &[&str]),
        ),
        (
            "hosted_runtime_projection",
            "public.hosted_runtime_projection(uuid)",
            "public.hosted_billing_projections",
            "plpgsql",
            "v",
            false,
            false,
            (&["search_path=pg_catalog, public, pg_temp"] as &[&str]),
            (&["owner_id"] as &[&str]),
            (&[
                "25cd5c35228ee26a82bda8d04084a763681d209b4f17ec8e0e92b51e417ed72e",
                "ba7fcf05e3069d2766bf90f7a868c52e55b2d9c1278bc9bb2279ce30e3b794c0",
            ] as &[&str]),
        ),
    ] {
        let row=db.query_opt("SELECT p.prosrc,p.proowner=c.relowner,p.prorettype=pg_catalog.to_regtype($2::text),l.lanname::text,p.provolatile::text,p.proisstrict,p.prosecdef,p.proconfig,p.proargnames,NOT p.proretset AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0 AND NOT p.proleakproof AND p.proargdefaults IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL AND(SELECT count(*) FROM pg_catalog.pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.oid=pg_catalog.to_regprocedure($1::text)",&[&signature,&result]).await?.ok_or(IdentitySchemaError::Invalid)?;
        let source: String = row.try_get(0)?;
        let original_hashes: &[&str] = original_hashes;
        let configuration = configuration
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        let names = names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let exact = if original_hashes.is_empty() {
            source == body(name)?
        } else {
            let hash = Sha256::digest(source.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            original_hashes.contains(&hash.as_str())
        };
        if !exact
            || !row.try_get::<_, bool>(1)?
            || !row.try_get::<_, bool>(2)?
            || row.try_get::<_, String>(3)? != language
            || row.try_get::<_, String>(4)? != volatility
            || row.try_get::<_, bool>(5)? != strict
            || row.try_get::<_, bool>(6)? != definer
            || row.try_get::<_, Option<Vec<String>>>(7)?.as_ref() != Some(&configuration)
            || row.try_get::<_, Option<Vec<String>>>(8)?.as_deref()
                != if names.is_empty() {
                    None
                } else {
                    Some(names.as_slice())
                }
            || !row.try_get::<_, bool>(9)?
        {
            return Err(IdentitySchemaError::Invalid);
        }
    }
    Ok(())
}
async fn tables<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for (name, columns) in [
        (
            "hosted_runtime_entries",
            &[
                "backend_pid:integer:true:false",
                "native_xid:xid8:true:false",
                "backend_start:timestamp with time zone:true:false",
                "namespace_id:uuid:true:false",
                "policy_revision:bigint:true:false",
                "expires_at:timestamp with time zone:true:false",
            ] as &[&str],
        ),
        (
            "hosted_runtime_requests",
            &[
                "operation:text:true:false",
                "namespace_id:uuid:true:false",
                "policy_revision:bigint:true:false",
                "proof:bytea:false:false",
                "native_pid:integer:true:true",
                "native_start:timestamp with time zone:true:true",
                "native_xid:xid8:true:true",
                "native_role:oid:true:true",
                "result:jsonb:false:false",
            ] as &[&str],
        ),
    ] {
        let row=db.query_one("SELECT c.relkind='r' AND c.relpersistence='p' AND c.relowner=a.relowner AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity,(SELECT pg_catalog.array_agg(x.attname||':'||pg_catalog.format_type(x.atttypid,x.atttypmod)||':'||x.attnotnull::text||':'||(d.adbin IS NOT NULL)::text ORDER BY x.attnum) FROM pg_catalog.pg_attribute x LEFT JOIN pg_catalog.pg_attrdef d ON(d.adrelid,d.adnum)=(x.attrelid,x.attnum) WHERE x.attrelid=c.oid AND x.attnum>0 AND NOT x.attisdropped) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_class a ON a.oid='public.accounts'::pg_catalog.regclass WHERE c.oid=pg_catalog.to_regclass(pg_catalog.format('public.%I',$1::text))",&[&name]).await?;
        let columns = columns.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        if !row.try_get::<_, bool>(0)? || row.try_get::<_, Vec<String>>(1)? != columns {
            return Err(IdentitySchemaError::Invalid);
        }
    }
    Ok(())
}
/// Explicit pre-installation fixtures may lack116. Partial, unknown or changed
/// installation always refuses; no older hosted helper implies this capability.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let row=db.query_one("SELECT pg_catalog.to_regclass('public.hosted_runtime_entries') IS NOT NULL,pg_catalog.to_regclass('public.hosted_runtime_requests') IS NOT NULL,EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname IN('hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_native_schema_valid','hosted_runtime_request_apply','hosted_runtime_request_remove','hosted_runtime_expiry','hosted_runtime_scope')),pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?;
    let entries: bool = row.try_get(0)?;
    let requests: bool = row.try_get(1)?;
    let helpers: bool = row.try_get(2)?;
    if !entries && !requests && !helpers {
        if row.try_get::<_, bool>(3)? {
            let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get(0)?;
            if !matches!(version, 108..=115) {
                return Err(IdentitySchemaError::Invalid);
            }
        }
        if db
            .query_one(
                "SELECT pg_catalog.to_regclass('public.schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get::<_, bool>(0)?
            && db
                .query_one(
                    "SELECT EXISTS(SELECT FROM public.schema_migrations WHERE version>=116)",
                    &[],
                )
                .await?
                .try_get::<_, bool>(0)?
        {
            return Err(IdentitySchemaError::Invalid);
        }
        return Ok(false);
    }
    if !entries || !requests || !helpers {
        return Err(IdentitySchemaError::Invalid);
    }
    let version: i64 = db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    if version!=116 || db.query_one("SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'hosted_runtime_%'",&[]).await?.try_get::<_,i64>(0)?!=15 {return Err(IdentitySchemaError::Invalid);}
    functions(db).await?;
    tables(db).await?;
    if !db.query_one("SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)",&[]).await?.try_get::<_,bool>(0)? {return Err(IdentitySchemaError::Invalid);}
    Ok(true)
}
/// Ordinary runtime schema/column capability only. Actual HMAC bind and native
/// same-transaction entry are required separately before hosted business work.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    if !optional(db).await?
        || !db
            .query_one("SELECT public.hosted_runtime_identity_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(IdentitySchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
