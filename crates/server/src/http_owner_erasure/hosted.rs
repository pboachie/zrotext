// SPDX-License-Identifier: AGPL-3.0-only
//! Treat hosted storage as one installation, never independently optional rows.
use super::TableCount;
use postgres_protocol::escape::escape_identifier;
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) const BLOCKERS: &[&str] = &[
    "hosted_billing_customers",
    "hosted_billing_projections",
    "hosted_billing_history",
    "hosted_billing_events",
    "hosted_billing_audit",
    "hosted_billing_usage",
    "hosted_billing_resolutions",
];
const TABLES: &[&str] = &[
    "hosted_billing_namespaces",
    "hosted_billing_customers",
    "hosted_billing_projections",
    "hosted_billing_history",
    "hosted_billing_events",
    "hosted_billing_audit",
    "hosted_billing_usage",
    "hosted_billing_resolutions",
    "hosted_runtime_secrets",
    "hosted_runtime_sessions",
];

/// No privilege changes or permission-error fallback. The caller retains its
/// transaction and performs the existing final owner/MFA and deletion fences.
pub(super) async fn blockers(tx: &Transaction<'_>, account: Uuid) -> Result<Vec<TableCount>, ()> {
    let row = tx.query_one(
        "SELECT n.oid,n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r' AND c.relpersistence='p'",
        &[],
    ).await.map_err(|_| ())?;
    let namespace: u32 = row.get(0);
    let name: String = row.get(1);
    if name.starts_with("pg_") || name == "information_schema" {
        return Err(());
    }
    let quoted = escape_identifier(&name);
    let shape = tx.query_one(
        "SELECT (SELECT count(*) FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND c.relname=ANY($2::text[]) AND c.relkind='r' AND c.relpersistence='p'),
         EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND pg_catalog.left(c.relname,7)='hosted_') OR
         EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.pronamespace=$1 AND pg_catalog.left(p.proname,7)='hosted_') OR
         EXISTS(SELECT FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace=$1 AND pg_catalog.left(t.tgname,7)='hosted_'),
         EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.pronamespace=$1 AND p.proname='hosted_runtime_schema_ready' AND p.pronargs=0 AND p.prorettype='pg_catalog.bool'::pg_catalog.regtype AND p.prokind='f'),
         EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND c.relname='schema_migrations' AND c.relkind='r' AND c.relpersistence='p'),
         EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND c.relname='schema_migrations')",
        &[&namespace, &TABLES],
    ).await.map_err(|_| ())?;
    if !shape.get::<_, bool>(1) {
        // Ledger evidence is needed only to distinguish genuine absence from
        // a damaged installation. A complete family needs no ledger privilege.
        if shape.get::<_, bool>(4) {
            if !shape.get::<_, bool>(3) {
                return Err(());
            }
            let readable: bool = tx.query_one(
                "SELECT pg_catalog.has_table_privilege(current_user,c.oid,'SELECT') OR pg_catalog.has_column_privilege(current_user,c.oid,'version','SELECT') FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND c.relname='schema_migrations'",
                &[&namespace],
            ).await.map_err(|_| ())?.get(0);
            if !readable || tx.query_one(
                &format!("SELECT EXISTS(SELECT FROM {quoted}.schema_migrations WHERE version>=106)"), &[],
            ).await.map_err(|_| ())?.get::<_, bool>(0) {
                return Err(());
            }
        }
        return Ok(Vec::new());
    }
    if shape.get::<_, i64>(0) != TABLES.len() as i64 || !shape.get::<_, bool>(2) {
        return Err(());
    }
    // The empty-namespace shortcut depends on these actual validated, nonnull
    // FK paths. Names and a readiness function alone cannot prove emptiness.
    let linked: bool = tx.query_one(
        "SELECT bool_and(EXISTS(SELECT FROM pg_catalog.pg_constraint k
          JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_class p ON p.oid=k.confrelid
          WHERE c.relnamespace=$1 AND p.relnamespace=$1 AND c.relname=e.child AND p.relname=e.parent
          AND k.contype='f' AND k.convalidated AND NOT k.condeferrable
          AND k.confupdtype='a' AND k.confdeltype='a'
          AND ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY x(n,ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=x.n AND NOT a.attisdropped ORDER BY x.ord)=e.columns
          AND ARRAY(SELECT a.attname::text FROM unnest(k.confkey) WITH ORDINALITY x(n,ord)
             JOIN pg_catalog.pg_attribute a ON a.attrelid=p.oid AND a.attnum=x.n AND NOT a.attisdropped ORDER BY x.ord)=e.columns
          AND NOT EXISTS(SELECT FROM unnest(k.conkey) x(n) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=x.n WHERE NOT a.attnotnull)))
         FROM (VALUES
          ('hosted_billing_customers','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_billing_projections','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_billing_events','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_billing_audit','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_billing_usage','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_billing_history','hosted_billing_customers',ARRAY['namespace_id','account_id']),
          ('hosted_billing_resolutions','hosted_billing_events',ARRAY['namespace_id','event_id']),
          ('hosted_runtime_secrets','hosted_billing_namespaces',ARRAY['namespace_id']),
          ('hosted_runtime_sessions','hosted_billing_namespaces',ARRAY['namespace_id'])) e(child,parent,columns)",
        &[&namespace],
    ).await.map_err(|_| ())?.get(0);
    let inherited: bool = tx.query_one(
        "SELECT EXISTS(SELECT FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid=i.inhparent WHERE c.relnamespace=$1 AND c.relname=ANY($2::text[]))",
        &[&namespace, &TABLES],
    ).await.map_err(|_| ())?.get(0);
    // Current native entry already pins both helpers and canonicalizes public.
    // The stock runtime may execute role_safe, whose SECURITY DEFINER body
    // includes schema_ready plus role/ownership/ACL checks; schema_ready itself
    // is deliberately internal. Nonpublic historical SQL fixtures retain their
    // original inventory check, never a fallback around the HTTP native gate.
    let readiness = if name == "public" {
        "hosted_runtime_role_safe"
    } else {
        "hosted_runtime_schema_ready"
    };
    if !linked
        || inherited
        || !tx
            .query_one(&format!("SELECT {quoted}.{readiness}() IS TRUE"), &[])
            .await
            .map_err(|_| ())?
            .get::<_, bool>(0)
    {
        return Err(());
    }
    let populated: bool = tx
        .query_one(
            &format!("SELECT EXISTS(SELECT FROM {quoted}.hosted_billing_namespaces)"),
            &[],
        )
        .await
        .map_err(|_| ())?
        .get(0);
    if !populated {
        // Every hosted blocker must reach a namespace by the checked FK paths.
        // No operator-only table needs to become readable by the service role.
        return Ok(Vec::new());
    }
    let readable: bool = tx.query_one(
        "SELECT bool_and(pg_catalog.has_table_privilege(current_user,c.oid,'SELECT') OR pg_catalog.has_column_privilege(current_user,c.oid,'account_id','SELECT')) FROM pg_catalog.pg_class c WHERE c.relnamespace=$1 AND c.relname=ANY($2::text[])",
        &[&namespace, &BLOCKERS],
    ).await.map_err(|_| ())?.get(0);
    if !readable {
        return Err(());
    }
    let mut result = Vec::new();
    for &table in BLOCKERS {
        let count: i64 = tx
            .query_one(
                &format!(
                    "SELECT count(*) FROM {quoted}.{} WHERE account_id=$1",
                    escape_identifier(table)
                ),
                &[&account],
            )
            .await
            .map_err(|_| ())?
            .get(0);
        if count > 0 {
            result.push(TableCount {
                table,
                rows: count as u64,
            });
        }
    }
    Ok(result)
}
