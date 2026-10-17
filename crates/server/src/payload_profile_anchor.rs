// SPDX-License-Identifier: AGPL-3.0-only
//! Lifecycle retention reporting only; no profile election/current authority.
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub(crate) enum Retention {
    NotInstalled,
    Deleted,
    Invalid,
}

/// Inspect the exact application namespace, including relocated test schemas.
/// No fallback relation from a different search-path entry supplies a report.
pub(crate) async fn retention<C: GenericClient + Sync>(
    db: &C,
    account: Uuid,
) -> Result<Retention, tokio_postgres::Error> {
    let Some(row) = db.query_opt(
        "SELECT n.nspname::text,CASE WHEN EXISTS (
           SELECT FROM pg_catalog.pg_class a WHERE a.relnamespace=c.relnamespace
             AND a.relname='payload_profile_account_anchors' AND a.relkind='r'
         ) THEN pg_catalog.format('SELECT state,selection_epoch FROM %I.payload_profile_account_anchors WHERE account_id=$1',n.nspname) END
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r'", &[],
    ).await? else {
        return Ok(Retention::Invalid);
    };
    let namespace: String = row.get(0);
    if namespace.starts_with("pg_") || namespace == "information_schema" {
        return Ok(Retention::Invalid);
    }
    let Some(query) = row.get::<_, Option<String>>(1) else {
        return Ok(Retention::NotInstalled);
    };
    let Some(anchor) = db.query_opt(&query, &[&account]).await? else {
        return Ok(Retention::Invalid);
    };
    if anchor.try_get::<_, String>(0)? == "deleted" && anchor.try_get::<_, i64>(1)? > 0 {
        Ok(Retention::Deleted)
    } else {
        Ok(Retention::Invalid)
    }
}

#[cfg(test)]
mod tests;
