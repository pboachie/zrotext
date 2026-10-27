// SPDX-License-Identifier: AGPL-3.0-only
//! Narrow compatibility for the schema-107 logical-restore CHECK rendering.
//!
//! This is run in the same transaction as the unchanged migration 108, after
//! the complete historical ledger has been verified under the migration lock.
//! PostgreSQL's logical dump renders three `BETWEEN` checks as comparisons;
//! reparsing that output flattens their AND expression trees, which changes
//! migration 108's definition-graph digest without changing their predicates.

use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

use crate::{Migration, MigrationError};

const MIGRATION_108_SHA: [u8; 32] = [
    0x0d, 0xd0, 0xb6, 0x83, 0xe0, 0xd0, 0x4e, 0x7e, 0xa8, 0x1c, 0x95, 0xf6, 0xdc, 0xef, 0xae, 0x3f,
    0xfd, 0x71, 0xbf, 0x35, 0x9f, 0x41, 0x8e, 0x9e, 0xc8, 0xdf, 0xc9, 0xbe, 0xbd, 0xf1, 0x3d, 0x78,
];
const EXPECTED_GRAPH: &str = "d2348d448965a4c8fa28116a89571fa932bf8f05dc5eb5927c8aceb308c78d2b";
const RESTORED_GRAPH: &str = "3fb2f2389eb67957c58f5845752bf904c083110cd3afde1ff9be58cc4f5cbaec";
const HISTORICAL_107_INVENTORY_SHA: [u8; 32] = [
    0x70, 0xcc, 0x6b, 0x87, 0x1a, 0xc5, 0xd3, 0x61, 0x94, 0xc9, 0xad, 0x31, 0xfa, 0x4a, 0x45, 0x08,
    0x41, 0xe8, 0x4b, 0xce, 0x48, 0x6c, 0x3c, 0xfd, 0x50, 0xd1, 0xe5, 0x07, 0x39, 0x67, 0x60, 0x7a,
];
const HISTORICAL_108: &str =
    include_str!("../../../deploy/compose/migrations/108_payload_profile_writer_fences.sql");

// These are the exact public predicates from migrations 007, 043 and 076.
// Adding each CHECK without NOT VALID also validates all pre-existing rows.
const RESTORE_CANONICAL_CHECKS: &str = r#"
ALTER TABLE public.sealed_inbound_events
  DROP CONSTRAINT sealed_inbound_events_envelope_check;
ALTER TABLE public.sealed_inbound_events
  ADD CONSTRAINT sealed_inbound_events_envelope_check CHECK (
    envelope IS NULL OR (octet_length(envelope) BETWEEN 426 AND 34082 AND
      ((envelope_profile=1 AND substring(envelope from 1 for 6)=decode('5a5453450102','hex')) OR
       (envelope_profile=2 AND substring(envelope from 1 for 6)=decode('5a5453450202','hex'))))
  );
ALTER TABLE public.webhook_endpoints
  DROP CONSTRAINT webhook_endpoints_callback_url_check;
ALTER TABLE public.webhook_endpoints
  ADD CONSTRAINT webhook_endpoints_callback_url_check CHECK (
    length(callback_url) BETWEEN 9 AND 2048 AND callback_url LIKE 'https://%'
  );
ALTER TABLE public.workflow_action_versions
  DROP CONSTRAINT workflow_action_versions_check;
ALTER TABLE public.workflow_action_versions
  ADD CONSTRAINT workflow_action_versions_check CHECK (
    revision BETWEEN 1 AND 128 AND expires_at_ms > not_before_ms
  );
"#;

// The graph in migration 108 deliberately does not include comments, labels,
// dependencies or every pg_constraint attribute. Never discard any such
// operator metadata when replacing a constraint. Dependency object IDs refer
// to existing schema objects and must remain identical across replacement.
const CONSTRAINT_METADATA: &str = r#"
SELECT c.conname,
       (c.contype = 'c' AND c.convalidated AND c.conenforced
        AND NOT c.condeferrable AND NOT c.condeferred AND NOT c.connoinherit
        AND c.conislocal AND c.coninhcount = 0 AND c.conparentid = 0
        AND NOT c.conperiod
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_description d
          WHERE d.classoid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND d.objoid = c.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_seclabel s
          WHERE s.classoid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND s.objoid = c.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_init_privs p
          WHERE p.classoid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND p.objoid = c.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend s
          WHERE s.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND s.objid = c.oid AND s.dbid = (
              SELECT oid FROM pg_catalog.pg_database
              WHERE datname = pg_catalog.current_database()))
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.refclassid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND d.refobjid = c.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND d.objid = c.oid AND d.deptype NOT IN ('n', 'a'))
       ) AS safe,
       pg_catalog.json_build_array(
         c.connamespace::oid, c.conrelid::oid, c.contypid::oid,
         c.conindid::oid, c.conparentid::oid, c.confrelid::oid,
         c.conkey, c.confkey, c.conpfeqop, c.conppeqop, c.conffeqop,
         c.conexclop, c.conislocal, c.coninhcount, c.connoinherit,
         c.convalidated, c.conenforced, c.condeferrable, c.condeferred, c.conperiod,
         (SELECT pg_catalog.json_agg(
             pg_catalog.json_build_array(d.refclassid::oid, d.refobjid::oid,
                                         d.refobjsubid, d.deptype::text)
             ORDER BY d.refclassid, d.refobjid, d.refobjsubid, d.deptype)
          FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND d.objid = c.oid)
       )::text AS metadata
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_class r ON r.oid = c.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid = r.relnamespace
WHERE n.nspname = 'public' AND (r.relname, c.conname) IN (
  ('sealed_inbound_events', 'sealed_inbound_events_envelope_check'),
  ('webhook_endpoints', 'webhook_endpoints_callback_url_check'),
  ('workflow_action_versions', 'workflow_action_versions_check')
)
ORDER BY c.conname COLLATE "C"
"#;

async fn constraint_metadata(tx: &Transaction<'_>) -> Result<Vec<String>, MigrationError> {
    let rows = tx.query(CONSTRAINT_METADATA, &[]).await?;
    if rows.len() != 3 || rows.iter().any(|row| !row.get::<_, bool>(1)) {
        return Err(MigrationError::Restore107Compatibility(
            "restored CHECK metadata has unsupported dependencies or annotations",
        ));
    }
    Ok(rows.into_iter().map(|row| row.get(2)).collect())
}

/// Prepare the exact PostgreSQL 18.6 logical-restore representation for 108.
///
/// The caller must hold the migrator advisory lock, have checked the complete
/// ledger, and run the unmodified 108 plus its ledger insertion before commit.
/// Any error must abort this transaction, including after a CHECK replacement.
pub(crate) async fn prepare(
    tx: &Transaction<'_>,
    migration_sql: &str,
    migrations: &[Migration],
) -> Result<(), MigrationError> {
    // The caller's ledger validation alone only binds it to the supplied
    // directory. Bind that directory's full applied prefix independently to
    // the immutable 001-107 inventory before changing any database object.
    let Some(history) = migrations.get(..107) else {
        return Err(MigrationError::Restore107Compatibility(
            "the historical migration inventory is incomplete",
        ));
    };
    let mut inventory = Sha256::new();
    for (index, migration) in history.iter().enumerate() {
        if migration.version != (index as i64) + 1 || migration.checksum.len() != 32 {
            return Err(MigrationError::Restore107Compatibility(
                "the historical migration inventory is not contiguous",
            ));
        }
        let name = migration.filename.as_bytes();
        inventory.update(migration.version.to_be_bytes());
        inventory.update((name.len() as u64).to_be_bytes());
        inventory.update(name);
        inventory.update(&migration.checksum);
    }
    let inventory_digest: [u8; 32] = inventory.finalize().into();
    let Some(next) = migrations.get(107) else {
        return Err(MigrationError::Restore107Compatibility(
            "migration 108 is missing",
        ));
    };
    if inventory_digest != HISTORICAL_107_INVENTORY_SHA
        || next.version != 108
        || next.filename != "108_payload_profile_writer_fences.sql"
        || next.sql != migration_sql
    {
        return Err(MigrationError::Restore107Compatibility(
            "the migration inventory is not the pinned historical inventory",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(migration_sql.as_bytes()).into();
    if migration_sql != HISTORICAL_108 || digest != MIGRATION_108_SHA {
        return Err(MigrationError::Restore107Compatibility(
            "migration 108 source is not the pinned historical file",
        ));
    }
    let (verifier_prefix, _) = migration_sql.split_once("DO $migration$").ok_or(
        MigrationError::Restore107Compatibility("migration 108 verifier prefix is missing"),
    )?;

    // The caller's initial unqualified ledger lookup may have been shadowed by
    // a temporary table. Recheck and lock the actual public ledger in this
    // transaction. Keep pg_temp explicitly last through the 108 insertion.
    // Use the same lock and statement timeouts as the historical migration.
    tx.batch_execute(
        "SET LOCAL lock_timeout = '3s'; SET LOCAL statement_timeout = '30s';\
         SET LOCAL search_path TO pg_catalog, public, pg_temp;\
         LOCK TABLE public.schema_migrations IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await?;
    let ledger = tx
        .query(
            "SELECT version, filename, checksum_sha256, kind \
             FROM public.schema_migrations ORDER BY version",
            &[],
        )
        .await?;
    if ledger.len() != 107
        || ledger.iter().zip(history).any(|(row, expected)| {
            let version: i64 = row.get(0);
            let filename: String = row.get(1);
            let checksum: Vec<u8> = row.get(2);
            let kind: String = row.get(3);
            version != expected.version
                || filename != expected.filename
                || checksum != expected.checksum
                || !matches!(kind.as_str(), "applied" | "legacy_baseline")
        })
    {
        return Err(MigrationError::Restore107Compatibility(
            "the public migration ledger does not match the pinned 001-107 inventory",
        ));
    }

    // Install only the exact verifier prefix from the pinned migration, in
    // this transaction. Existing colliding functions cause CREATE to refuse.
    tx.batch_execute(verifier_prefix).await?;
    let graph: String = tx
        .query_one(
            "SELECT pg_catalog.encode(public.payload_profile_writer_prior_graph(), 'hex')",
            &[],
        )
        .await?
        .get(0);
    if graph == RESTORED_GRAPH {
        let version: i32 = tx
            .query_one("SELECT current_setting('server_version_num')::integer", &[])
            .await?
            .get(0);
        if version != 180006 {
            return Err(MigrationError::Restore107Compatibility(
                "restored graph requires the reviewed PostgreSQL 18.6 renderer",
            ));
        }
        // The canonical path needs no extra table locks. For the exact
        // restored graph, lock all affected tables and recheck the *complete*
        // graph before the first DDL; hold those locks through migration 108.
        tx.batch_execute(
            "LOCK TABLE public.sealed_inbound_events, public.webhook_endpoints, \
             public.workflow_action_versions IN ACCESS EXCLUSIVE MODE;",
        )
        .await?;
        let locked_graph: String = tx
            .query_one(
                "SELECT pg_catalog.encode(public.payload_profile_writer_prior_graph(), 'hex')",
                &[],
            )
            .await?
            .get(0);
        if locked_graph != RESTORED_GRAPH {
            return Err(MigrationError::Restore107Compatibility(
                "the restored definition graph changed while acquiring locks",
            ));
        }
        let original_metadata = constraint_metadata(tx).await?;
        tx.batch_execute(RESTORE_CANONICAL_CHECKS).await?;
        if constraint_metadata(tx).await? != original_metadata {
            return Err(MigrationError::Restore107Compatibility(
                "CHECK reconstruction changed constraint metadata or dependencies",
            ));
        }
        let canonical: String = tx
            .query_one(
                "SELECT pg_catalog.encode(public.payload_profile_writer_prior_graph(), 'hex')",
                &[],
            )
            .await?
            .get(0);
        if canonical != EXPECTED_GRAPH {
            return Err(MigrationError::Restore107Compatibility(
                "CHECK reconstruction did not produce the canonical graph",
            ));
        }
    }

    // All other graphs are left untouched and must pass the historical 108
    // guards themselves. In particular, this does not bless unknown shapes.
    // The actual historical file must create and run these functions itself;
    // its complete existing guards are not replaced by this preflight.
    tx.batch_execute(
        "DROP FUNCTION public.payload_profile_writer_prior_graph(); \
         DROP FUNCTION public.payload_profile_writer_json(json); \
         SET LOCAL search_path TO public, pg_temp;",
    )
    .await?;
    Ok(())
}
