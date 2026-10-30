//! Strict, transactionally gated compatibility for the selected PG18.6 schema119 roundtrip.
//! Numbered migrations and the recorded writer-graph guard remain unchanged.
use crate::{Migration, MigrationError};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};

const HISTORY: [u8; 32] = [
    0xbb, 0xd3, 0xb3, 0xaf, 0x6e, 0xc5, 0x05, 0xce, 0xf5, 0xbb, 0x8e, 0xa3, 0x1d, 0x66, 0x60, 0x0d,
    0x1c, 0x24, 0x82, 0x6a, 0x1f, 0xa2, 0x51, 0x0f, 0x24, 0xea, 0x9d, 0xac, 0x6e, 0xb2, 0xe2, 0xb4,
];
const CANONICAL: &str = "39964f6cb79f7792292515d8afb0d875f024490039aebcb4159cddd0b9f608d1";
const RESTORED: &str = "d8e5e8b412f5884af5d1d8e5d40f4afe445dac476725caf6daabbf469440a8f3";
const M109: &str =
    include_str!("../../../deploy/compose/migrations/109_original_sealed_activation_receipts.sql");
const RECONSTITUTE: &str = r#"
ALTER TABLE public.conversation_profile03_closure_challenges DROP CONSTRAINT conversation_profile03_closure_challenges_check4;
ALTER TABLE public.conversation_profile03_closure_challenges ADD CONSTRAINT conversation_profile03_closure_challenges_check4 CHECK(octet_length(proof_site_id) BETWEEN 1 AND 256 AND octet_length(proof_instance_id) BETWEEN 1 AND 256);
ALTER TABLE public.conversation_profile03_closure_records DROP CONSTRAINT conversation_profile03_closure_records_check;
ALTER TABLE public.conversation_profile03_closure_records ADD CONSTRAINT conversation_profile03_closure_records_check CHECK(segment_count BETWEEN 1 AND 6 AND closed_from IN(0,1) AND closed_ms>=submit_observed_ms);
ALTER TABLE public.conversation_profile03_outcomes DROP CONSTRAINT conversation_profile03_outcomes_check;
ALTER TABLE public.conversation_profile03_outcomes ADD CONSTRAINT conversation_profile03_outcomes_check CHECK(segment_count BETWEEN 1 AND 6 AND evidence BETWEEN 0 AND 5);
"#;
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
  ('conversation_profile03_closure_challenges', 'conversation_profile03_closure_challenges_check4'),
  ('conversation_profile03_closure_records', 'conversation_profile03_closure_records_check'),
  ('conversation_profile03_outcomes', 'conversation_profile03_outcomes_check')
)
ORDER BY c.conname COLLATE "C"
"#;
fn refusal(s: &'static str) -> MigrationError {
    MigrationError::Restore119Compatibility(s)
}

fn graph_query() -> Result<&'static str, MigrationError> {
    let marker = "CREATE OR REPLACE FUNCTION public.payload_profile_writer_graph() RETURNS bytea\nLANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$";
    let (_, tail) = M109
        .split_once(marker)
        .ok_or(refusal("historical graph source missing"))?;
    let (body, _) = tail
        .split_once("$function$;")
        .ok_or(refusal("historical graph source incomplete"))?;
    Ok(body)
}

async fn graph(tx: &Transaction<'_>) -> Result<Vec<u8>, MigrationError> {
    Ok(tx.query_one(graph_query()?, &[]).await?.get(0))
}

async fn metadata(tx: &Transaction<'_>) -> Result<Vec<String>, MigrationError> {
    let rows = tx.query(CONSTRAINT_METADATA, &[]).await?;
    if rows.len() != 3 || rows.iter().any(|row| !row.get::<_, bool>(1)) {
        return Err(refusal("unsafe CHECK metadata"));
    }
    Ok(rows.into_iter().map(|row| row.get(2)).collect())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) async fn repair(
    client: &mut Client,
    migrations: &[Migration],
) -> Result<(), MigrationError> {
    // The installed ledger is exactly schema 119. A newer source directory
    // may contain a tail to apply after the repair; authenticate only the
    // complete historical prefix against the pinned backup inventory.
    let Some(migrations) = migrations.get(..119) else {
        return Ok(());
    };
    let mut h = Sha256::new();
    for (index, m) in migrations.iter().enumerate() {
        if m.version != (index as i64) + 1 || m.checksum.len() != 32 {
            return Err(refusal("noncontiguous inventory"));
        }
        let name = m.filename.as_bytes();
        h.update(m.version.to_be_bytes());
        h.update((name.len() as u64).to_be_bytes());
        h.update(name);
        h.update(&m.checksum);
    }
    if <[u8; 32]>::from(h.finalize()) != HISTORY {
        return Ok(());
    }
    // Test-only synchronization isolates a ledger change after apply's first
    // ledger read but before the no-op snapshot.
    #[cfg(test)]
    if client
        .query_one(
            "SELECT current_setting('zrotext.restore119_snapshot_test_barrier',true) = 'enabled'",
            &[],
        )
        .await?
        .get::<_, Option<bool>>(0)
        == Some(true)
    {
        client.batch_execute("SELECT pg_catalog.pg_advisory_lock(119119096); SELECT pg_catalog.pg_advisory_unlock(119119096)").await?;
    }
    // Ordinary replay needs only a coherent read-only snapshot. A mismatch
    // never authorizes DDL: the repair transaction repeats every guard under
    // its locks before making any change.
    let snapshot = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    snapshot.batch_execute("SET LOCAL lock_timeout='200ms'; SET LOCAL statement_timeout='30s'; SET LOCAL search_path TO pg_catalog, pg_temp").await?;
    let snapshot_rows = snapshot.query("SELECT version,filename,checksum_sha256,kind FROM public.schema_migrations ORDER BY version", &[]).await?;
    if snapshot_rows.len() != 119
        || snapshot_rows.iter().zip(migrations).any(|(row, m)| {
            row.get::<_, i64>(0) != m.version
                || row.get::<_, String>(1) != m.filename
                || row.get::<_, Vec<u8>>(2) != m.checksum
                || !matches!(
                    row.get::<_, String>(3).as_str(),
                    "applied" | "legacy_baseline"
                )
        })
    {
        return Err(refusal("ledger mismatch"));
    }
    let observed: Vec<u8> = snapshot.query_one("SELECT graph_sha256 FROM public.payload_profile_writer_catalog WHERE singleton AND migration_version=119", &[]).await?.get(0);
    let unchanged = graph(&snapshot).await? == observed;
    snapshot.commit().await?;
    if unchanged {
        return Ok(());
    }
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='30s'; SET LOCAL search_path TO pg_catalog, pg_temp; LOCK TABLE public.schema_migrations IN SHARE ROW EXCLUSIVE MODE; LOCK TABLE public.payload_profile_writer_catalog IN SHARE ROW EXCLUSIVE MODE;").await?;
    let rows=tx.query("SELECT version,filename,checksum_sha256,kind FROM public.schema_migrations ORDER BY version",&[]).await?;
    if rows.len() != 119
        || rows.iter().zip(migrations).any(|(row, m)| {
            row.get::<_, i64>(0) != m.version
                || row.get::<_, String>(1) != m.filename
                || row.get::<_, Vec<u8>>(2) != m.checksum
                || !matches!(
                    row.get::<_, String>(3).as_str(),
                    "applied" | "legacy_baseline"
                )
        })
    {
        return Err(refusal("ledger mismatch"));
    }
    let stored: Vec<u8>=tx.query_one("SELECT graph_sha256 FROM public.payload_profile_writer_catalog WHERE singleton AND migration_version=119",&[]).await?.get(0);
    let current = graph(&tx).await?;
    if current == stored {
        tx.commit().await?;
        return Ok(());
    }
    if hex(&stored) != CANONICAL || hex(&current) != RESTORED {
        return Err(refusal("unrecognized graph pair"));
    }
    let version: i32 = tx
        .query_one("SELECT current_setting('server_version_num')::int", &[])
        .await?
        .get(0);
    if version != 180006 {
        return Err(refusal("unsupported renderer"));
    }
    // Exact PG18.6 system-catalog relation set, including shared catalogs.
    // Any active catalog writer or unsupported privileges fail immediately.
    tx.batch_execute(r#"DO $fence$
DECLARE target text; observed text[]; expected constant text[] := ARRAY['pg_aggregate:2600:false','pg_am:2601:false','pg_amop:2602:false','pg_amproc:2603:false','pg_attrdef:2604:false','pg_attribute:1249:false','pg_auth_members:1261:true','pg_authid:1260:true','pg_cast:2605:false','pg_class:1259:false','pg_collation:3456:false','pg_constraint:2606:false','pg_conversion:2607:false','pg_database:1262:true','pg_db_role_setting:2964:true','pg_default_acl:826:false','pg_depend:2608:false','pg_description:2609:false','pg_enum:3501:false','pg_event_trigger:3466:false','pg_extension:3079:false','pg_foreign_data_wrapper:2328:false','pg_foreign_server:1417:false','pg_foreign_table:3118:false','pg_index:2610:false','pg_inherits:2611:false','pg_init_privs:3394:false','pg_language:2612:false','pg_largeobject:2613:false','pg_largeobject_metadata:2995:false','pg_namespace:2615:false','pg_opclass:2616:false','pg_operator:2617:false','pg_opfamily:2753:false','pg_parameter_acl:6243:true','pg_partitioned_table:3350:false','pg_policy:3256:false','pg_proc:1255:false','pg_publication:6104:false','pg_publication_namespace:6237:false','pg_publication_rel:6106:false','pg_range:3541:false','pg_replication_origin:6000:true','pg_rewrite:2618:false','pg_seclabel:3596:false','pg_sequence:2224:false','pg_shdepend:1214:true','pg_shdescription:2396:true','pg_shseclabel:3592:true','pg_statistic:2619:false','pg_statistic_ext:3381:false','pg_statistic_ext_data:3429:false','pg_subscription:6100:true','pg_subscription_rel:6102:false','pg_tablespace:1213:true','pg_transform:3576:false','pg_trigger:2620:false','pg_ts_config:3602:false','pg_ts_config_map:3603:false','pg_ts_dict:3600:false','pg_ts_parser:3601:false','pg_ts_template:3764:false','pg_type:1247:false','pg_user_mapping:1418:false'];
BEGIN
  SELECT array_agg(c.relname::text || ':' || c.oid::text || ':' || c.relisshared::text ORDER BY c.relname COLLATE "C") INTO observed
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='pg_catalog' AND c.relkind IN ('r','p');
  IF observed IS DISTINCT FROM expected THEN RAISE EXCEPTION 'unrecognized catalog set'; END IF;
  FOREACH target IN ARRAY expected LOOP
    EXECUTE pg_catalog.format('LOCK TABLE pg_catalog.%I IN SHARE MODE NOWAIT',pg_catalog.split_part(target,':',1));
  END LOOP;
  SELECT array_agg(c.relname::text || ':' || c.oid::text || ':' || c.relisshared::text ORDER BY c.relname COLLATE "C") INTO observed
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='pg_catalog' AND c.relkind IN ('r','p');
  IF observed IS DISTINCT FROM expected THEN RAISE EXCEPTION 'catalog set changed'; END IF;
END $fence$;"#).await?;
    // Catalog locks block new catalog writers but cannot stop an earlier DDL
    // transaction from committing writes whose catalog locks it released.
    // Require superuser visibility and refuse every other assigned transaction
    // ID or prepared transaction cluster-wide before the final graph read.
    let is_superuser: bool = tx.query_one("SELECT rolsuper FROM pg_catalog.pg_roles WHERE oid=(CURRENT_USER::pg_catalog.regrole)::oid", &[]).await?.get(0);
    if !is_superuser {
        return Err(refusal("cluster transaction visibility unavailable"));
    }
    tx.batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
        .await?;
    let blockers: i64 = tx.query_one("SELECT (SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid<>pg_catalog.pg_backend_pid() AND backend_xid IS NOT NULL) + (SELECT count(*) FROM pg_catalog.pg_prepared_xacts)", &[]).await?.get(0);
    if blockers != 0 {
        return Err(refusal("concurrent or prepared transaction present"));
    }
    tx.batch_execute("LOCK TABLE public.conversation_profile03_closure_challenges, public.conversation_profile03_closure_records, public.conversation_profile03_outcomes IN ACCESS EXCLUSIVE MODE NOWAIT;").await?;
    if hex(&graph(&tx).await?) != RESTORED {
        return Err(refusal("graph changed while locking"));
    }
    let before = metadata(&tx).await?;
    // Test-only rendezvous holds the catalog fence while a competitor tries DDL.
    #[cfg(test)]
    if tx
        .query_one(
            "SELECT current_setting('zrotext.restore119_test_barrier',true) = 'enabled'",
            &[],
        )
        .await?
        .get::<_, Option<bool>>(0)
        == Some(true)
    {
        tx.batch_execute("SET LOCAL lock_timeout=0; SELECT pg_catalog.pg_advisory_xact_lock(119119095); SET LOCAL lock_timeout='3s'")
            .await?;
    }
    tx.batch_execute(RECONSTITUTE).await?;
    // Test-only interruption proves all replacements roll back together.
    #[cfg(test)]
    if tx
        .query_one(
            "SELECT current_setting('zrotext.restore119_test_abort',true) = 'enabled'",
            &[],
        )
        .await?
        .get::<_, Option<bool>>(0)
        == Some(true)
    {
        return Err(refusal("synthetic interruption"));
    }

    if metadata(&tx).await? != before || graph(&tx).await? != stored {
        return Err(refusal("restored metadata or graph mismatch"));
    }
    tx.commit().await?;
    Ok(())
}
