// SPDX-License-Identifier: AGPL-3.0-only
//! Exact read-only catalog verification for the dormant candidate; never installs it.
use tokio_postgres::Transaction;

const TABLES: [(&str, &str); 4] = [
    (
        "workflow_openings",
        "account_id:uuid id:uuid definition_version:bigint state_version:bigint capacity:smallint phase:text description_context_id:uuid? description_revision:bigint? description_digest:bytea? decision_deadline_ms:bigint? created_by_user:uuid? created_session:uuid? created_ms:bigint?",
    ),
    (
        "workflow_opening_offers",
        "account_id:uuid id:uuid opening_id:uuid opening_definition_version:bigint state_version:bigint phase:text binding_scrubbed:boolean contact_identity:uuid? current_contact_id:uuid? purpose:text? consent_episode_id:uuid? context_id:uuid? context_revision:bigint? context_digest:bytea? issued_ms:bigint? expires_ms:bigint? created_by_user:uuid? created_session:uuid?",
    ),
    (
        "workflow_opening_allocations",
        "account_id:uuid id:uuid opening_id:uuid binding_scrubbed:boolean offer_id:uuid? offer_state_version:bigint? contact_identity:uuid? event_id:uuid? event_digest:bytea? response_use_digest:bytea observed_ms:bigint? accepted_ms:bigint? decision_deadline_ms:bigint? phase:text state_version:bigint reserved_by_user:uuid? reserved_session:uuid? confirmed_by_user:uuid? confirmed_session:uuid? confirmed_ms:bigint?",
    ),
    (
        "workflow_opening_requests",
        "account_id:uuid request_id:uuid opening_id:uuid redacted:boolean admission_charged:boolean subject_kind:smallint? subject_id:uuid? operation:smallint? request_digest:bytea? result:bytea? actor_user_id:uuid? actor_session_id:uuid? committed_ms:bigint?",
    ),
];

const CHECKS: [(&str, &[&str]); 4] = [
    (
        "workflow_openings",
        &[
            "CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))",
            "CHECK ((definition_version > 0))",
            "CHECK ((state_version > 0))",
            "CHECK (((capacity >= 1) AND (capacity <= 100)))",
            "CHECK ((phase = ANY (ARRAY['open'::text, 'closed'::text, 'cancelled'::text])))",
            "CHECK (((description_revision >= 1) AND (description_revision <= 128)))",
            "CHECK ((octet_length(description_digest) = 32))",
            "CHECK ((decision_deadline_ms > 0))",
            "CHECK ((created_ms > 0))",
            "CHECK (((description_context_id IS NULL) = (description_revision IS NULL)))",
            "CHECK (((description_context_id IS NULL) = (description_digest IS NULL)))",
            "CHECK (((description_context_id IS NULL) = (decision_deadline_ms IS NULL)))",
            "CHECK (((phase <> 'open'::text) OR ((description_context_id IS NOT NULL) AND (decision_deadline_ms IS NOT NULL))))",
            "CHECK (((description_context_id IS NULL) = (created_by_user IS NULL)))",
            "CHECK (((description_context_id IS NULL) = (created_session IS NULL)))",
            "CHECK (((description_context_id IS NULL) = (created_ms IS NULL)))",
            "CHECK (((decision_deadline_ms IS NULL) OR (created_ms < decision_deadline_ms)))",
        ],
    ),
    (
        "workflow_opening_offers",
        &[
            "CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))",
            "CHECK ((opening_definition_version > 0))",
            "CHECK ((state_version > 0))",
            "CHECK ((phase = ANY (ARRAY['active'::text, 'closed'::text, 'withdrawn'::text, 'cancelled'::text, 'expired'::text])))",
            "CHECK ((purpose = ANY (ARRAY['transactional'::text, 'operational'::text, 'marketing'::text])))",
            "CHECK (((context_revision >= 1) AND (context_revision <= 128)))",
            "CHECK ((octet_length(context_digest) = 32))",
            "CHECK ((issued_ms > 0))",
            "CHECK ((expires_ms > issued_ms))",
            "CHECK (((current_contact_id IS NULL) OR (current_contact_id = contact_identity)))",
            "CHECK ((((NOT binding_scrubbed) AND (contact_identity IS NOT NULL) AND (current_contact_id IS NOT NULL) AND (purpose IS NOT NULL) AND (consent_episode_id IS NOT NULL) AND (context_id IS NOT NULL) AND (context_revision IS NOT NULL) AND (context_digest IS NOT NULL) AND (issued_ms IS NOT NULL) AND (expires_ms IS NOT NULL) AND (created_by_user IS NOT NULL) AND (created_session IS NOT NULL)) OR (binding_scrubbed AND (phase <> 'active'::text) AND (contact_identity IS NULL) AND (current_contact_id IS NULL) AND (purpose IS NULL) AND (consent_episode_id IS NULL) AND (context_id IS NULL) AND (context_revision IS NULL) AND (context_digest IS NULL) AND (issued_ms IS NULL) AND (expires_ms IS NULL) AND (created_by_user IS NULL) AND (created_session IS NULL))))",
        ],
    ),
    (
        "workflow_opening_allocations",
        &[
            "CHECK ((id <> '00000000-0000-0000-0000-000000000000'::uuid))",
            "CHECK ((offer_state_version > 0))",
            "CHECK ((octet_length(event_digest) = 32))",
            "CHECK ((octet_length(response_use_digest) = 32))",
            "CHECK ((observed_ms > 0))",
            "CHECK ((accepted_ms >= observed_ms))",
            "CHECK ((decision_deadline_ms > accepted_ms))",
            "CHECK ((phase = ANY (ARRAY['pending'::text, 'confirmed'::text, 'released'::text, 'cancelled'::text, 'expired'::text])))",
            "CHECK ((state_version > 0))",
            "CHECK (((confirmed_by_user IS NULL) = (confirmed_session IS NULL)))",
            "CHECK (((confirmed_by_user IS NULL) = (confirmed_ms IS NULL)))",
            "CHECK ((((NOT binding_scrubbed) AND (offer_id IS NOT NULL) AND (offer_state_version IS NOT NULL) AND (contact_identity IS NOT NULL) AND (event_id IS NOT NULL) AND (event_digest IS NOT NULL) AND (observed_ms IS NOT NULL) AND (accepted_ms IS NOT NULL) AND (decision_deadline_ms IS NOT NULL) AND (reserved_by_user IS NOT NULL) AND (reserved_session IS NOT NULL) AND ((phase <> 'confirmed'::text) OR (confirmed_ms IS NOT NULL))) OR (binding_scrubbed AND (phase <> 'pending'::text) AND (offer_id IS NULL) AND (offer_state_version IS NULL) AND (contact_identity IS NULL) AND (event_id IS NULL) AND (event_digest IS NULL) AND (observed_ms IS NULL) AND (accepted_ms IS NULL) AND (decision_deadline_ms IS NULL) AND (reserved_by_user IS NULL) AND (reserved_session IS NULL) AND (confirmed_by_user IS NULL) AND (confirmed_session IS NULL) AND (confirmed_ms IS NULL))))",
        ],
    ),
    (
        "workflow_opening_requests",
        &[
            "CHECK ((request_id <> '00000000-0000-0000-0000-000000000000'::uuid))",
            "CHECK (((subject_kind >= 1) AND (subject_kind <= 3)))",
            "CHECK (((operation >= 1) AND (operation <= 9)))",
            "CHECK ((octet_length(request_digest) = 32))",
            "CHECK (((octet_length(result) >= 1) AND (octet_length(result) <= 32768)))",
            "CHECK ((committed_ms > 0))",
            "CHECK ((((NOT redacted) AND (subject_kind IS NOT NULL) AND (subject_id IS NOT NULL) AND (operation IS NOT NULL) AND (request_digest IS NOT NULL) AND (result IS NOT NULL) AND (actor_user_id IS NOT NULL) AND (actor_session_id IS NOT NULL) AND (committed_ms IS NOT NULL)) OR (redacted AND (subject_kind IS NULL) AND (subject_id IS NULL) AND (operation IS NULL) AND (request_digest IS NULL) AND (result IS NULL) AND (actor_user_id IS NULL) AND (actor_session_id IS NULL) AND (committed_ms IS NULL))))",
        ],
    ),
];

const KEYS: [(&str, &[&str]); 4] = [
    ("workflow_openings", &["account_id,id"]),
    (
        "workflow_opening_offers",
        &["account_id,id", "account_id,opening_id,id"],
    ),
    (
        "workflow_opening_allocations",
        &["account_id,id", "account_id,response_use_digest"],
    ),
    ("workflow_opening_requests", &["account_id,request_id"]),
];
type ForeignKeySpec = (&'static str, &'static str, &'static str, &'static str);
const FOREIGN: [(&str, &[ForeignKeySpec]); 4] = [
    (
        "workflow_openings",
        &[
            ("account_id", "accounts", "id", "c"),
            (
                "account_id,description_context_id",
                "workflow_contexts",
                "account_id,id",
                "a",
            ),
        ],
    ),
    (
        "workflow_opening_offers",
        &[
            (
                "account_id,opening_id",
                "workflow_openings",
                "account_id,id",
                "c",
            ),
            (
                "account_id,current_contact_id",
                "contacts",
                "account_id,id",
                "a",
            ),
            (
                "account_id,context_id",
                "workflow_contexts",
                "account_id,id",
                "a",
            ),
        ],
    ),
    (
        "workflow_opening_allocations",
        &[
            (
                "account_id,opening_id,offer_id",
                "workflow_opening_offers",
                "account_id,opening_id,id",
                "a",
            ),
            (
                "account_id,opening_id",
                "workflow_openings",
                "account_id,id",
                "c",
            ),
        ],
    ),
    (
        "workflow_opening_requests",
        &[
            ("account_id", "accounts", "id", "c"),
            (
                "account_id,opening_id",
                "workflow_openings",
                "account_id,id",
                "c",
            ),
        ],
    ),
];
const INDEXES: [(&str, &str, &str); 4] = [
    (
        "workflow_opening_capacity_count",
        "workflow_opening_allocations",
        "account_id,opening_id,phase",
    ),
    (
        "workflow_opening_contact_lifecycle",
        "workflow_opening_offers",
        "account_id,contact_identity,purpose,opening_id",
    ),
    (
        "workflow_opening_source_lifecycle",
        "workflow_opening_offers",
        "account_id,context_id,opening_id",
    ),
    (
        "workflow_opening_request_subject",
        "workflow_opening_requests",
        "account_id,subject_kind,subject_id",
    ),
];
async fn refuse(tx: &Transaction<'_>) -> Result<(), tokio_postgres::Error> {
    // An actual SQL error aborts the borrowed caller transaction as well as
    // returning failure. Optional lifecycle callers cannot commit partial work.
    tx.batch_execute(
        "DO $$ BEGIN RAISE EXCEPTION 'opening schema inconsistent' USING ERRCODE='42P01'; END $$",
    )
    .await
}
/// Resolve the same unqualified names used by commands, and verify those exact
/// OIDs belong to the current schema. Never inspect a different named object.
pub(super) async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    let mut objects = Vec::new();
    for (name, _) in TABLES {
        let row=tx.query_one("SELECT to_regclass($1)::oid,(SELECT oid FROM pg_namespace WHERE nspname=current_schema())", &[&name]).await?;
        objects.push((
            name,
            row.try_get::<_, Option<u32>>(0)?,
            row.try_get::<_, Option<u32>>(1)?,
        ));
    }
    if objects.iter().all(|(_, oid, _)| oid.is_none()) {
        return Ok(false);
    }
    if objects
        .iter()
        .any(|(_, oid, namespace)| oid.is_none() || namespace.is_none())
    {
        refuse(tx).await?;
        return Ok(false);
    }
    let candidate_oids: Vec<u32> = objects
        .iter()
        .map(|(_, oid, _)| oid.expect("presence checked"))
        .collect();
    for ((name, schema), (_, oid, namespace)) in TABLES.iter().zip(&objects) {
        let oid = oid.expect("presence checked");
        let namespace = namespace.expect("namespace checked");
        let row=tx.query_one("SELECT relnamespace,relkind::text,relpersistence::text,relrowsecurity,relforcerowsecurity,EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=$1 OR inhparent=$1),EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=$1),EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=$1 AND NOT tgisinternal) FROM pg_class WHERE oid=$1", &[&oid]).await?;
        if row.try_get::<_, u32>(0)? != namespace
            || row.try_get::<_, String>(1)? != "r"
            || row.try_get::<_, String>(2)? != "p"
            || (3..8).any(|i| row.get::<_, bool>(i))
        {
            refuse(tx).await?;
        }
        let invalid_internal:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_trigger t LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint LEFT JOIN pg_proc p ON p.oid=t.tgfoid LEFT JOIN pg_namespace n ON n.oid=p.pronamespace WHERE t.tgrelid=$1 AND t.tgisinternal AND (t.tgenabled<>'O' OR k.contype IS DISTINCT FROM 'f' OR NOT (k.conrelid=ANY($2::oid[])) OR t.tgrelid NOT IN (k.conrelid,k.confrelid) OR n.nspname IS DISTINCT FROM 'pg_catalog' OR p.proname NOT LIKE 'RI_FKey_%'))", &[&oid,&candidate_oids]).await?.try_get(0)?;
        if invalid_internal {
            refuse(tx).await?;
        }
        let columns=tx.query("SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attidentity::text,a.attgenerated::text,a.atthasmissing,t.typname,a.attcollation=t.typcollation,n.nspname FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace n ON n.oid=t.typnamespace LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum", &[&oid]).await?;
        let expected: Vec<_> = schema.split_whitespace().collect();
        if columns.len() != expected.len() {
            refuse(tx).await?;
        }
        for (row, field) in columns.iter().zip(expected) {
            let (column, ty) = field.split_once(':').expect("static column descriptor");
            let builtin_name = match ty.trim_end_matches('?') {
                "bigint" => "int8",
                "smallint" => "int2",
                "boolean" => "bool",
                name => name,
            };
            let default = match (*name, column) {
                (
                    "workflow_opening_offers" | "workflow_opening_allocations",
                    "binding_scrubbed",
                )
                | ("workflow_opening_requests", "redacted") => Some("false"),
                ("workflow_opening_requests", "admission_charged") => Some("true"),
                _ => None,
            };
            if row.try_get::<_, String>(0)? != column
                || row.try_get::<_, String>(1)? != ty.trim_end_matches('?')
                || row.try_get::<_, bool>(2)? == ty.ends_with('?')
                || row.try_get::<_, Option<String>>(3)?.as_deref() != default
                || !row.try_get::<_, String>(4)?.is_empty()
                || !row.try_get::<_, String>(5)?.is_empty()
                || row.try_get::<_, bool>(6)?
                || row.try_get::<_, String>(7)? != builtin_name
                || !row.try_get::<_, bool>(8)?
                || row.try_get::<_, String>(9)? != "pg_catalog"
            {
                refuse(tx).await?;
            }
        }
        let constraints=tx.query("SELECT contype::text,convalidated,condeferrable,condeferred,pg_get_constraintdef(oid),ARRAY(SELECT a.attname::text FROM unnest(conkey) WITH ORDINALITY k(n,pos) JOIN pg_attribute a ON a.attrelid=conrelid AND a.attnum=k.n ORDER BY k.pos),confrelid,ARRAY(SELECT a.attname::text FROM unnest(confkey) WITH ORDINALITY k(n,pos) JOIN pg_attribute a ON a.attrelid=confrelid AND a.attnum=k.n ORDER BY k.pos),confupdtype::text,confdeltype::text,confmatchtype::text,conindid,connoinherit,COALESCE((to_jsonb(pg_constraint)->>'conenforced')::boolean,true) FROM pg_constraint WHERE conrelid=$1 ORDER BY oid", &[&oid]).await?;
        let mut checks = Vec::new();
        let mut keys = Vec::new();
        let mut foreign = Vec::new();
        for row in constraints {
            let kind: String = row.try_get(0)?;
            let no_inherit: bool = row.try_get(12)?;
            let unexpected_inheritance = match kind.as_str() {
                "c" => no_inherit,
                "p" | "u" | "f" => !no_inherit,
                _ => false,
            };
            if !row.try_get::<_, bool>(1)?
                || row.try_get::<_, bool>(2)?
                || row.try_get::<_, bool>(3)?
                || unexpected_inheritance
                || !row.try_get::<_, bool>(13)?
            {
                refuse(tx).await?;
            }
            let columns = row.try_get::<_, Vec<String>>(5)?.join(",");
            match kind.as_str() {
                "n" => {} // PostgreSQL18 catalogs NOT NULL; column shape checked above.
                "c" => checks.push(row.try_get::<_, String>(4)?),
                "p" | "u" => {
                    keys.push((kind, columns));
                    if !index_valid(tx, row.try_get(11)?, oid, true).await? {
                        refuse(tx).await?;
                    }
                }
                "f" => {
                    if row.try_get::<_, String>(8)? != "a" || row.try_get::<_, String>(10)? != "s" {
                        refuse(tx).await?;
                    }
                    foreign.push((
                        columns,
                        row.try_get::<_, u32>(6)?,
                        row.try_get::<_, Vec<String>>(7)?.join(","),
                        row.try_get::<_, String>(9)?,
                    ));
                }
                _ => {
                    refuse(tx).await?;
                }
            }
        }
        let expected_checks = CHECKS
            .iter()
            .find(|(table, _)| table == name)
            .expect("static checks")
            .1;
        if checks.len() != expected_checks.len() {
            refuse(tx).await?;
        }
        for expected in expected_checks {
            if let Some(index) = checks
                .iter()
                .position(|actual| actual.as_str() == *expected)
            {
                checks.remove(index);
            } else {
                refuse(tx).await?;
            }
        }
        let expected_keys = KEYS
            .iter()
            .find(|(table, _)| table == name)
            .expect("static keys")
            .1;
        let mut expected_keys: Vec<_> = expected_keys
            .iter()
            .enumerate()
            .map(|(i, k)| (if i == 0 { "p" } else { "u" }.to_owned(), k.to_string()))
            .collect();
        keys.sort();
        expected_keys.sort();
        if keys != expected_keys {
            refuse(tx).await?;
        }
        let mut expected_foreign = Vec::new();
        for (columns, target, target_columns, delete) in FOREIGN
            .iter()
            .find(|(table, _)| table == name)
            .expect("static foreign keys")
            .1
        {
            let row = tx
                .query_opt(
                    "SELECT c.oid,c.relnamespace FROM pg_class c WHERE c.oid=to_regclass($1)",
                    &[target],
                )
                .await?;
            let Some(row) = row else {
                refuse(tx).await?;
                return Ok(false);
            };
            if row.try_get::<_, u32>(1)? != namespace {
                refuse(tx).await?;
            }
            expected_foreign.push((
                columns.to_string(),
                row.try_get::<_, u32>(0)?,
                target_columns.to_string(),
                delete.to_string(),
            ));
        }
        foreign.sort();
        expected_foreign.sort();
        if foreign != expected_foreign {
            refuse(tx).await?;
        }
        let mut secondary = Vec::new();
        for (index, table, columns) in INDEXES {
            if table == *name {
                secondary.push((index, columns));
            }
        }
        let count: i64 = tx
            .query_one("SELECT count(*) FROM pg_index WHERE indrelid=$1", &[&oid])
            .await?
            .try_get(0)?;
        if count != (expected_keys.len() + secondary.len()) as i64 {
            refuse(tx).await?;
        }
        for (name, columns) in secondary {
            let row=tx.query_opt("SELECT c.oid,c.relnamespace,ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(n,pos) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.n ORDER BY k.pos) FROM pg_class c JOIN pg_index i ON i.indexrelid=c.oid WHERE c.oid=to_regclass($1)",&[&name]).await?;
            let Some(row) = row else {
                refuse(tx).await?;
                return Ok(false);
            };
            if row.try_get::<_, u32>(1)? != namespace
                || row.try_get::<_, Vec<String>>(2)?.join(",") != columns
                || !index_valid(tx, row.try_get(0)?, oid, false).await?
            {
                refuse(tx).await?;
            }
        }
    }
    Ok(true)
}
async fn index_valid(
    tx: &Transaction<'_>,
    index: u32,
    table: u32,
    unique: bool,
) -> Result<bool, tokio_postgres::Error> {
    let row=tx.query_opt("SELECT i.indrelid,i.indisunique,i.indisvalid,i.indisready,i.indislive,i.indimmediate,i.indisexclusion,i.indpred IS NULL,i.indexprs IS NULL,i.indnatts=i.indnkeyatts,a.amname,NOT EXISTS(SELECT 1 FROM unnest(i.indoption) x WHERE x<>0),NOT EXISTS(SELECT 1 FROM unnest(i.indclass) x JOIN pg_opclass o ON o.oid=x JOIN pg_namespace n ON n.oid=o.opcnamespace WHERE NOT o.opcdefault OR n.nspname<>'pg_catalog'),NOT EXISTS(SELECT 1 FROM unnest(i.indkey::smallint[],i.indcollation::oid[]) k(att,coll) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.att WHERE k.coll<>a.attcollation),NOT i.indnullsnotdistinct,c.relkind='i' AND c.relpersistence='p' AND c.relnamespace=(SELECT relnamespace FROM pg_class WHERE oid=i.indrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam WHERE i.indexrelid=$1", &[&index]).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    Ok(row.try_get::<_, u32>(0)? == table
        && row.try_get::<_, bool>(1)? == unique
        && (2..6).all(|i| row.get::<_, bool>(i))
        && !row.try_get::<_, bool>(6)?
        && (7..10).all(|i| row.get::<_, bool>(i))
        && row.try_get::<_, String>(10)? == "btree"
        && row.try_get::<_, bool>(11)?
        && (12..16).all(|i| row.get::<_, bool>(i)))
}

#[cfg(test)]
mod tests;
