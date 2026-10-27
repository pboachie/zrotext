// SPDX-License-Identifier: AGPL-3.0-only
//! Optional-schema validation and bounded personal-data lifecycle. An absent
//! optional table is not readiness; partial/invalid installations fail closed.
use super::{super::ConversationError, store};
use tokio_postgres::{GenericClient, Transaction, types::Type};
use uuid::Uuid;
#[cfg(test)]
mod current_tests;
#[cfg(test)]
mod tests;
fn reject() -> ConversationError {
    ConversationError::Forbidden
}
// Application lookup may deliberately put pg_catalog first. Anchor the selected
// namespace to the existing account tables used by authentication, not the first
// search-path entry or the optional proposal table under inspection.
async fn application_namespace<C: GenericClient + Sync>(db: &C) -> Result<u32, ConversationError> {
    let row = db.query_opt(
        "SELECT a.relnamespace FROM pg_class a JOIN pg_namespace n ON n.oid=a.relnamespace WHERE a.oid=to_regclass('accounts') AND a.relkind='r' AND a.relpersistence='p' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND n.oid<>pg_my_temp_schema() AND NOT pg_is_other_temp_schema(n.oid) AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['sessions','memberships','device_line_bindings']) AS required(name) LEFT JOIN pg_class parent ON parent.oid=to_regclass(required.name) WHERE parent.oid IS NULL OR parent.relnamespace<>a.relnamespace OR parent.relkind<>'r' OR parent.relpersistence<>'p')",
        &[],
    ).await?.ok_or_else(reject)?;
    Ok(row.get(0))
}
async fn foreign_enforcement<C: GenericClient + Sync>(
    db: &C,
    namespace: u32,
) -> Result<(), ConversationError> {
    let constraints = db.query(
        "SELECT k.oid,k.conrelid,k.confrelid,k.conindid,k.confdeltype::text,k.connamespace=$1 AND k.conislocal AND k.coninhcount=0 AND k.conparentid=0 AND k.contypid=0 AND i.indrelid=k.confrelid AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL FROM pg_constraint k JOIN pg_index i ON i.indexrelid=k.conindid WHERE k.conrelid=to_regclass('owner_android_proposals') AND k.contype='f'",
        &[&namespace],
    ).await?;
    if constraints.len() != 4 {
        return Err(reject());
    }
    for constraint in constraints {
        let oid: u32 = constraint.get(0);
        let child: u32 = constraint.get(1);
        let parent: u32 = constraint.get(2);
        let index: u32 = constraint.get(3);
        let delete = match constraint.get::<_, String>(4).as_str() {
            "c" => "RI_FKey_cascade_del",
            "a" => "RI_FKey_noaction_del",
            _ => return Err(reject()),
        };
        if !constraint.get::<_, bool>(5) {
            return Err(reject());
        }
        // Inspect only this exact FK's triggers, including the action triggers
        // on its parent. Unrelated constraints on the parent are not our scope.
        let triggers = db.query(
            "SELECT t.tgrelid,t.tgconstrrelid,t.tgconstrindid,t.tgtype,p.proname::text,t.tgisinternal AND t.tgenabled='O' AND t.tgparentid=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND cardinality(t.tgattr::smallint[])=0 AND t.tgqual IS NULL AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AND p.pronamespace=(SELECT oid FROM pg_namespace WHERE nspname='pg_catalog') AND p.pronargs=0 AND p.prorettype='pg_catalog.trigger'::regtype AND p.prokind='f' AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='internal') AND t.tgfoid=to_regprocedure(format('pg_catalog.%I()',p.proname)) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgconstraint=$1",
            &[&oid],
        ).await?;
        if triggers.len() != 4 {
            return Err(reject());
        }
        for (relation, referenced, event, function) in [
            (child, parent, 5i16, "RI_FKey_check_ins"),
            (child, parent, 17, "RI_FKey_check_upd"),
            (parent, child, 9, delete),
            (parent, child, 17, "RI_FKey_noaction_upd"),
        ] {
            if !triggers.iter().any(|trigger| {
                trigger.get::<_, u32>(0) == relation
                    && trigger.get::<_, u32>(1) == referenced
                    && trigger.get::<_, u32>(2) == index
                    && trigger.get::<_, i16>(3) == event
                    && trigger.get::<_, String>(4) == function
                    && trigger.get::<_, bool>(5)
            }) {
                return Err(reject());
            }
        }
    }
    let owned: bool = db.query_one(
        "SELECT NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('owner_android_proposals') AND t.tgisinternal AND NOT EXISTS(SELECT 1 FROM pg_constraint k WHERE k.oid=t.tgconstraint AND k.conrelid=t.tgrelid AND k.contype='f'))",
        &[],
    ).await?.get(0);
    if !owned {
        return Err(reject());
    }
    Ok(())
}
pub(crate) async fn installed<C: GenericClient + Sync>(db: &C) -> Result<bool, ConversationError> {
    let present: bool = db
        .query_one(
            "SELECT to_regclass('owner_android_proposals') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    if !present {
        let partial: bool = db.query_one(
            "SELECT to_regprocedure('reject_owner_android_proposal_update()') IS NOT NULL OR to_regclass('owner_android_proposals_pkey') IS NOT NULL OR to_regclass('owner_android_proposals_expiry') IS NOT NULL OR to_regclass('owner_android_proposals_session') IS NOT NULL OR to_regclass('owner_android_proposals_owner') IS NOT NULL OR to_regclass('owner_android_proposals_binding') IS NOT NULL",
            &[],
        ).await?.get(0);
        if partial {
            return Err(reject());
        }
        return Ok(false);
    }
    let ordinary_mode: bool = db
        .query_one(
            "SELECT current_setting('session_replication_role') IN ('origin','local')",
            &[],
        )
        .await?
        .get(0);
    if !ordinary_mode {
        return Err(reject());
    }
    let namespace = application_namespace(db).await?;
    // Preparation checks the selected table's shape. Its AccessShare lock does
    // not exclude trigger ALTER; installed alone is a catalog snapshot.
    let statement = db
        .prepare("SELECT * FROM owner_android_proposals WHERE FALSE")
        .await?;
    let ordinary: bool = db.query_one(
        "SELECT c.relnamespace=$1 AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relispartition AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid) AND NOT EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class=c.oid) AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=c.oid) FROM pg_class c WHERE c.oid=to_regclass('owner_android_proposals')",
        &[&namespace],
    ).await?.get(0);
    if !ordinary {
        return Err(reject());
    }
    let expected = [
        ("account_id", Type::UUID, true),
        ("kind", Type::INT2, true),
        ("user_id", Type::UUID, true),
        ("session_id", Type::UUID, true),
        ("proposal_sha256", Type::BYTEA, true),
        ("proposal", Type::BYTEA, true),
        ("expected_context", Type::JSONB, true),
        ("origin", Type::TEXT, true),
        ("root_fingerprint", Type::BYTEA, true),
        ("checkpoint_version", Type::INT8, true),
        ("checkpoint_digest", Type::BYTEA, false),
        ("device_id", Type::UUID, true),
        ("line_id", Type::UUID, true),
        ("binding_generation", Type::INT8, true),
        ("peer", Type::TEXT, true),
        ("paired_fingerprint", Type::BYTEA, true),
        ("connection_epoch", Type::INT8, true),
        ("deployment_epoch", Type::INT8, true),
        ("site_id", Type::TEXT, true),
        ("instance_id", Type::TEXT, true),
        ("interval_id", Type::UUID, false),
        ("issued_ms", Type::INT8, true),
        ("expires_ms", Type::INT8, true),
    ];
    let columns=db.query("SELECT attname,attnotnull,attnum,atthasdef,attidentity::text,attgenerated::text FROM pg_attribute WHERE attrelid=to_regclass('owner_android_proposals') AND attnum>0 AND NOT attisdropped ORDER BY attnum",&[]).await?;
    if columns.len() != expected.len() || statement.columns().len() != expected.len() {
        return Err(reject());
    }
    for (position, ((column, row), (name, ty, notnull))) in statement
        .columns()
        .iter()
        .zip(columns)
        .zip(expected)
        .enumerate()
    {
        if column.name() != name
            || column.type_() != &ty
            || row.get::<_, String>(0) != name
            || row.get::<_, bool>(1) != notnull
            || row.get::<_, i16>(2) as usize != position + 1
            || row.get::<_, bool>(3)
            || !row.get::<_, String>(4).is_empty()
            || !row.get::<_, String>(5).is_empty()
        {
            return Err(reject());
        }
    }
    let row=db.query_one("SELECT count(*) FILTER(WHERE contype='c'),count(*) FILTER(WHERE contype='p'),count(*) FILTER(WHERE contype='f'),bool_and(convalidated AND NOT condeferrable AND NOT condeferred),count(*) FILTER(WHERE contype NOT IN('c','p','f','n')) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals')",&[]).await?;
    if row.get::<_, i64>(0) != 18
        || row.get::<_, i64>(1) != 1
        || row.get::<_, i64>(2) != 4
        || row.get::<_, Option<bool>>(3) != Some(true)
        || row.get::<_, i64>(4) != 0
    {
        return Err(reject());
    }
    let foreign_scope: bool = db.query_one(
        "SELECT NOT EXISTS(SELECT 1 FROM pg_constraint k JOIN pg_class target ON target.oid=k.confrelid WHERE k.conrelid=to_regclass('owner_android_proposals') AND k.contype='f' AND (target.relnamespace<>$1 OR k.confmatchtype<>'s' OR k.confupdtype<>'a')) AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE confrelid=to_regclass('owner_android_proposals') AND conrelid<>to_regclass('owner_android_proposals'))",
        &[&namespace],
    ).await?.get(0);
    if !foreign_scope {
        return Err(reject());
    }
    let definitions=db.query("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype IN('p','f')",&[]).await?.into_iter().map(|r|r.get::<_,String>(0).split_whitespace().collect::<String>().to_lowercase()).collect::<Vec<_>>();
    for expected in [
        "primarykey(account_id,kind)",
        "foreignkey(account_id)referencesaccounts(id)ondeletecascade",
        "foreignkey(account_id,session_id)referencessessions(account_id,id)ondeletecascade",
        "foreignkey(account_id,user_id)referencesmemberships(account_id,user_id)",
        "foreignkey(account_id,line_id,device_id,binding_generation)referencesdevice_line_bindings(account_id,line_id,device_id,generation)",
    ] {
        if !definitions.iter().any(|actual| actual == expected) {
            return Err(reject());
        }
    }
    foreign_enforcement(db, namespace).await?;
    let checks = db.query("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='c'", &[]).await?.into_iter().map(|r| r.get::<_,String>(0)).collect::<Vec<_>>();
    let expected_checks = [
        "CHECK ((((kind = 3) AND (checkpoint_version = 0) AND (checkpoint_digest IS NULL) AND (interval_id IS NULL)) OR ((kind = 4) AND (checkpoint_version > 0) AND (checkpoint_digest IS NOT NULL) AND (interval_id IS NULL)) OR ((kind = 5) AND (checkpoint_version > 0) AND (checkpoint_digest IS NOT NULL) AND (interval_id IS NOT NULL))))",
        "CHECK (((expires_ms > issued_ms) AND ((expires_ms - issued_ms) <= 300000)))",
        "CHECK (((jsonb_typeof(expected_context) = 'object'::text) AND (pg_column_size(expected_context) <= 8192)))",
        "CHECK (((octet_length(instance_id) >= 1) AND (octet_length(instance_id) <= 64)))",
        "CHECK (((octet_length(origin) >= 1) AND (octet_length(origin) <= 512)))",
        "CHECK (((octet_length(proposal) >= 1) AND (octet_length(proposal) <= 20480)))",
        "CHECK (((octet_length(site_id) >= 1) AND (octet_length(site_id) <= 64)))",
        "CHECK ((binding_generation > 0))",
        "CHECK ((checkpoint_version >= 0))",
        "CHECK ((connection_epoch > 0))",
        "CHECK ((deployment_epoch > 0))",
        "CHECK ((issued_ms > 0))",
        "CHECK ((kind = ANY (ARRAY[3, 4, 5])))",
        "CHECK ((octet_length(checkpoint_digest) = 32))",
        "CHECK ((octet_length(paired_fingerprint) = 32))",
        "CHECK ((octet_length(proposal_sha256) = 32))",
        "CHECK ((octet_length(root_fingerprint) = 32))",
        r"CHECK ((peer ~ '^\+[1-9][0-9]{1,14}$'::text))",
    ];
    if !expected_checks
        .iter()
        .all(|expected| checks.iter().any(|actual| actual == expected))
    {
        return Err(reject());
    }
    let index_count: i64 = db
        .query_one(
            "SELECT count(*) FROM pg_index WHERE indrelid=to_regclass('owner_android_proposals')",
            &[],
        )
        .await?
        .get(0);
    if index_count != 5 {
        return Err(reject());
    }
    for (index, keys, unique) in [
        ("owner_android_proposals_pkey", "account_id,kind", true),
        ("owner_android_proposals_expiry", "expires_ms", false),
        (
            "owner_android_proposals_session",
            "account_id,session_id",
            false,
        ),
        ("owner_android_proposals_owner", "account_id,user_id", false),
        (
            "owner_android_proposals_binding",
            "account_id,line_id,device_id,binding_generation",
            false,
        ),
    ] {
        let row = db.query_opt("SELECT i.indisunique, (SELECT string_agg(a.attname, ',' ORDER BY k.ordinality) FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum,ordinality) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum),i.indisprimary FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam WHERE i.indexrelid=to_regclass($1) AND i.indrelid=to_regclass('owner_android_proposals') AND c.relnamespace=$2 AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=i.indnkeyatts AND NOT EXISTS(SELECT 1 FROM unnest(i.indoption) AS option WHERE option<>0) AND am.amname='btree'", &[&index, &namespace]).await?.ok_or_else(reject)?;
        if row.get::<_, bool>(0) != unique
            || row.get::<_, Option<String>>(1).as_deref() != Some(keys)
            || row.get::<_, bool>(2) != unique
        {
            return Err(reject());
        }
    }
    // Migration108 adds exactly its mandatory writer trigger. Recognize that
    // pair only after the shared validator proves this table's complete public
    // graph and pinned writer implementation; a matching name alone is not
    // readiness. Historical pre-writer schemas retain the single-trigger rule.
    let writers = crate::payload_profile_writer::optional(db, "owner_android_proposals")
        .await
        .map_err(|_| reject())?;
    let trigger_count: i64 = db.query_one(
        "SELECT count(*) FROM pg_trigger WHERE tgrelid=to_regclass('owner_android_proposals') AND NOT tgisinternal",
        &[],
    ).await?.get(0);
    if trigger_count != 1 + i64::from(writers) {
        return Err(reject());
    }
    let trigger=db.query_opt("SELECT p.prosrc FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang WHERE t.tgrelid=to_regclass('owner_android_proposals') AND t.tgname='owner_android_proposals_immutable' AND NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=19 AND t.tgqual IS NULL AND t.tgnargs=0 AND cardinality(t.tgattr::smallint[])=0 AND t.tgconstraint=0 AND p.proname='reject_owner_android_proposal_update' AND p.pronamespace=$1 AND p.pronargs=0 AND p.prorettype='trigger'::regtype AND p.prokind='f' AND NOT p.prosecdef AND NOT p.proisstrict AND NOT p.proleakproof AND p.provolatile='v' AND p.proparallel='u' AND p.proconfig IS NULL AND l.lanname='plpgsql'",&[&namespace]).await?.ok_or_else(reject)?;
    let body = trigger
        .get::<_, String>(0)
        .split_whitespace()
        .collect::<String>();
    if body != "BEGINRAISEEXCEPTION'ownerproposalisimmutable';END;" {
        return Err(reject());
    }
    Ok(true)
}
const FENCE_RELATIONS: &str = "SELECT c.oid,format('LOCK TABLE ONLY %I.%I IN ROW EXCLUSIVE MODE NOWAIT',n.nspname,c.relname),c.relnamespace=$1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('owner_android_proposals') OR c.oid IN(SELECT confrelid FROM pg_constraint WHERE conrelid=to_regclass('owner_android_proposals') AND contype='f') ORDER BY c.oid";

// The diagnostic catalog snapshot above is not a DDL fence. Authoritative
// callers retain these compatible, nonwaiting table locks in their own
// transaction, then take root-before-owner row locks and recheck final time.
async fn fence(tx: &Transaction<'_>) -> Result<bool, ConversationError> {
    if !installed(tx).await? {
        return Ok(false);
    }
    let namespace = application_namespace(tx).await?;
    let relations = tx.query(FENCE_RELATIONS, &[&namespace]).await?;
    if relations.len() != 5 || relations.iter().any(|r| !r.get::<_, bool>(2)) {
        return Err(reject());
    }
    let mut ids = Vec::with_capacity(5);
    for relation in relations {
        ids.push(relation.get::<_, u32>(0));
        // PostgreSQL %I quotes both identifiers; only these five already-
        // validated OIDs are selected. No privileges or firing mode are set.
        tx.batch_execute(&relation.get::<_, String>(1)).await?;
    }
    if !installed(tx).await? {
        return Err(reject());
    }
    if application_namespace(tx).await? != namespace {
        return Err(reject());
    }
    let resolved = tx.query(FENCE_RELATIONS, &[&namespace]).await?;
    if resolved
        .into_iter()
        .map(|r| r.get::<_, u32>(0))
        .collect::<Vec<_>>()
        != ids
    {
        return Err(reject());
    }
    Ok(true)
}

/// Prepare optional erasure storage before the final owner/password fence.
/// The caller retains this exact transaction and locks rows before that fence.
pub(crate) async fn prepare_erase(db: &Transaction<'_>) -> Result<bool, ConversationError> {
    fence(db).await
}

pub(crate) async fn require_installed(db: &Transaction<'_>) -> Result<(), ConversationError> {
    if !fence(db).await? {
        return Err(reject());
    }
    Ok(())
}
pub(crate) async fn prune(db: &Transaction<'_>, limit: i64) -> Result<u64, ConversationError> {
    if !fence(db).await? {
        return Ok(0);
    }
    Ok(store::prune(db, limit).await?)
}
pub(crate) async fn inventory(
    db: &Transaction<'_>,
    account: Uuid,
) -> Result<serde_json::Value, ConversationError> {
    if !fence(db).await? {
        return Ok(serde_json::json!({"installed":false,"proposals":[]}));
    }
    let rows=db.query("SELECT kind,user_id,session_id,proposal_sha256,device_id,line_id,binding_generation,peer,checkpoint_version,checkpoint_digest,issued_ms,expires_ms,origin,proposal,expected_context::text FROM owner_android_proposals WHERE account_id=$1 ORDER BY kind LIMIT 3 FOR SHARE",&[&account]).await?;
    use base64::{Engine, engine::general_purpose::STANDARD};
    let entries = rows.into_iter().map(|r| {
        let expected:serde_json::Value=serde_json::from_str(&r.get::<_,String>(14)).map_err(|_|reject())?;
        Ok(serde_json::json!({"kind":r.get::<_,i16>(0),"user_id":r.get::<_,Uuid>(1),"session_id":r.get::<_,Uuid>(2),"proposal_sha256":STANDARD.encode(r.get::<_,Vec<u8>>(3)),"device_id":r.get::<_,Uuid>(4),"line_id":r.get::<_,Uuid>(5),"binding_generation":r.get::<_,i64>(6),"peer":r.get::<_,String>(7),"checkpoint_version":r.get::<_,i64>(8),"checkpoint_digest":r.get::<_,Option<Vec<u8>>>(9).map(|v|STANDARD.encode(v)),"issued_ms":r.get::<_,i64>(10).to_string(),"expires_ms":r.get::<_,i64>(11).to_string(),"origin":r.get::<_,String>(12),"proposal_b64":STANDARD.encode(r.get::<_,Vec<u8>>(13)),"expected_context":expected}))
    }).collect::<Result<Vec<_>,ConversationError>>()?;

    Ok(serde_json::json!({"installed":true,"proposals":entries}))
}
