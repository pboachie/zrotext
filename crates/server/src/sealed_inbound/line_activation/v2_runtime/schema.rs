// SPDX-License-Identifier: AGPL-3.0-only
//! Fail closed on the installed production schema; never install it at runtime.
use super::{LineActivationError, Result};
use std::collections::BTreeSet;
use tokio_postgres::GenericClient;
const LEASE: &str = include_str!(
    "../../../../../../deploy/compose/migrations/095_device_session_line_activation_version.sql"
);
const EXCHANGE: &str = include_str!(
    "../../../../../../deploy/compose/migrations/096_line_activation_v2_exchanges.sql"
);
fn invalid() -> LineActivationError {
    LineActivationError::Unavailable
}
fn body<'a>(sql: &'a str, name: &str) -> Result<&'a str> {
    let after = sql
        .split_once(&format!("CREATE FUNCTION {name}()"))
        .ok_or_else(invalid)?
        .1;
    Ok(after
        .split_once("AS $$")
        .ok_or_else(invalid)?
        .1
        .split_once("$$;")
        .ok_or_else(invalid)?
        .0)
}
async fn guard<C: GenericClient + Sync>(
    db: &C,
    table: &str,
    trigger: &str,
    function: &str,
    kind: i16,
    sql: &str,
) -> Result<()> {
    let row=db.query_opt("SELECT p.prosrc FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_language l ON l.oid=p.prolang WHERE c.oid=to_regclass($1) AND t.tgname=$2 AND NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=$3 AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgqual IS NULL AND p.proname=$4 AND p.pronamespace=c.relnamespace AND p.prorettype='trigger'::regtype AND p.pronargs=0 AND NOT p.prosecdef AND NOT p.proisstrict AND p.provolatile='v' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path='||current_setting('search_path')]",&[&table,&trigger,&kind,&function]).await?.ok_or_else(invalid)?;
    if row.get::<_, String>(0) != body(sql, function)? {
        return Err(invalid());
    }
    Ok(())
}
/// Required for every actual claimed socket epoch, including legacy claims.
pub async fn require_lease<C: GenericClient + Sync>(db: &C) -> Result<()> {
    let row=db.query_opt("SELECT a.attnotnull,pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=to_regclass('device_sessions') AND a.attname='line_activation_version' AND NOT a.attisdropped AND a.atttypid='int2'::regtype",&[]).await?.ok_or_else(invalid)?;
    let default: String = row.get(1);
    if !row.get::<_, bool>(0) || !matches!(default.as_str(), "1" | "1::smallint") {
        return Err(invalid());
    }
    let row=db.query_opt("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=to_regclass('device_sessions') AND conname='device_sessions_line_activation_version' AND contype='c' AND convalidated AND NOT connoinherit AND NOT condeferrable AND NOT condeferred",&[]).await?.ok_or_else(invalid)?;
    if canonical(&row.get::<_, String>(0))
        != canonical("CHECK ((line_activation_version = ANY (ARRAY[1, 2])))")
    {
        return Err(invalid());
    }
    guard(
        db,
        "device_sessions",
        "device_session_line_activation_version_before_update",
        "device_session_line_activation_version_guard",
        19,
        LEASE,
    )
    .await
}
async fn columns<C: GenericClient + Sync>(
    db: &C,
    table: &str,
    expected: &[(&str, &str, bool)],
) -> Result<()> {
    let rows=db.query("SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=to_regclass($1) AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",&[&table]).await?;
    if rows.len() != expected.len() {
        return Err(invalid());
    }
    for (r, (name, ty, required)) in rows.iter().zip(expected) {
        if r.get::<_, String>(0) != *name
            || r.get::<_, String>(1) != *ty
            || r.get::<_, bool>(2) != *required
        {
            return Err(invalid());
        }
        let expected_default = match *name {
            "protocol_version" => Some("2"),
            "created_at" | "received_at" => Some("clock_timestamp()"),
            _ => None,
        };
        let installed: Option<String> = r.get(3);
        if installed.as_deref() != expected_default {
            return Err(invalid());
        }
    }
    Ok(())
}
// Retain punctuation, operators, literals, order and grouping. Formatting alone
// is ignored; counting or substring-matching constraints is insufficient.
fn canonical(definition: &str) -> String {
    let mut result = String::new();
    let mut quote = None;
    for c in definition.chars() {
        if matches!(c, '\'' | '"') {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            }
        }
        if quote.is_some() || !c.is_ascii_whitespace() {
            result.push(c);
        }
    }
    result
}
async fn constraints<C: GenericClient + Sync>(
    db: &C,
    table: &str,
    expected: &[&str],
) -> Result<()> {
    // PostgreSQL 18 also catalogs NOT NULL constraints as type n; ordered
    // column metadata above validates those independently on all supported PGs.
    // PK, UNIQUE and FK constraints are inherently non-inheritable and PG 18
    // catalogs them with connoinherit set; only CHECK constraints must remain
    // inheritable, matching the openings verifier.
    let rows=db.query("SELECT contype::text,pg_get_constraintdef(oid),convalidated,condeferrable,condeferred,connoinherit FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype<>'n'",&[&table]).await?;
    let wanted: BTreeSet<_> = expected.iter().map(|s| canonical(s)).collect();
    if rows.len() != expected.len() || wanted.len() != expected.len() {
        return Err(invalid());
    }
    let mut actual = BTreeSet::new();
    for row in rows {
        let kind: String = row.get(0);
        let unexpected_inheritance = match kind.as_str() {
            "c" => row.get::<_, bool>(5),
            "p" | "u" | "f" => !row.get::<_, bool>(5),
            _ => false,
        };
        if !row.get::<_, bool>(2)
            || row.get::<_, bool>(3)
            || row.get::<_, bool>(4)
            || unexpected_inheritance
            || !actual.insert(canonical(&row.get::<_, String>(1)))
        {
            return Err(invalid());
        }
    }
    if actual != wanted {
        return Err(invalid());
    }
    Ok(())
}
async fn trigger_names<C: GenericClient + Sync>(
    db: &C,
    table: &str,
    expected: &[&str],
) -> Result<()> {
    let rows = db
        .query(
            "SELECT tgname FROM pg_trigger WHERE tgrelid=to_regclass($1) AND NOT tgisinternal",
            &[&table],
        )
        .await?;
    let actual: BTreeSet<String> = rows.iter().map(|r| r.get(0)).collect();
    let expected: BTreeSet<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    if actual != expected {
        return Err(invalid());
    }
    Ok(())
}
/// Separate v2 validation preserves the complete existing 087 lifecycle gate.
pub async fn require_installed<C: GenericClient + Sync>(db: &C) -> Result<()> {
    require_lease(db).await?;
    columns(
        db,
        "line_activation_v2_pending",
        &[
            ("challenge_id", "uuid", true),
            ("protocol_version", "smallint", true),
            ("purpose", "text", true),
            ("opening_id", "uuid", true),
            ("account_id", "uuid", true),
            ("line_id", "uuid", true),
            ("device_id", "uuid", true),
            ("generation", "bigint", true),
            ("initiating_user_id", "uuid", true),
            ("initiating_session_id", "uuid", true),
            ("registration_id", "uuid", false),
            ("site_id", "text", true),
            ("instance_id", "text", true),
            ("connection_epoch", "bigint", true),
            ("deployment_epoch", "bigint", true),
            ("device_fingerprint", "bytea", true),
            ("owner_fingerprint", "bytea", true),
            ("nonce", "bytea", false),
            ("expires_at", "timestamp with time zone", true),
            ("created_at", "timestamp with time zone", true),
            ("owner_signature_sha256", "bytea", false),
            ("approved_at", "timestamp with time zone", false),
            ("installed_at", "timestamp with time zone", false),
            ("retired_at", "timestamp with time zone", false),
        ],
    )
    .await?;
    constraints(db,"line_activation_v2_pending",&[
        "PRIMARY KEY (challenge_id)",
        "FOREIGN KEY (challenge_id) REFERENCES line_activation_challenges(id)",
        "CHECK ((protocol_version = 2))",
        "CHECK ((purpose = ANY (ARRAY['sms'::text, 'sealed'::text])))",
        "CHECK ((generation > 0))",
        "FOREIGN KEY (initiating_session_id) REFERENCES sessions(id)",
        "CHECK ((connection_epoch > 0))", "CHECK ((deployment_epoch > 0))",
        "CHECK ((octet_length(device_fingerprint) = 32))", "CHECK ((octet_length(owner_fingerprint) = 32))",
        "CHECK (((nonce IS NULL) OR (octet_length(nonce) = 32)))",
        "CHECK (((owner_signature_sha256 IS NULL) OR (octet_length(owner_signature_sha256) = 32)))",
        "UNIQUE (account_id, purpose, opening_id)",
        "UNIQUE (challenge_id, account_id, line_id, device_id, generation, purpose)",
        "FOREIGN KEY (account_id, line_id, device_id, generation) REFERENCES device_line_bindings(account_id, line_id, device_id, generation)",
        "FOREIGN KEY (account_id, registration_id) REFERENCES sealed_line_key_receipts(account_id, registration_id)",
        "CHECK (((purpose = 'sealed'::text) = (registration_id IS NOT NULL)))",
        "CHECK (((approved_at IS NULL) = (owner_signature_sha256 IS NULL)))",
        "CHECK (((installed_at IS NULL) OR ((purpose = 'sealed'::text) AND (approved_at IS NOT NULL) AND (nonce IS NULL))))",
        "CHECK (((retired_at IS NULL) OR (nonce IS NULL)))",
        "CHECK (((nonce IS NOT NULL) OR (installed_at IS NOT NULL) OR (retired_at IS NOT NULL)))",
    ]).await?;
    columns(
        db,
        "line_activation_v2_observations",
        &[
            ("challenge_id", "uuid", true),
            ("protocol_version", "smallint", true),
            ("purpose", "text", true),
            ("account_id", "uuid", true),
            ("line_id", "uuid", true),
            ("device_id", "uuid", true),
            ("generation", "bigint", true),
            ("observation", "bytea", true),
            ("device_signature_der", "bytea", true),
            ("device_statement_sha256", "bytea", true),
            ("device_signature_sha256", "bytea", true),
            ("confirmation_digest", "bytea", true),
            ("device_fingerprint", "bytea", true),
            ("proof_site_id", "text", true),
            ("proof_instance_id", "text", true),
            ("proof_connection_epoch", "bigint", true),
            ("proof_deployment_epoch", "bigint", true),
            ("received_at", "timestamp with time zone", true),
        ],
    )
    .await?;
    constraints(db,"line_activation_v2_observations",&[
        "PRIMARY KEY (challenge_id)", "CHECK ((protocol_version = 2))",
        "CHECK ((purpose = ANY (ARRAY['sms'::text, 'sealed'::text])))", "CHECK ((generation > 0))",
        "CHECK ((octet_length(observation) = 121))",
        "CHECK (((octet_length(device_signature_der) >= 8) AND (octet_length(device_signature_der) <= 80)))",
        "CHECK ((octet_length(device_statement_sha256) = 32))", "CHECK ((octet_length(device_signature_sha256) = 32))",
        "CHECK ((octet_length(confirmation_digest) = 32))", "CHECK ((octet_length(device_fingerprint) = 32))",
        "CHECK ((proof_connection_epoch > 0))", "CHECK ((proof_deployment_epoch > 0))",
        "FOREIGN KEY (challenge_id, account_id, line_id, device_id, generation, purpose) REFERENCES line_activation_v2_pending(challenge_id, account_id, line_id, device_id, generation, purpose)",
    ]).await?;
    trigger_names(
        db,
        "line_activation_v2_pending",
        &[
            "line_activation_v2_pending_before_insert_or_update",
            "line_activation_v2_pending_before_delete",
        ],
    )
    .await?;
    trigger_names(
        db,
        "line_activation_v2_observations",
        // Migration 096 declares a 64-byte trigger name; PostgreSQL truncates
        // identifiers to 63 bytes, so the installed name drops the final "e".
        &["line_activation_v2_observation_before_insert_or_update_or_delet"],
    )
    .await?;
    guard(
        db,
        "line_activation_v2_pending",
        "line_activation_v2_pending_before_insert_or_update",
        "line_activation_v2_pending_guard",
        23,
        EXCHANGE,
    )
    .await?;
    guard(
        db,
        "line_activation_v2_pending",
        "line_activation_v2_pending_before_delete",
        "line_activation_v2_pending_guard",
        11,
        EXCHANGE,
    )
    .await?;
    guard(
        db,
        "line_activation_v2_observations",
        // Same 63-byte truncation as the trigger-name check above.
        "line_activation_v2_observation_before_insert_or_update_or_delet",
        "line_activation_v2_observation_guard",
        31,
        EXCHANGE,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_definitions_preserve_literal_spaces_operators_and_grouping() {
        assert_eq!(
            canonical("CHECK ((generation > 0))"),
            canonical("CHECK( (generation>0) )")
        );
        for changed in [
            "CHECK ((generation >= 0))",
            "CHECK ((generation > 0) OR true)",
            "CHECK ((generation > 1))",
        ] {
            assert_ne!(canonical("CHECK ((generation > 0))"), canonical(changed));
        }
        assert_ne!(
            canonical("CHECK (purpose = 'sms')"),
            canonical("CHECK (purpose = 's ms')")
        );
        assert_ne!(
            canonical("UNIQUE (account_id, purpose, opening_id)"),
            canonical("UNIQUE (account_id, opening_id, purpose)")
        );
        assert_ne!(
            canonical("FOREIGN KEY (challenge_id) REFERENCES line_activation_challenges(id)"),
            canonical(
                "FOREIGN KEY (challenge_id) REFERENCES line_activation_challenges(id) ON DELETE CASCADE"
            )
        );
    }
}
