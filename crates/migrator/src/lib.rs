// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit, single-writer schema migration runner for the public Compose stack.

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use thiserror::Error;
use tokio_postgres::Client;

// Fixed, project-specific advisory lock. Held on one connection for the full run.
const MIGRATION_LOCK: i64 = 0x5a_52_4f_54_45_58_54;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("migration file error: {0}")]
    File(#[from] std::io::Error),
    #[error("invalid migration directory: {0}")]
    InvalidDirectory(String),
    #[error("migration {0} is not UTF-8")]
    NonUtf8(String),
    #[error("database migration error: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error(
        "applied migration {0:03} differs from its file; restore the original file and add a new migration"
    )]
    ChecksumMismatch(i64),
    #[error("database has an unrecorded M0 schema; inspect it and explicitly run --baseline-m0")]
    LegacySchemaNeedsBaseline,
    #[error(
        "--baseline-m0 requires an unmigrated database with the expected M0 structural shape and dispatch disabled: {0}"
    )]
    UnsafeBaseline(String),
    #[error("schema_migrations contains an unknown or out-of-order version: {0:03}")]
    LedgerOrder(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    pub version: i64,
    pub filename: String,
    pub kind: &'static str,
}

#[derive(Debug)]
struct Migration {
    version: i64,
    filename: String,
    sql: String,
    checksum: Vec<u8>,
}

/// Apply every pending numbered migration. Existing Compose M0 volumes require
/// `baseline_m0 = true` once, after the operator checks that dispatch is off.
pub async fn apply(
    client: &mut Client,
    directory: &Path,
    baseline_m0: bool,
) -> Result<Vec<AppliedMigration>, MigrationError> {
    let migrations = read_migrations(directory)?;
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])
        .await?;
    let result = apply_locked(client, &migrations, baseline_m0).await;
    let unlock = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK])
        .await;
    match (result, unlock) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(MigrationError::Database(error)),
        (Ok(applied), Ok(_)) => Ok(applied),
    }
}

async fn apply_locked(
    client: &mut Client,
    migrations: &[Migration],
    baseline_m0: bool,
) -> Result<Vec<AppliedMigration>, MigrationError> {
    // Migrations intentionally target the public application schema only.
    client.batch_execute("SET search_path TO public").await?;
    let tx = client.transaction().await?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version bigint PRIMARY KEY CHECK (version > 0),
            filename text NOT NULL UNIQUE,
            checksum_sha256 bytea NOT NULL CHECK (octet_length(checksum_sha256) = 32),
            kind text NOT NULL CHECK (kind IN ('applied', 'legacy_baseline')),
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )
    .await?;
    tx.commit().await?;

    let mut ledger = BTreeMap::new();
    for row in client
        .query(
            "SELECT version, filename, checksum_sha256, kind FROM schema_migrations ORDER BY version",
            &[],
        )
        .await?
    {
        let version: i64 = row.get(0);
        let filename: String = row.get(1);
        let checksum: Vec<u8> = row.get(2);
        let kind: String = row.get(3);
        ledger.insert(version, (filename, checksum, kind));
    }

    let mut applied = Vec::new();
    if baseline_m0 {
        if !ledger.is_empty() {
            return Err(MigrationError::UnsafeBaseline(
                "migration ledger is not empty".into(),
            ));
        }
        let first = &migrations[0];
        if first.version != 1 {
            return Err(MigrationError::InvalidDirectory(
                "the M0 foundation must be migration 001".into(),
            ));
        }
        let tx = client.transaction().await?;
        verify_m0_shape(&tx).await?;
        tx.execute(
            "INSERT INTO schema_migrations (version, filename, checksum_sha256, kind)
             VALUES ($1, $2, $3, 'legacy_baseline')",
            &[&first.version, &first.filename, &first.checksum],
        )
        .await?;
        tx.commit().await?;
        ledger.insert(
            first.version,
            (
                first.filename.clone(),
                first.checksum.clone(),
                "legacy_baseline".into(),
            ),
        );
        applied.push(AppliedMigration {
            version: first.version,
            filename: first.filename.clone(),
            kind: "legacy_baseline",
        });
    }

    // Fail before modifying the schema if any historical file was changed or
    // a ledger row is missing from the ordered migration directory.
    let mut pending_seen = false;
    for migration in migrations {
        match ledger.get(&migration.version) {
            Some((filename, checksum, kind)) => {
                if pending_seen {
                    return Err(MigrationError::LedgerOrder(migration.version));
                }
                if filename != &migration.filename
                    || checksum != &migration.checksum
                    || (kind != "applied" && kind != "legacy_baseline")
                {
                    return Err(MigrationError::ChecksumMismatch(migration.version));
                }
            }
            None => pending_seen = true,
        }
    }
    if let Some(version) = ledger
        .keys()
        .find(|v| !migrations.iter().any(|m| &m.version == *v))
    {
        return Err(MigrationError::LedgerOrder(*version));
    }

    if !ledger.contains_key(&1) {
        let legacy: bool = client
            .query_one(
                "SELECT to_regclass('public.deployment_authority') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        if legacy {
            return Err(MigrationError::LegacySchemaNeedsBaseline);
        }
    }

    for migration in migrations {
        if ledger.contains_key(&migration.version) {
            continue;
        }
        let tx = client.transaction().await?;
        if let Err(error) = tx.batch_execute(&migration.sql).await {
            // Dropping the transaction closes it without committing the failed file.
            return Err(MigrationError::Database(error));
        }
        tx.execute(
            "INSERT INTO schema_migrations (version, filename, checksum_sha256, kind)
             VALUES ($1, $2, $3, 'applied')",
            &[&migration.version, &migration.filename, &migration.checksum],
        )
        .await?;
        tx.commit().await?;
        applied.push(AppliedMigration {
            version: migration.version,
            filename: migration.filename.clone(),
            kind: "applied",
        });
    }
    Ok(applied)
}

fn read_migrations(directory: &Path) -> Result<Vec<Migration>, MigrationError> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".sql") {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(MigrationError::InvalidDirectory(format!(
                "{name} must be a regular file"
            )));
        }
        let (number, slug) = name
            .split_once('_')
            .ok_or_else(|| MigrationError::InvalidDirectory(format!("invalid filename {name}")))?;
        if number.len() < 3
            || !number.bytes().all(|b| b.is_ascii_digit())
            || slug.len() <= 4
            || !slug[..slug.len() - 4]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(MigrationError::InvalidDirectory(format!(
                "invalid filename {name}"
            )));
        }
        let version: i64 = number
            .parse()
            .map_err(|_| MigrationError::InvalidDirectory(format!("invalid version in {name}")))?;
        if version == 0 || files.contains_key(&version) {
            return Err(MigrationError::InvalidDirectory(format!(
                "duplicate or zero version in {name}"
            )));
        }
        let bytes = fs::read(entry.path())?;
        let sql =
            String::from_utf8(bytes.clone()).map_err(|_| MigrationError::NonUtf8(name.clone()))?;
        if contains_transaction_control(&sql) {
            return Err(MigrationError::InvalidDirectory(format!(
                "{name} contains transaction control; the runner owns BEGIN/COMMIT"
            )));
        }
        files.insert(
            version,
            Migration {
                version,
                filename: name,
                sql,
                checksum: Sha256::digest(bytes).to_vec(),
            },
        );
    }
    if files.is_empty() {
        return Err(MigrationError::InvalidDirectory(
            "no numbered SQL files".into(),
        ));
    }
    for (expected, actual) in (1_i64..).zip(files.keys()) {
        if expected != *actual {
            return Err(MigrationError::InvalidDirectory(format!(
                "expected migration {expected:03}, found {actual:03}"
            )));
        }
    }
    Ok(files.into_values().collect())
}

// Migration files are reviewed source code, but reject transaction control at
// the start of a SQL statement so no file can commit before its ledger row.
// Ignore comments and quoted/dollar-quoted text, including PL/pgSQL bodies.
fn contains_transaction_control(sql: &str) -> bool {
    fn controlled(words: &[String]) -> bool {
        match words.first().map(String::as_str) {
            Some("BEGIN" | "COMMIT" | "END" | "ROLLBACK" | "ABORT" | "SAVEPOINT") => true,
            Some("START" | "PREPARE" | "RELEASE") => words
                .get(1)
                .is_some_and(|second| second == "TRANSACTION" || second == "SAVEPOINT"),
            _ => false,
        }
    }
    fn word_end(word: &mut Vec<u8>, words: &mut Vec<String>) {
        if !word.is_empty() {
            if words.len() < 2 {
                words.push(String::from_utf8_lossy(word).to_ascii_uppercase());
            }
            word.clear();
        }
    }
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut word = Vec::new();
    let mut words = Vec::new();
    while i < bytes.len() {
        if bytes[i..].starts_with(b"--") {
            word_end(&mut word, &mut words);
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i..].starts_with(b"/*") {
            word_end(&mut word, &mut words);
            i += 2;
            let mut depth = 1;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if bytes[i] == b'\'' || bytes[i] == b'"' {
            word_end(&mut word, &mut words);
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == quote {
                    if i + 1 < bytes.len() && bytes[i + 1] == quote {
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else if bytes[i] == b'\\' && quote == b'\'' {
                    i = (i + 2).min(bytes.len());
                } else {
                    i += 1;
                }
            }
        } else if bytes[i] == b'$' {
            let mut end = i + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b'$' {
                word_end(&mut word, &mut words);
                let delimiter = &bytes[i..=end];
                i = end + 1;
                while i + delimiter.len() <= bytes.len()
                    && &bytes[i..i + delimiter.len()] != delimiter
                {
                    i += 1;
                }
                i = (i + delimiter.len()).min(bytes.len());
            } else {
                word_end(&mut word, &mut words);
                i += 1;
            }
        } else if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            word.push(bytes[i]);
            i += 1;
        } else {
            word_end(&mut word, &mut words);
            if bytes[i] == b';' {
                if controlled(&words) {
                    return true;
                }
                words.clear();
            }
            i += 1;
        }
    }
    word_end(&mut word, &mut words);
    controlled(&words)
}

async fn verify_m0_shape(tx: &tokio_postgres::Transaction<'_>) -> Result<(), MigrationError> {
    type M0Column = (&'static str, &'static str, bool);
    type M0Table = (&'static str, &'static [M0Column]);
    const TABLES: &[M0Table] = &[
        (
            "deployment_authority",
            &[
                ("singleton", "boolean", true),
                ("epoch", "bigint", true),
                ("dispatch_enabled", "boolean", true),
            ],
        ),
        (
            "sites",
            &[
                ("site_id", "text", true),
                ("enabled", "boolean", true),
                ("draining", "boolean", true),
                ("created_at", "timestamp with time zone", true),
            ],
        ),
        (
            "device_sessions",
            &[
                ("device_id", "uuid", true),
                ("site_id", "text", true),
                ("instance_id", "text", true),
                ("connection_epoch", "bigint", true),
                ("lease_until", "timestamp with time zone", true),
                ("deployment_epoch", "bigint", true),
            ],
        ),
        (
            "idempotency_keys",
            &[
                ("account_id", "uuid", true),
                ("key", "text", true),
                ("request_digest", "bytea", true),
                ("message_id", "uuid", true),
                ("expires_at", "timestamp with time zone", true),
            ],
        ),
        (
            "dispatch_fences",
            &[
                ("message_id", "uuid", true),
                ("device_id", "uuid", true),
                ("attempt_id", "uuid", true),
                ("generation", "bigint", true),
                ("session_epoch", "bigint", true),
                ("deployment_epoch", "bigint", true),
                ("grant_expires_at", "timestamp with time zone", true),
                ("outcome", "text", true),
            ],
        ),
    ];
    for (table, expected) in TABLES {
        let rows = tx
            .query(
                "SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
             FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = $1 AND c.relkind = 'r'
               AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
                &[table],
            )
            .await?;
        let actual: Vec<(String, String, bool)> = rows
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
        let expected: Vec<(String, String, bool)> = expected
            .iter()
            .map(|(n, t, nn)| (n.to_string(), t.to_string(), *nn))
            .collect();
        if actual != expected {
            return Err(MigrationError::UnsafeBaseline(format!(
                "{table} columns differ from M0"
            )));
        }
        let primary_count: i64 = tx
            .query_one(
                "SELECT count(*) FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = $1 AND con.contype = 'p'",
                &[table],
            )
            .await?
            .get(0);
        if primary_count != 1 {
            return Err(MigrationError::UnsafeBaseline(format!(
                "{table} primary key differs from M0"
            )));
        }
    }
    for index in ["idempotency_message_id", "dispatch_fences_active_device"] {
        let valid: bool = tx
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_index i
             JOIN pg_class c ON c.oid = i.indexrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = $1 AND i.indisunique AND i.indisvalid)",
                &[&index],
            )
            .await?
            .get(0);
        if !valid {
            return Err(MigrationError::UnsafeBaseline(format!(
                "{index} index is missing"
            )));
        }
    }
    let authority: Vec<_> = tx
        .query(
            "SELECT epoch, dispatch_enabled FROM deployment_authority WHERE singleton = true",
            &[],
        )
        .await?;
    if authority.len() != 1 || authority[0].get::<_, i64>(0) < 1 || authority[0].get::<_, bool>(1) {
        return Err(MigrationError::UnsafeBaseline(
            "M0 authority must have one positive epoch and dispatch disabled".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_control_is_rejected() {
        assert!(contains_transaction_control(
            "CREATE TABLE a(id int);\nCOMMIT;"
        ));
        assert!(!contains_transaction_control(
            "-- COMMIT;\nCREATE TABLE a(id int);"
        ));
        assert!(contains_transaction_control("/* comment */ ROLLBACK;"));
        assert!(contains_transaction_control("START TRANSACTION;"));
        assert!(!contains_transaction_control(
            "DO $$ BEGIN RAISE NOTICE 'COMMIT;'; END $$;"
        ));
    }

    #[test]
    fn repository_migrations_are_ordered() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
        let files = read_migrations(&path).unwrap();
        assert_eq!(files[0].version, 1);
        assert!(files.len() >= 3);
    }
}
