// SPDX-License-Identifier: AGPL-3.0-only
//! Exact admission contract and optional execution metering projection.
//! Retention and authenticated inventory use the canonical confirmation records module.
use tokio_postgres::{GenericClient, types::Type};

/// Pins the complete column contract in the same transaction before erasure.
/// An installed but incomplete table is an error, never the absent-table path.
pub(crate) async fn validate<C: GenericClient + Sync>(
    db: &C,
) -> Result<bool, tokio_postgres::Error> {
    let statement = db
        .prepare("SELECT * FROM conversation_confirmation_records LIMIT 0")
        .await?;
    let names = [
        "account_id",
        "message_id",
        "interval_id",
        "initiating_session_id",
        "device_id",
        "line_id",
        "binding_generation",
        "trust_generation",
        "manifest_version",
        "manifest_digest",
        "signer_key_id",
        "reader_key_id",
        "body_digest",
        "expires_at_ms",
        "envelope_digest",
        "confirmation_digest",
        "signature_digest",
        "confirmation",
        "signature",
        "created_at",
    ];
    let expected = [
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::UUID,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::INT8,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::BYTEA,
        Type::TIMESTAMPTZ,
    ];
    let columns = statement.columns();
    if !(20..=21).contains(&columns.len())
        || !columns[..20].iter().map(|column| column.name()).eq(names)
        || !columns[..20]
            .iter()
            .map(|column| column.type_())
            .eq(expected.iter())
    {
        return Ok(false);
    }
    if columns.len() == 20 {
        return Ok(true);
    }
    if columns[20].name() != "execution_metered" || columns[20].type_() != &Type::BOOL {
        return Ok(false);
    }
    Ok(db.query_one("SELECT NOT attnotnull FROM pg_attribute WHERE attrelid='conversation_confirmation_records'::regclass AND attname='execution_metered' AND NOT attisdropped",&[]).await?.get(0))
}

/// Call only after exact validation in the same transaction. NULL legacy
/// receipts are never filled by retry or configuration inference.
pub(crate) async fn execution_metering_installed<C: GenericClient + Sync>(
    db: &C,
) -> Result<bool, tokio_postgres::Error> {
    Ok(db
        .prepare("SELECT * FROM conversation_confirmation_records LIMIT 0")
        .await?
        .columns()
        .len()
        == 21)
}
