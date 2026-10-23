// SPDX-License-Identifier: AGPL-3.0-only
//! Closed first-origin storage capability. It does not authenticate a socket,
//! verify a signature, initialize a provider, adopt legacy keys or permit effects.
use tokio_postgres::GenericClient;

const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/118_device_protection_origins.sql");

#[derive(Debug, thiserror::Error)]
pub enum ProtectionSchemaError {
    #[error("device protection storage unavailable")]
    Invalid,
    #[error("device protection writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("device protection native storage unavailable")]
    Native(#[from] crate::hosted_runtime_identity::IdentitySchemaError),
    #[error("device protection database unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ProtectionSchemaError>;

fn body(name: &str) -> Result<&'static str> {
    zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        MIGRATION,
        name,
        "$function$",
    )
    .ok_or(ProtectionSchemaError::Invalid)
}
struct Function {
    name: &'static str,
    args: &'static str,
    returned: &'static str,
    language: &'static str,
    volatility: &'static str,
    strict: bool,
    definer: bool,
    set: bool,
    config: &'static [&'static str],
    names: &'static [&'static str],
}
const FUNCTIONS: &[Function] = &[
    Function {
        name: "device_protection_mode",
        args: "uuid",
        returned: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account"],
    },
    Function {
        name: "device_protection_actor",
        args: "uuid, uuid, text, text, bigint, bigint",
        returned: "bigint",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
        ],
    },
    Function {
        name: "device_protection_lock",
        args: "uuid, uuid, text, text, bigint, bigint",
        returned: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
        ],
    },
    Function {
        name: "device_protection_open",
        args: "uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, bytea",
        returned: "public.device_protection_origins",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: true,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
            "setup",
            "opening",
            "command",
            "origin_digest",
        ],
    },
    Function {
        name: "device_protection_association",
        args: "uuid, uuid, bytea, bytea",
        returned: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "opening", "association", "aes_probe"],
    },
    Function {
        name: "device_protection_attempt",
        args: "uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, uuid, bytea, bytea, uuid, bytea, bytea",
        returned: "public.device_protection_attempts",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: true,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
            "setup",
            "opening",
            "command",
            "proof_request",
            "association",
            "aes_probe",
            "previous_attempt",
            "previous_core_sha256",
            "previous_bundle_sha256",
        ],
    },
    Function {
        name: "device_protection_accept",
        args: "uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, uuid, uuid, bytea",
        returned: "public.device_protection_receipts",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: true,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
            "setup",
            "opening",
            "command",
            "proof_request",
            "attempt",
            "bundle",
        ],
    },
    Function {
        name: "device_protection_rows_guard",
        args: "",
        returned: "trigger",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[],
    },
    Function {
        name: "device_protection_complete",
        args: "",
        returned: "trigger",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[],
    },
    Function {
        name: "device_protection_retire",
        args: "",
        returned: "trigger",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[],
    },
    Function {
        name: "payload_profile_writer_policy",
        args: "uuid, bigint, text, text, jsonb, jsonb",
        returned: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[
            "account",
            "epoch",
            "relation_name",
            "operation",
            "old_row",
            "new_row",
        ],
    },
    Function {
        name: "payload_profile_writer_version",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "payload_profile_writer_ready",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "hosted_runtime_native_schema_valid",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "hosted_runtime_identity_ready",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "hosted_runtime_scope",
        args: "",
        returned: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "conversation_reviewed_send03_v2_ready",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
    Function {
        name: "device_protection_ready",
        args: "",
        returned: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
    },
];
async fn functions<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for expected in FUNCTIONS {
        let signature = format!("public.{}({})", expected.name, expected.args);
        let rows=db.query("SELECT p.prosrc,p.oid=pg_catalog.to_regprocedure($3::text),p.prorettype=$2::text::pg_catalog.regtype,l.lanname,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes IS NULL,p.proallargtypes IS NULL,p.proparallel='u',p.prokind='f',p.pronargdefaults=0,p.provariadic=0,p.proowner=c.relowner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass WHERE p.pronamespace='public'::pg_catalog.regnamespace AND p.proname=$1",&[&expected.name,&expected.returned,&signature]).await?;
        if rows.len() != 1 {
            return Err(ProtectionSchemaError::Invalid);
        }
        let row = &rows[0];
        let config = expected
            .config
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        let names = expected
            .names
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        if row.try_get::<_, String>(0)? != body(expected.name)?
            || !row.try_get::<_, bool>(1)?
            || !row.try_get::<_, bool>(2)?
            || row.try_get::<_, String>(3)? != expected.language
            || row.try_get::<_, String>(4)? != expected.volatility
            || row.try_get::<_, bool>(5)? != expected.strict
            || row.try_get::<_, bool>(6)? != expected.definer
            || row.try_get::<_, bool>(7)? != expected.set
            || row.try_get::<_, Option<Vec<String>>>(8)?.as_ref() != Some(&config)
            || row.try_get::<_, Option<Vec<String>>>(9)?.as_deref()
                != if names.is_empty() {
                    None
                } else {
                    Some(names.as_slice())
                }
            || !(10..17).all(|i| row.try_get::<_, bool>(i).unwrap_or(false))
        {
            return Err(ProtectionSchemaError::Invalid);
        }
    }
    Ok(())
}
type Column = (&'static str, &'static str, bool);
type Table = (&'static str, &'static [Column]);
const TABLES: &[Table] = &[
    (
        "device_protection_origins",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("setup_id", "uuid", true),
            ("opening_id", "uuid", true),
            ("command_id", "uuid", true),
            ("source_pairing_id", "uuid", true),
            ("created_by_user_id", "uuid", true),
            ("origin_digest", "bytea", true),
            ("enrolled_point", "bytea", true),
            ("enrolled_key_id", "bytea", true),
            ("enrolled_fingerprint", "bytea", true),
            ("opening_nonce", "bytea", true),
            ("created_ms", "bigint", true),
            ("pairing_created_ms", "bigint", true),
            ("pairing_claimed_ms", "bigint", true),
            ("pairing_proof_verified_ms", "bigint", true),
            ("pairing_approved_ms", "bigint", true),
            ("pairing_expires_ms", "bigint", true),
            ("opened_site_id", "text", true),
            ("opened_instance_id", "text", true),
            ("opened_connection_epoch", "bigint", true),
            ("opened_deployment_epoch", "bigint", true),
        ],
    ),
    (
        "device_protection_associations",
        &[
            ("account_id", "uuid", true),
            ("opening_id", "uuid", true),
            ("association", "bytea", true),
            ("association_sha256", "bytea", true),
            ("hmac_probe", "bytea", true),
            ("aes_probe", "bytea", true),
            ("aes_probe_sha256", "bytea", true),
            ("canary_point", "bytea", true),
            ("canary_key_id", "bytea", true),
            ("created_ms", "bigint", true),
        ],
    ),
    (
        "device_protection_attempts",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("setup_id", "uuid", true),
            ("opening_id", "uuid", true),
            ("command_id", "uuid", true),
            ("proof_request_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("nonce", "bytea", true),
            ("association_sha256", "bytea", true),
            ("core", "bytea", true),
            ("core_sha256", "bytea", true),
            ("issued_ms", "bigint", true),
            ("expires_ms", "bigint", true),
            ("proof_site_id", "text", true),
            ("proof_instance_id", "text", true),
            ("proof_connection_epoch", "bigint", true),
            ("proof_deployment_epoch", "bigint", true),
            ("previous_attempt_id", "uuid", false),
            ("previous_core_sha256", "bytea", false),
            ("previous_bundle_sha256", "bytea", false),
            ("recovery_window_started_ms", "bigint", false),
            ("recovery_window_ordinal", "smallint", false),
            ("closed_ms", "bigint", false),
            ("closed_bundle_sha256", "bytea", false),
            ("superseded_by_proof_request_id", "uuid", false),
            ("superseded_by_attempt_id", "uuid", false),
        ],
    ),
    (
        "device_protection_receipts",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("setup_id", "uuid", true),
            ("opening_id", "uuid", true),
            ("command_id", "uuid", true),
            ("proof_request_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("association_sha256", "bytea", true),
            ("core_sha256", "bytea", true),
            ("bundle", "bytea", true),
            ("bundle_sha256", "bytea", true),
            ("accepted_ms", "bigint", true),
            ("accepted_site_id", "text", true),
            ("accepted_instance_id", "text", true),
            ("accepted_connection_epoch", "bigint", true),
            ("accepted_deployment_epoch", "bigint", true),
        ],
    ),
    (
        "device_protection_retirements",
        &[
            ("account_id", "uuid", true),
            ("opening_id", "uuid", true),
            ("device_id", "uuid", true),
            ("enrolled_key_id", "bytea", true),
            ("reason", "text", true),
            ("retired_ms", "bigint", true),
        ],
    ),
];
async fn tables<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for (table, expected) in TABLES {
        let rows=db.query("SELECT a.attname::text,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,NOT a.atthasdef AND NOT a.atthasmissing AND a.attidentity='' AND a.attgenerated='' FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::pg_catalog.regnamespace AND c.relname=$1 AND c.relkind='r' AND c.relpersistence='p' AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",&[table]).await?;
        if rows.len() != expected.len() {
            return Err(ProtectionSchemaError::Invalid);
        }
        for (row, (name, kind, required)) in rows.iter().zip(*expected) {
            if row.try_get::<_, String>(0)? != *name
                || row.try_get::<_, String>(1)? != *kind
                || row.try_get::<_, bool>(2)? != *required
                || !row.try_get::<_, bool>(3)?
            {
                return Err(ProtectionSchemaError::Invalid);
            }
        }
    }
    Ok(())
}
/// False only for a genuinely absent pre118 installation. Partial/unknown
/// graphs refuse; a caller cannot infer first-ever local eligibility from false.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let row=db.query_one("SELECT (SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace='public'::pg_catalog.regnamespace AND relkind IN('r','p') AND relname LIKE 'device_protection_%'),(SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'device_protection_%')",&[]).await?;
    let tables_present: i64 = row.try_get(0)?;
    let helpers: i64 = row.try_get(1)?;
    if tables_present == 0 && helpers == 0 {
        if db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?.try_get::<_,bool>(0)? {
            crate::payload_profile_writer::optional(db,"public.accounts").await?;
            let version:i64=db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get(0)?;
            if !(108..=117).contains(&version){return Err(ProtectionSchemaError::Invalid);}
        }
        return Ok(false);
    }
    if tables_present != 5 || helpers != 11 {
        return Err(ProtectionSchemaError::Invalid);
    }
    if !crate::payload_profile_writer::optional(db, "public.accounts").await?
        || !crate::hosted_runtime_identity::optional(db).await?
    {
        return Err(ProtectionSchemaError::Invalid);
    }
    if db
        .query_one(
            "SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",
            &[],
        )
        .await?
        .try_get::<_, i64>(0)?
        != 118
    {
        return Err(ProtectionSchemaError::Invalid);
    }
    functions(db).await?;
    tables(db).await?;
    Ok(true)
}
/// Ordinary runtime capability only; the actual native entry and opaque
/// signature-verified enrolled actor remain mandatory in each business TX.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    crate::hosted_runtime_identity::require(db).await?;
    if !optional(db).await?
        || !db
            .query_one("SELECT public.device_protection_ready()", &[])
            .await?
            .try_get::<_, bool>(0)?
    {
        return Err(ProtectionSchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
