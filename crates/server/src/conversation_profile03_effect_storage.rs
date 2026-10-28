// SPDX-License-Identifier: AGPL-3.0-only
//! Closed one-use effect storage, never authentication, signature or permission.
use tokio_postgres::GenericClient;
const MIGRATION: &str =
    include_str!("../../../deploy/compose/migrations/119_conversation_profile03_effects.sql");
#[derive(Debug, thiserror::Error)]
pub enum EffectSchemaError {
    #[error("typed effect schema unavailable")]
    Invalid,
    #[error("typed effect native schema unavailable")]
    Native(#[from] crate::hosted_runtime_identity::IdentitySchemaError),
    #[error("typed effect writer unavailable")]
    Writer(#[from] crate::payload_profile_writer::WriterSchemaError),
    #[error("typed effect reviewed admission unavailable")]
    Admission(#[from] crate::conversation_reviewed_send03_storage::ReviewedSendSchemaError),
    #[error("typed effect grant schema unavailable")]
    Grant(#[from] crate::conversation_profile03_grant_storage::GrantSchemaError),
    #[error("typed effect storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, EffectSchemaError>;
fn body(name: &str) -> Result<&'static str> {
    zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        MIGRATION,
        name,
        "$function$",
    )
    .ok_or(EffectSchemaError::Invalid)
}
struct Function {
    name: &'static str,
    signature: &'static str,
    result: &'static str,
    language: &'static str,
    volatility: &'static str,
    strict: bool,
    definer: bool,
    set: bool,
    config: &'static [&'static str],
    names: &'static [&'static str],
    modes: &'static [&'static str],
    all_types: &'static [&'static str],
}
const FUNCTIONS: &[Function] = &[
    Function {
        name: "conversation_profile03_effect_fetch",
        signature: "public.conversation_profile03_effect_fetch(public.conversation_profile03_grants)",
        result: "bytea",
        language: "sql",
        volatility: "i",
        strict: true,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &["grant_row"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_mode",
        signature: "public.conversation_profile03_effect_mode(uuid)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_actor",
        signature: "public.conversation_profile03_effect_actor(uuid, uuid, text, text, bigint, bigint)",
        result: "bigint",
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
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_history_lock",
        signature: "public.conversation_profile03_effect_history_lock(uuid, uuid, uuid, text, text, bigint, bigint)",
        result: "public.conversation_profile03_effect_actors",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: true,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "attempt",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_not_quarantined",
        signature: "public.conversation_profile03_effect_not_quarantined(uuid, uuid, bytea, bytea)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "device", "point", "key_id"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_submit_bytes",
        signature: "public.conversation_profile03_effect_submit_bytes(uuid, uuid, uuid, uuid, uuid, bytea, bytea, smallint, bigint)",
        result: "bytea",
        language: "sql",
        volatility: "i",
        strict: true,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[
            "account",
            "device",
            "event",
            "message",
            "attempt",
            "fetch_sha",
            "session_sha",
            "segments",
            "observed",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_identity",
        signature: "public.conversation_profile03_effect_identity(uuid, uuid, bytea)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt", "command"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_current",
        signature: "public.conversation_profile03_effect_current(uuid, uuid)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_grant_issue",
        signature: "public.conversation_profile03_grant_issue(uuid, uuid, uuid, uuid, text, text, bigint, bigint, bigint)",
        result: "public.conversation_profile03_grants",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: true,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "message",
            "attempt",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
            "permission_deadline_ms",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_grant_issued",
        signature: "public.conversation_profile03_grant_issued(uuid, uuid)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_submit",
        signature: "public.conversation_profile03_effect_submit(uuid, uuid, text, text, bigint, bigint, bytea)",
        result: "record",
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
            "command_bytes",
            "inserted",
            "account_id",
            "device_id",
            "message_id",
            "attempt_id",
            "event_id",
            "command",
            "command_sha256",
            "fetch_transcript_sha256",
            "original_device_session_digest",
            "segment_count",
            "observed_ms",
            "accepted_ms",
        ],
        modes: &[
            "i", "i", "i", "i", "i", "i", "i", "t", "t", "t", "t", "t", "t", "t", "t", "t", "t",
            "t", "t", "t",
        ],
        all_types: &[
            "uuid", "uuid", "text", "text", "bigint", "bigint", "bytea", "boolean", "uuid", "uuid",
            "uuid", "uuid", "uuid", "bytea", "bytea", "bytea", "bytea", "smallint", "bigint",
            "bigint",
        ],
    },
    Function {
        name: "conversation_profile03_effect_state",
        signature: "public.conversation_profile03_effect_state(uuid, uuid, bytea)",
        result: "text",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt", "candidate"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_project",
        signature: "public.conversation_profile03_effect_project(uuid, uuid, text, bigint)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt", "target", "stamp_ms"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_outcome",
        signature: "public.conversation_profile03_effect_outcome(uuid, uuid, text, text, bigint, bigint, bytea)",
        result: "record",
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
            "command_bytes",
            "inserted",
            "account_id",
            "device_id",
            "message_id",
            "attempt_id",
            "event_id",
            "submit_event_id",
            "command",
            "event_sha256",
            "submit_command_sha256",
            "fetch_transcript_sha256",
            "original_device_session_digest",
            "submit_observed_ms",
            "segment_count",
            "evidence",
            "observed_ms",
            "segment_index",
            "recorded_ms",
            "resulting_state",
        ],
        modes: &[
            "i", "i", "i", "i", "i", "i", "i", "t", "t", "t", "t", "t", "t", "t", "t", "t", "t",
            "t", "t", "t", "t", "t", "t", "t", "t", "t",
        ],
        all_types: &[
            "uuid", "uuid", "text", "text", "bigint", "bigint", "bytea", "boolean", "uuid", "uuid",
            "uuid", "uuid", "uuid", "uuid", "bytea", "bytea", "bytea", "bytea", "bytea", "bigint",
            "smallint", "smallint", "bigint", "smallint", "bigint", "text",
        ],
    },
    Function {
        name: "conversation_profile03_effect_session",
        signature: "public.conversation_profile03_effect_session(uuid, uuid, text, text, bigint, bigint, bytea)",
        result: "bytea",
        language: "sql",
        volatility: "s",
        strict: true,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[
            "account",
            "device",
            "site",
            "instance",
            "connection_epoch",
            "deployment_epoch",
            "key_id",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_closure_core",
        signature: "public.conversation_profile03_effect_closure_core(public.conversation_profile03_grants, public.conversation_profile03_effect_actors, public.conversation_profile03_closure_records, public.conversation_profile03_closure_challenges)",
        result: "bytea",
        language: "sql",
        volatility: "i",
        strict: true,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &["g", "a", "r", "c"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_closure_challenge",
        signature: "public.conversation_profile03_effect_closure_challenge(uuid, uuid, text, text, bigint, bigint, uuid, bytea, uuid)",
        result: "public.conversation_profile03_closure_challenges",
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
            "proof_request",
            "record",
            "previous_challenge",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_closure_accept",
        signature: "public.conversation_profile03_effect_closure_accept(uuid, uuid, text, text, bigint, bigint, uuid, bytea, bytea)",
        result: "public.conversation_profile03_closure_receipts",
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
            "proof_request",
            "core",
            "signature",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_pending",
        signature: "public.conversation_profile03_effect_pending(uuid, uuid)",
        result: "boolean",
        language: "sql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &["account", "attempt"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_target",
        signature: "public.conversation_profile03_effect_target(uuid, uuid)",
        result: "text",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &["account", "attempt"],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_writer",
        signature: "public.conversation_profile03_effect_writer(uuid, text, text, jsonb, jsonb)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "relation_name",
            "operation",
            "old_row",
            "new_row",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_grant_writer",
        signature: "public.conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[
            "account",
            "relation_name",
            "operation",
            "old_row",
            "new_row",
        ],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_rows_guard",
        signature: "public.conversation_profile03_effect_rows_guard()",
        result: "trigger",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_complete",
        signature: "public.conversation_profile03_effect_complete()",
        result: "trigger",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog", "lock_timeout=3s"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "payload_profile_writer_policy",
        signature: "public.payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)",
        result: "void",
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
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "payload_profile_writer_version",
        signature: "public.payload_profile_writer_version()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "payload_profile_writer_ready",
        signature: "public.payload_profile_writer_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "hosted_runtime_native_schema_valid",
        signature: "public.hosted_runtime_native_schema_valid()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "hosted_runtime_identity_ready",
        signature: "public.hosted_runtime_identity_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "hosted_runtime_scope",
        signature: "public.hosted_runtime_scope()",
        result: "void",
        language: "plpgsql",
        volatility: "v",
        strict: false,
        definer: true,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_reviewed_send03_v2_ready",
        signature: "public.conversation_reviewed_send03_v2_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "device_protection_ready",
        signature: "public.device_protection_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_interval_ready",
        signature: "public.conversation_profile03_interval_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
    Function {
        name: "conversation_profile03_effect_ready",
        signature: "public.conversation_profile03_effect_ready()",
        result: "boolean",
        language: "sql",
        volatility: "s",
        strict: false,
        definer: false,
        set: false,
        config: &["search_path=pg_catalog"],
        names: &[],
        modes: &[],
        all_types: &[],
    },
];
const FUNCTION_METADATA: &str = "SELECT p.prosrc,p.proowner=c.relowner,p.prorettype=pg_catalog.to_regtype(($2::text[])[e.ordinal::integer]),l.lanname::text,p.provolatile::text,p.proisstrict,p.prosecdef,p.proretset,p.proconfig,p.proargnames,p.proargmodes::text[],CASE WHEN p.proallargtypes IS NULL THEN NULL ELSE ARRAY(SELECT pg_catalog.format_type(t,NULL) FROM unnest(p.proallargtypes) t) END,p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0 AND NOT p.proleakproof AND p.proargdefaults IS NULL AND(SELECT count(*) FROM pg_catalog.pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1,e.ordinal FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS e(signature,ordinal) JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature) JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_class c ON c.oid='public.accounts'::pg_catalog.regclass ORDER BY e.ordinal";
async fn functions<C: GenericClient + Sync>(db: &C) -> Result<()> {
    let signatures = FUNCTIONS.iter().map(|f| f.signature).collect::<Vec<_>>();
    let results = FUNCTIONS.iter().map(|f| f.result).collect::<Vec<_>>();
    // One metadata snapshot per call, never a cached capability. Every expected
    // row, original body and declaration comparison remains mandatory.
    let rows = db
        .query(FUNCTION_METADATA, &[&signatures, &results])
        .await?;
    if rows.len() != FUNCTIONS.len() {
        return Err(EffectSchemaError::Invalid);
    }
    for (index, (f, row)) in FUNCTIONS.iter().zip(rows).enumerate() {
        if row.try_get::<_, i64>(13)? != index as i64 + 1 {
            return Err(EffectSchemaError::Invalid);
        }
        let strings = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let maybe = |xs: &[&str]| {
            if xs.is_empty() {
                None
            } else {
                Some(strings(xs))
            }
        };
        if row.try_get::<_, String>(0)? != body(f.name)?
            || !row.try_get::<_, bool>(1)?
            || !row.try_get::<_, bool>(2)?
            || row.try_get::<_, String>(3)? != f.language
            || row.try_get::<_, String>(4)? != f.volatility
            || row.try_get::<_, bool>(5)? != f.strict
            || row.try_get::<_, bool>(6)? != f.definer
            || row.try_get::<_, bool>(7)? != f.set
            || row.try_get::<_, Option<Vec<String>>>(8)? != Some(strings(f.config))
            || row.try_get::<_, Option<Vec<String>>>(9)? != maybe(f.names)
            || row.try_get::<_, Option<Vec<String>>>(10)? != maybe(f.modes)
            || row.try_get::<_, Option<Vec<String>>>(11)? != maybe(f.all_types)
            || !row.try_get::<_, bool>(12)?
        {
            return Err(EffectSchemaError::Invalid);
        }
    }
    Ok(())
}
type Column = (&'static str, &'static str, bool);
type Table = (&'static str, &'static [Column]);
const TABLES: &[Table] = &[
    (
        "conversation_profile03_effect_actors",
        &[
            ("account_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("message_id", "uuid", true),
            ("device_id", "uuid", true),
            ("original_enrolled_point", "bytea", true),
            ("original_enrolled_key_id", "bytea", true),
            ("fetch_transcript_sha256", "bytea", true),
            ("original_device_session_digest", "bytea", true),
            ("minted_ms", "bigint", true),
        ],
    ),
    (
        "conversation_profile03_submits",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("message_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("event_id", "uuid", true),
            ("command", "bytea", true),
            ("command_sha256", "bytea", true),
            ("fetch_transcript_sha256", "bytea", true),
            ("original_device_session_digest", "bytea", true),
            ("segment_count", "smallint", true),
            ("observed_ms", "bigint", true),
            ("accepted_ms", "bigint", true),
        ],
    ),
    (
        "conversation_profile03_outcomes",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("message_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("event_id", "uuid", true),
            ("submit_event_id", "uuid", true),
            ("command", "bytea", true),
            ("event_sha256", "bytea", true),
            ("submit_command_sha256", "bytea", true),
            ("fetch_transcript_sha256", "bytea", true),
            ("original_device_session_digest", "bytea", true),
            ("submit_observed_ms", "bigint", true),
            ("segment_count", "smallint", true),
            ("evidence", "smallint", true),
            ("observed_ms", "bigint", true),
            ("segment_index", "smallint", false),
            ("recorded_ms", "bigint", true),
            ("resulting_state", "text", false),
        ],
    ),
    (
        "conversation_profile03_closure_records",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("message_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("closure_id", "uuid", true),
            ("submit_event_id", "uuid", true),
            ("record", "bytea", true),
            ("record_sha256", "bytea", true),
            ("submit_command_sha256", "bytea", true),
            ("fetch_transcript_sha256", "bytea", true),
            ("original_device_session_digest", "bytea", true),
            ("segment_count", "smallint", true),
            ("submit_observed_ms", "bigint", true),
            ("closed_from", "smallint", true),
            ("closed_ms", "bigint", true),
            ("created_ms", "bigint", true),
        ],
    ),
    (
        "conversation_profile03_closure_challenges",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("message_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("closure_id", "uuid", true),
            ("proof_request_id", "uuid", true),
            ("challenge_id", "uuid", true),
            ("nonce", "bytea", true),
            ("core", "bytea", true),
            ("core_sha256", "bytea", true),
            ("issued_ms", "bigint", true),
            ("expires_ms", "bigint", true),
            ("proof_site_id", "text", true),
            ("proof_instance_id", "text", true),
            ("proof_connection_epoch", "bigint", true),
            ("proof_deployment_epoch", "bigint", true),
            ("proof_device_session_digest", "bytea", true),
            ("previous_challenge_id", "uuid", false),
            ("recovery_window_started_ms", "bigint", false),
            ("recovery_window_ordinal", "smallint", false),
            ("closed_unaccepted_ms", "bigint", false),
            ("superseded_by_challenge_id", "uuid", false),
        ],
    ),
    (
        "conversation_profile03_closure_receipts",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("message_id", "uuid", true),
            ("attempt_id", "uuid", true),
            ("closure_id", "uuid", true),
            ("proof_request_id", "uuid", true),
            ("challenge_id", "uuid", true),
            ("submit_command_sha256", "bytea", true),
            ("record_sha256", "bytea", true),
            ("core", "bytea", true),
            ("core_sha256", "bytea", true),
            ("signature", "bytea", true),
            ("signature_sha256", "bytea", true),
            ("accepted_ms", "bigint", true),
        ],
    ),
    (
        "conversation_profile03_effect_quarantines",
        &[
            ("account_id", "uuid", true),
            ("device_id", "uuid", true),
            ("original_enrolled_point", "bytea", true),
            ("original_enrolled_key_id", "bytea", true),
            ("first_attempt_id", "uuid", true),
            ("first_event_id", "uuid", true),
            ("closure_id", "uuid", true),
            ("challenge_id", "uuid", true),
            ("recorded_ms", "bigint", true),
        ],
    ),
];
async fn tables<C: GenericClient + Sync>(db: &C) -> Result<()> {
    for (table, expected) in TABLES {
        let rows=db.query("SELECT a.attname::text,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,NOT a.atthasdef AND NOT a.atthasmissing AND a.attidentity='' AND a.attgenerated='' FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::pg_catalog.regnamespace AND c.relname=$1 AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND c.relowner=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='public.accounts'::pg_catalog.regclass) AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",&[table]).await?;
        if rows.len() != expected.len() {
            return Err(EffectSchemaError::Invalid);
        }
        for (row, (name, kind, required)) in rows.iter().zip(*expected) {
            if row.try_get::<_, String>(0)? != *name
                || row.try_get::<_, String>(1)? != *kind
                || row.try_get::<_, bool>(2)? != *required
                || !row.try_get::<_, bool>(3)?
            {
                return Err(EffectSchemaError::Invalid);
            }
        }
    }
    Ok(())
}
/// False only for total pre119 absence. Partial or recorded installations refuse.
pub async fn optional<C: GenericClient + Sync>(db: &C) -> Result<bool> {
    let names = TABLES
        .iter()
        .map(|(n, _)| (*n).to_owned())
        .collect::<Vec<_>>();
    let row=db.query_one("SELECT (SELECT count(*) FROM pg_catalog.pg_class WHERE relnamespace='public'::pg_catalog.regnamespace AND relname=ANY($1::text[])),(SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='public'::pg_catalog.regnamespace AND proname LIKE 'conversation_profile03_effect_%'),EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::pg_catalog.regnamespace AND EXISTS(SELECT FROM unnest($1::text[]) AS f(name) WHERE pg_catalog.starts_with(c.relname::text,f.name)))",&[&names]).await?;
    let present: i64 = row.try_get(0)?;
    let helpers: i64 = row.try_get(1)?;
    if present == 0 && helpers == 0 && !row.try_get::<_, bool>(2)? {
        if db.query_one("SELECT pg_catalog.to_regclass('public.payload_profile_writer_catalog') IS NOT NULL",&[]).await?.try_get::<_,bool>(0)? {
   crate::payload_profile_writer::optional(db,"public.accounts").await?;
   if db.query_one("SELECT migration_version>=119 FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get::<_,bool>(0)?{return Err(EffectSchemaError::Invalid);}
  }
        if db
            .query_one(
                "SELECT pg_catalog.to_regclass('public.schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get::<_, bool>(0)?
            && db
                .query_one(
                    "SELECT EXISTS(SELECT FROM public.schema_migrations WHERE version>=119)",
                    &[],
                )
                .await?
                .try_get::<_, bool>(0)?
        {
            return Err(EffectSchemaError::Invalid);
        }
        return Ok(false);
    }
    if present != 7 || helpers != 22 {
        return Err(EffectSchemaError::Invalid);
    }
    crate::hosted_runtime_identity::require(db).await?;
    if !crate::payload_profile_writer::optional(db,"public.accounts").await? || db.query_one("SELECT migration_version FROM public.payload_profile_writer_catalog WHERE singleton",&[]).await?.try_get::<_,i64>(0)?!=120 {return Err(EffectSchemaError::Invalid);}
    functions(db).await?;
    tables(db).await?;
    if !db
        .query_one("SELECT public.conversation_profile03_effect_ready()", &[])
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(EffectSchemaError::Invalid);
    }
    Ok(true)
}
/// A closed ordinary-runtime capability only. Genuine native/current opaque
/// actor, original crypto and successful first COMMIT remain independent.
pub async fn require<C: GenericClient + Sync>(db: &C) -> Result<()> {
    crate::conversation_profile03_grant_storage::require(db).await?;
    if !optional(db).await? {
        return Err(EffectSchemaError::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
