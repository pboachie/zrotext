// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sha2::{Digest, Sha256};

#[test]
fn every_required_declaration_pins_its_actual_source_including_transitive_writers() {
    let pins = [
        (
            "conversation_profile03_effect_fetch",
            "46d5570b5118ee73d6968d1e6004a5b574c188a13663004de8ba2b1c777e7a78",
        ),
        (
            "conversation_profile03_effect_mode",
            "6b59433120a1e8a2bea315ddbf5970b272fe693ea42783ca2c5344a97f19f022",
        ),
        (
            "conversation_profile03_effect_actor",
            "9aea9da8af7a64ceb3ecf9513941e3e757bbecae0fd9e4f1e423be93961e28e0",
        ),
        (
            "conversation_profile03_effect_history_lock",
            "eb8e490e3c5b6ff86631f2fef9ace0b83285da30228f7bbbe2aadc5591e03015",
        ),
        (
            "conversation_profile03_effect_not_quarantined",
            "0531273cb6c602eb5599634608e3438d5b554386d22de74df56849ca4eecd556",
        ),
        (
            "conversation_profile03_effect_submit_bytes",
            "84f843efc1ee479109ff2252971fa80b717c1be5abc56dadd7e316b356beae28",
        ),
        (
            "conversation_profile03_effect_identity",
            "db62bfbc313ca4d9594f993314b79b9e3ab4ed9d5191ca55e39b1905bbfbf8a4",
        ),
        (
            "conversation_profile03_effect_current",
            "b845626068cd2a9b86db28fd5c9b926046d9c51f58459b7b1ec98f605cc5e72d",
        ),
        (
            "conversation_profile03_grant_issue",
            "662948ed179db3ee8ecc81b8b38d2be6a8c25ec638fd563489c72a01f42da031",
        ),
        (
            "conversation_profile03_grant_issued",
            "b514e3fd0bc7399e1ee237b5b115fb879110781568e4fa18690d148a9eb2dc8b",
        ),
        (
            "conversation_profile03_effect_submit",
            "940c707d3dad998d28f01838390bef46060d04d09ad1a34a7ed21c2d73c26176",
        ),
        (
            "conversation_profile03_effect_state",
            "84e23bde85348bdd796cab1ce3ff38d9fca7366f34e4cf7197eb063d5929df24",
        ),
        (
            "conversation_profile03_effect_project",
            "ef12f10fc5344a3507a33af747e8e9fc99be35f33dca6ba5281e183b77f605b0",
        ),
        (
            "conversation_profile03_effect_outcome",
            "1d8cc03cd4a42b689282cf973a019acb2633e8e4b5f5cdd1700e8cb8bc17152d",
        ),
        (
            "conversation_profile03_effect_session",
            "ab028cd81576e17e1de0e4bfa0d78592f713d333fa79fbfe048e642618d4c8b7",
        ),
        (
            "conversation_profile03_effect_closure_core",
            "393b6ac32abe20fdd2d13b7a40793a3da61218e1d4b82fc1a4c17044326988ea",
        ),
        (
            "conversation_profile03_effect_closure_challenge",
            "268b13735b86066ca58117dc016f1af612e632551541c54b68cc0b9ba7bf4a29",
        ),
        (
            "conversation_profile03_effect_closure_accept",
            "7b01fb22b52d7607c9f56c06b10c69ee9a11deca2abf47c0930e6342716b17ba",
        ),
        (
            "conversation_profile03_effect_pending",
            "d838bc9e19c423494d1b9476b27a3cfea020e54f19cee8d2f2615688f2ce4ca2",
        ),
        (
            "conversation_profile03_effect_target",
            "183038293e19875f3a8912b104d1de045dd4bfb26ce5bfd743c689d9583ce886",
        ),
        (
            "conversation_profile03_effect_writer",
            "5f9a702de26f5d62ebb1057e6e94ebe4cacb999b424e270e5072f8ae93d710d0",
        ),
        (
            "conversation_profile03_grant_writer",
            "0666a76a343d03d4e0b1efac55e6d2f56cfe2133db7461dc6e644b637926841f",
        ),
        (
            "conversation_profile03_effect_rows_guard",
            "27bdf3ca66e4a93d97e2049ddf6bd9040a86ee9c409afd886b59c2dff71d2ea6",
        ),
        (
            "conversation_profile03_effect_complete",
            "bdacdf5a8d5582dcd0d13ed7ac9f0e43b3526821a8f0258e41b0e0622b318ea6",
        ),
        (
            "payload_profile_writer_policy",
            "0ff5722a8072c00e04b2aaf5f1701a46f244c857743f73ec557e64b94eb46667",
        ),
        (
            "payload_profile_writer_version",
            "703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c",
        ),
        (
            "payload_profile_writer_ready",
            "5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918",
        ),
        (
            "hosted_runtime_native_schema_valid",
            "be255c4a7269de17dbe975d019411481806e68eb590ac5fa66ef901f1d87f26d",
        ),
        (
            "hosted_runtime_identity_ready",
            "fe05742031ad01f8ec25539bfd2af310d76e31e60421eb8143e33eb91d5d21b2",
        ),
        (
            "hosted_runtime_scope",
            "b6d01cd95aa574d52d5d81b02aa2786cd56b0c4df630c1abd123501dd1e83f7b",
        ),
        (
            "conversation_reviewed_send03_v2_ready",
            "913249dc22a3aaa2d2cf904f82a9c2e73822f051445a91144407b439e8945997",
        ),
        (
            "device_protection_ready",
            "b32597624f0409599a76f4711dea9adae0a041f98d91e0c0f25eb96419a470d9",
        ),
        (
            "conversation_profile03_interval_ready",
            "962ffbf3817bbe46913b371b787914a218f69b918b678e886db01bdd2e73c247",
        ),
        (
            "conversation_profile03_effect_ready",
            "841fd43a8c9b8821f5ab80984b5486749052315570de713854b5be3e016842ba",
        ),
    ];
    assert_eq!(pins.len(), FUNCTIONS.len());
    let declarations = MIGRATION
        .lines()
        .filter_map(|line| {
            line.strip_prefix("CREATE FUNCTION public.")
                .or_else(|| line.strip_prefix("CREATE OR REPLACE FUNCTION public."))
        })
        .map(|s| s.split_once('(').unwrap().0)
        .collect::<Vec<_>>();
    // The migration also replaces one legacy invoker trigger; it is not a
    // typed effect capability and must not enter the typed FUNCTIONS table.
    let (legacy, declarations): (Vec<_>, Vec<_>) = declarations
        .into_iter()
        .partition(|name| *name == "close_billing_invoice_liability");
    assert_eq!(legacy, ["close_billing_invoice_liability"]);
    let legacy_body = zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        MIGRATION,
        "close_billing_invoice_liability",
        "$$",
    )
    .unwrap();
    let legacy_hash = Sha256::digest(legacy_body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        legacy_hash,
        "2c8daf93d7c5990fa0ac5ea2eb9c7ecf0a5cf7fc0cd5f67413092ca47c78c261"
    );
    assert_eq!(declarations.len(), FUNCTIONS.len());
    for ((name, expected), function) in pins.iter().zip(FUNCTIONS) {
        assert_eq!(*name, function.name);
        assert!(declarations.contains(name));
        let actual = Sha256::digest(body(name).unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, *expected, "{name}: declaration routing changed");
    }
}

#[test]
fn complete_interval_helper_policy_adds_only_the_six_typed_public_controls() {
    let source = body("conversation_profile03_interval_ready").unwrap();
    let (_, tail) = source.split_once("p.proname IN(").unwrap();
    let (names, _) = tail.split_once(')').unwrap();
    let actual = names
        .split(',')
        .map(|name| name.trim().trim_matches(char::from(39)))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            "conversation_profile03_interval_reserve",
            "conversation_profile03_interval_request",
            "conversation_profile03_interval_approve",
            "conversation_profile03_interval_install",
            "conversation_profile03_interval_stop",
            "conversation_profile03_interval_device_stop",
            "conversation_profile03_interval_ready",
            "conversation_profile03_grant_issue",
            "conversation_profile03_grant_lock",
            "conversation_profile03_grant_ready",
            "conversation_profile03_effect_history_lock",
            "conversation_profile03_effect_submit",
            "conversation_profile03_effect_outcome",
            "conversation_profile03_effect_closure_challenge",
            "conversation_profile03_effect_closure_accept",
            "conversation_profile03_effect_ready"
        ]
    );
    assert!(source.contains("NOT has_table_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')"));
    assert!(source.contains("NOT has_any_column_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,REFERENCES')"));
    assert!(source.contains("proname LIKE 'conversation_profile03_%' AND a.grantee=0"));
}

#[test]
fn standalone_predecessor_readiness_pins_the_actual_latest_declaration() {
    let name = "conversation_reviewed_send03_v2_ready";
    let digest = |source| {
        let body = zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
            source,
            name,
            "$function$",
        )
        .unwrap();
        Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let latest = digest(include_str!(
        "../../../../deploy/compose/migrations/118_device_protection_origins.sql"
    ));
    let stale = digest(include_str!(
        "../../../../deploy/compose/migrations/117_explicit_reviewed_intent_v2.sql"
    ));
    assert_ne!(latest, stale);
    let (_, predicate) = MIGRATION
        .split_once("p.oid=to_regprocedure('public.conversation_reviewed_send03_v2_ready()')")
        .unwrap();
    let (predicate, _) = predicate.split_once("AND p.proowner").unwrap();
    assert!(predicate.contains(&format!("='{latest}'")));
    assert!(!predicate.contains(&stale));
}

#[test]
fn every_predecessor_tuple_pins_the_latest_exact_source_body() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sql"))
        .collect::<Vec<_>>();
    files.sort();
    let mut latest = std::collections::BTreeMap::new();
    for path in files {
        if path.file_name().unwrap().to_str().unwrap()[..3]
            .parse::<u16>()
            .unwrap()
            >= 119
        {
            continue;
        }
        let source = std::fs::read_to_string(path).unwrap();
        let mut offset = 0;
        let mut declarations = Vec::new();
        for line in source.split_inclusive('\n') {
            if let Some(rest) = line
                .strip_prefix("CREATE FUNCTION ")
                .or_else(|| line.strip_prefix("CREATE OR REPLACE FUNCTION "))
            {
                let name = rest
                    .split_once('(')
                    .unwrap()
                    .0
                    .strip_prefix("public.")
                    .unwrap_or(rest.split_once('(').unwrap().0);
                declarations.push((offset, name.to_owned()));
            }
            offset += line.len();
        }
        for (index, (start, name)) in declarations.iter().enumerate() {
            let end = declarations
                .get(index + 1)
                .map_or(source.len(), |row| row.0);
            let declaration = &source[*start..end];
            let body = ["$function$", "$$"].iter().find_map(|marker| {
                declaration
                    .split_once(&format!("AS {marker}"))
                    .and_then(|(_, after)| after.split_once(&format!("{marker};")))
                    .map(|(body, _)| body)
            });
            if let Some(body) = body {
                latest.insert(
                    name.clone(),
                    Sha256::digest(body.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                );
            }
        }
    }
    let preflight = MIGRATION
        .split_once("CREATE TABLE public.conversation_profile03_effect_actors")
        .unwrap()
        .0;
    let mut pins = 0;
    for line in preflight.lines() {
        let Some(row) = line.trim_start().strip_prefix("('") else {
            continue;
        };
        let Some((signature, _)) = row.split_once("',") else {
            continue;
        };
        let Some((name, _)) = signature.split_once('(') else {
            continue;
        };
        let name = name.strip_prefix("public.").unwrap_or(name);
        let expected = latest
            .get(name)
            .unwrap_or_else(|| panic!("{name}: required predecessor source missing"));
        let hashes = row
            .split('\'')
            .filter(|token| token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect::<Vec<_>>();
        assert!(
            hashes.contains(&expected.as_str()),
            "{name}: stale predecessor pin"
        );
        pins += 1;
    }
    assert_eq!(pins, 124);
}

#[test]
fn inserted_receipts_have_flat_exact_outputs_and_distinct_input_names() {
    for (function, table) in [
        (
            "conversation_profile03_effect_submit",
            "conversation_profile03_submits",
        ),
        (
            "conversation_profile03_effect_outcome",
            "conversation_profile03_outcomes",
        ),
    ] {
        let f = FUNCTIONS.iter().find(|f| f.name == function).unwrap();
        let (_, columns) = TABLES.iter().find(|(name, _)| *name == table).unwrap();
        assert_eq!(
            &f.names[..7],
            &[
                "account",
                "device",
                "site",
                "instance",
                "connection_epoch",
                "deployment_epoch",
                "command_bytes"
            ]
        );
        assert_eq!(f.names[7], "inserted");
        assert_eq!(f.all_types[7], "boolean");
        assert_eq!(&f.modes[..7], &["i"; 7]);
        assert_eq!(f.modes[7..], vec!["t"; columns.len() + 1]);
        assert_eq!(f.names.len(), columns.len() + 8);
        assert_eq!(f.all_types.len(), f.names.len());
        for (index, (name, kind, _)) in columns.iter().enumerate() {
            assert_eq!(f.names[index + 8], *name);
            assert_eq!(f.all_types[index + 8], *kind);
        }
        let mut unique = f.names.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), f.names.len());
        assert_eq!(f.result, "record");
        assert!(f.set);
    }
}

#[test]
fn typed_stock_reset_finishes_before_the_only_provisioning_commit() {
    let stock = include_str!("../../../../deploy/compose/runtime-role.sql");
    let begin = stock.find("\nBEGIN;").unwrap();
    let commit = stock.find("\nCOMMIT;").unwrap();
    let typed = stock
        .find("-- Typed effect originals are account-lifetime history")
        .unwrap();
    assert!(begin < typed && typed < commit);
    assert_eq!(stock.matches("\nCOMMIT;").count(), 1);
    assert!(stock.trim_end().ends_with("COMMIT;"));
    for (table, _) in TABLES {
        assert!(stock[typed..commit].contains(table));
    }
}

#[cfg(test)]
mod database_tests;

#[test]
fn orphan_closure_check_is_nested_under_its_exact_record_shape() {
    let source = body("conversation_profile03_effect_complete").unwrap();
    let expected = " IF TG_TABLE_NAME='conversation_profile03_closure_records' THEN\n  IF NOT EXISTS(SELECT FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.closure_id=NEW.closure_id) THEN\n   RAISE EXCEPTION 'typed orphan closure assertion cannot commit' USING ERRCODE='23514'; END IF;\n END IF;";
    assert_eq!(source.matches(expected).count(), 1);
    assert_eq!(source.matches("NEW.closure_id").count(), 1);
}

#[cfg(test)]
mod schema_tests;

#[test]
fn effect_readiness_retains_exact_latest_graph_through_pinned_v2() {
    let body = |source, name| {
        zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
            source,
            name,
            "$function$",
        )
        .unwrap()
    };
    for (source, caller, callee) in [
        (
            MIGRATION,
            "conversation_profile03_effect_ready",
            "conversation_reviewed_send03_v2_ready",
        ),
        (
            MIGRATION,
            "conversation_reviewed_send03_v2_ready",
            "conversation_reviewed_send03_ready",
        ),
        (
            include_str!(
                "../../../../deploy/compose/migrations/117_explicit_reviewed_intent_v2.sql"
            ),
            "conversation_reviewed_send03_ready",
            "conversation_profile03_interval_ready",
        ),
        (
            MIGRATION,
            "conversation_profile03_interval_ready",
            "payload_profile_manifest_ready",
        ),
        (
            include_str!(
                "../../../../deploy/compose/migrations/112_payload_profile_manifest_successors.sql"
            ),
            "payload_profile_manifest_ready",
            "payload_profile_selection_ready",
        ),
        (
            include_str!(
                "../../../../deploy/compose/migrations/111_payload_profile_selection_refresh.sql"
            ),
            "payload_profile_selection_ready",
            "payload_profile_election_ready",
        ),
        (
            include_str!("../../../../deploy/compose/migrations/110_payload_profile_elections.sql"),
            "payload_profile_election_ready",
            "payload_profile_v2_ready",
        ),
        (
            include_str!(
                "../../../../deploy/compose/migrations/109_original_sealed_activation_receipts.sql"
            ),
            "payload_profile_v2_ready",
            "payload_profile_writer_ready",
        ),
        (
            MIGRATION,
            "hosted_runtime_identity_ready",
            "payload_profile_writer_ready",
        ),
    ] {
        assert!(
            body(source, caller)
                .trim_start()
                .starts_with(&format!("SELECT public.{callee}()")),
            "{caller}"
        );
    }
    let writer = body(MIGRATION, "payload_profile_writer_ready");
    assert!(writer.contains("SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=119 AND graph_sha256=public.payload_profile_writer_graph()"));
    assert!(writer.contains("FROM public.payload_profile_writer_catalog WHERE singleton),false)"));
    assert!(body(MIGRATION, "payload_profile_writer_version").contains(
        "SELECT count(*)=119 AND min(version)=1 AND max(version)=119 FROM public.schema_migrations"
    ));
    assert!(
        body(MIGRATION, "hosted_runtime_identity_ready")
            .contains("AND public.payload_profile_writer_version()")
    );
    for name in [
        "conversation_reviewed_send03_v2_ready",
        "hosted_runtime_identity_ready",
        "payload_profile_writer_ready",
        "payload_profile_writer_version",
    ] {
        assert!(FUNCTIONS.iter().any(|function| function.name == name));
    }
}
