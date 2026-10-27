// SPDX-License-Identifier: AGPL-3.0-only
//! Preserve the original closed-array bytes while traversing bounded array levels.
use crate::test_database::Fixture;
use futures_util::FutureExt;
use std::panic::{AssertUnwindSafe, resume_unwind};
use tokio_postgres::error::SqlState;

// The original recursive implementation is an independent equivalence oracle.
// Keep it literal: deriving it from the current migration would mirror a bug.
const LEGACY: &str = r#"
CREATE FUNCTION pg_temp.writer_json_legacy(value json) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE result text;
BEGIN
    IF json_typeof(value)='array' THEN
        SELECT '['||coalesce(string_agg(pg_temp.writer_json_legacy(element),',' ORDER BY ordinal),'')||']'
          INTO result FROM json_array_elements(value) WITH ORDINALITY items(element,ordinal);
        RETURN result;
    END IF;
    IF json_typeof(value)='object' THEN
        RAISE EXCEPTION 'writer canonical array required' USING ERRCODE='23514';
    END IF;
    RETURN value::text;
END;
$function$;
"#;

// Plan the array SELECT from the installed function, without executing it or
// changing planner settings. A tiny value must not inherit the multiplicative
// cost of deep correlated subplans and trigger default JIT compilation.
async fn assert_serializer_plan_stays_below_default_jit_cost(db: &tokio_postgres::Client) {
    let installed: String = db
        .query_one(
            "SELECT prosrc FROM pg_proc WHERE oid='public.payload_profile_writer_json(json)'::regprocedure",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let compiled = zrotext_delivery_store::hosted_runtime_identity::declared_function_body(
        include_str!("../../../../deploy/compose/migrations/108_payload_profile_writer_fences.sql"),
        "payload_profile_writer_json",
        "$function$",
    )
    .unwrap();
    assert_eq!(
        installed, compiled,
        "installed serializer differs from source"
    );
    let (_, query) = compiled.split_once("SELECT '['").unwrap();
    let (query, _) = query
        .split_once(
            "INTO result FROM json_array_elements(value) WITH ORDINALITY items(element,ordinal);",
        )
        .unwrap();
    db.batch_execute(
        "CREATE TEMP TABLE writer_plan_input(value json); \
         INSERT INTO writer_plan_input VALUES ('[[1,2,[],[3,4]]]'::json); \
         ANALYZE writer_plan_input;",
    )
    .await
    .unwrap();
    let rows = db
        .simple_query(&format!(
            "EXPLAIN (FORMAT JSON) SELECT '['{query} \
             FROM json_array_elements((SELECT value FROM pg_temp.writer_plan_input)) \
             WITH ORDINALITY items(element,ordinal);"
        ))
        .await
        .unwrap();
    let text = rows
        .iter()
        .find_map(|row| match row {
            tokio_postgres::SimpleQueryMessage::Row(row) => row.get(0),
            _ => None,
        })
        .unwrap();
    let plan: serde_json::Value = serde_json::from_str(text).unwrap();
    let cost = plan[0]["Plan"]["Total Cost"].as_f64().unwrap();
    assert!(
        cost.is_finite() && cost < 100_000.0,
        "serializer cost {cost} reaches default JIT threshold"
    );
    db.batch_execute("DROP TABLE pg_temp.writer_plan_input")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable ZT_AUTH_TEST_DATABASE_URL; compares installed canonical JSON with the original serializer"]
async fn bounded_array_serialization_preserves_legacy_bytes_and_object_refusals() {
    let fixture = Fixture::for_store("ZT_AUTH_TEST_DATABASE_URL").await;
    let outcome = AssertUnwindSafe(async {
        fixture.owner.batch_execute(LEGACY).await.unwrap();
        assert_serializer_plan_stays_below_default_jit_cost(&fixture.owner).await;
        let mut vectors = [
            r#"[""]"#, "null", "true", "false", "0", "-0", "1.00", "1e+2", "1E-02", "1e9999",
            "[]", "[[],[[]]]", r#""\u0041""#, r#""\ud83d\ude03""#,
            r#"["spaces, {} [] : preserved","quote \" and slash \\","\n\t\b\f\r"]"#,
            r#"[null,true,false,1.00,-0,1E+02]"#,
        ].map(str::to_owned).to_vec();
        let mut nested = r#"["nested spaces, and escapes \"",null,1.00]"#.to_owned();
        for _ in 0..32 {
            nested = format!("[{nested}]");
            vectors.push(nested.clone());
        }
        for ordinal in 0..128 {
            let leaf = serde_json::to_string(&format!("synthetic '{ordinal}, é and 😀"))
                .unwrap();
            vectors.push(format!("[{ordinal},[true,null,false],{leaf},[[],[1.00,-0,1E+02]]]"));
        }
        vectors.extend([
            "\"\"".to_owned(),
            r#"["\u0022","\u005c","\u007b"]"#.to_owned(),
            " \t[\n1,\r2,\t\" inside \\t string \"\n]\r ".to_owned(),
        ]);
        for count in 0..32 {
            let value = format!("{}\"{{}}", "\\".repeat(count));
            vectors.push(serde_json::to_string(&vec![value]).unwrap());
        }
        for value in vectors {
            let row = fixture.owner.query_one(
                "SELECT public.payload_profile_writer_json($1::text::json),pg_temp.writer_json_legacy($1::text::json)",
                &[&value],
            ).await.unwrap();
            assert_eq!(row.get::<_,String>(0),row.get::<_,String>(1));
        }
        let row=fixture.owner.query_one(
            "SELECT public.payload_profile_writer_json(NULL::json),pg_temp.writer_json_legacy(NULL::json)",
            &[],
        ).await.unwrap();
        assert_eq!(row.get::<_,Option<String>>(0),None);
        assert_eq!(row.get::<_,Option<String>>(1),None);
        fixture
            .owner
            .batch_execute(include_str!("canonical_json_tests/writer_graph_legacy.sql"))
            .await
            .unwrap();
        let row=fixture.owner.query_one(
            "SELECT public.payload_profile_writer_graph(),pg_temp.writer_graph_legacy()",
            &[],
        ).await.unwrap();
        assert_eq!(row.get::<_,Vec<u8>>(0),row.get::<_,Vec<u8>>(1));
        for value in ["{}", "[{}]", r#"[[1,{"a":2}]]"#, r#"{"a":1,"a":2}"#] {
            for query in [
                "SELECT public.payload_profile_writer_json($1::text::json)",
                "SELECT pg_temp.writer_json_legacy($1::text::json)",
            ] {
                let error=fixture.owner.query_one(query,&[&value]).await.unwrap_err();
                assert_eq!(error.code(),Some(&SqlState::CHECK_VIOLATION));
            }
        }
        let mut object="{}".to_owned();
        for _ in 0..32 {
            object=format!("[{object}]");
            for query in [
                "SELECT public.payload_profile_writer_json($1::text::json)",
                "SELECT pg_temp.writer_json_legacy($1::text::json)",
            ] {
                let error=fixture.owner.query_one(query,&[&object]).await.unwrap_err();
                assert_eq!(error.code(),Some(&SqlState::CHECK_VIOLATION));
            }
        }
    }).catch_unwind().await;
    fixture.finish().await;
    if let Err(panic) = outcome {
        resume_unwind(panic);
    }
}
