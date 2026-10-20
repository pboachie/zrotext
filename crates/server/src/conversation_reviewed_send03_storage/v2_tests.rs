// SPDX-License-Identifier: AGPL-3.0-only
//! Structural storage tests, separate from authenticated admission and signatures.
use super::*;
use tokio_postgres::error::SqlState;

fn decode(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn explicit_v2_parser_reads_shared_boundaries_without_a_plaintext_digest() {
    let fixture = super::tests::fixture().await;
    require_v2(&fixture.db).await.unwrap();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/reviewed-intent03-v2.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let original = decode(case["intent_hex"].as_str().unwrap());
        let parsed = fixture.owner.query_one(
            "SELECT (p).intent_version,(p).body_digest,(p).peer,(p).authenticated_segment_ceiling,(p).recipients FROM (SELECT public.conversation_reviewed_send03_parse($1) p) parsed",
            &[&original],
        ).await.unwrap();
        assert_eq!(parsed.get::<_, i16>(0), 2);
        assert!(parsed.get::<_, Option<Vec<u8>>>(1).is_none());
        assert_eq!(
            parsed.get::<_, String>(2).as_bytes(),
            decode(case["fields"]["peer"].as_str().unwrap())
        );
        assert_eq!(
            i64::from(parsed.get::<_, i16>(3)),
            case["fields"]["smsCeiling"].as_i64().unwrap()
        );
        assert_eq!(
            parsed.get::<_, Vec<u8>>(4).len(),
            case["fields"]["recipients"].as_array().unwrap().len() * 33
        );
        assert!((592..=803).contains(&original.len()));
        for at in [0, 4, 5, 6, 7, 520] {
            let mut changed = original.clone();
            changed[at] ^= 1;
            assert!(
                fixture
                    .owner
                    .query_one(
                        "SELECT public.conversation_reviewed_send03_parse($1)",
                        &[&changed]
                    )
                    .await
                    .is_err()
            );
        }
        for ceiling in [0, 7] {
            let mut changed = original.clone();
            *changed.last_mut().unwrap() = ceiling;
            assert!(
                fixture
                    .owner
                    .query_one(
                        "SELECT public.conversation_reviewed_send03_parse($1)",
                        &[&changed]
                    )
                    .await
                    .is_err()
            );
        }
        let mut obsolete_body = original.clone();
        obsolete_body.splice(520..520, [8_u8; 32]);
        assert!(
            fixture
                .owner
                .query_one(
                    "SELECT public.conversation_reviewed_send03_parse($1)",
                    &[&obsolete_body]
                )
                .await
                .is_err()
        );
    }
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn original_v1_can_be_parsed_for_history_but_cannot_request_new_admission() {
    let fixture = super::tests::fixture().await;
    let original = super::tests::intent();
    let row = fixture.owner.query_one(
        "SELECT (p).intent_version,(p).body_digest,(p).account_id,(p).interval_id,(p).message_id FROM (SELECT public.conversation_reviewed_send03_parse($1) p) parsed",
        &[&original],
    ).await.unwrap();
    assert_eq!(row.get::<_, i16>(0), 1);
    assert_eq!(row.get::<_, Vec<u8>>(1), original[520..552]);
    let account: uuid::Uuid = row.get(2);
    let interval: uuid::Uuid = row.get(3);
    let message: uuid::Uuid = row.get(4);
    let error = fixture
        .owner
        .query(
            "SELECT public.conversation_reviewed_send03_admit($1,$2,$3,$4,$5,$6,$7)",
            &[
                &account,
                &interval,
                &message,
                &original,
                &vec![1_u8; 64],
                &vec![2_u8],
                &2000_i64,
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    assert_eq!(
        error.as_db_error().unwrap().message(),
        "reviewed03 historical V1 is not a new admission"
    );
    assert_eq!(
        fixture
            .owner
            .query_one(
                "SELECT count(*) FROM public.conversation_reviewed_sends03",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL with CREATEDB/CREATEROLE on a disposable PostgreSQL cluster"]
async fn v2_capability_refuses_missing_or_substituted_format_and_column_contracts() {
    let mut fixture = super::tests::fixture().await;
    require_v2(&fixture.db).await.unwrap();
    for sql in [
        "DROP FUNCTION public.conversation_reviewed_send03_v2_ready()",
        "CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_v2_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog AS 'SELECT true'",
        "ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN intent_version SET DEFAULT 2",
        "ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN intent_version DROP NOT NULL",
        "ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN body_digest SET NOT NULL",
        "ALTER TABLE public.conversation_reviewed_sends03 DROP CONSTRAINT conversation_reviewed_sends03_intent_format_check",
        "GRANT UPDATE(intent_version) ON public.conversation_reviewed_sends03 TO PUBLIC",
    ] {
        assert!(optional(&fixture.owner).await.unwrap());
        let tx = fixture.owner.transaction().await.unwrap();
        tx.batch_execute(sql).await.unwrap();
        assert!(optional(&tx).await.is_err(), "{sql}");
        tx.rollback().await.unwrap();
        require_v2(&fixture.db).await.unwrap();
    }
    fixture.finish().await;
}

#[test]
fn explicit_v2_body_routes_match_all_current_independent_stock_pins() {
    use sha2::{Digest, Sha256};
    for (name, expected) in [
        (
            "conversation_reviewed_send03_parse",
            "9fc0eb8cfd60bb7296f7a34446e244573df2cbc3a519a6b0a0469e824e207b28",
        ),
        (
            "conversation_reviewed_send03_envelope",
            "5b2d548fb73912d9bcfa86e7e1b9ca760c3b649e2ecd6a236e500d9bbd2a77cc",
        ),
        (
            "conversation_reviewed_send03_scope",
            "838c3bd2760cb533b219cf19ec816a6f8e581499bf28ebc0a5683ae8eff86141",
        ),
        (
            "conversation_reviewed_send03_admit",
            "b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb",
        ),
        (
            "conversation_reviewed_send03_rows_guard",
            "6c9d1664c4e261cc2a5f5e3f6d5b7f704d9a1f598333b8f3f49a262a85dc6213",
        ),
        (
            "conversation_reviewed_send03_erasure_fence",
            "bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94",
        ),
        (
            "conversation_reviewed_send03_writer",
            "e41f43888594803a29744a49173201ce1831d3997706a9a02e3dcc14a8bc5b05",
        ),
        (
            "conversation_reviewed_send03_complete",
            "f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7",
        ),
        (
            "conversation_reviewed_send03_message_redact",
            "dca2173f22a2128120c22dd1bc96f3ae9e0519b671d9d5b569b7800137709bb1",
        ),
        (
            "payload_profile_writer_policy",
            "1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300",
        ),
        (
            "payload_profile_writer_version",
            "887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6",
        ),
        (
            "payload_profile_writer_ready",
            "10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458",
        ),
        (
            "conversation_reviewed_send03_ready",
            "9b1ea5e893b4be156e764c25d34237d0057a7fdd30b79b813ba7a65980921e79",
        ),
        (
            "conversation_reviewed_send03_v2_ready",
            "8a55e518f59d690418ec2bb6ca60b8b2c4ce51dce1759bfdc579887c5772f3ec",
        ),
    ] {
        let actual = Sha256::digest(super::body(name, 117).unwrap().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "{name}");
    }
    assert!(super::body("conversation_reviewed_send03_unknown", 117).is_err());
}
