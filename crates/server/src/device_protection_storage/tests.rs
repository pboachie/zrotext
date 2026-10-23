// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use sha2::{Digest, Sha256};

#[test]
fn every_required_declaration_uses_its_exact_installed_source() {
    let expected = [
        (
            "device_protection_mode",
            "322e00db3f06b5ad074549a0b0aee195fda333b3c4c9da56f00c524dc4bd02df",
        ),
        (
            "device_protection_actor",
            "85fe0c825d913bdc0fb60000b15525ce11197819ffead08c078c54252a3b105e",
        ),
        (
            "device_protection_lock",
            "c59c519eb41802618d17113eab6931d87841a52169ea43f211ffacc4ce9c44ec",
        ),
        (
            "device_protection_open",
            "a5b63607715566f6f148d16e182fa797f5693d436eb8950656d1d99ea53704bb",
        ),
        (
            "device_protection_association",
            "0b0233983d2cbc58f5f62f38faf412cd92e6ef6a7820070565650341a3463831",
        ),
        (
            "device_protection_attempt",
            "91131f0e39be397b35c7af8843bda1d0f6ff054a0e90a30b4a0112e992b3d8ce",
        ),
        (
            "device_protection_accept",
            "8ae393057e08e73fcd7600e6b09ce142b9ffc58a4443c82560348a2ece40ab63",
        ),
        (
            "device_protection_rows_guard",
            "2fcf0019dbe0cc6f59e45e733e22e8fe87f1c02babaa8c25d05cd9ba1d95d3f1",
        ),
        (
            "device_protection_complete",
            "a06f702ad69d2a899c4d64da0e77cb356043a34797ab5c4b49c7a18dad25a669",
        ),
        (
            "device_protection_retire",
            "13ea73a39d4ba51291028b8151cddf174bb34e4a99ccaa26a6e9ad6180454c85",
        ),
        (
            "payload_profile_writer_policy",
            "3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb",
        ),
        (
            "payload_profile_writer_version",
            "bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce",
        ),
        (
            "payload_profile_writer_ready",
            "891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6",
        ),
        (
            "hosted_runtime_native_schema_valid",
            "89be2b62b7ce164cccef13d37b25921e873172cd5323a978429dcc7aba7b99c0",
        ),
        (
            "hosted_runtime_identity_ready",
            "044f6e1b7b29d7be2932926b81156271862f07e92d2ed5ab2c7173da8fc2491b",
        ),
        (
            "hosted_runtime_scope",
            "bc3de24b275c1789c231e5969f2dbe68947d3bae6145c74a7d0982b51ebab9f7",
        ),
        (
            "conversation_reviewed_send03_v2_ready",
            "b464415eb86a8498a8a2da6becc624d8a6cb42051c6161c42e3ab3e3aa24e379",
        ),
        (
            "device_protection_ready",
            "c9ae9ef981e3d93c19e47237345a93c0f4fcadf4df94b24dd53295dcae3c67fa",
        ),
    ];
    assert_eq!(expected.len(), FUNCTIONS.len());
    for ((name, expected), required) in expected.into_iter().zip(FUNCTIONS) {
        assert_eq!(name, required.name);
        let actual = Sha256::digest(body(name).unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, expected, "{name}");
    }
    assert!(body("device_protection_unknown").is_err());
}
#[path = "database_tests.rs"]
mod database_tests;

#[test]
fn stock_provisioner_revokes_origin_writes_before_its_only_commit() {
    let stock = include_str!("../../../../deploy/compose/runtime-role.sql");
    let begin = stock.find("\nBEGIN;").unwrap();
    let origin = stock
        .find("-- First-origin ledgers are readable history")
        .unwrap();
    let commit = stock.find("\nCOMMIT;").unwrap();
    assert!(begin < origin && origin < commit);
    assert_eq!(stock.matches("\nCOMMIT;").count(), 1);
    assert!(stock.trim_end().ends_with("COMMIT;"));
    for name in [
        "device_protection_origins",
        "device_protection_associations",
        "device_protection_attempts",
        "device_protection_receipts",
        "device_protection_retirements",
    ] {
        assert!(stock[origin..commit].contains(name));
    }
    assert!(stock[origin..commit].contains("REVOKE ALL ON TABLE"));
    assert!(stock[origin..commit].contains("GRANT SELECT ON TABLE"));
}
