// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn args() -> Vec<String> {
    let path = |name: &str| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("manifest-parser")
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    };
    let values = [
        "11111111-1111-4111-8111-111111111111".into(),
        "https://owner.invalid".into(),
        "11".repeat(16),
        path("proposal.bin"),
        path("signed.bin"),
        "enroll".into(),
        "22222222-2222-4222-8222-222222222222".into(),
        "33333333-3333-4333-8333-333333333333".into(),
        "2".into(),
        "22".repeat(32),
        "1000".into(),
        "33".repeat(32),
        "04".to_owned() + &"44".repeat(64),
        "55".repeat(32),
        "2000".into(),
        "3000".into(),
    ];
    let mut args = vec!["profile03-manifest".into()];
    for (flag, value) in FLAGS.into_iter().zip(values) {
        args.push(flag.into());
        args.push(value);
    }
    args
}
#[test]
fn independent_flags_are_closed_and_ordered_with_no_ambiguous_output_or_operation() {
    let original = args();
    assert_eq!(parse(&original).unwrap().scope.predecessor_version, 2);
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed.remove(index);
        assert!(parse(&changed).is_err());
    }
    for (index, value) in [
        (4, "https://owner.invalid/path"),
        (12, "any"),
        (18, "02"),
        (22, "9223372036854775808"),
        (1, "--unknown"),
        (16, "00000000-0000-0000-0000-000000000000"),
    ] {
        let mut changed = original.clone();
        changed[index] = value.into();
        assert!(parse(&changed).is_err());
    }
    let mut same = original;
    same[10] = same[8].clone();
    assert!(parse(&same).is_err());
}
