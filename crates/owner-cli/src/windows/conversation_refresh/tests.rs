// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
fn fixture_path(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-refresh-parse")
        .join(name)
        .to_str()
        .unwrap()
        .into()
}
pub(crate) fn args() -> Vec<String> {
    let point = format!("04{}", "00".repeat(64));
    let values = [
        "11111111-1111-4111-8111-111111111111",
        "https://owner.invalid",
        "11111111111111111111111111111111",
        "proposal.bin",
        "signed.bin",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
        "55555555-5555-4555-8555-555555555555",
        "1",
        "+12",
        "7",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
        point.as_str(),
        "1000000",
    ];
    let mut a = vec!["conversation-refresh".into()];
    for (flag, value) in FLAGS.into_iter().zip(values) {
        a.extend([flag.into(), value.into()]);
    }
    a[8] = fixture_path("proposal.bin");
    a[10] = fixture_path("signed.bin");
    a
}
#[test]
fn independent_expected_flags_are_required_and_held() {
    let mut a = args();
    let input = parse(&a).unwrap();
    a[22] = "+13".into();
    assert_eq!(input.scope.peer, "+12");
    assert_eq!(input.scope.predecessor_version, 7);
    assert_eq!(input.scope.predecessor_digest, [17; 32]);
    assert_eq!(
        input.scope.session,
        [
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x42, 0x22, 0x82, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22
        ]
    );
}
#[test]
fn missing_unknown_duplicate_and_reordered_flags_are_refused() {
    let a = args();
    for n in 0..a.len() {
        let mut broken = a.clone();
        broken.remove(n);
        assert!(parse(&broken).is_err());
    }
    let mut broken = a.clone();
    broken[1] = "--unknown".into();
    assert!(parse(&broken).is_err());
    let mut broken = a;
    broken.swap(1, 3);
    assert!(parse(&broken).is_err());
}
#[test]
fn ambiguous_numbers_uuid_origin_and_identical_paths_are_refused() {
    for (index, value) in [
        (20, "01"),
        (20, "0"),
        (20, "9223372036854775808"),
        (2, "00000000-0000-0000-0000-000000000000"),
        (4, "https://owner.invalid/path"),
    ] {
        let mut a = args();
        a[index] = value.into();
        assert!(parse(&a).is_err(), "index {index}");
    }
    let mut a = args();
    a[10] = a[8].clone();
    assert!(parse(&a).is_err());
}
#[test]
fn unsafe_public_paths_are_refused_before_io() {
    // Derive all grammar variants from the controlled fixture root; no machine
    // or network location is hardcoded or accessed by these pre-I/O refusals.
    let sample = fixture_path("proposal.bin");
    let base = PathBuf::from(&sample);
    let parent = base.parent().unwrap().display().to_string();
    let separator = std::path::MAIN_SEPARATOR.to_string();
    let drive_relative = format!("{}{}", &sample[..2], &sample[3..]);
    let unc_variant = format!("{}{}{}", separator, separator, &sample[3..]);
    for path in [
        "relative.bin".to_string(),
        drive_relative,
        unc_variant,
        format!("{parent}{separator}..{separator}proposal.bin"),
        format!("{parent}{separator}NUL.bin"),
        format!("{sample}:stream"),
        format!("{sample}."),
        format!("{parent}{separator}"),
    ] {
        assert!(public_path(&path).is_err());
    }
    assert!(public_path(&sample).is_ok());
}
fn root() -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-refresh")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
#[test]
fn public_output_is_create_once_and_never_overwrites() {
    let root = root();
    let path = root.join("signed.bin");
    write_public(path.to_str().unwrap(), b"synthetic-public-manifest").unwrap();
    assert!(write_public(path.to_str().unwrap(), b"other").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-public-manifest");
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn public_input_size_is_bounded_and_not_rewritten() {
    let root = root();
    let path = root.join("proposal.bin");
    std::fs::write(&path, vec![1; refresh::MAX_PROPOSAL]).unwrap();
    assert_eq!(
        read_proposal(path.to_str().unwrap()).unwrap().len(),
        refresh::MAX_PROPOSAL
    );
    std::fs::write(&path, vec![2; refresh::MAX_PROPOSAL + 1]).unwrap();
    assert!(read_proposal(path.to_str().unwrap()).is_err());
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        (refresh::MAX_PROPOSAL + 1) as u64
    );
    std::fs::remove_dir_all(root).unwrap();
}
