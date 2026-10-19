// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit recovered-root approval of one exact first03 preserved-record proposal.
use super::conversation_refresh::{public_path, read_proposal, write_public};
use super::*;
use zrotext_root_material::payload_profile_upgrade::{self as upgrade, Expected, Scope};

const FLAGS: [&str; 12] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--device",
    "--line",
    "--manifest-version",
    "--manifest-digest",
    "--phone-reader",
    "--phone-signer",
    "--issued",
];
struct Input {
    scope: Scope,
    bundle: [u8; 16],
    proposal: String,
    output: String,
}
fn uuid(value: &str) -> Result<[u8; 16]> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| ())?;
    if id.is_nil() || id.hyphenated().to_string() != value {
        return Err(());
    }
    Ok(*id.as_bytes())
}
fn number(value: &str) -> Result<u64> {
    let n = value.parse::<u64>().map_err(|_| ())?;
    if n == 0 || n > i64::MAX as u64 || n.to_string() != value {
        return Err(());
    }
    Ok(n)
}
fn parse(args: &[String]) -> Result<Input> {
    if args.len() != 25
        || args[0] != "payload-profile-upgrade"
        || args[1..]
            .chunks_exact(2)
            .zip(FLAGS)
            .any(|(p, flag)| p[0] != flag)
    {
        return Err(());
    }
    let v = |n: usize| args[n * 2 + 2].as_str();
    if !canonical_origin(v(1)) || v(1).len() > 512 {
        return Err(());
    }
    let bundle = hex(v(2).as_bytes())?;
    if bundle == [0; 16] {
        return Err(());
    }
    public_path(v(3))?;
    public_path(v(4))?;
    if v(3).eq_ignore_ascii_case(v(4)) {
        return Err(());
    }
    let scope = Scope {
        account: uuid(v(0))?,
        device: uuid(v(5))?,
        line: uuid(v(6))?,
        origin: v(1).into(),
        fingerprint: [0; 32],
        predecessor_version: number(v(7))?,
        predecessor_digest: hex(v(8).as_bytes())?,
        phone_reader: hex(v(9).as_bytes())?,
        phone_signer: hex(v(10).as_bytes())?,
        issued_ms: number(v(11))?,
    };
    if [
        scope.predecessor_digest,
        scope.phone_reader,
        scope.phone_signer,
    ]
    .contains(&[0; 32])
    {
        return Err(());
    }
    Ok(Input {
        scope,
        bundle,
        proposal: v(3).into(),
        output: v(4).into(),
    })
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    let mut input = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt("Offline first same-root02-to03 payload profile upgrade. Use independently accepted scope and manifest high-water; a downloaded packet cannot supply the expected values.\r\nEnter full lowercase root fingerprint from your independent kit: ").map_err(|_| ())?;
    let fingerprint = session.read(64, TIMEOUT).map_err(|_| ())?;
    input.scope.fingerprint = hex(fingerprint.expose_ascii())?;
    drop(fingerprint);
    let identity = ExpectedIdentity {
        account_id: input.scope.account,
        origin: input.scope.origin.clone(),
        root_fingerprint: input.scope.fingerprint,
    };
    let store = Store::open_existing(&parent).map_err(|_| ())?;
    let bundle = store
        .read_bundle(&input.bundle, &identity)
        .map_err(|_| ())?;
    let card = recovery_kit::decode_public_card(
        bundle.public_card(),
        &identity,
        &Sha256::digest(bundle.encrypted_backup()).into(),
    )
    .map_err(|_| ())?;
    let proposal = upgrade::decode(&read_proposal(&input.proposal)?).map_err(|_| ())?;
    let expected = Expected {
        identity: identity.clone(),
        scope: input.scope,
    };
    let reviewed = upgrade::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    for line in [
        format!(
            "Account: {}\r\nOrigin: {}\r\nRoot fingerprint: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.account),
            reviewed.origin,
            display_hex(&reviewed.fingerprint)
        ),
        format!(
            "Device: {}\r\nLine: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.device),
            uuid::Uuid::from_bytes(reviewed.line)
        ),
        format!(
            "Original02 version: {}\r\nOriginal02 digest: {}\r\n",
            reviewed.predecessor_version,
            display_hex(&reviewed.predecessor_digest)
        ),
        format!(
            "Existing phone reader: {}\r\nExisting phone signer: {}\r\nIssued milliseconds: {}\r\n",
            display_hex(&reviewed.phone_reader),
            display_hex(&reviewed.phone_signer),
            reviewed.issued_ms
        ),
    ] {
        for chunk in line.as_bytes().chunks(512) {
            session
                .write_public_prompt(std::str::from_utf8(chunk).map_err(|_| ())?)
                .map_err(|_| ())?;
        }
    }
    session.write_public_prompt("Only the first same-root profile03 successor is signed. Every existing key, archive reader and expiry stays exact. This does not approve an election, owner session, SIM, message or SMS send.\r\nType APPROVE-PROFILE03 to approve once, or DECLINE: ").map_err(|_| ())?;
    let consent = session.read(24, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() != b"APPROVE-PROFILE03" {
        return Err(());
    }
    drop(consent);
    let kit = KitContext::new(identity.clone(), card.root_pin(), input.bundle).map_err(|_| ())?;
    let token = prompt("Enter recovery token from your independent kit: ", 79)?;
    let recovery = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    let mut output_session = Session::acquire().map_err(|_| ())?;
    let root =
        root_backup::open(bundle.encrypted_backup(), &recovery, &identity).map_err(|_| ())?;
    drop(recovery);
    if pin(&root, &identity.account_id)? != *card.root_pin() {
        return Err(());
    }
    output_session.write_public_prompt("").map_err(|_| ())?;
    let signed = upgrade::sign(&root, &proposal, &expected, now_millis()?).map_err(|_| ())?;
    drop(root);
    verify_process_eligibility().map_err(|_| ())?;
    upgrade::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    write_public(&input.output, &signed)?;
    output_session.write_public_prompt("Public first03 manifest written once. Verify its exact proposal and complete the separate authenticated owner/phone election. No network operation, permission or persistent unlock was created.\r\n").map_err(|_| ())?;
    output_session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_path(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("profile-upgrade-parser")
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }
    fn args() -> Vec<String> {
        let values = [
            "11111111-1111-4111-8111-111111111111".into(),
            "https://owner.invalid".into(),
            "11".repeat(16),
            fixture_path("upgrade.bin"),
            fixture_path("signed.bin"),
            "22222222-2222-4222-8222-222222222222".into(),
            "33333333-3333-4333-8333-333333333333".into(),
            "1".into(),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "2000".into(),
        ];
        let mut args = vec!["payload-profile-upgrade".into()];
        for (flag, value) in FLAGS.into_iter().zip(values) {
            args.push(flag.into());
            args.push(value.into());
        }
        args
    }
    #[test]
    fn exact_public_context_is_captured_and_ambiguous_flags_refuse() {
        let mut a = args();
        let selected = parse(&a).unwrap();
        a[16] = "9".into();
        assert_eq!(selected.scope.predecessor_version, 1);
        let a = args();
        for index in 0..a.len() {
            let mut changed = a.clone();
            changed.remove(index);
            assert!(parse(&changed).is_err());
        }
        for (index, value) in [
            (4, "https://owner.invalid/path"),
            (16, "01"),
            (24, "9223372036854775808"),
            (1, "--unknown"),
        ] {
            let mut changed = a.clone();
            changed[index] = value.into();
            assert!(parse(&changed).is_err());
        }
        let mut same_path = a.clone();
        same_path[10] = same_path[8].clone();
        assert!(parse(&same_path).is_err());
    }
}
