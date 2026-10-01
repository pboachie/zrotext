// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit one-shot console review of a typed preserved-record activation. No key creation.
use super::conversation_refresh::{public_path, read_proposal, write_public};
use super::*;
use zrotext_root_material::conversation_activation::{self as refresh, Expected, Scope};

const FLAGS: [&str; 16] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--session",
    "--device",
    "--line",
    "--generation",
    "--peer",
    "--manifest-version",
    "--manifest-digest",
    "--phone-reader",
    "--archive-reader",
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
    if args.len() != 33
        || args[0] != "conversation-activation"
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
    let scope = Scope {
        account: uuid(v(0))?,
        origin: v(1).into(),
        fingerprint: [0; 32],
        session: uuid(v(5))?,
        device: uuid(v(6))?,
        line: uuid(v(7))?,
        line_generation: number(v(8))?,
        peer: v(9).into(),
        predecessor_version: number(v(10))?,
        predecessor_digest: hex(v(11).as_bytes())?,
        phone_reader: hex(v(12).as_bytes())?,
        archive_reader: hex(v(13).as_bytes())?,
        phone_signer: hex(v(14).as_bytes())?,
        issued_ms: number(v(15))?,
    };
    // Validate paths before any secret input. Proposal bytes are never expected authority.
    public_path(v(3))?;
    public_path(v(4))?;
    if v(3).eq_ignore_ascii_case(v(4)) {
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
    session.write_public_prompt("Offline generation-one conversation preserved-record activation. Independently supplied scope and high-water are required; a downloaded proposal is not expected authority.\r\n").map_err(|_|())?;
    session
        .write_public_prompt("Enter full lowercase fingerprint from your independent kit: ")
        .map_err(|_| ())?;
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
    let proposal = refresh::decode(&read_proposal(&input.proposal)?).map_err(|_| ())?;
    let expected = Expected {
        identity: identity.clone(),
        scope: input.scope,
    };
    let reviewed = refresh::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    for line in [
        format!(
            "Root fingerprint: {}\r\nRoot generation: 1\r\n",
            display_hex(&reviewed.fingerprint)
        ),
        format!(
            "Account: {}\r\nOrigin: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.account),
            reviewed.origin
        ),
        format!(
            "Owner session: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.session)
        ),
        format!(
            "Device: {}\r\nLine: {}\r\nLine generation: {}\r\nPeer: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.device),
            uuid::Uuid::from_bytes(reviewed.line),
            reviewed.line_generation,
            reviewed.peer
        ),
        format!(
            "Predecessor version: {}\r\nPredecessor digest: {}\r\n",
            reviewed.predecessor_version,
            display_hex(&reviewed.predecessor_digest)
        ),
        format!(
            "Phone reader: {}\r\nExisting archive reader: {}\r\n",
            display_hex(&reviewed.phone_reader),
            display_hex(&reviewed.archive_reader)
        ),
        format!(
            "Existing phone signer: {}\r\nSuccessor issued at (epoch milliseconds): {}\r\n",
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
    session.write_public_prompt("Every existing manifest record, including the account archive reader, stays exact. Only manifest version, issued time and predecessor digest change; all records and expiry stay exact. The manifest signature does not encode peer/session; authenticated installation must enforce them.\r\nType APPROVE-ACTIVATION to approve once, or DECLINE: ").map_err(|_|())?;
    let consent = session.read(18, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() != b"APPROVE-ACTIVATION" {
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
    let signed = refresh::sign(&root, &proposal, &expected, now_millis()?).map_err(|_| ())?;
    drop(root);
    // A partial public output on I/O failure is not silently retried or overwritten.
    verify_process_eligibility().map_err(|_| ())?;
    refresh::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    write_public(&input.output, &signed)?;
    output_session.write_public_prompt("Public signed successor written once. No enrollment, network action, persistent unlock or archive change occurred. Independently verify and submit through authenticated activation/session CAS; separate phone confirmation remains required.\r\n").map_err(|_|())?;
    output_session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        let mut a = super::super::conversation_refresh::tests::args();
        a.drain(33..35);
        a.drain(13..15);
        a[0] = "conversation-activation".into();
        a[29] = "--phone-signer".into();
        a[31] = "--issued".into();
        a[32] = "2000".into();
        a
    }
    #[test]
    fn independent_activation_context_is_captured() {
        let mut a = args();
        let input = parse(&a).unwrap();
        a[20] = "+13".into();
        assert_eq!(input.scope.peer, "+12");
        assert_eq!(input.scope.issued_ms, 2000);
        assert_eq!(input.scope.predecessor_version, 7);
    }
    #[test]
    fn missing_extra_reordered_and_ambiguous_activation_flags_refused() {
        let a = args();
        for n in 0..a.len() {
            let mut bad = a.clone();
            bad.remove(n);
            assert!(parse(&bad).is_err());
        }
        for (index, value) in [
            (18, "01"),
            (22, "0"),
            (32, "9223372036854775808"),
            (4, "https://owner.invalid/path"),
            (1, "--unknown"),
        ] {
            let mut bad = a.clone();
            bad[index] = value.into();
            assert!(parse(&bad).is_err());
        }
        let mut bad = a;
        bad.swap(1, 3);
        assert!(parse(&bad).is_err());
    }
}

#[cfg(test)]
mod native_tests;
