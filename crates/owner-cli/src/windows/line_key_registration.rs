// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit offline RootLineRegister review. Never creates approval/root keys.
use super::conversation_refresh::{public_path, read_proposal, write_public};
use super::*;
use zrotext_root_material::line_key_registration::{
    self as registration, Expected, Scope, Statement,
};
const FLAGS: [&str; 21] = [
    "--account",
    "--origin",
    "--root-fingerprint",
    "--bundle",
    "--proposal",
    "--output",
    "--user",
    "--session",
    "--device",
    "--line",
    "--generation",
    "--challenge",
    "--nonce",
    "--issued",
    "--expires",
    "--approval-fingerprint",
    "--paired-signing-fingerprint",
    "--connection-epoch",
    "--deployment-epoch",
    "--site",
    "--instance",
];
struct Input {
    scope: Scope,
    fingerprint: [u8; 32],
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
    if args.len() != 43
        || args[0] != "line-key-registration"
        || args[1..].chunks_exact(2).zip(FLAGS).any(|(p, f)| p[0] != f)
    {
        return Err(());
    }
    let v = |n: usize| args[2 * n + 2].as_str();
    let fingerprint = hex(v(2).as_bytes())?;
    let bundle = hex(v(3).as_bytes())?;
    if fingerprint == [0; 32] || bundle == [0; 16] {
        return Err(());
    }
    public_path(v(4))?;
    public_path(v(5))?;
    if v(4).eq_ignore_ascii_case(v(5)) {
        return Err(());
    }
    let scope = Scope {
        account: uuid(v(0))?,
        origin: v(1).into(),
        user: uuid(v(6))?,
        owner_session: uuid(v(7))?,
        device: uuid(v(8))?,
        line: uuid(v(9))?,
        next_generation: number(v(10))?,
        challenge: uuid(v(11))?,
        nonce: hex(v(12).as_bytes())?,
        issued_ms: number(v(13))?,
        expires_ms: number(v(14))?,
        approval_fingerprint: hex(v(15).as_bytes())?,
        paired_signing_fingerprint: hex(v(16).as_bytes())?,
        connection_epoch: number(v(17))?,
        deployment_epoch: number(v(18))?,
        site_id: v(19).into(),
        instance_id: v(20).into(),
    };
    // Full typed shape is validated before secret entry by inspect, never by
    // treating fields read from the proposal as independent expected authority.
    if scope.origin.len() > 255
        || !canonical_origin(&scope.origin)
        || scope.nonce == [0; 32]
        || scope.approval_fingerprint == [0; 32]
        || scope.paired_signing_fingerprint == [0; 32]
        || scope.approval_fingerprint == scope.paired_signing_fingerprint
        || scope.expires_ms <= scope.issued_ms
        || scope.expires_ms - scope.issued_ms > 300_000
        || [&scope.site_id, &scope.instance_id].iter().any(|s| {
            !(1..=128).contains(&s.len()) || !s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
    {
        return Err(());
    }
    Ok(Input {
        scope,
        fingerprint,
        bundle,
        proposal: v(4).into(),
        output: v(5).into(),
    })
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    let input = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt("RootLineRegister: first-activation line approval-key authorization. Compare the browser session's new approval-key fingerprint, paired phone signing fingerprint, selected line and deployment independently. Offline matching does not prove current database root authority or phone consent.\r\nEnter full lowercase fingerprint from your independent ROOT kit: ").map_err(|_|())?;
    let fingerprint = session.read(64, TIMEOUT).map_err(|_| ())?;
    if hex::<32>(fingerprint.expose_ascii())? != input.fingerprint {
        return Err(());
    }
    drop(fingerprint);
    let identity = ExpectedIdentity {
        account_id: input.scope.account,
        origin: input.scope.origin.clone(),
        root_fingerprint: input.fingerprint,
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
    let statement = registration::decode(&read_proposal(&input.proposal)?).map_err(|_| ())?;
    let expected = Expected {
        identity: identity.clone(),
        scope: input.scope,
        root_pin: *card.root_pin(),
    };
    let reviewed = registration::inspect(&statement, &expected, now_millis()?).map_err(|_| ())?;
    let scope = &expected.scope;
    let mut session = Session::acquire().map_err(|_| ())?;
    for line in [
        format!(
            "Account: {}\r\nUser: {}\r\nOwner session: {}\r\n",
            uuid::Uuid::from_bytes(scope.account),
            uuid::Uuid::from_bytes(scope.user),
            uuid::Uuid::from_bytes(scope.owner_session)
        ),
        format!(
            "Origin: {}\r\nRoot fingerprint: {}\r\nRoot generation: 1\r\n",
            scope.origin,
            display_hex(&expected.identity.root_fingerprint)
        ),
        format!(
            "Phone device: {}\r\nLine: {}\r\nNext binding generation: {}\r\n",
            uuid::Uuid::from_bytes(scope.device),
            uuid::Uuid::from_bytes(scope.line),
            scope.next_generation
        ),
        format!(
            "Independently compared paired phone signing fingerprint: {}\r\nNew browser-session line approval-key fingerprint: {}\r\nApproval point SEC1: {}\r\n",
            display_hex(&scope.paired_signing_fingerprint),
            display_hex(&scope.approval_fingerprint),
            display_hex(statement.approval_point())
        ),
        format!(
            "Lease connection epoch: {}\r\nDeployment epoch: {}\r\nSite: {}\r\nInstance: {}\r\n",
            scope.connection_epoch, scope.deployment_epoch, scope.site_id, scope.instance_id
        ),
        format!(
            "Challenge: {}\r\nNonce: {}\r\nIssued/expires (epoch milliseconds): {}/{}\r\n",
            uuid::Uuid::from_bytes(scope.challenge),
            display_hex(&scope.nonce),
            scope.issued_ms,
            scope.expires_ms
        ),
    ] {
        for chunk in line.as_bytes().chunks(512) {
            session
                .write_public_prompt(std::str::from_utf8(chunk).map_err(|_| ())?)
                .map_err(|_| ())?;
        }
    }
    session.write_public_prompt("Authorize this exact first-activation scope and separate browser-session approval key once. The same registration transcript requires the new key's proof of possession before authenticated submission.\r\nType REGISTER-LINE-KEY to approve once, or DECLINE: ").map_err(|_|())?;
    let consent = session.read(17, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() == b"DECLINE" {
        drop(consent);
        let mut declined = Session::acquire().map_err(|_| ())?;
        declined
            .write_public_prompt("Declined. No root recovery or signature output occurred.\r\n")
            .map_err(|_| ())?;
        return declined.finish().map_err(|_| ());
    }
    if consent.expose_ascii() != b"REGISTER-LINE-KEY" {
        return Err(());
    }
    drop(consent);
    registration::inspect(&statement, &expected, now_millis()?).map_err(|_| ())?;
    let kit = KitContext::new(identity.clone(), card.root_pin(), input.bundle).map_err(|_| ())?;
    let token = prompt("Enter recovery token from your independent ROOT kit: ", 79)?;
    let recovery = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    // This same output session is held before recovery through sign/publication.
    let mut output_session = Session::acquire().map_err(|_| ())?;
    let root =
        root_backup::open(bundle.encrypted_backup(), &recovery, &identity).map_err(|_| ())?;
    drop(recovery);
    if pin(&root, &identity.account_id)? != *card.root_pin() {
        return Err(());
    }
    verify_process_eligibility().map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    let signature = reviewed.sign(&root, now_millis()?).map_err(|_| ())?;
    drop(root);
    publish(
        &signature,
        &statement,
        &expected,
        output_session,
        &input.output,
    )
}
fn publish(
    signature: &[u8; 64],
    statement: &Statement,
    expected: &Expected,
    mut session: Session,
    output: &str,
) -> Result<()> {
    verify_process_eligibility().map_err(|_| ())?;
    registration::inspect(statement, expected, now_millis()?).map_err(|_| ())?;
    session.write_public_prompt("").map_err(|_| ())?;
    write_public(output, signature)?;
    verify_process_eligibility().map_err(|_| ())?;
    registration::inspect(statement, expected, now_millis()?).map_err(|_| ())?;
    session
        .write_public_prompt(&format!(
            "RootLineRegister signature (raw64 lowercase hex): {}\r\n",
            display_hex(signature)
        ))
        .map_err(|_| ())?;
    session.write_public_prompt("Public RootLineRegister raw64 low-s signature written once. Preserve the exact transcript for the matching approval-key proof and authenticated submission. No durable root unlock or root bundle change occurred.\r\n").map_err(|_|())?;
    session.finish().map_err(|_| ())
}
#[cfg(test)]
mod tests;
