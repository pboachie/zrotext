// SPDX-License-Identifier: AGPL-3.0-only
//! One explicit existing-root approval for a typed browser-signer manifest.
use super::conversation_refresh::{public_path, read_proposal, write_public};
use super::*;
use zrotext_root_material::{
    profile03_manifest::Operation03,
    profile03_manifest_proposal::{self as manifest, Expected, Scope},
};

const FLAGS: [&str; 16] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--operation",
    "--device",
    "--line",
    "--manifest-version",
    "--manifest-digest",
    "--manifest-accepted",
    "--phone-reader",
    "--browser-point",
    "--browser-key",
    "--issued",
    "--expires",
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
        || args[0] != "profile03-manifest"
        || args[1..]
            .chunks_exact(2)
            .zip(FLAGS)
            .any(|(p, flag)| p[0] != flag)
    {
        return Err(());
    }
    let value = |n: usize| args[2 * n + 2].as_str();
    if !canonical_origin(value(1)) || value(1).len() > 512 {
        return Err(());
    }
    let bundle = hex(value(2).as_bytes())?;
    if bundle == [0; 16] {
        return Err(());
    }
    public_path(value(3))?;
    public_path(value(4))?;
    if value(3).eq_ignore_ascii_case(value(4)) {
        return Err(());
    }
    let operation = match value(5) {
        "enroll" => Operation03::Enroll,
        "renew" => Operation03::Renew,
        "replace" => Operation03::Replace,
        _ => return Err(()),
    };
    let scope = Scope {
        operation,
        account: uuid(value(0))?,
        origin: value(1).into(),
        fingerprint: [0; 32],
        device: uuid(value(6))?,
        line: uuid(value(7))?,
        predecessor_version: number(value(8))?,
        predecessor_digest: hex(value(9).as_bytes())?,
        predecessor_accepted_ms: number(value(10))?,
        phone_reader: hex(value(11).as_bytes())?,
        browser_point: hex(value(12).as_bytes())?,
        browser_key: hex(value(13).as_bytes())?,
        issued_ms: number(value(14))?,
        expires_ms: number(value(15))?,
    };
    if [
        scope.predecessor_digest,
        scope.phone_reader,
        scope.browser_key,
    ]
    .contains(&[0; 32])
    {
        return Err(());
    }
    Ok(Input {
        scope,
        bundle,
        proposal: value(3).into(),
        output: value(4).into(),
    })
}
fn public(session: &mut Session, text: &str) -> Result<()> {
    // Every formatted field below is canonical ASCII public metadata.
    for chunk in text.as_bytes().chunks(512) {
        session
            .write_public_prompt(std::str::from_utf8(chunk).map_err(|_| ())?)
            .map_err(|_| ())?;
    }
    Ok(())
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    let mut input = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt("Offline browser message-key manifest approval. Independently select the account, accepted checkpoint and browser public key; do not copy expected values from the proposal.\r\nEnter full lowercase root fingerprint from your independent kit: ").map_err(|_| ())?;
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
    let expected = Expected {
        identity: identity.clone(),
        root_pin: *card.root_pin(),
        scope: input.scope,
    };
    let proposal = manifest::decode(&read_proposal(&input.proposal)?).map_err(|_| ())?;
    let reviewed = manifest::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    let scope = reviewed.scope();
    public(
        &mut session,
        &format!(
            "Operation: {}\r\nAccount: {}\r\nOrigin: {}\r\nRoot: {}\r\nDevice: {}\r\nLine: {}\r\n",
            scope.operation.as_str(),
            uuid::Uuid::from_bytes(scope.account),
            scope.origin,
            display_hex(&scope.fingerprint),
            uuid::Uuid::from_bytes(scope.device),
            uuid::Uuid::from_bytes(scope.line)
        ),
    )?;
    public(
        &mut session,
        &format!(
            "Original version: {}\r\nOriginal digest: {}\r\nOriginal accepted milliseconds: {}\r\nPhone reader: {}\r\nBrowser point: {}\r\nBrowser key ID: {}\r\nIssued milliseconds: {}\r\nNew manifest expiry: {}\r\n",
            scope.predecessor_version,
            display_hex(&scope.predecessor_digest),
            scope.predecessor_accepted_ms,
            display_hex(&scope.phone_reader),
            display_hex(&scope.browser_point),
            display_hex(&scope.browser_key),
            scope.issued_ms,
            scope.expires_ms
        ),
    )?;
    let old = &proposal.predecessor()[153..proposal.predecessor().len() - 64];
    let next = &proposal.unsigned()[153..];
    for row in old.chunks_exact(149) {
        let after = next
            .chunks_exact(149)
            .find(|candidate| candidate[..33] == row[..33])
            .ok_or(())?;
        if row != after {
            public(
                &mut session,
                &format!(
                    "Retained role{} key {}: until {} -> {}, state {} -> {}\r\n",
                    row[0],
                    display_hex(&row[1..33]),
                    u64::from_be_bytes(row[140..148].try_into().map_err(|_| ())?),
                    u64::from_be_bytes(after[140..148].try_into().map_err(|_| ())?),
                    row[148],
                    after[148]
                ),
            )?;
        }
    }
    public(
        &mut session,
        "Approval signs only this public manifest. Existing messages and intervals retain their original keys. Server installation, phone consent and sending require separate checks.\r\nType APPROVE-MANIFEST03 to approve once, or DECLINE: ",
    )?;
    let approval = session.read(24, TIMEOUT).map_err(|_| ())?;
    if approval.expose_ascii() != b"APPROVE-MANIFEST03" {
        return Err(());
    }
    drop(approval);
    reviewed.recheck(now_millis()?).map_err(|_| ())?;
    let kit = KitContext::new(identity.clone(), card.root_pin(), input.bundle).map_err(|_| ())?;
    session
        .write_public_prompt("Enter recovery token from your independent kit: ")
        .map_err(|_| ())?;
    let token = session.read(79, TIMEOUT).map_err(|_| ())?;
    let recovery = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    session.write_public_prompt("").map_err(|_| ())?;
    let root =
        root_backup::open(bundle.encrypted_backup(), &recovery, &identity).map_err(|_| ())?;
    drop(recovery);
    if pin(&root, &identity.account_id)? != *card.root_pin() {
        return Err(());
    }
    verify_process_eligibility().map_err(|_| ())?;
    session.write_public_prompt("").map_err(|_| ())?;
    let signed = manifest::sign(&root, reviewed, now_millis()?).map_err(|_| ())?;
    drop(root);
    verify_process_eligibility().map_err(|_| ())?;
    manifest::verify_signed(&proposal, &expected, &signed, now_millis()?).map_err(|_| ())?;
    session.write_public_prompt("").map_err(|_| ())?;
    write_public(&input.output, &signed)?;
    session.write_public_prompt("Public manifest written once. Verify the exact proposal before the separate authenticated install. No network operation or persistent unlock was created.\r\n").map_err(|_| ())?;
    session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests;
