// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit one-shot console review of a typed first manifest. No key creation.
use super::conversation_refresh::{public_path, read_proposal, write_public};
use super::*;
use zrotext_root_material::conversation_genesis::{self as genesis, Expected, Scope};

const FLAGS: [&str; 16] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--session",
    "--device",
    "--line",
    "--device-signing-fingerprint",
    "--generation",
    "--peer",
    "--phone-reader-point",
    "--archive-reader-point",
    "--phone-signer-point",
    "--issued",
    "--expires",
];
struct Input {
    scope: Scope,
    bundle: [u8; 16],
    proposal: String,
    output: String,
    phone_reader: [u8; 65],
    archive_reader: [u8; 65],
    phone_signer: [u8; 65],
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
        || args[0] != "conversation-genesis"
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
        device_signing_fingerprint: hex(v(8).as_bytes())?,
        generation: number(v(9))?,
        peer: v(10).into(),
        issued_ms: number(v(14))?,
        expires_ms: number(v(15))?,
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
        phone_reader: hex(v(11).as_bytes())?,
        archive_reader: hex(v(12).as_bytes())?,
        phone_signer: hex(v(13).as_bytes())?,
    })
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    let mut input = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt("Offline first conversation manifest. Phone reader/signer and existing archive points must be independently compared. Downloaded proposal points and matching API identifiers cannot establish provenance. If independent point comparison is unavailable, decline.\r\n").map_err(|_|())?;
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
    let proposal = genesis::decode(&read_proposal(&input.proposal)?).map_err(|_| ())?;
    let expected = Expected {
        identity: identity.clone(),
        scope: input.scope,
        root_pin: *card.root_pin(),
        phone_reader: input.phone_reader,
        archive_reader: input.archive_reader,
        phone_signer: input.phone_signer,
    };
    let reviewed = genesis::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    let scope = &expected.scope;
    let mut session = Session::acquire().map_err(|_| ())?;
    for line in [
        format!(
            "Root fingerprint: {}\r\nRoot generation: 1\r\n",
            display_hex(&scope.fingerprint)
        ),
        format!(
            "Account: {}\r\nOrigin: {}\r\n",
            uuid::Uuid::from_bytes(scope.account),
            scope.origin
        ),
        format!(
            "Owner session: {}\r\n",
            uuid::Uuid::from_bytes(scope.session)
        ),
        format!(
            "Device: {}\r\nLine: {}\r\nLine generation: {}\r\nPeer: {}\r\n",
            uuid::Uuid::from_bytes(scope.device),
            uuid::Uuid::from_bytes(scope.line),
            scope.generation,
            scope.peer
        ),
        format!(
            "Paired phone signing fingerprint: {}\r\nBundle: {}\r\n",
            display_hex(&scope.device_signing_fingerprint),
            display_hex(&input.bundle)
        ),
        format!(
            "Independently compared phone reader point: {}\r\n",
            display_hex(&expected.phone_reader)
        ),
        format!(
            "Independently compared existing archive point: {}\r\n",
            display_hex(&expected.archive_reader)
        ),
        format!(
            "Independently compared phone signer point: {}\r\n",
            display_hex(&expected.phone_signer)
        ),
        format!(
            "Issued/expires (epoch milliseconds): {}/{}\r\n",
            scope.issued_ms, scope.expires_ms
        ),
    ] {
        for chunk in line.as_bytes().chunks(512) {
            session
                .write_public_prompt(std::str::from_utf8(chunk).map_err(|_| ())?)
                .map_err(|_| ())?;
        }
    }
    session.write_public_prompt("Only the exact first generation-one/version-one manifest with phone reader, existing archive reader, phone signer and root revoker will be signed. Session, peer and paired phone signing fingerprint are contextual review; the manifest signature does not encode them. Separate authenticated installation and phone approval remain required.\r\nType APPROVE-GENESIS to approve once, or DECLINE: ").map_err(|_|())?;
    let consent = session.read(15, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() == b"DECLINE" {
        drop(consent);
        let mut declined = Session::acquire().map_err(|_| ())?;
        declined
            .write_public_prompt("Declined. No root recovery or public output occurred.\r\n")
            .map_err(|_| ())?;
        return declined.finish().map_err(|_| ());
    }
    if consent.expose_ascii() != b"APPROVE-GENESIS" {
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
    let signed = reviewed.sign(&root, now_millis()?).map_err(|_| ())?;
    drop(root);
    // A partial public output on I/O failure is not silently retried or overwritten.
    verify_process_eligibility().map_err(|_| ())?;
    genesis::inspect(&proposal, &expected, now_millis()?).map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    write_public(&input.output, &signed)?;
    output_session.write_public_prompt("Public signed first manifest written once. No enrollment, network action, persistent unlock or archive change occurred. Independently verify and submit through authenticated installation; separate phone confirmation remains required.\r\n").map_err(|_|())?;
    output_session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests;
