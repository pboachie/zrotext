// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit offline owner-authorized encrypted custody publication signing.
use super::*;

pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    if args.first().map(String::as_str) != Some("custody-sign") {
        return Err(());
    }
    let mut translated = args.to_vec();
    translated[0] = "unlock".into();
    let Command::Unlock(context, id, path) = parse(&translated)? else {
        return Err(());
    };
    run_custody(context, id, path, parent)
}

fn run_custody(
    context: PublicContext,
    id: [u8; 16],
    challenge_path: String,
    parent: PathBuf,
) -> Result<()> {
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    show_context_with_generation(
        &mut session,
        &context,
        "unknown offline (the hub records the active generation)",
    )?;
    session
        .write_public_prompt("Enter full lowercase fingerprint from your independent kit: ")
        .map_err(|_| ())?;
    let fingerprint = session.read(64, TIMEOUT).map_err(|_| ())?;
    let expected = ExpectedIdentity {
        account_id: context.account,
        origin: context.origin,
        root_fingerprint: hex(fingerprint.expose_ascii())?,
    };
    drop(fingerprint);
    let store = Store::open_existing(&parent).map_err(|_| ())?;
    let bundle = store.read_bundle(&id, &expected).map_err(|_| ())?;
    let card = recovery_kit::decode_public_card(
        bundle.public_card(),
        &expected,
        &Sha256::digest(bundle.encrypted_backup()).into(),
    )
    .map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session
        .write_public_prompt(&format!(
            "Bundle: {}\r\nEncrypted backup SHA256: {}\r\nPublic card SHA256: {}\r\n",
            display_hex(&id),
            display_hex(&Sha256::digest(bundle.encrypted_backup())),
            display_hex(&Sha256::digest(bundle.public_card()))
        ))
        .map_err(|_| ())?;
    session.finish().map_err(|_| ())?;
    // Bind the public challenge to the independent identity BEFORE any secret
    // input, so a challenge for any other account, origin or root is refused
    // before the recovery token is requested.
    let unsigned = read_challenge(&challenge_path)?;
    let reviewed = zrotext_root_material::root_unlock::custody::ReviewedCustody::inspect(
        &unsigned,
        bundle.encrypted_backup(),
        bundle.public_card(),
        &expected,
        &id,
        now_millis()?,
    )
    .map_err(|_| ())?;
    let challenge = reviewed.challenge(now_millis()?).map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    session
        .write_public_prompt(&format!(
            "Challenge: {}\r\nExpires at (epoch milliseconds): {}\r\n",
            uuid::Uuid::from_bytes(challenge.challenge_id),
            challenge.expires_ms
        ))
        .map_err(|_| ())?;
    drop(session);
    let consent = prompt(
        "Type CUSTODY to authorize publication of this exact encrypted bundle and sign this challenge, or DECLINE: ",
        7,
    )?;
    if consent.expose_ascii() == b"DECLINE" {
        drop(consent);
        let mut decline = Session::acquire().map_err(|_| ())?;
        decline
            .write_public_prompt(
                "Declined. Nothing was signed and no enrollment, unlock state or file was created.\r\n",
            )
            .map_err(|_| ())?;
        return decline.finish().map_err(|_| ());
    }
    if consent.expose_ascii() != b"CUSTODY" {
        return Err(());
    }
    drop(consent);
    let kit = KitContext::new(expected.clone(), card.root_pin(), id).map_err(|_| ())?;
    let token = prompt("Enter recovery token from your independent kit: ", 79)?;
    let secret = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    let root = root_backup::open(bundle.encrypted_backup(), &secret, &expected).map_err(|_| ())?;
    drop(secret);
    if pin(&root, &expected.account_id)? != *card.root_pin() {
        return Err(());
    }
    // Fresh signing time: expiry is rechecked after interactive token entry.
    let signatures = reviewed.sign(&root, now_millis()?).map_err(|_| ())?;
    drop(root);
    let mut session = Session::acquire().map_err(|_| ())?;
    session
        .write_public_prompt(&format!(
            "Enrollment signature: {}\r\nCustody signature: {}\r\n",
            display_hex(&signatures.enrollment),
            display_hex(&signatures.custody)
        ))
        .map_err(|_| ())?;
    session
        .write_public_prompt(
            "Enrollment and exact encrypted custody publication signed. Submit only with the reviewed challenge and local bundle. No enrollment, unlock state or file was created.\r\n",
        )
        .map_err(|_| ())?;
    session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests;
