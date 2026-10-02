// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit archive creation with separate protected recovery-file publication.
use super::*;
use zrotext_root_material::{
    archive_backup::{ArchiveRecoverySecret, ArchiveSecret},
    archive_init,
};
mod storage;
const FLAGS: [&str; 6] = [
    "--account",
    "--origin",
    "--bundle",
    "--archive-output",
    "--receipt-output",
    "--recovery-output",
];
struct Input {
    context: PublicContext,
    bundle: [u8; 16],
    archive: String,
    receipt: String,
    recovery: String,
}
fn parse(args: &[String]) -> Result<Input> {
    if args.len() != 13
        || args[0] != "archive-init"
        || args[1..].chunks_exact(2).zip(FLAGS).any(|(p, f)| p[0] != f)
    {
        return Err(());
    }
    let account = uuid::Uuid::parse_str(&args[2]).map_err(|_| ())?;
    let bundle = hex(args[6].as_bytes())?;
    if account.is_nil()
        || account.hyphenated().to_string() != args[2]
        || !canonical_origin(&args[4])
        || args[4].len() > 512
        || bundle == [0; 16]
    {
        return Err(());
    }
    let paths = [&args[8], &args[10], &args[12]];
    for (n, path) in paths.iter().enumerate() {
        storage::validate_path(path).map_err(|_| ())?;
        if paths[..n].iter().any(|p| path.eq_ignore_ascii_case(p)) {
            return Err(());
        }
    }
    Ok(Input {
        context: PublicContext {
            account: *account.as_bytes(),
            origin: args[4].clone(),
        },
        bundle,
        archive: args[8].clone(),
        receipt: args[10].clone(),
        recovery: args[12].clone(),
    })
}
trait ArchiveMaterial {
    fn generate(&mut self) -> Result<(ArchiveSecret, ArchiveRecoverySecret)>;
}
struct SystemArchiveMaterial;
impl ArchiveMaterial for SystemArchiveMaterial {
    fn generate(&mut self) -> Result<(ArchiveSecret, ArchiveRecoverySecret)> {
        let key = SecretKey::try_generate_from_rng(&mut SysRng).map_err(|_| ())?;
        let mut scalar = Zeroizing::new([0; 32]);
        let encoded = Zeroizing::new(key.to_bytes());
        scalar.copy_from_slice(&encoded);
        drop(encoded);
        drop(key);
        let archive = ArchiveSecret::new(scalar).map_err(|_| ())?;
        let mut recovery = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(recovery.as_mut_slice())
            .map_err(|_| ())?;
        if *recovery == [0; 32] {
            return Err(());
        }
        Ok((archive, ArchiveRecoverySecret::new(recovery)))
    }
}
fn decline() -> Result<()> {
    let mut s = Session::acquire().map_err(|_| ())?;
    s.write_public_prompt("Declined. No archive material or output files were created.\r\n")
        .map_err(|_| ())?;
    s.finish().map_err(|_| ())
}
pub(super) fn run(args: &[String], parent: PathBuf) -> Result<()> {
    run_with_material(parse(args)?, parent, &mut SystemArchiveMaterial)
}
fn run_with_material(
    input: Input,
    parent: PathBuf,
    material: &mut impl ArchiveMaterial,
) -> Result<()> {
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    show_context_with_generation(
        &mut session,
        &input.context,
        "1 (root kit; registration unknown offline)",
    )?;
    session.write_public_prompt("Create one NEW unregistered account-wide archive candidate. This does not replace a registered archive or enroll authority.\r\nEnter full lowercase fingerprint from your independent root kit: ").map_err(|_|())?;
    let fingerprint = session.read(64, TIMEOUT).map_err(|_| ())?;
    let identity = ExpectedIdentity {
        account_id: input.context.account,
        origin: input.context.origin,
        root_fingerprint: hex(fingerprint.expose_ascii())?,
    };
    drop(fingerprint);
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
    let mut session = Session::acquire().map_err(|_| ())?;
    for line in [
        format!("Encrypted archive destination: {}\r\n", input.archive),
        format!("Public receipt destination: {}\r\n", input.receipt),
        format!(
            "PRIVATE raw32 archive recovery destination: {}\r\n",
            input.recovery
        ),
    ] {
        session.write_public_prompt(&line).map_err(|_| ())?;
    }
    session.write_public_prompt("All three destinations must be new. The private recovery file is separate from root recovery and grants account-wide archive decryption. Preserve it separately; do not upload it with public artifacts.\r\nType CREATE-ARCHIVE to create once, or DECLINE: ").map_err(|_|())?;
    let consent = session.read(14, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() == b"DECLINE" {
        drop(consent);
        return decline();
    }
    if consent.expose_ascii() != b"CREATE-ARCHIVE" {
        return Err(());
    }
    drop(consent);
    let consent = prompt(
        "Type SAVE-RECOVERY to confirm private raw32 recovery-file persistence at the displayed destination, or DECLINE: ",
        13,
    )?;
    if consent.expose_ascii() == b"DECLINE" {
        drop(consent);
        return decline();
    }
    if consent.expose_ascii() != b"SAVE-RECOVERY" {
        return Err(());
    }
    drop(consent);
    let kit = KitContext::new(identity.clone(), card.root_pin(), input.bundle).map_err(|_| ())?;
    let token = prompt("Enter recovery token from your independent ROOT kit: ", 79)?;
    let root_recovery = recovery_kit::decode_token(token.expose_ascii(), &kit).map_err(|_| ())?;
    drop(token);
    verify_process_eligibility().map_err(|_| ())?;
    // Hold this same eligible output session before any recovered or newly
    // generated scalar and through protected private-file publication.
    let mut output_session = Session::acquire().map_err(|_| ())?;
    let root =
        root_backup::open(bundle.encrypted_backup(), &root_recovery, &identity).map_err(|_| ())?;
    drop(root_recovery);
    if pin(&root, &identity.account_id)? != *card.root_pin() {
        return Err(());
    }
    drop(root);
    verify_process_eligibility().map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    // Exclusive, protected output handles are acquired before entropy. Any
    // existing file/unsafe ancestor/permission error refuses without generation.
    let outputs = storage::Outputs::reserve(&input.archive, &input.receipt, &input.recovery)
        .map_err(|_| ())?;
    verify_process_eligibility().map_err(|_| ())?;
    output_session.write_public_prompt("").map_err(|_| ())?;
    let (archive, recovery) = material.generate()?;
    let prepared =
        archive_init::prepare(archive, recovery, &identity, card.root_pin()).map_err(|_| ())?;
    let archive_id = prepared.identity().archive_id;
    let archive_point = prepared.identity().archive_point;
    outputs
        .publish(&prepared, &mut |_| {
            verify_process_eligibility().map_err(|_| zrotext_root_bundle::Error::UnsafeStore)?;
            output_session
                .write_public_prompt("")
                .map_err(|_| zrotext_root_bundle::Error::Storage)
        })
        .map_err(|_| ())?;
    drop(prepared);
    output_session
        .write_public_prompt(&format!(
            "Archive key ID: {}\r\nArchive point SEC1: {}\r\n",
            display_hex(&archive_id),
            display_hex(&archive_point)
        ))
        .map_err(|_| ())?;
    output_session.write_public_prompt("Archive ciphertext, independent public receipt and separate protected raw32 recovery file published once after authenticated memory and file recovery tests. Preserve and compare the receipt independently. No enrollment, archive rotation, network action or durable root unlock occurred.\r\n").map_err(|_|())?;
    output_session.finish().map_err(|_| ())
}

#[cfg(test)]
mod tests;
