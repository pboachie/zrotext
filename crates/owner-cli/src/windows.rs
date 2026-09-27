// SPDX-License-Identifier: AGPL-3.0-only
use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;
use zrotext_root_bundle::{EncryptedBundle, Store};
use zrotext_root_material::{
    recovery_kit::{self, KitContext},
    root_backup::{self, ExpectedIdentity, RecoverySecret, RootSecret},
    sealed_root_enrollment::{canonical_origin, root_fingerprint},
};
use zrotext_root_terminal::{Session, verify_process_eligibility};

type Result<T> = std::result::Result<T, ()>;
const TIMEOUT: Duration = Duration::from_secs(300);

struct PublicContext {
    account: [u8; 16],
    origin: String,
}
enum Command {
    Init(PublicContext),
    Restore(PublicContext, [u8; 16]),
}

fn hex<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    if input.len() != N * 2 {
        return Err(());
    }
    let mut result = [0; N];
    for (out, pair) in result.iter_mut().zip(input.chunks_exact(2)) {
        let digit = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(()),
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(result)
}
fn display_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(args: &[String]) -> Result<Command> {
    if !matches!(args.len(), 5 | 7) || args[1] != "--account" || args[3] != "--origin" {
        return Err(());
    }
    let account = uuid::Uuid::parse_str(&args[2]).map_err(|_| ())?;
    if account.is_nil()
        || account.hyphenated().to_string() != args[2]
        || !canonical_origin(&args[4])
    {
        return Err(());
    }
    let context = PublicContext {
        account: *account.as_bytes(),
        origin: args[4].clone(),
    };
    match (args[0].as_str(), args.len()) {
        ("init", 5) => Ok(Command::Init(context)),
        ("restore-check", 7) if args[5] == "--bundle" => {
            let id = hex(args[6].as_bytes())?;
            if id == [0; 16] {
                return Err(());
            }
            Ok(Command::Restore(context, id))
        }
        _ => Err(()),
    }
}

fn local_store_parent() -> Result<PathBuf> {
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };
    let mut pointer = std::ptr::null_mut();
    // SAFETY: system allocates the terminated path; always free it, including on error.
    unsafe {
        let status = SHGetKnownFolderPath(
            &FOLDERID_LocalAppData,
            0,
            std::ptr::null_mut(),
            &mut pointer,
        );
        let result = (|| {
            if status < 0 || pointer.is_null() {
                return Err(());
            }
            let mut length = 0;
            while length < 260 && *pointer.add(length) != 0 {
                length += 1;
            }
            if length == 260 {
                return Err(());
            }
            let path =
                String::from_utf16(std::slice::from_raw_parts(pointer, length)).map_err(|_| ())?;
            if !path.is_ascii() {
                return Err(());
            }
            Ok(PathBuf::from(path))
        })();
        CoTaskMemFree(pointer.cast());
        result
    }
}

trait Material {
    fn generate(&mut self) -> Result<(RootSecret, RecoverySecret)>;
}
struct SystemMaterial;
impl Material for SystemMaterial {
    fn generate(&mut self) -> Result<(RootSecret, RecoverySecret)> {
        let key = SecretKey::try_generate_from_rng(&mut SysRng).map_err(|_| ())?;
        let mut scalar = Zeroizing::new([0; 32]);
        let encoded = Zeroizing::new(key.to_bytes());
        scalar.copy_from_slice(&encoded);
        drop(encoded);
        let root = RootSecret::new(scalar).map_err(|_| ())?;
        drop(key);
        let mut recovery = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(recovery.as_mut_slice())
            .map_err(|_| ())?;
        Ok((root, RecoverySecret::new(recovery)))
    }
}

fn pin(root: &RootSecret, account: &[u8; 16]) -> Result<[u8; 94]> {
    let key = SecretKey::from_slice(root.as_bytes()).map_err(|_| ())?;
    let point = key.public_key().to_sec1_point(false);
    let mut bytes = [0; 94];
    bytes[..5].copy_from_slice(b"ZTRP\x02");
    bytes[5..21].copy_from_slice(account);
    bytes[21..29].copy_from_slice(&1_u64.to_be_bytes());
    bytes[29..].copy_from_slice(point.as_bytes());
    root_fingerprint(&bytes, account).map_err(|_| ())?;
    Ok(bytes)
}

fn prompt(text: &str, limit: usize) -> Result<zrotext_root_terminal::SensitiveLine> {
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt(text).map_err(|_| ())?;
    session.read(limit, TIMEOUT).map_err(|_| ())
}

fn show_context(session: &mut Session, context: &PublicContext) -> Result<()> {
    session
        .write_public_prompt(&format!(
            "Account: {}\r\n",
            uuid::Uuid::from_bytes(context.account)
        ))
        .map_err(|_| ())?;
    session.write_public_prompt("Origin: ").map_err(|_| ())?;
    session
        .write_public_prompt(&context.origin)
        .map_err(|_| ())?;
    session
        .write_public_prompt("\r\nGeneration: 1 (unregistered)\r\n")
        .map_err(|_| ())
}

fn run_init(context: PublicContext, parent: PathBuf, material: &mut impl Material) -> Result<()> {
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    show_context(&mut session, &context)?;
    session
        .write_public_prompt("Create a NEW unregistered root? Type CREATE: ")
        .map_err(|_| ())?;
    let consent = session.read(6, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() != b"CREATE" {
        return Err(());
    }
    drop(consent);
    // Hold eligible console transport before entropy and through publication.
    let mut reveal = Session::acquire().map_err(|_| ())?;
    let store = Store::open(&parent).map_err(|_| ())?;
    verify_process_eligibility().map_err(|_| ())?;
    reveal.write_public_prompt("").map_err(|_| ())?;
    let (root, recovery) = material.generate()?;
    let pin = pin(&root, &context.account)?;
    let expected = ExpectedIdentity {
        account_id: context.account,
        origin: context.origin.clone(),
        root_fingerprint: root_fingerprint(&pin, &context.account).map_err(|_| ())?,
    };
    let backup = root_backup::seal(&root, &recovery, &expected).map_err(|_| ())?;
    drop(root);
    let id = root_backup::validate_public_header(&backup, &expected).map_err(|_| ())?;
    let kit = KitContext::new(expected.clone(), &pin, id).map_err(|_| ())?;
    let token = recovery_kit::encode_token(&recovery, &kit);
    drop(recovery);
    let card = recovery_kit::encode_public_card(&pin, &expected, &Sha256::digest(&backup).into())
        .map_err(|_| ())?;
    let bundle = EncryptedBundle::new(&backup, &card, &expected).map_err(|_| ())?;
    store.publish(&bundle).map_err(|_| ())?;
    reveal
        .write_public_prompt(&format!(
            "Bundle: {}\r\nFingerprint: {}\r\n",
            display_hex(&id),
            display_hex(&expected.root_fingerprint)
        ))
        .map_err(|_| ())?;
    reveal.write_public_prompt("Keep account, origin, bundle ID, fingerprint and token separately. Recovery is NOT verified.\r\n").map_err(|_| ())?;
    reveal.confirm_and_reveal(&token, TIMEOUT).map_err(|_| ())?;
    drop(token);
    Ok(())
}

fn run_restore_check(context: PublicContext, id: [u8; 16], parent: PathBuf) -> Result<()> {
    verify_process_eligibility().map_err(|_| ())?;
    let mut session = Session::acquire().map_err(|_| ())?;
    show_context(&mut session, &context)?;
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
    drop(root);
    let mut session = Session::acquire().map_err(|_| ())?;
    session.write_public_prompt("Recovery verified in this process. No enrollment or persistent unlock was created.\r\n").map_err(|_| ())?;
    // Session cleanup is explicit even when no additional input is needed.
    session.finish().map_err(|_| ())
}

pub(super) fn run(args: &[String]) -> Result<()> {
    let command = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let parent = local_store_parent()?;
    match command {
        Command::Init(context) => run_init(context, parent, &mut SystemMaterial),
        Command::Restore(context, id) => run_restore_check(context, id, parent),
    }
}

#[cfg(test)]
mod tests;
