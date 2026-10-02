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

#[cfg(feature = "unlock")]
mod conversation_activation;
#[cfg(feature = "unlock")]
mod conversation_genesis;
#[cfg(feature = "unlock")]
mod conversation_refresh;
#[cfg(feature = "unlock")]
mod custody_sign;
#[cfg(all(test, feature = "unlock"))]
mod native_fixture_path;

type Result<T> = std::result::Result<T, ()>;
const TIMEOUT: Duration = Duration::from_secs(300);

struct PublicContext {
    account: [u8; 16],
    origin: String,
}
enum Command {
    Init(PublicContext),
    Restore(PublicContext, [u8; 16]),
    #[cfg(feature = "unlock")]
    Unlock(PublicContext, [u8; 16], String),
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
    #[cfg(feature = "unlock")]
    let bounded = matches!(args.len(), 5 | 7 | 9);
    #[cfg(not(feature = "unlock"))]
    let bounded = matches!(args.len(), 5 | 7);
    if !bounded || args[1] != "--account" || args[3] != "--origin" {
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
        #[cfg(feature = "unlock")]
        ("unlock", 9) if args[5] == "--bundle" && args[7] == "--challenge" => {
            let id = hex(args[6].as_bytes())?;
            if id == [0; 16] {
                return Err(());
            }
            Ok(Command::Unlock(context, id, args[8].clone()))
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
    show_context_with_generation(session, context, "1 (unregistered)")
}

/// The generation note differs per flow: init and restore propose a first
/// unregistered generation, while offline unlock cannot observe the hub's
/// active generation and must not imply one.
fn show_context_with_generation(
    session: &mut Session,
    context: &PublicContext,
    generation_note: &str,
) -> Result<()> {
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
        .write_public_prompt(&format!("\r\nGeneration: {generation_note}\r\n"))
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

/// Bounded read of the public enrollment challenge file: an ASCII absolute
/// drive path (at most 260 bytes) holding exactly the RootEnrollment01 bytes
/// (152..=663). The challenge is public data; this tool never writes it.
#[cfg(feature = "unlock")]
fn read_challenge(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let bytes = path.as_bytes();
    // Absolute drive path only: an ASCII drive letter, a colon and a
    // separator, with a non-separator tail. This refuses drive-relative
    // paths, UNC and device-path spellings (any leading separator),
    // non-ASCII input, embedded NUL, trailing separators and absurd
    // lengths, all before any filesystem access.
    if bytes.len() > 260
        || bytes.len() < 4
        || !path.is_ascii()
        || !bytes[0].is_ascii_alphabetic()
        || bytes.get(1) != Some(&b':')
        || !(bytes[2] == b'\\' || bytes[2] == b'/')
        || bytes[bytes.len() - 1] == b'\\'
        || bytes[bytes.len() - 1] == b'/'
        || bytes.contains(&0)
    {
        return Err(());
    }
    // Reserved DOS device names are refused in every component.
    for component in path[3..].split(['\\', '/']) {
        let stem = component.split('.').next().unwrap_or("");
        if matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(());
        }
    }
    // Open the named path itself through the Win32 boundary with explicit
    // flags: reparse points are not traversed and the object must already
    // exist, so a symlink or junction cannot redirect a controlled path.
    #[cfg(windows)]
    let mut file = {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, OPEN_EXISTING,
        };
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        // SAFETY: in-parameters only; the returned handle is owned below.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(());
        }
        // SAFETY: we own the handle; CreateFileW succeeded.
        unsafe { std::fs::File::from_raw_handle(handle as _) }
    };
    #[cfg(not(windows))]
    let mut file = std::fs::File::open(std::path::Path::new(path)).map_err(|_| ())?;
    // The opened path must be a regular file, never a reparse point. The
    // reparse attribute bit covers symlinks, junctions and mount points.
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        let metadata = file.metadata().map_err(|_| ())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !metadata.file_type().is_file()
        {
            return Err(());
        }
    }
    #[cfg(not(windows))]
    {
        if !file.metadata().map_err(|_| ())?.is_file() {
            return Err(());
        }
    }

    let mut buffer = [0_u8; 664];
    let mut filled = 0;
    loop {
        let read = file.read(&mut buffer[filled..]).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        filled += read;
        if filled > 663 {
            return Err(());
        }
    }
    if filled < 152 {
        return Err(());
    }
    Ok(buffer[..filled].to_vec())
}

#[cfg(feature = "unlock")]
fn now_millis() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis(),
    )
    .map_err(|_| ())
}

/// Candidate unlock ceremony: verified recovery, then exactly one bound
/// enrollment challenge signature. No state, file or network output exists.
#[cfg(feature = "unlock")]
fn run_unlock(
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
    // Bind the public challenge to the independent identity BEFORE any secret
    // input, so a challenge for any other account, origin or root is refused
    // before the recovery token is requested.
    let unsigned = read_challenge(&challenge_path)?;
    let challenge =
        zrotext_root_material::root_unlock::inspect_challenge(&unsigned, &expected, now_millis()?)
            .map_err(|_| ())?;
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
        "Type UNLOCK to recover the root once and sign this challenge, or decline-UNLOCK to decline: ",
        14,
    )?;
    if consent.expose_ascii() == b"decline-UNLOCK" {
        drop(consent);
        let mut decline = Session::acquire().map_err(|_| ())?;
        decline
            .write_public_prompt(
                "Declined. Nothing was signed and no enrollment, unlock state or file was created.\r\n",
            )
            .map_err(|_| ())?;
        return decline.finish().map_err(|_| ());
    }
    if consent.expose_ascii() != b"UNLOCK" {
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
    let signature = zrotext_root_material::root_unlock::sign_enrollment(
        &root,
        &unsigned,
        &expected,
        now_millis()?,
    )
    .map_err(|_| ())?;
    drop(root);
    let mut session = Session::acquire().map_err(|_| ())?;
    session
        .write_public_prompt(&format!("Signature: {}\r\n", display_hex(&signature)))
        .map_err(|_| ())?;
    session
        .write_public_prompt(
            "One challenge signed with the recovered root. No enrollment, unlock state or file was created.\r\n",
        )
        .map_err(|_| ())?;
    session.finish().map_err(|_| ())
}

pub(super) fn run(args: &[String]) -> Result<()> {
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("conversation-genesis") {
        return conversation_genesis::run(args, local_store_parent()?);
    }
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("custody-sign") {
        return custody_sign::run(args, local_store_parent()?);
    }
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("conversation-refresh") {
        return conversation_refresh::run(args, local_store_parent()?);
    }
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("conversation-activation") {
        return conversation_activation::run(args, local_store_parent()?);
    }
    let command = parse(args)?;
    verify_process_eligibility().map_err(|_| ())?;
    let parent = local_store_parent()?;
    match command {
        Command::Init(context) => run_init(context, parent, &mut SystemMaterial),
        Command::Restore(context, id) => run_restore_check(context, id, parent),
        #[cfg(feature = "unlock")]
        Command::Unlock(context, id, path) => run_unlock(context, id, path, parent),
    }
}

#[cfg(test)]
mod tests;
