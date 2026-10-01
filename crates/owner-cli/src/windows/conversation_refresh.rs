// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit one-shot console review of a typed role-5 refresh. No key creation.
use super::*;
use std::io::Write;
use zrotext_root_material::conversation_refresh::{self as refresh, Expected, Scope};

const FLAGS: [&str; 18] = [
    "--account",
    "--origin",
    "--bundle",
    "--proposal",
    "--output",
    "--session",
    "--interval",
    "--device",
    "--line",
    "--generation",
    "--peer",
    "--manifest-version",
    "--manifest-digest",
    "--phone-reader",
    "--archive-reader",
    "--signer",
    "--signer-point",
    "--until",
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
    if args.len() != 37
        || args[0] != "conversation-refresh"
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
        interval: uuid(v(6))?,
        device: uuid(v(7))?,
        line: uuid(v(8))?,
        line_generation: number(v(9))?,
        peer: v(10).into(),
        predecessor_version: number(v(11))?,
        predecessor_digest: hex(v(12).as_bytes())?,
        phone_reader: hex(v(13).as_bytes())?,
        archive_reader: hex(v(14).as_bytes())?,
        signer: hex(v(15).as_bytes())?,
        point: hex(v(16).as_bytes())?,
        until_ms: number(v(17))?,
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
    session.write_public_prompt("Offline generation-one conversation role-5 refresh. Independently supplied scope and high-water are required; a downloaded proposal is not expected authority.\r\n").map_err(|_|())?;
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
            "Owner session: {}\r\nInterval: {}\r\n",
            uuid::Uuid::from_bytes(reviewed.session),
            uuid::Uuid::from_bytes(reviewed.interval)
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
            "New role-5 signer: {}\r\nPublic point: {}\r\nExpires at (epoch milliseconds): {}\r\n",
            display_hex(&reviewed.signer),
            display_hex(&reviewed.point),
            reviewed.until_ms
        ),
    ] {
        for chunk in line.as_bytes().chunks(512) {
            session
                .write_public_prompt(std::str::from_utf8(chunk).map_err(|_| ())?)
                .map_err(|_| ())?;
        }
    }
    session.write_public_prompt("Every existing manifest record, including the account archive reader, stays exact. Only this line's session-lifetime role-5 signer is added. The manifest signature does not encode peer/session; authenticated installation must enforce them.\r\nType REFRESH-ROLE5 to approve once, or DECLINE: ").map_err(|_|())?;
    let consent = session.read(13, TIMEOUT).map_err(|_| ())?;
    if consent.expose_ascii() != b"REFRESH-ROLE5" {
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
    output_session.write_public_prompt("Public signed successor written once. No enrollment, network action, persistent unlock or archive change occurred. Independently verify and install through authenticated predecessor/session CAS.\r\n").map_err(|_|())?;
    output_session.finish().map_err(|_| ())
}
pub(super) fn public_path(path: &str) -> Result<()> {
    let b = path.as_bytes();
    if !(4..=260).contains(&b.len())
        || !path.is_ascii()
        || !b[0].is_ascii_alphabetic()
        || b[1] != b':'
        || !matches!(b[2], b'\\' | b'/')
        || matches!(b[b.len() - 1], b'\\' | b'/')
        || b.contains(&0)
    {
        return Err(());
    }
    for component in path[3..].split(['\\', '/']) {
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.contains(':')
            || component.ends_with([' ', '.'])
            || matches!(
                stem.as_str(),
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
            )
        {
            return Err(());
        }
    }
    Ok(())
}
pub(super) fn write_public(path: &str, bytes: &[u8]) -> Result<()> {
    public_path(path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}

#[cfg(test)]
pub(super) mod tests;

pub(super) fn read_proposal(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    public_path(path)?;
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
    // exist. The final component cannot redirect this open through a reparse
    // point; ancestor junctions may still be traversed. Public input remains
    // untrusted until independently bound cryptographic inspection.
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

    let mut buffer = vec![0_u8; refresh::MAX_PROPOSAL + 1];
    let mut filled = 0;
    loop {
        let read = file.read(&mut buffer[filled..]).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        filled += read;
        if filled > refresh::MAX_PROPOSAL {
            return Err(());
        }
    }
    if filled < 5 {
        return Err(());
    }
    Ok(buffer[..filled].to_vec())
}

#[cfg(test)]
mod native_tests;
