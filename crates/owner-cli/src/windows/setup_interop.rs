// SPDX-License-Identifier: AGPL-3.0-only
//! cfg(test)-only public fixture callback transport. No production locator,
//! network, caller-selected paths, key/scalar input or recovery-token input.
use super::*;
use serde_json::{Map, Value, json};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Console::*, Threading::*},
};
use zrotext_root_material::{
    line_key_registration as registration, sealed_root_enrollment as enrollment,
};
const REQUEST: &str = "ZT_OWNER_SETUP_INTEROP_REQUEST_HEX";
const CHILD: &str = "ZT_OWNER_SETUP_INTEROP_CHILD";
const MAX_REQUEST: usize = 8192;
const MAX_RESULT: usize = 4096;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Custody,
    LineRegistration,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Prepare,
    Custody,
    Line,
}
impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepareRootFixture",
            Self::Custody => "signCustody",
            Self::Line => "signLineRegistration",
        }
    }
    fn stage(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Custody => "custody",
            Self::Line => "line",
        }
    }
    fn test(self) -> &'static str {
        match self {
            Self::Prepare | Self::Custody => {
                "windows::custody_sign::tests::native_console_custody_signs_only_reviewed_bundle"
            }
            Self::Line => {
                "windows::line_key_registration::tests::native_console_registration_requires_independent_scope_and_fresh_publication"
            }
        }
    }
    fn family(self) -> Family {
        match self {
            Self::Prepare | Self::Custody => Family::Custody,
            Self::Line => Family::LineRegistration,
        }
    }
}
struct Request {
    operation: Operation,
    expected: Map<String, Value>,
    artifacts: Option<Map<String, Value>>,
    bytes: Option<Vec<u8>>,
}
fn keys(map: &Map<String, Value>, names: &[&str]) -> Result<()> {
    if map.len() != names.len() || names.iter().any(|n| !map.contains_key(*n)) {
        return Err(());
    }
    Ok(())
}
fn text<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    map.get(name).and_then(Value::as_str).ok_or(())
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
fn hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum * 2 || value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| hex::<1>(p).map(|b| b[0]))
        .collect()
}
fn fixture_origin(origin: &str) -> bool {
    if origin.len() > 255 || !canonical_origin(origin) {
        return false;
    }
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    for reserved in ["owner.example.test", "owner.invalid"] {
        if host == reserved {
            return true;
        }
        if let Some(port) = host
            .strip_prefix(reserved)
            .and_then(|s| s.strip_prefix(':'))
            && let Ok(n) = port.parse::<u16>()
            && n > 0
            && n != 443
            && n.to_string() == port
        {
            return true;
        }
    }
    false
}
fn parse_request(bytes: &[u8]) -> Result<Request> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let map = value.as_object().ok_or(())?;
    if map.get("version") != Some(&json!(1)) || map.get("synthetic") != Some(&json!(true)) {
        return Err(());
    }
    let operation = match text(map, "operation")? {
        "prepareRootFixture" => Operation::Prepare,
        "signCustody" => Operation::Custody,
        "signLineRegistration" => Operation::Line,
        _ => return Err(()),
    };
    keys(
        map,
        if operation == Operation::Prepare {
            &["version", "synthetic", "operation", "expected"]
        } else {
            &[
                "version",
                "synthetic",
                "operation",
                "expected",
                "artifacts",
                "transcript",
            ]
        },
    )?;
    let expected = map
        .get("expected")
        .and_then(Value::as_object)
        .ok_or(())?
        .clone();
    let expected_keys: &[&str] = match operation {
        Operation::Prepare => &["account", "origin"],
        Operation::Custody => &[
            "account",
            "origin",
            "rootFingerprint",
            "user",
            "session",
            "challenge",
            "nonce",
            "issued",
            "expires",
        ],
        Operation::Line => &[
            "account",
            "origin",
            "rootFingerprint",
            "user",
            "session",
            "device",
            "line",
            "generation",
            "challenge",
            "nonce",
            "issued",
            "expires",
            "approvalFingerprint",
            "pairedSigningFingerprint",
            "connectionEpoch",
            "deploymentEpoch",
            "site",
            "instance",
        ],
    };
    keys(&expected, expected_keys)?;
    uuid(text(&expected, "account")?)?;
    if !fixture_origin(text(&expected, "origin")?) {
        return Err(());
    }
    let artifacts = if operation == Operation::Prepare {
        None
    } else {
        let artifacts = map
            .get("artifacts")
            .and_then(Value::as_object)
            .ok_or(())?
            .clone();
        keys(
            &artifacts,
            &[
                "rootPin",
                "rootFingerprint",
                "bundleId",
                "encryptedBackup",
                "publicCard",
            ],
        )?;
        hex::<94>(text(&artifacts, "rootPin")?.as_bytes())?;
        hex::<32>(text(&artifacts, "rootFingerprint")?.as_bytes())?;
        hex::<16>(text(&artifacts, "bundleId")?.as_bytes())?;
        hex_bytes(text(&artifacts, "encryptedBackup")?, 748)?;
        hex_bytes(text(&artifacts, "publicCard")?, 645)?;
        Some(artifacts)
    };
    let transcript = if operation == Operation::Prepare {
        None
    } else {
        Some(hex_bytes(
            text(map, "transcript")?,
            registration::MAX_TRANSCRIPT,
        )?)
    };
    let request = Request {
        operation,
        expected,
        artifacts,
        bytes: transcript,
    };
    if operation == Operation::Custody {
        let challenge = expected_challenge(&request.expected)?;
        if enrollment::parse(request.bytes.as_ref().ok_or(())?).map_err(|_| ())? != challenge {
            return Err(());
        }
    }
    if operation == Operation::Line {
        let expected = expected_line(&request.expected)?;
        let statement = registration::decode(request.bytes.as_ref().ok_or(())?).map_err(|_| ())?;
        registration::inspect(&statement, &expected, expected.scope.issued_ms).map_err(|_| ())?;
    }
    Ok(request)
}
fn expected_challenge(m: &Map<String, Value>) -> Result<enrollment::Challenge> {
    let challenge = enrollment::Challenge {
        account_id: uuid(text(m, "account")?)?,
        user_id: uuid(text(m, "user")?)?,
        session_id: uuid(text(m, "session")?)?,
        challenge_id: uuid(text(m, "challenge")?)?,
        nonce: hex(text(m, "nonce")?.as_bytes())?,
        root_fingerprint: hex(text(m, "rootFingerprint")?.as_bytes())?,
        issued_ms: number(text(m, "issued")?)?,
        expires_ms: number(text(m, "expires")?)?,
        origin: text(m, "origin")?.into(),
    };
    if challenge.nonce == [0; 32] || challenge.root_fingerprint == [0; 32] {
        return Err(());
    }
    enrollment::encode(&challenge).map_err(|_| ())?;
    Ok(challenge)
}
fn fake_root() -> RootSecret {
    let mut scalar = Zeroizing::new([0; 32]);
    scalar[31] = 1;
    RootSecret::new(scalar).unwrap()
}
fn fake_pin(account: &[u8; 16]) -> Result<[u8; 94]> {
    pin(&fake_root(), account)
}
fn fake_identity(m: &Map<String, Value>) -> Result<ExpectedIdentity> {
    let account = uuid(text(m, "account")?)?;
    let origin = text(m, "origin")?;
    if !fixture_origin(origin) {
        return Err(());
    }
    let fingerprint = root_fingerprint(&fake_pin(&account)?, &account).map_err(|_| ())?;
    if let Some(expected) = m.get("rootFingerprint")
        && hex::<32>(expected.as_str().ok_or(())?.as_bytes())? != fingerprint
    {
        return Err(());
    }
    Ok(ExpectedIdentity {
        account_id: account,
        origin: origin.into(),
        root_fingerprint: fingerprint,
    })
}
fn expected_line(m: &Map<String, Value>) -> Result<registration::Expected> {
    let identity = fake_identity(m)?;
    let scope = registration::Scope {
        account: identity.account_id,
        origin: identity.origin.clone(),
        user: uuid(text(m, "user")?)?,
        owner_session: uuid(text(m, "session")?)?,
        device: uuid(text(m, "device")?)?,
        line: uuid(text(m, "line")?)?,
        next_generation: number(text(m, "generation")?)?,
        challenge: uuid(text(m, "challenge")?)?,
        nonce: hex(text(m, "nonce")?.as_bytes())?,
        issued_ms: number(text(m, "issued")?)?,
        expires_ms: number(text(m, "expires")?)?,
        approval_fingerprint: hex(text(m, "approvalFingerprint")?.as_bytes())?,
        paired_signing_fingerprint: hex(text(m, "pairedSigningFingerprint")?.as_bytes())?,
        connection_epoch: number(text(m, "connectionEpoch")?)?,
        deployment_epoch: number(text(m, "deploymentEpoch")?)?,
        site_id: text(m, "site")?.into(),
        instance_id: text(m, "instance")?.into(),
    };
    let root_pin = fake_pin(&identity.account_id)?;
    Ok(registration::Expected {
        identity,
        scope,
        root_pin,
    })
}
struct Artifacts {
    pin: [u8; 94],
    id: [u8; 16],
    backup: Vec<u8>,
    card: Vec<u8>,
}
impl Artifacts {
    fn public(&self, identity: &ExpectedIdentity) -> Value {
        json!({"rootPin":display_hex(&self.pin),"rootFingerprint":display_hex(&identity.root_fingerprint),"bundleId":display_hex(&self.id),"encryptedBackup":display_hex(&self.backup),"publicCard":display_hex(&self.card)})
    }
    fn from_request(map: &Map<String, Value>, identity: &ExpectedIdentity) -> Result<Self> {
        let artifacts = Self {
            pin: hex(text(map, "rootPin")?.as_bytes())?,
            id: hex(text(map, "bundleId")?.as_bytes())?,
            backup: hex_bytes(text(map, "encryptedBackup")?, 748)?,
            card: hex_bytes(text(map, "publicCard")?, 645)?,
        };
        if artifacts.pin != fake_pin(&identity.account_id)?
            || hex::<32>(text(map, "rootFingerprint")?.as_bytes())? != identity.root_fingerprint
            || artifacts.id
                != root_backup::validate_public_header(&artifacts.backup, identity)
                    .map_err(|_| ())?
        {
            return Err(());
        }
        let card = recovery_kit::decode_public_card(
            &artifacts.card,
            identity,
            &Sha256::digest(&artifacts.backup).into(),
        )
        .map_err(|_| ())?;
        if card.root_pin() != &artifacts.pin {
            return Err(());
        }
        let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
        let restored = root_backup::open(&artifacts.backup, &recovery, identity).map_err(|_| ())?;
        if restored.as_bytes() != fake_root().as_bytes() {
            return Err(());
        }
        drop(restored);
        drop(recovery);
        Ok(artifacts)
    }
}
fn child(request: &Request, parent: &Path) -> Result<Value> {
    assert_child_console();
    let identity = fake_identity(&request.expected)?;
    let artifacts = if request.operation == Operation::Prepare {
        let root = fake_root();
        let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
        let pin = fake_pin(&identity.account_id)?;
        let backup = root_backup::seal(&root, &recovery, &identity).map_err(|_| ())?;
        let id = root_backup::validate_public_header(&backup, &identity).map_err(|_| ())?;
        let card =
            recovery_kit::encode_public_card(&pin, &identity, &Sha256::digest(&backup).into())
                .map_err(|_| ())?;
        drop(root);
        drop(recovery);
        Artifacts {
            pin,
            id,
            backup,
            card,
        }
    } else {
        Artifacts::from_request(request.artifacts.as_ref().ok_or(())?, &identity)?
    };
    let bundle =
        EncryptedBundle::new(&artifacts.backup, &artifacts.card, &identity).map_err(|_| ())?;
    let store = Store::open(parent).map_err(|_| ())?;
    store.publish(&bundle).map_err(|_| ())?;
    if request.operation == Operation::Prepare {
        // Fixture setup only; this operation is not a root initialization claim.
        let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
        let restored =
            root_backup::open(bundle.encrypted_backup(), &recovery, &identity).map_err(|_| ())?;
        drop(restored);
        drop(recovery);
        let session = Session::acquire().map_err(|_| ())?;
        session.finish().map_err(|_| ())?;
        return Ok(
            json!({"version":1,"synthetic":true,"operation":request.operation.name(),"artifacts":artifacts.public(&identity)}),
        );
    }
    let proposal = parent.join("public-transcript.bin");
    std::fs::write(&proposal, request.bytes.as_ref().ok_or(())?).map_err(|_| ())?;
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &artifacts.pin, artifacts.id).map_err(|_| ())?,
    );
    drop(recovery);
    let fingerprint = display_hex(&identity.root_fingerprint);
    let operation = request.operation;
    let injector = std::thread::spawn(move || {
        send_after("Enter full lowercase fingerprint", fingerprint.as_bytes());
        send_after(
            if operation == Operation::Custody {
                "Type CUSTODY"
            } else {
                "Type REGISTER-LINE-KEY"
            },
            if operation == Operation::Custody {
                b"CUSTODY"
            } else {
                b"REGISTER-LINE-KEY"
            },
        );
        send_after("Enter recovery token", token.expose_ascii());
    });
    let outcome = if operation == Operation::Custody {
        let args = vec![
            "custody-sign".into(),
            "--account".into(),
            text(&request.expected, "account")?.into(),
            "--origin".into(),
            identity.origin.clone(),
            "--bundle".into(),
            display_hex(&artifacts.id),
            "--challenge".into(),
            proposal.to_str().ok_or(())?.into(),
        ];
        let result = super::custody_sign::run(&args, parent.to_path_buf());
        injector.join().map_err(|_| ())?;
        result?;
        let enrollment = screen_signature("Enrollment signature: ")?;
        let custody = screen_signature("Custody signature: ")?;
        let challenge = expected_challenge(&request.expected)?;
        enrollment::verify(
            &artifacts.pin,
            request.bytes.as_ref().ok_or(())?,
            &enrollment,
            &challenge,
            now_millis()?,
        )
        .map_err(|_| ())?;
        let reviewed = zrotext_root_material::root_unlock::custody::ReviewedCustody::inspect(
            request.bytes.as_ref().ok_or(())?,
            &artifacts.backup,
            &artifacts.card,
            &identity,
            &artifacts.id,
            now_millis()?,
        )
        .map_err(|_| ())?;
        // Independent public verification of the exact ciphertext/card custody domain.
        let mut statement = b"ZTSE/root-custody/v1\0".to_vec();
        let bytes = request.bytes.as_ref().ok_or(())?;
        statement.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        statement.extend_from_slice(bytes);
        statement.extend_from_slice(&Sha256::digest(&artifacts.backup));
        statement.extend_from_slice(&Sha256::digest(&artifacts.card));
        statement.extend_from_slice(&identity.root_fingerprint);
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        let sig = Signature::from_slice(&custody).map_err(|_| ())?;
        if !canonical_signature(&custody) {
            return Err(());
        }
        VerifyingKey::from_sec1_bytes(&artifacts.pin[29..])
            .map_err(|_| ())?
            .verify(&statement, &sig)
            .map_err(|_| ())?;
        drop(reviewed);
        json!({"enrollmentSignature":display_hex(&enrollment),"custodySignature":display_hex(&custody)})
    } else {
        let output = parent.join("public-signature.bin");
        let m = &request.expected;
        let mut args = vec!["line-key-registration".into()];
        for (flag, value) in [
            ("--account", text(m, "account")?.to_owned()),
            ("--origin", identity.origin.clone()),
            (
                "--root-fingerprint",
                display_hex(&identity.root_fingerprint),
            ),
            ("--bundle", display_hex(&artifacts.id)),
            ("--proposal", proposal.to_str().ok_or(())?.into()),
            ("--output", output.to_str().ok_or(())?.into()),
            ("--user", text(m, "user")?.into()),
            ("--session", text(m, "session")?.into()),
            ("--device", text(m, "device")?.into()),
            ("--line", text(m, "line")?.into()),
            ("--generation", text(m, "generation")?.into()),
            ("--challenge", text(m, "challenge")?.into()),
            ("--nonce", text(m, "nonce")?.into()),
            ("--issued", text(m, "issued")?.into()),
            ("--expires", text(m, "expires")?.into()),
            (
                "--approval-fingerprint",
                text(m, "approvalFingerprint")?.into(),
            ),
            (
                "--paired-signing-fingerprint",
                text(m, "pairedSigningFingerprint")?.into(),
            ),
            ("--connection-epoch", text(m, "connectionEpoch")?.into()),
            ("--deployment-epoch", text(m, "deploymentEpoch")?.into()),
            ("--site", text(m, "site")?.into()),
            ("--instance", text(m, "instance")?.into()),
        ] {
            args.extend([flag.into(), value]);
        }
        let result = super::line_key_registration::run(&args, parent.to_path_buf());
        injector.join().map_err(|_| ())?;
        result?;
        let signature: [u8; 64] = std::fs::read(&output)
            .map_err(|_| ())?
            .try_into()
            .map_err(|_| ())?;
        let statement = registration::decode(request.bytes.as_ref().ok_or(())?).map_err(|_| ())?;
        registration::inspect(&statement, &expected_line(m)?, now_millis()?).map_err(|_| ())?;
        statement.verify_root(&signature).map_err(|_| ())?;
        if screen_signature("RootLineRegister signature (raw64 lowercase hex): ")? != signature {
            return Err(());
        }
        json!({"rootSignature":display_hex(&signature)})
    };
    if screen().contains("ZTRK1-")
        || store
            .read_bundle(&artifacts.id, &identity)
            .map_err(|_| ())?
            .encrypted_backup()
            != artifacts.backup
    {
        return Err(());
    }
    Ok(
        json!({"version":1,"synthetic":true,"operation":operation.name(),"artifacts":artifacts.public(&identity),"signatures":outcome}),
    )
}
// Verify the original signature; reject high-s without accepting normalization.
fn canonical_signature(raw: &[u8; 64]) -> bool {
    p256::ecdsa::Signature::from_slice(raw)
        .is_ok_and(|signature| signature.normalize_s().to_bytes().as_slice() == raw)
}
fn fixed_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-native-owner-setup")
}
fn validated_parent(supplied: &Path, operation: Operation) -> Result<PathBuf> {
    let root = fixed_root();
    let tail = supplied.strip_prefix(&root).map_err(|_| ())?;
    let mut parts = tail.components();
    let run = parts.next().ok_or(())?.as_os_str().to_str().ok_or(())?;
    let (pid, nanos) = run.split_once('-').ok_or(())?;
    let pid = pid.parse::<u32>().map_err(|_| ())?;
    let nanos = nanos.parse::<u128>().map_err(|_| ())?;
    if pid == 0
        || nanos == 0
        || run != format!("{pid}-{nanos}")
        || parts.next().ok_or(())?.as_os_str() != operation.stage()
        || parts.next().is_some()
    {
        return Err(());
    }
    let run = root.join(format!("{pid}-{nanos}"));
    let parent = run.join(operation.stage());
    for path in [&root, &run, &parent] {
        let m = std::fs::symlink_metadata(path).map_err(|_| ())?;
        if !m.is_dir() || m.file_attributes() & 0x0400 != 0 {
            return Err(());
        }
    }
    if supplied.canonicalize().map_err(|_| ())? != parent.canonicalize().map_err(|_| ())? {
        return Err(());
    }
    Ok(parent)
}
struct OwnedRun(PathBuf);
impl Drop for OwnedRun {
    fn drop(&mut self) {
        let root = fixed_root();
        let Ok(root) = root.canonicalize() else {
            return;
        };
        let Ok(target) = self.0.canonicalize() else {
            return;
        };
        if target != root
            && target.starts_with(&root)
            && let Ok(m) = std::fs::symlink_metadata(&self.0)
            && m.is_dir()
            && m.file_attributes() & 0x0400 == 0
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
/// Returns true only when this exact native test was selected for an explicit
/// public fixture callback. Ordinary regression stages are otherwise unchanged.
pub(super) fn dispatch(family: Family) -> bool {
    let Some(raw) = std::env::var_os("ZT_OWNER_SETUP_INTEROP_REQUEST_HEX") else {
        assert!(std::env::var_os("ZT_OWNER_SETUP_INTEROP_CHILD").is_none());
        return false;
    };
    let raw = raw.to_str().expect("fixture request encoding");
    let bytes = hex_bytes(raw, MAX_REQUEST).expect("bounded public fixture request");
    let request = parse_request(&bytes).expect("typed public fixture request");
    assert!(
        request.operation.family() == family,
        "wrong fixture callback test"
    );
    if let Some(stage) = std::env::var_os("ZT_OWNER_SETUP_INTEROP_CHILD") {
        let result = std::panic::catch_unwind(|| {
            assert_eq!(stage.to_str(), Some(request.operation.stage()));
            let supplied =
                PathBuf::from(std::env::var_os("TEMP").expect("owned fixture directory"));
            let parent =
                validated_parent(&supplied, request.operation).expect("owned fixture namespace");
            let value = child(&request, &parent).expect("fixture CLI callback refused");
            let result = serde_json::to_vec(&value).unwrap();
            assert!(result.len() <= MAX_RESULT);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(parent.join("public-result.json"))
                .unwrap();
            file.write_all(&result).unwrap();
            file.sync_all().unwrap();
        });
        std::process::exit(if result.is_ok() { 0 } else { 90 });
    }
    let root = fixed_root();
    std::fs::create_dir_all(&root).unwrap();
    let metadata = std::fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir() && metadata.file_attributes() & 0x0400 == 0);
    let run = root.join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&run).unwrap();
    let _owned = OwnedRun(run.clone());
    let parent = run.join(request.operation.stage());
    std::fs::create_dir(&parent).unwrap();
    let parent = validated_parent(&parent, request.operation).unwrap();
    launch(&request, &parent, raw);
    let mut bytes = Vec::new();
    File::open(parent.join("public-result.json"))
        .unwrap()
        .take((MAX_RESULT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= MAX_RESULT);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["operation"], request.operation.name());
    assert_eq!(value["synthetic"], true);
    assert!(!String::from_utf8_lossy(&bytes).contains("ZTRK1-"));
    println!(
        "ZT_OWNER_SETUP_RESULT={}",
        serde_json::to_string(&value).unwrap()
    );
    true
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn launch(request: &Request, parent: &Path, raw: &str) {
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact {} --nocapture --test-threads=1",
        executable.display(),
        request.operation.test()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        (CHILD, request.operation.stage().into()),
        (REQUEST, raw.into()),
    ] {
        environment.extend(wide(OsStr::new(&format!(
            "{key}={}",
            value.to_str().unwrap()
        ))));
    }
    environment.push(0);
    // SAFETY: bounded terminated owned buffers; no inherited handles/user console.
    unsafe {
        let mut startup: STARTUPINFOW = zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = 0;
        let mut process = zeroed();
        assert_ne!(
            crate::native_process::create(
                application.as_ptr(),
                command.as_mut_ptr(),
                environment.as_ptr().cast(),
                &startup,
                &mut process,
                || verify_process_eligibility().is_ok()
            ),
            0
        );
        let handle = OwnedHandle::from_raw_handle(process.hProcess);
        let _thread = OwnedHandle::from_raw_handle(process.hThread);
        if WaitForSingleObject(handle.as_raw_handle(), 20000) != WAIT_OBJECT_0 {
            TerminateProcess(handle.as_raw_handle(), 99);
            WaitForSingleObject(handle.as_raw_handle(), 5000);
            panic!("fixture callback child timeout");
        }
        let mut code = 0;
        assert_ne!(GetExitCodeProcess(handle.as_raw_handle(), &mut code), 0);
        assert_eq!(code, 0, "fixture callback child failed");
    }
}
fn assert_child_console() {
    crate::native_process::assert_current_process_limited();
    verify_process_eligibility().unwrap();
    // SAFETY: bounded process list and startup outputs; hidden test child only.
    unsafe {
        let mut processes = [0; 8];
        assert_eq!(GetConsoleProcessList(processes.as_mut_ptr(), 8), 1);
        assert_eq!(processes[0], GetCurrentProcessId());
        let mut startup = zeroed();
        GetStartupInfoW(&mut startup);
        assert_eq!(startup.dwFlags & STARTF_USESHOWWINDOW, STARTF_USESHOWWINDOW);
        assert_eq!(startup.wShowWindow, 0);
        let window = GetConsoleWindow();
        assert!(!window.is_null());
        assert_eq!(
            windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible(window),
            0
        );
    }
}
fn screen() -> String {
    let mut text = vec![0; 16000];
    let mut count = 0;
    unsafe {
        assert_ne!(
            ReadConsoleOutputCharacterW(
                GetStdHandle(STD_OUTPUT_HANDLE),
                text.as_mut_ptr(),
                text.len() as u32,
                COORD { X: 0, Y: 0 },
                &mut count
            ),
            0
        );
    }
    String::from_utf16_lossy(&text[..count as usize])
}
fn screen_signature(label: &str) -> Result<[u8; 64]> {
    let text = screen();
    if text.matches(label).count() != 1 {
        return Err(());
    }
    let value: String = text
        .split_once(label)
        .ok_or(())?
        .1
        .chars()
        .take(128)
        .collect();
    hex(value.as_bytes())
}
fn send_after(prompt: &str, text: &[u8]) {
    let start = std::time::Instant::now();
    while !screen().contains(prompt) {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "fixture CLI prompt absent"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for byte in text.iter().chain(std::iter::once(&b'\r')) {
        unsafe {
            let mut record: INPUT_RECORD = zeroed();
            record.EventType = KEY_EVENT as u16;
            record.Event.KeyEvent.bKeyDown = 1;
            record.Event.KeyEvent.wRepeatCount = 1;
            record.Event.KeyEvent.uChar.UnicodeChar = u16::from(*byte);
            let mut count = 0;
            assert_ne!(
                WriteConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &record, 1, &mut count),
                0
            );
            assert_eq!(count, 1);
        }
    }
}
#[cfg(test)]
mod tests;
