// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic keys and a hidden, exclusively owned limited-token console only.
use super::*;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::Digest;
use std::{
    ffi::OsStr,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Console::*, Threading::*},
};
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn child(stage: &'static str, parent: PathBuf) {
    crate::native_process::assert_current_process_limited();
    verify_process_eligibility().unwrap();
    // The test child owns a hidden console; no fixture injector ever touches a user console.
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
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let pin = pin(&root, &[1; 16]).unwrap();
    let identity = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://owner.invalid".into(),
        root_fingerprint: root_fingerprint(&pin, &[1; 16]).unwrap(),
    };
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card =
        recovery_kit::encode_public_card(&pin, &identity, &Sha256::digest(&backup).into()).unwrap();
    let bundle = EncryptedBundle::new(&backup, &card, &identity).unwrap();
    let store = Store::open(&parent).unwrap();
    store.publish(&bundle).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &pin, id).unwrap(),
    );
    let now = now_millis().unwrap();
    let challenge = zrotext_root_material::sealed_root_enrollment::Challenge {
        account_id: if stage == "scope" {
            [8; 16]
        } else {
            identity.account_id
        },
        user_id: [2; 16],
        session_id: [3; 16],
        challenge_id: [4; 16],
        nonce: [5; 32],
        root_fingerprint: identity.root_fingerprint,
        issued_ms: now,
        expires_ms: now + if stage == "expiry" { 2000 } else { 120000 },
        origin: identity.origin.clone(),
    };
    let unsigned = zrotext_root_material::sealed_root_enrollment::encode(&challenge).unwrap();
    let path = parent.join("challenge.bin");
    std::fs::write(&path, &unsigned).unwrap();
    drop(root);
    drop(recovery);
    let fingerprint = display_hex(&identity.root_fingerprint);
    let sender = std::thread::spawn(move || {
        send_after("Enter full lowercase fingerprint", fingerprint.as_bytes());
        if stage == "scope" {
            return;
        }
        send_after(
            "Type CUSTODY",
            if stage == "decline" {
                b"DECLINE"
            } else {
                b"CUSTODY"
            },
        );
        if stage == "decline" {
            return;
        }
        if stage == "expiry" {
            std::thread::sleep(Duration::from_millis(2200));
        }
        send_after(
            "Enter recovery token",
            if stage == "token" {
                b"INVALID"
            } else {
                token.expose_ascii()
            },
        );
    });
    let args: Vec<String> = [
        "custody-sign".into(),
        "--account".into(),
        uuid::Uuid::from_bytes(identity.account_id).to_string(),
        "--origin".into(),
        identity.origin.clone(),
        "--bundle".into(),
        display_hex(&id),
        "--challenge".into(),
        path.to_str().unwrap().into(),
    ]
    .into();
    let result = run(&args, parent.clone());
    sender.join().unwrap();
    assert_eq!(result.is_ok(), matches!(stage, "success" | "decline"));
    let screen = screen();
    assert!(!screen.contains("ZTRK1-"));
    if stage == "success" {
        let parse_signature = |label: &str| {
            let suffix = screen.split(label).nth(1).unwrap();
            let value: String = suffix.chars().take(128).collect();
            hex::<64>(value.as_bytes()).unwrap()
        };
        let enrollment = parse_signature("Enrollment signature: ");
        let custody = parse_signature("Custody signature: ");
        zrotext_root_material::sealed_root_enrollment::verify(
            &pin,
            &unsigned,
            &enrollment,
            &challenge,
            now_millis().unwrap(),
        )
        .unwrap();
        let mut statement = b"ZTSE/root-custody/v1\0".to_vec();
        statement.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
        statement.extend_from_slice(&unsigned);
        statement.extend_from_slice(&Sha256::digest(&backup));
        statement.extend_from_slice(&Sha256::digest(&card));
        statement.extend_from_slice(&identity.root_fingerprint);
        VerifyingKey::from_sec1_bytes(&pin[29..])
            .unwrap()
            .verify(&statement, &Signature::from_slice(&custody).unwrap())
            .unwrap();
    } else {
        assert!(!screen.contains("Enrollment signature: "));
        assert!(!screen.contains("Custody signature: "));
    }
    if matches!(stage, "scope" | "decline") {
        assert!(!screen.contains("Enter recovery token"));
    }
    assert_eq!(
        store
            .read_bundle(&id, &identity)
            .unwrap()
            .encrypted_backup(),
        backup
    );
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 2);
}
fn fixed_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-native-custody")
}
fn validated_parent(supplied: &std::path::Path, stage: &str) -> PathBuf {
    let root = fixed_root();
    let tail = supplied.strip_prefix(&root).unwrap();
    let mut parts = tail.components();
    let run = parts.next().unwrap().as_os_str().to_str().unwrap();
    let (pid, nanos) = run.split_once('-').unwrap();
    let pid = pid.parse::<u32>().unwrap();
    let nanos = nanos.parse::<u128>().unwrap();
    assert!(pid > 0 && nanos > 0);
    assert_eq!(run, format!("{pid}-{nanos}"));
    assert_eq!(parts.next().unwrap().as_os_str(), stage);
    assert!(parts.next().is_none());
    let parent = root.join(format!("{pid}-{nanos}")).join(stage);
    use std::os::windows::fs::MetadataExt;
    for path in [&root, &parent.parent().unwrap().to_path_buf(), &parent] {
        let m = std::fs::symlink_metadata(path).unwrap();
        assert!(m.is_dir() && m.file_attributes() & 0x0400 == 0);
    }
    assert_eq!(
        supplied.canonicalize().unwrap(),
        parent.canonicalize().unwrap()
    );
    parent
}
#[test]
fn native_console_custody_signs_only_reviewed_bundle() {
    if let Ok(stage) = std::env::var("ZT_CUSTODY_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let stage = match stage.as_str() {
                "success" => "success",
                "scope" => "scope",
                "decline" => "decline",
                "token" => "token",
                "expiry" => "expiry",
                _ => panic!("unknown fixture stage"),
            };
            let supplied = PathBuf::from(std::env::var_os("TEMP").unwrap());
            child(stage, validated_parent(&supplied, stage));
        });
        std::process::exit(if result.is_ok() { 0 } else { 90 });
    }
    let parent = fixed_root().join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&parent).unwrap();
    for stage in ["success", "scope", "decline", "token", "expiry"] {
        let stage_parent = parent.join(stage);
        std::fs::create_dir_all(&stage_parent).unwrap();
        launch(stage, &validated_parent(&stage_parent, stage));
    }
    assert!(
        parent
            .canonicalize()
            .unwrap()
            .starts_with(fixed_root().canonicalize().unwrap())
    );
    std::fs::remove_dir_all(parent).unwrap();
}
fn launch(stage: &str, parent: &std::path::Path) {
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact windows::custody_sign::tests::native_console_custody_signs_only_reviewed_bundle --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_CUSTODY_NATIVE_CASE", stage.into()),
    ] {
        environment.extend(wide(OsStr::new(&format!(
            "{key}={}",
            value.to_str().unwrap()
        ))));
    }
    environment.push(0);
    // SAFETY: live terminated buffers; no inherited handles or user console.
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
                || verify_process_eligibility().is_ok(),
            ),
            0
        );
        let handle = OwnedHandle::from_raw_handle(process.hProcess);
        let _thread = OwnedHandle::from_raw_handle(process.hThread);
        if WaitForSingleObject(handle.as_raw_handle(), 20000) != WAIT_OBJECT_0 {
            TerminateProcess(handle.as_raw_handle(), 99);
            WaitForSingleObject(handle.as_raw_handle(), 5000);
            panic!("synthetic child timeout");
        }
        let mut code = 0;
        assert_ne!(GetExitCodeProcess(handle.as_raw_handle(), &mut code), 0);
        assert_eq!(code, 0, "synthetic stage {stage} failed");
    }
}

fn screen() -> String {
    let mut text = vec![0; 16000];
    let mut count = 0;
    // SAFETY: only the owned hidden child calls this with bounded output storage.
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
fn send_after(prompt: &str, text: &[u8]) {
    let start = std::time::Instant::now();
    while !screen().contains(prompt) {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "synthetic prompt missing"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for byte in text.iter().chain(std::iter::once(&b'\r')) {
        // SAFETY: child ownership is verified before spawning this injector.
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
