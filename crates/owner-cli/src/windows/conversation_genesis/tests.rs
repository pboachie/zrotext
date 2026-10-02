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
#[path = "../../../../root-material/src/conversation_genesis/fixture.rs"]
mod fixture;
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
    let now = now_millis().unwrap();
    let (root, mut expected, proposal, unsigned) =
        fixture::fixture(now, now + if stage == "expiry" { 2000 } else { 120000 });
    let identity = expected.identity.clone();
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card = recovery_kit::encode_public_card(
        &expected.root_pin,
        &identity,
        &Sha256::digest(&backup).into(),
    )
    .unwrap();
    let bundle = EncryptedBundle::new(&backup, &card, &identity).unwrap();
    let store = Store::open(&parent).unwrap();
    store.publish(&bundle).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &expected.root_pin, id).unwrap(),
    );
    drop(root);
    drop(recovery);
    let proposal_path = parent.join("proposal.bin");
    std::fs::write(&proposal_path, &proposal).unwrap();
    let output_path = parent.join("signed.bin");
    if stage == "scope" {
        expected.scope.peer = "+13".into();
    }
    if stage == "point" {
        expected.phone_reader = expected.archive_reader;
    }
    if stage == "existing" {
        std::fs::write(&output_path, b"existing-public-fixture").unwrap();
    }
    let s = &expected.scope;
    let values: Vec<String> = vec![
        uuid::Uuid::from_bytes(s.account).to_string(),
        s.origin.clone(),
        display_hex(&id),
        proposal_path.to_str().unwrap().into(),
        output_path.to_str().unwrap().into(),
        uuid::Uuid::from_bytes(s.session).to_string(),
        uuid::Uuid::from_bytes(s.device).to_string(),
        uuid::Uuid::from_bytes(s.line).to_string(),
        display_hex(&s.device_signing_fingerprint),
        s.generation.to_string(),
        s.peer.clone(),
        display_hex(&expected.phone_reader),
        display_hex(&expected.archive_reader),
        display_hex(&expected.phone_signer),
        s.issued_ms.to_string(),
        s.expires_ms.to_string(),
    ];
    let mut args = vec!["conversation-genesis".into()];
    for (flag, value) in FLAGS.into_iter().zip(values) {
        args.extend([flag.into(), value]);
    }
    // Missing/reordered flags and missing independent points fail before IO.
    assert!(parse(&args[..args.len() - 2]).is_err());
    let mut bad = args.clone();
    bad.swap(1, 3);
    assert!(parse(&bad).is_err());
    let mut bad = args.clone();
    bad[24] = String::new();
    assert!(parse(&bad).is_err());
    let fingerprint = display_hex(&identity.root_fingerprint);
    let sender = std::thread::spawn(move || {
        send_after("Enter full lowercase fingerprint", fingerprint.as_bytes());
        if matches!(stage, "scope" | "point") {
            return;
        }
        send_after(
            "Type APPROVE-GENESIS",
            if stage == "decline" {
                b"DECLINE"
            } else {
                b"APPROVE-GENESIS"
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
    let result = run(&args, parent.clone());
    sender.join().unwrap();
    assert_eq!(result.is_ok(), matches!(stage, "success" | "decline"));
    let screen = screen();
    assert!(!screen.contains("ZTRK1-"));
    if stage == "success" {
        let signed = std::fs::read(&output_path).unwrap();
        assert_eq!(&signed[..747], unsigned);
        let signature = Signature::from_slice(&signed[747..]).unwrap();
        assert_eq!(signature.normalize_s().to_bytes(), signature.to_bytes());
        let transcript = [
            b"ZTSE/manifest/v2\0".as_slice(),
            &(unsigned.len() as u32).to_be_bytes(),
            &unsigned,
        ]
        .concat();
        VerifyingKey::from_sec1_bytes(&expected.root_pin[29..])
            .unwrap()
            .verify(&transcript, &signature)
            .unwrap();
        assert!(screen.contains("Public signed first manifest written once"));
    } else if stage == "existing" {
        assert_eq!(
            std::fs::read(&output_path).unwrap(),
            b"existing-public-fixture"
        );
    } else {
        assert!(!output_path.exists());
    }
    if matches!(stage, "scope" | "point" | "decline") {
        assert!(!screen.contains("Enter recovery token"));
    }
    assert_eq!(
        store
            .read_bundle(&id, &identity)
            .unwrap()
            .encrypted_backup(),
        backup
    );
}
fn fixed_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-native-genesis")
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
fn native_console_genesis_requires_independent_points_and_scope() {
    if let Ok(stage) = std::env::var("ZT_GENESIS_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let stage = match stage.as_str() {
                "success" => "success",
                "scope" => "scope",
                "decline" => "decline",
                "token" => "token",
                "expiry" => "expiry",
                "point" => "point",
                "existing" => "existing",
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
    for stage in [
        "success", "scope", "point", "decline", "token", "expiry", "existing",
    ] {
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
        "\"{}\" --exact windows::conversation_genesis::tests::native_console_genesis_requires_independent_points_and_scope --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_GENESIS_NATIVE_CASE", stage.into()),
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
