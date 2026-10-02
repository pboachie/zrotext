// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic keys and a hidden, exclusively owned limited-token console only.
use super::*;
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

#[path = "../../../../root-material/src/line_key_registration/fixture.rs"]
mod fixture;
fn child(stage: &'static str, parent: PathBuf) {
    crate::native_process::assert_current_process_limited();
    verify_process_eligibility().unwrap();
    unsafe {
        let mut processes = [0; 8];
        assert_eq!(GetConsoleProcessList(processes.as_mut_ptr(), 8), 1);
        assert_eq!(processes[0], GetCurrentProcessId());
        let mut startup = zeroed();
        GetStartupInfoW(&mut startup);
        assert_eq!(startup.dwFlags & STARTF_USESHOWWINDOW, STARTF_USESHOWWINDOW);
        assert_eq!(startup.wShowWindow, 0);
        assert_eq!(
            windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible(GetConsoleWindow()),
            0
        );
    }
    let now = now_millis().unwrap();
    let (mut expected, statement, bytes) = fixture::fixture(
        now,
        now + if matches!(stage, "expiry" | "expired-output") {
            2000
        } else {
            120000
        },
    );
    let identity = expected.identity.clone();
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
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
    let proposal = parent.join("proposal.bin");
    std::fs::write(&proposal, &bytes).unwrap();
    let output = parent.join("signature.bin");
    if stage == "existing" {
        std::fs::write(&output, b"existing-public-fixture").unwrap();
    }
    if matches!(stage, "cancel-output" | "expired-output") {
        let session = Session::acquire().unwrap();
        let signature = registration::inspect(&statement, &expected, now)
            .unwrap()
            .sign(&root, now)
            .unwrap();
        drop(root);
        drop(recovery);
        if stage == "cancel-output" {
            unsafe {
                assert_ne!(GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0), 0);
            }
            std::thread::sleep(Duration::from_millis(100));
        } else {
            std::thread::sleep(Duration::from_millis(2200));
        }
        assert!(
            publish(
                &signature,
                &statement,
                &expected,
                session,
                output.to_str().unwrap()
            )
            .is_err()
        );
        assert!(!output.exists());
        assert!(!screen().contains("RootLineRegister signature (raw64"));
    } else {
        drop(root);
        drop(recovery);
        if stage == "scope" {
            expected.scope.paired_signing_fingerprint = [9; 32];
        }
        if stage == "approval" {
            expected.scope.approval_fingerprint = [9; 32];
        }
        let s = &expected.scope;
        let values: Vec<String> = vec![
            uuid::Uuid::from_bytes(s.account).to_string(),
            s.origin.clone(),
            display_hex(&identity.root_fingerprint),
            display_hex(&id),
            proposal.to_str().unwrap().into(),
            output.to_str().unwrap().into(),
            uuid::Uuid::from_bytes(s.user).to_string(),
            uuid::Uuid::from_bytes(s.owner_session).to_string(),
            uuid::Uuid::from_bytes(s.device).to_string(),
            uuid::Uuid::from_bytes(s.line).to_string(),
            s.next_generation.to_string(),
            uuid::Uuid::from_bytes(s.challenge).to_string(),
            display_hex(&s.nonce),
            s.issued_ms.to_string(),
            s.expires_ms.to_string(),
            display_hex(&s.approval_fingerprint),
            display_hex(&s.paired_signing_fingerprint),
            s.connection_epoch.to_string(),
            s.deployment_epoch.to_string(),
            s.site_id.clone(),
            s.instance_id.clone(),
        ];
        let mut args = vec!["line-key-registration".into()];
        for (flag, value) in FLAGS.into_iter().zip(values) {
            args.extend([flag.into(), value]);
        }
        assert!(parse(&args[..41]).is_err());
        let mut bad = args.clone();
        bad.swap(1, 3);
        assert!(parse(&bad).is_err());
        let mut bad = args.clone();
        bad[6] = String::new();
        assert!(parse(&bad).is_err());
        let fingerprint = display_hex(&identity.root_fingerprint);
        let sender = std::thread::spawn(move || {
            send_after("Enter full lowercase fingerprint", fingerprint.as_bytes());
            if matches!(stage, "scope" | "approval") {
                return;
            }
            send_after(
                "Type REGISTER-LINE-KEY",
                if stage == "decline" {
                    b"DECLINE"
                } else {
                    b"REGISTER-LINE-KEY"
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
        if stage == "success" {
            let signature = std::fs::read(&output).unwrap();
            assert_eq!(signature.len(), 64);
            statement.verify_root(&signature).unwrap();
            assert!(screen().contains(&display_hex(&signature)));
            assert!(screen().contains("Public RootLineRegister raw64"));
        } else if stage == "existing" {
            assert_eq!(std::fs::read(&output).unwrap(), b"existing-public-fixture");
            assert!(!screen().contains("RootLineRegister signature (raw64"));
        } else {
            assert!(!output.exists());
            assert!(!screen().contains("RootLineRegister signature (raw64"));
        }
    }
    assert!(!screen().contains("ZTRK1-"));
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
        .join("tmp-native-line-key")
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
fn native_console_registration_requires_independent_scope_and_fresh_publication() {
    if let Ok(stage) = std::env::var("ZT_LINE_REGISTRATION_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let stage = match stage.as_str() {
                "success" => "success",
                "scope" => "scope",
                "approval" => "approval",
                "decline" => "decline",
                "token" => "token",
                "expiry" => "expiry",
                "existing" => "existing",
                "cancel-output" => "cancel-output",
                "expired-output" => "expired-output",
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
        "success",
        "scope",
        "approval",
        "decline",
        "token",
        "expiry",
        "existing",
        "cancel-output",
        "expired-output",
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
        "\"{}\" --exact windows::line_key_registration::tests::native_console_registration_requires_independent_scope_and_fresh_publication --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_LINE_REGISTRATION_NATIVE_CASE", stage.into()),
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
