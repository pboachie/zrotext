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

struct FixtureMaterial {
    calls: usize,
}
impl ArchiveMaterial for FixtureMaterial {
    fn generate(&mut self) -> Result<(ArchiveSecret, ArchiveRecoverySecret)> {
        self.calls += 1;
        let mut scalar = [0; 32];
        scalar[31] = 3;
        Ok((
            ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
            ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
        ))
    }
}
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
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    let root_pin = pin(&root, &[1; 16]).unwrap();
    let identity = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://owner.invalid".into(),
        root_fingerprint: zrotext_root_material::sealed_root_enrollment::root_fingerprint(
            &root_pin, &[1; 16],
        )
        .unwrap(),
    };
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card =
        recovery_kit::encode_public_card(&root_pin, &identity, &Sha256::digest(&backup).into())
            .unwrap();
    let bundle = EncryptedBundle::new(&backup, &card, &identity).unwrap();
    let store = Store::open(&parent).unwrap();
    store.publish(&bundle).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &root_pin, id).unwrap(),
    );
    drop(root);
    drop(recovery);
    let archive = parent.join("archive.bin");
    let receipt = parent.join("receipt.txt");
    let private = if stage == "permission" {
        parent.join("restricted").join("recovery.bin")
    } else {
        parent.join("recovery.bin")
    };
    if stage == "permission" {
        std::fs::create_dir(private.parent().unwrap()).unwrap();
        storage::fixture_directory_permissions(private.parent().unwrap(), false);
    }
    if stage == "existing" {
        std::fs::write(&private, b"existing").unwrap();
    }
    let values = [
        uuid::Uuid::from_bytes(identity.account_id).to_string(),
        identity.origin.clone(),
        display_hex(&id),
        archive.to_str().unwrap().into(),
        receipt.to_str().unwrap().into(),
        private.to_str().unwrap().into(),
    ];
    let mut args = vec!["archive-init".into()];
    for (flag, value) in FLAGS.into_iter().zip(values) {
        args.extend([flag.into(), value]);
    }
    assert!(parse(&args[..11]).is_err());
    let mut bad = args.clone();
    bad[12] = bad[8].clone();
    assert!(parse(&bad).is_err());
    if stage == "cancel" {
        let mut material = FixtureMaterial { calls: 0 };
        let (secret, recovery) = material.generate().unwrap();
        let prepared = archive_init::prepare(secret, recovery, &identity, &root_pin).unwrap();
        let mut session = Session::acquire().unwrap();
        let result = storage::Outputs::reserve(
            archive.to_str().unwrap(),
            receipt.to_str().unwrap(),
            private.to_str().unwrap(),
        )
        .unwrap()
        .publish(&prepared, &mut |boundary| {
            if matches!(boundary, storage::Boundary::Commit) {
                unsafe {
                    assert_ne!(GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0), 0);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            session
                .write_public_prompt("")
                .map_err(|_| zrotext_root_bundle::Error::Storage)
        });
        assert!(result.is_err());
        assert!(!archive.exists() && !receipt.exists() && !private.exists());
        drop(prepared);
    } else {
        let fingerprint = display_hex(&identity.root_fingerprint);
        let sender = std::thread::spawn(move || {
            send_after("Enter full lowercase fingerprint", fingerprint.as_bytes());
            send_after(
                "Type CREATE-ARCHIVE",
                if stage == "decline" {
                    b"DECLINE"
                } else {
                    b"CREATE-ARCHIVE"
                },
            );
            if stage == "decline" {
                return;
            }
            send_after(
                "Type SAVE-RECOVERY",
                if stage == "save" {
                    b"DECLINE"
                } else {
                    b"SAVE-RECOVERY"
                },
            );
            if stage == "save" {
                return;
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
        let mut material = FixtureMaterial { calls: 0 };
        let result = run_with_material(parse(&args).unwrap(), parent.clone(), &mut material);
        sender.join().unwrap();
        assert_eq!(
            result.is_ok(),
            matches!(stage, "success" | "decline" | "save")
        );
        assert_eq!(material.calls, usize::from(stage == "success"));
        if stage == "success" {
            let encrypted = std::fs::read(&archive).unwrap();
            let private_bytes = Zeroizing::new(std::fs::read(&private).unwrap());
            assert_eq!(private_bytes.len(), 32);
            assert_eq!(private_bytes.as_slice(), [8; 32]);
            storage::assert_protected(&private);
            let mut scalar = [0; 32];
            scalar[31] = 3;
            let prepared = archive_init::prepare(
                ArchiveSecret::new(Zeroizing::new(scalar)).unwrap(),
                ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
                &identity,
                &root_pin,
            )
            .unwrap();
            zrotext_root_material::archive_backup::open(
                &encrypted,
                &ArchiveRecoverySecret::new(Zeroizing::new([8; 32])),
                prepared.identity(),
            )
            .unwrap();
            let public = std::fs::read_to_string(&receipt).unwrap();
            assert!(public.contains(&display_hex(&prepared.identity().archive_id)));
            assert!(public.contains(&display_hex(&prepared.identity().archive_point)));
            assert!(screen().contains("published once after authenticated"));
        } else {
            assert!(!archive.exists() && !receipt.exists());
            if stage == "existing" {
                assert_eq!(std::fs::read(&private).unwrap(), b"existing");
            } else {
                assert!(!private.exists());
            }
        }
    }
    if stage == "permission" {
        storage::fixture_directory_permissions(private.parent().unwrap(), true);
    }
    let text = screen();
    assert!(!text.contains("ZTRK1-"));
    assert!(!text.contains(&display_hex(&[8; 32])));
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
        .join("tmp-native-archive-init")
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
fn native_console_archive_requires_separate_consent_and_protected_recovery() {
    if let Ok(stage) = std::env::var("ZT_ARCHIVE_INIT_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let stage = match stage.as_str() {
                "success" => "success",
                "decline" => "decline",
                "save" => "save",
                "token" => "token",
                "existing" => "existing",
                "permission" => "permission",
                "cancel" => "cancel",
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
        "decline",
        "save",
        "token",
        "existing",
        "permission",
        "cancel",
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
        "\"{}\" --exact windows::archive_init::tests::native_console_archive_requires_separate_consent_and_protected_recovery --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_ARCHIVE_INIT_NATIVE_CASE", stage.into()),
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
