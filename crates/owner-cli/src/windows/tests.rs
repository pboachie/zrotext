// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
static PHASE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(10);
pub(super) fn phase(value: i32) {
    PHASE.store(value, std::sync::atomic::Ordering::SeqCst);
}
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

fn launch(stage: &str, parent: &std::path::Path) {
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact windows::tests::native_create_then_fresh_restore --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_OWNER_NATIVE_CASE", stage.into()),
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
                &mut process
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
struct Synthetic;
impl Material for Synthetic {
    fn generate(&mut self) -> Result<(RootSecret, RecoverySecret)> {
        Ok((
            RootSecret::new(Zeroizing::new([7; 32])).unwrap(),
            RecoverySecret::new(Zeroizing::new([9; 32])),
        ))
    }
}
fn context() -> PublicContext {
    PublicContext {
        account: [0xaa; 16],
        origin: "https://example.invalid".into(),
    }
}

fn create_child() {
    phase(20);
    let injector = std::thread::spawn(|| {
        send_after("Type CREATE:", b"CREATE");
        send_after("Type REVEAL", b"REVEAL");
    });
    run_init(
        context(),
        std::env::temp_dir().components().collect::<PathBuf>(),
        &mut Synthetic,
    )
    .unwrap();
    phase(21);
    injector.join().unwrap();
    assert!(screen().contains("ZTRK1-"));
    assert!(screen().contains("NOT verified"));
}
fn restore_child(stage: &str) {
    // Only the public random bundle ID comes from disk. All identity and secret
    // fixture material is independently known to this fresh test process.
    let parent = std::env::temp_dir().components().collect::<PathBuf>();
    let entries: Vec<_> = std::fs::read_dir(parent.join("zrotext-root-bundles"))
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(entries.len(), 1);
    let name = entries[0].file_name().into_string().unwrap();
    let id = hex(name.strip_prefix("bundle-").unwrap().as_bytes()).unwrap();
    let (root, recovery) = Synthetic.generate().unwrap();
    let pin = pin(&root, &context().account).unwrap();
    let expected = ExpectedIdentity {
        account_id: context().account,
        origin: context().origin,
        root_fingerprint: root_fingerprint(&pin, &context().account).unwrap(),
    };
    let fingerprint = if stage == "wrong-fingerprint" {
        "00".repeat(32)
    } else {
        display_hex(&expected.root_fingerprint)
    };
    let token =
        recovery_kit::encode_token(&recovery, &KitContext::new(expected, &pin, id).unwrap());
    drop(root);
    drop(recovery);
    let wrong_fingerprint = stage == "wrong-fingerprint";
    let wrong_token = stage == "wrong-token";
    let injector = std::thread::spawn(move || {
        send_after("independent kit:", fingerprint.as_bytes());
        if !wrong_fingerprint {
            if wrong_token {
                send_after("Enter recovery token", b"INVALID");
            } else {
                send_after("Enter recovery token", token.expose_ascii());
            }
        }
    });
    let result = run_restore_check(context(), id, parent);
    assert_eq!(result.is_ok(), stage == "restore");
    injector.join().unwrap();
    assert_eq!(screen().contains("Recovery verified"), stage == "restore");
    assert!(!screen().contains("ZTRK1-"));
}

struct FailingMaterial {
    called: bool,
}
impl Material for FailingMaterial {
    fn generate(&mut self) -> Result<(RootSecret, RecoverySecret)> {
        self.called = true;
        Err(())
    }
}
fn rejected_init(stage: &str) {
    let create = stage != "decline-create";
    let injector = std::thread::spawn(move || {
        send_after("Type CREATE:", if create { b"CREATE" } else { b"NO" })
    });
    let mut material = FailingMaterial { called: false };
    assert!(
        run_init(
            context(),
            std::env::temp_dir().components().collect::<PathBuf>(),
            &mut material
        )
        .is_err()
    );
    injector.join().unwrap();
    assert_eq!(material.called, create);
    assert!(!screen().contains("Type REVEAL"));
    assert!(!screen().contains("ZTRK1-"));
}

#[test]
fn native_create_then_fresh_restore() {
    if let Ok(stage) = std::env::var("ZT_OWNER_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            // SAFETY: verify this is the hidden, exclusively owned test console.
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
            phase(15);
            verify_process_eligibility().unwrap();
            match stage.as_str() {
                "create" => create_child(),
                "restore" | "wrong-fingerprint" | "wrong-token" => restore_child(&stage),
                "decline-create" | "rng-failure" => rejected_init(&stage),
                _ => panic!("unknown synthetic stage"),
            }
        });
        std::process::exit(if result.is_ok() {
            0
        } else {
            PHASE.load(std::sync::atomic::Ordering::SeqCst)
        });
    }
    let parent = std::env::temp_dir().join(format!(
        "zrotext-owner-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&parent).unwrap();
    launch("decline-create", &parent);
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    launch("rng-failure", &parent);
    assert_eq!(
        std::fs::read_dir(parent.join("zrotext-root-bundles"))
            .unwrap()
            .count(),
        0
    );
    launch("create", &parent);
    launch("wrong-fingerprint", &parent);
    launch("wrong-token", &parent);
    launch("restore", &parent);
    let bundles: Vec<_> = std::fs::read_dir(parent.join("zrotext-root-bundles"))
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(bundles.len(), 1);
    let files: Vec<_> = std::fs::read_dir(bundles[0].path())
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(files.len(), 2);
    for file in files {
        let bytes = std::fs::read(file.path()).unwrap();
        assert!(!bytes.windows(32).any(|w| w == [7; 32] || w == [9; 32]));
        assert!(!bytes.windows(6).any(|w| w == b"ZTRK1-"));
    }
    // Delete only the resolved, uniquely created direct TEMP child owned above.
    let resolved = parent.canonicalize().unwrap();
    let temp = std::env::temp_dir().canonicalize().unwrap();
    assert_eq!(resolved.parent(), Some(temp.as_path()));
    assert!(
        resolved
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("zrotext-owner-test-")
    );
    std::fs::remove_dir_all(resolved).unwrap();
}

#[test]
fn arguments_accept_only_the_two_bounded_commands() {
    let args: Vec<String> = [
        "init",
        "--account",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "--origin",
        "https://example.invalid",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(matches!(parse(&args), Ok(Command::Init(_))));
    let mut invalid = args.clone();
    invalid.push("--seed".into());
    assert!(parse(&invalid).is_err());
    invalid = args.clone();
    invalid[2] = invalid[2].to_uppercase();
    assert!(parse(&invalid).is_err());
    invalid = args;
    invalid[0] = "restore-check".into();
    invalid.extend(["--bundle".into(), "01".repeat(16)]);
    assert!(matches!(parse(&invalid), Ok(Command::Restore(_, _))));
}
