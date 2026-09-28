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

/// Fixed per-user root for test directories: `AppData\Local\Temp` under the
/// account's profile directory, resolved from the process token by the OS
/// rather than from the TEMP/TMP environment, so every test path descends
/// from a controlled root. Children receive the directory created here as TEMP.
fn test_root() -> PathBuf {
    use std::os::windows::{ffi::OsStringExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::GetUserProfileDirectoryW,
    };
    // SAFETY: the token handle is owned and closed on drop; the profile path
    // is written into a caller-sized buffer whose returned length is bounded.
    let profile = unsafe {
        let mut raw = std::mem::MaybeUninit::uninit();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, raw.as_mut_ptr()),
            0
        );
        let token = std::os::windows::io::OwnedHandle::from_raw_handle(raw.assume_init());
        let mut buffer = vec![0_u16; 1024];
        let mut length = buffer.len() as u32;
        assert_ne!(
            GetUserProfileDirectoryW(
                std::os::windows::io::AsRawHandle::as_raw_handle(&token),
                buffer.as_mut_ptr(),
                &mut length
            ),
            0,
            "resolve the profile directory"
        );
        let length = buffer
            .iter()
            .take(length as usize)
            .take_while(|&&c| c != 0)
            .count();
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]))
    };
    let root = profile.join("AppData").join("Local").join("Temp");
    std::fs::create_dir_all(&root).unwrap();
    root
}
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

/// Synthetic unlock material matching the Synthetic generator and kit context.
#[cfg(feature = "unlock")]
fn unlock_material() -> (RootSecret, RecoverySecret, ExpectedIdentity) {
    let (root, recovery) = Synthetic.generate().unwrap();
    let pin = pin(&root, &context().account).unwrap();
    let expected = ExpectedIdentity {
        account_id: context().account,
        origin: context().origin,
        root_fingerprint: root_fingerprint(&pin, &context().account).unwrap(),
    };
    (root, recovery, expected)
}

/// Synthetic public challenge for the expected identity (or a different
/// account when one is supplied), valid around the current local clock.
#[cfg(feature = "unlock")]
fn unlock_challenge(expected: &ExpectedIdentity, account: [u8; 16]) -> Vec<u8> {
    let now = now_millis().unwrap();
    zrotext_root_material::sealed_root_enrollment::encode(
        &zrotext_root_material::sealed_root_enrollment::Challenge {
            account_id: account,
            user_id: [2; 16],
            session_id: [3; 16],
            challenge_id: [4; 16],
            nonce: [5; 32],
            root_fingerprint: expected.root_fingerprint,
            issued_ms: now.saturating_sub(1).max(1),
            expires_ms: now + 299_000,
            origin: expected.origin.clone(),
        },
    )
    .unwrap()
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

/// Fresh-process unlock ceremony against the bundle the create stage left.
/// Only the public bundle ID comes from disk; identity, kit and challenge
/// fixtures are independently known to this process.
#[cfg(feature = "unlock")]
fn unlock_child(stage: &str) {
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
    let wrong_challenge = stage == "unlock-wrong-challenge";
    let wrong_token = stage == "unlock-wrong-token";
    let unsigned = unlock_challenge(
        &expected,
        if wrong_challenge {
            [0xbb; 16]
        } else {
            expected.account_id
        },
    );
    let challenge_path = std::env::temp_dir().join("zrotext-owner-unlock-challenge.ztre");
    std::fs::write(&challenge_path, &unsigned).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(expected.clone(), &pin, id).unwrap(),
    );
    drop(root);
    drop(recovery);
    let fingerprint = display_hex(&expected.root_fingerprint);
    let injector = std::thread::spawn(move || {
        send_after("independent kit:", fingerprint.as_bytes());
        if wrong_challenge {
            return;
        }
        send_after("Type UNLOCK", b"UNLOCK");
        if wrong_token {
            send_after("Enter recovery token", b"INVALID");
        } else {
            send_after("Enter recovery token", token.expose_ascii());
        }
    });
    let result = run_unlock(
        context(),
        id,
        challenge_path.to_str().unwrap().to_string(),
        parent,
    );
    injector.join().unwrap();
    let screen = screen();
    if stage == "unlock" {
        assert!(result.is_ok());
        assert!(screen.contains("No enrollment, unlock state or file was created."));
        // Transcribe the public signature from the screen and verify it with
        // the public enrollment codec, exactly like a receiving ceremony would.
        let shown = screen.split("Signature: ").nth(1).expect("signature shown");
        let hex: String = shown
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            .collect();
        assert_eq!(hex.len(), 128);
        let mut signature = [0_u8; 64];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            signature[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        let parsed = zrotext_root_material::sealed_root_enrollment::parse(&unsigned).unwrap();
        zrotext_root_material::sealed_root_enrollment::verify(
            &pin,
            &unsigned,
            &signature,
            &parsed,
            now_millis().unwrap(),
        )
        .unwrap();
    } else {
        assert!(result.is_err());
        assert!(!screen.contains("Signature: "));
        if wrong_challenge {
            // The unbound challenge is refused before any secret is requested.
            assert!(!screen.contains("Type UNLOCK"));
            assert!(!screen.contains("Enter recovery token"));
        }
    }
    assert!(!screen.contains("ZTRK1-"));
    std::fs::remove_file(&challenge_path).unwrap();
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
            phase(14);
            crate::native_process::assert_current_process_limited();
            phase(15);
            verify_process_eligibility().unwrap();
            match stage.as_str() {
                "create" => create_child(),
                "restore" | "wrong-fingerprint" | "wrong-token" => restore_child(&stage),
                "decline-create" | "rng-failure" => rejected_init(&stage),
                #[cfg(feature = "unlock")]
                "unlock" | "unlock-wrong-challenge" | "unlock-wrong-token" => unlock_child(&stage),
                _ => panic!("unknown synthetic stage"),
            }
        });
        std::process::exit(if result.is_ok() {
            0
        } else {
            PHASE.load(std::sync::atomic::Ordering::SeqCst)
        });
    }
    let parent = test_root().join(format!(
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
    #[cfg(feature = "unlock")]
    {
        launch("unlock", &parent);
        launch("unlock-wrong-challenge", &parent);
        launch("unlock-wrong-token", &parent);
    }
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
    // Delete only the resolved, uniquely created direct child of the test root.
    let resolved = parent.canonicalize().unwrap();
    let temp = test_root().canonicalize().unwrap();
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
    // Disabled-by-default proof: the default build refuses the unlock command
    // word outright; only a deliberate --features unlock build accepts it.
    #[cfg(not(feature = "unlock"))]
    {
        let mut refused = invalid.clone();
        refused[0] = "unlock".into();
        refused.extend(["--challenge".into(), "C:\\<challenge>".into()]);
        assert!(parse(&refused).is_err());
    }
}

#[cfg(feature = "unlock")]
#[test]
fn unlock_arguments_and_challenge_reads_stay_bounded() {
    let account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let bundle = "01".repeat(16);
    let args: Vec<String> = [
        "unlock",
        "--account",
        account,
        "--origin",
        "https://example.invalid",
        "--bundle",
        bundle.as_str(),
        "--challenge",
        "C:\\<challenge>",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(matches!(parse(&args), Ok(Command::Unlock(_, _, _))));
    for refusal in [
        // Missing or misplaced flags never parse.
        {
            let mut short = args.clone();
            short.truncate(7);
            short
        },
        {
            let mut misplaced = args.clone();
            misplaced[7] = "--seed".into();
            misplaced
        },
        {
            let mut extra = args.clone();
            extra.push("--extra".into());
            extra
        },
    ] {
        assert!(parse(&refusal).is_err());
    }
    // Public challenge reads: bounded, exact-frame only, fail closed.
    let (_root, _recovery, expected) = unlock_material();
    let unsigned = unlock_challenge(&expected, expected.account_id);
    let directory = std::env::temp_dir();
    let challenge = directory.join(format!(
        "zrotext-owner-unlock-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&challenge, &unsigned).unwrap();
    let path = challenge.to_str().unwrap().to_string();
    assert_eq!(read_challenge(&path).unwrap(), unsigned);
    // A trailing byte stays inside the read bound and is rejected by parsing.
    let mut trailing = unsigned.clone();
    trailing.push(0);
    std::fs::write(&challenge, &trailing).unwrap();
    assert_eq!(read_challenge(&path).unwrap(), trailing);
    assert_eq!(
        zrotext_root_material::root_unlock::inspect_challenge(
            &trailing,
            &expected,
            now_millis().unwrap()
        )
        .unwrap_err(),
        zrotext_root_material::root_unlock::UnlockError::InvalidInput
    );
    // Oversize and undersize files are rejected without trusting their length.
    std::fs::write(&challenge, [0_u8; 664]).unwrap();
    assert!(read_challenge(&path).is_err());
    std::fs::write(&challenge, &unsigned[..151]).unwrap();
    assert!(read_challenge(&path).is_err());
    std::fs::remove_file(&challenge).unwrap();
    // Relative, non-drive-letter and empty paths are all refused. UNC and
    // network spellings take the same non-drive-letter branch.
    for refused in ["challenge.ztre", "1:\\challenge.ztre", ""] {
        assert!(read_challenge(refused).is_err());
    }
}
