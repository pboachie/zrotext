// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, sync::atomic::AtomicU32};

static PHASE: AtomicU32 = AtomicU32::new(10);
fn step(phase: u32) {
    PHASE.store(phase, Ordering::SeqCst);
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

/// Test-only launcher: never inherit or attach to the caller's console/handles.
fn isolated(name: &str, run: fn()) {
    if std::env::var("ZT_TERMINAL_NATIVE_CASE").as_deref() == Ok(name) {
        let result = std::panic::catch_unwind(|| {
            // SAFETY: bounded PID list; only this isolated test child may inject.
            unsafe {
                let mut processes = [0_u32; 8];
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
            run();
        });
        std::process::exit(if result.is_ok() {
            0
        } else {
            PHASE.load(Ordering::SeqCst) as i32
        });
    }
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact windows::tests::{name} --nocapture --test-threads=1",
        executable.display()
    )));
    let mut variables = vec![
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", std::env::temp_dir().into_os_string()),
        ("ZT_TERMINAL_NATIVE_CASE", name.into()),
    ];
    variables.sort_by_key(|(key, _)| key.to_ascii_uppercase());
    let mut environment = Vec::<u16>::new();
    for (key, value) in variables {
        environment.extend(wide(OsStr::new(&format!(
            "{key}={}",
            value.to_str().unwrap()
        ))));
    }
    environment.push(0);
    // SAFETY: owned UTF-16 buffers outlive process creation; no inherited handles.
    unsafe {
        let mut startup: STARTUPINFOW = zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = 0;
        let mut process = zeroed();
        assert_ne!(
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                null(),
                &startup,
                &mut process
            ),
            0
        );
        let process_handle = OwnedHandle::from_raw_handle(process.hProcess);
        let _thread = OwnedHandle::from_raw_handle(process.hThread);
        if WaitForSingleObject(process_handle.as_raw_handle(), 20000) != WAIT_OBJECT_0 {
            TerminateProcess(process_handle.as_raw_handle(), 99);
            WaitForSingleObject(process_handle.as_raw_handle(), 5000);
            panic!("isolated synthetic console test timed out");
        }
        let mut code = 0;
        assert_ne!(
            GetExitCodeProcess(process_handle.as_raw_handle(), &mut code),
            0
        );
        assert_eq!(
            code, 0,
            "isolated synthetic case {name} failed at phase {code}"
        );
    }
}

fn input() -> HANDLE {
    unsafe { GetStdHandle(STD_INPUT_HANDLE) }
}
fn snapshot() -> Vec<u16> {
    snapshot_size(256)
}
fn snapshot_size(size: usize) -> Vec<u16> {
    let mut text = vec![0; size];
    let mut count = 0;
    // SAFETY: synthetic child-owned screen and bounded writable output buffer.
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
    assert_eq!(count as usize, size);
    text
}
fn inject(value: u16, repeat: u16) {
    // SAFETY: only called after isolated-child ownership assertion. Fully
    // initialized synthetic record; no real input or user console involved.
    unsafe {
        let mut event: INPUT_RECORD = zeroed();
        event.EventType = KEY_EVENT as u16;
        event.Event.KeyEvent.bKeyDown = 1;
        event.Event.KeyEvent.wRepeatCount = repeat;
        event.Event.KeyEvent.uChar.UnicodeChar = value;
        let mut written = 0;
        assert_ne!(WriteConsoleInputW(input(), &event, 1, &mut written), 0);
        assert_eq!(written, 1);
    }
}
fn line() {
    for value in b"SYNTHETIC\r" {
        inject(*value as u16, 1);
    }
}

fn synthetic_token() -> zrotext_root_material::recovery_kit::RecoveryToken {
    use zrotext_root_material::{
        recovery_kit::{KitContext, encode_token},
        root_backup::{ExpectedIdentity, RecoverySecret},
        sealed_root_enrollment::root_fingerprint,
    };
    let source = include_str!("../../../../protocol/v1/vectors/recovery-kit-01.json");
    let encoded = source
        .split("\"rootPinHex\": \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let pin: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let expected = ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: root_fingerprint(&pin, &[1; 16]).unwrap(),
    };
    encode_token(
        &RecoverySecret::new(Zeroizing::new([9; 32])),
        &KitContext::new(expected, &pin, [1; 16]).unwrap(),
    )
}

fn consent(value: &[u8]) {
    let value = value.to_vec();
    let baseline = String::from_utf16_lossy(&snapshot_size(2048))
        .matches("Type REVEAL")
        .count();
    std::thread::spawn(move || {
        let started = Instant::now();
        while String::from_utf16_lossy(&snapshot_size(2048))
            .matches("Type REVEAL")
            .count()
            <= baseline
        {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(5));
        }
        for b in value.iter().chain(std::iter::once(&b'\r')) {
            inject(u16::from(*b), 1);
        }
    });
}

#[test]
fn native_reveal_rejects_input_queued_before_prompt() {
    isolated("native_reveal_rejects_input_queued_before_prompt", || {
        let token = synthetic_token();
        let session = Session::acquire().unwrap();
        for b in b"REVEAL\r" {
            inject(u16::from(*b), 1);
        }
        assert_eq!(
            session.confirm_and_reveal(&token, Duration::from_secs(2)),
            Err(Error::Busy)
        );
        assert!(!String::from_utf16_lossy(&snapshot_size(2048)).contains("ZTRK1-"));
    });
}

#[test]
fn native_reveal_requires_exact_consent_and_restores() {
    isolated("native_reveal_requires_exact_consent_and_restores", || {
        let token = synthetic_token();
        let original = mode(input()).unwrap();
        let session = Session::acquire().unwrap();
        consent(b"REVEAL");
        session
            .confirm_and_reveal(&token, Duration::from_secs(2))
            .unwrap();
        assert_eq!(mode(input()).unwrap(), original);
        let snapshot = snapshot_size(2048);
        let text = String::from_utf16_lossy(&snapshot);
        assert!(text.contains(std::str::from_utf8(token.expose_ascii()).unwrap()));
    });
}

#[test]
fn native_reveal_decline_and_timeout_do_not_output_token() {
    isolated(
        "native_reveal_decline_and_timeout_do_not_output_token",
        || {
            let token = synthetic_token();
            for value in [b"reveal".as_slice(), b"NO"] {
                let session = Session::acquire().unwrap();
                consent(value);
                assert_eq!(
                    session.confirm_and_reveal(&token, Duration::from_secs(2)),
                    Err(Error::Rejected)
                );
            }
            let session = Session::acquire().unwrap();
            assert_eq!(
                session.confirm_and_reveal(&token, Duration::from_millis(10)),
                Err(Error::TimedOut)
            );
            assert!(!String::from_utf16_lossy(&snapshot()).contains("ZTRK1-"));
        },
    );
}

#[test]
fn native_partial_reveal_returns_error_without_second_output() {
    isolated(
        "native_partial_reveal_returns_error_without_second_output",
        || {
            let token = synthetic_token();
            let mut session = Session::acquire().unwrap();
            session.fault = Some(Fault::RevealAfterPrefix);
            consent(b"REVEAL");
            assert_eq!(
                session.confirm_and_reveal(&token, Duration::from_secs(2)),
                Err(Error::Io)
            );
            assert!(
                !String::from_utf16_lossy(&snapshot())
                    .contains(std::str::from_utf8(token.expose_ascii()).unwrap())
            );
        },
    );
}

#[test]
fn native_reveal_cleanup_failure_is_not_success_and_poisons() {
    isolated(
        "native_reveal_cleanup_failure_is_not_success_and_poisons",
        || {
            let token = synthetic_token();
            let mut session = Session::acquire().unwrap();
            session.fault = Some(Fault::Unregister);
            consent(b"REVEAL");
            assert_eq!(
                session.confirm_and_reveal(&token, Duration::from_secs(2)),
                Err(Error::RestorationFailed)
            );
            assert!(matches!(Session::acquire(), Err(Error::Poisoned)));
        },
    );
}

#[test]
fn native_public_finish_propagates_restoration_failure() {
    isolated(
        "native_public_finish_propagates_restoration_failure",
        || {
            let mut session = Session::acquire().unwrap();
            session.fault = Some(Fault::Unregister);
            assert_eq!(session.finish(), Err(Error::RestorationFailed));
        },
    );
}

#[test]
fn native_no_echo_and_exact_restore() {
    isolated("native_no_echo_and_exact_restore", || {
        step(11);
        let original = mode(input()).unwrap();
        let before = snapshot();
        let session = Session::acquire().unwrap();
        step(12);
        for handle in &session.handles {
            let mut flags = 0;
            unsafe {
                assert_ne!(GetHandleInformation(handle.as_raw_handle(), &mut flags), 0);
            }
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        assert_eq!(
            mode(input()).unwrap()
                & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            0
        );
        line();
        let result = session.read(128, Duration::from_secs(2)).unwrap();
        step(13);
        assert_eq!(result.expose_ascii(), b"SYNTHETIC");
        assert_eq!(mode(input()).unwrap(), original);
        assert_eq!(snapshot(), before);
    });
}

#[test]
fn native_public_prompt_and_backspace() {
    isolated("native_public_prompt_and_backspace", || {
        step(20);
        let original = mode(input()).unwrap();
        let mut session = Session::acquire().unwrap();
        session.fault = Some(Fault::ShortWrite);
        let mut screen = unsafe { zeroed() };
        unsafe {
            assert_ne!(
                GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut screen),
                0
            );
        }
        session.write_public_prompt("Synthetic prompt: ").unwrap();
        let mut prompt = [0_u16; 18];
        let mut count = 0;
        unsafe {
            assert_ne!(
                ReadConsoleOutputCharacterW(
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    prompt.as_mut_ptr(),
                    18,
                    screen.dwCursorPosition,
                    &mut count
                ),
                0
            );
        }
        assert_eq!(count, 18);
        assert_eq!(
            prompt.as_slice(),
            "Synthetic prompt: ".encode_utf16().collect::<Vec<_>>()
        );
        session.fault = None;
        let before = snapshot();
        for value in b"AB\x08C\r" {
            inject(*value as u16, 1);
        }
        let result = session.read(3, Duration::from_secs(2)).unwrap();
        assert_eq!(result.expose_ascii(), b"AC");
        assert_eq!(snapshot(), before);
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_preexisting_input_is_preserved_on_refusal() {
    isolated("native_preexisting_input_is_preserved_on_refusal", || {
        step(30);
        let original = mode(input()).unwrap();
        inject(65, 1);
        assert!(matches!(Session::acquire(), Err(Error::Busy)));
        assert_eq!(mode(input()).unwrap(), original);
        let mut count = 0;
        unsafe {
            assert_ne!(GetNumberOfConsoleInputEvents(input(), &mut count), 0);
        }
        assert_eq!(count, 1);
    });
}

#[test]
fn native_overflow_unicode_abort_and_timeout_restore() {
    isolated("native_overflow_unicode_abort_and_timeout_restore", || {
        let original = mode(input()).unwrap();
        for (index, value, repeat, expected) in [
            (0, 65, 129, Error::Rejected),
            (1, 0xd800, 1, Error::Rejected),
            (2, 3, 1, Error::Cancelled),
            (3, 27, 1, Error::Cancelled),
        ] {
            step(40 + index);
            let session = Session::acquire().unwrap();
            inject(value, repeat);
            inject(66, 1);
            assert!(
                matches!(session.read(128,Duration::from_secs(1)),Err(error) if error==expected)
            );
            assert_eq!(mode(input()).unwrap(), original);
            let mut count = 0;
            unsafe {
                GetNumberOfConsoleInputEvents(input(), &mut count);
            }
            assert_eq!(count, 0);
        }
        step(44);
        let session = Session::acquire().unwrap();
        assert!(matches!(
            session.read(1, Duration::from_millis(10)),
            Err(Error::TimedOut)
        ));
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_ctrl_break_cancels_and_restores() {
    isolated("native_ctrl_break_cancels_and_restores", || {
        step(50);
        let original = mode(input()).unwrap();
        let session = Session::acquire().unwrap();
        // Only this child belongs to this private console; group zero cannot reach parent.
        unsafe {
            assert_ne!(GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0), 0);
        }
        assert!(matches!(
            session.read(128, Duration::from_secs(2)),
            Err(Error::Cancelled)
        ));
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_changed_and_wrong_direction_handles_are_rejected() {
    isolated(
        "native_changed_and_wrong_direction_handles_are_rejected",
        || {
            step(60);
            let original = input();
            let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
            unsafe {
                assert_ne!(SetStdHandle(STD_INPUT_HANDLE, output), 0);
            }
            assert!(matches!(Session::acquire(), Err(Error::Unsupported)));
            unsafe {
                assert_ne!(SetStdHandle(STD_INPUT_HANDLE, original), 0);
            }
            let original_mode = mode(original).unwrap();
            let session = Session::acquire().unwrap();
            unsafe {
                assert_ne!(SetStdHandle(STD_INPUT_HANDLE, output), 0);
            }
            assert!(matches!(
                session.read(1, Duration::from_secs(1)),
                Err(Error::Unsupported)
            ));
            unsafe {
                assert_ne!(SetStdHandle(STD_INPUT_HANDLE, original), 0);
            }
            assert_eq!(mode(original).unwrap(), original_mode);
        },
    );
}

#[test]
fn native_each_redirected_handle_is_refused_before_mode_change() {
    isolated(
        "native_each_redirected_handle_is_refused_before_mode_change",
        || {
            use windows_sys::Win32::{Storage::FileSystem::*, System::Pipes::CreatePipe};
            step(70);
            let originals: Vec<_> = STANDARD
                .into_iter()
                .map(|h| unsafe { GetStdHandle(h) })
                .collect();
            let original_mode = mode(input()).unwrap();
            for standard in STANDARD {
                for kind in 0..3 {
                    let mut other = null_mut();
                    // SAFETY: fixture handles are owned, noninheritable and child-local.
                    let raw = unsafe {
                        if kind == 0 {
                            let mut read = null_mut();
                            assert_ne!(CreatePipe(&mut read, &mut other, null(), 0), 0);
                            read
                        } else {
                            let path = if kind == 1 {
                                std::path::PathBuf::from("NUL")
                            } else {
                                std::env::temp_dir().join(format!(
                                    "zrotext-console-empty-{}",
                                    GetCurrentProcessId()
                                ))
                            };
                            CreateFileW(
                                wide(path.as_os_str()).as_ptr(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                null(),
                                if kind == 1 { OPEN_EXISTING } else { CREATE_NEW },
                                if kind == 1 {
                                    0
                                } else {
                                    FILE_FLAG_DELETE_ON_CLOSE
                                },
                                null_mut(),
                            )
                        }
                    };
                    assert_ne!(raw, INVALID_HANDLE_VALUE);
                    let replacement = unsafe { OwnedHandle::from_raw_handle(raw) };
                    let _other = if other.is_null() {
                        None
                    } else {
                        Some(unsafe { OwnedHandle::from_raw_handle(other) })
                    };
                    unsafe {
                        assert_ne!(SetStdHandle(standard, replacement.as_raw_handle()), 0);
                    }
                    assert!(matches!(Session::acquire(), Err(Error::Unsupported)));
                    for (index, handle) in STANDARD.into_iter().enumerate() {
                        unsafe {
                            assert_ne!(SetStdHandle(handle, originals[index]), 0);
                        }
                    }
                    assert_eq!(mode(input()).unwrap(), original_mode);
                }
            }
        },
    );
}

#[test]
fn native_missing_console_is_refused() {
    isolated("native_missing_console_is_refused", || {
        step(80);
        unsafe {
            assert_ne!(FreeConsole(), 0);
        }
        assert!(matches!(Session::acquire(), Err(Error::Unsupported)));
    });
}

#[test]
fn native_api_faults_discard_input_and_restore() {
    isolated("native_api_faults_discard_input_and_restore", || {
        step(90);
        let original = mode(input()).unwrap();
        assert!(matches!(
            Session::acquire_inner(Some(Fault::SetMode)),
            Err(Error::Io)
        ));
        assert_eq!(mode(input()).unwrap(), original);
        let session = Session::acquire_inner(Some(Fault::Read)).unwrap();
        line();
        assert!(matches!(
            session.read(128, Duration::from_secs(1)),
            Err(Error::Io)
        ));
        assert_eq!(mode(input()).unwrap(), original);
        let mut session = Session::acquire_inner(Some(Fault::Write)).unwrap();
        assert_eq!(session.write_public_prompt("Synthetic"), Err(Error::Io));
        line();
        assert!(matches!(
            session.read(128, Duration::from_secs(1)),
            Err(Error::Rejected)
        ));
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_restore_failure_never_releases_input_and_poisons() {
    isolated(
        "native_restore_failure_never_releases_input_and_poisons",
        || {
            step(100);
            let session = Session::acquire_inner(Some(Fault::Restore)).unwrap();
            line();
            assert!(matches!(
                session.read(128, Duration::from_secs(1)),
                Err(Error::RestorationFailed)
            ));
            assert!(matches!(Session::acquire(), Err(Error::Poisoned)));
        },
    );
}

#[test]
fn native_handler_cleanup_failure_never_releases_input() {
    isolated(
        "native_handler_cleanup_failure_never_releases_input",
        || {
            step(110);
            let session = Session::acquire_inner(Some(Fault::Unregister)).unwrap();
            line();
            assert!(matches!(
                session.read(128, Duration::from_secs(1)),
                Err(Error::RestorationFailed)
            ));
            assert!(matches!(Session::acquire(), Err(Error::Poisoned)));
        },
    );
}

#[test]
fn native_drop_restores_and_second_acquire_is_busy() {
    isolated("native_drop_restores_and_second_acquire_is_busy", || {
        step(120);
        let original = mode(input()).unwrap();
        let session = Session::acquire().unwrap();
        assert!(matches!(Session::acquire(), Err(Error::Busy)));
        drop(session);
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_unwind_restores_input_mode() {
    isolated("native_unwind_restores_input_mode", || {
        step(130);
        let original = mode(input()).unwrap();
        let result = std::panic::catch_unwind(|| {
            let _session = Session::acquire().unwrap();
            panic!("synthetic unwind");
        });
        assert!(result.is_err());
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn native_event_budget_is_bounded() {
    isolated("native_event_budget_is_bounded", || {
        step(140);
        let original = mode(input()).unwrap();
        let session = Session::acquire().unwrap();
        unsafe {
            let mut event: INPUT_RECORD = zeroed();
            event.EventType = FOCUS_EVENT as u16;
            let events = vec![event; 4097];
            let mut written = 0;
            assert_ne!(
                WriteConsoleInputW(input(), events.as_ptr(), events.len() as u32, &mut written),
                0
            );
            assert_eq!(written, 4097);
        }
        assert!(matches!(
            session.read(1, Duration::from_secs(5)),
            Err(Error::Rejected)
        ));
        assert_eq!(mode(input()).unwrap(), original);
    });
}

#[test]
fn missing_nonblocking_export_has_no_fallback() {
    assert!(matches!(
        resolve_reader(c"ZrotextSyntheticMissingConsoleExport"),
        Err(Error::Unsupported)
    ));
}

#[test]
fn native_changed_mode_and_invalid_limits_do_not_release_input() {
    isolated(
        "native_changed_mode_and_invalid_limits_do_not_release_input",
        || {
            step(150);
            let original = mode(input()).unwrap();
            let session = Session::acquire().unwrap();
            unsafe {
                assert_ne!(
                    SetConsoleMode(
                        input(),
                        mode(input()).unwrap() | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT
                    ),
                    0
                );
            }
            line();
            assert!(matches!(
                session.read(128, Duration::from_secs(1)),
                Err(Error::Unsupported)
            ));
            assert_eq!(mode(input()).unwrap(), original);
            for (limit, timeout) in [
                (0, Duration::from_secs(1)),
                (129, Duration::from_secs(1)),
                (1, Duration::ZERO),
                (1, Duration::from_secs(301)),
            ] {
                let session = Session::acquire().unwrap();
                line();
                assert!(matches!(session.read(limit, timeout), Err(Error::Rejected)));
                assert_eq!(mode(input()).unwrap(), original);
            }
        },
    );
}
