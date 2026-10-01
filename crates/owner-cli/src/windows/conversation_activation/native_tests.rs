// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic keys and a hidden, exclusively owned limited-token console only.
use super::*;
#[path = "../native_fixture_path.rs"]
mod fixture_path;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
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
fn scope_fingerprint(pin: &[u8]) -> [u8; 32] {
    root_fingerprint(pin, &[1; 16]).unwrap()
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn signing(n: u8) -> SigningKey {
    let mut b = [0; 32];
    b[31] = n;
    SigningKey::from_slice(&b).unwrap()
}
fn point(n: u8) -> [u8; 65] {
    signing(n)
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn id(role: u8, n: u8) -> [u8; 32] {
    hash(
        &[
            b"ZTSE/key/v1\0".as_slice(),
            if role <= 3 { &[0, 16] } else { &[1, 1] },
            &point(n),
        ]
        .concat(),
    )
}
fn record(role: u8, n: u8, from: u64, until: u64) -> Vec<u8> {
    let device = if matches!(role, 1 | 4) {
        [4; 16]
    } else {
        [0; 16]
    };
    let line = if matches!(role, 1 | 4 | 5) {
        [5; 16]
    } else {
        [0; 16]
    };
    let scope: u16 = match role {
        1 => 4,
        2 => 12,
        4 => 2,
        5 => 1,
        _ => 0,
    };
    [
        &[role],
        id(role, n).as_slice(),
        &point(n),
        &device,
        &line,
        &scope.to_be_bytes(),
        &from.to_be_bytes(),
        &until.to_be_bytes(),
        &[1],
    ]
    .concat()
}
fn header(version: u64, issued: u64, expires: u64, digest: [u8; 32], count: u8) -> Vec<u8> {
    [
        b"ZTMA\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &version.to_be_bytes(),
        &issued.to_be_bytes(),
        &expires.to_be_bytes(),
        &digest,
        &point(1),
        &[count],
    ]
    .concat()
}
fn wrapper(s: &Scope, before: &[u8], after: &[u8]) -> Vec<u8> {
    let mut b = b"ZTCA\x01".to_vec();
    for v in [s.account, s.session, s.device, s.line] {
        b.extend(v);
    }
    b.extend(s.line_generation.to_be_bytes());
    b.push(s.peer.len() as u8);
    b.extend(s.peer.as_bytes());
    b.extend((s.origin.len() as u16).to_be_bytes());
    b.extend(s.origin.as_bytes());
    b.extend(s.fingerprint);
    b.extend(s.predecessor_version.to_be_bytes());
    for v in [
        s.predecessor_digest,
        s.phone_reader,
        s.archive_reader,
        s.phone_signer,
    ] {
        b.extend(v);
    }
    b.extend(s.issued_ms.to_be_bytes());
    for v in [before, after] {
        b.extend((v.len() as u16).to_be_bytes());
        b.extend(v);
    }
    b
}
fn child(stage: &str, parent: PathBuf) {
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
    // External clock/artifact are synthetic test-process inputs only; Expected below
    // is recomputed independently from the fixed fixture scope and records.
    let interop = stage == "interop";
    let now = if interop {
        std::env::var("ZT_ACTIVATION_INTEROP_NOW")
            .unwrap()
            .parse::<u64>()
            .unwrap()
    } else {
        now_millis().unwrap()
    };

    let expires = now + 3_600_000;
    let issued = now - 1000;
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
    let bundle_id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card = recovery_kit::encode_public_card(&pin, &identity, &hash(&backup)).unwrap();
    let bundle = EncryptedBundle::new(&backup, &card, &identity).unwrap();
    let store = Store::open(&parent).unwrap();
    store.publish(&bundle).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &pin, bundle_id).unwrap(),
    );
    drop(root);
    drop(recovery);
    let mut before = header(7, issued, expires, [9; 32], 4);
    for (role, n) in [(1, 2), (2, 3), (4, 4), (6, 1)] {
        before.extend(record(role, n, issued, expires));
    }
    let digest = hash(&before);
    let signature: Signature = signing(1).sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(before.len() as u32).to_be_bytes(),
            &before,
        ]
        .concat(),
    );
    before.extend(signature.normalize_s().to_bytes());
    let scope = Scope {
        account: [1; 16],
        session: [2; 16],
        device: [4; 16],
        line: [5; 16],
        line_generation: 1,
        peer: "+12".into(),
        origin: identity.origin.clone(),
        fingerprint: identity.root_fingerprint,
        predecessor_version: 7,
        predecessor_digest: digest,
        phone_reader: id(1, 2),
        archive_reader: id(2, 3),
        phone_signer: id(4, 4),
        issued_ms: now,
    };
    let mut after = header(8, now, expires, digest, 4);
    for (role, n) in [(1, 2), (2, 3), (4, 4), (6, 1)] {
        after.extend(record(role, n, issued, expires));
    }
    let proposal_path = parent.join("proposal.bin");
    let proposal = if interop {
        {
            let value = std::env::var("ZT_ACTIVATION_INTEROP_PROPOSAL_HEX").unwrap();
            assert!(value.len() <= refresh::MAX_PROPOSAL * 2 && value.len().is_multiple_of(2));
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| hex::<1>(pair).unwrap()[0])
                .collect::<Vec<_>>()
        }
    } else {
        wrapper(&scope, &before, &after)
    };
    std::fs::write(&proposal_path, proposal).unwrap();
    let output_path = parent.join("signed.bin");
    let values = vec![
        uuid::Uuid::from_bytes(scope.account).to_string(),
        scope.origin.clone(),
        display_hex(&bundle_id),
        proposal_path.to_str().unwrap().into(),
        output_path.to_str().unwrap().into(),
        uuid::Uuid::from_bytes(scope.session).to_string(),
        uuid::Uuid::from_bytes(scope.device).to_string(),
        uuid::Uuid::from_bytes(scope.line).to_string(),
        "1".into(),
        if stage == "scope" {
            "+13".into()
        } else {
            scope.peer.clone()
        },
        "7".into(),
        display_hex(&digest),
        display_hex(&scope.phone_reader),
        display_hex(&scope.archive_reader),
        display_hex(&scope.phone_signer),
        now.to_string(),
    ];
    let mut args = vec!["conversation-activation".into()];
    for (flag, value) in FLAGS.into_iter().zip(values) {
        args.extend([flag.into(), value]);
    }
    let fingerprint = display_hex(&identity.root_fingerprint);
    let stage_owned = stage.to_owned();
    let injector = std::thread::spawn(move || {
        send_after("independent kit:", fingerprint.as_bytes());
        if stage_owned != "scope" {
            send_after(
                "Type APPROVE-ACTIVATION",
                if stage_owned == "decline" {
                    b"DECLINE"
                } else {
                    b"APPROVE-ACTIVATION"
                },
            );
            if stage_owned != "decline" {
                send_after(
                    "Enter recovery token",
                    if stage_owned == "token" {
                        b"INVALID"
                    } else {
                        token.expose_ascii()
                    },
                );
            }
        }
    });
    let result = run(&args, parent.clone());
    injector.join().unwrap();
    assert_eq!(result.is_ok(), (stage == "success" || interop));
    assert_eq!(output_path.exists(), (stage == "success" || interop));
    if stage == "success" || interop {
        let expected = Expected { identity, scope };
        let p = refresh::decode(&std::fs::read(&proposal_path).unwrap()).unwrap();
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let root = RootSecret::new(Zeroizing::new(scalar)).unwrap();
        let signed = refresh::sign(&root, &p, &expected, now_millis().unwrap()).unwrap();
        assert_eq!(std::fs::read(&output_path).unwrap(), signed);
        assert_eq!(&signed[..signed.len() - 64], after);
        assert!(screen().contains("Public signed successor written once"));
    } else {
        assert!(!screen().contains("Public signed successor written once"));
    }
    assert!(!screen().contains("ZTRK1-"));
    assert_eq!(
        store
            .read_bundle(
                &bundle_id,
                &ExpectedIdentity {
                    account_id: [1; 16],
                    origin: "https://owner.invalid".into(),
                    root_fingerprint: scope_fingerprint(&pin)
                }
            )
            .unwrap()
            .encrypted_backup(),
        backup
    );
}
#[test]
fn native_console_activation_uses_existing_bundle_once() {
    if let Ok(stage) = std::env::var("ZT_ACTIVATION_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let supplied = PathBuf::from(std::env::var_os("TEMP").unwrap());
            let parent = fixture_path::validated_parent(
                fixture_path::Purpose::Activation,
                &supplied,
                &stage,
            )
            .unwrap();
            child(&stage, parent)
        });
        std::process::exit(if result.is_ok() { 0 } else { 90 });
    }
    fixture_path::assert_shape_rejections(fixture_path::Purpose::Activation);
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-native-activation")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&parent).unwrap();
    for stage in ["success", "scope", "decline", "token"] {
        let stage_parent = parent.join(stage);
        std::fs::create_dir_all(&stage_parent).unwrap();
        assert_eq!(
            fixture_path::validated_parent(fixture_path::Purpose::Activation, &stage_parent, stage)
                .unwrap(),
            stage_parent
        );
        assert!(
            fixture_path::validated_parent(
                fixture_path::Purpose::Activation,
                &stage_parent.join("extra"),
                stage
            )
            .is_err()
        );
        launch(stage, &stage_parent);
    }
    if std::env::var_os("ZT_ACTIVATION_INTEROP_PROPOSAL_HEX").is_some() {
        let stage_parent = parent.join("interop");
        std::fs::create_dir_all(&stage_parent).unwrap();
        launch("interop", &stage_parent);
        let signed = std::fs::read(stage_parent.join("signed.bin")).unwrap();
        assert!(signed.len() <= refresh::MAX_PROPOSAL);
        println!("ZT_ACTIVATION_INTEROP_SIGNED={}", display_hex(&signed));
    }
    std::fs::remove_dir_all(parent).unwrap();
}
fn launch(stage: &str, parent: &std::path::Path) {
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact windows::conversation_activation::native_tests::native_console_activation_uses_existing_bundle_once --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_ACTIVATION_NATIVE_CASE", stage.into()),
    ] {
        environment.extend(wide(OsStr::new(&format!(
            "{key}={}",
            value.to_str().unwrap()
        ))));
    }
    if stage == "interop" {
        for key in [
            "ZT_ACTIVATION_INTEROP_PROPOSAL_HEX",
            "ZT_ACTIVATION_INTEROP_NOW",
        ] {
            let value = std::env::var(key).unwrap();
            environment.extend(wide(OsStr::new(&format!("{key}={value}"))));
        }
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
