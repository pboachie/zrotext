// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic public proposals, roots and exclusively owned hidden consoles only.
use super::*;
use p256::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};
use serde_json::{Value, json};
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

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn base64(bytes: &[u8]) -> String {
    // Test-only canonical public transport encoder, independent of the decoder.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for part in bytes.chunks(3) {
        let n = (u32::from(part[0]) << 16)
            | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
            | u32::from(*part.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i > part.len() {
                '='
            } else {
                ALPHABET[((n >> shift) & 63) as usize] as char
            });
        }
    }
    out
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn point(n: u8) -> [u8; 65] {
    key(n)
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn key_id(role: u8, n: u8) -> [u8; 32] {
    hash(
        &[
            b"ZTSE/key/v1\0".as_slice(),
            if role <= 3 { &[0, 16] } else { &[1, 1] },
            &point(n),
        ]
        .concat(),
    )
}
fn fixture(now: u64) -> (Value, signing::Expected) {
    let origin = "https://contact.invalid";
    let account = [7; 16];
    let issued = now - 1000;
    let expires = now + 120_000;
    let until = now + 60_000;
    let mut pin = b"ZTRP\x02".to_vec();
    pin.extend(account);
    pin.extend(1_u64.to_be_bytes());
    pin.extend(point(1));
    let fingerprint = root_fingerprint(&pin, &account).unwrap();
    let mut manifest = b"ZTMA\x02".to_vec();
    manifest.extend(account);
    for n in [1_u64, 1, issued, expires] {
        manifest.extend(n.to_be_bytes());
    }
    manifest.extend([0; 32]);
    manifest.extend(point(1));
    manifest.push(2);
    for (role, n, scope) in [(2, 2, 12_u16), (6, 1, 0)] {
        manifest.push(role);
        manifest.extend(key_id(role, n));
        manifest.extend(point(n));
        manifest.extend([0; 32]);
        manifest.extend(scope.to_be_bytes());
        manifest.extend(0_u64.to_be_bytes());
        manifest.extend(expires.to_be_bytes());
        manifest.push(1);
    }
    let manifest_digest = hash(&manifest);
    let signature: Signature = key(1).sign(
        &[
            b"ZTSE/manifest/v2\0".as_slice(),
            &(manifest.len() as u32).to_be_bytes(),
            &manifest,
        ]
        .concat(),
    );
    manifest.extend(signature.normalize_s().to_bytes());
    let mut unsigned = b"ZTKA\x01\x03".to_vec();
    unsigned.extend([8; 16]);
    unsigned.extend(account);
    unsigned.extend((origin.len() as u16).to_be_bytes());
    unsigned.extend(origin.as_bytes());
    for n in [1_u64, 1, 1] {
        unsigned.extend(n.to_be_bytes());
    }
    for b in [fingerprint, manifest_digest, key_id(2, 2)] {
        unsigned.extend(b);
    }
    unsigned.extend(point(2));
    unsigned.extend((now - 500).to_be_bytes());
    unsigned.extend(until.to_be_bytes());
    let expected = signing::Expected {
        account,
        origin: origin.into(),
        fingerprint,
        reader_id: key_id(2, 2),
        reader_point: point(2),
        requested_until_ms: until,
    };
    let create = json!({"create_request":uuid::Uuid::from_bytes([9;16]).to_string(),"expected_revision":"0","prior":{"phase":"empty"},"selected_reader_id":base64(&key_id(2,2)),"compared_root_fingerprint":base64(&fingerprint),"requested_until_ms":until.to_string()});
    let typed: Create = serde_json::from_value(create.clone()).unwrap();
    let record = |role, n| json!({"key_id_b64":base64(&key_id(role,n)),"public_point_b64":base64(&point(n)),"from_ms":"0","until_ms":expires.to_string()});
    let pending = json!({"kind":"pending","create_input_digest":base64(&create_digest(&typed,&expected).unwrap()),"create_request":create["create_request"],"authorization":uuid::Uuid::from_bytes([8;16]).to_string(),"generation":"1","creation_expected_revision":"0","allocated_revision":"1","unsigned_digest":base64(&hash(&unsigned)),"unsigned":base64(&unsigned),"issued_ms":(now-500).to_string(),"expires_ms":expires.to_string(),"until_ms":until.to_string(),"created_by_user":uuid::Uuid::from_bytes([10;16]).to_string(),"created_session":uuid::Uuid::from_bytes([11;16]).to_string(),"creation_source":{"kind":"historical_creation_source","account_id":uuid::Uuid::from_bytes(account).to_string(),"root_pin_b64":base64(&pin),"root_fingerprint_b64":base64(&fingerprint),"trust_generation":"1","manifest_version":"1","manifest_digest_b64":base64(&manifest_digest),"manifest_b64":base64(&manifest),"observed_ms":(now-750).to_string(),"manifest_issued_ms":issued.to_string(),"manifest_expires_ms":expires.to_string(),"signed_until_ms":expires.to_string(),"reader":record(2,2),"root_writer":record(6,1)},"current":{"phase":"empty","mutation_revision":"1","allocation_generation":"1","observed_ms":now.to_string()}});
    (json!({"create":create,"pending":pending}), expected)
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn args(parent: &std::path::Path, expected: &signing::Expected, bundle: [u8; 16]) -> Vec<String> {
    let values = [
        uuid::Uuid::from_bytes(expected.account).to_string(),
        expected.origin.clone(),
        display_hex(&bundle),
        parent.join("proposal.json").to_str().unwrap().into(),
        parent.join("signed.bin").to_str().unwrap().into(),
        display_hex(&expected.reader_id),
        display_hex(&expected.reader_point),
        expected.requested_until_ms.to_string(),
    ];
    let mut result = vec!["contact-reader-sign".into()];
    for (f, v) in FLAGS.into_iter().zip(values) {
        result.extend([f.into(), v]);
    }
    result
}
#[test]
fn strict_public_wrapper_preserves_actual_proposal_and_original_commitment() {
    let (v, expected) = fixture(10_000);
    let p = decode(&bytes(&v)).unwrap();
    let facts = p.inspect(&expected, 10_000).unwrap().facts();
    assert_eq!(facts.account, expected.account);
    assert_eq!(facts.reader_generation, 1);
    assert_eq!(p.input_digest, create_digest(&p.create, &expected).unwrap());
}
#[test]
fn direct_typed_wire_rejects_duplicates_aliases_and_unknown_fields() {
    let (v, _) = fixture(10_000);
    let raw = serde_json::to_string(&v).unwrap();
    for value in [
        raw.replacen(
            "\"create_request\":",
            "\"create_request\":\"bad\",\"create_request\":",
            1,
        ),
        raw.replacen("\"create\":", "\"create\":{},\"create\":", 1),
        raw.replacen("\"expires_ms\":", "\"extra\":true,\"expires_ms\":", 1),
        raw.replacen(
            "\"create_request\":",
            r#""create_request":"bad","create_\u0072equest":"#,
            1,
        ),
    ] {
        assert!(decode(value.as_bytes()).is_err());
    }
}
#[test]
fn public_wire_has_independent_outer_and_raw_inner_caps() {
    let (v, _) = fixture(10_000);
    let create = serde_json::to_string(&v["create"]).unwrap();
    let pending = serde_json::to_string(&v["pending"]).unwrap();
    for (c, p) in [
        (
            format!("{{{}{}", " ".repeat(8192), &create[1..]),
            pending.clone(),
        ),
        (
            create.clone(),
            format!("{{{}{}", " ".repeat(20_480), &pending[1..]),
        ),
    ] {
        assert!(decode(format!("{{\"create\":{c},\"pending\":{p}}}").as_bytes()).is_err());
    }
    assert!(decode(&[b' '; MAX_WRAPPER + 1]).is_err());
    assert!(decode(b"{\"create\":[],\"pending\":{}}").is_err());
    assert!(decode(b"\xff").is_err());
}
#[test]
fn canonical_numbers_base64_and_actor_identities_are_required() {
    let (v, expected) = fixture(10_000);
    for (field, value) in [
        ("issued_ms", json!(9500)),
        ("issued_ms", json!("09500")),
        ("generation", json!("-1")),
        (
            "created_session",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("unsigned_digest", json!("AA==\n")),
    ] {
        let mut bad = v.clone();
        bad["pending"][field] = value;
        assert!(
            decode(&bytes(&bad))
                .and_then(|p| p.inspect(&expected, 10_000))
                .is_err()
        );
    }
}
#[test]
fn mismatched_original_create_prior_and_frozen_source_refuse() {
    let (v, expected) = fixture(10_000);
    for (section, field, value) in [
        ("create", "expected_revision", json!("1")),
        (
            "create",
            "create_request",
            json!(uuid::Uuid::from_bytes([12; 16]).to_string()),
        ),
        (
            "pending",
            "authorization",
            json!(uuid::Uuid::from_bytes([12; 16]).to_string()),
        ),
        ("pending", "allocated_revision", json!("2")),
    ] {
        let mut bad = v.clone();
        bad[section][field] = value;
        assert!(
            decode(&bytes(&bad))
                .unwrap()
                .inspect(&expected, 10_000)
                .is_err()
        );
    }
    let mut bad = v;
    bad["pending"]["creation_source"]["observed_ms"] = json!("9999");
    assert!(
        decode(&bytes(&bad))
            .unwrap()
            .inspect(&expected, 10_000)
            .is_err()
    );
}
#[test]
fn pending_expiry_and_current_allocator_never_extend_the_signature() {
    let (v, expected) = fixture(10_000);
    let p = decode(&bytes(&v)).unwrap();
    assert!(p.inspect(&expected, 130_000).is_err());
    let mut changed = v.clone();
    changed["pending"]["current"]["allocation_generation"] = json!("0");
    assert!(
        decode(&bytes(&changed))
            .unwrap()
            .inspect(&expected, 10_000)
            .is_err()
    );
    changed = v;
    changed["pending"]["expires_ms"] = json!("400001");
    assert!(
        decode(&bytes(&changed))
            .unwrap()
            .inspect(&expected, 10_000)
            .is_err()
    );
}
#[test]
fn fixed_command_arguments_refuse_aliases_reordering_and_output_reuse() {
    let (_, expected) = fixture(10_000);
    let original = args(&fixture_root(), &expected, [1; 16]);
    assert!(parse(&original).is_ok());
    let mut bad = original.clone();
    bad.swap(1, 3);
    assert!(parse(&bad).is_err());
    bad = original.clone();
    bad[8] = bad[10].replace('/', "\\").to_ascii_uppercase();
    assert!(parse(&bad).is_err());
    bad = original;
    bad[16] = "09000".into();
    assert!(parse(&bad).is_err());
}
#[test]
fn public_paths_reject_relative_devices_streams_and_ambiguous_components() {
    for path in ["relative.json", r"\proposal.json"] {
        assert!(public_path(path).is_err());
    }
    for name in ["../p.json", "NUL.bin", "a:stream", "a.", "a "] {
        let path = fixture_root().join(name);
        assert!(public_path(path.to_str().unwrap()).is_err());
    }
    assert!(public_path(&format!("{}//a", fixture_root().display())).is_err());
    assert!(public_path(fixture_root().join("bad\u{7f}").to_str().unwrap()).is_err());
    assert!(public_path(fixture_root().join("proposal.json").to_str().unwrap()).is_ok());
}
#[test]
fn complete_review_and_receipt_are_ascii_chunked_without_omission() {
    let (v, expected) = fixture(10_000);
    let p = decode(&bytes(&v)).unwrap();
    let f = p.inspect(&expected, 10_000).unwrap().facts();
    let input = parse(&args(&fixture_root(), &expected, [1; 16])).unwrap();
    let text = review_text(&input, &p, &f).unwrap();
    let parts = chunks(&text).unwrap();
    assert!(parts.len() > 1);
    assert!(parts.iter().all(|p| p.len() <= 512));
    assert_eq!(parts.concat(), text);
    assert!(text.contains("Historical source comparison: 9250"));
    assert!(text.contains("APPROVE-READER"));
    assert!(chunks("bad\u{2028}").is_err());
}
#[test]
fn wall_and_post_token_clocks_refuse_rollback_expiry_and_late_success() {
    let mut life = Lifetime {
        expires: 20_000,
        until: 15_000,
        last: 10_000,
        started: Instant::now(),
        budget: Duration::from_secs(20),
        signing_start: None,
    };
    assert_eq!(life.observe(10_001, Duration::ZERO, None), Ok(10_001));
    assert!(life.observe(10_000, Duration::ZERO, None).is_err());
    assert!(life.observe(15_000, Duration::ZERO, None).is_err());
    assert!(
        life.observe(10_002, Duration::ZERO, Some(Duration::from_secs(10)))
            .is_err()
    );
    assert!(life.observe(10_002, Duration::from_secs(20), None).is_err());
    assert_eq!(
        life.observe(10_002, Duration::ZERO, Some(Duration::from_millis(9999))),
        Ok(10_002)
    );
}
#[test]
fn public_output_is_create_new_and_read_input_refuses_directories_and_oversize() {
    let parent = unique_parent();
    std::fs::create_dir_all(&parent).unwrap();
    let path = parent.join("signed.bin");
    write_public(path.to_str().unwrap(), &[9; 314]).unwrap();
    assert!(write_public(path.to_str().unwrap(), &[8; 314]).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), vec![9; 314]);
    assert!(read_proposal(parent.to_str().unwrap()).is_err());
    let big = parent.join("big.json");
    std::fs::write(&big, vec![b' '; MAX_WRAPPER + 1]).unwrap();
    assert!(read_proposal(big.to_str().unwrap()).is_err());
    cleanup(&parent);
}
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("tmp-native-contact")
}
fn unique_parent() -> PathBuf {
    fixture_root().join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn fixture_shape(path: &std::path::Path, stage: &str) -> Result<(u32, u128, &'static str)> {
    let stage = match stage {
        "success" => "success",
        "decline" => "decline",
        "token" => "token",
        "existing" => "existing",
        "scope" => "scope",
        _ => return Err(()),
    };
    let root = fixture_root();
    let mut components = path.strip_prefix(&root).map_err(|_| ())?.components();
    let Some(std::path::Component::Normal(run)) = components.next() else {
        return Err(());
    };
    let Some(std::path::Component::Normal(actual_stage)) = components.next() else {
        return Err(());
    };
    if components.next().is_some() || actual_stage != OsStr::new(stage) {
        return Err(());
    }
    let run = run.to_str().ok_or(())?;
    if run.len() > 50 {
        return Err(());
    }
    let (pid, nanos) = run.split_once('-').ok_or(())?;
    if pid.is_empty()
        || nanos.is_empty()
        || !pid.bytes().all(|b| b.is_ascii_digit())
        || !nanos.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(());
    }
    let pid = pid.parse::<u32>().map_err(|_| ())?;
    let nanos = nanos.parse::<u128>().map_err(|_| ())?;
    if pid == 0 || nanos == 0 || format!("{pid}-{nanos}") != run {
        return Err(());
    }
    Ok((pid, nanos, stage))
}
fn validate_parent(path: &std::path::Path, stage: &str) -> Result<PathBuf> {
    let (pid, nanos, stage) = fixture_shape(path, stage)?;
    let root = fixture_root();
    // Only the fixed root, parsed integers and a static stage reach fixture IO.
    // TEMP never supplies a directory or filename string to the child fixture.
    let run = root.join(format!("{pid}-{nanos}"));
    let parent = run.join(stage);
    for candidate in [&root, &run, &parent] {
        no_reparse(candidate)?;
        if !std::fs::symlink_metadata(candidate)
            .map_err(|_| ())?
            .is_dir()
        {
            return Err(());
        }
    }
    let canonical = parent.canonicalize().map_err(|_| ())?;
    if path.canonicalize().map_err(|_| ())? != canonical
        || !canonical.starts_with(root.canonicalize().map_err(|_| ())?)
    {
        return Err(());
    }
    // Keep ordinary drive spelling; the production CLI refuses device paths.
    Ok(parent)
}
fn no_reparse(path: &std::path::Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    for p in path.ancestors() {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_attributes() & 0x0400 != 0 => return Err(()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}
fn cleanup(parent: &std::path::Path) {
    assert_eq!(parent.parent(), Some(fixture_root().as_path()));
    no_reparse(parent).unwrap();
    fn descend(path: &std::path::Path) {
        for item in std::fs::read_dir(path).unwrap() {
            let item = item.unwrap();
            no_reparse(&item.path()).unwrap();
            if item.file_type().unwrap().is_dir() {
                descend(&item.path());
            }
        }
    }
    descend(parent);
    std::fs::remove_dir_all(parent).unwrap();
}
#[test]
fn native_contact_signing_consumes_real_sessions_and_preserves_existing_bundle() {
    if let Ok(stage) = std::env::var("ZT_CONTACT_SIGN_NATIVE_CASE") {
        let result = std::panic::catch_unwind(|| {
            let supplied = PathBuf::from(std::env::var_os("TEMP").unwrap());
            let parent = validate_parent(&supplied, &stage).unwrap();
            child(&stage, parent);
        });
        std::process::exit(if result.is_ok() { 0 } else { 90 });
    }
    let fixed = fixture_root();
    for stage in ["success", "decline", "token", "existing", "scope"] {
        assert_eq!(
            fixture_shape(&fixed.join("123-456").join(stage), stage).unwrap(),
            (123, 456, stage)
        );
    }
    for run in [
        "",
        "123",
        "-456",
        "123-",
        "123-456-7",
        "a-456",
        "123-a",
        "0-456",
        "123-0",
        "0123-456",
        "123-0456",
    ] {
        assert!(fixture_shape(&fixed.join(run).join("success"), "success").is_err());
    }
    for run in [
        format!("{}-456", u64::from(u32::MAX) + 1),
        format!("123-{}0", u128::MAX),
    ] {
        assert!(fixture_shape(&fixed.join(run).join("success"), "success").is_err());
    }
    for candidate in [
        fixed.join("123-456"),
        fixed.join("123-456/success/extra"),
        fixed.join("../123-456/success"),
        fixed.join("123-456/../success"),
        fixed.join("123-456/unknown"),
        fixed.with_file_name("other").join("123-456/success"),
    ] {
        assert!(fixture_shape(&candidate, "success").is_err());
    }
    assert!(fixture_shape(&fixed.join("123-456/scope"), "success").is_err());
    assert!(fixture_shape(&fixed.join("123-456/unknown"), "unknown").is_err());
    assert!(
        validate_parent(
            &fixture_root().join("1-2").join("extra").join("success"),
            "success"
        )
        .is_err()
    );
    let parent = unique_parent();
    std::fs::create_dir_all(&parent).unwrap();
    no_reparse(&parent).unwrap();
    for stage in ["success", "decline", "token", "existing", "scope"] {
        let path = parent.join(stage);
        std::fs::create_dir(&path).unwrap();
        assert_eq!(validate_parent(&path, stage).unwrap(), path);
        launch(stage, &path);
    }
    cleanup(&parent);
}
fn child(stage: &str, parent: PathBuf) {
    crate::native_process::assert_current_process_limited();
    verify_process_eligibility().unwrap();
    // SAFETY: this test-only child owns its new hidden console exclusively.
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
    let (value, expected) = fixture(now);
    let root = RootSecret::new(Zeroizing::new([1; 32])).unwrap();
    let recovery = RecoverySecret::new(Zeroizing::new([9; 32]));
    let identity = ExpectedIdentity {
        account_id: expected.account,
        origin: expected.origin.clone(),
        root_fingerprint: expected.fingerprint,
    };
    let root_pin = pin(&root, &expected.account).unwrap();
    let backup = root_backup::seal(&root, &recovery, &identity).unwrap();
    let bundle_id = root_backup::validate_public_header(&backup, &identity).unwrap();
    let card = recovery_kit::encode_public_card(&root_pin, &identity, &hash(&backup)).unwrap();
    let bundle = EncryptedBundle::new(&backup, &card, &identity).unwrap();
    let store = Store::open(&parent).unwrap();
    store.publish(&bundle).unwrap();
    let token = recovery_kit::encode_token(
        &recovery,
        &KitContext::new(identity.clone(), &root_pin, bundle_id).unwrap(),
    );
    drop(root);
    drop(recovery);
    std::fs::write(parent.join("proposal.json"), bytes(&value)).unwrap();
    let output = parent.join("signed.bin");
    if stage == "existing" {
        std::fs::write(&output, b"preserved").unwrap();
    }
    let mut command = args(&parent, &expected, bundle_id);
    if stage == "scope" {
        command[12] = display_hex(&[3; 32]);
    }
    let fingerprint = display_hex(&expected.fingerprint);
    let stage_owned = stage.to_owned();
    let injector = std::thread::spawn(move || {
        send_after("independent kit:", fingerprint.as_bytes());
        if stage_owned != "scope" {
            send_after(
                "Type APPROVE-READER",
                if stage_owned == "decline" {
                    b"DECLINE"
                } else {
                    b"APPROVE-READER"
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
    let result = run(&command, parent.clone());
    injector.join().unwrap();
    assert_eq!(result.is_ok(), stage == "success");
    if stage == "success" {
        let signed = std::fs::read(&output).unwrap();
        let proposal = decode(&bytes(&value)).unwrap();
        assert_eq!(&signed[..signed.len() - 64], proposal.unsigned);
        let signature = Signature::from_slice(&signed[signed.len() - 64..]).unwrap();
        assert_eq!(signature.normalize_s(), signature);
        key(1)
            .verifying_key()
            .verify(
                &[
                    b"ZT/contact-reader/authorization/v1\0".as_slice(),
                    &(proposal.unsigned.len() as u32).to_be_bytes(),
                    &proposal.unsigned,
                ]
                .concat(),
                &signature,
            )
            .unwrap();
        assert!(screen().contains("Signed locally; server completion has not been acknowledged"));
    } else if stage == "existing" {
        assert_eq!(std::fs::read(&output).unwrap(), b"preserved");
    } else {
        assert!(!output.exists());
    }
    if stage != "success" {
        assert!(!screen().contains("Signed locally; server completion"));
    }
    assert!(!screen().contains("ZTRK1-"));
    assert_eq!(
        store
            .read_bundle(&bundle_id, &identity)
            .unwrap()
            .encrypted_backup(),
        backup
    );
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn launch(stage: &str, parent: &std::path::Path) {
    let executable = std::env::current_exe().unwrap();
    let application = wide(executable.as_os_str());
    let mut command = wide(OsStr::new(&format!(
        "\"{}\" --exact windows::contact_reader_signing::tests::native_contact_signing_consumes_real_sessions_and_preserves_existing_bundle --nocapture --test-threads=1",
        executable.display()
    )));
    let mut environment = Vec::new();
    for (key, value) in [
        ("SystemRoot", std::env::var_os("SystemRoot").unwrap()),
        ("TEMP", parent.as_os_str().to_os_string()),
        ("ZT_CONTACT_SIGN_NATIVE_CASE", stage.into()),
    ] {
        environment.extend(wide(OsStr::new(&format!(
            "{key}={}",
            value.to_str().unwrap()
        ))));
    }
    environment.push(0);
    // SAFETY: bounded live terminated buffers, no inherited handles or user console.
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
            panic!("synthetic contact child timeout");
        }
        let mut code = 0;
        assert_ne!(GetExitCodeProcess(handle.as_raw_handle(), &mut code), 0);
        assert_eq!(code, 0, "synthetic stage {stage} failed");
    }
}
fn screen() -> String {
    let mut text = vec![0; 16000];
    let mut count = 0;
    // SAFETY: only the exclusive hidden child calls this, with bounded storage.
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
    let start = Instant::now();
    while !screen().contains(prompt) {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "synthetic prompt missing"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for byte in text.iter().chain(std::iter::once(&b'\r')) {
        // SAFETY: the child proved sole hidden-console ownership before injection.
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
