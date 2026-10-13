#[cfg(not(windows))]
fn main() {
    eprintln!("Windows protected provider required; no hardware acceptance");
    std::process::exit(1);
}
#[cfg(windows)]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--probe") {
        if let Err(error) = zrotext_hpke_candidate::cng::HardwareRecipient::probe() {
            eprintln!("{error}");
            std::process::exit(77)
        }
        return;
    }
    if std::env::args().len() != 1 {
        eprintln!("unsupported arguments");
        std::process::exit(1)
    }
    if let Err(error) = exercise() {
        eprintln!("{error}");
        std::process::exit(1)
    }
    println!("native Windows hardware archive read, reopen and exact owned-key cleanup passed");
}
#[cfg(windows)]
fn exercise() -> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };
    use zrotext_hpke_candidate::{
        cng::{HardwareRecipient, NativeError},
        manifest::{enroll_root, verify_manifest},
        reader::{ArchiveContext, open_hardware_archive02},
    };
    HardwareRecipient::probe()?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    let suffix = random
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(std::env::temp_dir().join(format!("zrotext-native-cng-pending-{suffix}.json")))?;
    let key = HardwareRecipient::create(|name| {
        serde_json::to_writer(&mut receipt, &serde_json::json!({"pending_alias":name})).map_err(
            |_| NativeError {
                operation: "receipt write",
                status: 0,
            },
        )?;
        receipt.sync_all().map_err(|_| NativeError {
            operation: "receipt sync",
            status: 0,
        })
    })?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let public = key.public_point()?;
        let hex = public
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        println!("{}", serde_json::json!({"public":hex}));
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin()
            .take(1_000_001)
            .read_to_string(&mut input)?;
        if input.len() > 1_000_000 {
            return Err("fixture size".into());
        }
        let d: serde_json::Value = serde_json::from_str(&input)?;
        if d.get("archiveScalar").is_some() {
            return Err("producer exported recipient scalar".into());
        }
        let bytes = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(STANDARD.decode(d[name].as_str().ok_or("fixture field")?)?)
        };
        let root = enroll_root(&bytes("rootPin")?, &bytes("fingerprint")?).map_err(|_| "root")?;
        let now = d["now"].as_u64().ok_or("fixture time")?;
        let manifest =
            verify_manifest(&bytes("manifest")?, &root, None, 2, now).map_err(|_| "manifest")?;
        let account: [u8; 16] = bytes("account")?.try_into().map_err(|_| "account width")?;
        let device: [u8; 16] = bytes("device")?.try_into().map_err(|_| "device width")?;
        let line: [u8; 16] = bytes("line")?.try_into().map_err(|_| "line width")?;
        let reader: [u8; 32] = bytes("reader")?.try_into().map_err(|_| "reader width")?;
        let context = ArchiveContext {
            account: &account,
            device: &device,
            line: &line,
            reader: &reader,
            peer: "+12",
            now,
        };
        let reopened = HardwareRecipient::open(&key.alias()?, &public)?;
        let raw = bytes("inbound")?;
        let value = open_hardware_archive02(&raw, &manifest, &manifest, &reopened, &context)
            .map_err(|_| "native reader")?;
        if value.as_str() != d["text"].as_str().ok_or("text")? {
            return Err("plaintext mismatch".into());
        }
        let mut other_entropy = [0u8; 32];
        getrandom::fill(&mut other_entropy)?;
        let other = p256::SecretKey::from_slice(&other_entropy)?;
        use p256::elliptic_curve::sec1::ToSec1Point;
        if HardwareRecipient::open(
            &key.alias()?,
            other.public_key().to_sec1_point(false).as_bytes(),
        )
        .is_ok()
        {
            return Err("wrong public binding".into());
        }
        reopened.close()?;
        if open_hardware_archive02(&raw, &manifest, &manifest, &reopened, &context).is_ok() {
            return Err("closed provider accepted".into());
        }
        Ok(())
    })();
    // Always delete only this freshly owned key, including fixture/reader failure.
    let alias = key.alias()?;
    let public = key.public_point()?;
    key.delete()?;
    if HardwareRecipient::open(&alias, &public).is_ok() {
        return Err("deleted key reopened".into());
    }
    receipt.set_len(0)?;
    receipt.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut receipt, &serde_json::json!({"owned_key_deleted":true}))?;
    receipt.sync_all()?;
    result
}
