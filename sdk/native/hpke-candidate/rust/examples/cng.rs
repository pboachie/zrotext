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
    let elected =
        std::env::args().len() == 2 && std::env::args().nth(1).as_deref() == Some("--elected");
    if std::env::args().len() != 1 && !elected {
        eprintln!("unsupported arguments");
        std::process::exit(1)
    }
    if let Err(error) = exercise(elected) {
        eprintln!("{error}");
        std::process::exit(1)
    }
    println!("native Windows hardware profile read, reopen and exact owned-key cleanup passed");
}
#[cfg(windows)]
fn exercise(elected: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };
    use zrotext_hpke_candidate::cng::{HardwareRecipient, NativeError};
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
        let private_field = if elected {
            "readerScalar"
        } else {
            "archiveScalar"
        };
        if d.get(private_field).is_some() {
            return Err("producer exported selected recipient scalar".into());
        }
        let reopened = HardwareRecipient::open(&key.alias()?, &public)?;
        let value = open_fixture(&d, &reopened, elected, "+12")?;
        let field = if elected { "bodyText" } else { "text" };
        if value.as_str() != d[field].as_str().ok_or("text")? {
            return Err("plaintext mismatch".into());
        }
        if elected && open_fixture(&d, &reopened, true, "+13").is_ok() {
            return Err("wrong peer accepted".into());
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
        if open_fixture(&d, &reopened, elected, "+12").is_ok() {
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

#[cfg(windows)]
fn open_fixture(
    d: &serde_json::Value,
    custody: &zrotext_hpke_candidate::cng::HardwareRecipient,
    elected: bool,
    peer: &str,
) -> Result<zeroize::Zeroizing<String>, Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use zrotext_hpke_candidate::{
        elected_reader::{ElectedContext, open_hardware_elected03},
        election::{ElectionEvidence, ElectionRecord, verify_accepted_election03},
        manifest::{enroll_root, verify_manifest},
        reader::{ArchiveContext, open_hardware_archive02},
    };
    let b = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(STANDARD.decode(d[name].as_str().ok_or("fixture field")?)?)
    };
    let root = enroll_root(&b("rootPin")?, &b("fingerprint")?).map_err(|_| "root")?;
    if elected {
        let record = |name: &str| -> Result<ElectionRecord, Box<dyn std::error::Error>> {
            let mut r = ElectionRecord::default();
            for (k, v) in d[name].as_object().ok_or("record")? {
                if let Some(s) = v.as_str() {
                    r.bytes.insert(k.clone(), STANDARD.decode(s)?);
                } else {
                    r.numbers
                        .insert(k.clone(), v.as_u64().ok_or("record number")?);
                }
            }
            Ok(r)
        };
        let prior = verify_manifest(&b("signed02")?, &root, None, 2, 10000).map_err(|_| "prior")?;
        let proof = verify_accepted_election03(ElectionEvidence {
            bundle: &b("bundle")?,
            expected_core: &b("core")?,
            accepted: &record("accepted")?,
            predecessor: &prior,
            signed02: &b("signed02")?,
            signed03: &b("signed03")?,
            device_point: &b("deviceSigningPoint")?,
            owner_point: &b("ownerApprovalPoint")?,
        })
        .map_err(|_| "proof")?;
        let message: [u8; 16] = b("message")?.try_into().map_err(|_| "message")?;
        return open_hardware_elected03(
            &b("envelope")?,
            proof.accepted_manifest(),
            &proof,
            &record("authority")?,
            custody,
            &ElectedContext {
                message: &message,
                peer,
                now: 30000,
            },
        )
        .map_err(|_| "native elected reader".into());
    }
    let now = d["now"].as_u64().ok_or("time")?;
    let manifest = verify_manifest(&b("manifest")?, &root, None, 2, now).map_err(|_| "manifest")?;
    let account: [u8; 16] = b("account")?.try_into().map_err(|_| "account")?;
    let device: [u8; 16] = b("device")?.try_into().map_err(|_| "device")?;
    let line: [u8; 16] = b("line")?.try_into().map_err(|_| "line")?;
    let reader: [u8; 32] = b("reader")?.try_into().map_err(|_| "reader")?;
    open_hardware_archive02(
        &b("inbound")?,
        &manifest,
        &manifest,
        custody,
        &ArchiveContext {
            account: &account,
            device: &device,
            line: &line,
            reader: &reader,
            peer,
            now,
        },
    )
    .map_err(|_| "native archive reader".into())
}
