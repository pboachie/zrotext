#[cfg(not(windows))]
fn main() {
    eprintln!("Windows protected signer required; no qualification");
    std::process::exit(1)
}
#[cfg(windows)]
fn main() {
    if let Err(e) = native::run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
#[cfg(windows)]
mod native {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        cell::Cell,
        io::{Read, Seek, SeekFrom, Write},
        process::{Command, Stdio},
    };
    use zrotext_hpke_candidate::{
        Error,
        cng::{HardwareSigner, NativeError},
        compose::{ComposeRequest, Recipient, compose_protected03},
        election::{ElectionEvidence, ElectionProof, ElectionRecord, verify_accepted_election03},
        journal::JournalError,
        manifest::{enroll_root, verify_manifest},
        outbound::OutboundJournal,
    };
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    const CONTENT: &str = "Native composed sample";
    fn need(v: bool, message: &str) -> Result<()> {
        if v { Ok(()) } else { Err(message.into()) }
    }
    fn b(d: &serde_json::Value, name: &str) -> Vec<u8> {
        STANDARD
            .decode(d[name].as_str().expect("synthetic binary field"))
            .expect("synthetic base64")
    }
    fn record(d: &serde_json::Value, name: &str) -> ElectionRecord {
        let mut r = ElectionRecord::default();
        for (k, v) in d[name].as_object().expect("synthetic record") {
            if let Some(s) = v.as_str() {
                r.bytes
                    .insert(k.clone(), STANDARD.decode(s).expect("synthetic base64"));
            } else {
                r.numbers
                    .insert(k.clone(), v.as_u64().expect("synthetic number"));
            }
        }
        r
    }
    fn crypto<T>(v: std::result::Result<T, Error>) -> Result<T> {
        v.map_err(|e| format!("{e:?}").into())
    }
    fn journal<T>(v: std::result::Result<T, JournalError>) -> Result<T> {
        v.map_err(|e| format!("{e:?}").into())
    }
    fn proof(d: &serde_json::Value) -> Result<ElectionProof> {
        let root = crypto(enroll_root(&b(d, "rootPin"), &b(d, "fingerprint")))?;
        let prior = crypto(verify_manifest(&b(d, "signed02"), &root, None, 2, 10000))?;
        crypto(verify_accepted_election03(ElectionEvidence {
            bundle: &b(d, "bundle"),
            expected_core: &b(d, "core"),
            accepted: &record(d, "accepted"),
            predecessor: &prior,
            signed02: &b(d, "signed02"),
            signed03: &b(d, "signed03"),
            device_point: &b(d, "deviceSigningPoint"),
            owner_point: &b(d, "ownerApprovalPoint"),
        }))
    }
    fn request<'a>(
        d: &serde_json::Value,
        proof: &'a ElectionProof,
        signer: &'a HardwareSigner,
        authority: &'a dyn Fn() -> std::result::Result<(ElectionRecord, u64), Error>,
    ) -> ComposeRequest<'a> {
        let raw = b(d, "signed03");
        let archive = (0..raw[152] as usize)
            .map(|i| &raw[153 + i * 149..153 + (i + 1) * 149])
            .find(|k| k[0] == 2)
            .expect("archive");
        ComposeRequest {
            manifest: proof.accepted_manifest(),
            proof,
            authority,
            message: b(d, "message").try_into().expect("message"),
            observed: 30000,
            expires: 40000,
            peer: "+12",
            content: CONTENT,
            signer,
            recipients: vec![
                Recipient {
                    role: 1,
                    id: record(d, "accepted").bytes["selectedReaderKeyId"]
                        .clone()
                        .try_into()
                        .expect("id"),
                },
                Recipient {
                    role: 2,
                    id: archive[1..33].try_into().expect("id"),
                },
            ],
        }
    }
    fn read() -> Result<serde_json::Value> {
        let mut input = String::new();
        std::io::stdin().take(1000001).read_to_string(&mut input)?;
        need(input.len() <= 1000000, "fixture size")?;
        Ok(serde_json::from_str(&input)?)
    }
    pub fn run() -> Result<()> {
        match std::env::args().nth(1).as_deref() {
            Some("--probe") => {
                if HardwareSigner::probe().is_err() {
                    std::process::exit(77)
                };
                Ok(())
            }
            Some("--replay") => child(),
            _ => exercise(),
        }
    }
    fn child() -> Result<()> {
        let c = read()?;
        let d = &c["Fixture"];
        let signer =
            HardwareSigner::open(c["Alias"].as_str().ok_or("alias")?, &b(d, "signerPoint"))?;
        let proof = proof(d)?;
        let authority = || Ok((record(d, "authority"), 30000));
        let r = request(d, &proof, &signer, &authority);
        let j = journal(OutboundJournal::open(
            c["Path"].as_str().ok_or("path")?,
            &b(d, "rootPin"),
            &b(d, "fingerprint"),
        ))?;
        let out = journal(j.compose_or_replay(&r))?;
        println!("{}", serde_json::json!({"envelope":STANDARD.encode(out)}));
        Ok(())
    }
    fn exercise() -> Result<()> {
        HardwareSigner::probe()?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let suffix = format!("{:x}", u128::from_le_bytes(random));
        let mut receipt = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                std::env::temp_dir().join(format!("zrotext-native-sign-pending-{suffix}.json")),
            )?;
        let key = HardwareSigner::create(|alias| {
            serde_json::to_writer(&mut receipt, &serde_json::json!({"pending_alias":alias}))
                .map_err(|_| NativeError {
                    operation: "receipt write",
                    status: 0,
                })?;
            receipt.sync_all().map_err(|_| NativeError {
                operation: "receipt sync",
                status: 0,
            })
        })?;
        let result = (|| -> Result<()> {
            let public = key.public_point()?;
            println!(
                "{}",
                serde_json::json!({"public":public.iter().map(|v|format!("{v:02x}")).collect::<String>()})
            );
            std::io::stdout().flush()?;
            let d = read()?;
            need(
                d.get("envelope").is_none() && b(&d, "signerPoint") == public,
                "external signer producer binding",
            )?;
            let signer = HardwareSigner::open(&key.alias()?, &public)?;
            need(signer.delete_created().is_err(), "opened signer deleted")?;
            let proof = proof(&d)?;
            let clock = Cell::new(30000u64);
            let authority = || Ok((record(&d, "authority"), clock.get()));
            let r = request(&d, &proof, &signer, &authority);
            let dir = std::env::temp_dir().join(format!("zrotext-native-outbound-{suffix}"));
            std::fs::create_dir(&dir)?;
            let path = dir.join("outbound.db");
            let open = || {
                journal(OutboundJournal::open(
                    &path,
                    &b(&d, "rootPin"),
                    &b(&d, "fingerprint"),
                ))
            };
            let j = open()?;
            let out = journal(j.compose_or_replay(&r))?;
            need(journal(j.compose_or_replay(&r))? == out, "exact replay")?;
            drop(j);
            let j = open()?;
            need(journal(j.compose_or_replay(&r))? == out, "restart replay")?;
            let mut changed = r.clone();
            changed.content = "Different synthetic intent";
            need(
                matches!(j.compose_or_replay(&changed), Err(JournalError::Conflict)),
                "intent conflict",
            )?;
            clock.set(31000);
            journal(j.compose_or_replay(&r))?;
            drop(j);
            let j = open()?;
            clock.set(30000);
            need(j.compose_or_replay(&r).is_err(), "restart clock rollback")?;
            clock.set(31000);
            let long = "x".repeat(32769);
            for text in ["", "\0", "\u{feff}bad", &long] {
                let mut bad = r.clone();
                bad.content = text;
                need(compose_protected03(&bad).is_err(), "strict text")?;
            }
            for peer in ["+1", "bad", "+000"] {
                let mut bad = r.clone();
                bad.peer = peer;
                need(compose_protected03(&bad).is_err(), "peer")?;
            }
            for expires in [30000, 100001, 1 << 63] {
                let mut bad = r.clone();
                bad.expires = expires;
                need(compose_protected03(&bad).is_err(), "expiry")?;
            }
            let mut bad = r.clone();
            bad.recipients.pop();
            need(compose_protected03(&bad).is_err(), "recipient count")?;
            let race_path = dir.join("race.db");
            drop(journal(OutboundJournal::open(
                &race_path,
                &b(&d, "rootPin"),
                &b(&d, "fingerprint"),
            ))?);
            let payload = serde_json::to_vec(
                &serde_json::json!({"Fixture":d,"Alias":key.alias()?,"Path":race_path}),
            )?;
            let child = || -> Result<std::process::Child> {
                let mut c = Command::new(std::env::current_exe()?)
                    .arg("--replay")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                c.stdin.take().ok_or("child stdin")?.write_all(&payload)?;
                Ok(c)
            };
            let a = child()?;
            let second = child()?;
            let a = a.wait_with_output()?;
            let second = second.wait_with_output()?;
            need(
                a.status.success() && second.status.success() && a.stdout == second.stdout,
                "two-process exact CAS",
            )?;
            let calls = Cell::new(0);
            let lost = || {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    return Err(Error::Authentication);
                };
                Ok((record(&d, "authority"), 31000))
            };
            let mut uncertain = r.clone();
            uncertain.message[0] ^= 1;
            uncertain.authority = &lost;
            need(
                j.compose_or_replay(&uncertain).is_err() && calls.get() == 3,
                "postcommit authority loss",
            )?;
            let identity = [
                record(&d, "authority").bytes["accountId"].as_slice(),
                &uncertain.message,
                record(&d, "authority").bytes["deviceId"].as_slice(),
                record(&d, "authority").bytes["lineId"].as_slice(),
            ]
            .concat();
            let db = rusqlite::Connection::open(&path)?;
            let saved: Vec<u8> = db.query_row(
                "SELECT envelope FROM outbound WHERE identity=?1",
                [identity],
                |r| r.get(0),
            )?;
            drop(db);
            uncertain.authority = &authority;
            need(
                journal(j.compose_or_replay(&uncertain))? == saved,
                "ambiguous exact recovery",
            )?;
            let phase = Cell::new(0);
            let newer_authority = || {
                phase.set(phase.get() + 1);
                Ok((
                    record(&d, "authority"),
                    if phase.get() == 3 { 32000 } else { 31000 },
                ))
            };
            let mut newer = r.clone();
            newer.message[0] ^= 2;
            newer.authority = &newer_authority;
            journal(j.compose_or_replay(&newer))?;
            drop(j);
            let j = open()?;
            newer.authority = &authority;
            need(
                j.compose_or_replay(&newer).is_err(),
                "postcommit comparison not persisted",
            )?;
            let mut entropy = [0u8; 32];
            getrandom::fill(&mut entropy)?;
            let other = p256::SecretKey::from_slice(&entropy)?;
            use p256::elliptic_curve::sec1::ToSec1Point;
            need(
                HardwareSigner::open(
                    &key.alias()?,
                    other.public_key().to_sec1_point(false).as_bytes(),
                )
                .is_err(),
                "wrong signer point",
            )?;
            signer.close()?;
            need(compose_protected03(&r).is_err(), "closed signer")?;
            drop(j);
            std::fs::remove_dir_all(dir)?;
            println!(
                "{}",
                serde_json::json!({"envelope":STANDARD.encode(out),"expectedText":CONTENT,"checks":"exact replay, process CAS, ambiguity, clock rollback, strict input and custody passed"})
            );
            Ok(())
        })();
        let alias = key.alias()?;
        let public = key.public_point()?;
        let cleanup = key.delete_created();
        if cleanup.is_ok() {
            need(
                HardwareSigner::open(&alias, &public).is_err(),
                "deleted signer reopened",
            )?;
            receipt.set_len(0)?;
            receipt.seek(SeekFrom::Start(0))?;
            serde_json::to_writer(&mut receipt, &serde_json::json!({"owned_key_deleted":true}))?;
            receipt.sync_all()?;
        }
        cleanup?;
        result
    }
}
