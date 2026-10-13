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
        compose::Recipient,
        compose02::{ComposeRequest02, compose_protected02},
        journal::JournalError,
        manifest::{Manifest, enroll_root, verify_manifest, verify_root_transition02},
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
    fn crypto<T>(v: std::result::Result<T, Error>) -> Result<T> {
        v.map_err(|e| format!("{e:?}").into())
    }
    fn journal<T>(v: std::result::Result<T, JournalError>) -> Result<T> {
        v.map_err(|e| format!("{e:?}").into())
    }
    fn proof(d: &serde_json::Value) -> Result<Manifest> {
        let root = crypto(enroll_root(&b(d, "rootPin"), &b(d, "fingerprint")))?;
        crypto(verify_manifest(&b(d, "manifest"), &root, None, 2, 10000))
    }
    fn request<'a>(
        d: &serde_json::Value,
        manifest: &'a Manifest,
        signer: &'a HardwareSigner,
        comparison: &'a dyn Fn() -> std::result::Result<u64, Error>,
    ) -> ComposeRequest02<'a> {
        let raw = b(d, "manifest");
        let recipients = (0..raw[150] as usize)
            .map(|i| &raw[151 + i * 149..151 + (i + 1) * 149])
            .filter(|k| k[0] == 1 || k[0] == 2)
            .map(|k| Recipient {
                role: k[0],
                id: k[1..33].try_into().unwrap(),
            })
            .collect();
        ComposeRequest02 {
            manifest,
            comparison,
            current: None,
            message: [49; 16],
            device: b(d, "device").try_into().unwrap(),
            line: b(d, "line").try_into().unwrap(),
            observed: 30000,
            expires: 40000,
            peer: "+12",
            content: CONTENT,
            signer,
            recipients,
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
        let comparison = || Ok(30000);
        let current = || Ok((&proof, 30000));
        let mut r = request(d, &proof, &signer, &comparison);
        r.current = Some(&current);
        let j = journal(OutboundJournal::open(
            c["Path"].as_str().ok_or("path")?,
            &b(d, "rootPin"),
            &b(d, "fingerprint"),
        ))?;
        let out = journal(j.compose_or_replay02(&r))?;
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
            let comparison = || Ok(clock.get());
            let current = || Ok((&proof, clock.get()));
            let mut r = request(&d, &proof, &signer, &comparison);
            r.current = Some(&current);
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
            let out = journal(j.compose_or_replay02(&r))?;
            need(journal(j.compose_or_replay02(&r))? == out, "exact replay")?;
            drop(j);
            let j = open()?;
            need(journal(j.compose_or_replay02(&r))? == out, "restart replay")?;
            let mut changed = r.clone();
            changed.content = "Different synthetic intent";
            need(
                matches!(j.compose_or_replay02(&changed), Err(JournalError::Conflict)),
                "intent conflict",
            )?;
            clock.set(31000);
            journal(j.compose_or_replay02(&r))?;
            drop(j);
            let j = open()?;
            clock.set(30000);
            need(j.compose_or_replay02(&r).is_err(), "restart clock rollback")?;
            clock.set(31000);
            let long = "x".repeat(32769);
            for text in ["", "\0", "\u{feff}bad", &long] {
                let mut bad = r.clone();
                bad.content = text;
                need(compose_protected02(&bad).is_err(), "strict text")?;
            }
            for peer in ["+1", "bad", "+000"] {
                let mut bad = r.clone();
                bad.peer = peer;
                need(compose_protected02(&bad).is_err(), "peer")?;
            }
            for expires in [30000, 930001, 1 << 63] {
                let mut bad = r.clone();
                bad.expires = expires;
                need(compose_protected02(&bad).is_err(), "expiry")?;
            }
            let mut bad = r.clone();
            bad.recipients.pop();
            need(compose_protected02(&bad).is_err(), "recipient count")?;
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
                Ok(31000)
            };
            let mut uncertain = r.clone();
            uncertain.message[0] ^= 1;
            uncertain.comparison = &lost;
            need(
                j.compose_or_replay02(&uncertain).is_err() && calls.get() == 3,
                "postcommit comparison loss",
            )?;
            let identity = [
                b(&d, "account").as_slice(),
                &uncertain.message,
                b(&d, "device").as_slice(),
                b(&d, "line").as_slice(),
            ]
            .concat();
            let db = rusqlite::Connection::open(&path)?;
            let saved: Vec<u8> = db.query_row(
                "SELECT envelope FROM outbound WHERE identity=?1",
                [identity],
                |r| r.get(0),
            )?;
            drop(db);
            uncertain.comparison = &comparison;
            need(
                journal(j.compose_or_replay02(&uncertain))? == saved,
                "ambiguous exact recovery",
            )?;
            let phase = Cell::new(0);
            let newer_comparison = || {
                phase.set(phase.get() + 1);
                Ok(if phase.get() == 3 { 32000 } else { 31000 })
            };
            let mut newer = r.clone();
            newer.message[0] ^= 2;
            let newer_current = || Ok((&proof, if phase.get() == 3 { 32000 } else { 31000 }));
            newer.current = Some(&newer_current);
            newer.comparison = &newer_comparison;
            journal(j.compose_or_replay02(&newer))?;
            drop(j);
            let j = open()?;
            newer.comparison = &comparison;
            newer.current = r.current;
            need(
                j.compose_or_replay02(&newer).is_err(),
                "postcommit comparison not persisted",
            )?;
            let mut boundaries = Vec::new();
            for observed in [0, 1] {
                let mut candidate = r.clone();
                candidate.message = [0; 16];
                candidate.observed = observed;
                candidate.expires = observed + 1;
                boundaries.push(STANDARD.encode(crypto(compose_protected02(&candidate))?));
                need(
                    j.compose_or_replay02(&candidate).is_err(),
                    "expired boundary persisted",
                )?;
            }
            let rotated_root = crypto(verify_root_transition02(
                &b(&d, "transition"),
                r.manifest,
                &b(&d, "newPoint"),
                33000,
            ))?;
            let rotated_manifest = crypto(verify_manifest(
                &b(&d, "newManifest"),
                &rotated_root,
                None,
                2,
                33000,
            ))?;
            let rotated_comparison = || Ok(33000);
            let mut rotated = r.clone();
            rotated.manifest = &rotated_manifest;
            rotated.message[0] ^= 4;
            rotated.comparison = &rotated_comparison;
            let rotated_current = || Ok((&rotated_manifest, 33000));
            rotated.current = Some(&rotated_current);
            let rotated_envelope = journal(j.compose_or_replay02(&rotated))?;
            drop(j);
            let j = open()?;
            need(
                journal(j.compose_or_replay02(&rotated))? == rotated_envelope,
                "rotated exact replay",
            )?;
            clock.set(33000);
            let root = crypto(enroll_root(&b(&d, "rootPin"), &b(&d, "fingerprint")))?;
            let retained = crypto(verify_manifest(
                &b(&d, "currentRetained"),
                &root,
                Some(&proof),
                2,
                33000,
            ))?;
            let retained_source = || Ok((&retained, 33000));
            let mut retained_request = r.clone();
            retained_request.current = Some(&retained_source);
            need(
                journal(j.compose_or_replay02(&retained_request))? == out,
                "retained current replay",
            )?;
            let revoked = crypto(verify_manifest(
                &b(&d, "currentRevoked"),
                &root,
                Some(&proof),
                2,
                33000,
            ))?;
            let revoked_source = || Ok((&revoked, 33000));
            retained_request.current = Some(&revoked_source);
            need(
                j.compose_or_replay02(&retained_request).is_err(),
                "revoked current replay",
            )?;
            retained_request.current = None;
            need(
                j.compose_or_replay02(&retained_request).is_err(),
                "missing current evidence",
            )?;
            let checks = Cell::new(0);
            let late_source = || {
                checks.set(checks.get() + 1);
                Ok((
                    if checks.get() == 3 {
                        &revoked
                    } else {
                        &retained
                    },
                    33000,
                ))
            };
            let mut late = r.clone();
            late.message[0] ^= 8;
            late.current = Some(&late_source);
            need(
                j.compose_or_replay02(&late).is_err(),
                "postcommit current revocation exposed",
            )?;
            let c = rusqlite::Connection::open(&path)?;
            let late_identity = [
                b(&d, "account").as_slice(),
                &late.message,
                &late.device,
                &late.line,
            ]
            .concat();
            let saved: Vec<u8> = c.query_row(
                "SELECT envelope FROM outbound WHERE identity=?1",
                [late_identity],
                |row| row.get(0),
            )?;
            drop(c);
            late.current = Some(&retained_source);
            need(
                journal(j.compose_or_replay02(&late))? == saved,
                "current revocation exact recovery",
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
            need(compose_protected02(&r).is_err(), "closed signer")?;
            drop(j);
            std::fs::remove_dir_all(dir)?;
            println!(
                "{}",
                serde_json::json!({"envelope":STANDARD.encode(out),"expectedText":CONTENT,"boundaries":boundaries,"rotatedEnvelope":STANDARD.encode(rotated_envelope),"checks":"exact replay, process CAS, ambiguity, clock rollback, strict input and custody passed"})
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
