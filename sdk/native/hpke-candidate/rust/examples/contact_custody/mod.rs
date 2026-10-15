//! External installed consumer: fixture provisioning stays in the parent process.
use zrotext_hpke_candidate::contact::{Cancellation, Expected, FieldInput, Production, Statement};
pub struct Session {
    #[cfg(windows)]
    owned: Option<(
        zrotext_hpke_candidate::cng::ContactRootSigner,
        std::fs::File,
    )>,
}
impl Session {
    pub fn new() -> Self {
        if std::env::args().len() == 1 {
            return Self {
                #[cfg(windows)]
                owned: None,
            };
        }
        assert!(
            std::env::args().len() == 2 && std::env::args().nth(1).as_deref() == Some("--hardware")
        );
        #[cfg(not(windows))]
        panic!("Windows protected provider required");
        #[cfg(windows)]
        {
            use std::io::Write;
            use zrotext_hpke_candidate::cng::{ContactRootSigner, HardwareSigner, NativeError};
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let mut receipt = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(std::env::temp_dir().join(format!(
                    "zrotext-contact-owned-{:x}.json",
                    u128::from_le_bytes(random)
                )))
                .unwrap();
            let key = ContactRootSigner::create(|alias| {
                serde_json::to_writer(&mut receipt, &serde_json::json!({"pending_alias":alias}))
                    .map_err(|_| NativeError {
                        operation: "receipt write",
                        status: 0,
                    })?;
                receipt.sync_all().map_err(|_| NativeError {
                    operation: "receipt sync",
                    status: 0,
                })
            })
            .unwrap();
            // Establish cleanup ownership before any fallible setup observation.
            let session = Self {
                owned: Some((key, receipt)),
            };
            let key = &session.owned.as_ref().unwrap().0;
            let alias = key.alias().unwrap();
            let point = key.public_point().unwrap();
            assert!(HardwareSigner::open(&alias, &point).is_err());
            println!(
                "{}",
                serde_json::json!({"alias":alias,"public":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,point)})
            );
            std::io::stdout().flush().unwrap();
            session
        }
    }
    pub fn protected(&self) -> bool {
        #[cfg(windows)]
        {
            self.owned.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
    #[allow(dead_code)] // Shared consumer helper: field-only binary does not call mutation APIs.
    pub fn produce_mutation(
        &self,
        proposal: &zrotext_hpke_candidate::contact::mutation::Proposal,
        cancel: &Cancellation,
        closed: bool,
    ) -> Result<zrotext_hpke_candidate::contact::mutation::Production, ()> {
        #[cfg(windows)]
        {
            use zrotext_hpke_candidate::cng::ContactRootSigner;
            let key = &self.owned.as_ref().ok_or(())?.0;
            let borrowed = std::sync::Arc::new(
                ContactRootSigner::open(
                    &key.alias().map_err(|_| ())?,
                    &key.public_point().map_err(|_| ())?,
                )
                .map_err(|_| ())?,
            );
            assert!(
                borrowed.delete_created().is_err(),
                "borrowed deletion accepted"
            );
            if closed {
                borrowed.close().map_err(|_| ())?;
            }
            let result = zrotext_hpke_candidate::contact::mutation::produce_protected_mutation01(
                borrowed.clone(),
                proposal,
                cancel,
            )
            .map_err(|_| ());
            borrowed.close().map_err(|_| ())?;
            result
        }
        #[cfg(not(windows))]
        {
            let _ = (proposal, cancel, closed);
            Err(())
        }
    }
    pub fn produce(
        &self,
        st: &Statement,
        expected: &Expected,
        input: &FieldInput,
        cancel: &Cancellation,
        closed: bool,
    ) -> Result<Production, ()> {
        #[cfg(windows)]
        {
            use zrotext_hpke_candidate::cng::ContactRootSigner;
            let key = &self.owned.as_ref().ok_or(())?.0;
            let borrowed = std::sync::Arc::new(
                ContactRootSigner::open(
                    &key.alias().map_err(|_| ())?,
                    &key.public_point().map_err(|_| ())?,
                )
                .map_err(|_| ())?,
            );
            assert!(
                borrowed.delete_created().is_err(),
                "borrowed handle deleted owner key"
            );
            if closed {
                borrowed.close().map_err(|_| ())?;
            }
            let result = zrotext_hpke_candidate::contact::produce_protected_field01(
                borrowed.clone(),
                st,
                expected,
                input,
                cancel,
            )
            .map_err(|_| ());
            borrowed.close().map_err(|_| ())?;
            result
        }
        #[cfg(not(windows))]
        {
            let _ = (st, expected, input, cancel, closed);
            Err(())
        }
    }
}
#[cfg(windows)]
impl Drop for Session {
    fn drop(&mut self) {
        use std::io::{Seek, SeekFrom};
        if let Some((key, mut receipt)) = self.owned.take() {
            let cleanup = (|| -> Result<(), Box<dyn std::error::Error>> {
                let alias = key.alias();
                let point = key.public_point();
                key.delete_created()?;
                let (alias, point) = (alias?, point?);
                if zrotext_hpke_candidate::cng::ContactRootSigner::open(&alias, &point).is_ok() {
                    return Err("deleted key reopened".into());
                }
                receipt.set_len(0)?;
                receipt.seek(SeekFrom::Start(0))?;
                serde_json::to_writer(
                    &mut receipt,
                    &serde_json::json!({"owned_key_deleted":true}),
                )?;
                receipt.sync_all()?;
                Ok(())
            })();
            if cleanup.is_err() {
                eprintln!("owned contact cleanup failed; private receipt retained");
                std::process::exit(1);
            }
            println!("{}", serde_json::json!({"owned_key_deleted":true}));
        }
    }
}
