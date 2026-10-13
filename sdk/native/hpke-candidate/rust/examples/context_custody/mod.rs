use zrotext_hpke_candidate::{
    Error,
    manifest::Manifest,
    workflow_context::{WorkflowContextRole, WorkflowContextScope},
};
pub struct Session {
    #[cfg(windows)]
    owned: Option<(
        std::sync::Arc<zrotext_hpke_candidate::cng::HardwareRecipient>,
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
            use zrotext_hpke_candidate::cng::{HardwareRecipient, NativeError};
            HardwareRecipient::probe().unwrap();
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let mut receipt = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(std::env::temp_dir().join(format!(
                    "zrotext-context-owned-{:x}.json",
                    u128::from_le_bytes(random)
                )))
                .unwrap();
            let key = HardwareRecipient::create(|alias| {
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
            let session = Self {
                owned: Some((std::sync::Arc::new(key), receipt)),
            };
            let point = session.owned.as_ref().unwrap().0.public_point().unwrap();
            println!(
                "{}",
                serde_json::json!({"public":point.iter().map(|b|format!("{b:02x}")).collect::<String>()})
            );
            std::io::stdout().flush().unwrap();
            session
        }
    }
    pub fn open(
        &self,
        source: impl FnMut() -> Result<(std::sync::Arc<Manifest>, u64), Error> + Send + 'static,
        scope: &WorkflowContextScope,
        role: WorkflowContextRole,
        scalar: &[u8],
        envelope: &[u8],
        provider_mode: u8,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        #[cfg(not(windows))]
        let _ = provider_mode;
        #[cfg(windows)]
        if let Some((key, _)) = &self.owned {
            let mut source = source;
            assert!(scalar.is_empty(), "selected scalar exposed");
            if provider_mode != 0 {
                let borrowed = std::sync::Arc::new(
                    zrotext_hpke_candidate::cng::HardwareRecipient::open(
                        &key.alias().unwrap(),
                        &key.public_point().unwrap(),
                    )
                    .unwrap(),
                );
                if provider_mode == 1 {
                    let (m, now) = source()?;
                    let mut calls = 0;
                    return zrotext_hpke_candidate::workflow_context::open_current_protected_workflow_context(||{calls+=1;if calls==2 {source()?;borrowed.close().unwrap()};Ok((&*m,now))},scope,role,&borrowed,envelope);
                }
                let close = borrowed.clone();
                let mut calls = 0;
                return zrotext_hpke_candidate::workflow_context::bounded::open_protected(
                    &Default::default(),
                    move || {
                        let result = source();
                        calls += 1;
                        if calls == 2 {
                            close.close().unwrap()
                        };
                        result
                    },
                    scope.clone(),
                    role,
                    borrowed,
                    envelope,
                );
            }
            return zrotext_hpke_candidate::workflow_context::bounded::open_protected(
                &Default::default(),
                source,
                scope.clone(),
                role,
                key.clone(),
                envelope,
            );
        }
        zrotext_hpke_candidate::workflow_context::bounded::open_software(
            &Default::default(),
            source,
            scope.clone(),
            role,
            scalar,
            envelope,
        )
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
                key.delete()?;
                let (alias, point) = (alias?, point?);
                if zrotext_hpke_candidate::cng::HardwareRecipient::open(&alias, &point).is_ok() {
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
                eprintln!("owned hardware cleanup failed; private receipt retained");
                std::process::exit(1)
            }
            println!("{}", serde_json::json!({"owned_key_deleted":true}));
        }
    }
}
