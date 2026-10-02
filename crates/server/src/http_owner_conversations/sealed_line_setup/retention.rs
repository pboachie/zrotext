// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit unspawned retention lane; it removes expired public challenges and
//! clears unusable pending nonces, preserving immutable receipts and proofs.
use super::{lifecycle, registration};
use crate::{sealed_inbound::line_activation::sealed_exchange, sealed_root_ceremony};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

pub struct Retention {
    database_url: String,
}
impl Retention {
    pub(crate) fn new(database_url: String) -> Self {
        Self { database_url }
    }
    /// Runs only when the runtime explicitly spawns this returned capability.
    /// One worker-class database slot is held only during a bounded sweep.
    pub async fn run(self, draining: Arc<AtomicBool>, drain_notify: Arc<Notify>) {
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(30),
        );
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut unavailable_logged = false;
        loop {
            let notification = drain_notify.notified();
            tokio::pin!(notification);
            notification.as_mut().enable();
            if draining.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                biased;
                _=&mut notification=> {if draining.load(Ordering::Acquire) {break;}},
                _=ticks.tick()=> {
                    if draining.load(Ordering::Acquire) {break;}
                    let sweep=async {
                        let mut db=crate::runtime_db::connect_worker(&self.database_url).await.map_err(|_| ())?;
                        sweep(&mut db).await.map_err(|_| ())
                    };
                    let result=tokio::select! {
                        biased;
                        _=&mut notification=> {if draining.load(Ordering::Acquire) {break;} continue;},
                        result=tokio::time::timeout(Duration::from_secs(10),sweep)=>result,
                    };
                    match result {
                        Ok(Ok(_))=>unavailable_logged=false,
                        _ if !unavailable_logged=> {eprintln!("sealed setup retention unavailable");unavailable_logged=true;},
                        _=>{},
                    }
                }
            }
        }
    }
}
/// Cleanup takes only nonblocking row locks. Pending receipt locks serialize
/// nonce removal with activation; it never renews expired authorization.
pub(super) async fn sweep(
    client: &mut tokio_postgres::Client,
) -> Result<(u64, u64), sealed_root_ceremony::CeremonyError> {
    let tx = sealed_root_ceremony::begin(client).await?;
    lifecycle::require_installed(&tx).await?;
    let challenges = registration::cleanup(&tx, 100).await?;
    let nonces = sealed_exchange::cleanup(&tx, 100).await?;
    tx.commit().await?;
    Ok((challenges, nonces))
}
