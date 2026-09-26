// SPDX-License-Identifier: AGPL-3.0-only
//! Untrusted Android preconditions, scoped to one authenticated socket epoch.
use super::{DeviceSession, DeviceSocketState};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio_postgres::Client;

pub(super) const PROTOCOL: &str = "zrotext-device-status-v1";

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize)]
        pub(super) enum $name {
            $(#[serde(rename = $wire)] $variant),+
        }
        impl $name {
            fn wire(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
        }
    };
}
wire_enum!(SelectedSim { NotSelected => "not_selected", Active => "active", Inactive => "inactive", Unavailable => "unavailable" });
wire_enum!(SmsPermission { Granted => "granted", Denied => "denied", Unavailable => "unavailable" });
wire_enum!(AirplaneMode { Enabled => "enabled", Disabled => "disabled", Unavailable => "unavailable" });

pub(super) struct Report {
    pub selected_sim: SelectedSim,
    pub sms_permission: SmsPermission,
    pub airplane_mode: AirplaneMode,
}

#[derive(Default)]
pub(super) struct ReportBudget(Option<Instant>);
impl ReportBudget {
    // Enforced before checking out a database client; excess reports are ignored.
    pub fn admit(&mut self, now: Instant) -> bool {
        if self.0.is_some_and(|previous| {
            now.saturating_duration_since(previous) < Duration::from_secs(30)
        }) {
            return false;
        }
        self.0 = Some(now);
        true
    }
}

pub(super) async fn record(
    client: &mut Client,
    session: DeviceSession,
    state: &DeviceSocketState,
    report: Report,
) -> Result<bool, tokio_postgres::Error> {
    if state.draining.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(false);
    }
    let tx = client.transaction().await?;
    // Share locks keep revocation, a replacement epoch, and writer changes from
    // crossing the observation write. Identity always comes from the socket.
    let live = tx
        .query_opt(
            "SELECT 1 FROM device_sessions ds \
         JOIN devices d ON (d.account_id,d.id)=(ds.account_id,ds.device_id) \
         JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
         JOIN accounts a ON a.id=d.account_id JOIN sites s ON s.site_id=ds.site_id \
         JOIN deployment_authority p ON p.singleton=TRUE \
         WHERE ds.account_id=$1 AND ds.device_id=$2 AND ds.site_id=$3 AND ds.instance_id=$4 \
         AND ds.connection_epoch=$5 AND ds.deployment_epoch=$6 AND ds.lease_until>clock_timestamp() \
         AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL \
         AND s.enabled=TRUE AND s.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery() \
         FOR SHARE OF ds,d,k,a,s,p",
            &[
                &session.account_id,
                &session.device_id,
                &state.site_id,
                &state.instance_id,
                &session.connection_epoch,
                &state.deployment_epoch,
            ],
        )
        .await?;
    if live.is_none() {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO device_preconditions(device_id,account_id,connection_epoch,deployment_epoch,received_at,selected_sim,sms_permission,airplane_mode) \
         VALUES($1,$2,$3,$4,statement_timestamp(),$5,$6,$7) \
         ON CONFLICT(device_id) DO UPDATE SET account_id=EXCLUDED.account_id, \
         connection_epoch=EXCLUDED.connection_epoch,deployment_epoch=EXCLUDED.deployment_epoch, \
         received_at=EXCLUDED.received_at,selected_sim=EXCLUDED.selected_sim, \
         sms_permission=EXCLUDED.sms_permission,airplane_mode=EXCLUDED.airplane_mode",
        &[&session.device_id,&session.account_id,&session.connection_epoch,&state.deployment_epoch,
          &report.selected_sim.wire(),&report.sms_permission.wire(),&report.airplane_mode.wire()],
    ).await?;
    // Both the authority lock and the snapshot UPSERT can wait beyond the lease.
    // Recheck the current clock only after all mutation locks are held. A failed
    // final fence rolls back the snapshot, including its refreshed receipt time.
    let lease_live: bool = tx.query_one(
        "SELECT lease_until>clock_timestamp() FROM device_sessions WHERE account_id=$1 AND device_id=$2",
        &[&session.account_id, &session.device_id],
    ).await?.get(0);
    if !lease_live || state.draining.load(std::sync::atomic::Ordering::Acquire) {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_budget_limits_database_work_and_refuses_time_reversal() {
        let start = Instant::now();
        let mut budget = ReportBudget::default();
        assert!(budget.admit(start));
        assert!(!budget.admit(start + Duration::from_millis(29_999)));
        assert!(budget.admit(start + Duration::from_secs(30)));
        assert!(!budget.admit(start));
    }
}
