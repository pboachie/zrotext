// SPDX-License-Identifier: AGPL-3.0-only
use super::database_capacity_tests::Fixture;
use super::*;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn status_rolls_back_when_lease_or_drain_changes_during_authority_or_snapshot_lock_wait() {
    let fixture = Fixture::new().await;
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/041_device_preconditions.sql"
        ))
        .await
        .unwrap();
    fixture
        .db
        .batch_execute(include_str!(
            "../../../../deploy/compose/migrations/047_device_network_service.sql"
        ))
        .await
        .unwrap();
    let (device, _) = fixture.device().await;
    let state = socket_state(fixture.url.clone(), "capacity-test");
    let session = DeviceSession {
        account_id: fixture.account_id,
        device_id: device,
        connection_epoch: 1,
    };
    fixture.db.execute("INSERT INTO device_sessions(device_id,account_id,site_id,instance_id,connection_epoch,deployment_epoch,lease_until) VALUES($1,$2,$3,$4,1,1,clock_timestamp()+interval '1 minute')", &[&device,&fixture.account_id,&state.site_id,&state.instance_id]).await.unwrap();
    fixture.db.execute("INSERT INTO device_preconditions(device_id,account_id,connection_epoch,deployment_epoch,received_at,selected_sim,sms_permission,airplane_mode) VALUES($1,$2,1,1,clock_timestamp(),'active','denied','disabled')", &[&device,&fixture.account_id]).await.unwrap();
    let (mut locker, connection) = tokio_postgres::connect(&fixture.url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let mut outcomes = Vec::new();
    for snapshot_lock in [false, true] {
        for expire_lease in [true, false] {
            state.draining.store(false, Ordering::Release);
            let seconds: f64 = if expire_lease { 2.0 } else { 60.0 };
            fixture.db.execute("UPDATE device_sessions SET lease_until=clock_timestamp()+$2*interval '1 second' WHERE device_id=$1", &[&device,&seconds]).await.unwrap();
            fixture
                .db
                .execute(
                    "UPDATE device_preconditions SET sms_permission='denied' WHERE device_id=$1",
                    &[&device],
                )
                .await
                .unwrap();
            let prior: String = fixture
                .db
                .query_one(
                    "SELECT received_at::text FROM device_preconditions WHERE device_id=$1",
                    &[&device],
                )
                .await
                .unwrap()
                .get(0);
            let tx = locker.transaction().await.unwrap();
            let lock_sql = if snapshot_lock {
                "SELECT device_id FROM device_preconditions WHERE device_id=$1 FOR UPDATE"
            } else {
                "SELECT device_id FROM device_keys WHERE device_id=$1 FOR UPDATE"
            };
            tx.query_one(lock_sql, &[&device]).await.unwrap();
            let (mut writer, connection) =
                tokio_postgres::connect(&fixture.url, NoTls).await.unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            let pid: i32 = writer
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let report_state = state.clone();
            let pending = tokio::spawn(async move {
                preconditions::record(
                    &mut writer,
                    session,
                    &report_state,
                    preconditions::Report {
                        selected_sim: preconditions::SelectedSim::Active,
                        sms_permission: preconditions::SmsPermission::Granted,
                        airplane_mode: preconditions::AirplaneMode::Disabled,
                        network_service: None,
                    },
                )
                .await
                .unwrap()
            });
            // Observe an actual PostgreSQL lock wait, not an assumed scheduler delay.
            timeout(Duration::from_secs(5), async {
                loop {
                    let blocked: bool = fixture
                        .db
                        .query_one("SELECT cardinality(pg_blocking_pids($1))>0", &[&pid])
                        .await
                        .unwrap()
                        .get(0);
                    if blocked {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(fixture.db.query_one("SELECT lease_until>clock_timestamp() FROM device_sessions WHERE device_id=$1", &[&device]).await.unwrap().get::<_,bool>(0));
            if expire_lease {
                timeout(Duration::from_secs(5), async {
                    while fixture.db.query_one("SELECT lease_until>clock_timestamp() FROM device_sessions WHERE device_id=$1", &[&device]).await.unwrap().get::<_,bool>(0) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.unwrap();
            } else {
                state.draining.store(true, Ordering::Release);
            }
            tx.commit().await.unwrap();
            let accepted = timeout(Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap();
            let unchanged: bool = fixture.db.query_one("SELECT sms_permission='denied' AND received_at::text=$2 FROM device_preconditions WHERE device_id=$1", &[&device,&prior]).await.unwrap().get(0);
            outcomes.push((snapshot_lock, expire_lease, accepted, unchanged));
        }
    }
    fixture.finish().await;
    assert_eq!(
        outcomes,
        vec![
            (false, true, false, true),
            (false, false, false, true),
            (true, true, false, true),
            (true, false, false, true)
        ]
    );
}
