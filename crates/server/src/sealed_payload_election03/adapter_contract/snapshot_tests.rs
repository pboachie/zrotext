// SPDX-License-Identifier: AGPL-3.0-only
//! Called by the ignored disposable-fence fixture; no production SQL installed.
use tokio_postgres::{Client, IsolationLevel, error::SqlState};
use uuid::Uuid;

pub(super) async fn old_snapshots_refuse(
    owner: &mut Client,
    writer: &mut Client,
    account: Uuid,
    key: i64,
) {
    for isolation in [IsolationLevel::RepeatableRead, IsolationLevel::Serializable] {
        let old = writer
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        // Freeze a snapshot on an unrelated untouched row. The future03 row
        // does not yet exist, and changing only it cannot refresh this snapshot.
        old.query_one("SELECT counter FROM leases WHERE account=$1", &[&account])
            .await
            .unwrap();
        let election = owner.transaction().await.unwrap();
        assert!(
            election
                .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
        election
            .execute(
                "INSERT INTO current_elections VALUES($1,3,$2)",
                &[&account, &vec![3u8; 32]],
            )
            .await
            .unwrap();
        // Production acceptance must atomically advance its pre-existing stable
        // anchor, even when the03 current-selection row is a new insertion.
        election
            .execute(
                "UPDATE selection SET epoch=epoch+1 WHERE account=$1",
                &[&account],
            )
            .await
            .unwrap();
        election.commit().await.unwrap();
        let refusal = old
            .execute(
                "INSERT INTO queue VALUES($1,$2,2,NULL)",
                &[&account, &Uuid::new_v4()],
            )
            .await;
        assert!(
            matches!(
                refusal.as_ref().err().and_then(|error| error.code()),
                Some(&SqlState::T_R_SERIALIZATION_FAILURE)
            ),
            "old {isolation:?} snapshot must not authorize legacy02 DML: {refusal:?}"
        );
        old.rollback().await.unwrap();
        assert_eq!(
            owner
                .query_one("SELECT count(*) FROM queue WHERE account=$1", &[&account])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        // Fixture reset only; the production contract never removes an accepted
        // selection or rolls a generation/epoch backwards.
        owner
            .execute(
                "DELETE FROM current_elections WHERE account=$1",
                &[&account],
            )
            .await
            .unwrap();
        owner
            .execute(
                "UPDATE selection SET epoch=epoch+1 WHERE account=$1",
                &[&account],
            )
            .await
            .unwrap();
        let old = writer
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .await
            .unwrap();
        old.query_one("SELECT counter FROM leases WHERE account=$1", &[&account])
            .await
            .unwrap();
        let later_account = Uuid::new_v4();
        let addition = owner.transaction().await.unwrap();
        addition
            .execute("INSERT INTO selection VALUES($1,1)", &[&later_account])
            .await
            .unwrap();
        addition
            .execute(
                "INSERT INTO current_elections VALUES($1,3,$2)",
                &[&later_account, &vec![3u8; 32]],
            )
            .await
            .unwrap();
        addition.commit().await.unwrap();
        let refusal = old
            .execute(
                "INSERT INTO queue VALUES($1,$2,2,NULL)",
                &[&later_account, &Uuid::new_v4()],
            )
            .await
            .unwrap_err();
        assert_eq!(
            refusal.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "an invisible anchor is refusal, never default02"
        );
        old.rollback().await.unwrap();
    }
}
