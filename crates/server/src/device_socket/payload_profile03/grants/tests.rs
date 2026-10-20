// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn ready() -> ReadyFrame03 {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../protocol/v1/vectors/sealed-profile03-contract-01.json"
    ))
    .unwrap();
    ReadyFrame03::parse(&serde_json::to_vec(&value["readyFrame"]).unwrap()).unwrap()
}
fn session(ready: &ReadyFrame03) -> DeviceSession {
    DeviceSession {
        account_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        connection_epoch: ready.claims().connection_epoch,
    }
}
#[test]
fn readiness_survives_distinct_grants_without_resetting_publication_or_attempt_budget() {
    let ready = ready();
    let actor = session(&ready);
    let mut state = Readiness03::new();
    let now = Instant::now();
    state
        .accept(ready.clone(), actor, ready.claims().deployment_epoch)
        .unwrap();
    assert!(state.due(now));
    state.committed(now);
    assert!(state.present());
    assert!(!state.due(now + Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS - 1)));
    assert!(state.due(now + Duration::from_secs(MIN_SECONDS_BETWEEN_GRANTS)));
    state
        .accept(ready.clone(), actor, ready.claims().deployment_epoch)
        .unwrap();
    assert_eq!(state.issued, 1);
    assert_eq!(state.publications, 2);
    assert!(!state.due(now));
    state.issued = 1024;
    assert!(!state.due(now + Duration::from_secs(3600)));
    state
        .accept(ready.clone(), actor, ready.claims().deployment_epoch)
        .unwrap();
    assert!(!state.due(now + Duration::from_secs(3600)));
    while state.publications < 64 {
        state
            .accept(ready.clone(), actor, ready.claims().deployment_epoch)
            .unwrap();
    }
    assert!(
        state
            .accept(ready.clone(), actor, ready.claims().deployment_epoch)
            .is_none()
    );
    assert_eq!(state.issued, 1024);
}
#[test]
fn ready03_is_closed_and_cannot_change_actual_socket_identity_or_legacy_parser() {
    let ready = ready();
    let actor = session(&ready);
    let mut state = Readiness03::new();
    let deployment = ready.claims().deployment_epoch;
    let mut other = actor;
    other.connection_epoch += 1;
    assert!(state.accept(ready.clone(), other, deployment).is_none());
    assert!(state.accept(ready.clone(), actor, deployment + 1).is_none());
    assert_eq!(state.publications, 0);
    let raw = String::from_utf8(ready.to_json().unwrap()).unwrap();
    assert!(matches!(
        super::super::parse(&raw).unwrap(),
        Some(Incoming::Ready(_))
    ));
    let duplicate = format!("{{\"grant_version\":3,{}", &raw[1..]);
    assert!(super::super::parse(&duplicate).is_err());
    let extra = format!("{{\"extra\":1,{}", &raw[1..]);
    assert!(super::super::parse(&extra).is_err());
    assert!(super::super::parse(&format!("{}{}", raw, " ".repeat(MAX_FRAME_BYTES))).is_err());
    let legacy=serde_json::json!({"v":1,"type":"sealed_ready","grant_version":2,"connection_epoch":actor.connection_epoch,
        "line_id":Uuid::from_u128(3),"binding_generation":1,"reader_key_id":URL_SAFE_NO_PAD.encode([1;32])}).to_string();
    assert!(super::super::parse(&legacy).unwrap().is_none());
    assert!(serde_json::from_str::<ClientFrame>(&legacy).is_ok());
}
