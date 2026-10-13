use std::{
    io,
    time::{Duration, Instant},
};
use zrotext_hpke_candidate::original_http::{HttpError, OriginalHttp, Request};
fn main() {
    let v: serde_json::Value = serde_json::from_reader(io::stdin()).unwrap();
    let start = Instant::now();
    let mut state = "unavailable";
    if let Ok(client) = OriginalHttp::new(
        v["Origin"].as_str().unwrap(),
        Duration::from_millis(v["Timeout"].as_u64().unwrap()),
        v["Roots"].as_str().unwrap().as_bytes(),
    ) {
        let id = "11111111-1111-4111-8111-111111111111".to_string();
        let method = v["Method"].as_str().unwrap();
        let request = match method {
            "current" => Request::Current,
            "page" => Request::Page {
                limit: 20,
                cursor: None,
            },
            "read" => Request::Read {
                event_id: if v["Invalid"] == "uuid" {
                    "invalid".into()
                } else {
                    id
                },
            },
            "consume" => Request::OwnerReview {
                event_id: id.clone(),
                request_id: id,
                active_request_id: None,
            },
            "status" => Request::Status { consumption_id: id },
            _ => panic!("test method"),
        };
        state = match client.exchange(
            v["Grant"].as_str().unwrap(),
            if v["Invalid"] == "version" { 0 } else { 1 },
            request,
        ) {
            Ok(_) => "untrusted",
            Err(HttpError::Unknown) => "unknown",
            Err(HttpError::Unavailable) => "unavailable",
        };
    }
    println!(
        "{}",
        serde_json::json!({"state":state,"elapsed":start.elapsed().as_secs_f64()})
    );
}
