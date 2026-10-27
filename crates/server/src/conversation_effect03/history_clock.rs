// SPDX-License-Identifier: AGPL-3.0-only
//! A distinct passive clock request, never a current/content permission parser.
//! Its identifiers are untrusted selectors until the actual held adapter checks
//! the original grant actor and the independently verified current socket.
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use crate::sealed_manifest03::Check;
use uuid::Uuid;

const REQUEST: &str = "payload_profile_history_clock03_request";
pub const MAX_JSON_BYTES: usize = 4096;
object_body! {struct Body{v:u8,r#type:String,connection_epoch:i64,request_id:String,message_id:String,attempt_id:String}}

pub struct Request03 {
    pub connection_epoch: i64,
    pub request_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
}
fn id(value: &str) -> Check<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| "history clock UUID")?;
    if id.is_nil() || id.to_string() != value {
        return Err("history clock canonical UUID");
    }
    Ok(id)
}
impl Request03 {
    pub fn parse(raw: &str) -> Check<Option<Self>> {
        if raw.len() > MAX_JSON_BYTES {
            return Err("history clock frame size");
        }
        #[derive(serde::Deserialize)]
        struct Route {
            r#type: String,
        }
        let mut decoder = serde_json::Deserializer::from_str(raw);
        let route: Route =
            crate::sealed_inbound::line_activation::v2_runtime::decode_object(&mut decoder)
                .map_err(|_| "history clock object route")?;
        decoder.end().map_err(|_| "history clock trailing input")?;
        if route.r#type != REQUEST {
            return Ok(None);
        }
        let body: Body = serde_json::from_str(raw).map_err(|_| "history clock closed request")?;
        if body.v != 1 || body.r#type != REQUEST || body.connection_epoch <= 0 {
            return Err("history clock header/connection");
        }
        Ok(Some(Self {
            connection_epoch: body.connection_epoch,
            request_id: id(&body.request_id)?,
            message_id: id(&body.message_id)?,
            attempt_id: id(&body.attempt_id)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn request() -> Value {
        json!({"v":1,"type":REQUEST,"connection_epoch":7,
            "request_id":Uuid::from_u128(1),"message_id":Uuid::from_u128(2),
            "attempt_id":Uuid::from_u128(3)})
    }

    #[test]
    fn history_clock_has_its_own_exact_nonce_and_route() {
        let body = request();
        let parsed = Request03::parse(&body.to_string()).unwrap().unwrap();
        assert_eq!(parsed.connection_epoch, 7);
        assert_eq!(parsed.request_id, Uuid::from_u128(1));
        assert_eq!(parsed.message_id, Uuid::from_u128(2));
        assert_eq!(parsed.attempt_id, Uuid::from_u128(3));
        // Existing current/status parsers receive no broadened kind or JSON
        // conversion. A status timestamp cannot become a fresh clock here.
        assert!(
            super::super::wire::Request03::parse(&body.to_string())
                .unwrap()
                .is_none()
        );
        let mut other = body;
        other["type"] = json!("payload_profile_submit_status03_request");
        assert!(Request03::parse(&other.to_string()).unwrap().is_none());
    }

    #[test]
    fn history_clock_rejects_added_permission_fields_and_duplicate_or_missing_keys() {
        for extra in ["submit_once", "current", "lease", "server_time_ms"] {
            let mut body = request();
            body[extra] = json!(true);
            assert!(Request03::parse(&body.to_string()).is_err(), "{extra}");
        }
        for key in [
            "v",
            "type",
            "connection_epoch",
            "request_id",
            "message_id",
            "attempt_id",
        ] {
            let mut body = request();
            body.as_object_mut().unwrap().remove(key);
            assert!(Request03::parse(&body.to_string()).is_err(), "{key}");
        }
        let raw = request().to_string();
        for suffix in [
            ",\"request_id\":\"00000000-0000-0000-0000-000000000001\"}",
            r#","\u0072equest_id":"00000000-0000-0000-0000-000000000001"}"#,
        ] {
            assert!(Request03::parse(&format!("{}{suffix}", &raw[..raw.len() - 1])).is_err());
        }
        assert!(Request03::parse(&format!("[{raw}]")).is_err());
        assert!(Request03::parse(&format!("{raw}{{}}")).is_err());
        assert!(Request03::parse(&" ".repeat(4097)).is_err());
    }

    #[test]
    fn history_clock_requires_original_canonical_selectors_and_integer_epoch() {
        for value in [json!(0), json!(-1), json!("7"), json!(7.0), Value::Null] {
            let mut body = request();
            body["connection_epoch"] = value;
            assert!(Request03::parse(&body.to_string()).is_err());
        }
        for value in [
            json!(Uuid::nil()),
            json!("00000000000000000000000000000001"),
            json!("00000000-0000-0000-0000-00000000000A"),
            Value::Null,
        ] {
            let mut body = request();
            body["attempt_id"] = value;
            assert!(Request03::parse(&body.to_string()).is_err());
        }
    }
}
