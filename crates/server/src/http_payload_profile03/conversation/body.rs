// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Operation {
    Reserve,
    Request,
    Status,
    OpeningStatus,
    Context,
    Stop,
}
object_body! {struct Mapping{connector_id:String,read_grant_id:String,key_id:String}}
object_body! {struct Reserve{v:u8,opening_id:String,line_id:String,peer:String,archive_reader_key_id:String,phone_signer_key_id:String,browser_signer_key_id:String,interval_expires_ms:String,integration_readers:Vec<Mapping>}}
object_body! {struct Request03{v:u8,opening_id:String,interval_id:String,statement:String,owner_signature:String,password:String,factor:String}}
object_body! {struct Status{v:u8,opening_id:String,interval_id:String}}
object_body! {struct OpeningStatus{v:u8,opening_id:String}}
object_body! {struct Context{v:u8,request_id:String,opening_id:String,interval_id:String}}
object_body! {struct Stop{v:u8,interval_id:String}}
pub(super) enum Body {
    Reserve {
        opening: Uuid,
        line: Uuid,
        peer: String,
        archive: [u8; 32],
        phone: [u8; 32],
        browser: [u8; 32],
        expires: u64,
        integrations: Vec<IntegrationReader03>,
    },
    Request {
        opening: Uuid,
        interval: Uuid,
        statement: Vec<u8>,
        signature: Vec<u8>,
        password: String,
        factor: String,
    },
    Status {
        opening: Uuid,
        interval: Uuid,
    },
    OpeningStatus {
        opening: Uuid,
    },
    Context {
        request: Uuid,
        opening: Uuid,
        interval: Uuid,
    },
    Stop {
        interval: Uuid,
    },
}
fn key(raw: &str) -> Result<[u8; 32], StatusCode> {
    let value: [u8; 32] = super::super::request::binary(raw, 32, 32)?
        .try_into()
        .unwrap();
    if value == [0; 32] {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(value)
}
fn decimal(raw: &str) -> Result<u64, StatusCode> {
    let n = raw.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?;
    if n == 0 || n > i64::MAX as u64 || n.to_string() != raw {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(n)
}
pub(super) fn parse(op: Operation, bytes: &[u8]) -> Result<Body, StatusCode> {
    use super::super::request::{binary, credentials, id, version};
    if bytes.is_empty() || bytes.len() > 96 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    macro_rules! read {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes).map_err(|_| StatusCode::BAD_REQUEST)?
        };
    }
    Ok(match op {
        Operation::Reserve => {
            let b = read!(Reserve);
            version(b.v)?;
            let peer = b.peer.as_bytes();
            if !(3..=16).contains(&peer.len())
                || peer[0] != b'+'
                || !(b'1'..=b'9').contains(&peer[1])
                || !peer[2..].iter().all(u8::is_ascii_digit)
                || b.integration_readers.len() > 6
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            let mut integrations: Vec<IntegrationReader03> = Vec::new();
            for r in b.integration_readers {
                let value = IntegrationReader03 {
                    connector_id: id(&r.connector_id)?,
                    read_grant_id: id(&r.read_grant_id)?,
                    key_id: key(&r.key_id)?,
                };
                if integrations
                    .last()
                    .is_some_and(|r| r.key_id >= value.key_id)
                    || integrations.iter().any(|r| {
                        r.connector_id == value.connector_id
                            || r.read_grant_id == value.read_grant_id
                    })
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                integrations.push(value);
            }
            Body::Reserve {
                opening: id(&b.opening_id)?,
                line: id(&b.line_id)?,
                peer: b.peer,
                archive: key(&b.archive_reader_key_id)?,
                phone: key(&b.phone_signer_key_id)?,
                browser: key(&b.browser_signer_key_id)?,
                expires: decimal(&b.interval_expires_ms)?,
                integrations,
            }
        }
        Operation::Request => {
            let b = read!(Request03);
            version(b.v)?;
            credentials(&b.password, &b.factor)?;
            Body::Request {
                opening: id(&b.opening_id)?,
                interval: id(&b.interval_id)?,
                statement: binary(&b.statement, 695, 1092)?,
                signature: binary(&b.owner_signature, 64, 64)?,
                password: b.password,
                factor: b.factor,
            }
        }
        Operation::Status => {
            let b = read!(Status);
            version(b.v)?;
            Body::Status {
                opening: id(&b.opening_id)?,
                interval: id(&b.interval_id)?,
            }
        }
        Operation::OpeningStatus => {
            let b = read!(OpeningStatus);
            version(b.v)?;
            Body::OpeningStatus {
                opening: id(&b.opening_id)?,
            }
        }
        Operation::Context => {
            let b = read!(Context);
            version(b.v)?;
            Body::Context {
                request: id(&b.request_id)?,
                opening: id(&b.opening_id)?,
                interval: id(&b.interval_id)?,
            }
        }
        Operation::Stop => {
            let b = read!(Stop);
            version(b.v)?;
            Body::Stop {
                interval: id(&b.interval_id)?,
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    #[test]
    fn context_and_opening_reads_are_distinct_closed_nonce_correlated_shapes() {
        let request = Uuid::from_u128(1);
        let opening = Uuid::from_u128(2);
        let interval = Uuid::from_u128(3);
        let context=serde_json::json!({"v":1,"request_id":request,"opening_id":opening,"interval_id":interval}).to_string();
        let status = serde_json::json!({"v":1,"opening_id":opening}).to_string();
        assert!(parse(Operation::Context, context.as_bytes()).is_ok());
        assert!(parse(Operation::OpeningStatus, status.as_bytes()).is_ok());
        assert!(parse(Operation::Status, status.as_bytes()).is_err());
        assert!(parse(Operation::Context, status.as_bytes()).is_err());
        assert!(parse(Operation::OpeningStatus, context.as_bytes()).is_err());
        for raw in [
            format!("{{\"owner_session_id\":\"x\",{}", &context[1..]),
            format!("{{\"request_id\":\"{request}\",{}", &context[1..]),
            context.replace(&request.to_string(), &Uuid::nil().to_string()),
            "[]".into(),
        ] {
            assert!(parse(Operation::Context, raw.as_bytes()).is_err());
        }
    }
    #[test]
    fn interval_bodies_are_closed_and_preserve_original_opening_and_mapping_scope() {
        let opening = Uuid::from_u128(1);
        let line = Uuid::from_u128(2);
        let b = serde_json::json!({"v":1,"opening_id":opening,"line_id":line,"peer":"+12","archive_reader_key_id":B.encode([1;32]),"phone_signer_key_id":B.encode([2;32]),"browser_signer_key_id":B.encode([3;32]),"interval_expires_ms":"1000","integration_readers":[]});
        let raw = b.to_string();
        assert!(parse(Operation::Reserve, raw.as_bytes()).is_ok());
        for suffix in [r#", "unexpected":true}"#, r#", "\u0076":1}"#] {
            let changed = format!("{}{}", &raw[..raw.len() - 1], suffix);
            assert!(parse(Operation::Reserve, changed.as_bytes()).is_err());
        }
        for value in ["0", "01000", "+1000", "1e3", "9223372036854775808"] {
            let mut b = b.clone();
            b["interval_expires_ms"] = value.into();
            assert!(parse(Operation::Reserve, b.to_string().as_bytes()).is_err());
        }
        assert!(parse(Operation::Stop, format!("[1,\"{line}\"]").as_bytes()).is_err());
    }
}
