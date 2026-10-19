// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded closed owner DTOs. Binary evidence remains untrusted until the
//! separate actual record/signature/currentness composition accepts it.
use crate::sealed_inbound::line_activation::v2_runtime::object_body;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;
#[derive(Clone, Copy)]
pub(super) enum Operation {
    Bootstrap,
    Current,
    Reserve,
    Status,
    Proof,
    Accept,
}
impl Operation {
    pub fn mutation(self) -> bool {
        matches!(self, Self::Reserve | Self::Accept)
    }
}
object_body! {struct Bootstrap {v:u8,line_id:String}}
object_body! {struct Status {v:u8,opening_id:String,line_id:String}}
object_body! {struct Proof {v:u8,opening_id:String,challenge_id:String}}
object_body! {struct Reserve {v:u8,opening_id:String,line_id:String,successor_manifest03:String,password:String,factor:String}}
object_body! {struct Accept {v:u8,opening_id:String,challenge_id:String,successor_manifest03:String,bundle:String,password:String,factor:String}}
pub(super) enum Body {
    Bootstrap(Uuid),
    Current(Uuid),
    Status(Uuid, Uuid),
    Proof(Uuid, Uuid),
    Reserve {
        opening: Uuid,
        line: Uuid,
        successor: Vec<u8>,
        password: String,
        factor: String,
    },
    Accept {
        opening: Uuid,
        challenge: Uuid,
        successor: Vec<u8>,
        bundle: Vec<u8>,
        password: String,
        factor: String,
    },
}
fn id(s: &str) -> Result<Uuid, StatusCode> {
    let v = Uuid::parse_str(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    if v.is_nil() || v.to_string() != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(v)
}
fn binary(s: &str, min: usize, max: usize) -> Result<Vec<u8>, StatusCode> {
    if s.len() > max.div_ceil(3) * 4
        || s.is_empty()
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = B.decode(s).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !(min..=max).contains(&bytes.len()) || B.encode(&bytes) != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(bytes)
}
fn version(v: u8) -> Result<(), StatusCode> {
    if v != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}
fn credentials(password: &str, factor: &str) -> Result<(), StatusCode> {
    if password.is_empty() || password.len() > 1024 || factor.is_empty() || factor.len() > 26 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}
pub(super) fn parse(op: Operation, bytes: &[u8]) -> Result<Body, StatusCode> {
    if bytes.is_empty() || bytes.len() > 96 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    macro_rules! body {
        ($ty:ty) => {
            serde_json::from_slice::<$ty>(bytes).map_err(|_| StatusCode::BAD_REQUEST)?
        };
    }
    Ok(match op {
        Operation::Current => {
            let b = body!(Bootstrap);
            version(b.v)?;
            Body::Current(id(&b.line_id)?)
        }
        Operation::Bootstrap => {
            let b = body!(Bootstrap);
            version(b.v)?;
            Body::Bootstrap(id(&b.line_id)?)
        }
        Operation::Status => {
            let b = body!(Status);
            version(b.v)?;
            Body::Status(id(&b.opening_id)?, id(&b.line_id)?)
        }
        Operation::Proof => {
            let b = body!(Proof);
            version(b.v)?;
            Body::Proof(id(&b.opening_id)?, id(&b.challenge_id)?)
        }
        Operation::Reserve => {
            let b = body!(Reserve);
            version(b.v)?;
            credentials(&b.password, &b.factor)?;
            Body::Reserve {
                opening: id(&b.opening_id)?,
                line: id(&b.line_id)?,
                successor: binary(&b.successor_manifest03, 366, 9753)?,
                password: b.password,
                factor: b.factor,
            }
        }
        Operation::Accept => {
            let b = body!(Accept);
            version(b.v)?;
            credentials(&b.password, &b.factor)?;
            Body::Accept {
                opening: id(&b.opening_id)?,
                challenge: id(&b.challenge_id)?,
                successor: binary(&b.successor_manifest03, 366, 9753)?,
                bundle: binary(&b.bundle, 628, 628)?,
                password: b.password,
                factor: b.factor,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_bodies_reject_arrays_extra_and_escaped_duplicate_fields() {
        let line = Uuid::from_u128(3);
        let valid = serde_json::json!({"v":1,"line_id":line.to_string()}).to_string();
        assert!(parse(Operation::Bootstrap, valid.as_bytes()).is_ok());
        for invalid in [
            format!("[1,\"{line}\"]"),
            format!("{{\"v\":1,\"line_id\":\"{line}\",\"unexpected\":true}}"),
            format!(r#"{{"v":1,"v\u0000":1,"line_id":"{line}"}}"#),
            format!(r#"{{"v":1,"\u0076":1,"line_id":"{line}"}}"#),
            format!("{{\"v\":1,\"line_id\":\"{line}\",\"line_id\":\"{line}\"}}"),
        ] {
            assert!(parse(Operation::Bootstrap, invalid.as_bytes()).is_err());
        }
    }
    #[test]
    fn canonical_ids_evidence_lengths_and_unused_bits_are_not_normalized() {
        assert!(id(&Uuid::nil().to_string()).is_err());
        assert!(id("00000000000000000000000000000003").is_err());
        let bytes = vec![1; 628];
        let encoded = B.encode(&bytes);
        assert_eq!(binary(&encoded, 628, 628).unwrap(), bytes);
        assert!(binary(&(encoded.clone() + "="), 628, 628).is_err());
        assert!(binary(&B.encode(vec![1; 627]), 628, 628).is_err());
        assert!(binary(&B.encode(vec![1; 629]), 628, 628).is_err());
        assert!(parse(Operation::Bootstrap, b"{\"v\":1,\"line_id\":\"\xff\"}").is_err());
        assert!(credentials("", "1").is_err());
        assert!(credentials("synthetic", &"x".repeat(27)).is_err());
    }
}
