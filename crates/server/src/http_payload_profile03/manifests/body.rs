// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    manifest_install03::live::{HistoryCursor03, Position03},
    sealed_inbound::line_activation::v2_runtime::object_body,
};
use uuid::Uuid;
#[derive(Clone, Copy)]
pub(super) enum Operation {
    Install,
    Status,
    History,
    Current,
}
object_body! {struct Current{v:u8,line_id:String}}
object_body! {struct Install{v:u8,opening_id:String,statement:String,signature:String,successor_manifest03:String,password:String,factor:String}}
object_body! {struct Status{v:u8,opening_id:String,statement_sha256:String,successor_sha256:String,signature_sha256:String}}
// Value occurs only on these three primitive nullable fields. Unlike Option,
// a missing field is refused; nested objects/arrays are never accepted here.
object_body! {struct History{v:u8,line_id:String,after_version:String,after_digest:String,after_ancestry_sha256:String,tip_version:serde_json::Value,tip_digest:serde_json::Value,tip_ancestry_sha256:serde_json::Value}}
pub(super) enum Body {
    Install {
        opening: Uuid,
        statement: Vec<u8>,
        successor: Vec<u8>,
        signature: Vec<u8>,
        password: String,
        factor: String,
    },
    Status {
        opening: Uuid,
        hashes: [[u8; 32]; 3],
    },
    History(HistoryCursor03),
    Current(Uuid),
}
fn number(s: &str) -> Result<u64, StatusCode> {
    let value = s
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if value.to_string() != s {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(value)
}
fn digest(s: &str) -> Result<[u8; 32], StatusCode> {
    request::binary(s, 32, 32)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)
}
pub(super) fn cursor(
    line: &str,
    after_version: &str,
    after_digest: &str,
    after_prefix: &str,
    tip: [&serde_json::Value; 3],
) -> Result<HistoryCursor03, StatusCode> {
    let tip = if tip.iter().all(|v| v.is_null()) {
        None
    } else {
        let text = |i: usize| tip[i].as_str().ok_or(StatusCode::BAD_REQUEST);
        Some(Position03 {
            version: number(text(0)?)?,
            digest: digest(text(1)?)?,
            prefix: digest(text(2)?)?,
        })
    };
    Ok(HistoryCursor03 {
        line: request::id(line)?,
        after: Position03 {
            version: number(after_version)?,
            digest: digest(after_digest)?,
            prefix: digest(after_prefix)?,
        },
        tip,
    })
}
pub(super) fn parse(op: Operation, raw: &[u8]) -> Result<Body, StatusCode> {
    if raw.is_empty() || raw.len() > 96 * 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    macro_rules! body {
        ($t:ty) => {
            serde_json::from_slice::<$t>(raw).map_err(|_| StatusCode::BAD_REQUEST)?
        };
    }
    Ok(match op {
        Operation::Current => {
            let b = body!(Current);
            request::version(b.v)?;
            Body::Current(request::id(&b.line_id)?)
        }
        Operation::Install => {
            let b = body!(Install);
            request::version(b.v)?;
            request::credentials(&b.password, &b.factor)?;
            Body::Install {
                opening: request::id(&b.opening_id)?,
                statement: request::binary(&b.statement, 513, 513)?,
                signature: request::binary(&b.signature, 64, 64)?,
                successor: request::binary(&b.successor_manifest03, 366, 9753)?,
                password: b.password,
                factor: b.factor,
            }
        }
        Operation::Status => {
            let b = body!(Status);
            request::version(b.v)?;
            Body::Status {
                opening: request::id(&b.opening_id)?,
                hashes: [
                    digest(&b.statement_sha256)?,
                    digest(&b.successor_sha256)?,
                    digest(&b.signature_sha256)?,
                ],
            }
        }
        Operation::History => {
            let b = body!(History);
            request::version(b.v)?;
            Body::History(cursor(
                &b.line_id,
                &b.after_version,
                &b.after_digest,
                &b.after_ancestry_sha256,
                [&b.tip_version, &b.tip_digest, &b.tip_ancestry_sha256],
            )?)
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
    #[test]
    fn history_requires_all_three_nullable_tip_fields_and_canonical_closed_scope() {
        let digest = B.encode([1u8; 32]);
        let valid = serde_json::json!({"v":1,"line_id":Uuid::from_u128(3),"after_version":"2","after_digest":digest,"after_ancestry_sha256":digest,"tip_version":null,"tip_digest":null,"tip_ancestry_sha256":null});
        assert!(parse(Operation::History, &serde_json::to_vec(&valid).unwrap()).is_ok());
        for field in ["tip_version", "tip_digest", "tip_ancestry_sha256"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(parse(Operation::History, &serde_json::to_vec(&missing).unwrap()).is_err());
            let mut mixed = valid.clone();
            mixed[field] = serde_json::json!("2");
            assert!(parse(Operation::History, &serde_json::to_vec(&mixed).unwrap()).is_err());
        }
        for version in ["02", "+2", "0", "9223372036854775808"] {
            let mut invalid = valid.clone();
            invalid["after_version"] = serde_json::json!(version);
            assert!(parse(Operation::History, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let encoded = valid.to_string();
        let duplicate = format!("{{\"v\":1,{}", &encoded[1..]);
        assert!(parse(Operation::History, duplicate.as_bytes()).is_err());
        assert!(parse(Operation::History, format!("[{encoded}]").as_bytes()).is_err());
    }
}
