// SPDX-License-Identifier: AGPL-3.0-only
//! Per-connection conversation authority after the existing enrolled-device proof.
use super::{DeviceSession, DeviceSocketState};
use crate::{
    http_owner_conversations::{
        ConversationError,
        channel::{self, AuthenticatedChannelSession},
    },
    inbound::InboundSession,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone)]
pub(super) struct Policy {
    origin_hash: [u8; 32],
    pub(super) sealed_line_setup: bool,
}
pub(super) struct Negotiated {
    phone_session: Uuid,
    origin_hash: [u8; 32],
    device: DeviceSession,
    deployment_epoch: i64,
}
impl Policy {
    pub(super) fn new(origin: &str) -> Result<Self, &'static str> {
        let url = url::Url::parse(origin).map_err(|_| "Conversation WSS origin invalid")?;
        if url.scheme() != "wss"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err("Conversation WSS origin invalid");
        }
        let host = url.host_str().ok_or("Conversation WSS origin invalid")?;
        let port = url.port().unwrap_or(443);
        if port == 0 {
            return Err("Conversation WSS origin invalid");
        }
        let canonical = format!("wss://{}:{port}", host.to_ascii_lowercase());
        Ok(Self {
            origin_hash: Sha256::digest(canonical.as_bytes()).into(),
            sealed_line_setup: false,
        })
    }
    pub(super) fn negotiate(
        &self,
        device: DeviceSession,
        deployment_epoch: i64,
        challenge: Uuid,
    ) -> Result<(Negotiated, String), ConversationError> {
        if device.account_id.is_nil()
            || device.device_id.is_nil()
            || device.connection_epoch <= 0
            || deployment_epoch <= 0
            || challenge.is_nil()
        {
            return Err(ConversationError::Invalid);
        }
        let held = Negotiated {
            phone_session: Uuid::new_v4(),
            origin_hash: self.origin_hash,
            device,
            deployment_epoch,
        };
        let origin = held
            .origin_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let reply=serde_json::json!({"v":1,"type":"conversation_session","challenge":challenge,"account_id":device.account_id,"device_id":device.device_id,"phone_session":held.phone_session,"connection_epoch":device.connection_epoch,"deployment_epoch":deployment_epoch,"origin_hash":origin}).to_string();
        Ok((held, reply))
    }
}
impl Negotiated {
    pub(super) async fn execution_current(
        &self,
        client: &mut tokio_postgres::Client,
        device: DeviceSession,
        state: &DeviceSocketState,
        message: Uuid,
        attempt: Uuid,
    ) -> Result<bool, ConversationError> {
        if device != self.device || state.deployment_epoch != self.deployment_epoch {
            return Ok(false);
        }
        crate::http_owner_conversations::channel::execution::permission::current(
            client,
            &AuthenticatedChannelSession {
                device: InboundSession {
                    account_id: device.account_id,
                    device_id: device.device_id,
                    site_id: state.site_id.as_str(),
                    instance_id: state.instance_id.as_str(),
                    connection_epoch: device.connection_epoch,
                    deployment_epoch: self.deployment_epoch,
                },
                phone_session: self.phone_session,
                origin_hash: self.origin_hash,
            },
            message,
            attempt,
        )
        .await
    }
    pub(super) async fn handle(
        &self,
        client: &mut tokio_postgres::Client,
        device: DeviceSession,
        state: &DeviceSocketState,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ConversationError> {
        if device != self.device || state.deployment_epoch != self.deployment_epoch {
            return Err(ConversationError::Forbidden);
        }
        channel::handle(
            client,
            &AuthenticatedChannelSession {
                device: InboundSession {
                    account_id: device.account_id,
                    device_id: device.device_id,
                    connection_epoch: device.connection_epoch,
                    site_id: &state.site_id,
                    instance_id: &state.instance_id,
                    deployment_epoch: state.deployment_epoch,
                },
                phone_session: self.phone_session,
                origin_hash: self.origin_hash,
            },
            bytes,
        )
        .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_is_origin_and_authenticated_connection_bound() {
        let p = Policy::new("wss://EXAMPLE.org").unwrap();
        assert_eq!(
            p.origin_hash,
            Policy::new("wss://example.org:443/").unwrap().origin_hash
        );
        let device = DeviceSession {
            account_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            connection_epoch: 7,
        };
        let challenge = Uuid::new_v4();
        let (a, json) = p.negotiate(device, 3, challenge).unwrap();
        let (b, _) = p.negotiate(device, 3, challenge).unwrap();
        assert_ne!(a.phone_session, b.phone_session);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["challenge"], challenge.to_string());
        assert_eq!(v["account_id"], device.account_id.to_string());
        assert_eq!(v["connection_epoch"], 7);
        assert!(p.negotiate(device, 0, challenge).is_err());
        assert!(p.negotiate(device, 3, Uuid::nil()).is_err());
    }
    #[test]
    fn origin_refuses_credentials_path_query_and_cleartext() {
        for origin in [
            "ws://example.org",
            "wss://user@example.org",
            "wss://example.org/path",
            "wss://example.org?q=1",
            "wss://example.org#x",
            "wss://example.org:0",
        ] {
            assert!(Policy::new(origin).is_err());
        }
    }
}
