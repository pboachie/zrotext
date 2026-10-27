// SPDX-License-Identifier: AGPL-3.0-only
//! Distinct typed evidence/history transport on the actual enrolled socket.
//! Route recognition supplies no original actor, current projection or permit.
use super::*;
use crate::conversation_effect03::{
    history_clock,
    wire::{Kind03, OrdinaryAdmission03, Request03},
};
use crate::conversation_grant03::effects;
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy)]
enum Route03 {
    Effect(Kind03),
    Clock,
}
pub(super) struct Incoming {
    route: Route03,
    raw: String,
}
pub(super) fn parse(raw: &str) -> Result<Option<Incoming>, ()> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    #[derive(Deserialize)]
    struct Route {
        r#type: String,
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let route: Route =
        crate::sealed_inbound::line_activation::v2_runtime::decode_object(&mut decoder)
            .map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    let route = if route.r#type == "payload_profile_history_clock03_request" {
        Route03::Clock
    } else if let Some(kind) = Kind03::from_name(&route.r#type) {
        Route03::Effect(kind)
    } else {
        return Ok(None);
    };
    // Full closed decoding occurs only AFTER the actual current actor's request
    // admission COMMIT, including malformed recognized request bodies.
    Ok(Some(Incoming {
        route,
        raw: raw.to_owned(),
    }))
}
pub(super) fn dispatch<'a>(
    socket: &'a mut WebSocket,
    state: &'a DeviceSocketState,
    actor: SocketActor,
    current_origin: Option<&'a str>,
    frame: Incoming,
) -> Pin<Box<impl Future<Output = Option<()>> + Send + 'a>> {
    Box::pin(async move {
        let admission = match frame.route {
            Route03::Effect(kind) => kind.admission(),
            Route03::Clock => OrdinaryAdmission03::Read,
        };
        let mut client = runtime_db::connect_device(&state.database_url).await.ok()?;
        let admitted = effects::admit(&mut client, actor, state, admission)
            .await
            .ok()?;
        let value = match frame.route {
            Route03::Clock => {
                let request = history_clock::Request03::parse(&frame.raw).ok()??;
                effects::history_clock(&mut client, admitted, state, request)
                    .await
                    .ok()?
            }
            Route03::Effect(kind) => {
                let request = Request03::parse(&frame.raw).ok()??;
                if request.kind() != kind {
                    return None;
                }
                effects::apply(&mut client, admitted, state, current_origin, request)
                    .await
                    .ok()?
            }
        };
        drop(client);
        let raw = serde_json::to_string(&value).ok()?;
        if raw.len() > 192 * 1024 {
            return None;
        }
        socket.send(Message::Text(raw.into())).await.ok()
    })
}

#[cfg(test)]
mod tests;
