// SPDX-License-Identifier: AGPL-3.0-only
//! Receipt upload on the existing authenticated phone channel. No API key or plaintext.
use super::*;
use crate::sealed_inbound::ingest::ingest_conversation;

pub(super) async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    challenge: Uuid,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    // Only a selector: the stored canonical installation supplies the full scope.
    let interval = Uuid::from_slice(bytes.get(166..182).ok_or(ConversationError::Invalid)?)
        .map_err(|_| ConversationError::Invalid)?;
    let row = client.query_opt(
        "SELECT statement FROM conversation_intervals WHERE account_id=$1 AND id=$2 AND phase='active'",
        &[&authenticated.device.account_id, &interval],
    ).await?.ok_or(ConversationError::Forbidden)?;
    let original: Option<Vec<u8>> = row.get(0);
    let statement =
        activation::Statement::decode(original.as_deref().ok_or(ConversationError::Forbidden)?)?;
    let expected = scope(&statement)?;
    let start = 118 + expected.len();
    if statement.device != authenticated.device.device_id
        || bytes.get(118..start) != Some(expected.as_slice())
    {
        return Err(ConversationError::Forbidden);
    }
    let length = u32::from_be_bytes(
        bytes
            .get(start..start + 4)
            .ok_or(ConversationError::Invalid)?
            .try_into()
            .map_err(|_| ConversationError::Invalid)?,
    ) as usize;
    if !(1..=40_000).contains(&length) || bytes.len() != start + 4 + length {
        return Err(ConversationError::Invalid);
    }
    let envelope = &bytes[start + 4..];
    // A race with renewal fails closed inside ingest. No submitted manifest can establish trust.
    let manifest: Vec<u8> = client.query_opt(
        "SELECT manifest FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL",
        &[&authenticated.device.account_id],
    ).await?.ok_or(ConversationError::Forbidden)?.get(0);
    let outcome = ingest_conversation(
        client,
        authenticated.device,
        statement.line,
        statement.generation,
        &manifest,
        envelope,
        activation::CaptureInterval {
            interval,
            activation_digest: statement.activation_digest,
        },
    )
    .await
    .map_err(|error| match error {
        crate::sealed_inbound::ingest::IngestError::Database(error) => {
            ConversationError::Database(error)
        }
        _ => ConversationError::Forbidden,
    })?;
    let mut reply = header(authenticated, 13, challenge)?;
    reply.extend_from_slice(outcome.event_id.as_bytes());
    reply.extend_from_slice(&Sha256::digest(envelope));
    reply.push(u8::from(outcome.created));
    Ok(reply) // Ingest has committed before an ACK can be returned.
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires ZT_INBOUND_TEST_DATABASE_URL; isolated synthetic schema"]
    async fn authenticated_capture_commits_exact_retry_and_stop_rejects_upload() {
        let (f, _, statement) = activation::tests::pending().await;
        activation::tests::activate(&f, &statement).await;
        let authenticated = AuthenticatedChannelSession {
            device: f.session(),
            phone_session: Uuid::new_v4(),
            origin_hash: [9; 32],
        };
        let event = Uuid::new_v4();
        let now: i64 =
            f.db.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let envelope =
            crate::http_owner_conversations::tests::envelope(&f, event, 1, now as u64, b"+12");
        let nonce = Uuid::new_v4();
        let request = [
            header(&authenticated, 12, nonce).unwrap(),
            scope(&statement).unwrap(),
            (envelope.len() as u32).to_be_bytes().to_vec(),
            envelope.clone(),
        ]
        .concat();
        let first = super::super::handle(&mut f.connect().await, &authenticated, &request)
            .await
            .unwrap();
        assert_eq!(&first[..118], header(&authenticated, 13, nonce).unwrap());
        assert_eq!(&first[118..134], event.as_bytes());
        assert_eq!(&first[134..166], Sha256::digest(&envelope).as_slice());
        assert_eq!(first[166], 1);
        let retry = super::super::handle(&mut f.connect().await, &authenticated, &request)
            .await
            .unwrap();
        assert_eq!(&retry[..166], &first[..166]);
        assert_eq!(retry[166], 0);
        let stop = [
            header(&authenticated, 3, Uuid::new_v4()).unwrap(),
            scope(&statement).unwrap(),
        ]
        .concat();
        super::super::handle(&mut f.connect().await, &authenticated, &stop)
            .await
            .unwrap();
        assert!(
            super::super::handle(&mut f.connect().await, &authenticated, &request)
                .await
                .is_err()
        );
        assert_eq!(
            f.db.query_one("SELECT COUNT(*) FROM sealed_inbound_events", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        f.cleanup().await;
    }
}
