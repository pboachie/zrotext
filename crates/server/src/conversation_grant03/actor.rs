// SPDX-License-Identifier: AGPL-3.0-only
//! Immutable original enrolled actor minted by the typed grant factory.
//! Reading a point is not socket authentication or current content permission.
use super::*;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
use tokio_postgres::{GenericClient, Row};

pub(super) struct RetainedActor03 {
    pub(super) point: [u8; 65],
    pub(super) key_id: [u8; 32],
    pub(super) fetch: [u8; 32],
    pub(super) session: [u8; 32],
    pub(super) minted: u64,
}
fn digest(row: &Row, name: &str) -> Result<[u8; 32]> {
    let value: [u8; 32] = row
        .try_get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| Error::Unsupported)?;
    if value == [0; 32] {
        return Err(Error::Unsupported);
    }
    Ok(value)
}
fn established_key_id(point: &[u8; 65]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ZTSE/key/v1\0");
    hash.update([1, 1]);
    hash.update(point);
    hash.finalize().into()
}
impl RetainedActor03 {
    pub(super) async fn read<C: GenericClient + Sync>(tx: &C, grant: &GrantRow03) -> Result<Self> {
        let row = tx.query_opt(
            "SELECT * FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND attempt_id=$2",
            &[&grant.ids[0], &grant.ids[2]],
        ).await?.ok_or(Error::NotFound)?;
        Self::from_row(grant, &row)
    }
    pub(super) fn from_row(grant: &GrantRow03, row: &Row) -> Result<Self> {
        let point: [u8; 65] = row
            .try_get::<_, Vec<u8>>("original_enrolled_point")?
            .try_into()
            .map_err(|_| Error::Unsupported)?;
        let value = Self {
            point,
            key_id: digest(row, "original_enrolled_key_id")?,
            fetch: digest(row, "fetch_transcript_sha256")?,
            session: digest(row, "original_device_session_digest")?,
            minted: u64::try_from(row.try_get::<_, i64>("minted_ms")?)
                .map_err(|_| Error::Unsupported)?,
        };
        value.verifying_key()?;
        if row.try_get::<_, Uuid>("account_id")? != grant.ids[0]
            || row.try_get::<_, Uuid>("attempt_id")? != grant.ids[2]
            || row.try_get::<_, Uuid>("message_id")? != grant.ids[1]
            || row.try_get::<_, Uuid>("device_id")? != grant.ids[7]
            || value.key_id != established_key_id(&value.point)
            || value.fetch != crate::sealed_manifest03::sha(&grant.frame()?.fetch_transcript())
            || value.session != grant.digests[9]
            || value.minted != grant.numbers[8]
        {
            return Err(Error::Authentication);
        }
        Ok(value)
    }
    pub(super) fn verifying_key(&self) -> Result<VerifyingKey> {
        if self.point[0] != 4 {
            return Err(Error::Authentication);
        }
        VerifyingKey::from_sec1_bytes(&self.point).map_err(|_| Error::Authentication)
    }
    pub(super) fn matches_socket(&self, socket: crate::device_socket::SocketActor) -> Result<()> {
        if !socket.proof().matches_point(&self.point)
            || socket.proof().signing_key_id() != &self.key_id
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn matches_selected(&self, review: &HeldReviewed03<'_, '_>) -> Result<()> {
        if review
            .selected()
            .enrolled_signing_key()?
            .to_sec1_point(false)
            .as_bytes()
            != self.point
            || review.selected().device_session_digest() != &self.session
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

pub(super) fn socket_matches(
    socket: crate::device_socket::SocketActor,
    current: DeviceInterval03<'_>,
) -> Result<()> {
    let session = socket.session();
    let identity = socket.proof().identity();
    if session.account_id != current.session.account_id
        || session.device_id != current.session.device_id
        || session.connection_epoch != current.session.connection_epoch
        || identity.account_id != session.account_id
        || identity.device_id != session.device_id
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(super) fn verify_new(
    socket: crate::device_socket::SocketActor,
    current: DeviceInterval03<'_>,
    review: &HeldReviewed03<'_, '_>,
) -> Result<()> {
    socket_matches(socket, current)?;
    if !socket.proof().matches_point(
        review
            .selected()
            .enrolled_signing_key()?
            .to_sec1_point(false)
            .as_bytes(),
    ) {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn established_actor_key_id_uses_the_enrolled_domain_without_a_role_byte() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/device-protection-origin-v1.json"
        ))
        .unwrap();
        // Consume the existing public point; never regenerate its producer.
        let point: [u8; 65] = B
            .decode(v["parameters"]["enrolled_point"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut exact = b"ZTSE/key/v1\0\x01\x01".to_vec();
        exact.extend(point);
        assert_eq!(
            established_key_id(&point),
            <[u8; 32]>::from(Sha256::digest(exact))
        );
        assert_eq!(
            B.encode(established_key_id(&point)),
            v["parameters"]["enrolled_key_id"].as_str().unwrap()
        );
        let mut wrong = b"ZTSE/key/v1\0\x04\x01\x01".to_vec();
        wrong.extend(point);
        assert_ne!(
            established_key_id(&point),
            <[u8; 32]>::from(Sha256::digest(wrong))
        );
    }
}
