// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded encrypted-only custody, committed inside root enrollment. No private
//! root/recovery material is accepted. The default server mounts no adapter.

use crate::{
    auth::SessionPrincipal,
    sealed_root_ceremony::{self as ceremony, CeremonyError},
    sealed_root_enrollment as proof,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zrotext_root_material::{recovery_kit::decode_public_card, root_backup};

pub const MAX_BACKUP: usize = 748;
pub const MAX_CARD: usize = 645;
const DOMAIN: &[u8] = b"ZTSE/root-custody/v1\0";

/// Borrowed ciphertext/public bytes and a separate owner's independently
/// compared fingerprint. Neither a normal session nor public-card metadata may
/// supply the intended pin. The signature binds the exact enrollment and bundle.
pub struct Publication<'a> {
    pub encrypted_backup: &'a [u8],
    pub public_card: &'a [u8],
    pub independently_compared_fingerprint: [u8; 32],
    pub signature: &'a [u8],
}

/// Exact public custody statement for an independently controlled signing
/// client. This does not sign, decrypt, establish comparison or enroll a root.
pub fn statement(
    unsigned_enrollment: &[u8],
    backup: &[u8],
    card: &[u8],
    compared: &[u8; 32],
) -> Result<Vec<u8>, CeremonyError> {
    proof::parse(unsigned_enrollment)?;
    if backup.len() > MAX_BACKUP || card.len() > MAX_CARD {
        return Err("custody bounds".into());
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 4 + unsigned_enrollment.len() + 96);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(unsigned_enrollment.len() as u32).to_be_bytes());
    bytes.extend_from_slice(unsigned_enrollment);
    bytes.extend_from_slice(&Sha256::digest(backup));
    bytes.extend_from_slice(&Sha256::digest(card));
    bytes.extend_from_slice(compared);
    Ok(bytes)
}

pub(crate) struct Validated<'a> {
    publication: Publication<'a>,
    backup_id: Uuid,
    backup_digest: [u8; 32],
    card_digest: [u8; 32],
    unsigned: Vec<u8>,
}

pub(crate) fn validate<'a>(
    publication: Publication<'a>,
    root_pin: &[u8],
    account: Uuid,
    origin: &str,
    unsigned: &[u8],
) -> Result<Validated<'a>, CeremonyError> {
    let fingerprint = proof::root_fingerprint(root_pin, account.as_bytes())?;
    let enrollment = proof::parse(unsigned)?;
    if enrollment.account_id != *account.as_bytes()
        || enrollment.root_fingerprint != fingerprint
        || enrollment.origin != origin
    {
        return Err("custody enrollment identity".into());
    }
    if publication.independently_compared_fingerprint != fingerprint {
        return Err("independent root comparison required".into());
    }
    let expected = root_backup::ExpectedIdentity {
        account_id: *account.as_bytes(),
        origin: origin.to_owned(),
        root_fingerprint: fingerprint,
    };
    let backup_id = root_backup::validate_public_header(publication.encrypted_backup, &expected)
        .map_err(|_| CeremonyError::Rejected("encrypted backup identity"))?;
    let backup_digest = Sha256::digest(publication.encrypted_backup).into();
    decode_public_card(publication.public_card, &expected, &backup_digest)
        .map_err(|_| CeremonyError::Rejected("public card identity/digest"))?;
    let message = statement(
        unsigned,
        publication.encrypted_backup,
        publication.public_card,
        &publication.independently_compared_fingerprint,
    )?;
    let signature = Signature::from_slice(publication.signature)
        .map_err(|_| CeremonyError::Rejected("custody signature"))?;
    if signature.normalize_s().to_bytes().as_slice() != publication.signature {
        return Err("custody signature canonicality".into());
    }
    VerifyingKey::from_sec1_bytes(&root_pin[29..94])
        .map_err(|_| CeremonyError::Rejected("custody root"))?
        .verify(&message, &signature)
        .map_err(|_| CeremonyError::Rejected("custody signature"))?;
    Ok(Validated {
        unsigned: unsigned.to_vec(),
        card_digest: Sha256::digest(publication.public_card).into(),
        publication,
        backup_id: Uuid::from_bytes(backup_id),
        backup_digest,
    })
}

pub(crate) async fn insert(
    tx: &Transaction<'_>,
    receipt: &ceremony::Receipt,
    bundle: Validated<'_>,
) -> Result<(), CeremonyError> {
    tx.execute("INSERT INTO sealed_root_custody(account_id,challenge_id,backup_id,generation,root_pin,root_fingerprint,encrypted_backup,public_card,backup_sha256,card_sha256,committed_ms,unsigned_enrollment,custody_signature) \
        VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        &[&receipt.account_id,&receipt.challenge_id,&bundle.backup_id,&receipt.root_pin,
          &receipt.root_fingerprint, &bundle.publication.encrypted_backup,&bundle.publication.public_card,
          &&bundle.backup_digest[..],&&bundle.card_digest[..],&receipt.completed_ms,&bundle.unsigned,&bundle.publication.signature]).await?;
    Ok(())
}

/// The export contains only the original immutable ciphertext/public bytes.
/// No Debug implementation permits accidental bundle logging.
pub struct Export {
    pub account_id: Uuid,
    pub challenge_id: Uuid,
    pub backup_id: Uuid,
    pub generation: i64,
    pub root_pin: Vec<u8>,
    pub root_fingerprint: Vec<u8>,
    pub encrypted_backup: Vec<u8>,
    pub public_card: Vec<u8>,
    pub committed_ms: i64,
    pub unsigned_enrollment: Vec<u8>,
    pub custody_signature: Vec<u8>,
}

/// Current-owner export/reconciliation; lock authority before account to match
/// admission. A historical bundle never repins a client or authorizes dispatch.
pub async fn export(
    client: &mut Client,
    principal: &SessionPrincipal,
    origin: &str,
    independently_compared: &[u8; 32],
) -> Result<Option<Export>, CeremonyError> {
    let tx = ceremony::begin(client).await?;
    let account = principal.tenant.account_id();
    let authority = tx
        .query_opt(
            "SELECT root_pin,root_fingerprint,generation FROM sealed_manifest_authorities \
        WHERE account_id=$1 FOR SHARE",
            &[&account],
        )
        .await?;
    ceremony::owner_locks(&tx, principal, false).await?;
    let Some(authority) = authority else {
        tx.commit().await?;
        return Ok(None);
    };
    let fingerprint: Vec<u8> = authority.get(1);
    if fingerprint.as_slice() != independently_compared || authority.get::<_, i64>(2) != 1 {
        return Err("current independently compared root required".into());
    }
    let row = tx.query_opt("SELECT challenge_id,backup_id,generation,root_pin,root_fingerprint,encrypted_backup,public_card,backup_sha256,card_sha256,committed_ms,unsigned_enrollment,custody_signature \
        FROM sealed_root_custody WHERE account_id=$1", &[&account]).await?;
    let result = if let Some(row) = row {
        let root_pin: Vec<u8> = row.get(3);
        let backup: Vec<u8> = row.get(5);
        let card: Vec<u8> = row.get(6);
        let unsigned: Vec<u8> = row.get(10);
        let signature: Vec<u8> = row.get(11);
        if root_pin != authority.get::<_, Vec<u8>>(0)
            || row.get::<_, Vec<u8>>(4) != fingerprint
            || row.get::<_, Vec<u8>>(7) != Sha256::digest(&backup).to_vec()
            || row.get::<_, Vec<u8>>(8) != Sha256::digest(&card).to_vec()
        {
            return Err("custody integrity/current root".into());
        }
        let expected = root_backup::ExpectedIdentity {
            account_id: *account.as_bytes(),
            origin: origin.to_owned(),
            root_fingerprint: *independently_compared,
        };
        let backup_id = root_backup::validate_public_header(&backup, &expected)
            .map_err(|_| CeremonyError::Rejected("stored backup identity"))?;
        decode_public_card(&card, &expected, &Sha256::digest(&backup).into())
            .map_err(|_| CeremonyError::Rejected("stored card identity"))?;
        if Uuid::from_bytes(backup_id) != row.get::<_, Uuid>(1) || row.get::<_, i64>(2) != 1 {
            return Err("custody generation/backup ID".into());
        }
        let challenge = proof::parse(&unsigned)?;
        if challenge.account_id != *account.as_bytes()
            || challenge.root_fingerprint != *independently_compared
            || Uuid::from_bytes(challenge.challenge_id) != row.get::<_, Uuid>(0)
        {
            return Err("custody enrollment context".into());
        }
        validate(
            Publication {
                encrypted_backup: &backup,
                public_card: &card,
                independently_compared_fingerprint: *independently_compared,
                signature: &signature,
            },
            &root_pin,
            account,
            origin,
            &unsigned,
        )?;
        Some(Export {
            account_id: account,
            challenge_id: row.get(0),
            backup_id: row.get(1),
            generation: 1,
            root_pin,
            root_fingerprint: fingerprint,
            encrypted_backup: backup,
            public_card: card,
            committed_ms: row.get(9),
            unsigned_enrollment: unsigned,
            custody_signature: signature,
        })
    } else {
        None
    };
    ceremony::live(&tx, principal).await?;
    tx.commit().await?;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests;
