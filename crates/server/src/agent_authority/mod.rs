// SPDX-License-Identifier: AGPL-3.0-only
//! Agent policy kernel. Callers must load and lock authoritative grant,
//! approval, suppression and action records in the same effect transaction.
//! This module does not mint authority from a client request or received text.

use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Metadata,
    ReadContent,
    Draft,
    Send,
}

/// Independent grants: reading metadata never grants content, drafting or send.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    pub metadata: bool,
    pub read_content: bool,
    pub draft: bool,
    pub send: bool,
}

impl Permissions {
    fn allows(self, operation: Operation) -> bool {
        match operation {
            Operation::Metadata => self.metadata,
            Operation::ReadContent => self.read_content,
            Operation::Draft => self.draft,
            Operation::Send => self.send,
        }
    }
}

/// Exact opaque action identity. The recipient is an account-keyed routing digest and
/// content is the independently verified unsigned envelope digest, never text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub account: Uuid,
    pub grant: Uuid,
    pub action: Uuid,
    pub message: Uuid,
    pub line: Uuid,
    pub device: Uuid,
    pub binding_generation: i64,
    pub recipient: [u8; 32],
    pub unsigned_envelope: [u8; 32],
    pub not_before_ms: i64,
    pub expires_ms: i64,
}

impl Action {
    /// Fixed-width, domain-separated encoding binds every editable field.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ZT/agent-owner-action/v1\0");
        for id in [
            self.account,
            self.grant,
            self.action,
            self.message,
            self.line,
            self.device,
        ] {
            hash.update(id.as_bytes());
        }
        hash.update(self.binding_generation.to_be_bytes());
        hash.update(self.recipient);
        hash.update(self.unsigned_envelope);
        hash.update(self.not_before_ms.to_be_bytes());
        hash.update(self.expires_ms.to_be_bytes());
        hash.finalize().into()
    }
}

/// A database snapshot, not a deserializable tool argument. Owner step-up and
/// the transaction store establish these facts; policy cannot establish them.
pub struct Grant {
    pub account: Uuid,
    pub id: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub binding_generation: i64,
    pub recipient: [u8; 32],
    pub permissions: Permissions,
    pub expires_ms: i64,
    pub revoked: bool,
    pub taken_over: bool,
    pub owner_self_notification: bool,
    pub reader_identity: Option<Uuid>,
    pub model_provider_identity: Option<Uuid>,
    pub model_reads_content: bool,
    pub message_limit: i32,
    pub turn_limit: i32,
}

pub struct Current {
    pub account: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub binding_generation: i64,
    pub now_ms: i64,
    pub suppressed: bool,
    pub reader_revoked: bool,
    pub messages_reserved: i32,
    pub turns_consumed: i32,
}

/// Authenticated owner record with its exact approved digest. Never populated
/// from an SMS, model response, SDK annotation or caller-supplied approved flag.
pub struct Approval {
    pub action_digest: [u8; 32],
    pub expires_ms: i64,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    InvalidPolicy,
    ForeignScope,
    MissingPermission,
    Revoked,
    TakenOver,
    Expired,
    Suppressed,
    ReaderUnavailable,
    NeedsOwnerApproval,
    TooEarly,
    BudgetExhausted,
}

impl Grant {
    /// Evaluated again at dispatch using fresh locked state. An admission or
    /// cached readiness decision cannot replace this authorization decision.
    pub fn authorize(&self, current: &Current, operation: Operation) -> Result<(), Denial> {
        if self.id.is_nil()
            || self.account.is_nil()
            || self.device.is_nil()
            || self.line.is_nil()
            || self.binding_generation <= 0
            || self.recipient == [0; 32]
            || !self.owner_self_notification
            || !(1..=100).contains(&self.message_limit)
            || !(1..=3).contains(&self.turn_limit)
            || (self.model_reads_content
                && (self.model_provider_identity.is_none() || !self.permissions.read_content))
        {
            return Err(Denial::InvalidPolicy);
        }
        if (
            self.account,
            self.device,
            self.line,
            self.binding_generation,
        ) != (
            current.account,
            current.device,
            current.line,
            current.binding_generation,
        ) {
            return Err(Denial::ForeignScope);
        }
        if self.revoked {
            return Err(Denial::Revoked);
        }
        if self.taken_over {
            return Err(Denial::TakenOver);
        }
        if current.now_ms <= 0 || current.now_ms >= self.expires_ms {
            return Err(Denial::Expired);
        }
        if !self.permissions.allows(operation) {
            return Err(Denial::MissingPermission);
        }
        if operation == Operation::ReadContent
            && (self.reader_identity.is_none() || current.reader_revoked)
        {
            return Err(Denial::ReaderUnavailable);
        }
        if operation == Operation::Send && current.suppressed {
            return Err(Denial::Suppressed);
        }
        Ok(())
    }

    /// Check before reserving a new action. Exact durable replay uses its
    /// recorded identity instead; it cannot create another reservation/effect.
    pub fn authorize_new_action(
        &self,
        current: &Current,
        action: &Action,
        approval: Option<&Approval>,
    ) -> Result<(), Denial> {
        self.authorize(current, Operation::Send)?;
        if (
            action.account,
            action.grant,
            action.device,
            action.line,
            action.binding_generation,
            action.recipient,
        ) != (
            self.account,
            self.id,
            self.device,
            self.line,
            self.binding_generation,
            self.recipient,
        ) || action.action.is_nil()
            || action.message.is_nil()
            || action.unsigned_envelope == [0; 32]
        {
            return Err(Denial::ForeignScope);
        }
        if action.not_before_ms <= 0
            || action.expires_ms <= action.not_before_ms
            || action.expires_ms > self.expires_ms
            || current.now_ms >= action.expires_ms
        {
            return Err(Denial::Expired);
        }
        if current.now_ms < action.not_before_ms {
            return Err(Denial::TooEarly);
        }
        approval
            .filter(|a| {
                !a.revoked
                    && a.expires_ms > current.now_ms
                    && a.expires_ms >= action.expires_ms
                    && a.action_digest == action.digest()
            })
            .ok_or(Denial::NeedsOwnerApproval)?;
        if current.messages_reserved < 0
            || current.turns_consumed < 0
            || current.messages_reserved >= self.message_limit
            || current.turns_consumed >= self.turn_limit
        {
            return Err(Denial::BudgetExhausted);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
