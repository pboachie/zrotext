// SPDX-License-Identifier: AGPL-3.0-only
use super::Refusal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Test,
    Live,
}

/// Server-configured identity, never derived from event metadata or the browser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Namespace {
    id: [u8; 16],
    mode: Mode,
    provider_account: String,
}

impl Namespace {
    pub fn new(id: [u8; 16], mode: Mode, provider_account: &str) -> Result<Self, Refusal> {
        if id == [0; 16] || !valid_external_id(provider_account) {
            return Err(Refusal::InvalidConfiguration);
        }
        Ok(Self {
            id,
            mode,
            provider_account: provider_account.to_owned(),
        })
    }

    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn provider_account(&self) -> &str {
        &self.provider_account
    }
}

pub(super) fn valid_external_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Immutable database marker read under the caller's admission transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Marker {
    pub namespace: Namespace,
    pub policy_revision: u64,
    pub enabled: bool,
}

/// Identity from a reviewed current-state provider read, not a webhook body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIdentity {
    pub mode: Mode,
    pub provider_account: String,
}

#[derive(Clone, Debug, Default)]
pub struct Gate {
    verified: Option<Marker>,
}

impl Gate {
    /// Disabled is the only default. There is no free-access fallback for a
    /// hosted-paid route when billing is disabled, missing or unavailable.
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn verify(
        enabled: bool,
        expected: &Namespace,
        revision: u64,
        stored: &Marker,
        provider: &ProviderIdentity,
    ) -> Result<Self, Refusal> {
        if !enabled || !stored.enabled {
            return Err(Refusal::Disabled);
        }
        if revision == 0 || stored.policy_revision == 0 {
            return Err(Refusal::InvalidConfiguration);
        }
        if expected != &stored.namespace
            || provider.mode != expected.mode
            || provider.provider_account != expected.provider_account
        {
            return Err(Refusal::NamespaceMismatch);
        }
        if revision != stored.policy_revision {
            return Err(Refusal::StalePolicy);
        }
        Ok(Self {
            verified: Some(stored.clone()),
        })
    }

    /// Recheck the marker under every mutation transaction. A process-local
    /// startup proof cannot outlive a policy change or operator pause.
    pub fn check_marker(&self, stored: &Marker) -> Result<&Marker, Refusal> {
        let expected = self.verified.as_ref().ok_or(Refusal::Disabled)?;
        if !stored.enabled {
            return Err(Refusal::Disabled);
        }
        if stored.namespace != expected.namespace {
            return Err(Refusal::NamespaceMismatch);
        }
        if stored.policy_revision != expected.policy_revision {
            return Err(Refusal::StalePolicy);
        }
        Ok(expected)
    }

    pub fn marker(&self) -> Result<&Marker, Refusal> {
        self.verified.as_ref().ok_or(Refusal::Disabled)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    namespace: Namespace,
    owner: [u8; 16],
    customer: String,
    subscription: String,
}

impl Scope {
    /// Binding must come from authenticated server state. Events cannot create
    /// a customer/owner binding merely by carrying this shape.
    pub fn new(
        namespace: Namespace,
        owner: [u8; 16],
        customer: &str,
        subscription: &str,
    ) -> Result<Self, Refusal> {
        if owner == [0; 16] || !valid_external_id(customer) || !valid_external_id(subscription) {
            return Err(Refusal::InvalidConfiguration);
        }
        Ok(Self {
            namespace,
            owner,
            customer: customer.to_owned(),
            subscription: subscription.to_owned(),
        })
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub fn owner(&self) -> [u8; 16] {
        self.owner
    }

    pub fn customer(&self) -> &str {
        &self.customer
    }

    pub fn subscription(&self) -> &str {
        &self.subscription
    }

    pub fn check(&self, observed: &Self) -> Result<(), Refusal> {
        if self.namespace != observed.namespace {
            return Err(Refusal::NamespaceMismatch);
        }
        if self != observed {
            return Err(Refusal::TenantMismatch);
        }
        Ok(())
    }
}
