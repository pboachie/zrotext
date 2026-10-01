// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant line-scoped connector registration and key lifecycle (#640).
//! No production route calls this module.
//!
//! A connector is a customer-controlled integration client. Its identity is
//! one manifest role-3 (integration reader) public key: registration binds
//! server-side grants to that exact manifest record, it never mints new
//! cryptographic authority. Reading/decrypting and sending/signing are
//! separate grants, each constrained to explicit lines (and optionally to an
//! explicit conversation set), time-bounded, and independently revocable.
//!
//! Registration is two-phase: an owner session proposes, and a *different*
//! live owner session approves while the accepted manifest still has the
//! exact generation/version/digest recorded at proposal. Approval refuses a
//! stale or forked manifest; authorization refuses a changed generation, a
//! retired key, a revoked or expired grant, and a revoked line. Key rotation
//! replaces the public point and retires the old one; a used point can never
//! be registered again in the account, so a revoked or lost key cannot be
//! resurrected through re-registration. Recovery from key loss is always a
//! fresh two-phase registration with a new key.
//!
//! Every lifecycle decision and every authorization outcome is appended to
//! `connector_audit_events` (identifiers and reasons only). Owners can export
//! those access records and erase them per connector; account erasure
//! cascades. There is no implicit managed-AI reader, no plaintext fallback,
//! and no storage of message content here. Dispatch runtimes (#615/#641)
//! must recheck `authorize_reader_wrap`/`authorize_send` inside their
//! dispatch transaction; these functions are gates, not queues, and a
//! revocation summary reports the outstanding authorized-send count a
//! dispatcher must stop. Private key material never enters this module: only
//! public points, derived key ids, grants and audit rows are stored, and no
//! raw key bytes are logged.

use crate::{
    auth::{AuthError, SessionPrincipal, TokenHasher, abuse_limits},
    sealed_manifest::{self, ChainPosition, ManifestTrust, VerifiedManifest},
};
use p256::ecdsa::VerifyingKey;
use tokio_postgres::{Client, IsolationLevel, Transaction};
use uuid::Uuid;

/// At most this many pending+active connectors per account.
pub const MAX_CONNECTORS_PER_ACCOUNT: i64 = 8;
/// At most this many grants per registration request.
pub const MAX_GRANTS_PER_REGISTRATION: usize = 8;
/// At most this many conversation ids in one grant restriction.
pub const MAX_CONVERSATION_RESTRICTION: usize = 32;
/// Registrations and grants never outlive 90 days from creation.
pub const MAX_LIFETIME_MS: u64 = 90 * 86_400_000;
/// Manifest role-3 scope bits a read grant may request (mirrors the manifest
/// reader checks: 4 = read outbound, 8 = read inbound, 12 = both).
pub const READ_OUTBOUND: u16 = 4;
pub const READ_INBOUND: u16 = 8;
pub const READ_BOTH: u16 = 12;
/// Local registration policy; this does not change general session
/// authentication. A session unused longer than this cannot act here.
const REGISTRATION_IDLE_HOURS: i32 = 72;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("connector registry rejected: {0}")]
    Rejected(&'static str),
    #[error("connector registry authentication failed")]
    Authentication(#[from] AuthError),
    #[error("connector registry database operation failed")]
    Database(#[from] tokio_postgres::Error),
}
impl From<&'static str> for RegistryError {
    fn from(value: &'static str) -> Self {
        Self::Rejected(value)
    }
}

/// The grant kinds a registration may request. Send and read are never
/// conflated: one grant row carries exactly one kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantKind {
    /// Sealed reader-wrap creation for the connector's own manifest role-3
    /// key. `directions` must be one of READ_OUTBOUND/READ_INBOUND/READ_BOTH
    /// and a subset of the manifest record's scope.
    Read { directions: u16 },
    /// Workflow send/sign authority. The manifest grants no signing role to
    /// integrations; this is the server-side grant the future dispatch
    /// runtime composes with exact approvals (#615).
    Send,
}

impl GrantKind {
    fn wire(&self) -> &'static str {
        match self {
            GrantKind::Read { .. } => "read",
            GrantKind::Send => "send",
        }
    }
    fn directions(&self) -> i16 {
        match self {
            GrantKind::Read { directions } => *directions as i16,
            GrantKind::Send => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GrantRequest {
    pub kind: GrantKind,
    pub line_id: Uuid,
    /// When non-empty, the read grant applies only to these opaque
    /// conversation ids; the conversation transport owns their meaning.
    pub conversation_restriction: Vec<Uuid>,
    pub expires_ms: u64,
}

#[derive(Clone, Debug)]
pub struct RegistrationRequest {
    /// Owner-chosen label; no protocol meaning.
    pub display_name: String,
    /// The connector's manifest role-3 public point (65-byte SEC1).
    pub key_point: [u8; 65],
    pub grants: Vec<GrantRequest>,
    pub expires_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RegistrationTicket {
    pub account_id: Uuid,
    pub connector_id: Uuid,
    pub key_id: [u8; 32],
    pub manifest_generation: u64,
    pub manifest_version: u64,
    pub expires_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RevocationSummary {
    pub connector_id: Uuid,
    /// Grants that were live and are now fenced.
    pub grants_stopped: i64,
    /// Send authorizations recorded for this connector before revocation;
    /// dispatchers must stop exactly this outstanding work.
    pub send_authorizations: i64,
}

/// Proof a connector may build one reader wrap naming its own role-3 key.
/// The wrap target is always exactly `(role 3, key_id)`; callers must not
/// widen it to devices, the archive reader, or the owner root.
#[derive(Debug, Eq, PartialEq)]
pub struct WrapAuthorization {
    pub connector_id: Uuid,
    pub grant_id: Uuid,
    pub key_id: [u8; 32],
    pub manifest_generation: u64,
    pub manifest_version: u64,
}

/// Proof a connector holds a live send grant for one line. The future
/// dispatch runtime rechecks this in its dispatch transaction and applies
/// its own exact-approval and budget policy on top.
#[derive(Debug, Eq, PartialEq)]
pub struct SendAuthorization {
    pub connector_id: Uuid,
    pub grant_id: Uuid,
    pub manifest_generation: u64,
    pub manifest_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationState {
    Pending,
    Active,
    Revoked,
}

#[derive(Debug)]
pub struct GrantView {
    pub grant_id: Uuid,
    pub kind: GrantKind,
    pub line_id: Uuid,
    pub conversation_restriction: Vec<Uuid>,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub revoked_ms: Option<i64>,
}

#[derive(Debug)]
pub struct RegistrationView {
    pub connector_id: Uuid,
    pub display_name: String,
    pub state: RegistrationState,
    /// Public key id (domain-separated digest of the point), never the point.
    pub key_id: [u8; 32],
    pub manifest_generation: i64,
    pub manifest_version: i64,
    pub proposed_ms: i64,
    pub approved_ms: Option<i64>,
    pub expires_ms: i64,
    pub revoked_ms: Option<i64>,
    pub grants: Vec<GrantView>,
}

/// One exported access-record row. Identifiers, outcome and reason only.
#[derive(Debug, Eq, PartialEq)]
pub struct AccessRecord {
    pub event_id: i64,
    pub connector_id: Uuid,
    pub grant_id: Option<Uuid>,
    pub action: String,
    pub outcome: String,
    pub reason: String,
    pub recorded_ms: i64,
}

#[derive(Debug)]
pub struct AccessExport {
    pub registrations: Vec<RegistrationView>,
    pub records: Vec<AccessRecord>,
    pub exported_ms: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ErasedCounts {
    pub connector_id: Uuid,
    pub audit_events: u64,
}

async fn begin<'client>(
    client: &'client mut Client,
    account: &Uuid,
) -> Result<Transaction<'client>, RegistryError> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    // Sealed admission and custody lock manifest authority before account
    // rows. Take that same first lock for every connector transaction, before
    // owner/account and connector locks, so concurrent operations cannot cycle.
    // A missing or revoked authority is not an authentication decision here:
    // revocation and audit still work, and authority-consuming paths retain
    // current_manifest's complete live-manifest verification below.
    tx.query_opt(
        "SELECT account_id FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
        &[account],
    )
    .await?;
    Ok(tx)
}

async fn clock(tx: &Transaction<'_>, previous: u64) -> Result<u64, RegistryError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if now <= 0 || (now as u64) < previous {
        return Err("database time regressed".into());
    }
    Ok(now as u64)
}

/// Lock and authenticate the acting owner: active account, owner membership,
/// verified MFA user, live session and enabled owner MFA, exactly the root
/// ceremony fence. Registration never trusts the session's role copy alone.
pub(crate) async fn owner_fence(
    tx: &Transaction<'_>,
    principal: &SessionPrincipal,
) -> Result<(), RegistryError> {
    let account = principal.tenant.account_id();
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&account],
    )
    .await?
    .ok_or(RegistryError::Rejected("inactive account"))?;
    tx.query_opt(
        "SELECT id FROM users WHERE id=$1 AND email_verified_at IS NOT NULL AND mfa_enabled FOR UPDATE",
        &[&principal.user_id],
    )
    .await?
    .ok_or(RegistryError::Rejected("verified MFA owner required"))?;
    tx.query_opt(
        "SELECT user_id FROM memberships WHERE account_id=$1 AND user_id=$2 AND role='owner' FOR SHARE",
        &[&account, &principal.user_id],
    )
    .await?
    .ok_or(RegistryError::Rejected("owner membership"))?;
    tx.query_opt(
        "SELECT id FROM sessions WHERE id=$1 AND account_id=$2 AND user_id=$3 FOR UPDATE",
        &[&principal.session_id, &account, &principal.user_id],
    )
    .await?
    .ok_or(RegistryError::Rejected("session identity"))?;
    tx.query_opt(
        "SELECT account_id FROM owner_mfa WHERE account_id=$1 AND user_id=$2 AND enabled_at IS NOT NULL FOR UPDATE",
        &[&account, &principal.user_id],
    )
    .await?
    .ok_or(RegistryError::Rejected("enabled MFA required"))?;
    if !tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
         JOIN users u ON u.id=m.user_id JOIN sessions s ON s.account_id=a.id AND s.user_id=u.id \
         JOIN owner_mfa f ON f.account_id=a.id AND f.user_id=u.id \
         WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL AND m.role='owner' \
         AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL \
         AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
         AND COALESCE(s.last_used_at,s.created_at)>clock_timestamp()-make_interval(hours=>$4))",
            &[
                &account,
                &principal.user_id,
                &principal.session_id,
                &REGISTRATION_IDLE_HOURS,
            ],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err("owner/session/MFA fence".into());
    }
    Ok(())
}

/// Verify the account's currently accepted manifest fresh at database time
/// and return it with that time. An authority without an accepted manifest
/// (version 0), a revoked authority, or an expired accepted manifest fails
/// closed: connector authority cannot predate or outlive it.
async fn current_manifest(
    tx: &Transaction<'_>,
    account: &Uuid,
    previous_clock: u64,
) -> Result<(VerifiedManifest, u64), RegistryError> {
    let row = tx
        .query_opt(
            "SELECT root_pin,root_fingerprint,generation,version,semantic_digest,manifest,last_verified_ms \
         FROM sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR UPDATE",
            &[account],
        )
        .await?
        .ok_or(RegistryError::Rejected(
            "missing/revoked manifest authority",
        ))?;
    let high_water: i64 = row.get(6);
    let pin: Vec<u8> = row.get(0);
    let fingerprint: Vec<u8> = row.get(1);
    let generation: i64 = row.get(2);
    let version: i64 = row.get(3);
    let digest: Option<Vec<u8>> = row.get(4);
    let bytes: Option<Vec<u8>> = row.get(5);
    if version <= 0 {
        return Err("no accepted manifest".into());
    }
    let digest = digest
        .ok_or("stored digest")?
        .try_into()
        .map_err(|_| "stored digest")?;
    let bytes = bytes.ok_or("stored manifest")?;
    let trust = ManifestTrust {
        account_id: *account.as_bytes(),
        root_fingerprint: fingerprint.try_into().map_err(|_| "stored fingerprint")?,
        generation: generation.try_into().map_err(|_| "stored generation")?,
        position: ChainPosition::Current {
            version: version as u64,
            digest,
        },
    };
    // Floor trusted time on the stored high water exactly like the manifest
    // store's wall_time: a host clock step backwards must fail closed instead
    // of tripping the authority's monotonicity guard or rewinding freshness.
    // This read does not write last_verified_ms: the admitting device owns
    // that hot row, and connector traffic must not contend on it.
    let now = clock(tx, (high_water.max(0) as u64).max(previous_clock)).await?;
    let manifest = sealed_manifest::verify(&pin, &bytes, &trust, now)
        .map_err(|_| "manifest authority not verifiable")?;
    Ok((manifest, now))
}

/// Require the exact point to be the account's currently active role-3
/// reader and return its key id and scope. This is the only bridge from a
/// registration to cryptographic authority, and it can never select another
/// role, so device, archive and owner-root points cannot be aliased.
fn require_integration_reader(
    manifest: &VerifiedManifest,
    now: u64,
    point: &[u8; 65],
) -> Result<([u8; 32], u16), RegistryError> {
    let (key_id, scope, _) = manifest
        .active_integration_reader(point.as_slice(), now)
        .ok_or(RegistryError::Rejected("integration reader authority"))?;
    Ok((key_id, scope))
}

/// The point must not alias an enrolled device key or the account root pin.
/// The manifest already rejects duplicate points inside itself; this fences
/// server-side enrollment identities outside the manifest.
async fn point_aliases_device_or_root(
    tx: &Transaction<'_>,
    account: &Uuid,
    point: &[u8; 65],
) -> Result<bool, RegistryError> {
    Ok(tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM device_keys WHERE account_id=$1 AND signing_key_sec1=$2) \
         OR EXISTS(SELECT 1 FROM sealed_manifest_authorities WHERE account_id=$1 \
                   AND substring(root_pin FROM 30 FOR 65)=$2)",
            &[account, &&point[..]],
        )
        .await?
        .get::<_, bool>(0))
}

/// One audit fact to append: identifiers, action, outcome and reason only.
struct Audit<'a> {
    connector: &'a Uuid,
    grant: Option<&'a Uuid>,
    action: &'static str,
    actor: Option<&'a Uuid>,
    outcome: &'static str,
    reason: &'static str,
}

async fn journal(
    tx: &Transaction<'_>,
    account: &Uuid,
    audit: Audit<'_>,
    recorded_ms: u64,
) -> Result<(), RegistryError> {
    tx.execute(
        "INSERT INTO connector_audit_events \
         (account_id,connector_id,grant_id,action,actor_user,outcome,reason,recorded_ms) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        &[
            account,
            audit.connector,
            &audit.grant,
            &audit.action,
            &audit.actor,
            &audit.outcome,
            &audit.reason,
            &(recorded_ms as i64),
        ],
    )
    .await?;
    Ok(())
}

fn validate_grant_bounds(request: &GrantRequest) -> Result<(), RegistryError> {
    match &request.kind {
        GrantKind::Read { directions } => {
            if !matches!(*directions, READ_OUTBOUND | READ_INBOUND | READ_BOTH) {
                return Err("read directions".into());
            }
        }
        GrantKind::Send => {}
    }
    if request.conversation_restriction.len() > MAX_CONVERSATION_RESTRICTION {
        return Err("conversation restriction size".into());
    }
    if matches!(request.kind, GrantKind::Send) && !request.conversation_restriction.is_empty() {
        return Err("send grants are line-scoped only".into());
    }
    Ok(())
}

fn parse_state(value: &str) -> Result<RegistrationState, RegistryError> {
    match value {
        "pending" => Ok(RegistrationState::Pending),
        "active" => Ok(RegistrationState::Active),
        "revoked" => Ok(RegistrationState::Revoked),
        _ => Err(RegistryError::Rejected("stored registration state")),
    }
}

/// Phase one: an authenticated owner session proposes a connector identity
/// with its exact grants. The public point must already be an active role-3
/// reader in the currently accepted manifest, must not alias a device key or
/// the root pin, must never have been used in this account, and every line
/// must be an active phone line of the same account. Nothing here activates
/// anything: the rows are pending until an independent session approves.
pub async fn propose(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    request: RegistrationRequest,
) -> Result<RegistrationTicket, RegistryError> {
    let account = principal.tenant.account_id();
    if request.display_name.is_empty()
        || request.display_name.len() > 80
        || request.grants.is_empty()
        || request.grants.len() > MAX_GRANTS_PER_REGISTRATION
    {
        return Err("registration shape".into());
    }
    for grant in &request.grants {
        validate_grant_bounds(grant)?;
    }
    VerifyingKey::from_sec1_bytes(&request.key_point).map_err(|_| "key point")?;
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let now = clock(&tx, 0).await?;
    if request.expires_ms <= now || request.expires_ms - now > MAX_LIFETIME_MS {
        tx.commit().await?;
        return Err("registration expiry bound".into());
    }
    for grant in &request.grants {
        if grant.expires_ms <= now || grant.expires_ms - now > MAX_LIFETIME_MS {
            tx.commit().await?;
            return Err("grant expiry bound".into());
        }
        if grant.expires_ms > request.expires_ms {
            tx.commit().await?;
            return Err("grant outlives registration".into());
        }
    }
    let live: i64 = tx
        .query_one(
            "SELECT count(*) FROM connector_registrations WHERE account_id=$1 \
         AND state IN ('pending','active')",
            &[&account],
        )
        .await?
        .get(0);
    if live >= MAX_CONNECTORS_PER_ACCOUNT {
        tx.commit().await?;
        return Err("connector limit reached".into());
    }
    let (manifest, manifest_now) = current_manifest(&tx, &account, now).await?;
    let (key_id, scope) = require_integration_reader(&manifest, manifest_now, &request.key_point)?;
    if point_aliases_device_or_root(&tx, &account, &request.key_point).await? {
        tx.commit().await?;
        return Err("key point aliases device/owner key".into());
    }
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM connector_keys WHERE account_id=$1 AND key_point=$2)",
            &[&account, &&request.key_point[..]],
        )
        .await?
        .get(0);
    if exists {
        tx.commit().await?;
        return Err("key point already used in account".into());
    }
    for grant in &request.grants {
        if let GrantKind::Read { directions } = grant.kind
            && directions & scope != directions
        {
            tx.commit().await?;
            return Err("read grant wider than manifest scope".into());
        }
        let active_line: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM phone_lines WHERE account_id=$1 AND id=$2 \
           AND state='active')",
                &[&account, &grant.line_id],
            )
            .await?
            .get(0);
        if !active_line {
            tx.commit().await?;
            return Err("grant line not active".into());
        }
    }
    let connector = Uuid::new_v4();
    let (_, _, record_until) = manifest
        .active_integration_reader(request.key_point.as_slice(), manifest_now)
        .ok_or(RegistryError::Rejected("integration reader authority"))?;
    tx.execute(
        "INSERT INTO connector_registrations \
         (account_id,connector_id,display_name,state,key_point,key_id,manifest_generation, \
          manifest_version,manifest_digest,proposed_by_user,proposed_session,proposed_ms,expires_ms) \
         VALUES($1,$2,$3,'pending',$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        &[
            &account,
            &connector,
            &request.display_name,
            &&request.key_point[..],
            &&key_id[..],
            &(manifest.generation() as i64),
            &(manifest.version() as i64),
            &manifest.digest().as_slice(),
            &principal.user_id,
            &principal.session_id,
            &(now as i64),
            &(request.expires_ms as i64),
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO connector_keys \
         (account_id,connector_id,key_id,key_point,valid_from_ms,valid_until_ms) \
         VALUES($1,$2,$3,$4,$5,least($6::bigint,$7::bigint))",
        &[
            &account,
            &connector,
            &&key_id[..],
            &&request.key_point[..],
            &(now as i64),
            &(request.expires_ms as i64),
            &(record_until as i64),
        ],
    )
    .await?;
    for grant in &request.grants {
        let grant_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO connector_grants \
             (account_id,connector_id,grant_id,kind,read_directions,line_id, \
              conversation_restriction,created_by_user,created_ms,expires_ms) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &account,
                &connector,
                &grant_id,
                &grant.kind.wire(),
                &grant.kind.directions(),
                &grant.line_id,
                &grant.conversation_restriction,
                &principal.user_id,
                &(now as i64),
                &(grant.expires_ms as i64),
            ],
        )
        .await?;
    }
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector,
            grant: None,
            action: "proposed",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "proposal stored pending independent approval",
        },
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(RegistrationTicket {
        account_id: account,
        connector_id: connector,
        key_id,
        manifest_generation: manifest.generation(),
        manifest_version: manifest.version(),
        expires_ms: request.expires_ms,
    })
}

/// Phase two: a different live owner session activates a pending
/// registration. Approval replays are refused, the proposing session cannot
/// approve its own proposal, and the accepted manifest must still carry the
/// exact generation/version/digest recorded at proposal — a stale, forked or
/// advanced manifest forces a fresh proposal instead of a silent rebind.
pub async fn approve(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    connector_id: Uuid,
) -> Result<RegistrationTicket, RegistryError> {
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let now = clock(&tx, 0).await?;
    let row = tx
        .query_opt(
            "SELECT key_point,key_id,manifest_generation,manifest_version,manifest_digest, \
         proposed_session,expires_ms,proposed_ms FROM connector_registrations \
         WHERE account_id=$1 AND connector_id=$2 AND state='pending' FOR UPDATE",
            &[&account, &connector_id],
        )
        .await?
        .ok_or(RegistryError::Rejected("registration not pending"))?;
    let proposed_session: Uuid = row.get(5);
    if proposed_session == principal.session_id {
        tx.commit().await?;
        return Err("independent approval session required".into());
    }
    let proposed_ms: i64 = row.get(7);
    let expires_ms: i64 = row.get(6);
    if expires_ms <= now as i64 {
        tx.commit().await?;
        return Err("registration expired".into());
    }
    let key_point: Vec<u8> = row.get(0);
    let key_point: [u8; 65] = key_point.try_into().map_err(|_| "stored key point")?;
    let stored_generation: i64 = row.get(2);
    let stored_version: i64 = row.get(3);
    let stored_digest: Vec<u8> = row.get(4);
    let (manifest, manifest_now) = current_manifest(&tx, &account, now).await?;
    if manifest.generation() as i64 != stored_generation
        || manifest.version() as i64 != stored_version
        || manifest.digest().as_slice() != stored_digest.as_slice()
    {
        tx.commit().await?;
        return Err("manifest changed since proposal; propose again".into());
    }
    let (key_id, _) = require_integration_reader(&manifest, manifest_now, &key_point)?;
    let stored_key_id: Vec<u8> = row.get(1);
    if stored_key_id != key_id {
        tx.commit().await?;
        return Err("integration key identity changed".into());
    }
    // Storage requires approved_ms >= proposed_ms; a host clock step backwards
    // between the two transactions must not fail an otherwise-valid approval.
    let approved_ms = manifest_now.max(proposed_ms as u64);
    tx.execute(
        "UPDATE connector_registrations SET state='active',approved_by_user=$3, \
         approved_session=$4,approved_ms=$5 WHERE account_id=$1 AND connector_id=$2",
        &[
            &account,
            &connector_id,
            &principal.user_id,
            &principal.session_id,
            &(approved_ms as i64),
        ],
    )
    .await?;
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector_id,
            grant: None,
            action: "approved",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "registration activated by an independent session",
        },
        approved_ms,
    )
    .await?;
    tx.commit().await?;
    Ok(RegistrationTicket {
        account_id: account,
        connector_id,
        key_id,
        manifest_generation: manifest.generation(),
        manifest_version: manifest.version(),
        expires_ms: expires_ms as u64,
    })
}

/// Reject a still-pending proposal. Nothing was ever active, so no grants
/// need fencing; the identity and its key history stay recorded so the point
/// cannot return through a later registration.
pub async fn reject(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    connector_id: Uuid,
    reason: &str,
) -> Result<(), RegistryError> {
    if reason.is_empty() || reason.len() > 200 {
        return Err("rejection reason".into());
    }
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let now = clock(&tx, 0).await?;
    let updated = tx
        .execute(
            "UPDATE connector_registrations SET state='revoked',revoked_ms=$3,revoked_by_user=$4, \
         revocation_reason=$5 WHERE account_id=$1 AND connector_id=$2 AND state='pending'",
            &[
                &account,
                &connector_id,
                &(now as i64),
                &principal.user_id,
                &reason,
            ],
        )
        .await?;
    if updated == 0 {
        tx.commit().await?;
        return Err("registration not pending".into());
    }
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector_id,
            grant: None,
            action: "rejected",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "pending proposal rejected before activation",
        },
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Replace the connector's public point with a new active role-3 key from the
/// same manifest generation. The new point must not have been used before in
/// the account, the old point is retired and can never return, and a scope
/// that no longer covers the existing read grants refuses the rotation
/// instead of silently widening or narrowing authority.
pub async fn rotate_key(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    connector_id: Uuid,
    new_point: [u8; 65],
) -> Result<RegistrationTicket, RegistryError> {
    VerifyingKey::from_sec1_bytes(&new_point).map_err(|_| RegistryError::Rejected("key point"))?;
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let now = clock(&tx, 0).await?;
    let row = tx
        .query_opt(
            "SELECT key_point,manifest_generation,expires_ms \
         FROM connector_registrations WHERE account_id=$1 AND connector_id=$2 \
         AND state='active' AND expires_ms>$3 FOR UPDATE",
            &[&account, &connector_id, &(now as i64)],
        )
        .await?
        .ok_or(RegistryError::Rejected("registration not active"))?;
    if row.get::<_, Vec<u8>>(0) == new_point.to_vec() {
        tx.commit().await?;
        return Err("rotation must use a new key".into());
    }
    let stored_generation: i64 = row.get(1);
    let expires_ms: i64 = row.get(2);
    let (manifest, manifest_now) = current_manifest(&tx, &account, now).await?;
    if manifest.generation() as i64 != stored_generation {
        tx.commit().await?;
        return Err("manifest generation changed; re-register".into());
    }
    let (new_key_id, new_scope) = require_integration_reader(&manifest, manifest_now, &new_point)?;
    if point_aliases_device_or_root(&tx, &account, &new_point).await? {
        tx.commit().await?;
        return Err("key point aliases device/owner key".into());
    }
    let used: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM connector_keys WHERE account_id=$1 AND key_point=$2)",
            &[&account, &&new_point[..]],
        )
        .await?
        .get(0);
    if used {
        tx.commit().await?;
        return Err("key point already used in account".into());
    }
    let held: Option<i16> = tx
        .query_opt(
            "SELECT bit_or(read_directions) FROM connector_grants \
         WHERE account_id=$1 AND connector_id=$2 AND kind='read' AND revoked_ms IS NULL",
            &[&account, &connector_id],
        )
        .await?
        .and_then(|r| r.get(0));
    if let Some(directions) = held
        && directions as u16 & new_scope != directions as u16
    {
        tx.commit().await?;
        return Err("rotation narrower than held read grants".into());
    }
    let record_until = manifest
        .active_integration_reader(new_point.as_slice(), manifest_now)
        .map(|(_, _, until)| until)
        .ok_or(RegistryError::Rejected("integration reader authority"))?;
    tx.execute(
        "UPDATE connector_keys SET retired_ms=$3 \
         WHERE account_id=$1 AND connector_id=$2 AND retired_ms IS NULL",
        &[&account, &connector_id, &(manifest_now as i64)],
    )
    .await?;
    tx.execute(
        "INSERT INTO connector_keys \
         (account_id,connector_id,key_id,key_point,valid_from_ms,valid_until_ms) \
         VALUES($1,$2,$3,$4,$5,least($6::bigint,$7::bigint))",
        &[
            &account,
            &connector_id,
            &&new_key_id[..],
            &&new_point[..],
            &(manifest_now as i64),
            &(expires_ms as i64),
            &(record_until as i64),
        ],
    )
    .await?;
    let changed = tx
        .execute(
            "UPDATE connector_registrations SET key_point=$3,key_id=$4 \
         WHERE account_id=$1 AND connector_id=$2 AND state='active'",
            &[&account, &connector_id, &&new_point[..], &&new_key_id[..]],
        )
        .await?;
    if changed == 0 {
        return Err("registration not active".into());
    }
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector_id,
            grant: None,
            action: "rotated",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "connector key rotated; previous point retired permanently",
        },
        manifest_now,
    )
    .await?;
    tx.commit().await?;
    Ok(RegistrationTicket {
        account_id: account,
        connector_id,
        key_id: new_key_id,
        manifest_generation: manifest.generation(),
        manifest_version: manifest.version(),
        expires_ms: expires_ms as u64,
    })
}

/// Revoke a pending or active registration and all of its grants. The
/// returned summary reports how many grants were live and how many send
/// authorizations were recorded, so dispatch runtimes stop exactly that
/// outstanding work; later authorization checks fail closed immediately.
pub async fn revoke(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    connector_id: Uuid,
    reason: &str,
) -> Result<RevocationSummary, RegistryError> {
    if reason.is_empty() || reason.len() > 200 {
        return Err("revocation reason".into());
    }
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let now = clock(&tx, 0).await?;
    let changed = tx
        .execute(
            "UPDATE connector_registrations SET state='revoked',revoked_ms=$3,revoked_by_user=$4, \
         revocation_reason=$5 WHERE account_id=$1 AND connector_id=$2 \
         AND state IN ('pending','active')",
            &[
                &account,
                &connector_id,
                &(now as i64),
                &principal.user_id,
                &reason,
            ],
        )
        .await?;
    if changed == 0 {
        tx.commit().await?;
        return Err("registration not revocable".into());
    }
    let grants_stopped: i64 = tx
        .query_one(
            "WITH stopped AS (UPDATE connector_grants SET revoked_ms=$3,revoked_by_user=$4 \
         WHERE account_id=$1 AND connector_id=$2 AND revoked_ms IS NULL RETURNING 1) \
         SELECT count(*) FROM stopped",
            &[&account, &connector_id, &(now as i64), &principal.user_id],
        )
        .await?
        .get(0);
    let send_authorizations: i64 = tx
        .query_one(
            "SELECT count(*) FROM connector_audit_events WHERE account_id=$1 \
         AND connector_id=$2 AND action='send_authorized'",
            &[&account, &connector_id],
        )
        .await?
        .get(0);
    tx.execute(
        "UPDATE connector_keys SET retired_ms=least(COALESCE(retired_ms,$3),$3) \
         WHERE account_id=$1 AND connector_id=$2",
        &[&account, &connector_id, &(now as i64)],
    )
    .await?;
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector_id,
            grant: None,
            action: "revoked",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "registration and all grants fenced",
        },
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(RevocationSummary {
        connector_id,
        grants_stopped,
        send_authorizations,
    })
}

/// Load an active-state registration by public key id, locked for this
/// transaction, with its bound generation. Unknown or revoked connectors
/// fail closed here before any journal write; the expiry check belongs to
/// the caller so a known-but-expired connector still gets an audited denial.
async fn load_active_registration(
    tx: &Transaction<'_>,
    account: &Uuid,
    key_id: &[u8; 32],
) -> Result<(Uuid, [u8; 65], i64, i64, u64), RegistryError> {
    let row = tx
        .query_opt(
            "SELECT connector_id,key_point,manifest_generation,expires_ms \
         FROM connector_registrations WHERE account_id=$1 AND key_id=$2 \
         AND state='active' FOR UPDATE",
            &[account, &&key_id[..]],
        )
        .await?
        .ok_or(RegistryError::Rejected("unknown or inactive connector"))?;
    let expires_ms: i64 = row.get(3);
    let now = clock(tx, 0).await?;
    let key_point: Vec<u8> = row.get(1);
    let key_point: [u8; 65] = key_point.try_into().map_err(|_| "stored key point")?;
    Ok((
        row.get::<_, Uuid>(0),
        key_point,
        row.get::<_, i64>(2),
        expires_ms,
        now,
    ))
}

/// Shared authorization gate. Loads the registration by public key id and
/// holds it locked, re-verifies the accepted manifest, enforces the same
/// generation binding, then finds the newest live grant for the kind, line,
/// optional direction and optional conversation restriction. Denials of a
/// known connector are journaled and committed as access records; probes
/// with an unknown key write nothing.
async fn authorize_inner(
    client: &mut Client,
    account: &Uuid,
    key_id: &[u8; 32],
    line: &Uuid,
    conversation: Option<&Uuid>,
    direction: Option<u16>,
    send: bool,
) -> Result<AuthorizedInner, RegistryError> {
    let tx = begin(client, account).await?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[account],
    )
    .await?
    .ok_or(RegistryError::Rejected("inactive account"))?;
    let (connector, key_point, bound_generation, expires_ms, now) =
        load_active_registration(&tx, account, key_id).await?;
    macro_rules! deny {
        ($reason:expr) => {{
            journal(
                &tx,
                account,
                Audit {
                    connector: &connector,
                    grant: None,
                    action: if send {
                        "send_denied"
                    } else {
                        "reader_wrap_denied"
                    },
                    actor: None,
                    outcome: "denied",
                    reason: $reason,
                },
                now,
            )
            .await?;
            tx.commit().await?;
            return Err($reason.into());
        }};
    }
    if expires_ms <= now as i64 {
        deny!("registration expired");
    }
    let (manifest, manifest_now) = match current_manifest(&tx, account, now).await {
        Ok(value) => value,
        Err(_) => deny!("manifest authority not verifiable"),
    };
    if manifest.generation() as i64 != bound_generation {
        deny!("manifest generation changed; re-register");
    }
    let (verified_key_id, current_scope) =
        match require_integration_reader(&manifest, manifest_now, &key_point) {
            Ok(value) => value,
            Err(_) => deny!("integration reader authority"),
        };
    if &verified_key_id != key_id {
        deny!("integration key identity changed");
    }
    let kind = if send { "send" } else { "read" };
    // smallint & int4 widens to int4 in PostgreSQL, so bind an i32 here.
    let wanted: i32 = if send {
        0
    } else {
        direction.unwrap_or(0) as i32
    };
    if !send && current_scope & wanted as u16 != wanted as u16 {
        deny!("read direction outside current manifest scope");
    }
    let row = match tx
        .query_opt(
            "SELECT grant_id,conversation_restriction FROM connector_grants \
         WHERE account_id=$1 AND connector_id=$2 AND kind=$3 AND line_id=$4 \
         AND revoked_ms IS NULL AND expires_ms>$5 \
         AND ($6=0 OR read_directions & $6 = $6) \
         ORDER BY created_ms DESC,grant_id DESC LIMIT 1 FOR UPDATE",
            &[
                account,
                &connector,
                &kind,
                line,
                &(manifest_now as i64),
                &wanted,
            ],
        )
        .await?
    {
        Some(row) => row,
        None => deny!("no live grant for line/kind"),
    };
    if !send {
        let restriction: Vec<Uuid> = row.get(1);
        match (conversation, restriction.as_slice()) {
            (_, []) => {}
            (None, _) => deny!("conversation required by grant restriction"),
            (Some(conversation), ids) => {
                if !ids.contains(conversation) {
                    deny!("conversation outside grant restriction");
                }
            }
        }
    }
    let line_active: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM phone_lines WHERE account_id=$1 AND id=$2 \
         AND state='active')",
            &[account, line],
        )
        .await?
        .get(0);
    if !line_active {
        deny!("line not active");
    }
    let grant_id: Uuid = row.get(0);
    journal(
        &tx,
        account,
        Audit {
            connector: &connector,
            grant: Some(&grant_id),
            action: if send {
                "send_authorized"
            } else {
                "reader_wrap_authorized"
            },
            actor: None,
            outcome: "allowed",
            reason: if send {
                "live send grant held for line"
            } else {
                "live read grant held for line"
            },
        },
        manifest_now,
    )
    .await?;
    tx.commit().await?;
    Ok(AuthorizedInner {
        connector_id: connector,
        grant_id,
        generation: manifest.generation(),
        version: manifest.version(),
    })
}

struct AuthorizedInner {
    connector_id: Uuid,
    grant_id: Uuid,
    generation: u64,
    version: u64,
}

/// Gate reader-wrap creation by an authorized connector client. Succeeds only
/// for the connector's own role-3 key with a live read grant covering the
/// direction, line and (when restricted) conversation. The result names
/// exactly `(role 3, key_id)`; callers must not widen it, and no other role
/// can ever be selected through this gate.
pub async fn authorize_reader_wrap(
    client: &mut Client,
    account_id: Uuid,
    connector_key_id: &[u8; 32],
    line: Uuid,
    conversation: Option<Uuid>,
    direction: u16,
) -> Result<WrapAuthorization, RegistryError> {
    if !matches!(direction, READ_OUTBOUND | READ_INBOUND | READ_BOTH) {
        return Err("read directions".into());
    }
    let inner = authorize_inner(
        client,
        &account_id,
        connector_key_id,
        &line,
        conversation.as_ref(),
        Some(direction),
        false,
    )
    .await?;
    Ok(WrapAuthorization {
        connector_id: inner.connector_id,
        grant_id: inner.grant_id,
        key_id: *connector_key_id,
        manifest_generation: inner.generation,
        manifest_version: inner.version,
    })
}

/// Gate workflow send/sign composition by an authorized connector client.
/// Returns the live send grant for the line; the dispatch runtime (#615)
/// still applies exact approvals, budgets and suppression inside dispatch and
/// must recheck this gate there.
pub async fn authorize_send(
    client: &mut Client,
    account_id: Uuid,
    connector_key_id: &[u8; 32],
    line: Uuid,
) -> Result<SendAuthorization, RegistryError> {
    let inner = authorize_inner(
        client,
        &account_id,
        connector_key_id,
        &line,
        None,
        None,
        true,
    )
    .await?;
    Ok(SendAuthorization {
        connector_id: inner.connector_id,
        grant_id: inner.grant_id,
        manifest_generation: inner.generation,
        manifest_version: inner.version,
    })
}

/// Owner-facing snapshot of registrations and their grants for audit. Public
/// key ids only; points and any private material never leave storage.
pub async fn list_registrations(
    client: &mut Client,
    principal: &SessionPrincipal,
) -> Result<Vec<RegistrationView>, RegistryError> {
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    let mut views = Vec::new();
    for row in tx
        .query(
            "SELECT connector_id,display_name,state,key_id,manifest_generation,manifest_version, \
         proposed_ms,approved_ms,expires_ms,revoked_ms FROM connector_registrations \
         WHERE account_id=$1 ORDER BY proposed_ms,connector_id",
            &[&account],
        )
        .await?
    {
        let connector: Uuid = row.get(0);
        let mut grants = Vec::new();
        for grant in tx
            .query(
                "SELECT grant_id,kind,read_directions,line_id,conversation_restriction, \
             created_ms,expires_ms,revoked_ms FROM connector_grants \
             WHERE account_id=$1 AND connector_id=$2 ORDER BY created_ms,grant_id",
                &[&account, &connector],
            )
            .await?
        {
            let kind_wire: String = grant.get(1);
            let directions: i16 = grant.get(2);
            grants.push(GrantView {
                grant_id: grant.get(0),
                kind: if kind_wire == "read" {
                    GrantKind::Read {
                        directions: directions as u16,
                    }
                } else {
                    GrantKind::Send
                },
                line_id: grant.get(3),
                conversation_restriction: grant.get(4),
                created_ms: grant.get(5),
                expires_ms: grant.get(6),
                revoked_ms: grant.get(7),
            });
        }
        views.push(RegistrationView {
            connector_id: connector,
            display_name: row.get(1),
            state: parse_state(row.get::<_, String>(2).as_str())?,
            key_id: row
                .get::<_, Vec<u8>>(3)
                .try_into()
                .map_err(|_| "stored key id")?,
            manifest_generation: row.get(4),
            manifest_version: row.get(5),
            proposed_ms: row.get(6),
            approved_ms: row.get(7),
            expires_ms: row.get(8),
            revoked_ms: row.get(9),
            grants,
        });
    }
    tx.commit().await?;
    Ok(views)
}

/// Export every connector access record for the account, newest first, plus
/// the current registration/grant snapshot. Identifiers, actions, outcomes
/// and reasons only; no key points, no content, no plaintext. The export
/// itself is journaled when at least one registration exists.
pub async fn export_access_records(
    client: &mut Client,
    principal: &SessionPrincipal,
) -> Result<AccessExport, RegistryError> {
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    let mut records = Vec::new();
    for row in tx
        .query(
            "SELECT event_id,connector_id,grant_id,action,outcome,reason,recorded_ms \
         FROM connector_audit_events WHERE account_id=$1 \
         ORDER BY recorded_ms DESC,event_id DESC",
            &[&account],
        )
        .await?
    {
        records.push(AccessRecord {
            event_id: row.get(0),
            connector_id: row.get(1),
            grant_id: row.get(2),
            action: row.get(3),
            outcome: row.get(4),
            reason: row.get(5),
            recorded_ms: row.get(6),
        });
    }
    tx.commit().await?;
    let registrations = list_registrations(client, principal).await?;
    let stamped = match registrations.first() {
        Some(oldest) => {
            let tx = begin(client, &account).await?;
            owner_fence(&tx, principal).await?;
            let stamped = clock(&tx, 0).await?;
            journal(
                &tx,
                &account,
                Audit {
                    connector: &oldest.connector_id,
                    grant: None,
                    action: "exported",
                    actor: Some(&principal.user_id),
                    outcome: "recorded",
                    reason: "access records exported for owner review",
                },
                stamped,
            )
            .await?;
            tx.commit().await?;
            stamped as i64
        }
        None => 0,
    };
    Ok(AccessExport {
        registrations,
        records,
        exported_ms: stamped,
    })
}

/// Erase one connector's access records after revocation. The revoked
/// registration, grant definitions and key history remain as durable scope
/// evidence (their points can never return), while the per-access audit rows
/// are removed. A single 'erased' marker is appended after the deletion so
/// the erasure itself stays auditable without retaining access details.
pub async fn erase_access_records(
    client: &mut Client,
    hasher: &TokenHasher,
    principal: &SessionPrincipal,
    connector_id: Uuid,
) -> Result<ErasedCounts, RegistryError> {
    let account = principal.tenant.account_id();
    let tx = begin(client, &account).await?;
    owner_fence(&tx, principal).await?;
    if !abuse_limits::consume_owner_management(&tx, hasher, &principal.user_id.to_string()).await? {
        tx.commit().await?;
        return Err(AuthError::RateLimited.into());
    }
    let state: Option<String> = tx
        .query_opt(
            "SELECT state FROM connector_registrations WHERE account_id=$1 AND connector_id=$2",
            &[&account, &connector_id],
        )
        .await?
        .map(|r| r.get(0));
    match state.as_deref() {
        Some("revoked") => {}
        Some(_) => {
            tx.commit().await?;
            return Err("revoke before erasing access records".into());
        }
        None => {
            tx.commit().await?;
            return Err("unknown registration".into());
        }
    }
    let now = clock(&tx, 0).await?;
    let audit_events = tx
        .execute(
            "DELETE FROM connector_audit_events WHERE account_id=$1 AND connector_id=$2",
            &[&account, &connector_id],
        )
        .await?;
    journal(
        &tx,
        &account,
        Audit {
            connector: &connector_id,
            grant: None,
            action: "erased",
            actor: Some(&principal.user_id),
            outcome: "recorded",
            reason: "access records erased after revocation",
        },
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(ErasedCounts {
        connector_id,
        audit_events: audit_events as u64,
    })
}

#[cfg(test)]
mod tests;
