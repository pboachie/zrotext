-- SPDX-License-Identifier: AGPL-3.0-only
-- Account-scoped contacts and per-purpose consent records (issue #634).
--
-- Routing identity is one normalized E.164 number per account. Display
-- names and free-text notes are stored only as AES-256-GCM ciphertext
-- sealed by the contacts key-encryption key with account/contact/field
-- binding, so the plaintext is never persisted. Consent records are
-- append-only grant/withdraw events per purpose with source, effective
-- time and optional expiry; contact import never writes them. Deleting a
-- contact cascades its consent history; suppression, hold and opt-out
-- records are separate planes this schema never touches.
CREATE TABLE contacts (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_e164 text NOT NULL CHECK (recipient_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    display_name_ciphertext bytea,
    notes_ciphertext bytea,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (account_id, recipient_e164),
    UNIQUE (account_id, id)
);
CREATE INDEX contacts_listing ON contacts(account_id, created_at DESC, id DESC);

CREATE TABLE contact_consent_records (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_id uuid NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('transactional', 'operational', 'marketing')),
    action text NOT NULL CHECK (action IN ('grant', 'withdraw')),
    source text NOT NULL CHECK (source IN ('manual_entry', 'off_channel_record')),
    effective_at timestamptz NOT NULL,
    expires_at timestamptz,
    recorded_by uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action = 'grant') OR (expires_at IS NULL)),
    CHECK (expires_at IS NULL OR expires_at > effective_at),
    FOREIGN KEY (account_id, contact_id) REFERENCES contacts(account_id, id) ON DELETE CASCADE,
    FOREIGN KEY (account_id, recorded_by) REFERENCES memberships(account_id, user_id)
);
CREATE INDEX contact_consent_records_history
    ON contact_consent_records(account_id, contact_id, purpose, effective_at, id);
CREATE INDEX contact_consent_records_contact ON contact_consent_records(contact_id);
