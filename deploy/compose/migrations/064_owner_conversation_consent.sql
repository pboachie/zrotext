-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant owner conversation API prerequisite; no runtime route is enabled.
-- One selected conversation per account. Withdrawal keeps the small consent
-- record with no peer after withdrawal. Content is still governed by the
-- existing sealed-inbound retention; this does not solve backup/erasure gates.
CREATE TABLE owner_conversation_consents (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation > 0),
    peer text CHECK (peer ~ '^\+[1-9][0-9]{1,14}$'),
    disclosure_version text NOT NULL CHECK (disclosure_version='conversation-content-v1'),
    enabled_by uuid NOT NULL,
    enabled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    CHECK ((revoked_at IS NULL AND peer IS NOT NULL) OR (revoked_at IS NOT NULL AND peer IS NULL)),
    FOREIGN KEY (account_id, enabled_by) REFERENCES memberships(account_id,user_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation)
);
