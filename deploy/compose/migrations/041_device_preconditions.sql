-- SPDX-License-Identifier: AGPL-3.0-only
-- One latest, untrusted Android observation per device; never dispatch authority.
CREATE TABLE device_preconditions (
    device_id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch > 0),
    received_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    selected_sim text NOT NULL CHECK (selected_sim IN ('not_selected','active','inactive','unavailable')),
    sms_permission text NOT NULL CHECK (sms_permission IN ('granted','denied','unavailable')),
    airplane_mode text NOT NULL CHECK (airplane_mode IN ('enabled','disabled','unavailable')),
    FOREIGN KEY (account_id,device_id) REFERENCES devices(account_id,id) ON DELETE CASCADE
);
CREATE INDEX device_preconditions_received ON device_preconditions(received_at,device_id);
