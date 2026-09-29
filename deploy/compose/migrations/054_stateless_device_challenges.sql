-- SPDX-License-Identifier: AGPL-3.0-only
-- Socket handshake challenges are now stateless HMAC values derived from the
-- enrollment pepper; nothing writes device_auth_challenges any more, so the
-- table and its indexes are dropped. Existing rows were one-hour-retention
-- challenge material only; no durable state is lost. An older binary still
-- inserts challenges into this table, so after this migration every device
-- handshake fails on it: rolling back means restoring the pre-upgrade backup,
-- as for any downgrade (deploy/compose/UPGRADE.md).
DROP TABLE IF EXISTS device_auth_challenges;
