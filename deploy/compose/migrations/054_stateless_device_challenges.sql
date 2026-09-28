-- SPDX-License-Identifier: AGPL-3.0-only
-- Socket handshake challenges are now stateless HMAC values derived from the
-- enrollment pepper; nothing writes device_auth_challenges any more, so the
-- table and its indexes are dropped. Existing rows were one-hour-retention
-- challenge material only; no durable state is lost.
DROP TABLE IF EXISTS device_auth_challenges;
