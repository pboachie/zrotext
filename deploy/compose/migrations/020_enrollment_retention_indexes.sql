-- SPDX-License-Identifier: AGPL-3.0-only
-- Support bounded expiry-ordered enrollment retention cleanup.
CREATE INDEX pairing_requests_expiry ON pairing_requests(expires_at, id);
