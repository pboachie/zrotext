-- SPDX-License-Identifier: AGPL-3.0-only
-- Support bounded creation-ordered cleanup of unverified owners whose
-- verification window has elapsed. Verified owners are never indexed here.
CREATE INDEX users_pending_created ON users(created_at, id)
    WHERE email_verified_at IS NULL;
