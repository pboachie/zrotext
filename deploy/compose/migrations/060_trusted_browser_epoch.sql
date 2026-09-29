-- Placeholder number: final assignment by the coordinator at queue front.
-- Issue #526: a per-owner trust epoch for trusted-browser cookies. Bumping it
-- revokes every trusted browser for the owner without touching stored cookie
-- state; the epoch is part of the cookie's MAC, so old cookies simply stop
-- verifying.
ALTER TABLE users ADD COLUMN trusted_browser_epoch bigint NOT NULL DEFAULT 0
    CHECK (trusted_browser_epoch >= 0);
