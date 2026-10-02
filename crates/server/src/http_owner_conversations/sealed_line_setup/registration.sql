-- SPDX-License-Identifier: AGPL-3.0-only
-- Unnumbered local proposal. Never automatically applied by a runtime adapter.
-- One pending challenge per account; at most sixteen completed first-activation
-- attempts are allowed by the transaction, retaining bounded public tombstones.
CREATE TABLE sealed_line_key_challenges (
 account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 challenge_id uuid NOT NULL UNIQUE,
 user_id uuid NOT NULL,
 session_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 transcript bytea NOT NULL CHECK(octet_length(transcript)<=1024),
 issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
 completed_ms bigint,
 CHECK(completed_ms IS NULL OR completed_ms>=issued_ms)
);
CREATE INDEX sealed_line_key_challenges_expiry ON sealed_line_key_challenges(expires_ms);
CREATE TABLE sealed_line_key_receipts (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 registration_id uuid NOT NULL,
 user_id uuid NOT NULL,
 session_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 transcript bytea NOT NULL CHECK(octet_length(transcript)<=1024),
 root_signature bytea NOT NULL CHECK(octet_length(root_signature)=64),
 approval_signature bytea NOT NULL CHECK(octet_length(approval_signature)=64),
 approval_point bytea NOT NULL CHECK(octet_length(approval_point)=65),
 approval_fingerprint bytea NOT NULL CHECK(octet_length(approval_fingerprint)=32),
 paired_fingerprint bytea NOT NULL CHECK(octet_length(paired_fingerprint)=32),
 issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
 completed_ms bigint NOT NULL CHECK(completed_ms>=issued_ms AND completed_ms<expires_ms),
 assigned_challenge_id uuid REFERENCES line_activation_challenges(id),
 retired_ms bigint,
 activated_ms bigint,
 PRIMARY KEY(account_id,registration_id),
 UNIQUE(account_id,approval_fingerprint),
 FOREIGN KEY(account_id,approval_fingerprint) REFERENCES line_owner_approval_keys(account_id,fingerprint),
 CHECK(NOT (retired_ms IS NOT NULL AND activated_ms IS NOT NULL))
);
CREATE INDEX sealed_line_key_receipts_challenge ON sealed_line_key_receipts(assigned_challenge_id);
CREATE INDEX sealed_line_key_receipts_pending ON sealed_line_key_receipts(account_id,device_id,line_id)
 WHERE retired_ms IS NULL AND activated_ms IS NULL;
CREATE FUNCTION sealed_line_key_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['assigned_challenge_id','retired_ms','activated_ms'])<>
    (to_jsonb(OLD)-ARRAY['assigned_challenge_id','retired_ms','activated_ms']) OR
    (OLD.assigned_challenge_id IS NOT NULL AND NEW.assigned_challenge_id IS DISTINCT FROM OLD.assigned_challenge_id) OR
    (OLD.retired_ms IS NOT NULL AND NEW.retired_ms IS DISTINCT FROM OLD.retired_ms) OR
    (OLD.activated_ms IS NOT NULL AND NEW.activated_ms IS DISTINCT FROM OLD.activated_ms) THEN
  RAISE EXCEPTION 'sealed registration receipt is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_line_key_receipt_before_update BEFORE UPDATE ON sealed_line_key_receipts
 FOR EACH ROW EXECUTE FUNCTION sealed_line_key_receipt_guard();
