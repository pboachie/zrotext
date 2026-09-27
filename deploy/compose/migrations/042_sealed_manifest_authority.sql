-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant candidate-02 authority only. This migration deliberately provisions
-- no root. An independent owner trust ceremony is still required; neither
-- device line approval keys nor an untrusted manifest can establish this pin.
CREATE TABLE sealed_manifest_authorities (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    root_pin bytea NOT NULL CHECK (octet_length(root_pin)=94),
    root_fingerprint bytea NOT NULL CHECK (octet_length(root_fingerprint)=32),
    generation bigint NOT NULL CHECK (generation>0),
    anchor_digest bytea NOT NULL CHECK (octet_length(anchor_digest)=32),
    version bigint NOT NULL DEFAULT 0 CHECK (version>=0),
    semantic_digest bytea,
    manifest bytea,
    accepted_at_ms bigint,
    last_verified_ms bigint NOT NULL DEFAULT 0 CHECK (last_verified_ms>=0),
    revoked_at timestamptz,
    CHECK ((generation=1 AND anchor_digest=decode(repeat('00',32),'hex')) OR
           (generation>1 AND anchor_digest<>decode(repeat('00',32),'hex'))),
    CHECK ((version=0 AND semantic_digest IS NULL AND manifest IS NULL AND
            accepted_at_ms IS NULL AND last_verified_ms=0) OR
           (version>0 AND semantic_digest IS NOT NULL AND octet_length(semantic_digest)=32 AND
            manifest IS NOT NULL AND octet_length(manifest) BETWEEN 364 AND 9751 AND
            accepted_at_ms IS NOT NULL AND accepted_at_ms>0 AND last_verified_ms>=accepted_at_ms))
);

CREATE FUNCTION sealed_manifest_authority_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.account_id<>OLD.account_id OR NEW.root_pin<>OLD.root_pin OR
       NEW.root_fingerprint<>OLD.root_fingerprint OR NEW.generation<>OLD.generation OR
       NEW.anchor_digest<>OLD.anchor_digest OR
       (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) OR
       NEW.last_verified_ms<OLD.last_verified_ms OR NEW.version<OLD.version OR
       (NEW.version>OLD.version AND NEW.version::numeric<>OLD.version::numeric+1) OR
       (NEW.version=OLD.version AND
         (NEW.semantic_digest IS DISTINCT FROM OLD.semantic_digest OR
          NEW.manifest IS DISTINCT FROM OLD.manifest OR
          NEW.accepted_at_ms IS DISTINCT FROM OLD.accepted_at_ms)) THEN
        RAISE EXCEPTION 'sealed manifest authority cannot change trust or roll back'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_manifest_authority_before_update
    BEFORE UPDATE ON sealed_manifest_authorities
    FOR EACH ROW EXECUTE FUNCTION sealed_manifest_authority_guard();
-- No DELETE guard: account erasure must cascade. The application has no root
-- provisioning API, so an absent authority fails closed rather than resetting.
