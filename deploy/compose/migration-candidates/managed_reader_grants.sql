-- SPDX-License-Identifier: AGPL-3.0-only
-- Issue #761 SQL proposal, NOT discovered or installed by the migrator.
-- Promotion requires a fresh main and active-owner migration inventory.
CREATE TABLE managed_reader_keys (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 key_id bytea NOT NULL CHECK(octet_length(key_id)=32),
 key_point bytea NOT NULL CHECK(octet_length(key_point)=65),
 expires_ms bigint NOT NULL CHECK(expires_ms>0), revoked_ms bigint,
 PRIMARY KEY(account_id,id,generation)
);
CREATE TABLE managed_reader_policies (
 account_id uuid NOT NULL, id uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 reader_id uuid NOT NULL, reader_generation bigint NOT NULL,
 provider_id uuid NOT NULL, provider_version bigint NOT NULL CHECK(provider_version>0),
 provider_digest bytea NOT NULL CHECK(octet_length(provider_digest)=32),
 budget_id uuid NOT NULL, budget_version bigint NOT NULL CHECK(budget_version>0),
 budget_digest bytea NOT NULL CHECK(octet_length(budget_digest)=32),
 expires_ms bigint NOT NULL CHECK(expires_ms>0),
 max_calls bigint NOT NULL CHECK(max_calls>=0), max_input_bytes bigint NOT NULL CHECK(max_input_bytes>=0),
 max_cost_microunits bigint NOT NULL CHECK(max_cost_microunits>=0),
 PRIMARY KEY(account_id,id,version),
 UNIQUE(account_id,id,version,digest,reader_id,reader_generation),
 FOREIGN KEY(account_id,reader_id,reader_generation) REFERENCES managed_reader_keys(account_id,id,generation)
);
CREATE TABLE managed_reader_grants (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 id uuid NOT NULL, contact_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('transactional','operational','marketing')),
 current_version bigint NOT NULL CHECK(current_version BETWEEN 1 AND 128),
 revocation_generation bigint NOT NULL DEFAULT 0 CHECK(revocation_generation>=0), revoked_ms bigint,
 PRIMARY KEY(account_id,id),
 CHECK((revoked_ms IS NULL AND revocation_generation=0) OR (revoked_ms IS NOT NULL AND revocation_generation=1))
);
CREATE TABLE managed_reader_grant_versions (
 account_id uuid NOT NULL, grant_id uuid NOT NULL, id uuid NOT NULL,
 version bigint NOT NULL CHECK(version BETWEEN 1 AND 128),
 policy_id uuid NOT NULL, policy_version bigint NOT NULL, policy_digest bytea NOT NULL,
 reader_id uuid NOT NULL, reader_generation bigint NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'),
 created_by_user uuid NOT NULL, created_session uuid NOT NULL, created_ms bigint NOT NULL,
 PRIMARY KEY(account_id,grant_id,version), UNIQUE(account_id,id),
 FOREIGN KEY(account_id,grant_id) REFERENCES managed_reader_grants(account_id,id),
 FOREIGN KEY(account_id,policy_id,policy_version,policy_digest,reader_id,reader_generation)
 REFERENCES managed_reader_policies(account_id,id,version,digest,reader_id,reader_generation)
);
ALTER TABLE managed_reader_grants ADD CONSTRAINT managed_reader_current_version
 FOREIGN KEY(account_id,id,current_version) REFERENCES managed_reader_grant_versions(account_id,grant_id,version)
 DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE managed_reader_selections (
 account_id uuid NOT NULL, id uuid NOT NULL, grant_id uuid NOT NULL, grant_version bigint NOT NULL,
 kind text NOT NULL CHECK(kind='workflow_context_v1'), source_id uuid NOT NULL,
 source_version bigint NOT NULL CHECK(source_version BETWEEN 1 AND 128), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(account_id,id), UNIQUE(account_id,grant_id,grant_version,kind,source_id),
 FOREIGN KEY(account_id,grant_id,grant_version) REFERENCES managed_reader_grant_versions(account_id,grant_id,version)
 -- No archive FK: retention may erase the source while exact grant history survives.
);
CREATE TABLE managed_reader_events (
 account_id uuid NOT NULL, id uuid NOT NULL, grant_id uuid NOT NULL, grant_version bigint NOT NULL,
 operation text NOT NULL CHECK(operation IN ('create','replace','narrow','revoke','withdraw')),
 actor_user_id uuid, actor_session_id uuid, created_ms bigint NOT NULL,
 PRIMARY KEY(account_id,id),
 FOREIGN KEY(account_id,grant_id,grant_version) REFERENCES managed_reader_grant_versions(account_id,grant_id,version)
);
CREATE FUNCTION managed_reader_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN RAISE EXCEPTION 'managed reader row immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER managed_reader_policy_immutable BEFORE UPDATE ON managed_reader_policies FOR EACH ROW EXECUTE FUNCTION managed_reader_immutable();
CREATE TRIGGER managed_reader_version_immutable BEFORE UPDATE ON managed_reader_grant_versions FOR EACH ROW EXECUTE FUNCTION managed_reader_immutable();
CREATE TRIGGER managed_reader_selection_immutable BEFORE UPDATE ON managed_reader_selections FOR EACH ROW EXECUTE FUNCTION managed_reader_immutable();
CREATE TRIGGER managed_reader_event_immutable BEFORE UPDATE ON managed_reader_events FOR EACH ROW EXECUTE FUNCTION managed_reader_immutable();
CREATE FUNCTION managed_reader_head_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (NEW.account_id,NEW.id,NEW.contact_id,NEW.purpose) IS DISTINCT FROM (OLD.account_id,OLD.id,OLD.contact_id,OLD.purpose)
 OR OLD.revoked_ms IS NOT NULL
 OR NOT ((NEW.current_version=OLD.current_version+1 AND NEW.revoked_ms IS NULL AND NEW.revocation_generation=0)
 OR (NEW.current_version=OLD.current_version AND NEW.revoked_ms IS NOT NULL AND NEW.revocation_generation=1))
 THEN RAISE EXCEPTION 'invalid managed reader transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER managed_reader_head_guard BEFORE UPDATE ON managed_reader_grants FOR EACH ROW EXECUTE FUNCTION managed_reader_head_guard();
CREATE FUNCTION managed_reader_key_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (NEW.account_id,NEW.id,NEW.generation,NEW.key_id,NEW.key_point,NEW.expires_ms) IS DISTINCT FROM
 (OLD.account_id,OLD.id,OLD.generation,OLD.key_id,OLD.key_point,OLD.expires_ms)
 OR OLD.revoked_ms IS NOT NULL OR NEW.revoked_ms IS NULL
 THEN RAISE EXCEPTION 'invalid managed reader key transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER managed_reader_key_guard BEFORE UPDATE ON managed_reader_keys FOR EACH ROW EXECUTE FUNCTION managed_reader_key_guard();
-- APIs append audit events; UPDATE is rejected. The privileged DB role can
-- DELETE. Owner erasure explicitly deletes children first and reports counts.
