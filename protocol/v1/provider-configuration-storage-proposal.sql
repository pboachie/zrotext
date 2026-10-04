-- SPDX-License-Identifier: AGPL-3.0-only
-- Unnumbered proposal. Ordinary migrations do not install this schema.
-- Owner declarations remain unavailable; no provider acceptance or usage authority.
CREATE TABLE provider_configuration_heads (
    account_id uuid NOT NULL REFERENCES accounts(id),
    config_id uuid NOT NULL CHECK(config_id <> '00000000-0000-0000-0000-000000000000'),
    config_version smallint NOT NULL CHECK(config_version BETWEEN 1 AND 16),
    record_version bigint NOT NULL CHECK(record_version > 0),
    state text NOT NULL CHECK(state IN ('draft','withdrawn')),
    created_by uuid NOT NULL, created_session uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,config_id)
);
CREATE TABLE provider_configuration_versions (
    account_id uuid NOT NULL, config_id uuid NOT NULL,
    version smallint NOT NULL CHECK(version BETWEEN 1 AND 16),
    declaration bytea CHECK(octet_length(declaration) BETWEEN 2 AND 8192),
    declaration_digest bytea NOT NULL CHECK(octet_length(declaration_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,config_id,version),
    FOREIGN KEY(account_id,config_id) REFERENCES provider_configuration_heads(account_id,config_id)
        DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE provider_configuration_heads ADD CONSTRAINT provider_configuration_current_version
    FOREIGN KEY(account_id,config_id,config_version)
    REFERENCES provider_configuration_versions(account_id,config_id,version)
    DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE provider_configuration_mutations (
    account_id uuid NOT NULL, request_id uuid NOT NULL
        CHECK(request_id <> '00000000-0000-0000-0000-000000000000'),
    config_id uuid NOT NULL, config_version smallint NOT NULL CHECK(config_version BETWEEN 1 AND 16),
    operation text NOT NULL CHECK(operation IN ('create','revise','withdraw')),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    record_version bigint NOT NULL CHECK(record_version > 0),
    state text NOT NULL CHECK(state IN ('draft','withdrawn')),
    created_by uuid NOT NULL, created_session uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,request_id),
    FOREIGN KEY(account_id,config_id,config_version)
        REFERENCES provider_configuration_versions(account_id,config_id,version),
    CHECK((operation='withdraw')=(state='withdrawn'))
);
CREATE FUNCTION provider_configuration_head_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'draft' OR NEW.config_version<>1 OR NEW.record_version<>1 THEN
            RAISE EXCEPTION 'invalid initial declaration' USING ERRCODE='23514';
        END IF;
    ELSE
        IF (NEW.account_id,NEW.config_id,NEW.created_by,NEW.created_session,NEW.created_at)
            IS DISTINCT FROM (OLD.account_id,OLD.config_id,OLD.created_by,OLD.created_session,OLD.created_at)
            OR OLD.state='withdrawn' THEN
            RAISE EXCEPTION 'configuration identity cannot reopen' USING ERRCODE='23514';
        END IF;
        IF NEW.state='withdrawn' THEN
            IF NEW.config_version<>OLD.config_version OR
                NEW.record_version::numeric<>LEAST(OLD.record_version::numeric+1,9223372036854775807::numeric) THEN
                RAISE EXCEPTION 'invalid irreversible withdrawal' USING ERRCODE='23514';
            END IF;
        ELSIF NEW.config_version<>OLD.config_version+1 OR
            NEW.record_version::numeric<>OLD.record_version::numeric+1 THEN
            RAISE EXCEPTION 'invalid declaration revision' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provider_configuration_head_before BEFORE INSERT OR UPDATE ON provider_configuration_heads
    FOR EACH ROW EXECUTE FUNCTION provider_configuration_head_guard();
CREATE FUNCTION provider_configuration_version_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE current_state text;
BEGIN
    SELECT state INTO current_state FROM provider_configuration_heads
        WHERE account_id=NEW.account_id AND config_id=NEW.config_id;
    IF TG_OP='INSERT' THEN
        IF current_state IS DISTINCT FROM 'draft' OR NEW.declaration IS NULL THEN
            RAISE EXCEPTION 'version requires live declaration' USING ERRCODE='23514';
        END IF;
    ELSIF current_state IS DISTINCT FROM 'withdrawn' OR OLD.declaration IS NULL OR NEW.declaration IS NOT NULL
        OR (to_jsonb(NEW)-'declaration') IS DISTINCT FROM (to_jsonb(OLD)-'declaration') THEN
        RAISE EXCEPTION 'only irreversible private byte scrub is allowed' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provider_configuration_version_before BEFORE INSERT OR UPDATE ON provider_configuration_versions
    FOR EACH ROW EXECUTE FUNCTION provider_configuration_version_guard();
CREATE FUNCTION provider_configuration_commit_consistency() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE a uuid; c uuid; current_state text;
BEGIN
    a:=NEW.account_id; c:=NEW.config_id;
    SELECT state INTO current_state FROM provider_configuration_heads WHERE account_id=a AND config_id=c;
    -- Full account erasure deletes heads and versions together. Deferred FKs
    -- retain referential consistency; absent heads have no retained content.
    IF current_state IS NULL THEN RETURN NULL; END IF;
    IF EXISTS(SELECT 1 FROM provider_configuration_versions
        WHERE account_id=a AND config_id=c AND
            ((current_state='withdrawn' AND declaration IS NOT NULL) OR
             (current_state='draft' AND declaration IS NULL))) THEN
        RAISE EXCEPTION 'declaration state and private bytes disagree' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER provider_configuration_head_consistency AFTER INSERT OR UPDATE ON provider_configuration_heads
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION provider_configuration_commit_consistency();
CREATE CONSTRAINT TRIGGER provider_configuration_version_consistency AFTER INSERT OR UPDATE ON provider_configuration_versions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION provider_configuration_commit_consistency();
CREATE FUNCTION provider_configuration_mutation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN RAISE EXCEPTION 'declaration acknowledgment is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER provider_configuration_mutation_before BEFORE UPDATE ON provider_configuration_mutations
    FOR EACH ROW EXECUTE FUNCTION provider_configuration_mutation_guard();
