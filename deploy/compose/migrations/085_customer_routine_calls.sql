-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant owner-declared routines; no hosted provider/send authority.
-- Debits and admission tombstones are independent of content/call retention.
-- Removing call/policy metadata cannot replenish current-day or turn limits.
CREATE TABLE workflow_routine_period_debits (
    account_id uuid NOT NULL REFERENCES accounts(id),
    utc_day bigint NOT NULL,
    calls bigint NOT NULL CHECK(calls BETWEEN 0 AND 100),
    units bigint NOT NULL CHECK(units BETWEEN 0 AND 1000000),
    PRIMARY KEY(account_id,utc_day)
);
CREATE TABLE workflow_routine_turn_debits (
    account_id uuid NOT NULL REFERENCES accounts(id),
    context_id uuid NOT NULL,
    turns bigint NOT NULL CHECK(turns BETWEEN 0 AND 3),
    PRIMARY KEY(account_id,context_id)
);
CREATE TABLE workflow_routine_admission_tombstones (
    account_id uuid NOT NULL REFERENCES accounts(id),
    call_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    PRIMARY KEY(account_id,call_id)
);
CREATE FUNCTION workflow_routine_debit_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME='workflow_routine_period_debits' THEN
        IF (NEW.account_id,NEW.utc_day) IS DISTINCT FROM (OLD.account_id,OLD.utc_day)
           OR NEW.calls<OLD.calls OR NEW.units<OLD.units THEN
            RAISE EXCEPTION 'routine period debit cannot reset' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='workflow_routine_turn_debits' THEN
        IF (NEW.account_id,NEW.context_id) IS DISTINCT FROM (OLD.account_id,OLD.context_id)
           OR NEW.turns<OLD.turns THEN
            RAISE EXCEPTION 'routine turn debit cannot reset' USING ERRCODE='23514';
        END IF;
    ELSE
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'routine admission tombstone cannot rewrite' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_period_debit_before_update BEFORE UPDATE ON workflow_routine_period_debits
    FOR EACH ROW EXECUTE FUNCTION workflow_routine_debit_guard();
CREATE TRIGGER workflow_routine_turn_debit_before_update BEFORE UPDATE ON workflow_routine_turn_debits
    FOR EACH ROW EXECUTE FUNCTION workflow_routine_debit_guard();
CREATE TRIGGER workflow_routine_tombstone_before_update BEFORE UPDATE ON workflow_routine_admission_tombstones
    FOR EACH ROW EXECUTE FUNCTION workflow_routine_debit_guard();
CREATE TABLE workflow_routine_policies (
    account_id uuid NOT NULL REFERENCES accounts(id),
    id uuid NOT NULL,
    input_grant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    input_revision bigint NOT NULL CHECK(input_revision BETWEEN 1 AND 128),
    input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
    routine_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    policy jsonb NOT NULL CHECK(COALESCE(
        (policy->>'executor'='deterministic_local'
            AND (policy->>'adapter_id') IS NULL AND (policy->>'artifact_digest') IS NULL)
        OR (policy->>'executor'='local_process'
            AND jsonb_typeof(policy->'adapter_id')='string'
            AND jsonb_typeof(policy->'artifact_digest')='string'
            AND (policy->>'adapter_id') ~ '^[a-z][a-z0-9_-]{0,63}$'
            AND (policy->>'artifact_digest') ~ '^[0-9a-f]{64}$')
    ,false)),
    policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
    created_by_user uuid NOT NULL,
    created_session uuid NOT NULL,
    expires_ms bigint NOT NULL CHECK(expires_ms>0),
    withdrawn_ms bigint,
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,input_grant_id,context_id,input_revision)
        REFERENCES workflow_integration_grants(account_id,grant_id,context_id,context_revision),
    FOREIGN KEY(account_id,routine_id) REFERENCES workflow_routines(account_id,id),
    FOREIGN KEY(account_id,created_by_user) REFERENCES memberships(account_id,user_id)
);
CREATE INDEX workflow_routine_policies_context ON workflow_routine_policies(account_id,context_id,id);
CREATE INDEX workflow_routine_policies_routine ON workflow_routine_policies(account_id,routine_id,id);
CREATE FUNCTION workflow_routine_policy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'withdrawn_ms')<>(to_jsonb(OLD)-'withdrawn_ms') OR
       (OLD.withdrawn_ms IS NOT NULL AND NEW.withdrawn_ms IS DISTINCT FROM OLD.withdrawn_ms) THEN
        RAISE EXCEPTION 'routine policy cannot widen or resurrect' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_policy_before_update BEFORE UPDATE ON workflow_routine_policies
    FOR EACH ROW EXECUTE FUNCTION workflow_routine_policy_guard();

CREATE TABLE workflow_routine_calls (
    account_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    units bigint NOT NULL CHECK(units BETWEEN 1 AND 1000000),
    phase text NOT NULL CHECK(phase IN ('unknown','produced','published','proposed')),
    created_ms bigint NOT NULL CHECK(created_ms>0),
    produced_digest bytea CHECK(octet_length(produced_digest)=32),
    output_grant_id uuid,
    output_context_id uuid,
    output_revision bigint,
    output_digest bytea CHECK(octet_length(output_digest)=32),
    publication_request uuid,
    publication_digest bytea CHECK(octet_length(publication_digest)=32),
    published_by_user uuid,
    published_session uuid,
    action_id uuid,
    binding_digest bytea CHECK(octet_length(binding_digest)=32),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,policy_id) REFERENCES workflow_routine_policies(account_id,id),
    FOREIGN KEY(account_id,output_grant_id,output_context_id,output_revision)
        REFERENCES workflow_integration_grants(account_id,grant_id,context_id,context_revision),
    FOREIGN KEY(account_id,published_by_user) REFERENCES memberships(account_id,user_id),
    CHECK((phase='unknown')=(produced_digest IS NULL)),
    CHECK((phase IN ('published','proposed'))=(output_grant_id IS NOT NULL)),
    CHECK((output_grant_id IS NULL)=(output_context_id IS NULL)),
    CHECK(output_context_id IS NULL OR output_context_id=id),
    CHECK((output_grant_id IS NULL)=(output_revision IS NULL)),
    CHECK((output_grant_id IS NULL)=(output_digest IS NULL)),
    CHECK((output_grant_id IS NULL)=(publication_request IS NULL)),
    CHECK((output_grant_id IS NULL)=(publication_digest IS NULL)),
    CHECK((output_grant_id IS NULL)=(published_by_user IS NULL)),
    CHECK((output_grant_id IS NULL)=(published_session IS NULL)),
    CHECK((phase='proposed')=(action_id IS NOT NULL)),
    CHECK((action_id IS NULL)=(binding_digest IS NULL))
);
CREATE INDEX workflow_routine_calls_policy ON workflow_routine_calls(account_id,policy_id,id);
CREATE INDEX workflow_routine_calls_output ON workflow_routine_calls(account_id,output_grant_id,output_context_id,output_revision);
CREATE FUNCTION workflow_routine_call_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (NEW.account_id,NEW.id,NEW.policy_id,NEW.request_digest,NEW.units,NEW.created_ms)
       IS DISTINCT FROM (OLD.account_id,OLD.id,OLD.policy_id,OLD.request_digest,OLD.units,OLD.created_ms) OR
       NOT ((NEW IS NOT DISTINCT FROM OLD) OR
            (OLD.phase='unknown' AND NEW.phase='produced') OR
            (OLD.phase='produced' AND NEW.phase='published' AND NEW.produced_digest=OLD.produced_digest) OR
            (OLD.phase='published' AND NEW.phase='proposed' AND
             (to_jsonb(NEW)-'phase'-'action_id'-'binding_digest')=(to_jsonb(OLD)-'phase'-'action_id'-'binding_digest'))) THEN
        RAISE EXCEPTION 'routine execution cannot reset or rewrite its checkpoint' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_calls_before_update BEFORE UPDATE ON workflow_routine_calls
    FOR EACH ROW EXECUTE FUNCTION workflow_routine_call_guard();

-- Existing owner takeover/stop remains authoritative across the separately
-- published output context. Account serialization is held by those services.
CREATE FUNCTION workflow_routine_stop_outputs() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE input_context uuid; input_routine uuid;
BEGIN
    IF TG_TABLE_NAME='workflow_context_fences' THEN
        input_context := NEW.context_id;
    ELSE
        input_routine := NEW.id;
    END IF;
    -- The full closure is stopped by one UPDATE before its AFTER callbacks.
    -- Those callbacks perform this indexed live-edge check and return without
    -- rewalking already-stopped chains. No trigger-depth authority bypass.
    IF NOT EXISTS (
        SELECT 1 FROM workflow_routine_policies p
        JOIN workflow_routine_calls c ON (c.account_id,c.policy_id)=(p.account_id,p.id)
        JOIN workflow_routines r ON (r.account_id,r.id,r.context_id)=(c.account_id,c.id,c.output_context_id)
        WHERE p.account_id=NEW.account_id AND c.output_context_id IS NOT NULL
          AND (p.context_id=input_context OR p.routine_id=input_routine)
          AND r.stopped_at IS NULL
    ) THEN RETURN NEW; END IF;
    -- UNION deduplicates even cyclic links. Admission bounds this account's
    -- retained call identities to 1000. One statement stops the full closure
    -- before its AFTER row triggers fire, so nested callbacks find no new
    -- transition and do not recursively walk one row at a time.
    WITH RECURSIVE outputs(id,context_id) AS (
        SELECT r.id,r.context_id
        FROM workflow_routine_policies p
        JOIN workflow_routine_calls c ON (c.account_id,c.policy_id)=(p.account_id,p.id)
        JOIN workflow_routines r ON (r.account_id,r.id,r.context_id)=(c.account_id,c.id,c.output_context_id)
        WHERE p.account_id=NEW.account_id AND c.output_context_id IS NOT NULL
          AND (p.context_id=input_context OR p.routine_id=input_routine)
        UNION
        SELECT r.id,r.context_id
        FROM outputs prior
        JOIN workflow_routine_policies p ON p.account_id=NEW.account_id AND p.routine_id=prior.id
        JOIN workflow_routine_calls c ON (c.account_id,c.policy_id)=(p.account_id,p.id)
        JOIN workflow_routines r ON (r.account_id,r.id,r.context_id)=(c.account_id,c.id,c.output_context_id)
        WHERE c.output_context_id IS NOT NULL
    )
    UPDATE workflow_routines r SET stopped_at=clock_timestamp()
    WHERE r.account_id=NEW.account_id AND r.stopped_at IS NULL
      AND r.id IN (SELECT id FROM outputs);
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_outputs_on_takeover
    AFTER UPDATE OF stopped_at ON workflow_context_fences
    FOR EACH ROW WHEN (OLD.stopped_at IS NULL AND NEW.stopped_at IS NOT NULL)
    EXECUTE FUNCTION workflow_routine_stop_outputs();
CREATE TRIGGER workflow_routine_outputs_on_stop
    AFTER UPDATE OF stopped_at ON workflow_routines
    FOR EACH ROW WHEN (OLD.stopped_at IS NULL AND NEW.stopped_at IS NOT NULL)
    EXECUTE FUNCTION workflow_routine_stop_outputs();
