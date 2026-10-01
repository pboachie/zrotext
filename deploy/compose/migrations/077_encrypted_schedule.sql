-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant recipient-local work metadata. Approval lives only in workflow_actions;
-- ciphertext lives in immutable workflow context versions, not a second queue.
CREATE TABLE workflow_schedule_policies (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id text NOT NULL CHECK(id ~ '^window-v1-[0-9a-f]{64}$'),
    timezone text CHECK(timezone ~ '^[!-~]{1,128}$'),
    first_local_date date NOT NULL CHECK(first_local_date BETWEEN DATE '0001-01-01' AND DATE '9999-12-31'),
    opens_minute smallint NOT NULL CHECK(opens_minute BETWEEN 0 AND 1439),
    closes_minute smallint NOT NULL CHECK(closes_minute BETWEEN 0 AND 1439),
    repeat_every_days smallint CHECK(repeat_every_days BETWEEN 1 AND 365),
    max_occurrences smallint NOT NULL CHECK(max_occurrences BETWEEN 1 AND 100),
    pacing_seconds integer NOT NULL CHECK(pacing_seconds BETWEEN 60 AND 86400),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id), CHECK(opens_minute<>closes_minute),
    CHECK(repeat_every_days IS NOT NULL OR max_occurrences=1)
);
CREATE TABLE workflow_schedule_series (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id uuid NOT NULL, policy_id text NOT NULL,
    context_id uuid NOT NULL, context_revision bigint NOT NULL,
    routine_id uuid NOT NULL, routine_generation bigint NOT NULL CHECK(routine_generation>0),
    pacing_until_ms bigint NOT NULL DEFAULT 0 CHECK(pacing_until_ms>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,policy_id) REFERENCES workflow_schedule_policies(account_id,id),
    FOREIGN KEY(account_id,context_id,context_revision)
        REFERENCES workflow_context_versions(account_id,context_id,revision) ON DELETE CASCADE,
    FOREIGN KEY(account_id,routine_id) REFERENCES workflow_routines(account_id,id) ON DELETE CASCADE
);
CREATE INDEX workflow_schedule_series_routine ON workflow_schedule_series(account_id,routine_id);
CREATE INDEX workflow_schedule_series_context ON workflow_schedule_series(account_id,context_id,context_revision);
CREATE INDEX workflow_schedule_series_policy ON workflow_schedule_series(account_id,policy_id);

CREATE TABLE workflow_schedule_occurrences (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id uuid NOT NULL, series_id uuid NOT NULL, ordinal smallint NOT NULL CHECK(ordinal BETWEEN 0 AND 99),
    action_id uuid NOT NULL, action_revision bigint NOT NULL,
    binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
    request_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    dispatch_id uuid NOT NULL, message_id uuid,
    actor_kind text NOT NULL CHECK(actor_kind IN ('owner','integration')),
    actor_id uuid NOT NULL, owner_session_id uuid,
    opens_at_ms bigint, closes_at_ms bigint, not_before_ms bigint NOT NULL CHECK(not_before_ms>=0),
    expires_at_ms bigint NOT NULL CHECK(expires_at_ms>not_before_ms),
    phase text NOT NULL CHECK(phase IN ('owner_review','waiting_window','waiting_renderer','waiting_phone',
        'claimed','dispatching','unknown','cancelled','expired','missed_window','completed','failed')),
    review_reason text CHECK(review_reason IN ('unknown_timezone','nonexistent_civil_time','ambiguous_civil_time')),
    lease_id uuid, lease_until_ms bigint, retry_at_ms bigint NOT NULL DEFAULT 0 CHECK(retry_at_ms>=0),
    observed_message_state text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id), UNIQUE(account_id,series_id,ordinal), UNIQUE(account_id,request_id),
    UNIQUE(account_id,action_id,action_revision), UNIQUE(account_id,dispatch_id),
    FOREIGN KEY(account_id,series_id) REFERENCES workflow_schedule_series(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,action_id,action_revision,binding_digest)
        REFERENCES workflow_action_versions(account_id,action_id,revision,binding_digest) ON DELETE CASCADE,
    CHECK((opens_at_ms IS NULL AND closes_at_ms IS NULL) OR
          (opens_at_ms>=0 AND closes_at_ms>opens_at_ms)),
    CHECK(phase IN ('owner_review','cancelled','expired') OR opens_at_ms IS NOT NULL),
    CHECK((phase='owner_review' AND review_reason IS NOT NULL AND opens_at_ms IS NULL) OR
          (phase<>'owner_review' AND review_reason IS NULL)),
    CHECK((phase='claimed' AND lease_id IS NOT NULL AND lease_until_ms IS NOT NULL
          AND lease_until_ms<=expires_at_ms AND lease_until_ms>0) OR
          (phase<>'claimed' AND lease_id IS NULL AND lease_until_ms IS NULL)),
    CHECK(phase NOT IN ('dispatching','unknown','completed','failed') OR message_id IS NOT NULL),
    CHECK((actor_kind='owner')=(owner_session_id IS NOT NULL))
);
CREATE INDEX workflow_schedule_claimable ON workflow_schedule_occurrences(account_id,retry_at_ms,not_before_ms,id)
    WHERE phase IN ('waiting_window','waiting_renderer','waiting_phone','claimed');
CREATE INDEX workflow_schedule_expiry ON workflow_schedule_occurrences(expires_at_ms,account_id,id)
    WHERE phase NOT IN ('cancelled','expired','missed_window','completed','failed');
CREATE INDEX workflow_schedule_action ON workflow_schedule_occurrences(account_id,action_id,action_revision,binding_digest);
CREATE INDEX workflow_schedule_message ON workflow_schedule_occurrences(account_id,message_id) WHERE message_id IS NOT NULL;

CREATE TABLE workflow_schedule_audit (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id uuid NOT NULL, occurrence_id uuid NOT NULL, request_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    actor_kind text NOT NULL CHECK(actor_kind IN ('owner','integration','system')),
    actor_id uuid, operation text NOT NULL CHECK(operation IN ('schedule','claim','defer','cancel','expire','dispatch','reconcile')),
    result text NOT NULL CHECK(result IN ('owner_review','waiting_window','waiting_renderer','waiting_phone',
        'claimed','dispatching','unknown','cancelled','expired','missed_window','completed','failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id), UNIQUE(account_id,request_id),
    CHECK((actor_kind='system')=(actor_id IS NULL))
);
CREATE INDEX workflow_schedule_audit_retention ON workflow_schedule_audit(created_at,account_id,id);
CREATE INDEX workflow_schedule_audit_occurrence ON workflow_schedule_audit(account_id,occurrence_id);

CREATE FUNCTION workflow_schedule_policy_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN RAISE EXCEPTION 'workflow schedule policy is immutable' USING ERRCODE='23514'; END; $$;
CREATE FUNCTION workflow_schedule_policy_identity() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE canonical text; expected text;
BEGIN
    SELECT '{'||string_agg(to_json(key)::text||':'||value::text,',' ORDER BY key COLLATE "C")||'}'
      INTO canonical FROM jsonb_each(jsonb_build_object(
        'timezone',NEW.timezone,'first_local_date',to_char(NEW.first_local_date,'YYYY-MM-DD'),
        'opens_minute',NEW.opens_minute,'closes_minute',NEW.closes_minute,
        'repeat_every_days',NEW.repeat_every_days,'max_occurrences',NEW.max_occurrences,
        'pacing_seconds',NEW.pacing_seconds));
    expected := 'window-v1-'||encode(sha256(convert_to('ZT/window-policy/v1','UTF8')||decode('00','hex')||convert_to(canonical,'UTF8')),'hex');
    IF NEW.id<>expected THEN
        RAISE EXCEPTION 'workflow schedule policy identity differs' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;

CREATE TRIGGER workflow_schedule_policy_before_insert BEFORE INSERT ON workflow_schedule_policies
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_policy_identity();
CREATE TRIGGER workflow_schedule_policy_before_update BEFORE UPDATE ON workflow_schedule_policies
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_policy_immutable();

CREATE FUNCTION workflow_schedule_series_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'pacing_until_ms')<>(to_jsonb(OLD)-'pacing_until_ms')
        OR NEW.pacing_until_ms<OLD.pacing_until_ms THEN
        RAISE EXCEPTION 'workflow schedule series binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_schedule_series_before_update BEFORE UPDATE ON workflow_schedule_series
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_series_guard();

CREATE FUNCTION workflow_schedule_occurrence_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE needs_link boolean := false;
BEGIN
    IF TG_OP='INSERT' THEN
        needs_link := NEW.message_id IS NOT NULL;
        IF NOT EXISTS(SELECT 1 FROM workflow_schedule_series s
            JOIN workflow_schedule_policies p ON (p.account_id,p.id)=(s.account_id,s.policy_id)
            JOIN workflow_actions a ON a.account_id=s.account_id AND a.id=NEW.action_id
            JOIN workflow_action_versions v ON (v.account_id,v.action_id,v.revision,v.binding_digest)=
                (a.account_id,a.id,a.revision,a.binding_digest)
            WHERE s.account_id=NEW.account_id AND s.id=NEW.series_id AND NEW.ordinal<p.max_occurrences
              AND a.context_id=s.context_id AND a.routine_id=s.routine_id
              AND v.content_version=s.context_revision AND v.authority_generation=s.routine_generation
              AND v.not_before_ms=NEW.not_before_ms AND v.expires_at_ms=NEW.expires_at_ms
              AND a.revision=NEW.action_revision AND a.binding_digest=NEW.binding_digest AND a.phase='approved') THEN
            RAISE EXCEPTION 'workflow schedule requires exact approved action' USING ERRCODE='23514';
        END IF;
    ELSIF (to_jsonb(NEW)-ARRAY['phase','review_reason','lease_id','lease_until_ms','retry_at_ms','message_id','observed_message_state','updated_at'])<>
          (to_jsonb(OLD)-ARRAY['phase','review_reason','lease_id','lease_until_ms','retry_at_ms','message_id','observed_message_state','updated_at'])
          OR (OLD.message_id IS NOT NULL AND NEW.message_id IS DISTINCT FROM OLD.message_id)
          OR (OLD.phase IN ('cancelled','expired','missed_window','completed','failed') AND NEW IS DISTINCT FROM OLD)
          OR (OLD.phase IN ('dispatching','unknown') AND NEW.phase NOT IN ('dispatching','unknown','completed','failed')) THEN
        RAISE EXCEPTION 'workflow schedule identity or terminal state cannot change' USING ERRCODE='23514';
    ELSE
        needs_link := NEW.message_id IS DISTINCT FROM OLD.message_id;
    END IF;
    IF needs_link AND NOT EXISTS(
        SELECT 1 FROM workflow_message_links l WHERE l.account_id=NEW.account_id AND l.action_id=NEW.action_id
          AND l.revision=NEW.action_revision AND l.binding_digest=NEW.binding_digest
          AND l.message_id=NEW.message_id AND l.dispatch_id=NEW.dispatch_id) THEN
        RAISE EXCEPTION 'workflow schedule effect needs exact confirmed message link' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_schedule_occurrence_before_write BEFORE INSERT OR UPDATE ON workflow_schedule_occurrences
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_occurrence_guard();

CREATE FUNCTION workflow_schedule_message_link_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE o.account_id=NEW.account_id
        AND o.action_id=NEW.action_id AND o.action_revision=NEW.revision
        AND o.binding_digest=NEW.binding_digest AND o.dispatch_id<>NEW.dispatch_id) THEN
        RAISE EXCEPTION 'workflow message link differs from reserved schedule dispatch' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_schedule_link_before_insert BEFORE INSERT ON workflow_message_links
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_message_link_guard();

CREATE TRIGGER workflow_schedule_audit_before_update BEFORE UPDATE ON workflow_schedule_audit
    FOR EACH ROW EXECUTE FUNCTION workflow_schedule_policy_immutable();

-- Extend the shared decision fence rather than introducing another grant path.
-- Immediate actions without schedules retain the decision service predicate.
-- A scheduled action can effect only its exact reserved occurrence/window.
-- Session identifiers are immutable metadata, not reconstructed credentials.
-- No FK blocks normal session retention: a missing session simply fails closed.
CREATE FUNCTION workflow_schedule_owner_actor_current(wanted_account uuid,wanted_occurrence uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o
    JOIN sessions s ON (s.account_id,s.user_id,s.id)=(o.account_id,o.actor_id,o.owner_session_id)
    JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id)
    JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id
    WHERE o.account_id=wanted_account AND o.id=wanted_occurrence AND o.actor_kind='owner'
      AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL
      AND u.email_verified_at IS NOT NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp());
$$;
-- A later independently reviewed executor-grant migration can replace this
-- stable helper in place. Integration actors are closed in this migration.
CREATE FUNCTION workflow_schedule_actor_current(wanted_account uuid,wanted_occurrence uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_schedule_owner_actor_current(wanted_account,wanted_occurrence);
$$;
ALTER FUNCTION workflow_effect_current(uuid,uuid) RENAME TO workflow_decision_effect_current;
CREATE FUNCTION workflow_effect_current(wanted_account uuid,wanted_message uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_decision_effect_current(wanted_account,wanted_message) AND (
    NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o JOIN messages m
        ON (m.account_id,m.workflow_action_id)=(o.account_id,o.action_id)
        WHERE m.account_id=wanted_account AND m.id=wanted_message)
    OR EXISTS(SELECT 1 FROM workflow_schedule_occurrences o
        JOIN workflow_message_links l ON (l.account_id,l.action_id,l.revision,l.binding_digest)=
            (o.account_id,o.action_id,o.action_revision,o.binding_digest)
        WHERE o.account_id=wanted_account AND o.message_id=wanted_message
          AND l.message_id=o.message_id AND l.dispatch_id=o.dispatch_id
          AND o.phase='dispatching'
          AND workflow_schedule_actor_current(o.account_id,o.id)
          AND o.opens_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
          AND o.closes_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
          AND o.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint)
);
$$;

-- Refresh the shared trigger body when replacing the public predicate, so
-- sessions that used the earlier guard re-plan against the full fence chain.
CREATE OR REPLACE FUNCTION workflow_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME='message_events' THEN
        IF NEW.evidence_code IS DISTINCT FROM 'durable_intent' THEN RETURN NEW; END IF;
    END IF;
    IF EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
        AND workflow_action_id IS NOT NULL) AND
       NOT workflow_effect_current(NEW.account_id,NEW.message_id) THEN
        RAISE EXCEPTION 'workflow automation is fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;

-- Recheck at commit after insert/uniqueness waits and other transaction writes.
-- No grant or durable-intent acknowledgement is published before commit.
CREATE CONSTRAINT TRIGGER workflow_attempt_final_guard AFTER INSERT ON message_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
CREATE CONSTRAINT TRIGGER workflow_dispatch_final_guard AFTER INSERT ON dispatch_fences
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
CREATE CONSTRAINT TRIGGER workflow_intent_final_guard AFTER INSERT ON message_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
