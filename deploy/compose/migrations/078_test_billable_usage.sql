-- SPDX-License-Identifier: AGPL-3.0-only
-- Serial migration 078. Source-only TEST candidate: no rows,
-- worker registration, provider calls, products, prices or launch activation.
-- Existing reserve/refund usage tables remain the admission authority.

CREATE TABLE billing_usage_test_policies (
    account_id uuid NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    stripe_customer_id text NOT NULL,
    meter_id text NOT NULL CHECK (meter_id ~ '^mtr_[A-Za-z0-9_]{1,96}$'),
    event_name text NOT NULL CHECK (event_name ~ '^[A-Za-z0-9_.-]{1,100}$'),
    mode text NOT NULL DEFAULT 'test' CHECK (mode = 'test'),
    api_version text NOT NULL DEFAULT '2025-07-30.basil'
        CHECK (api_version = '2025-07-30.basil'),
    active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, policy_version),
    FOREIGN KEY (account_id, stripe_customer_id)
        REFERENCES billing_customers(account_id, stripe_customer_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX billing_usage_one_active_policy
    ON billing_usage_test_policies(account_id) WHERE active;

-- A provenance snapshot of the EXISTING reservation, not another quota or
-- reservation counter. Captured in its admission transaction only if opted in.
CREATE TABLE billing_usage_bindings (
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    usage_entry_kind text NOT NULL DEFAULT 'reserve' CHECK (usage_entry_kind = 'reserve'),
    policy_version bigint NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    report_at timestamptz NOT NULL,
    PRIMARY KEY (account_id, message_id),
    FOREIGN KEY (account_id, message_id, usage_entry_kind)
        REFERENCES usage_ledger(account_id, message_id, entry_kind) ON DELETE CASCADE,
    FOREIGN KEY (account_id, policy_version)
        REFERENCES billing_usage_test_policies(account_id, policy_version) ON DELETE CASCADE,
    CHECK (period_start = date_trunc('month',period_start::timestamp)::date),
    CHECK (period_end = (period_start + interval '1 month')::date)
);

CREATE TABLE billing_usage_finalized (
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    contract_version smallint NOT NULL DEFAULT 1 CHECK (contract_version = 1),
    category text NOT NULL DEFAULT 'android_execution' CHECK (category = 'android_execution'),
    units smallint NOT NULL DEFAULT 1 CHECK (units = 1),
    success_event_id uuid NOT NULL,
    success_attempt_id uuid NOT NULL,
    finalized_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, message_id),
    FOREIGN KEY (account_id, message_id)
        REFERENCES billing_usage_bindings(account_id, message_id) ON DELETE CASCADE
);

CREATE INDEX billing_usage_binding_period
    ON billing_usage_bindings(account_id,period_start,policy_version,message_id);

CREATE TABLE billing_usage_outbox (
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    identifier text NOT NULL UNIQUE CHECK (identifier ~ '^zt-usage-v1-[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','leased','acknowledged','review')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 7),
    first_attempt_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_until timestamptz,
    acknowledged_at timestamptz,
    error_class text CHECK (error_class IN ('retry','unknown','permanent','window',
        'period_closed','binding','disabled','response','attempt_limit','meter_error','conflict')),
    PRIMARY KEY (account_id, message_id),
    FOREIGN KEY (account_id, message_id)
        REFERENCES billing_usage_finalized(account_id, message_id) ON DELETE CASCADE,
    CHECK ((state = 'leased') = (lease_id IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (state <> 'acknowledged' OR acknowledged_at IS NOT NULL),
    CHECK (acknowledged_at IS NULL OR state IN ('acknowledged','review'))
);
CREATE INDEX billing_usage_outbox_due ON billing_usage_outbox(account_id,next_attempt_at,message_id)
    WHERE state IN ('pending','leased');
CREATE INDEX billing_usage_outbox_active_lease ON billing_usage_outbox(account_id,lease_until)
    WHERE state='leased';

-- Signature verification and TEST/meter/account binding precede insertion.
-- Thin-error samples are not a complete list: retain the affected validation
-- interval and park every matching event, never just the sampled identifier.
CREATE TABLE billing_usage_meter_error_receipts (
    event_id text PRIMARY KEY CHECK (event_id ~ '^evt_[A-Za-z0-9_]{1,96}$'),
    meter_id text NOT NULL,
    body_digest bytea NOT NULL CHECK (octet_length(body_digest) = 32),
    validation_start timestamptz NOT NULL,
    validation_end timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (validation_start <= validation_end)
);

CREATE TABLE billing_usage_meter_errors (
    event_id text NOT NULL REFERENCES billing_usage_meter_error_receipts(event_id),
    account_id uuid NOT NULL,
    policy_version bigint NOT NULL,
    body_digest bytea NOT NULL CHECK (octet_length(body_digest) = 32),
    validation_start timestamptz NOT NULL,
    validation_end timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,policy_version,event_id),
    FOREIGN KEY (account_id, policy_version)
        REFERENCES billing_usage_test_policies(account_id, policy_version) ON DELETE CASCADE,
    CHECK (validation_start <= validation_end)
);

CREATE TABLE billing_usage_reconciliations (
    account_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    policy_version bigint NOT NULL,
    period_start date NOT NULL,
    finalized_units bigint NOT NULL CHECK (finalized_units >= 0),
    acknowledged_units bigint NOT NULL CHECK (acknowledged_units >= 0),
    provider_units bigint NOT NULL CHECK (provider_units >= 0),
    invoice_units bigint CHECK (invoice_units >= 0),
    pending_units bigint NOT NULL CHECK (pending_units >= 0),
    review_units bigint NOT NULL CHECK (review_units >= 0),
    snapshot_digest bytea NOT NULL CHECK (octet_length(snapshot_digest) = 32),
    state text NOT NULL CHECK (state IN ('pending','diverged','observed_equal')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id, snapshot_id),
    FOREIGN KEY (account_id, policy_version)
        REFERENCES billing_usage_test_policies(account_id, policy_version) ON DELETE CASCADE
);

-- An attributed owner review REQUEST, never proof of a provider credit or
-- invoice mutation. One terminal decision per original logical action;
-- retries/duplicates cannot accumulate credits. No price or monetary amount.
CREATE TABLE billing_usage_adjustment_requests (
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    request_id uuid NOT NULL,
    policy_version smallint NOT NULL DEFAULT 1 CHECK (policy_version=1),
    decision text NOT NULL CHECK (decision IN ('request_credit','retain_charge')),
    reason text NOT NULL CHECK (reason IN ('uncertain_execution','meter_rejection','owner_cancelled_review')),
    requested_units smallint NOT NULL CHECK (requested_units IN (-1,0)),
    owner_user_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,message_id),
    UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,message_id) REFERENCES billing_usage_finalized(account_id,message_id) ON DELETE CASCADE,
    CHECK ((decision='request_credit' AND requested_units=-1) OR
           (decision='retain_charge' AND requested_units=0))
);

CREATE FUNCTION billing_usage_freeze() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'billable usage provenance is immutable';
END
$$;
CREATE TRIGGER billing_usage_bindings_immutable BEFORE UPDATE ON billing_usage_bindings
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
CREATE TRIGGER billing_usage_finalized_immutable BEFORE UPDATE ON billing_usage_finalized
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
CREATE TRIGGER billing_usage_error_receipts_immutable BEFORE UPDATE ON billing_usage_meter_error_receipts
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
CREATE TRIGGER billing_usage_errors_immutable BEFORE UPDATE ON billing_usage_meter_errors
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
CREATE TRIGGER billing_usage_reconciliations_immutable BEFORE UPDATE ON billing_usage_reconciliations
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
CREATE TRIGGER billing_usage_adjustments_immutable BEFORE UPDATE ON billing_usage_adjustment_requests
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();

CREATE FUNCTION billing_usage_policy_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.account_id,NEW.policy_version,NEW.stripe_customer_id,NEW.meter_id,
        NEW.event_name,NEW.mode,NEW.api_version,NEW.created_at)
        IS DISTINCT FROM
       (OLD.account_id,OLD.policy_version,OLD.stripe_customer_id,OLD.meter_id,
        OLD.event_name,OLD.mode,OLD.api_version,OLD.created_at) THEN
        RAISE EXCEPTION 'billable policy widening needs a new version';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER billing_usage_policy_immutable BEFORE UPDATE ON billing_usage_test_policies
    FOR EACH ROW EXECUTE FUNCTION billing_usage_policy_identity();

CREATE FUNCTION billing_usage_outbox_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.account_id,NEW.message_id,NEW.identifier,NEW.first_attempt_at)
        IS DISTINCT FROM
       (OLD.account_id,OLD.message_id,OLD.identifier,
        COALESCE(OLD.first_attempt_at,NEW.first_attempt_at)) THEN
        RAISE EXCEPTION 'billable outbox identity is immutable';
    END IF;
    IF OLD.acknowledged_at IS NOT NULL AND NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at THEN
        RAISE EXCEPTION 'provider acknowledgement history is immutable';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER billing_usage_outbox_immutable BEFORE UPDATE ON billing_usage_outbox
    FOR EACH ROW EXECUTE FUNCTION billing_usage_outbox_identity();

CREATE FUNCTION billing_usage_capture_reservation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.entry_kind = 'reserve' AND NEW.metric = 'outbound_message' THEN
        INSERT INTO billing_usage_bindings(account_id,message_id,policy_version,
            period_start,period_end,report_at)
        SELECT NEW.account_id,NEW.message_id,p.policy_version,
            u.period_start,u.period_end,NEW.created_at
        FROM billing_usage_test_policies p JOIN usage_periods u
            ON u.account_id=NEW.account_id AND u.metric=NEW.metric AND u.period_start=NEW.period_start
        WHERE p.account_id=NEW.account_id AND p.active AND p.mode='test'
        FOR SHARE OF p;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER billing_usage_bind_reserve AFTER INSERT ON usage_ledger
    FOR EACH ROW EXECUTE FUNCTION billing_usage_capture_reservation();

CREATE FUNCTION billing_usage_finalize_sent() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE finalized boolean;
BEGIN
    -- Only the aggregate all-segment success transition. Intent, grants,
    -- delivery acknowledgements, failures and unknowns are not charge events.
    IF NEW.evidence_code = 'sent_callback_ok' AND NEW.resulting_state = 'submitted' THEN
        WITH inserted AS (
            INSERT INTO billing_usage_finalized(account_id,message_id,success_event_id,success_attempt_id)
            SELECT NEW.account_id,NEW.message_id,NEW.id,NEW.attempt_id
            FROM billing_usage_bindings b JOIN messages m
                ON (m.account_id,m.id)=(b.account_id,b.message_id)
            WHERE b.account_id=NEW.account_id AND b.message_id=NEW.message_id
                AND m.state='submitted' AND NOT EXISTS (
                    SELECT 1 FROM usage_ledger l WHERE l.account_id=NEW.account_id
                        AND l.message_id=NEW.message_id AND l.entry_kind='refund')
            ON CONFLICT(account_id,message_id) DO NOTHING RETURNING 1
        ) SELECT EXISTS(SELECT 1 FROM inserted) INTO finalized;
        IF finalized THEN
            INSERT INTO billing_usage_outbox(account_id,message_id,identifier)
            VALUES(NEW.account_id,NEW.message_id,'zt-usage-v1-' || encode(sha256(convert_to(
                NEW.account_id::text || ':' || NEW.message_id::text || ':android_execution:1','UTF8')),'hex'));
        END IF;
    ELSIF NEW.evidence_code = 'callback_conflict' THEN
        UPDATE billing_usage_outbox SET state='review',lease_id=NULL,lease_until=NULL,
            error_class='conflict'
        WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER billing_usage_success_outbox AFTER INSERT ON message_events
    FOR EACH ROW EXECUTE FUNCTION billing_usage_finalize_sent();


-- Shared provider error receipts contain no content. Erasing the final tenant
-- mapping removes its otherwise orphaned receipt; shared mappings survive.
CREATE FUNCTION billing_usage_error_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Serialize last-mapping cleanup; a fresh statement after the lock sees
    -- another tenant's committed deletion rather than retaining an orphan.
    PERFORM 1 FROM billing_usage_meter_error_receipts WHERE event_id=OLD.event_id FOR UPDATE;
    DELETE FROM billing_usage_meter_error_receipts r WHERE r.event_id=OLD.event_id
        AND NOT EXISTS(SELECT 1 FROM billing_usage_meter_errors e WHERE e.event_id=r.event_id);
    RETURN OLD;
END
$$;
CREATE TRIGGER billing_usage_error_erasure AFTER DELETE ON billing_usage_meter_errors
    FOR EACH ROW EXECUTE FUNCTION billing_usage_error_cleanup();
