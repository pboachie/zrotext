-- SPDX-License-Identifier: AGPL-3.0-only
-- Default-off synthetic TEST candidate. Budget receipts are not execution authority.
CREATE TABLE exposure_deployment_budgets (
    id uuid PRIMARY KEY,
    version bigint NOT NULL CHECK(version>0),
    enabled boolean NOT NULL DEFAULT false,
    period_start_ms bigint NOT NULL CHECK(period_start_ms>=0),
    period_end_ms bigint NOT NULL,
    soft_units bigint NOT NULL CHECK(soft_units>=0),
    hard_units bigint NOT NULL CHECK(hard_units>=soft_units),
    outstanding_units bigint NOT NULL DEFAULT 0 CHECK(outstanding_units>=0),
    finalized_units bigint NOT NULL DEFAULT 0 CHECK(finalized_units>=0),
    CHECK(period_end_ms>period_start_ms)
);

CREATE TABLE exposure_route_policies (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    version bigint NOT NULL CHECK(version>0),
    deployment_id uuid NOT NULL REFERENCES exposure_deployment_budgets(id),
    enabled boolean NOT NULL DEFAULT false,
    operation text NOT NULL CHECK(operation IN ('provider','ai')),
    input_limit bigint NOT NULL CHECK(input_limit>=0),
    output_limit bigint NOT NULL CHECK(output_limit>0),
    input_rate bigint NOT NULL CHECK(input_rate>=0),
    output_rate bigint NOT NULL CHECK(output_rate>0),
    fixed_units bigint NOT NULL CHECK(fixed_units>=0),
    maximum_outstanding integer NOT NULL CHECK(maximum_outstanding BETWEEN 1 AND 1000),
    PRIMARY KEY(account_id,id),
    UNIQUE(account_id,id,version,deployment_id,operation)
);

-- One fixed original period per policy row. Rollover requires a new row;
-- old outstanding liability continues to consume the deployment envelope.
CREATE TABLE exposure_scope_budgets (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope_kind text NOT NULL CHECK(scope_kind IN ('tenant','device','route','workflow','campaign','turn')),
    scope_id uuid NOT NULL,
    version bigint NOT NULL CHECK(version>0),
    enabled boolean NOT NULL DEFAULT false,
    period_start_ms bigint NOT NULL CHECK(period_start_ms>=0),
    period_end_ms bigint NOT NULL,
    soft_units bigint NOT NULL CHECK(soft_units>=0),
    hard_units bigint NOT NULL CHECK(hard_units>=soft_units),
    outstanding_units bigint NOT NULL DEFAULT 0 CHECK(outstanding_units>=0),
    finalized_units bigint NOT NULL DEFAULT 0 CHECK(finalized_units>=0),
    PRIMARY KEY(account_id,scope_kind,scope_id,version),
    CHECK(period_end_ms>period_start_ms)
);
CREATE UNIQUE INDEX exposure_one_active_deployment ON exposure_deployment_budgets((true)) WHERE enabled;
CREATE UNIQUE INDEX exposure_one_active_scope ON exposure_scope_budgets(account_id,scope_kind,scope_id) WHERE enabled;

-- A policy revision may retain exact period identity, but an overlapping
-- invented interval cannot reset finalized usage. Actual invoice eligibility
-- remains an independent, unavailable lifecycle adapter.
CREATE FUNCTION exposure_period_no_overlap() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME='exposure_deployment_budgets' THEN
        IF EXISTS(SELECT 1 FROM exposure_deployment_budgets b
            WHERE b.period_start_ms<NEW.period_end_ms AND NEW.period_start_ms<b.period_end_ms
              AND (b.period_start_ms,b.period_end_ms) IS DISTINCT FROM
                  (NEW.period_start_ms,NEW.period_end_ms)) THEN
            RAISE EXCEPTION 'exposure deployment periods overlap' USING ERRCODE='23514';
        END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM exposure_scope_budgets b WHERE b.account_id=NEW.account_id
            AND b.scope_kind=NEW.scope_kind AND b.scope_id=NEW.scope_id
            AND b.period_start_ms<NEW.period_end_ms AND NEW.period_start_ms<b.period_end_ms
            AND (b.period_start_ms,b.period_end_ms) IS DISTINCT FROM
                (NEW.period_start_ms,NEW.period_end_ms)) THEN
            RAISE EXCEPTION 'exposure scope periods overlap' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER exposure_deployment_period BEFORE INSERT ON exposure_deployment_budgets
    FOR EACH ROW EXECUTE FUNCTION exposure_period_no_overlap();
CREATE TRIGGER exposure_scope_period BEFORE INSERT ON exposure_scope_budgets
    FOR EACH ROW EXECUTE FUNCTION exposure_period_no_overlap();

CREATE TABLE exposure_reservations (
    account_id uuid NOT NULL,
    id uuid NOT NULL,
    action_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
    route_policy_id uuid NOT NULL,
    operation text NOT NULL CHECK(operation IN ('provider','ai')),
    policy_version bigint NOT NULL CHECK(policy_version>0),
    deployment_id uuid NOT NULL REFERENCES exposure_deployment_budgets(id),
    device_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    routine_id uuid NOT NULL,
    routine_generation bigint NOT NULL CHECK(routine_generation>0),
    owner_user_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    maximum_units bigint NOT NULL CHECK(maximum_units>0),
    original_period_start_ms bigint NOT NULL,
    original_period_end_ms bigint NOT NULL,
    state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','executing','unknown','settled','released','review')),
    lease_id uuid,
    lease_until_ms bigint,
    actual_units bigint CHECK(actual_units>=0 AND actual_units<=maximum_units),
    result_digest bytea CHECK(octet_length(result_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    UNIQUE(account_id,action_id,revision,operation),
    FOREIGN KEY(account_id,action_id,revision,binding_digest)
        REFERENCES workflow_action_versions(account_id,action_id,revision,binding_digest),
    FOREIGN KEY(account_id,route_policy_id,policy_version,deployment_id,operation)
        REFERENCES exposure_route_policies(account_id,id,version,deployment_id,operation) ON DELETE CASCADE,
    FOREIGN KEY(account_id,device_id) REFERENCES devices(account_id,id),
    CHECK(original_period_end_ms>original_period_start_ms),
    CHECK((lease_id IS NULL)=(lease_until_ms IS NULL)),
    CHECK(state NOT IN ('executing','unknown') OR lease_id IS NOT NULL),
    CHECK((state IN ('settled','released'))=(actual_units IS NOT NULL AND result_digest IS NOT NULL)),
    CHECK(state<>'released' OR actual_units=0)
);
CREATE INDEX exposure_reservations_policy ON exposure_reservations(account_id,route_policy_id,state);
CREATE TABLE exposure_reservation_scopes (
    account_id uuid NOT NULL,
    reservation_id uuid NOT NULL,
    scope_kind text NOT NULL,
    scope_id uuid NOT NULL,
    version bigint NOT NULL,
    PRIMARY KEY(account_id,reservation_id,scope_kind),
    FOREIGN KEY(account_id,reservation_id) REFERENCES exposure_reservations(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,scope_kind,scope_id,version)
        REFERENCES exposure_scope_budgets(account_id,scope_kind,scope_id,version)
);

CREATE FUNCTION exposure_policy_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'enabled'-'outstanding_units'-'finalized_units') IS DISTINCT FROM
       (to_jsonb(OLD)-'enabled'-'outstanding_units'-'finalized_units') THEN
        RAISE EXCEPTION 'exposure policy identity is immutable' USING ERRCODE='23514';
    END IF;
    IF NOT OLD.enabled AND NEW.enabled THEN
        RAISE EXCEPTION 'exposure policy cannot reactivate' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER exposure_deployment_immutable BEFORE UPDATE ON exposure_deployment_budgets
    FOR EACH ROW EXECUTE FUNCTION exposure_policy_immutable();
CREATE TRIGGER exposure_route_immutable BEFORE UPDATE ON exposure_route_policies
    FOR EACH ROW EXECUTE FUNCTION exposure_policy_immutable();
CREATE TRIGGER exposure_scope_immutable BEFORE UPDATE ON exposure_scope_budgets
    FOR EACH ROW EXECUTE FUNCTION exposure_policy_immutable();

CREATE FUNCTION exposure_reservation_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'state'-'lease_id'-'lease_until_ms'-'actual_units'-'result_digest') IS DISTINCT FROM
       (to_jsonb(OLD)-'state'-'lease_id'-'lease_until_ms'-'actual_units'-'result_digest') THEN
        RAISE EXCEPTION 'exposure reservation identity is immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.state IN ('settled','released') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'exposure settlement is immutable' USING ERRCODE='23514';
    END IF;
    IF OLD.lease_id IS NOT NULL AND
       (NEW.lease_id,NEW.lease_until_ms) IS DISTINCT FROM (OLD.lease_id,OLD.lease_until_ms) THEN
        RAISE EXCEPTION 'exposure intent lease cannot be replaced' USING ERRCODE='23514';
    END IF;
    IF OLD.lease_id IS NULL AND NEW.lease_id IS NOT NULL AND
       (OLD.state<>'reserved' OR NEW.state<>'executing') THEN
        RAISE EXCEPTION 'exposure intent requires an unstarted reservation' USING ERRCODE='23514';
    END IF;
    IF OLD.state IN ('executing','unknown','review') AND NEW.state='reserved' THEN
        RAISE EXCEPTION 'uncertain external effect cannot be retried as new work' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER exposure_reservation_immutable BEFORE UPDATE ON exposure_reservations
    FOR EACH ROW EXECUTE FUNCTION exposure_reservation_immutable();
