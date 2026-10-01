-- SPDX-License-Identifier: AGPL-3.0-only
-- Restricted TEST candidate. Installation enables no account or provider.
ALTER TABLE usage_quota_policies ADD COLUMN invoice_bound_test boolean NOT NULL DEFAULT false;
ALTER TABLE usage_quota_policies ADD CONSTRAINT invoice_bound_test_source
    CHECK(NOT invoice_bound_test OR source='stripe_test');

CREATE TABLE billing_invoice_periods (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    subscription_id text NOT NULL REFERENCES billing_reconciliations(stripe_subscription_id),
    invoice_id text NOT NULL CHECK(invoice_id ~ '^in_[A-Za-z0-9]+$'),
    line_id text NOT NULL CHECK(line_id ~ '^il_[A-Za-z0-9]+$'),
    item_id text NOT NULL CHECK(item_id ~ '^si_[A-Za-z0-9]+$'),
    start_ms bigint NOT NULL CHECK(start_ms>0),
    end_ms bigint NOT NULL CHECK(end_ms>start_ms AND end_ms-start_ms<=31968000000),
    original_price_id text NOT NULL CHECK(original_price_id ~ '^price_[A-Za-z0-9]+$'),
    original_limit bigint NOT NULL CHECK(original_limit>=0),
    reserved_units bigint NOT NULL DEFAULT 0 CHECK(reserved_units>=0),
    refunded_units bigint NOT NULL DEFAULT 0 CHECK(refunded_units>=0 AND refunded_units<=reserved_units),
    open_units bigint NOT NULL DEFAULT 0 CHECK(open_units>=0 AND open_units<=reserved_units-refunded_units),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(account_id,id),
    UNIQUE(account_id,subscription_id,start_ms,end_ms),
    UNIQUE(account_id,invoice_id)
);

CREATE TABLE billing_invoice_entitlements (
    account_id uuid PRIMARY KEY REFERENCES accounts(id),
    subscription_id text NOT NULL REFERENCES billing_reconciliations(stripe_subscription_id),
    customer_id text NOT NULL,
    mode text NOT NULL DEFAULT 'test' CHECK(mode='test'),
    period_id uuid,
    observed_invoice_id text,
    effective_price_id text,
    effective_limit bigint NOT NULL CHECK(effective_limit>=0),
    phase text NOT NULL CHECK(phase IN ('active','grace','restricted','cancelled','review')),
    grace_until_ms bigint,
    cancel_at_ms bigint,
    generation bigint NOT NULL CHECK(generation>0),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(account_id,customer_id) REFERENCES billing_customers(account_id,stripe_customer_id),
    FOREIGN KEY(account_id,period_id) REFERENCES billing_invoice_periods(account_id,id)
);

-- Supplemental period attribution of the existing usage ledger, not a second
-- charge ledger. Original message identity survives message/ledger retention;
-- unconfirmed work retains its open liability instead of gaining credit.
CREATE TABLE billing_invoice_usage (
    account_id uuid NOT NULL REFERENCES accounts(id),
    message_id uuid NOT NULL,
    period_id uuid NOT NULL,
    terminal boolean NOT NULL DEFAULT false,
    refunded boolean NOT NULL DEFAULT false,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,message_id),
    FOREIGN KEY(account_id,period_id) REFERENCES billing_invoice_periods(account_id,id)
);
CREATE INDEX billing_invoice_usage_period ON billing_invoice_usage(account_id,period_id);

CREATE TABLE billing_invoice_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    generation bigint NOT NULL CHECK(generation>0),
    period_id uuid,
    phase text NOT NULL CHECK(phase IN ('active','grace','restricted','cancelled','review')),
    effective_limit bigint NOT NULL CHECK(effective_limit>=0),
    observed_invoice_id text,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(account_id,period_id) REFERENCES billing_invoice_periods(account_id,id)
);
CREATE INDEX billing_invoice_audit_account ON billing_invoice_audit(account_id,id);
CREATE INDEX billing_invoice_audit_retention ON billing_invoice_audit(recorded_at,id);

CREATE FUNCTION preserve_billing_invoice_period() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id,NEW.account_id,NEW.subscription_id,NEW.invoice_id,NEW.line_id,NEW.item_id,
        NEW.start_ms,NEW.end_ms,NEW.original_price_id,NEW.original_limit,NEW.applied_at)
       IS DISTINCT FROM
       (OLD.id,OLD.account_id,OLD.subscription_id,OLD.invoice_id,OLD.line_id,OLD.item_id,
        OLD.start_ms,OLD.end_ms,OLD.original_price_id,OLD.original_limit,OLD.applied_at)
       OR NEW.reserved_units<OLD.reserved_units OR NEW.refunded_units<OLD.refunded_units THEN
        RAISE EXCEPTION 'invoice period authority is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_period_immutable BEFORE UPDATE ON billing_invoice_periods
    FOR EACH ROW EXECUTE FUNCTION preserve_billing_invoice_period();

CREATE FUNCTION preserve_billing_invoice_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.account_id,NEW.message_id,NEW.period_id,NEW.recorded_at)
       IS DISTINCT FROM (OLD.account_id,OLD.message_id,OLD.period_id,OLD.recorded_at)
       OR (OLD.terminal AND NOT NEW.terminal) OR (OLD.refunded AND NOT NEW.refunded) THEN
        RAISE EXCEPTION 'invoice usage identity cannot reopen' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_usage_immutable BEFORE UPDATE ON billing_invoice_usage
    FOR EACH ROW EXECUTE FUNCTION preserve_billing_invoice_usage();

-- Called by existing ledger insertion while the admission transaction holds
-- its canonical account/customer/reconciliation/policy locks. No reverse
-- account or customer lock is acquired inside this function.
CREATE FUNCTION reserve_billing_invoice_unit(p_account uuid,p_message uuid) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE e billing_invoice_entitlements%ROWTYPE;
        p billing_invoice_periods%ROWTYPE;
        carry bigint;
        now_ms bigint;
BEGIN
    IF EXISTS(SELECT 1 FROM billing_invoice_usage WHERE account_id=p_account AND message_id=p_message) THEN
        RETURN false;
    END IF;
    SELECT * INTO e FROM billing_invoice_entitlements WHERE account_id=p_account FOR UPDATE;
    IF NOT FOUND OR e.period_id IS NULL THEN RETURN false; END IF;
    SELECT * INTO p FROM billing_invoice_periods WHERE account_id=p_account AND id=e.period_id FOR UPDATE;
    now_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
    IF NOT FOUND OR e.phase NOT IN ('active','grace')
       OR (e.cancel_at_ms IS NOT NULL AND e.cancel_at_ms<=now_ms)
       OR p.start_ms>now_ms OR p.end_ms<=now_ms
       OR (e.phase='grace' AND (e.grace_until_ms IS NULL OR e.grace_until_ms<=now_ms))
       OR NOT EXISTS(SELECT 1 FROM billing_customers c WHERE c.account_id=p_account AND c.stripe_customer_id=e.customer_id)
       OR NOT EXISTS(SELECT 1 FROM usage_quota_policies q WHERE q.account_id=p_account AND q.metric='outbound_message'
           AND q.source='stripe_test' AND q.invoice_bound_test)
       OR NOT EXISTS(SELECT 1 FROM billing_reconciliations r WHERE r.account_id=p_account
           AND r.stripe_subscription_id=e.subscription_id AND r.stripe_customer_id=e.customer_id
           AND r.dirty_generation=r.processed_generation AND r.processed_generation=e.generation AND r.state='queued')
       OR EXISTS(SELECT 1 FROM billing_reconciliations r WHERE r.account_id=p_account AND r.dirty_generation<>r.processed_generation)
       OR EXISTS(SELECT 1 FROM billing_risk_events r WHERE r.account_id=p_account AND r.state IN ('queued','held','needs_review'))
       OR EXISTS(SELECT 1 FROM billing_payment_holds h WHERE h.account_id=p_account)
       OR (SELECT count(*) FROM billing_subscriptions s WHERE s.account_id=p_account
           AND s.stripe_status NOT IN ('canceled','incomplete_expired','provider_deleted'))<>1
       OR NOT EXISTS(SELECT 1 FROM billing_subscriptions s WHERE s.account_id=p_account
           AND s.stripe_subscription_id=e.subscription_id AND s.stripe_customer_id=e.customer_id
           AND s.stripe_price_id=e.effective_price_id AND s.recognized_price
           AND s.latest_invoice_id=e.observed_invoice_id
           AND ((e.phase='active' AND s.stripe_status='active') OR (e.phase='grace' AND s.stripe_status='past_due')))
       OR NOT EXISTS(SELECT 1 FROM messages m WHERE m.account_id=p_account AND m.id=p_message)
       OR NOT EXISTS(SELECT 1 FROM usage_ledger l WHERE l.account_id=p_account AND l.message_id=p_message
           AND l.entry_kind='reserve' AND l.units=1) THEN
        RETURN false;
    END IF;
    SELECT coalesce(sum(open_units),0)::bigint INTO carry FROM billing_invoice_periods
        WHERE account_id=p_account AND id<>p.id;
    IF e.effective_limit<=0 OR p.reserved_units-p.refunded_units>=e.effective_limit
       OR carry>=e.effective_limit-(p.reserved_units-p.refunded_units) THEN RETURN false; END IF;
    UPDATE billing_invoice_periods SET reserved_units=reserved_units+1,open_units=open_units+1 WHERE id=p.id;
    INSERT INTO billing_invoice_usage(account_id,message_id,period_id) VALUES(p_account,p_message,p.id);
    RETURN true;
END $$;

CREATE FUNCTION apply_billing_invoice_ledger() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p_id uuid;
        was_open boolean;
BEGIN
    IF NEW.entry_kind='reserve' THEN
        IF EXISTS(SELECT 1 FROM usage_quota_policies WHERE account_id=NEW.account_id AND metric=NEW.metric AND invoice_bound_test)
           AND NOT reserve_billing_invoice_unit(NEW.account_id,NEW.message_id) THEN
            RAISE EXCEPTION 'invoice budget unavailable' USING ERRCODE='23514',CONSTRAINT='billing_invoice_budget_available';
        END IF;
    ELSE
        SELECT period_id INTO p_id FROM billing_invoice_usage WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
        IF FOUND THEN
            PERFORM 1 FROM billing_invoice_periods WHERE id=p_id FOR UPDATE;
            SELECT NOT terminal AND NOT refunded INTO was_open FROM billing_invoice_usage
                WHERE account_id=NEW.account_id AND message_id=NEW.message_id AND NOT refunded FOR UPDATE;
            IF FOUND THEN
                UPDATE billing_invoice_periods SET refunded_units=refunded_units+1,
                    open_units=open_units-CASE WHEN was_open THEN 1 ELSE 0 END WHERE id=p_id;
                UPDATE billing_invoice_usage SET refunded=true WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_ledger AFTER INSERT ON usage_ledger
    FOR EACH ROW EXECUTE FUNCTION apply_billing_invoice_ledger();

CREATE FUNCTION close_billing_invoice_liability() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p_id uuid;
BEGIN
    IF NEW.state IN ('delivered','failed','cancelled','expired') AND NEW.state IS DISTINCT FROM OLD.state THEN
        SELECT period_id INTO p_id FROM billing_invoice_usage WHERE account_id=NEW.account_id AND message_id=NEW.id;
        IF FOUND THEN
            PERFORM 1 FROM billing_invoice_periods WHERE id=p_id FOR UPDATE;
            UPDATE billing_invoice_usage SET terminal=true WHERE account_id=NEW.account_id AND message_id=NEW.id AND NOT terminal;
            IF FOUND THEN
                UPDATE billing_invoice_periods SET open_units=open_units-1 WHERE id=p_id
                    AND NOT EXISTS(SELECT 1 FROM billing_invoice_usage WHERE account_id=NEW.account_id AND message_id=NEW.id AND refunded);
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER billing_invoice_liability AFTER UPDATE OF state ON messages
    FOR EACH ROW EXECUTE FUNCTION close_billing_invoice_liability();
