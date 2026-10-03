-- SPDX-License-Identifier: AGPL-3.0-only
-- Sealed ciphertext delivery is an independent, explicitly selected endpoint scope.
ALTER TABLE webhook_endpoints ADD COLUMN sealed_events_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE sealed_event_deliveries (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    event_id uuid NOT NULL,
    trust_generation bigint NOT NULL CHECK (trust_generation > 0),
    interval_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','leased','succeeded','dead')),
    attempt_count smallint NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 7),
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_id uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (account_id,endpoint_id) REFERENCES webhook_endpoints(account_id,id),
    FOREIGN KEY (account_id,event_id) REFERENCES sealed_inbound_events(account_id,id),
    FOREIGN KEY (account_id,interval_id) REFERENCES conversation_intervals(account_id,id),
    UNIQUE (account_id,id),
    UNIQUE (endpoint_id,event_id),
    CHECK ((status='leased' AND lease_id IS NOT NULL AND lease_until IS NOT NULL)
        OR (status<>'leased' AND lease_id IS NULL AND lease_until IS NULL))
);
CREATE INDEX sealed_event_deliveries_due ON sealed_event_deliveries(next_attempt_at,id)
    WHERE status='pending';

CREATE TABLE sealed_event_delivery_attempts (
    delivery_id uuid NOT NULL REFERENCES sealed_event_deliveries(id),
    attempt_number smallint NOT NULL CHECK (attempt_number BETWEEN 1 AND 7),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    outcome text CHECK (outcome IN ('ack','timeout','http_error','network_error','policy_rejected')),
    http_status smallint CHECK (http_status BETWEEN 100 AND 599),
    PRIMARY KEY (delivery_id,attempt_number),
    CHECK ((completed_at IS NULL) = (outcome IS NULL))
);

-- Retention and committed withdrawal must remove dependent delivery metadata
-- in the same transaction; no retained second copy can outlive body erasure.
CREATE FUNCTION sealed_event_delivery_forget() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME='sealed_inbound_events' THEN
        IF NEW.envelope IS NOT NULL THEN RETURN NEW; END IF;
        PERFORM id FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND event_id=NEW.id ORDER BY id FOR UPDATE;
        DELETE FROM sealed_event_delivery_attempts a USING sealed_event_deliveries d
            WHERE a.delivery_id=d.id AND d.account_id=NEW.account_id AND d.event_id=NEW.id;
        DELETE FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND event_id=NEW.id;
    ELSE
        IF NEW.phase NOT IN ('withdrawn','expired') THEN RETURN NEW; END IF;
        PERFORM id FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND interval_id=NEW.id ORDER BY id FOR UPDATE;
        DELETE FROM sealed_event_delivery_attempts a USING sealed_event_deliveries d
            WHERE a.delivery_id=d.id AND d.account_id=NEW.account_id AND d.interval_id=NEW.id;
        DELETE FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND interval_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER sealed_event_delivery_body_purge AFTER UPDATE OF envelope ON sealed_inbound_events
    FOR EACH ROW EXECUTE FUNCTION sealed_event_delivery_forget();
CREATE TRIGGER sealed_event_delivery_interval_withdrawal AFTER UPDATE OF phase ON conversation_intervals
    FOR EACH ROW EXECUTE FUNCTION sealed_event_delivery_forget();

CREATE FUNCTION sealed_event_delivery_retire_endpoint() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.enabled AND NEW.sealed_events_enabled THEN RETURN NEW; END IF;
    PERFORM id FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND endpoint_id=NEW.id ORDER BY id FOR UPDATE;
    DELETE FROM sealed_event_delivery_attempts a USING sealed_event_deliveries d
        WHERE a.delivery_id=d.id AND d.account_id=NEW.account_id AND d.endpoint_id=NEW.id;
    DELETE FROM sealed_event_deliveries WHERE account_id=NEW.account_id AND endpoint_id=NEW.id;
    RETURN NEW;
END $$;
CREATE TRIGGER sealed_event_delivery_endpoint_retirement AFTER UPDATE OF enabled,sealed_events_enabled ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION sealed_event_delivery_retire_endpoint();

CREATE INDEX sealed_event_deliveries_expired_lease ON sealed_event_deliveries(lease_until,id) WHERE status='leased';

-- Legacy disable cannot preserve an implicit encrypted-transfer opt-in.
CREATE FUNCTION sealed_event_selection_disable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT NEW.enabled THEN NEW.sealed_events_enabled := false; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER sealed_event_selection_disabled BEFORE UPDATE OF enabled ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION sealed_event_selection_disable();

CREATE INDEX sealed_event_deliveries_event ON sealed_event_deliveries(account_id,event_id,id);
CREATE INDEX sealed_event_deliveries_interval ON sealed_event_deliveries(account_id,interval_id,id);
CREATE INDEX sealed_event_deliveries_endpoint ON sealed_event_deliveries(account_id,endpoint_id,id);
