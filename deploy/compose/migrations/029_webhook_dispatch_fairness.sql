-- SPDX-License-Identifier: AGPL-3.0-only
-- Durable cursors make claims fair across processes, not just within one worker.
-- Maintenance gate: stop webhook senders on every old node first. This lock
-- prevents an old claim from racing lease recovery and the unique index build.
LOCK TABLE webhook_deliveries IN ACCESS EXCLUSIVE MODE;
-- Mirror claim_webhook's expired-lease recovery. The attempt number and
-- generation remain immutable audit history; only incomplete attempts close.
UPDATE webhook_attempts a SET completed_at=now(),outcome='timeout'
FROM webhook_deliveries d
WHERE a.delivery_id=d.id AND a.generation=d.generation
  AND a.attempt_number=d.attempt_count AND a.completed_at IS NULL
  AND d.status='leased' AND d.lease_until<=now();
UPDATE webhook_deliveries SET
    status=CASE WHEN attempt_count<7 THEN 'pending' ELSE 'dead' END,
    terminal_reason=CASE WHEN attempt_count<7 THEN NULL ELSE 'failed' END,
    lease_owner=NULL,
    lease_until=NULL,
    next_attempt_at=now() + (CASE attempt_count
        WHEN 1 THEN 60 WHEN 2 THEN 300 WHEN 3 THEN 900
        WHEN 4 THEN 3600 WHEN 5 THEN 21600 WHEN 6 THEN 86400
        ELSE 0 END * interval '1 second'),
    updated_at=now()
WHERE status='leased' AND lease_until<=now();
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM webhook_deliveries WHERE status='leased') THEN
        RAISE EXCEPTION 'webhook migration 027 requires zero active leases; set WEBHOOK_DELIVERY_ENABLED=false on every old node, wait for leases to expire, then retry';
    END IF;
END;
$$;
CREATE SEQUENCE webhook_claim_sequence;
CREATE TABLE webhook_dispatch_accounts (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    last_claim_seq bigint NOT NULL DEFAULT 0
);
CREATE INDEX webhook_dispatch_accounts_fair
    ON webhook_dispatch_accounts(last_claim_seq,account_id);
INSERT INTO webhook_dispatch_accounts(account_id)
SELECT DISTINCT account_id FROM webhook_endpoints;

CREATE FUNCTION register_webhook_dispatch_account() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO webhook_dispatch_accounts(account_id) VALUES(NEW.account_id)
    ON CONFLICT(account_id) DO NOTHING;
    RETURN NEW;
END;
$$;
CREATE TRIGGER webhook_endpoint_dispatch_account
AFTER INSERT ON webhook_endpoints FOR EACH ROW
EXECUTE FUNCTION register_webhook_dispatch_account();

ALTER TABLE webhook_endpoints
    ADD COLUMN last_claim_seq bigint NOT NULL DEFAULT 0,
    ADD COLUMN failure_started_at timestamptz,
    ADD COLUMN paused_at timestamptz;
CREATE UNIQUE INDEX webhook_one_leased_per_endpoint
    ON webhook_deliveries(endpoint_id) WHERE status='leased';
CREATE INDEX webhook_expired_leases
    ON webhook_deliveries(lease_until,id) WHERE status='leased';
CREATE INDEX webhook_deliveries_endpoint_due
    ON webhook_deliveries(endpoint_id,next_attempt_at,id)
    WHERE status='pending';
