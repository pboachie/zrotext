-- SPDX-License-Identifier: AGPL-3.0-only
-- Explicit owner replay is limited to two additional seven-attempt cycles.
-- Historical dead rows have no reliable retirement reason; never replay them.

ALTER TABLE webhook_deliveries
    ADD COLUMN generation smallint NOT NULL DEFAULT 1
        CHECK (generation BETWEEN 1 AND 3),
    ADD COLUMN terminal_reason text;
UPDATE webhook_deliveries SET terminal_reason='legacy' WHERE status='dead';
ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_terminal_reason CHECK
        ((status='dead') = (terminal_reason IS NOT NULL) AND
         (terminal_reason IS NULL OR terminal_reason IN
            ('failed', 'policy_rejected', 'retired', 'legacy'))),
    ADD CONSTRAINT webhook_deliveries_account_id_id_key UNIQUE (account_id,id);

ALTER TABLE webhook_attempts
    ADD COLUMN generation smallint NOT NULL DEFAULT 1
        CHECK (generation BETWEEN 1 AND 3);
ALTER TABLE webhook_attempts
    DROP CONSTRAINT webhook_attempts_delivery_id_attempt_number_key;
ALTER TABLE webhook_attempts
    ADD CONSTRAINT webhook_attempts_generation_number_key
        UNIQUE (delivery_id,generation,attempt_number);

CREATE TABLE webhook_replay_requests (
    account_id uuid NOT NULL,
    request_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    generation smallint NOT NULL CHECK (generation BETWEEN 2 AND 3),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id,request_id),
    UNIQUE (delivery_id,generation),
    FOREIGN KEY (account_id,delivery_id)
        REFERENCES webhook_deliveries(account_id,id)
);
