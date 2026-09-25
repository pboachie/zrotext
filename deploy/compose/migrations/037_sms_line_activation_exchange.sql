-- SPDX-License-Identifier: AGPL-3.0-only
-- Carries one SMS line activation challenge between the owner's browser and
-- the enrolled device. The owner signs over the device signature, so the
-- device proof is stored until the owner approves. The nonce is retained only
-- until the activation acknowledgement is sent; both signatures, not nonce
-- secrecy, authorize activation.
CREATE TABLE sms_line_activation_exchanges (
    challenge_id uuid PRIMARY KEY REFERENCES line_activation_challenges(id),
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    nonce bytea CHECK (nonce IS NULL OR octet_length(nonce) = 32),
    pushed_connection_epoch bigint CHECK (pushed_connection_epoch > 0),
    android_api_level integer CHECK (android_api_level BETWEEN 28 AND 65535),
    active_subscription_count smallint CHECK (active_subscription_count = 1),
    selected_subscription_id integer CHECK (selected_subscription_id >= 0),
    device_signature_der bytea CHECK
        (device_signature_der IS NULL OR octet_length(device_signature_der) BETWEEN 8 AND 80),
    proof_site_id text,
    proof_instance_id text,
    proof_connection_epoch bigint CHECK (proof_connection_epoch > 0),
    proof_deployment_epoch bigint CHECK (proof_deployment_epoch > 0),
    proof_received_at timestamptz,
    ack_sent_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (account_id, line_id, device_id, generation)
        REFERENCES device_line_bindings(account_id, line_id, device_id, generation),
    CHECK ((proof_received_at IS NULL) = (device_signature_der IS NULL)),
    CHECK (proof_received_at IS NULL OR (
        android_api_level IS NOT NULL AND active_subscription_count IS NOT NULL
        AND selected_subscription_id IS NOT NULL AND proof_site_id IS NOT NULL
        AND proof_instance_id IS NOT NULL AND proof_connection_epoch IS NOT NULL
        AND proof_deployment_epoch IS NOT NULL)),
    CHECK (ack_sent_at IS NULL OR (proof_received_at IS NOT NULL AND nonce IS NULL))
);
CREATE INDEX sms_line_activation_exchanges_device
    ON sms_line_activation_exchanges(account_id, device_id) WHERE ack_sent_at IS NULL;

CREATE FUNCTION sms_line_activation_exchange_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'SMS line activation exchange cannot be deleted' USING ERRCODE = '23514';
    END IF;
    -- Identity is fixed; the device proof and acknowledgement are write-once;
    -- a cleared nonce can never return.
    IF NEW.challenge_id <> OLD.challenge_id OR NEW.account_id <> OLD.account_id OR
       NEW.line_id <> OLD.line_id OR NEW.device_id <> OLD.device_id OR
       NEW.generation <> OLD.generation OR NEW.created_at <> OLD.created_at OR
       (OLD.nonce IS NULL AND NEW.nonce IS NOT NULL) OR
       (OLD.nonce IS NOT NULL AND NEW.nonce IS NOT NULL AND NEW.nonce <> OLD.nonce) OR
       (OLD.proof_received_at IS NOT NULL AND (
           NEW.proof_received_at IS DISTINCT FROM OLD.proof_received_at OR
           NEW.device_signature_der IS DISTINCT FROM OLD.device_signature_der OR
           NEW.android_api_level IS DISTINCT FROM OLD.android_api_level OR
           NEW.active_subscription_count IS DISTINCT FROM OLD.active_subscription_count OR
           NEW.selected_subscription_id IS DISTINCT FROM OLD.selected_subscription_id OR
           NEW.proof_site_id IS DISTINCT FROM OLD.proof_site_id OR
           NEW.proof_instance_id IS DISTINCT FROM OLD.proof_instance_id OR
           NEW.proof_connection_epoch IS DISTINCT FROM OLD.proof_connection_epoch OR
           NEW.proof_deployment_epoch IS DISTINCT FROM OLD.proof_deployment_epoch)) OR
       (OLD.ack_sent_at IS NOT NULL AND NEW.ack_sent_at IS DISTINCT FROM OLD.ack_sent_at) THEN
        RAISE EXCEPTION 'SMS line activation exchange cannot change identity or replay'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sms_line_activation_exchange_before_update
    BEFORE UPDATE ON sms_line_activation_exchanges
    FOR EACH ROW EXECUTE FUNCTION sms_line_activation_exchange_guard();
CREATE TRIGGER sms_line_activation_exchange_before_delete
    BEFORE DELETE ON sms_line_activation_exchanges
    FOR EACH ROW EXECUTE FUNCTION sms_line_activation_exchange_guard();
