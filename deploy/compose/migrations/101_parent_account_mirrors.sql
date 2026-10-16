-- SPDX-License-Identifier: AGPL-3.0-only
-- Ownership mirrors only; no profile-selection or generic writer policy.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $migration$
DECLARE
    installation name;
BEGIN
    SELECT n.nspname INTO STRICT installation
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r';
    IF installation LIKE 'pg_%' OR installation='information_schema' THEN
        RAISE EXCEPTION 'application installation namespace required' USING ERRCODE='23514';
    END IF;

    -- Freeze parent/child writes before backfill and trigger installation. A
    -- busy installation aborts this migration transaction within lock_timeout.
    EXECUTE pg_catalog.format($ddl$
        LOCK TABLE %1$I.email_verifications,%1$I.password_resets,
          %1$I.password_reset_mail_outbox,%1$I.sealed_event_deliveries,
          %1$I.sealed_event_delivery_attempts,%1$I.verification_mail_outbox,
          %1$I.webhook_attempts,%1$I.webhook_deliveries IN SHARE ROW EXCLUSIVE MODE;

        ALTER TABLE %1$I.email_verifications
          ADD CONSTRAINT email_verifications_account_identity UNIQUE(account_id,id);
        ALTER TABLE %1$I.password_resets
          ADD CONSTRAINT password_resets_account_identity UNIQUE(account_id,id);

        ALTER TABLE %1$I.password_reset_mail_outbox ADD COLUMN account_id uuid;
        ALTER TABLE %1$I.verification_mail_outbox ADD COLUMN account_id uuid;
        ALTER TABLE %1$I.sealed_event_delivery_attempts ADD COLUMN account_id uuid;
        ALTER TABLE %1$I.webhook_attempts ADD COLUMN account_id uuid;

        UPDATE %1$I.password_reset_mail_outbox c SET account_id=p.account_id
          FROM %1$I.password_resets p WHERE p.id=c.reset_id;
        UPDATE %1$I.verification_mail_outbox c SET account_id=p.account_id
          FROM %1$I.email_verifications p WHERE p.id=c.verification_id;
        UPDATE %1$I.sealed_event_delivery_attempts c SET account_id=p.account_id
          FROM %1$I.sealed_event_deliveries p WHERE p.id=c.delivery_id;
        UPDATE %1$I.webhook_attempts c SET account_id=p.account_id
          FROM %1$I.webhook_deliveries p WHERE p.id=c.delivery_id;

        ALTER TABLE %1$I.password_reset_mail_outbox
          ALTER COLUMN account_id SET NOT NULL,
          ADD CONSTRAINT password_reset_mail_account_parent
            FOREIGN KEY(account_id,reset_id) REFERENCES %1$I.password_resets(account_id,id) ON DELETE CASCADE;
        ALTER TABLE %1$I.verification_mail_outbox
          ALTER COLUMN account_id SET NOT NULL,
          ADD CONSTRAINT verification_mail_account_parent
            FOREIGN KEY(account_id,verification_id) REFERENCES %1$I.email_verifications(account_id,id) ON DELETE CASCADE;
        ALTER TABLE %1$I.sealed_event_delivery_attempts
          ALTER COLUMN account_id SET NOT NULL,
          ADD CONSTRAINT sealed_event_attempt_account_parent
            FOREIGN KEY(account_id,delivery_id) REFERENCES %1$I.sealed_event_deliveries(account_id,id);
        ALTER TABLE %1$I.webhook_attempts
          ALTER COLUMN account_id SET NOT NULL,
          ADD CONSTRAINT webhook_attempt_account_parent
            FOREIGN KEY(account_id,delivery_id) REFERENCES %1$I.webhook_deliveries(account_id,id);
    $ddl$, installation);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.parent_account_mirror_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
        DECLARE parent_account uuid;
        BEGIN
            IF TG_OP NOT IN ('INSERT','UPDATE') THEN
                RAISE EXCEPTION 'unexpected mirror operation' USING ERRCODE='23514';
            END IF;
            IF TG_OP='UPDATE' AND NEW.account_id IS DISTINCT FROM OLD.account_id THEN
                RAISE EXCEPTION 'child account identity is immutable' USING ERRCODE='23514';
            END IF;
            IF TG_RELID=pg_catalog.to_regclass(%2$L) THEN
                IF TG_OP='UPDATE' AND NEW.reset_id IS DISTINCT FROM OLD.reset_id THEN
                    RAISE EXCEPTION 'child parent identity is immutable' USING ERRCODE='23514';
                END IF;
                SELECT account_id INTO parent_account FROM %1$I.password_resets WHERE id=NEW.reset_id;
            ELSIF TG_RELID=pg_catalog.to_regclass(%3$L) THEN
                IF TG_OP='UPDATE' AND NEW.verification_id IS DISTINCT FROM OLD.verification_id THEN
                    RAISE EXCEPTION 'child parent identity is immutable' USING ERRCODE='23514';
                END IF;
                SELECT account_id INTO parent_account FROM %1$I.email_verifications WHERE id=NEW.verification_id;
            ELSIF TG_RELID=pg_catalog.to_regclass(%4$L) THEN
                IF TG_OP='UPDATE' AND NEW.delivery_id IS DISTINCT FROM OLD.delivery_id THEN
                    RAISE EXCEPTION 'child parent identity is immutable' USING ERRCODE='23514';
                END IF;
                SELECT account_id INTO parent_account FROM %1$I.sealed_event_deliveries WHERE id=NEW.delivery_id;
            ELSIF TG_RELID=pg_catalog.to_regclass(%5$L) THEN
                IF TG_OP='UPDATE' AND NEW.delivery_id IS DISTINCT FROM OLD.delivery_id THEN
                    RAISE EXCEPTION 'child parent identity is immutable' USING ERRCODE='23514';
                END IF;
                SELECT account_id INTO parent_account FROM %1$I.webhook_deliveries WHERE id=NEW.delivery_id;
            ELSE
                RAISE EXCEPTION 'unexpected mirror relation' USING ERRCODE='23514';
            END IF;
            IF parent_account IS NULL THEN
                RAISE EXCEPTION 'missing account-owned parent' USING ERRCODE='23514';
            END IF;
            IF TG_OP='INSERT' AND NEW.account_id IS NULL THEN
                -- Existing INSERT callers omit this new column. No default or
                -- user-controlled setting chooses the resulting identity.
                NEW.account_id := parent_account;
            END IF;
            IF NEW.account_id IS DISTINCT FROM parent_account THEN
                RAISE EXCEPTION 'child account differs from parent' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $function$
    $ddl$, installation,
      pg_catalog.format('%I.password_reset_mail_outbox',installation),
      pg_catalog.format('%I.verification_mail_outbox',installation),
      pg_catalog.format('%I.sealed_event_delivery_attempts',installation),
      pg_catalog.format('%I.webhook_attempts',installation));

    EXECUTE pg_catalog.format($ddl$
        CREATE TRIGGER parent_account_mirror_before_change BEFORE INSERT OR UPDATE
          ON %1$I.password_reset_mail_outbox FOR EACH ROW EXECUTE FUNCTION %1$I.parent_account_mirror_guard();
        CREATE TRIGGER parent_account_mirror_before_change BEFORE INSERT OR UPDATE
          ON %1$I.verification_mail_outbox FOR EACH ROW EXECUTE FUNCTION %1$I.parent_account_mirror_guard();
        CREATE TRIGGER parent_account_mirror_before_change BEFORE INSERT OR UPDATE
          ON %1$I.sealed_event_delivery_attempts FOR EACH ROW EXECUTE FUNCTION %1$I.parent_account_mirror_guard();
        CREATE TRIGGER parent_account_mirror_before_change BEFORE INSERT OR UPDATE
          ON %1$I.webhook_attempts FOR EACH ROW EXECUTE FUNCTION %1$I.parent_account_mirror_guard();
        REVOKE ALL ON FUNCTION %1$I.parent_account_mirror_guard() FROM PUBLIC;
    $ddl$, installation);
    IF installation='public' AND EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime'
    ) THEN
        REVOKE ALL ON FUNCTION public.parent_account_mirror_guard() FROM zrotext_runtime;
    END IF;
END;
$migration$;
