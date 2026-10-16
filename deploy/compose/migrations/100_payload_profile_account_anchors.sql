-- SPDX-License-Identifier: AGPL-3.0-only
-- Identity/lifecycle foundation only. No profile03 selection or epoch-advance API.
-- A retained UUID is pseudonymous identity, not anonymous/nonidentifying data.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $migration$
DECLARE
    installation name;
    accounts_name text;
    anchors_name text;
BEGIN
    SELECT n.nspname INTO STRICT installation
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r';
    IF installation LIKE 'pg_%' OR installation='information_schema' THEN
        RAISE EXCEPTION 'application installation namespace required' USING ERRCODE='23514';
    END IF;
    accounts_name := pg_catalog.format('%I.accounts', installation);
    anchors_name := pg_catalog.format('%I.payload_profile_account_anchors', installation);

    -- Serialize backfill with every account INSERT/DELETE before installing the
    -- lifecycle triggers; do not miss an account created between those steps.
    EXECUTE pg_catalog.format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE', accounts_name);
    EXECUTE pg_catalog.format($ddl$
        CREATE TABLE %1$I.payload_profile_account_anchors (
            account_id uuid PRIMARY KEY,
            state text NOT NULL DEFAULT 'live' CHECK (state IN ('live','deleted')),
            selection_epoch bigint NOT NULL DEFAULT 0 CHECK (selection_epoch>=0),
            CHECK (state='live' OR selection_epoch>0)
        )
    $ddl$, installation);
    -- Deliberately no cascading account FK: the minimal tombstone survives
    -- authorized account erasure. No message/user/device/root/key data is held.
    EXECUTE pg_catalog.format(
        'INSERT INTO %s(account_id) SELECT id FROM %s', anchors_name, accounts_name);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.payload_profile_account_fence_key(account uuid)
        RETURNS bigint LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
            SELECT ('x'||substr(encode(sha256(
                convert_to('ZTSE/line/payload-profile/account-fence/v1','UTF8')
                ||decode('00','hex')||int4send(16)||uuid_send(account)
            ),'hex'),1,16))::bit(64)::bigint
        $function$
    $ddl$, installation);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.payload_profile_anchor_row_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
        BEGIN
            IF TG_RELID IS DISTINCT FROM pg_catalog.to_regclass(%3$L) THEN
                RAISE EXCEPTION 'unexpected anchor relation' USING ERRCODE='23514';
            END IF;
            IF TG_OP='DELETE' THEN
                RAISE EXCEPTION 'account anchor identity is retained' USING ERRCODE='23514';
            ELSIF TG_OP='INSERT' THEN
                IF NEW.state<>'live' OR NEW.selection_epoch<>0 OR NOT EXISTS (
                    SELECT FROM %1$I.accounts WHERE id=NEW.account_id
                ) THEN
                    RAISE EXCEPTION 'invalid new account anchor' USING ERRCODE='23514';
                END IF;
            ELSIF TG_OP='UPDATE' THEN
                IF NEW.account_id<>OLD.account_id THEN
                    RAISE EXCEPTION 'account anchor identity is immutable' USING ERRCODE='23514';
                END IF;
                IF NEW.state=OLD.state AND NEW.selection_epoch=OLD.selection_epoch THEN
                    RETURN NEW;
                END IF;
                -- The only epoch change in this foundation is account deletion.
                -- A future accepted-selection transaction needs its own reviewed
                -- ledger/epoch coupling; no general advance function exists here.
                IF OLD.state<>'live' OR NEW.state<>'deleted'
                    OR NEW.selection_epoch<>OLD.selection_epoch+1 OR EXISTS (
                        SELECT FROM %1$I.accounts WHERE id=OLD.account_id
                    ) THEN
                    RAISE EXCEPTION 'unsupported account anchor transition' USING ERRCODE='23514';
                END IF;
            ELSE
                RAISE EXCEPTION 'unexpected anchor operation' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $function$
    $ddl$, installation, accounts_name, anchors_name);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.payload_profile_anchor_account_created() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
        BEGIN
            IF TG_OP<>'INSERT' OR TG_RELID IS DISTINCT FROM pg_catalog.to_regclass(%2$L) THEN
                RAISE EXCEPTION 'unexpected account creation context' USING ERRCODE='23514';
            END IF;
            -- Never upsert a retained UUID or overwrite its original epoch/state.
            INSERT INTO %1$I.payload_profile_account_anchors(account_id) VALUES(NEW.id);
            RETURN NEW;
        END;
        $function$
    $ddl$, installation, accounts_name);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.payload_profile_anchor_account_changing() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
        DECLARE current_state text;
        BEGIN
            IF TG_RELID IS DISTINCT FROM pg_catalog.to_regclass(%2$L) THEN
                RAISE EXCEPTION 'unexpected account relation' USING ERRCODE='23514';
            END IF;
            IF TG_OP='UPDATE' THEN
                IF NEW.id<>OLD.id THEN
                    RAISE EXCEPTION 'account identity is immutable' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            ELSIF TG_OP<>'DELETE' THEN
                RAISE EXCEPTION 'unexpected account mutation context' USING ERRCODE='23514';
            END IF;
            IF NOT pg_catalog.pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(OLD.id)) THEN
                RAISE EXCEPTION 'account profile fence busy' USING ERRCODE='55P03';
            END IF;
            SELECT state INTO current_state FROM %1$I.payload_profile_account_anchors
              WHERE account_id=OLD.id FOR UPDATE NOWAIT;
            IF NOT FOUND OR current_state<>'live' THEN
                RAISE EXCEPTION 'missing live account anchor' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $function$
    $ddl$, installation, accounts_name);

    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.payload_profile_anchor_account_deleted() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
        DECLARE changed bigint;
        BEGIN
            IF TG_OP<>'DELETE' OR TG_RELID IS DISTINCT FROM pg_catalog.to_regclass(%2$L) THEN
                RAISE EXCEPTION 'unexpected account deletion context' USING ERRCODE='23514';
            END IF;
            UPDATE %1$I.payload_profile_account_anchors SET state='deleted',selection_epoch=selection_epoch+1
              WHERE account_id=OLD.id AND state='live';
            GET DIAGNOSTICS changed=ROW_COUNT;
            IF changed<>1 THEN
                RAISE EXCEPTION 'account anchor deletion did not commit exactly once' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $function$
    $ddl$, installation, accounts_name);

    EXECUTE pg_catalog.format($ddl$
        CREATE TRIGGER payload_profile_anchor_before_change
          BEFORE INSERT OR UPDATE OR DELETE ON %1$I.payload_profile_account_anchors
          FOR EACH ROW EXECUTE FUNCTION %1$I.payload_profile_anchor_row_guard();
        CREATE TRIGGER payload_profile_anchor_after_account_insert
          AFTER INSERT ON %1$I.accounts
          FOR EACH ROW EXECUTE FUNCTION %1$I.payload_profile_anchor_account_created();
        CREATE TRIGGER payload_profile_anchor_before_account_change
          BEFORE UPDATE OR DELETE ON %1$I.accounts
          FOR EACH ROW EXECUTE FUNCTION %1$I.payload_profile_anchor_account_changing();
        CREATE TRIGGER payload_profile_anchor_after_account_delete
          AFTER DELETE ON %1$I.accounts
          FOR EACH ROW EXECUTE FUNCTION %1$I.payload_profile_anchor_account_deleted();
        REVOKE ALL ON TABLE %1$I.payload_profile_account_anchors FROM PUBLIC;
        REVOKE ALL ON FUNCTION %1$I.payload_profile_account_fence_key(uuid) FROM PUBLIC;
        REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_row_guard() FROM PUBLIC;
        REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_created() FROM PUBLIC;
        REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_changing() FROM PUBLIC;
        REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_deleted() FROM PUBLIC;
    $ddl$, installation);

    -- The stock provisioner is public-only. A relocated disposable test schema
    -- must not give a shared role unexpected grants in a foreign namespace.
    IF installation='public' AND EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime'
    ) THEN
        EXECUTE pg_catalog.format($acl$
            REVOKE ALL ON TABLE %1$I.payload_profile_account_anchors FROM zrotext_runtime;
            REVOKE ALL (account_id,state,selection_epoch) ON TABLE %1$I.payload_profile_account_anchors FROM PUBLIC,zrotext_runtime;
            GRANT SELECT ON TABLE %1$I.payload_profile_account_anchors TO zrotext_runtime;
            GRANT UPDATE(account_id) ON TABLE %1$I.payload_profile_account_anchors TO zrotext_runtime;
            GRANT EXECUTE ON FUNCTION %1$I.payload_profile_account_fence_key(uuid) TO zrotext_runtime;
            REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_row_guard() FROM zrotext_runtime;
            REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_created() FROM zrotext_runtime;
            REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_changing() FROM zrotext_runtime;
            REVOKE ALL ON FUNCTION %1$I.payload_profile_anchor_account_deleted() FROM zrotext_runtime;
        $acl$, installation);
    END IF;
END;
$migration$;
