-- SPDX-License-Identifier: AGPL-3.0-only
-- Membership/user snapshot participation only, not profile selection permission.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $migration$
DECLARE installation name;
BEGIN
    SELECT n.nspname INTO STRICT installation
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r';
    IF installation LIKE 'pg_%' OR installation='information_schema' THEN
        RAISE EXCEPTION 'application installation namespace required' USING ERRCODE='23514';
    END IF;
    -- Install both sides atomically with respect to unmodified writers.
    EXECUTE pg_catalog.format('LOCK TABLE %I.users,%I.memberships IN SHARE ROW EXCLUSIVE MODE',installation,installation);
    EXECUTE pg_catalog.format($ddl$
        CREATE FUNCTION %1$I.user_membership_freshness_guard() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE wanted_user uuid;
                wanted_account uuid;
                old_account uuid;
                new_account uuid;
                account_set uuid[];
                reduction boolean;
                current_state text;
                current_epoch bigint;
        BEGIN
            IF TG_TABLE_SCHEMA<>%2$L OR TG_RELID NOT IN (%3$L::regclass,%4$L::regclass)
              OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
              OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
                RAISE EXCEPTION 'unexpected user membership freshness context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID=%3$L::regclass THEN
                IF TG_OP='UPDATE' AND NEW.id IS DISTINCT FROM OLD.id THEN
                    RAISE EXCEPTION 'current user identity is immutable' USING ERRCODE='23514';
                END IF;
                IF TG_OP='DELETE' THEN wanted_user:=OLD.id; reduction:=true;
                ELSE
                    wanted_user:=NEW.id;
                    -- A real no-op tuple touch changes no permission or payload.
                    reduction:=TG_OP='UPDATE' AND to_jsonb(NEW)=to_jsonb(OLD);
                END IF;
                IF wanted_user IS NULL THEN
                    RAISE EXCEPTION 'nonnull user identity required' USING ERRCODE='23514';
                END IF;
                SELECT pg_catalog.array_agg(account_id ORDER BY account_id) INTO account_set
                  FROM %1$I.memberships WHERE user_id=wanted_user;
                -- Empty membership is genuine bootstrap/unassociated state.
                -- Every concurrent membership writer below changes this exact
                -- user tuple, forcing an old RR/SSI mutation to refuse40001.
            ELSE
                -- Migration 048 already forbids seat reassignment. Preserve the
                -- identity locally too: every allowed operation touches exactly
                -- the same current user, never only one side of a move.
                IF TG_OP='UPDATE' AND (NEW.account_id,NEW.user_id)
                  IS DISTINCT FROM (OLD.account_id,OLD.user_id) THEN
                    RAISE EXCEPTION 'membership identity is immutable' USING ERRCODE='23514';
                END IF;
                IF TG_OP<>'INSERT' AND (OLD.account_id IS NULL OR OLD.user_id IS NULL) THEN
                    RAISE EXCEPTION 'nonnull old membership identity required' USING ERRCODE='23514';
                END IF;
                IF TG_OP<>'INSERT' THEN old_account:=OLD.account_id; END IF;
                IF TG_OP<>'DELETE' THEN
                    new_account:=NEW.account_id;
                    IF NEW.account_id IS NULL OR NEW.user_id IS NULL THEN
                        RAISE EXCEPTION 'nonnull membership identity required' USING ERRCODE='23514';
                    END IF;
                END IF;
                SELECT pg_catalog.array_agg(candidate ORDER BY candidate) INTO account_set FROM (
                    SELECT DISTINCT candidate FROM pg_catalog.unnest(ARRAY[old_account,new_account]) candidate
                      WHERE candidate IS NOT NULL
                ) accounts;
                reduction:=TG_OP='DELETE';
            END IF;
            FOREACH wanted_account IN ARRAY COALESCE(account_set,ARRAY[]::uuid[]) LOOP
                IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(%1$I.payload_profile_account_fence_key(wanted_account)) THEN
                    RAISE EXCEPTION 'user membership account fence busy' USING ERRCODE='55P03';
                END IF;
                SELECT state,selection_epoch INTO current_state,current_epoch
                  FROM %1$I.payload_profile_account_anchors WHERE account_id=wanted_account FOR SHARE NOWAIT;
                IF NOT FOUND OR current_state IS NULL OR current_epoch IS NULL OR current_epoch<0
                  OR current_state NOT IN ('live','deleted') OR (current_state='deleted' AND current_epoch=0)
                  OR (current_state<>'live' AND NOT reduction) THEN
                    RAISE EXCEPTION 'user membership anchor unavailable' USING ERRCODE='23514';
                END IF;
                -- Reading/locking the actual tuple is essential: a changed
                -- epoch must cause an old RR/SSI snapshot to refuse, not default02.
            END LOOP;
            IF TG_RELID=%4$L::regclass THEN
                IF TG_OP='DELETE' THEN wanted_user:=OLD.user_id; ELSE wanted_user:=NEW.user_id; END IF;
                PERFORM id FROM %1$I.users WHERE id=wanted_user FOR UPDATE NOWAIT;
                IF FOUND THEN
                    -- Locking alone leaves old RR snapshots usable. The real
                    -- version change serializes them even for membership DELETE.
                    -- Its nested users guard reads/locks only; no depth bypass.
                    UPDATE %1$I.users SET id=id WHERE id=wanted_user;
                ELSIF TG_OP<>'DELETE' THEN
                    RAISE EXCEPTION 'membership user unavailable' USING ERRCODE='23514';
                END IF;
                -- A parent-user DELETE cascade may already have removed users.
                -- Its OLD account was still fenced above; absence grants nothing.
            END IF;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END;
        $function$;
        CREATE TRIGGER user_membership_freshness_before_user_change
          BEFORE INSERT OR UPDATE OR DELETE ON %1$I.users
          FOR EACH ROW EXECUTE FUNCTION %1$I.user_membership_freshness_guard();
        CREATE TRIGGER user_membership_freshness_before_membership_change
          BEFORE INSERT OR UPDATE OR DELETE ON %1$I.memberships
          FOR EACH ROW EXECUTE FUNCTION %1$I.user_membership_freshness_guard();
        REVOKE ALL ON FUNCTION %1$I.user_membership_freshness_guard() FROM PUBLIC;
    $ddl$,installation,installation,
        pg_catalog.format('%I.users',installation),pg_catalog.format('%I.memberships',installation));
    IF installation='public' AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime') THEN
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.user_membership_freshness_guard() FROM zrotext_runtime',installation);
    END IF;
END;
$migration$;
