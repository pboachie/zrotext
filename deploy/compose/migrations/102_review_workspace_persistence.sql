-- SPDX-License-Identifier: AGPL-3.0-only
-- Unmounted, owner/test-only persistence. No authentication/session authority.
-- Bounds below are component resource defaults, not a hosted retention policy.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $migration$
DECLARE installation name;
BEGIN
    SELECT n.nspname INTO STRICT installation
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r';
    IF installation LIKE 'pg_%' OR installation='information_schema' THEN
        RAISE EXCEPTION 'application installation namespace required' USING ERRCODE='23514';
    END IF;
    EXECUTE pg_catalog.format($ddl$
        CREATE TABLE %1$I.review_realm_installation (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            realm_id uuid NOT NULL UNIQUE CHECK (realm_id<>'00000000-0000-0000-0000-000000000000'),
            database_id uuid NOT NULL CHECK (database_id<>'00000000-0000-0000-0000-000000000000'),
            origin text NOT NULL CHECK (origin ~ '^https://[a-z0-9][a-z0-9.-]*(:[1-9][0-9]{0,4})?$' AND length(origin)<=253),
            deployment_digest bytea NOT NULL CHECK (octet_length(deployment_digest)=32 AND deployment_digest<>decode(repeat('00',32),'hex')),
            service_digest bytea NOT NULL CHECK (octet_length(service_digest)=32 AND service_digest<>decode(repeat('00',32),'hex')),
            auth_key_digest bytea NOT NULL CHECK (octet_length(auth_key_digest)=32 AND auth_key_digest<>decode(repeat('00',32),'hex')),
            enrollment_key_digest bytea NOT NULL CHECK (octet_length(enrollment_key_digest)=32 AND enrollment_key_digest<>decode(repeat('00',32),'hex')),
            reauthentication_key_digest bytea NOT NULL CHECK (octet_length(reauthentication_key_digest)=32 AND reauthentication_key_digest<>decode(repeat('00',32),'hex')),
            grant_key_digest bytea NOT NULL CHECK (octet_length(grant_key_digest)=32 AND grant_key_digest<>decode(repeat('00',32),'hex')),
            mfa_key_digest bytea NOT NULL CHECK (octet_length(mfa_key_digest)=32 AND mfa_key_digest<>decode(repeat('00',32),'hex')),
            UNIQUE(realm_id,origin),
            CHECK (auth_key_digest<>enrollment_key_digest AND auth_key_digest<>reauthentication_key_digest
                AND auth_key_digest<>grant_key_digest AND auth_key_digest<>mfa_key_digest
                AND enrollment_key_digest<>reauthentication_key_digest AND enrollment_key_digest<>grant_key_digest
                AND enrollment_key_digest<>mfa_key_digest AND reauthentication_key_digest<>grant_key_digest
                AND reauthentication_key_digest<>mfa_key_digest AND grant_key_digest<>mfa_key_digest)
        );
        -- Deliberately empty. Migration cannot declare a supplied DB isolated.
        CREATE TABLE %1$I.review_brokers (
            id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'),
            realm_id uuid NOT NULL REFERENCES %1$I.review_realm_installation(realm_id),
            credential_revision bigint NOT NULL CHECK (credential_revision>0),
            password_verifier text NOT NULL CHECK (length(password_verifier) BETWEEN 1 AND 1024),
            disabled_ms bigint CHECK (disabled_ms>0),
            UNIQUE(id,realm_id)
        );
        -- Separate identity space: no users/memberships or ordinary sessions FK.
        CREATE INDEX review_broker_realm ON %1$I.review_brokers(realm_id);
        CREATE TABLE %1$I.review_broker_sessions (
            id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'),
            realm_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            authentication_event_id uuid NOT NULL UNIQUE CHECK (authentication_event_id<>'00000000-0000-0000-0000-000000000000'),
            credential_revision bigint NOT NULL CHECK (credential_revision>0),
            slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 128),
            token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest)=32 AND token_digest<>decode(repeat('00',32),'hex')),
            browser_binding bytea NOT NULL CHECK (octet_length(browser_binding)=32 AND browser_binding<>decode(repeat('00',32),'hex')),
            origin text NOT NULL,
            issued_ms bigint NOT NULL CHECK (issued_ms>0),
            expires_ms bigint NOT NULL,
            last_used_ms bigint NOT NULL,
            revoked_ms bigint,
            FOREIGN KEY(broker_id,realm_id) REFERENCES %1$I.review_brokers(id,realm_id),
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            UNIQUE(id,broker_id,realm_id,authentication_event_id,credential_revision),
            UNIQUE(broker_id,slot),
            CHECK (expires_ms>issued_ms AND expires_ms-issued_ms<=1209600000),
            CHECK (last_used_ms>=issued_ms AND last_used_ms<expires_ms),
            CHECK (revoked_ms IS NULL OR revoked_ms>=issued_ms)
        );
        CREATE TABLE %1$I.review_bootstrap_attempts (
            id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'),
            realm_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            broker_session_id uuid NOT NULL,
            authentication_event_id uuid NOT NULL,
            credential_revision bigint NOT NULL,
            slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 128),
            reserved_account_id uuid NOT NULL UNIQUE CHECK (reserved_account_id<>'00000000-0000-0000-0000-000000000000'),
            reserved_user_id uuid NOT NULL UNIQUE CHECK (reserved_user_id<>'00000000-0000-0000-0000-000000000000'),
            continuation_digest bytea NOT NULL UNIQUE CHECK (octet_length(continuation_digest)=32 AND continuation_digest<>decode(repeat('00',32),'hex')),
            request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32 AND request_digest<>decode(repeat('00',32),'hex')),
            origin text NOT NULL,
            issued_ms bigint NOT NULL CHECK (issued_ms>0),
            expires_ms bigint NOT NULL,
            reconcile_until_ms bigint NOT NULL,
            state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','provisioned')),
            bound_account_id uuid REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            bound_user_id uuid REFERENCES %1$I.users(id) ON DELETE CASCADE,
            provisioned_ms bigint,
            FOREIGN KEY(broker_session_id,broker_id,realm_id,authentication_event_id,credential_revision)
              REFERENCES %1$I.review_broker_sessions(id,broker_id,realm_id,authentication_event_id,credential_revision),
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            FOREIGN KEY(bound_account_id,bound_user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            UNIQUE(broker_id,slot),
            CHECK (reserved_account_id<>reserved_user_id),
            CHECK (expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
            CHECK (reconcile_until_ms>expires_ms AND reconcile_until_ms-issued_ms<=604800000),
            CHECK ((state='reserved' AND bound_account_id IS NULL AND bound_user_id IS NULL AND provisioned_ms IS NULL)
                OR (state='provisioned' AND bound_account_id IS NOT NULL AND bound_user_id IS NOT NULL
                    AND bound_account_id=reserved_account_id AND bound_user_id=reserved_user_id
                    AND provisioned_ms IS NOT NULL AND provisioned_ms>=issued_ms AND provisioned_ms<expires_ms))
        );
        CREATE INDEX review_bootstrap_bound_account ON %1$I.review_bootstrap_attempts(bound_account_id,bound_user_id);
        CREATE INDEX review_bootstrap_bound_user ON %1$I.review_bootstrap_attempts(bound_user_id);
        CREATE INDEX review_bootstrap_session ON %1$I.review_bootstrap_attempts(broker_session_id);
        CREATE INDEX review_bootstrap_cleanup ON %1$I.review_bootstrap_attempts(reconcile_until_ms,id);
        CREATE TABLE %1$I.review_workspaces (
            account_id uuid PRIMARY KEY REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            user_id uuid NOT NULL UNIQUE REFERENCES %1$I.users(id) ON DELETE CASCADE,
            realm_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 128),
            creating_attempt_id uuid NOT NULL UNIQUE CHECK (creating_attempt_id<>'00000000-0000-0000-0000-000000000000'),
            created_ms bigint NOT NULL CHECK (created_ms>0),
            FOREIGN KEY(account_id,user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            FOREIGN KEY(broker_id,realm_id) REFERENCES %1$I.review_brokers(id,realm_id),
            UNIQUE(broker_id,slot)
        );
        -- No workspace->attempt/session FK: finite receipt cleanup is not erasure.
        CREATE FUNCTION %1$I.review_workspace_row_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE mutable_columns text[];
        BEGIN
            IF TG_TABLE_SCHEMA<>%2$L OR TG_RELID NOT IN (
                %5$L::regclass,%6$L::regclass,%7$L::regclass,%8$L::regclass,%9$L::regclass
            ) OR TG_OP<>'UPDATE' THEN
                RAISE EXCEPTION 'unexpected review identity update context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID=%6$L::regclass THEN
                mutable_columns:=ARRAY['credential_revision','password_verifier','disabled_ms'];
                IF NEW.credential_revision<OLD.credential_revision
                  OR (NEW.password_verifier<>OLD.password_verifier AND NEW.credential_revision<=OLD.credential_revision)
                  OR (OLD.disabled_ms IS NOT NULL AND NEW.disabled_ms IS DISTINCT FROM OLD.disabled_ms) THEN
                    RAISE EXCEPTION 'invalid broker revision transition' USING ERRCODE='23514';
                END IF;
            ELSIF TG_RELID=%7$L::regclass THEN
                mutable_columns:=ARRAY['last_used_ms','revoked_ms'];
                IF NEW.last_used_ms<OLD.last_used_ms
                  OR (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
                    RAISE EXCEPTION 'invalid broker session transition' USING ERRCODE='23514';
                END IF;
            ELSIF TG_RELID=%8$L::regclass THEN
                mutable_columns:=ARRAY['state','bound_account_id','bound_user_id','provisioned_ms'];
                IF OLD.state<>'reserved' OR NEW.state<>'provisioned' THEN
                    RAISE EXCEPTION 'bootstrap result is immutable' USING ERRCODE='23514';
                END IF;
            ELSE mutable_columns:=ARRAY[]::text[];
            END IF;
            IF (to_jsonb(NEW)-mutable_columns) IS DISTINCT FROM (to_jsonb(OLD)-mutable_columns) THEN
                RAISE EXCEPTION 'review identity is immutable' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_workspace_broker_session_create(
            wanted_broker uuid,wanted_session uuid,wanted_event uuid,wanted_revision bigint,
            wanted_token bytea,wanted_browser bytea,wanted_origin text
        ) RETURNS uuid LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_brokers;
                available_slot smallint;
                now_ms bigint;
        BEGIN
            IF wanted_revision IS NULL OR wanted_origin IS NULL THEN
                RAISE EXCEPTION 'nonnull review context required' USING ERRCODE='23514';
            END IF;
            SELECT * INTO STRICT captured FROM %1$I.review_brokers WHERE id=wanted_broker FOR UPDATE NOWAIT;
            IF captured.disabled_ms IS NOT NULL OR captured.credential_revision<>wanted_revision THEN
                RAISE EXCEPTION 'current review broker unavailable' USING ERRCODE='23514';
            END IF;
            SELECT s::smallint INTO available_slot FROM pg_catalog.generate_series(1,128) s
              WHERE NOT EXISTS (SELECT FROM %1$I.review_broker_sessions b WHERE b.broker_id=captured.id AND b.slot=s)
              ORDER BY s LIMIT 1;
            IF available_slot IS NULL THEN
                RAISE EXCEPTION 'review broker session capacity reached' USING ERRCODE='54000';
            END IF;
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            INSERT INTO %1$I.review_broker_sessions(id,realm_id,broker_id,authentication_event_id,credential_revision,
                slot,token_digest,browser_binding,origin,issued_ms,expires_ms,last_used_ms)
              VALUES(wanted_session,captured.realm_id,captured.id,wanted_event,wanted_revision,available_slot,
                wanted_token,wanted_browser,wanted_origin,now_ms,now_ms+1209600000,now_ms);
            -- No password check or verified authentication is implied by this
            -- owner/test-only fixture constructor. No runtime EXECUTE exists.
            PERFORM %1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,true);
            RETURN wanted_session;
        END;
        $function$;
        CREATE TRIGGER review_workspace_identity_before_update BEFORE UPDATE ON %1$I.review_realm_installation
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_row_guard();
        CREATE TRIGGER review_workspace_identity_before_update BEFORE UPDATE ON %1$I.review_brokers
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_row_guard();
        CREATE TRIGGER review_workspace_identity_before_update BEFORE UPDATE ON %1$I.review_broker_sessions
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_row_guard();
        CREATE TRIGGER review_workspace_identity_before_update BEFORE UPDATE ON %1$I.review_bootstrap_attempts
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_row_guard();
        CREATE TRIGGER review_workspace_identity_before_update BEFORE UPDATE ON %1$I.review_workspaces
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_row_guard();

        -- Owner-only structural/current-row check, not a password verifier.
        -- Current broker is locked before the exact session in every consumer.
        -- Allocation takes UPDATE upfront; permission-only reads take SHARE.
        CREATE FUNCTION %1$I.review_workspace_current_session(
            wanted_session uuid,wanted_event uuid,wanted_revision bigint,wanted_origin text,
            allocation boolean
        ) RETURNS %1$I.review_broker_sessions
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_broker_sessions;
                current_broker %1$I.review_brokers;
                now_ms bigint;
        BEGIN
            IF wanted_session IS NULL OR wanted_event IS NULL OR wanted_revision IS NULL
              OR wanted_origin IS NULL OR allocation IS NULL THEN
                RAISE EXCEPTION 'nonnull review context required' USING ERRCODE='23514';
            END IF;
            SELECT * INTO STRICT captured FROM %1$I.review_broker_sessions WHERE id=wanted_session;
            IF allocation THEN
                SELECT * INTO STRICT current_broker FROM %1$I.review_brokers
                  WHERE id=captured.broker_id AND realm_id=captured.realm_id FOR UPDATE NOWAIT;
            ELSE
                SELECT * INTO STRICT current_broker FROM %1$I.review_brokers
                  WHERE id=captured.broker_id AND realm_id=captured.realm_id FOR SHARE NOWAIT;
            END IF;
            IF allocation THEN
                SELECT * INTO STRICT captured FROM %1$I.review_broker_sessions WHERE id=wanted_session FOR UPDATE NOWAIT;
            ELSE
                SELECT * INTO STRICT captured FROM %1$I.review_broker_sessions WHERE id=wanted_session FOR SHARE NOWAIT;
            END IF;
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF current_broker.disabled_ms IS NOT NULL OR current_broker.credential_revision<>wanted_revision
              OR captured.broker_id<>current_broker.id OR captured.realm_id<>current_broker.realm_id
              OR captured.authentication_event_id<>wanted_event OR captured.credential_revision<>wanted_revision
              OR captured.origin<>wanted_origin OR captured.revoked_ms IS NOT NULL
              OR now_ms<captured.issued_ms OR now_ms<captured.last_used_ms OR now_ms>=captured.expires_ms
              OR now_ms-captured.last_used_ms>=259200000 THEN
                RAISE EXCEPTION 'current review broker session unavailable' USING ERRCODE='23514';
            END IF;
            RETURN captured;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_workspace_reserve(
            wanted_attempt uuid,wanted_account uuid,wanted_user uuid,
            wanted_session uuid,wanted_event uuid,wanted_revision bigint,
            wanted_continuation bytea,wanted_request bytea,wanted_origin text
        ) RETURNS uuid LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_broker_sessions;
                available_slot smallint;
                now_ms bigint;
        BEGIN
            IF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
                RAISE EXCEPTION 'new review workspace requires read committed' USING ERRCODE='25001';
            END IF;
            IF NOT pg_catalog.pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(wanted_account)) THEN
                RAISE EXCEPTION 'review candidate account fence busy' USING ERRCODE='55P03';
            END IF;
            captured:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,true);
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF EXISTS (SELECT FROM %1$I.review_bootstrap_attempts WHERE broker_session_id=wanted_session
                AND state='reserved' AND expires_ms>now_ms) THEN
                RAISE EXCEPTION 'review session already has a pending reservation' USING ERRCODE='23514';
            END IF;
            SELECT s::smallint INTO available_slot FROM pg_catalog.generate_series(1,128) s
              WHERE NOT EXISTS (SELECT FROM %1$I.review_bootstrap_attempts a WHERE a.broker_id=captured.broker_id AND a.slot=s)
              ORDER BY s LIMIT 1;
            IF available_slot IS NULL THEN
                RAISE EXCEPTION 'review attempt capacity reached' USING ERRCODE='54000';
            END IF;
            INSERT INTO %1$I.review_bootstrap_attempts(id,realm_id,broker_id,broker_session_id,authentication_event_id,
                credential_revision,slot,reserved_account_id,reserved_user_id,continuation_digest,request_digest,
                origin,issued_ms,expires_ms,reconcile_until_ms)
              VALUES(wanted_attempt,captured.realm_id,captured.broker_id,captured.id,wanted_event,wanted_revision,
                available_slot,wanted_account,wanted_user,wanted_continuation,wanted_request,wanted_origin,
                now_ms,now_ms+300000,now_ms+604800000);
            -- Reservations record private prospective IDs, not a namespace claim.
            -- RC absence is point-in-time only. PKs/100's retained anchor are
            -- the final atomic occupied/collision/reuse defense during INSERT.
            captured:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,true);
            IF (EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint<now_ms
              OR (EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint>=now_ms+300000
              OR EXISTS (SELECT FROM %1$I.accounts WHERE id=wanted_account)
              OR EXISTS (SELECT FROM %1$I.payload_profile_account_anchors WHERE account_id=wanted_account)
              OR EXISTS (SELECT FROM %1$I.users WHERE id=wanted_user) THEN
                RAISE EXCEPTION 'review identity is not fresh' USING ERRCODE='23514';
            END IF;
            RETURN wanted_attempt;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_workspace_provision(
            wanted_attempt uuid,wanted_session uuid,wanted_event uuid,wanted_revision bigint,
            wanted_continuation bytea,wanted_request bytea,wanted_origin text
        ) RETURNS TABLE(account_id uuid,user_id uuid)
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_bootstrap_attempts;
                current_session %1$I.review_broker_sessions;
                initial_capture %1$I.review_bootstrap_attempts;
                locked_capture %1$I.review_bootstrap_attempts;
                anchor_state text;
                anchor_epoch bigint;
                available_slot smallint;
                now_ms bigint;
                changed bigint;
                checked_floor_ms bigint;
        BEGIN
            checked_floor_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            SELECT * INTO STRICT initial_capture FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt;
            captured:=initial_capture;
            IF NOT pg_catalog.pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(captured.reserved_account_id)) THEN
                RAISE EXCEPTION 'review candidate account fence busy' USING ERRCODE='55P03';
            END IF;
            -- Re-read AFTER the candidate fence. A different factory may have
            -- committed its result between initial capture and our lock.
            SELECT * INTO STRICT captured FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt;
            IF (to_jsonb(captured)-ARRAY['state','bound_account_id','bound_user_id','provisioned_ms'])
              IS DISTINCT FROM (to_jsonb(initial_capture)-ARRAY['state','bound_account_id','bound_user_id','provisioned_ms']) THEN
                RAISE EXCEPTION 'review continuation identity changed' USING ERRCODE='40001';
            END IF;
            IF captured.state='provisioned' THEN
                SELECT state,selection_epoch INTO anchor_state,anchor_epoch
                  FROM %1$I.payload_profile_account_anchors anchor WHERE anchor.account_id=captured.reserved_account_id FOR SHARE NOWAIT;
                IF NOT FOUND OR anchor_state<>'live' OR anchor_epoch<>0 THEN
                    RAISE EXCEPTION 'review result anchor unavailable' USING ERRCODE='23514';
                END IF;
            ELSIF pg_catalog.current_setting('transaction_isolation')<>'read committed' THEN
                RAISE EXCEPTION 'new review workspace requires read committed' USING ERRCODE='25001';
            END IF;
            current_session:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,captured.state='reserved');
            SELECT * INTO STRICT locked_capture FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt FOR UPDATE NOWAIT;
            IF to_jsonb(locked_capture) IS DISTINCT FROM to_jsonb(captured) THEN
                RAISE EXCEPTION 'review continuation state changed' USING ERRCODE='40001';
            END IF;
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF captured.broker_session_id<>wanted_session OR captured.broker_id<>current_session.broker_id
              OR captured.realm_id<>current_session.realm_id OR captured.authentication_event_id<>wanted_event
              OR captured.credential_revision<>wanted_revision OR captured.origin<>wanted_origin
              OR captured.continuation_digest<>wanted_continuation OR captured.request_digest<>wanted_request
              OR wanted_continuation IS NULL OR wanted_request IS NULL OR wanted_origin IS NULL
              OR now_ms<captured.issued_ms OR now_ms<checked_floor_ms OR now_ms>=captured.reconcile_until_ms THEN
                RAISE EXCEPTION 'exact review continuation unavailable' USING ERRCODE='23514';
            END IF;
            IF captured.state='provisioned' THEN
                IF NOT EXISTS (SELECT FROM %1$I.review_workspaces w WHERE w.account_id=captured.bound_account_id
                    AND w.user_id=captured.bound_user_id AND w.creating_attempt_id=captured.id) THEN
                    RAISE EXCEPTION 'review result association unavailable' USING ERRCODE='23514';
                END IF;
                current_session:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,false);
                now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
                IF now_ms<checked_floor_ms OR now_ms<captured.issued_ms OR now_ms>=captured.reconcile_until_ms THEN
                    RAISE EXCEPTION 'review result expired during reconciliation' USING ERRCODE='23514';
                END IF;
                RETURN QUERY SELECT captured.bound_account_id,captured.bound_user_id;
                RETURN;
            END IF;
            IF now_ms>=captured.expires_ms
              OR EXISTS (SELECT FROM %1$I.accounts a WHERE a.id=captured.reserved_account_id)
              OR EXISTS (SELECT FROM %1$I.payload_profile_account_anchors anchor WHERE anchor.account_id=captured.reserved_account_id)
              OR EXISTS (SELECT FROM %1$I.users u WHERE u.id=captured.reserved_user_id) THEN
                RAISE EXCEPTION 'fresh review reservation unavailable' USING ERRCODE='23514';
            END IF;
            SELECT s::smallint INTO available_slot FROM pg_catalog.generate_series(1,128) s
              WHERE NOT EXISTS (SELECT FROM %1$I.review_workspaces w WHERE w.broker_id=captured.broker_id AND w.slot=s)
              ORDER BY s LIMIT 1;
            IF available_slot IS NULL THEN
                RAISE EXCEPTION 'review workspace capacity reached' USING ERRCODE='54000';
            END IF;
            checked_floor_ms:=now_ms;
            INSERT INTO %1$I.accounts(id) VALUES(captured.reserved_account_id);
            SELECT state,selection_epoch INTO anchor_state,anchor_epoch
              FROM %1$I.payload_profile_account_anchors anchor WHERE anchor.account_id=captured.reserved_account_id FOR SHARE NOWAIT;
            IF NOT FOUND OR anchor_state<>'live' OR anchor_epoch<>0 THEN
                RAISE EXCEPTION 'fresh review anchor unavailable' USING ERRCODE='23514';
            END IF;
            -- Invalid verifier cannot be used by ordinary password login. Email
            -- remains genuinely unverified; no owner_mfa or session is invented.
            INSERT INTO %1$I.users(id,email,password_hash)
              VALUES(captured.reserved_user_id,captured.reserved_user_id::text||'@review.invalid','!');
            INSERT INTO %1$I.memberships(account_id,user_id,role)
              VALUES(captured.reserved_account_id,captured.reserved_user_id,'owner');
            INSERT INTO %1$I.review_workspaces(account_id,user_id,realm_id,broker_id,slot,creating_attempt_id,created_ms)
              VALUES(captured.reserved_account_id,captured.reserved_user_id,captured.realm_id,captured.broker_id,
                available_slot,captured.id,now_ms);
            -- Every INSERT/unique/FK arbitration above may have waited. No
            -- decision based only on transaction-start time may commit authority.
            current_session:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,captured.state='reserved');
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF now_ms<captured.issued_ms OR now_ms<checked_floor_ms OR now_ms>=captured.expires_ms THEN
                RAISE EXCEPTION 'review reservation expired during provision' USING ERRCODE='23514';
            END IF;
            checked_floor_ms:=now_ms;
            UPDATE %1$I.review_bootstrap_attempts SET state='provisioned',bound_account_id=captured.reserved_account_id,
              bound_user_id=captured.reserved_user_id,provisioned_ms=now_ms WHERE id=captured.id;
            GET DIAGNOSTICS changed=ROW_COUNT;
            IF changed<>1 THEN RAISE EXCEPTION 'review result update unavailable' USING ERRCODE='23514'; END IF;
            current_session:=%1$I.review_workspace_current_session(wanted_session,wanted_event,wanted_revision,wanted_origin,true);
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF now_ms<captured.issued_ms OR now_ms<checked_floor_ms OR now_ms>=captured.expires_ms THEN
                RAISE EXCEPTION 'review reservation expired during result commit' USING ERRCODE='23514';
            END IF;
            RETURN QUERY SELECT captured.reserved_account_id,captured.reserved_user_id;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_workspace_before_delete() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured_account uuid;
                bound_identity boolean;
        BEGIN
            IF TG_OP<>'DELETE' OR TG_TABLE_SCHEMA<>%2$L THEN
                RAISE EXCEPTION 'unexpected review deletion context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID=%8$L::regclass THEN
                captured_account:=OLD.reserved_account_id;
                bound_identity:=OLD.state='provisioned';
            ELSIF TG_RELID=%9$L::regclass THEN
                captured_account:=OLD.account_id;
                bound_identity:=true;
            ELSE RAISE EXCEPTION 'unexpected review deletion relation' USING ERRCODE='23514';
            END IF;
            IF NOT pg_catalog.pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(captured_account)) THEN
                RAISE EXCEPTION 'review account deletion fence busy' USING ERRCODE='55P03';
            END IF;
            -- OLD identity remains available during parent cascades. Reduction
            -- does not demand a live broker/session or turn expiry into authority.
            PERFORM account_id FROM %1$I.payload_profile_account_anchors
              WHERE account_id=captured_account FOR SHARE NOWAIT;
            IF bound_identity AND NOT FOUND THEN
                RAISE EXCEPTION 'bound review deletion anchor unavailable' USING ERRCODE='23514';
            END IF;
            RETURN OLD;
        END;
        $function$;
        CREATE TRIGGER review_workspace_before_delete BEFORE DELETE ON %1$I.review_bootstrap_attempts
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_before_delete();
        CREATE TRIGGER review_workspace_before_delete BEFORE DELETE ON %1$I.review_workspaces
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_workspace_before_delete();

        CREATE FUNCTION %1$I.review_workspace_attempt_cleanup(wanted_attempt uuid) RETURNS boolean
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_bootstrap_attempts;
                now_ms bigint;
        BEGIN
            SELECT * INTO captured FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt;
            IF NOT FOUND THEN RETURN false; END IF;
            IF NOT pg_catalog.pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(captured.reserved_account_id)) THEN
                RAISE EXCEPTION 'review cleanup account fence busy' USING ERRCODE='55P03';
            END IF;
            SELECT * INTO STRICT captured FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt;
            PERFORM account_id FROM %1$I.payload_profile_account_anchors
              WHERE account_id=captured.reserved_account_id FOR SHARE NOWAIT;
            IF captured.state='provisioned' AND NOT FOUND THEN
                RAISE EXCEPTION 'bound review cleanup anchor unavailable' USING ERRCODE='23514';
            END IF;
            PERFORM id FROM %1$I.review_brokers WHERE id=captured.broker_id FOR UPDATE NOWAIT;
            SELECT * INTO STRICT captured FROM %1$I.review_bootstrap_attempts WHERE id=wanted_attempt FOR UPDATE NOWAIT;
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF (captured.state='reserved' AND now_ms-captured.expires_ms>=3600000)
              OR (captured.state='provisioned' AND now_ms>=captured.reconcile_until_ms) THEN
                -- Never delete prospective account/user parents. A reserved ID
                -- may have been occupied independently since point-in-time read.
                DELETE FROM %1$I.review_bootstrap_attempts WHERE id=captured.id;
                IF (EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint<now_ms THEN
                    RAISE EXCEPTION 'review cleanup clock regressed' USING ERRCODE='23514';
                END IF;
                RETURN true;
            END IF;
            RETURN false;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_workspace_session_cleanup(wanted_broker uuid) RETURNS bigint
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE now_ms bigint;
                changed bigint;
        BEGIN
            PERFORM id FROM %1$I.review_brokers WHERE id=wanted_broker FOR UPDATE NOWAIT;
            IF NOT FOUND THEN RETURN 0; END IF;
            now_ms:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            WITH expired AS (
                SELECT b.id FROM %1$I.review_broker_sessions b
                  WHERE b.broker_id=wanted_broker
                    AND now_ms-LEAST(b.expires_ms,b.last_used_ms+259200000,COALESCE(b.revoked_ms,b.expires_ms))>=3600000
                    AND NOT EXISTS (SELECT FROM %1$I.review_bootstrap_attempts a WHERE a.broker_session_id=b.id)
                  ORDER BY b.id LIMIT 100 FOR UPDATE OF b NOWAIT
            ) DELETE FROM %1$I.review_broker_sessions b USING expired e WHERE b.id=e.id;
            GET DIAGNOSTICS changed=ROW_COUNT;
            IF (EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint<now_ms THEN
                RAISE EXCEPTION 'review cleanup clock regressed' USING ERRCODE='23514';
            END IF;
            RETURN changed;
        END;
        $function$;
    $ddl$, installation, installation,
        pg_catalog.format('%I.accounts',installation),
        pg_catalog.format('%I.users',installation),
        pg_catalog.format('%I.review_realm_installation',installation),
        pg_catalog.format('%I.review_brokers',installation),
        pg_catalog.format('%I.review_broker_sessions',installation),
        pg_catalog.format('%I.review_bootstrap_attempts',installation),
        pg_catalog.format('%I.review_workspaces',installation));

    -- Explicit relation AND column reset defeats inherited broad defaults and
    -- polluted column ACLs. Repeated by the complete runtime-role provisioner.
    DECLARE
        relation_name text;
        columns_sql text;
        routine record;
        grantee_sql text;
    BEGIN
        FOREACH grantee_sql IN ARRAY ARRAY['PUBLIC','zrotext_runtime'] LOOP
            IF grantee_sql='zrotext_runtime' AND (installation<>'public' OR NOT EXISTS (
                SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime'
            )) THEN CONTINUE; END IF;
            FOREACH relation_name IN ARRAY ARRAY['review_realm_installation','review_brokers',
                'review_broker_sessions','review_bootstrap_attempts','review_workspaces'] LOOP
                SELECT pg_catalog.string_agg(pg_catalog.quote_ident(attname),',' ORDER BY attnum) INTO columns_sql
                  FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',installation,relation_name))
                    AND attnum>0 AND NOT attisdropped;
                EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.%I FROM %s',installation,relation_name,grantee_sql);
                EXECUTE pg_catalog.format('REVOKE ALL (%s) ON TABLE %I.%I FROM %s',columns_sql,installation,relation_name,grantee_sql);
                IF grantee_sql='zrotext_runtime' THEN
                    EXECUTE pg_catalog.format('GRANT SELECT ON TABLE %I.%I TO zrotext_runtime',installation,relation_name);
                END IF;
            END LOOP;
            FOR routine IN SELECT p.oid::pg_catalog.regprocedure AS signature FROM pg_catalog.pg_proc p
              JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname=installation AND p.proname LIKE 'review_workspace_%' LOOP
                EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %s',routine.signature,grantee_sql);
            END LOOP;
        END LOOP;
    END;
END;
$migration$;
