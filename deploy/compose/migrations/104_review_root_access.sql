-- SPDX-License-Identifier: AGPL-3.0-only
-- Isolated review source foundation; no marker/broker/route activation.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE installation name; relation_name text; columns_sql text; routine record; signature text;
BEGIN
    SELECT n.nspname INTO STRICT installation FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE c.oid=pg_catalog.to_regclass('accounts') AND c.relkind='r';
    IF installation LIKE 'pg_%' OR installation='information_schema' THEN
        RAISE EXCEPTION 'application namespace required' USING ERRCODE='23514';
    END IF;
    EXECUTE pg_catalog.format($ddl$
        -- Metadata only: backfill creates no password/event/authentication.
        -- Volatile DEFAULT fills old rows without invoking an identity UPDATE;
        -- future OOB creation must explicitly supply its distinct credential ID.
        ALTER TABLE %1$I.review_brokers ADD COLUMN credential_id uuid NOT NULL DEFAULT gen_random_uuid();
        ALTER TABLE %1$I.review_brokers ALTER COLUMN credential_id DROP DEFAULT;
        ALTER TABLE %1$I.review_brokers ADD CONSTRAINT review_broker_credential_unique UNIQUE(credential_id);
        ALTER TABLE %1$I.review_brokers ADD CONSTRAINT review_broker_credential_identity UNIQUE(id,realm_id,credential_id);
        ALTER TABLE %1$I.review_brokers ADD CONSTRAINT review_broker_credential_distinct
          CHECK (credential_id<>'00000000-0000-0000-0000-000000000000' AND credential_id<>id);
        ALTER TABLE %1$I.review_realm_installation ADD COLUMN active_config_digest bytea;
        ALTER TABLE %1$I.review_realm_installation ADD COLUMN active_config_revision bigint NOT NULL DEFAULT 0;
        ALTER TABLE %1$I.review_realm_installation ADD CONSTRAINT review_active_configuration
          CHECK ((active_config_revision=0 AND active_config_digest IS NULL)
              OR (active_config_revision>0 AND (active_config_digest IS NULL
                  OR (octet_length(active_config_digest)=32 AND active_config_digest<>decode(repeat('00',32),'hex')))));
        ALTER TABLE %1$I.review_workspaces ADD CONSTRAINT review_workspace_exact_identity
          UNIQUE(account_id,user_id,realm_id,broker_id);

        CREATE TABLE %1$I.review_access_preparations (
            browser_digest bytea PRIMARY KEY CHECK(octet_length(browser_digest)=32 AND browser_digest<>decode(repeat('00',32),'hex')),
            realm_id uuid NOT NULL REFERENCES %1$I.review_realm_installation(realm_id),
            database_commitment bytea NOT NULL CHECK(octet_length(database_commitment)=32 AND database_commitment<>decode(repeat('00',32),'hex')),
            auth_key_commitment bytea NOT NULL CHECK(octet_length(auth_key_commitment)=32 AND auth_key_commitment<>decode(repeat('00',32),'hex')),
            config_revision bigint NOT NULL CHECK(config_revision>0),
            config_digest bytea NOT NULL CHECK(octet_length(config_digest)=32 AND config_digest<>decode(repeat('00',32),'hex')),
            origin text NOT NULL,
            created_ms bigint NOT NULL CHECK(created_ms>0),
            browser_expires_ms bigint NOT NULL,
            browser_confirmed_ms bigint,
            generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
            state text NOT NULL DEFAULT 'empty'
              CHECK(state IN ('empty','prepared','confirmed','checking','committed','cancelled_no_effect','rejected_no_effect')),
            preparation_id uuid,
            request_id uuid,
            operation smallint CHECK(operation BETWEEN 1 AND 5),
            request_digest bytea,
            prepared_csrf_digest bytea,
            prepared_ms bigint,
            create_deadline_ms bigint,
            delivery_deadline_ms bigint,
            active_broker_generation bigint NOT NULL DEFAULT 0 CHECK(active_broker_generation>=0),
            active_owner_generation bigint NOT NULL DEFAULT 0 CHECK(active_owner_generation>=0),
            delivered boolean NOT NULL DEFAULT false,
            locator_pending boolean NOT NULL DEFAULT false,
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            CHECK(browser_expires_ms>created_ms AND browser_expires_ms-created_ms<=1209600000),
            CHECK(browser_confirmed_ms IS NULL OR (browser_confirmed_ms>=created_ms AND browser_confirmed_ms<browser_expires_ms)),
            CHECK(active_broker_generation<=generation AND active_owner_generation<=generation),
            CHECK((state='empty' AND generation=0 AND preparation_id IS NULL AND request_id IS NULL AND operation IS NULL
                AND request_digest IS NULL AND prepared_csrf_digest IS NULL AND prepared_ms IS NULL AND create_deadline_ms IS NULL AND delivery_deadline_ms IS NULL)
              OR (state<>'empty' AND generation>0 AND browser_confirmed_ms IS NOT NULL
                AND preparation_id IS NOT NULL AND preparation_id<>'00000000-0000-0000-0000-000000000000'
                AND request_id IS NOT NULL AND request_id<>'00000000-0000-0000-0000-000000000000' AND request_id<>preparation_id
                AND operation IS NOT NULL AND request_digest IS NOT NULL AND octet_length(request_digest)=32
                AND prepared_csrf_digest IS NOT NULL AND octet_length(prepared_csrf_digest)=32
                AND prepared_csrf_digest<>decode(repeat('00',32),'hex')
                AND request_digest<>decode(repeat('00',32),'hex') AND prepared_ms IS NOT NULL AND prepared_ms>=created_ms
                AND create_deadline_ms IS NOT NULL AND create_deadline_ms>=prepared_ms AND create_deadline_ms-prepared_ms<=300000
                AND delivery_deadline_ms IS NOT NULL AND delivery_deadline_ms>=create_deadline_ms
                AND delivery_deadline_ms-prepared_ms<=604800000 AND delivery_deadline_ms<=browser_expires_ms)),
            CHECK(NOT delivered OR state='committed')
        );
        -- Deliberately NO account/user/session/locator pointers in this guard.
        CREATE INDEX review_access_preparation_cleanup ON %1$I.review_access_preparations(browser_expires_ms,browser_digest);

        CREATE TABLE %1$I.review_access_sessions (
            id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
            realm_id uuid NOT NULL,
            account_id uuid NOT NULL,
            user_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            credential_revision bigint NOT NULL CHECK(credential_revision>0),
            broker_session_id uuid NOT NULL,
            authentication_event_id uuid NOT NULL,
            browser_digest bytea NOT NULL CHECK(octet_length(browser_digest)=32 AND browser_digest<>decode(repeat('00',32),'hex')),
            delivery_generation bigint NOT NULL CHECK(delivery_generation>0),
            auth_key_commitment bytea NOT NULL CHECK(octet_length(auth_key_commitment)=32 AND auth_key_commitment<>decode(repeat('00',32),'hex')),
            config_revision bigint NOT NULL CHECK(config_revision>0),
            config_digest bytea NOT NULL CHECK(octet_length(config_digest)=32 AND config_digest<>decode(repeat('00',32),'hex')),
            origin text NOT NULL,
            slot smallint NOT NULL CHECK(slot BETWEEN 1 AND 16),
            token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32 AND token_digest<>decode(repeat('00',32),'hex')),
            csrf_digest bytea NOT NULL CHECK(octet_length(csrf_digest)=32 AND csrf_digest<>decode(repeat('00',32),'hex')),
            source smallint NOT NULL CHECK(source IN (1,3)),
            source_request_id uuid NOT NULL CHECK(source_request_id<>'00000000-0000-0000-0000-000000000000'),
            bootstrap_attempt_id uuid,
            resume_challenge_id uuid,
            source_result_digest bytea NOT NULL CHECK(octet_length(source_result_digest)=32 AND source_result_digest<>decode(repeat('00',32),'hex')),
            issued_ms bigint NOT NULL CHECK(issued_ms>0),
            expires_ms bigint NOT NULL,
            last_used_ms bigint NOT NULL,
            revoked_ms bigint,
            FOREIGN KEY(account_id,user_id,realm_id,broker_id)
              REFERENCES %1$I.review_workspaces(account_id,user_id,realm_id,broker_id) ON DELETE CASCADE,
            FOREIGN KEY(account_id,user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            FOREIGN KEY(account_id) REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES %1$I.users(id) ON DELETE CASCADE,
            FOREIGN KEY(broker_id,realm_id,credential_id) REFERENCES %1$I.review_brokers(id,realm_id,credential_id),
            FOREIGN KEY(broker_session_id,broker_id,realm_id,authentication_event_id,credential_revision)
              REFERENCES %1$I.review_broker_sessions(id,broker_id,realm_id,authentication_event_id,credential_revision),
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            UNIQUE(account_id,slot),
            UNIQUE(id,account_id,user_id),
            UNIQUE(id,account_id,user_id,realm_id,broker_id,credential_id,credential_revision,
                broker_session_id,authentication_event_id,browser_digest,delivery_generation,config_revision),
            CHECK((source=1 AND bootstrap_attempt_id IS NOT NULL AND bootstrap_attempt_id<>'00000000-0000-0000-0000-000000000000' AND resume_challenge_id IS NULL)
                OR (source=3 AND resume_challenge_id IS NOT NULL AND resume_challenge_id<>'00000000-0000-0000-0000-000000000000' AND bootstrap_attempt_id IS NULL)),
            CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=1209600000),
            CHECK(last_used_ms>=issued_ms AND last_used_ms<expires_ms),
            CHECK(revoked_ms IS NULL OR revoked_ms>=issued_ms)
        );
        CREATE INDEX review_access_session_user ON %1$I.review_access_sessions(user_id);
        CREATE INDEX review_access_session_broker ON %1$I.review_access_sessions(broker_session_id);

        CREATE TABLE %1$I.review_access_authentications (
            preparation_id uuid PRIMARY KEY CHECK(preparation_id<>'00000000-0000-0000-0000-000000000000'),
            request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
            operation smallint NOT NULL CHECK(operation IN (1,2)),
            realm_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            credential_revision bigint NOT NULL CHECK(credential_revision>0),
            broker_session_id uuid NOT NULL UNIQUE,
            authentication_event_id uuid NOT NULL UNIQUE,
            broker_csrf_digest bytea NOT NULL CHECK(octet_length(broker_csrf_digest)=32 AND broker_csrf_digest<>decode(repeat('00',32),'hex')),
            browser_digest bytea NOT NULL CHECK(octet_length(browser_digest)=32 AND browser_digest<>decode(repeat('00',32),'hex')),
            generation bigint NOT NULL CHECK(generation>0),
            request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32 AND request_digest<>decode(repeat('00',32),'hex')),
            result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32 AND result_digest<>decode(repeat('00',32),'hex')),
            config_revision bigint NOT NULL CHECK(config_revision>0),
            config_digest bytea NOT NULL CHECK(octet_length(config_digest)=32 AND config_digest<>decode(repeat('00',32),'hex')),
            auth_key_commitment bytea NOT NULL CHECK(octet_length(auth_key_commitment)=32 AND auth_key_commitment<>decode(repeat('00',32),'hex')),
            origin text NOT NULL,
            issued_ms bigint NOT NULL CHECK(issued_ms>0),
            delivery_deadline_ms bigint NOT NULL,
            account_id uuid REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            user_id uuid REFERENCES %1$I.users(id) ON DELETE CASCADE,
            owner_session_id uuid,
            bootstrap_attempt_id uuid,
            FOREIGN KEY(account_id,user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            FOREIGN KEY(owner_session_id,account_id,user_id,realm_id,broker_id,credential_id,credential_revision,
                broker_session_id,authentication_event_id,browser_digest,generation,config_revision)
              REFERENCES %1$I.review_access_sessions(id,account_id,user_id,realm_id,broker_id,credential_id,credential_revision,
                broker_session_id,authentication_event_id,browser_digest,delivery_generation,config_revision) ON DELETE CASCADE,
            FOREIGN KEY(broker_id,realm_id,credential_id) REFERENCES %1$I.review_brokers(id,realm_id,credential_id),
            FOREIGN KEY(broker_session_id,broker_id,realm_id,authentication_event_id,credential_revision)
              REFERENCES %1$I.review_broker_sessions(id,broker_id,realm_id,authentication_event_id,credential_revision) ON DELETE CASCADE,
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            CHECK(delivery_deadline_ms>issued_ms AND delivery_deadline_ms-issued_ms<=604800000),
            CHECK((operation=1 AND account_id IS NOT NULL AND user_id IS NOT NULL AND owner_session_id IS NOT NULL
                AND bootstrap_attempt_id IS NOT NULL AND bootstrap_attempt_id<>'00000000-0000-0000-0000-000000000000')
              OR (operation=2 AND account_id IS NULL AND user_id IS NULL AND owner_session_id IS NULL AND bootstrap_attempt_id IS NULL))
        );
        CREATE INDEX review_access_auth_account ON %1$I.review_access_authentications(account_id,user_id);
        CREATE INDEX review_access_auth_user ON %1$I.review_access_authentications(user_id);
        CREATE INDEX review_access_auth_cleanup ON %1$I.review_access_authentications(delivery_deadline_ms,preparation_id);

        -- Same atomic subject/route counter semantics as ordinary auth, with a
        -- closed catalog path and qualified persistence. This avoids inheriting
        -- an arbitrary URL path or changing ordinary relocated auth fixtures.
        CREATE FUNCTION %1$I.review_access_abuse_consume(p_scope text,p_global_hash bytea,p_subject_hash bytea,
            p_global_max integer,p_global_seconds integer,p_subject_max integer,p_subject_seconds integer)
        RETURNS boolean LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
        DECLARE started timestamptz; attempts integer; allowed boolean;
        BEGIN
            SELECT a.window_started_at,a.attempts INTO started,attempts FROM %1$I.auth_abuse_counters a
              WHERE a.scope=p_scope AND a.subject_hash=p_global_hash;
            IF FOUND AND started>clock_timestamp()-make_interval(secs=>p_global_seconds) AND attempts>=p_global_max THEN RETURN false; END IF;
            BEGIN
                IF p_subject_hash IS NOT NULL THEN
                    allowed:=false;
                    INSERT INTO %1$I.auth_abuse_counters AS a(scope,subject_hash,window_started_at,attempts,updated_at)
                      VALUES(p_scope,p_subject_hash,clock_timestamp(),1,clock_timestamp())
                      ON CONFLICT(scope,subject_hash) DO UPDATE SET
                        window_started_at=CASE WHEN a.window_started_at<=clock_timestamp()-make_interval(secs=>p_subject_seconds)
                            THEN clock_timestamp() ELSE a.window_started_at END,
                        attempts=CASE WHEN a.window_started_at<=clock_timestamp()-make_interval(secs=>p_subject_seconds)
                            THEN 1 ELSE a.attempts+1 END,updated_at=clock_timestamp()
                      WHERE a.window_started_at<=clock_timestamp()-make_interval(secs=>p_subject_seconds) OR a.attempts<p_subject_max
                      RETURNING true INTO allowed;
                    IF NOT COALESCE(allowed,false) THEN RETURN false; END IF;
                END IF;
                allowed:=false;
                INSERT INTO %1$I.auth_abuse_counters AS a(scope,subject_hash,window_started_at,attempts,updated_at)
                  VALUES(p_scope,p_global_hash,clock_timestamp(),1,clock_timestamp())
                  ON CONFLICT(scope,subject_hash) DO UPDATE SET
                    window_started_at=CASE WHEN a.window_started_at<=clock_timestamp()-make_interval(secs=>p_global_seconds)
                        THEN clock_timestamp() ELSE a.window_started_at END,
                    attempts=CASE WHEN a.window_started_at<=clock_timestamp()-make_interval(secs=>p_global_seconds)
                        THEN 1 ELSE a.attempts+1 END,updated_at=clock_timestamp()
                  WHERE a.window_started_at<=clock_timestamp()-make_interval(secs=>p_global_seconds) OR a.attempts<p_global_max
                  RETURNING true INTO allowed;
                IF NOT COALESCE(allowed,false) THEN
                    IF p_subject_hash IS NOT NULL THEN RAISE EXCEPTION 'review route budget exhausted' USING ERRCODE='ZX001'; END IF;
                    RETURN false;
                END IF;
                RETURN true;
            EXCEPTION WHEN SQLSTATE 'ZX001' THEN RETURN false;
            END;
        END;
        $function$;

        CREATE TABLE %1$I.review_access_root_reauth (
            id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
            realm_id uuid NOT NULL,
            account_id uuid NOT NULL,
            user_id uuid NOT NULL,
            owner_session_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            credential_revision bigint NOT NULL CHECK(credential_revision>0),
            broker_session_id uuid NOT NULL,
            authentication_event_id uuid NOT NULL,
            browser_digest bytea NOT NULL CHECK(octet_length(browser_digest)=32 AND browser_digest<>decode(repeat('00',32),'hex')),
            delivery_generation bigint NOT NULL CHECK(delivery_generation>0),
            config_revision bigint NOT NULL CHECK(config_revision>0),
            preparation_id uuid NOT NULL CHECK(preparation_id<>'00000000-0000-0000-0000-000000000000'),
            request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
            request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32 AND request_digest<>decode(repeat('00',32),'hex')),
            root_challenge_id uuid NOT NULL CHECK(root_challenge_id<>'00000000-0000-0000-0000-000000000000'),
            operation text NOT NULL DEFAULT 'root_custody_enrollment' CHECK(operation='root_custody_enrollment'),
            root_pin bytea NOT NULL CHECK(octet_length(root_pin)=94),
            root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32 AND root_fingerprint<>decode(repeat('00',32),'hex')),
            encrypted_backup_digest bytea NOT NULL CHECK(octet_length(encrypted_backup_digest)=32 AND encrypted_backup_digest<>decode(repeat('00',32),'hex')),
            public_card_digest bytea NOT NULL CHECK(octet_length(public_card_digest)=32 AND public_card_digest<>decode(repeat('00',32),'hex')),
            unsigned_enrollment bytea NOT NULL CHECK(octet_length(unsigned_enrollment) BETWEEN 152 AND 663),
            custody_statement bytea NOT NULL CHECK(octet_length(custody_statement) BETWEEN 1 AND 1024),
            statement_digest bytea NOT NULL CHECK(octet_length(statement_digest)=32 AND statement_digest<>decode(repeat('00',32),'hex')),
            nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32 AND nonce_digest<>decode(repeat('00',32),'hex')),
            reauth_nonce bytea NOT NULL CHECK(octet_length(reauth_nonce)=32 AND sha256(reauth_nonce)=nonce_digest),
            origin text NOT NULL,
            state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','consumed','cancelled')),
            issued_ms bigint NOT NULL CHECK(issued_ms>0),
            expires_ms bigint NOT NULL,
            retain_until_ms bigint NOT NULL,
            completed_ms bigint,
            result_digest bytea,
            completion_preparation_id uuid,
            completion_request_id uuid,
            completion_request_digest bytea,
            FOREIGN KEY(owner_session_id,account_id,user_id,realm_id,broker_id,credential_id,credential_revision,
                broker_session_id,authentication_event_id,browser_digest,delivery_generation,config_revision)
              REFERENCES %1$I.review_access_sessions(id,account_id,user_id,realm_id,broker_id,credential_id,credential_revision,
                broker_session_id,authentication_event_id,browser_digest,delivery_generation,config_revision) ON DELETE CASCADE,
            FOREIGN KEY(account_id) REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES %1$I.users(id) ON DELETE CASCADE,
            FOREIGN KEY(account_id,user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
            CHECK(retain_until_ms>=expires_ms AND retain_until_ms-issued_ms<=604800000),
            CHECK((state='pending' AND completed_ms IS NULL AND result_digest IS NULL
                AND completion_preparation_id IS NULL AND completion_request_id IS NULL AND completion_request_digest IS NULL)
              OR (state='consumed' AND completed_ms IS NOT NULL AND completed_ms>=issued_ms AND completed_ms<expires_ms
                AND result_digest IS NOT NULL AND octet_length(result_digest)=32 AND result_digest<>decode(repeat('00',32),'hex')
                AND completion_preparation_id IS NOT NULL AND completion_preparation_id<>'00000000-0000-0000-0000-000000000000'
                AND completion_request_id IS NOT NULL AND completion_request_id<>'00000000-0000-0000-0000-000000000000'
                AND completion_request_digest IS NOT NULL AND octet_length(completion_request_digest)=32
                AND completion_request_digest<>decode(repeat('00',32),'hex'))
              OR (state='cancelled' AND completed_ms IS NOT NULL AND completed_ms>=issued_ms AND result_digest IS NULL
                AND completion_preparation_id IS NULL AND completion_request_id IS NULL AND completion_request_digest IS NULL))
        );
        CREATE UNIQUE INDEX review_access_root_one_pending ON %1$I.review_access_root_reauth(account_id,owner_session_id)
          WHERE state='pending';
        CREATE INDEX review_access_root_user ON %1$I.review_access_root_reauth(user_id);
        CREATE INDEX review_access_root_cleanup ON %1$I.review_access_root_reauth(retain_until_ms,id);

        CREATE TABLE %1$I.review_access_locators (
            account_id uuid PRIMARY KEY,
            user_id uuid NOT NULL UNIQUE,
            realm_id uuid NOT NULL,
            broker_id uuid NOT NULL,
            origin text NOT NULL,
            version smallint NOT NULL DEFAULT 1 CHECK(version=1),
            locator_digest bytea NOT NULL UNIQUE CHECK(octet_length(locator_digest)=32 AND locator_digest<>decode(repeat('00',32),'hex')),
            auth_key_commitment bytea NOT NULL CHECK(octet_length(auth_key_commitment)=32 AND auth_key_commitment<>decode(repeat('00',32),'hex')),
            config_digest bytea NOT NULL CHECK(octet_length(config_digest)=32 AND config_digest<>decode(repeat('00',32),'hex')),
            config_revision bigint NOT NULL CHECK(config_revision>0),
            preparation_id uuid NOT NULL CHECK(preparation_id<>'00000000-0000-0000-0000-000000000000'),
            request_id uuid NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
            generation bigint NOT NULL CHECK(generation>0),
            created_ms bigint NOT NULL CHECK(created_ms>0),
            retained_request_id uuid,
            retained_selector_digest bytea,
            retained_ms bigint,
            FOREIGN KEY(account_id,user_id,realm_id,broker_id)
              REFERENCES %1$I.review_workspaces(account_id,user_id,realm_id,broker_id) ON DELETE CASCADE,
            FOREIGN KEY(account_id) REFERENCES %1$I.accounts(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES %1$I.users(id) ON DELETE CASCADE,
            FOREIGN KEY(account_id,user_id) REFERENCES %1$I.memberships(account_id,user_id) ON DELETE CASCADE,
            FOREIGN KEY(realm_id,origin) REFERENCES %1$I.review_realm_installation(realm_id,origin),
            CHECK((retained_request_id IS NULL AND retained_selector_digest IS NULL AND retained_ms IS NULL)
              OR(retained_request_id IS NOT NULL AND retained_request_id<>'00000000-0000-0000-0000-000000000000'
                AND retained_selector_digest IS NOT NULL AND octet_length(retained_selector_digest)=32
                AND retained_selector_digest<>decode(repeat('00',32),'hex') AND retained_ms IS NOT NULL AND retained_ms>=created_ms))
        );
        -- No attempt/session/result FK: exact private locator survives their
        -- finite cleanup and disappears with real account/user/member erasure.
        CREATE OR REPLACE FUNCTION %1$I.review_workspace_row_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE mutable_columns text[];
        BEGIN
            IF TG_TABLE_SCHEMA<>%2$L OR TG_RELID NOT IN (
                %5$L::regclass,%6$L::regclass,%7$L::regclass,%8$L::regclass,%9$L::regclass
            ) OR TG_OP<>'UPDATE' THEN
                RAISE EXCEPTION 'unexpected review identity update context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID=%5$L::regclass THEN
                mutable_columns:=ARRAY['active_config_digest','active_config_revision'];
                IF (NEW.active_config_digest,NEW.active_config_revision) IS DISTINCT FROM
                  (OLD.active_config_digest,OLD.active_config_revision) THEN
                    IF OLD.active_config_revision=9223372036854775807
                      OR NEW.active_config_revision IS DISTINCT FROM OLD.active_config_revision+1 THEN
                        RAISE EXCEPTION 'review configuration revision must advance' USING ERRCODE='23514';
                    END IF;
                END IF;
            ELSIF TG_RELID=%6$L::regclass THEN
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

        CREATE FUNCTION %1$I.review_access_clock(previous_ms bigint DEFAULT 0) RETURNS bigint
        LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
        DECLARE observed bigint;
        BEGIN
            observed:=(EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
            IF previous_ms IS NULL OR observed<=0 OR observed<previous_ms THEN
                RAISE EXCEPTION 'review clock unavailable' USING ERRCODE='23514';
            END IF;
            RETURN observed;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_marker(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        BEGIN
            PERFORM realm_id FROM %1$I.review_realm_installation WHERE realm_id=wanted_realm
                AND origin=wanted_origin AND sha256(uuid_send(database_id))=wanted_database
                AND auth_key_digest=wanted_key AND active_config_digest=wanted_config
                AND active_config_revision=wanted_revision AND wanted_revision>0 FOR SHARE NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'current review configuration unavailable' USING ERRCODE='23514'; END IF;
            RETURN %1$I.review_access_clock();
        END;
        $function$;

        -- These triggers protect immutable provenance and parent erasure even
        -- from owner/test writes. They are not password/signature witnesses.
        CREATE FUNCTION %1$I.review_access_bound_guard() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured_account uuid; anchor_state text; mutable_columns text[];
        BEGIN
            IF TG_TABLE_SCHEMA<>%2$L OR TG_RELID NOT IN (
                %10$L::regclass,%11$L::regclass,%12$L::regclass,%13$L::regclass
            ) OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
                RAISE EXCEPTION 'unexpected review access row context' USING ERRCODE='23514';
            END IF;
            IF TG_OP='DELETE' THEN captured_account:=OLD.account_id; ELSE captured_account:=NEW.account_id; END IF;
            -- Only the closed broker-only authentication branch lacks an
            -- account. No account-bound result may fall back to this branch.
            IF captured_account IS NULL THEN
                IF TG_RELID<>%11$L::regclass THEN
                    RAISE EXCEPTION 'review account identity required' USING ERRCODE='23514';
                END IF;
                IF TG_OP='DELETE' THEN
                    IF OLD.operation<>2 THEN RAISE EXCEPTION 'review account identity required' USING ERRCODE='23514'; END IF;
                ELSE
                    IF NEW.operation<>2 THEN RAISE EXCEPTION 'review account identity required' USING ERRCODE='23514'; END IF;
                END IF;
            ELSE
                IF NOT pg_try_advisory_xact_lock_shared(%1$I.payload_profile_account_fence_key(captured_account)) THEN
                    RAISE EXCEPTION 'review access account fence busy' USING ERRCODE='55P03';
                END IF;
                SELECT state INTO anchor_state FROM %1$I.payload_profile_account_anchors
                  WHERE account_id=captured_account FOR SHARE NOWAIT;
                IF NOT FOUND OR (TG_OP<>'DELETE' AND anchor_state<>'live') THEN
                    RAISE EXCEPTION 'review access account anchor unavailable' USING ERRCODE='23514';
                END IF;
            END IF;
            IF TG_OP='UPDATE' THEN
                IF TG_RELID=%10$L::regclass THEN
                    mutable_columns:=ARRAY['last_used_ms','revoked_ms'];
                    IF NEW.last_used_ms<OLD.last_used_ms OR
                        (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
                        RAISE EXCEPTION 'review owner session reduction required' USING ERRCODE='23514';
                    END IF;
                ELSIF TG_RELID=%12$L::regclass THEN
                    mutable_columns:=ARRAY['state','completed_ms','result_digest','completion_preparation_id',
                        'completion_request_id','completion_request_digest'];
                    IF OLD.state<>'pending' OR NEW.state NOT IN ('consumed','cancelled') THEN
                        RAISE EXCEPTION 'review reauthentication already disposed' USING ERRCODE='23514';
                    END IF;
                ELSIF TG_RELID=%13$L::regclass THEN
                    mutable_columns:=ARRAY['retained_request_id','retained_selector_digest','retained_ms'];
                    IF OLD.retained_ms IS NOT NULL OR NEW.retained_ms IS NULL THEN
                        RAISE EXCEPTION 'locator retention acknowledgement is immutable' USING ERRCODE='23514';
                    END IF;
                ELSE mutable_columns:=ARRAY[]::text[];
                END IF;
                IF (to_jsonb(NEW)-mutable_columns) IS DISTINCT FROM (to_jsonb(OLD)-mutable_columns) THEN
                    RAISE EXCEPTION 'review access provenance is immutable' USING ERRCODE='23514';
                END IF;
            ELSIF TG_OP='INSERT' THEN
                IF TG_RELID=%12$L::regclass THEN
                    IF NEW.state<>'pending' THEN
                        RAISE EXCEPTION 'review reauthentication starts pending' USING ERRCODE='23514';
                    END IF;
                END IF;
            END IF;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END;
        $function$;
        CREATE TRIGGER review_access_bound_before_change BEFORE INSERT OR UPDATE OR DELETE ON %1$I.review_access_sessions
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_access_bound_guard();
        CREATE TRIGGER review_access_bound_before_change BEFORE INSERT OR UPDATE OR DELETE ON %1$I.review_access_authentications
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_access_bound_guard();
        CREATE TRIGGER review_access_bound_before_change BEFORE INSERT OR UPDATE OR DELETE ON %1$I.review_access_root_reauth
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_access_bound_guard();
        CREATE TRIGGER review_access_bound_before_change BEFORE INSERT OR UPDATE OR DELETE ON %1$I.review_access_locators
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_access_bound_guard();

        CREATE FUNCTION %1$I.review_access_preparation_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
        DECLARE mutable_columns text[]; allowed_transition boolean; now_ms bigint;
        BEGIN
            IF TG_TABLE_SCHEMA<>%2$L OR TG_RELID<>%14$L::regclass THEN
                RAISE EXCEPTION 'unexpected review preparation relation' USING ERRCODE='23514';
            END IF;
            IF TG_OP='DELETE' THEN
                now_ms:=%1$I.review_access_clock(GREATEST(OLD.created_ms,OLD.prepared_ms));
                IF now_ms<OLD.browser_expires_ms+3600000 OR OLD.state='checking' THEN
                    RAISE EXCEPTION 'review browser retention remains' USING ERRCODE='23514';
                END IF;
                RETURN OLD;
            ELSIF TG_OP='INSERT' THEN
                IF NEW.state<>'empty' OR NEW.generation<>0 OR NEW.active_broker_generation<>0 OR NEW.active_owner_generation<>0
                  OR NEW.browser_confirmed_ms IS NOT NULL OR NEW.delivered OR NEW.locator_pending THEN
                    RAISE EXCEPTION 'review browser starts empty' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            ELSIF TG_OP<>'UPDATE' THEN
                RAISE EXCEPTION 'unexpected review preparation operation' USING ERRCODE='23514';
            END IF;
            mutable_columns:=ARRAY['browser_confirmed_ms','generation','state','preparation_id','request_id','operation',
                'request_digest','prepared_csrf_digest','prepared_ms','create_deadline_ms','delivery_deadline_ms',
                'active_broker_generation','active_owner_generation','delivered','locator_pending'];
            IF (to_jsonb(NEW)-mutable_columns) IS DISTINCT FROM (to_jsonb(OLD)-mutable_columns)
              OR (OLD.browser_confirmed_ms IS NOT NULL AND NEW.browser_confirmed_ms IS DISTINCT FROM OLD.browser_confirmed_ms) THEN
                RAISE EXCEPTION 'review browser identity is immutable' USING ERRCODE='23514';
            END IF;
            IF NEW.generation<>OLD.generation THEN
                IF OLD.generation=9223372036854775807 OR NEW.generation<>OLD.generation+1 OR NEW.state<>'prepared'
                  OR NEW.operation NOT IN (1,2,4,5) OR NEW.delivered OR NEW.locator_pending
                  OR NEW.active_broker_generation<>OLD.active_broker_generation OR NEW.active_owner_generation<>OLD.active_owner_generation
                  OR (OLD.state NOT IN ('empty','cancelled_no_effect','rejected_no_effect')
                    AND NOT(OLD.state='committed' AND OLD.delivered AND NOT OLD.locator_pending)) THEN
                    RAISE EXCEPTION 'review preparation cannot advance' USING ERRCODE='23514';
                END IF;
                RETURN NEW;
            END IF;
            IF (to_jsonb(NEW)-ARRAY['browser_confirmed_ms','state','active_broker_generation','active_owner_generation','delivered','locator_pending'])
              IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['browser_confirmed_ms','state','active_broker_generation','active_owner_generation','delivered','locator_pending']) THEN
                RAISE EXCEPTION 'current review preparation is immutable' USING ERRCODE='23514';
            END IF;
            allowed_transition:=(OLD.state='empty' AND NEW.state='empty')
                OR (OLD.state='prepared' AND NEW.state IN ('confirmed','cancelled_no_effect'))
                OR (OLD.state='confirmed' AND NEW.state IN ('checking','cancelled_no_effect'))
                OR (OLD.state='checking' AND NEW.state IN ('committed','cancelled_no_effect','rejected_no_effect'))
                OR (OLD.state IN ('committed','cancelled_no_effect','rejected_no_effect') AND NEW.state=OLD.state);
            IF NOT allowed_transition OR (OLD.delivered AND NOT NEW.delivered) THEN
                RAISE EXCEPTION 'review preparation transition refused' USING ERRCODE='23514';
            END IF;
            IF OLD.state='checking' AND NEW.state='committed' THEN
                IF NEW.operation=1 THEN
                    IF NEW.active_broker_generation<>NEW.generation OR NEW.active_owner_generation<>NEW.generation OR NOT NEW.locator_pending THEN
                        RAISE EXCEPTION 'initial review delivery generation required' USING ERRCODE='23514'; END IF;
                ELSIF NEW.operation=2 THEN
                    IF NEW.active_broker_generation<>NEW.generation OR NEW.active_owner_generation<>OLD.active_owner_generation OR NEW.locator_pending THEN
                        RAISE EXCEPTION 'broker-only delivery generation required' USING ERRCODE='23514'; END IF;
                ELSIF NEW.operation IN (4,5) THEN
                    IF NEW.active_broker_generation<>OLD.active_broker_generation OR NEW.active_owner_generation<>OLD.active_owner_generation OR NEW.locator_pending THEN
                        RAISE EXCEPTION 'root operation cannot replace delivery' USING ERRCODE='23514'; END IF;
                ELSE RAISE EXCEPTION 'unsupported review issuance source' USING ERRCODE='23514';
                END IF;
            ELSIF NEW.active_broker_generation<>OLD.active_broker_generation OR NEW.active_owner_generation<>OLD.active_owner_generation
              OR (NEW.locator_pending IS DISTINCT FROM OLD.locator_pending AND NOT(OLD.state='committed' AND OLD.locator_pending AND NOT NEW.locator_pending)) THEN
                RAISE EXCEPTION 'only committed issuance changes active generations' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END;
        $function$;
        CREATE TRIGGER review_access_preparation_before_change BEFORE INSERT OR UPDATE OR DELETE ON %1$I.review_access_preparations
          FOR EACH ROW EXECUTE FUNCTION %1$I.review_access_preparation_guard();

        CREATE FUNCTION %1$I.review_access_guard_lock(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea)
        RETURNS %1$I.review_access_preparations
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_preparations; now_ms bigint;
        BEGIN
            now_ms:=%1$I.review_access_marker(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision);
            SELECT * INTO STRICT captured FROM %1$I.review_access_preparations
              WHERE browser_digest=wanted_browser FOR UPDATE NOWAIT;
            IF captured.realm_id IS DISTINCT FROM wanted_realm OR captured.database_commitment IS DISTINCT FROM wanted_database
              OR captured.origin IS DISTINCT FROM wanted_origin OR captured.auth_key_commitment IS DISTINCT FROM wanted_key
              OR captured.config_digest IS DISTINCT FROM wanted_config OR captured.config_revision IS DISTINCT FROM wanted_revision
              OR now_ms<captured.created_ms OR now_ms>=captured.browser_expires_ms THEN
                RAISE EXCEPTION 'review browser unavailable' USING ERRCODE='23514';
            END IF;
            RETURN captured;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_browser(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_issued bigint,wanted_expires bigint,confirmation boolean)
        RETURNS %1$I.review_access_preparations
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_preparations; now_ms bigint; floor_ms bigint;
        BEGIN
            floor_ms:=%1$I.review_access_marker(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision);
            IF confirmation IS NULL OR wanted_issued IS NULL OR wanted_expires IS NULL OR floor_ms<wanted_issued
              OR floor_ms>=wanted_expires THEN RAISE EXCEPTION 'review browser time unavailable' USING ERRCODE='23514'; END IF;
            SELECT * INTO captured FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser FOR UPDATE NOWAIT;
            IF NOT FOUND THEN
                IF confirmation THEN RAISE EXCEPTION 'review browser missing' USING ERRCODE='23514'; END IF;
                INSERT INTO %1$I.review_access_preparations(browser_digest,realm_id,database_commitment,auth_key_commitment,
                    config_digest,config_revision,origin,created_ms,browser_expires_ms)
                  VALUES(wanted_browser,wanted_realm,wanted_database,wanted_key,wanted_config,wanted_revision,
                    wanted_origin,wanted_issued,wanted_expires);
            END IF;
            captured:=%1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
            IF captured.created_ms IS DISTINCT FROM wanted_issued OR captured.browser_expires_ms IS DISTINCT FROM wanted_expires THEN
                RAISE EXCEPTION 'review browser identity changed' USING ERRCODE='23514';
            END IF;
            IF confirmation AND captured.browser_confirmed_ms IS NULL THEN
                now_ms:=%1$I.review_access_clock(floor_ms);
                UPDATE %1$I.review_access_preparations SET browser_confirmed_ms=now_ms WHERE browser_digest=wanted_browser;
            END IF;
            now_ms:=%1$I.review_access_clock(floor_ms);
            IF now_ms>=wanted_expires THEN RAISE EXCEPTION 'review browser expired' USING ERRCODE='23514'; END IF;
            RETURN %1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_prepare(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_preparation uuid,wanted_request uuid,wanted_operation smallint,wanted_digest bytea,wanted_generation bigint,
            wanted_prepared bigint,wanted_create bigint,wanted_delivery bigint,wanted_csrf_digest bytea)
        RETURNS %1$I.review_access_preparations
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_preparations; now_ms bigint; floor_ms bigint;
        BEGIN
            captured:=%1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
            floor_ms:=%1$I.review_access_clock(captured.created_ms);
            IF captured.browser_confirmed_ms IS NULL OR wanted_operation IS NULL OR wanted_operation NOT IN (1,2,4,5)
              OR (wanted_operation=1 AND captured.active_owner_generation>0)
              OR captured.generation=9223372036854775807 OR wanted_generation IS DISTINCT FROM captured.generation+1
              OR (captured.state NOT IN ('empty','cancelled_no_effect','rejected_no_effect')
                AND NOT(captured.state='committed' AND captured.delivered AND NOT captured.locator_pending))
              OR wanted_prepared IS NULL OR wanted_create IS NULL OR wanted_delivery IS NULL
              OR floor_ms<wanted_prepared OR floor_ms>=wanted_create THEN
                RAISE EXCEPTION 'review preparation unavailable' USING ERRCODE='23514';
            END IF;
            UPDATE %1$I.review_access_preparations SET generation=wanted_generation,state='prepared',
                preparation_id=wanted_preparation,request_id=wanted_request,operation=wanted_operation,request_digest=wanted_digest,
                prepared_csrf_digest=wanted_csrf_digest,
                prepared_ms=wanted_prepared,create_deadline_ms=wanted_create,delivery_deadline_ms=wanted_delivery,
                delivered=false,locator_pending=false WHERE browser_digest=wanted_browser;
            now_ms:=%1$I.review_access_clock(floor_ms);
            IF now_ms>=wanted_create THEN RAISE EXCEPTION 'review preparation expired' USING ERRCODE='23514'; END IF;
            RETURN %1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
        END;
        $function$;

        -- Closed guard transitions never acquire account/broker locks later.
        -- The application must commit admission before releasing its DB client
        -- and awaiting real password/signature work. Checking is UNKNOWN.
        CREATE FUNCTION %1$I.review_access_transition(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_preparation uuid,wanted_request uuid,wanted_operation smallint,wanted_digest bytea,wanted_generation bigint,
            transition text)
        RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_preparations; next_state text; now_ms bigint; floor_ms bigint;
        BEGIN
            captured:=%1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
            floor_ms:=%1$I.review_access_clock(GREATEST(captured.created_ms,captured.prepared_ms));
            IF wanted_preparation IS NULL OR wanted_request IS NULL OR wanted_operation IS NULL OR wanted_digest IS NULL
              OR wanted_generation IS NULL OR captured.preparation_id IS DISTINCT FROM wanted_preparation
              OR captured.request_id IS DISTINCT FROM wanted_request OR captured.operation IS DISTINCT FROM wanted_operation
              OR captured.request_digest IS DISTINCT FROM wanted_digest OR captured.generation IS DISTINCT FROM wanted_generation THEN
                RAISE EXCEPTION 'exact review preparation unavailable' USING ERRCODE='23514';
            END IF;
            IF transition='confirm' AND captured.state='prepared' AND floor_ms<captured.create_deadline_ms THEN next_state:='confirmed';
            ELSIF transition='claim' AND captured.state='confirmed' AND floor_ms<captured.create_deadline_ms THEN next_state:='checking';
            ELSIF transition='cancel' AND captured.state IN ('prepared','confirmed','checking') THEN next_state:='cancelled_no_effect';
            ELSIF transition='reject_rolled_back' AND captured.state='checking' THEN next_state:='rejected_no_effect';
            ELSIF transition='inspect' OR (transition='cancel' AND captured.state IN ('committed','cancelled_no_effect','rejected_no_effect'))
                OR (transition='confirm' AND captured.state='confirmed' AND floor_ms<captured.create_deadline_ms) THEN
                RETURN captured.state;
            ELSE RAISE EXCEPTION 'review guard busy or unknown' USING ERRCODE='55P03';
            END IF;
            UPDATE %1$I.review_access_preparations SET state=next_state WHERE browser_digest=wanted_browser;
            now_ms:=%1$I.review_access_clock(floor_ms);
            IF next_state IN ('confirmed','checking') AND now_ms>=captured.create_deadline_ms THEN
                RAISE EXCEPTION 'review preparation expired during transition' USING ERRCODE='23514';
            END IF;
            RETURN next_state;
        END;
        $function$;

        -- SQL trusts the actual application password-check boundary. Calling
        -- this wrapper does not itself verify a password or a Rust witness.
        -- The supplied owned verifier/revision/config snapshot is compared to
        -- the locked current row before and after all staged allocation writes.
        CREATE FUNCTION %1$I.review_access_login(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_preparation uuid,wanted_request uuid,wanted_operation smallint,wanted_digest bytea,wanted_generation bigint,
            wanted_broker uuid,wanted_credential uuid,wanted_credential_revision bigint,wanted_verifier text,
            wanted_broker_session uuid,wanted_event uuid,wanted_broker_token bytea,wanted_broker_csrf bytea,
            wanted_account uuid,wanted_user uuid,wanted_owner_session uuid,wanted_owner_token bytea,wanted_owner_csrf bytea,
            wanted_locator bytea,wanted_checked_floor bigint)
        RETURNS %1$I.review_access_authentications
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' SET statement_timeout TO '5s' AS $function$
        DECLARE guard %1$I.review_access_preparations; broker %1$I.review_brokers;
            now_ms bigint; floor_ms bigint; expiry_ms bigint; broker_slot smallint; result_hash bytea;
            result %1$I.review_access_authentications; actual_account uuid; actual_user uuid; provisioned_floor bigint;
        BEGIN
            IF pg_catalog.current_setting('transaction_isolation')<>'read committed' OR wanted_operation IS NULL
              OR wanted_operation NOT IN (1,2) THEN RAISE EXCEPTION 'review login unavailable' USING ERRCODE='25001'; END IF;
            IF wanted_operation=1 THEN
                IF wanted_account IS NULL OR wanted_user IS NULL OR wanted_owner_session IS NULL THEN
                    RAISE EXCEPTION 'prospective review identity required' USING ERRCODE='23514';
                END IF;
                IF NOT pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(wanted_account)) THEN
                    RAISE EXCEPTION 'review candidate account busy' USING ERRCODE='55P03';
                END IF;
            ELSIF wanted_account IS NOT NULL OR wanted_user IS NOT NULL OR wanted_owner_session IS NOT NULL
                OR wanted_owner_token IS NOT NULL OR wanted_owner_csrf IS NOT NULL OR wanted_locator IS NOT NULL THEN
                RAISE EXCEPTION 'broker-only login has no owner candidates' USING ERRCODE='23514';
            END IF;
            guard:=%1$I.review_access_guard_lock(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision,wanted_browser);
            floor_ms:=%1$I.review_access_clock(GREATEST(guard.prepared_ms,wanted_checked_floor));
            IF wanted_checked_floor IS NULL OR wanted_checked_floor<guard.prepared_ms THEN
                RAISE EXCEPTION 'owned password clock floor required' USING ERRCODE='23514';
            END IF;
            IF guard.state<>'checking' OR guard.preparation_id IS DISTINCT FROM wanted_preparation
              OR guard.request_id IS DISTINCT FROM wanted_request OR guard.operation IS DISTINCT FROM wanted_operation
              OR guard.request_digest IS DISTINCT FROM wanted_digest OR guard.generation IS DISTINCT FROM wanted_generation
              OR floor_ms>=guard.create_deadline_ms THEN
                RAISE EXCEPTION 'exact checking review login unavailable' USING ERRCODE='23514';
            END IF;
            SELECT * INTO STRICT broker FROM %1$I.review_brokers WHERE id=wanted_broker AND realm_id=wanted_realm FOR UPDATE NOWAIT;
            IF broker.disabled_ms IS NOT NULL OR broker.credential_id IS DISTINCT FROM wanted_credential
              OR broker.credential_revision IS DISTINCT FROM wanted_credential_revision
              OR broker.password_verifier IS DISTINCT FROM wanted_verifier THEN
                RAISE EXCEPTION 'checked review credential changed' USING ERRCODE='23514';
            END IF;
            SELECT s::smallint INTO broker_slot FROM generate_series(1,128) s
              WHERE NOT EXISTS(SELECT FROM %1$I.review_broker_sessions b WHERE b.broker_id=wanted_broker AND b.slot=s)
              ORDER BY s LIMIT 1;
            IF broker_slot IS NULL THEN RAISE EXCEPTION 'review broker capacity reached' USING ERRCODE='54000'; END IF;
            now_ms:=%1$I.review_access_clock(floor_ms);
            expiry_ms:=LEAST(now_ms+1209600000,guard.browser_expires_ms,guard.delivery_deadline_ms);
            IF now_ms>=guard.create_deadline_ms OR now_ms>=expiry_ms THEN
                RAISE EXCEPTION 'review login expired before allocation' USING ERRCODE='23514';
            END IF;
            floor_ms:=now_ms;
            INSERT INTO %1$I.review_broker_sessions(id,realm_id,broker_id,authentication_event_id,credential_revision,
                slot,token_digest,browser_binding,origin,issued_ms,expires_ms,last_used_ms)
              VALUES(wanted_broker_session,wanted_realm,wanted_broker,wanted_event,wanted_credential_revision,
                broker_slot,wanted_broker_token,wanted_browser,wanted_origin,now_ms,expiry_ms,now_ms);
            result_hash:=sha256(wanted_digest||uuid_send(wanted_broker)||uuid_send(wanted_credential)
                ||int8send(wanted_credential_revision)||uuid_send(wanted_broker_session)||uuid_send(wanted_event));
            IF wanted_operation=1 THEN
                PERFORM %1$I.review_workspace_reserve(wanted_preparation,wanted_account,wanted_user,
                    wanted_broker_session,wanted_event,wanted_credential_revision,wanted_locator,wanted_digest,wanted_origin);
                SELECT p.account_id,p.user_id INTO STRICT actual_account,actual_user FROM %1$I.review_workspace_provision(
                    wanted_preparation,wanted_broker_session,wanted_event,wanted_credential_revision,wanted_locator,wanted_digest,wanted_origin) p;
                IF actual_account IS DISTINCT FROM wanted_account OR actual_user IS DISTINCT FROM wanted_user THEN
                    RAISE EXCEPTION 'exact initial workspace required' USING ERRCODE='23514';
                END IF;
                SELECT provisioned_ms INTO STRICT provisioned_floor FROM %1$I.review_bootstrap_attempts WHERE id=wanted_preparation;
                floor_ms:=%1$I.review_access_clock(GREATEST(floor_ms,provisioned_floor));
                IF floor_ms>=guard.create_deadline_ms OR floor_ms>=expiry_ms THEN
                    RAISE EXCEPTION 'review login expired during workspace provision' USING ERRCODE='23514';
                END IF;
                INSERT INTO %1$I.review_access_sessions(id,realm_id,account_id,user_id,broker_id,credential_id,credential_revision,
                    broker_session_id,authentication_event_id,browser_digest,delivery_generation,auth_key_commitment,
                    config_revision,config_digest,origin,slot,token_digest,csrf_digest,source,source_request_id,
                    bootstrap_attempt_id,source_result_digest,issued_ms,expires_ms,last_used_ms)
                  VALUES(wanted_owner_session,wanted_realm,wanted_account,wanted_user,wanted_broker,wanted_credential,wanted_credential_revision,
                    wanted_broker_session,wanted_event,wanted_browser,wanted_generation,wanted_key,wanted_revision,wanted_config,
                    wanted_origin,1,wanted_owner_token,wanted_owner_csrf,1,wanted_request,wanted_preparation,result_hash,now_ms,expiry_ms,now_ms);
                INSERT INTO %1$I.review_access_locators(account_id,user_id,realm_id,broker_id,origin,locator_digest,
                    auth_key_commitment,config_digest,config_revision,preparation_id,request_id,generation,created_ms)
                  VALUES(wanted_account,wanted_user,wanted_realm,wanted_broker,wanted_origin,wanted_locator,
                    wanted_key,wanted_config,wanted_revision,wanted_preparation,wanted_request,wanted_generation,guard.prepared_ms);
            END IF;
            INSERT INTO %1$I.review_access_authentications(preparation_id,request_id,operation,realm_id,broker_id,credential_id,
                credential_revision,broker_session_id,authentication_event_id,broker_csrf_digest,browser_digest,generation,
                request_digest,result_digest,config_revision,config_digest,auth_key_commitment,origin,issued_ms,delivery_deadline_ms,
                account_id,user_id,owner_session_id,bootstrap_attempt_id)
              VALUES(wanted_preparation,wanted_request,wanted_operation,wanted_realm,wanted_broker,wanted_credential,
                wanted_credential_revision,wanted_broker_session,wanted_event,wanted_broker_csrf,wanted_browser,wanted_generation,
                wanted_digest,result_hash,wanted_revision,wanted_config,wanted_key,wanted_origin,now_ms,expiry_ms,
                wanted_account,wanted_user,wanted_owner_session,CASE WHEN wanted_operation=1 THEN wanted_preparation ELSE NULL END);
            UPDATE %1$I.review_access_preparations SET state='committed',active_broker_generation=wanted_generation,
                active_owner_generation=CASE WHEN wanted_operation=1 THEN wanted_generation ELSE active_owner_generation END,
                locator_pending=(wanted_operation=1) WHERE browser_digest=wanted_browser;
            -- All constraints, relation locks and FK/unique arbitration above
            -- may have waited. Retain the actual marker/prep/broker locks and
            -- recheck trusted clock and exact immutable current rows last.
            now_ms:=%1$I.review_access_clock(floor_ms);
            PERFORM %1$I.review_access_marker(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision);
            PERFORM %1$I.review_workspace_current_session(wanted_broker_session,wanted_event,wanted_credential_revision,wanted_origin,true);
            IF now_ms>=guard.create_deadline_ms OR now_ms>=expiry_ms OR NOT EXISTS(
                SELECT FROM %1$I.review_brokers b WHERE b.id=wanted_broker AND b.credential_id=wanted_credential
                    AND b.credential_revision=wanted_credential_revision AND b.password_verifier=wanted_verifier AND b.disabled_ms IS NULL)
                OR (wanted_operation=1 AND NOT EXISTS(SELECT FROM %1$I.accounts a JOIN %1$I.memberships m ON m.account_id=a.id
                    JOIN %1$I.users u ON u.id=m.user_id WHERE a.id=wanted_account AND u.id=wanted_user
                    AND a.disabled_at IS NULL AND m.role='owner' AND m.revoked_at IS NULL)) THEN
                RAISE EXCEPTION 'review login final fence unavailable' USING ERRCODE='23514';
            END IF;
            SELECT * INTO STRICT result FROM %1$I.review_access_authentications WHERE preparation_id=wanted_preparation;
            now_ms:=%1$I.review_access_clock(now_ms);
            IF now_ms>=guard.create_deadline_ms OR now_ms>=expiry_ms THEN
                RAISE EXCEPTION 'review login final read expired' USING ERRCODE='23514';
            END IF;
            RETURN result;
        END;
        $function$;
        -- These authenticated currentness wrappers never issue ordinary auth
        -- sessions or satisfy ordinary MFA. The mutation flag elects stronger
        -- locks up front; it grants no operation or write permission itself.
        CREATE FUNCTION %1$I.review_access_account_lock(wanted_account uuid,wanted_user uuid,mutation boolean)
        RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE floor_ms bigint; anchor %1$I.payload_profile_account_anchors;
        BEGIN
            IF current_setting('transaction_isolation')<>'read committed' OR mutation IS NULL
              OR wanted_account IS NULL OR wanted_user IS NULL THEN
                RAISE EXCEPTION 'review account transaction unavailable' USING ERRCODE='23514'; END IF;
            IF mutation THEN
                IF NOT pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(wanted_account)) THEN
                    RAISE EXCEPTION 'review account busy' USING ERRCODE='55P03'; END IF;
            ELSIF NOT pg_try_advisory_xact_lock_shared(%1$I.payload_profile_account_fence_key(wanted_account)) THEN
                RAISE EXCEPTION 'review account busy' USING ERRCODE='55P03';
            END IF;
            SELECT * INTO STRICT anchor FROM %1$I.payload_profile_account_anchors WHERE account_id=wanted_account FOR SHARE NOWAIT;
            IF anchor.state<>'live' THEN RAISE EXCEPTION 'review account deleted' USING ERRCODE='23514'; END IF;
            -- Existing authority precedes account to match ordinary admission.
            IF mutation THEN
                PERFORM account_id FROM %1$I.sealed_manifest_authorities WHERE account_id=wanted_account FOR UPDATE NOWAIT;
                PERFORM id FROM %1$I.accounts WHERE id=wanted_account AND disabled_at IS NULL FOR UPDATE NOWAIT;
            ELSE
                PERFORM account_id FROM %1$I.sealed_manifest_authorities WHERE account_id=wanted_account FOR SHARE NOWAIT;
                PERFORM id FROM %1$I.accounts WHERE id=wanted_account AND disabled_at IS NULL FOR SHARE NOWAIT;
            END IF;
            IF NOT FOUND THEN RAISE EXCEPTION 'review account inactive' USING ERRCODE='23514'; END IF;
            IF mutation THEN
                PERFORM id FROM %1$I.users WHERE id=wanted_user FOR UPDATE NOWAIT;
            ELSE
                PERFORM id FROM %1$I.users WHERE id=wanted_user FOR SHARE NOWAIT;
            END IF;
            IF NOT FOUND THEN RAISE EXCEPTION 'review user unavailable' USING ERRCODE='23514'; END IF;
            PERFORM user_id FROM %1$I.memberships WHERE account_id=wanted_account AND user_id=wanted_user
              AND role='owner' AND revoked_at IS NULL FOR SHARE NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'review membership unavailable' USING ERRCODE='23514'; END IF;
            floor_ms:=%1$I.review_access_clock(0);
            RETURN floor_ms;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_broker_current(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_session uuid,wanted_token bytea,wanted_csrf bytea,mutation boolean)
        RETURNS %1$I.review_access_authentications
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_authentications; locked %1$I.review_access_authentications;
          guard %1$I.review_access_preparations; broker %1$I.review_brokers; parent %1$I.review_broker_sessions;
          floor_ms bigint; now_ms bigint;
        BEGIN
            IF mutation IS NULL OR current_setting('transaction_isolation')<>'read committed' THEN
                RAISE EXCEPTION 'review currentness transaction unavailable' USING ERRCODE='23514'; END IF;
            SELECT * INTO STRICT captured FROM %1$I.review_access_authentications WHERE broker_session_id=wanted_session;
            floor_ms:=%1$I.review_access_clock(0);
            IF captured.operation=1 THEN
                floor_ms:=%1$I.review_access_account_lock(captured.account_id,captured.user_id,mutation);
            ELSIF captured.operation<>2 OR captured.account_id IS NOT NULL OR captured.user_id IS NOT NULL THEN
                RAISE EXCEPTION 'review broker branch unavailable' USING ERRCODE='23514';
            END IF;
            floor_ms:=GREATEST(floor_ms,%1$I.review_access_marker(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,wanted_revision));
            IF mutation THEN
                SELECT * INTO STRICT guard FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser FOR UPDATE NOWAIT;
            ELSE
                SELECT * INTO STRICT guard FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser FOR SHARE NOWAIT;
            END IF;
            SELECT * INTO STRICT broker FROM %1$I.review_brokers WHERE id=captured.broker_id FOR SHARE NOWAIT;
            SELECT * INTO STRICT parent FROM %1$I.review_broker_sessions WHERE id=wanted_session FOR SHARE NOWAIT;
            SELECT * INTO STRICT locked FROM %1$I.review_access_authentications WHERE broker_session_id=wanted_session FOR SHARE NOWAIT;
            IF locked IS DISTINCT FROM captured OR locked.realm_id IS DISTINCT FROM wanted_realm
              OR locked.origin IS DISTINCT FROM wanted_origin OR locked.auth_key_commitment IS DISTINCT FROM wanted_key
              OR locked.config_digest IS DISTINCT FROM wanted_config OR locked.config_revision IS DISTINCT FROM wanted_revision
              OR locked.browser_digest IS DISTINCT FROM wanted_browser OR locked.broker_csrf_digest IS DISTINCT FROM wanted_csrf
              OR broker.realm_id IS DISTINCT FROM wanted_realm OR broker.credential_id IS DISTINCT FROM locked.credential_id
              OR broker.credential_revision IS DISTINCT FROM locked.credential_revision OR broker.disabled_ms IS NOT NULL
              OR parent.broker_id IS DISTINCT FROM locked.broker_id OR parent.realm_id IS DISTINCT FROM wanted_realm
              OR parent.authentication_event_id IS DISTINCT FROM locked.authentication_event_id
              OR parent.credential_revision IS DISTINCT FROM locked.credential_revision
              OR parent.browser_binding IS DISTINCT FROM wanted_browser OR parent.origin IS DISTINCT FROM wanted_origin
              OR parent.token_digest IS DISTINCT FROM wanted_token OR parent.revoked_ms IS NOT NULL
              OR guard.realm_id IS DISTINCT FROM wanted_realm OR guard.database_commitment IS DISTINCT FROM wanted_database
              OR guard.origin IS DISTINCT FROM wanted_origin OR guard.auth_key_commitment IS DISTINCT FROM wanted_key
              OR guard.config_digest IS DISTINCT FROM wanted_config OR guard.config_revision IS DISTINCT FROM wanted_revision
              OR guard.active_broker_generation IS DISTINCT FROM locked.generation THEN
                RAISE EXCEPTION 'review broker currentness unavailable' USING ERRCODE='23514'; END IF;
            now_ms:=%1$I.review_access_clock(GREATEST(floor_ms,parent.last_used_ms,locked.issued_ms,guard.created_ms));
            IF now_ms>=parent.expires_ms OR now_ms-parent.last_used_ms>=259200000
              OR now_ms>=locked.delivery_deadline_ms OR now_ms>=guard.browser_expires_ms THEN
                RAISE EXCEPTION 'review broker expired' USING ERRCODE='23514'; END IF;
            RETURN locked;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_owner_current(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_broker_session uuid,wanted_broker_token bytea,wanted_broker_csrf bytea,
            wanted_owner_session uuid,wanted_owner_token bytea,wanted_owner_csrf bytea,mutation boolean)
        RETURNS %1$I.review_access_sessions
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE captured %1$I.review_access_sessions; locked %1$I.review_access_sessions;
          auth %1$I.review_access_authentications; guard %1$I.review_access_preparations; now_ms bigint; floor_ms bigint;
        BEGIN
            SELECT * INTO STRICT captured FROM %1$I.review_access_sessions WHERE id=wanted_owner_session;
            IF NOT EXISTS(SELECT FROM %1$I.review_access_authentications a WHERE a.broker_session_id=wanted_broker_session
                AND a.account_id=captured.account_id AND a.user_id=captured.user_id AND a.owner_session_id=captured.id) THEN
                RAISE EXCEPTION 'review owner broker association unavailable' USING ERRCODE='23514'; END IF;
            floor_ms:=%1$I.review_access_account_lock(captured.account_id,captured.user_id,mutation);
            auth:=%1$I.review_access_broker_current(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,
                wanted_revision,wanted_browser,wanted_broker_session,wanted_broker_token,wanted_broker_csrf,mutation);
            SELECT * INTO STRICT locked FROM %1$I.review_access_sessions WHERE id=wanted_owner_session FOR SHARE NOWAIT;
            SELECT * INTO STRICT guard FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser;
            IF locked IS DISTINCT FROM captured OR locked.account_id IS DISTINCT FROM auth.account_id
              OR locked.user_id IS DISTINCT FROM auth.user_id OR locked.id IS DISTINCT FROM auth.owner_session_id
              OR locked.realm_id IS DISTINCT FROM wanted_realm OR locked.origin IS DISTINCT FROM wanted_origin
              OR locked.config_digest IS DISTINCT FROM wanted_config OR locked.config_revision IS DISTINCT FROM wanted_revision
              OR locked.auth_key_commitment IS DISTINCT FROM wanted_key OR locked.browser_digest IS DISTINCT FROM wanted_browser
              OR locked.broker_id IS DISTINCT FROM auth.broker_id OR locked.credential_id IS DISTINCT FROM auth.credential_id
              OR locked.credential_revision IS DISTINCT FROM auth.credential_revision
              OR locked.broker_session_id IS DISTINCT FROM wanted_broker_session
              OR locked.authentication_event_id IS DISTINCT FROM auth.authentication_event_id
              OR locked.delivery_generation IS DISTINCT FROM auth.generation OR guard.active_owner_generation IS DISTINCT FROM locked.delivery_generation
              OR locked.token_digest IS DISTINCT FROM wanted_owner_token OR locked.csrf_digest IS DISTINCT FROM wanted_owner_csrf
              OR locked.source<>1 OR locked.revoked_ms IS NOT NULL OR NOT EXISTS(
                SELECT FROM %1$I.review_workspaces w WHERE w.account_id=locked.account_id AND w.user_id=locked.user_id
                  AND w.realm_id=wanted_realm AND w.broker_id=locked.broker_id AND w.creating_attempt_id=locked.bootstrap_attempt_id) THEN
                RAISE EXCEPTION 'review owner currentness unavailable' USING ERRCODE='23514'; END IF;
            now_ms:=%1$I.review_access_clock(GREATEST(floor_ms,locked.last_used_ms,auth.issued_ms));
            IF now_ms>=locked.expires_ms OR now_ms-locked.last_used_ms>=259200000 OR now_ms>=auth.delivery_deadline_ms
              OR now_ms>=guard.browser_expires_ms THEN
                RAISE EXCEPTION 'review owner expired' USING ERRCODE='23514'; END IF;
            RETURN locked;
        END;
        $function$;

        CREATE FUNCTION %1$I.review_access_owner_settlement(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_broker_session uuid,wanted_broker_token bytea,wanted_broker_csrf bytea,
            wanted_owner_session uuid,wanted_owner_token bytea,wanted_owner_csrf bytea,
            action text,wanted_preparation uuid,wanted_request uuid,wanted_generation bigint,wanted_digest bytea,
            wanted_locator bytea,wanted_selector bytea)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE owner_row %1$I.review_access_sessions; guard %1$I.review_access_preparations;
          selector %1$I.review_access_locators; now_ms bigint; floor_ms bigint; changed bigint;
        BEGIN
            IF action IS NULL OR action NOT IN ('delivery_ack','locator_context','locator_ack','locator_status') THEN
                RAISE EXCEPTION 'unsupported review settlement' USING ERRCODE='23514'; END IF;
            owner_row:=%1$I.review_access_owner_current(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,
                wanted_revision,wanted_browser,wanted_broker_session,wanted_broker_token,wanted_broker_csrf,
                wanted_owner_session,wanted_owner_token,wanted_owner_csrf,true);
            SELECT * INTO STRICT guard FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser;
            floor_ms:=%1$I.review_access_clock(owner_row.last_used_ms);
            IF action='delivery_ack' THEN
                IF guard.state<>'committed' OR guard.preparation_id IS DISTINCT FROM wanted_preparation
                  OR guard.request_id IS DISTINCT FROM wanted_request OR guard.generation IS DISTINCT FROM wanted_generation
                  OR guard.prepared_csrf_digest IS DISTINCT FROM wanted_digest OR floor_ms>=guard.delivery_deadline_ms
                  OR NOT ((guard.operation=1 AND EXISTS(SELECT FROM %1$I.review_access_authentications a
                    WHERE a.preparation_id=wanted_preparation AND a.owner_session_id=owner_row.id AND a.request_id=wanted_request))
                    OR (guard.operation=4 AND EXISTS(SELECT FROM %1$I.review_access_root_reauth r WHERE r.preparation_id=wanted_preparation
                        AND r.request_id=wanted_request AND r.owner_session_id=owner_row.id))
                    OR (guard.operation=5 AND EXISTS(SELECT FROM %1$I.review_access_root_reauth r WHERE r.completion_preparation_id=wanted_preparation
                        AND r.completion_request_id=wanted_request AND r.owner_session_id=owner_row.id AND r.state='consumed'))) THEN
                    RAISE EXCEPTION 'review delivery result unavailable' USING ERRCODE='23514'; END IF;
                IF NOT guard.delivered THEN
                    UPDATE %1$I.review_access_preparations SET delivered=true WHERE browser_digest=wanted_browser;
                END IF;
            ELSE
                SELECT * INTO STRICT selector FROM %1$I.review_access_locators WHERE account_id=owner_row.account_id FOR UPDATE NOWAIT;
                IF selector.user_id IS DISTINCT FROM owner_row.user_id OR selector.realm_id IS DISTINCT FROM wanted_realm
                  OR selector.broker_id IS DISTINCT FROM owner_row.broker_id OR selector.origin IS DISTINCT FROM wanted_origin
                  OR selector.auth_key_commitment IS DISTINCT FROM wanted_key OR selector.config_digest IS DISTINCT FROM wanted_config
                  OR selector.config_revision IS DISTINCT FROM wanted_revision OR selector.preparation_id IS DISTINCT FROM wanted_preparation
                  OR floor_ms<selector.created_ms OR wanted_request IS NULL OR wanted_request='00000000-0000-0000-0000-000000000000'
                  OR wanted_selector IS NULL OR octet_length(wanted_selector)<>32 THEN
                    RAISE EXCEPTION 'review locator association unavailable' USING ERRCODE='23514'; END IF;
                IF action IN ('locator_context','locator_ack') AND selector.locator_digest IS DISTINCT FROM wanted_locator THEN
                    RAISE EXCEPTION 'review locator possession unavailable' USING ERRCODE='23514'; END IF;
                IF action='locator_ack' AND selector.retained_ms IS NULL THEN
                    IF guard.state<>'committed' OR guard.operation<>1 OR guard.preparation_id<>wanted_preparation
                      OR NOT guard.delivered OR NOT guard.locator_pending THEN
                        RAISE EXCEPTION 'review locator delivery unavailable' USING ERRCODE='23514'; END IF;
                    UPDATE %1$I.review_access_locators SET retained_request_id=wanted_request,
                        retained_selector_digest=wanted_selector,retained_ms=floor_ms WHERE account_id=owner_row.account_id;
                    GET DIAGNOSTICS changed=ROW_COUNT;
                    IF changed<>1 THEN RAISE EXCEPTION 'review locator lost' USING ERRCODE='23514'; END IF;
                    UPDATE %1$I.review_access_preparations SET locator_pending=false WHERE browser_digest=wanted_browser;
                ELSIF action IN ('locator_ack','locator_status') THEN
                    IF selector.retained_ms IS NULL OR selector.retained_request_id IS DISTINCT FROM wanted_request
                      OR selector.retained_selector_digest IS DISTINCT FROM wanted_selector THEN
                        RAISE EXCEPTION 'review locator acknowledgement unavailable' USING ERRCODE='23514'; END IF;
                END IF;
            END IF;
            owner_row:=%1$I.review_access_owner_current(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,
                wanted_revision,wanted_browser,wanted_broker_session,wanted_broker_token,wanted_broker_csrf,
                wanted_owner_session,wanted_owner_token,wanted_owner_csrf,true);
            now_ms:=%1$I.review_access_clock(floor_ms);
            IF action='delivery_ack' AND now_ms>=guard.delivery_deadline_ms THEN
                RAISE EXCEPTION 'review delivery expired after settlement' USING ERRCODE='23514'; END IF;
            RETURN action<>'locator_context' OR selector.retained_ms IS NOT NULL;
        END;
        $function$;
        -- The application must supply genuine verified root/custody signatures
        -- through its private same-transaction witness. SQL owns all mutable
        -- identity, one-use, deadline and atomic persistence checks; this helper
        -- does not claim PostgreSQL verifies P-256 or a password itself.
        CREATE FUNCTION %1$I.review_access_root_commit(wanted_realm uuid,wanted_database bytea,wanted_origin text,
            wanted_key bytea,wanted_config bytea,wanted_revision bigint,wanted_browser bytea,
            wanted_broker_session uuid,wanted_broker_token bytea,wanted_broker_csrf bytea,
            wanted_owner_session uuid,wanted_owner_token bytea,wanted_owner_csrf bytea,
            wanted_preparation uuid,wanted_request uuid,wanted_generation bigint,wanted_digest bytea,material jsonb,
            checked_principal uuid,checked_credential uuid,checked_revision bigint,checked_verifier text,checked_floor bigint)
        RETURNS %1$I.review_access_root_reauth
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE owner_row %1$I.review_access_sessions; guard %1$I.review_access_preparations;
          reauth %1$I.review_access_root_reauth; challenge record;
          now_ms bigint; floor_ms bigint; expiry_ms bigint; retain_ms bigint; keys text[]; changed bigint;
          pin bytea; fingerprint bytea; unsigned bytea; statement bytea; root_nonce bytea; nonce bytea;
          backup bytea; card bytea; enrollment_signature bytea; custody_signature bytea; root_id uuid; reauth_id uuid;
        BEGIN
            owner_row:=%1$I.review_access_owner_current(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,
                wanted_revision,wanted_browser,wanted_broker_session,wanted_broker_token,wanted_broker_csrf,
                wanted_owner_session,wanted_owner_token,wanted_owner_csrf,true);
            SELECT * INTO STRICT guard FROM %1$I.review_access_preparations WHERE browser_digest=wanted_browser;
            floor_ms:=%1$I.review_access_clock(GREATEST(owner_row.last_used_ms,guard.prepared_ms));
            IF guard.preparation_id IS DISTINCT FROM wanted_preparation OR guard.request_id IS DISTINCT FROM wanted_request
              OR guard.generation IS DISTINCT FROM wanted_generation OR guard.request_digest IS DISTINCT FROM wanted_digest
              OR guard.operation NOT IN (4,5) OR guard.state<>'checking' OR floor_ms>=guard.create_deadline_ms
              OR jsonb_typeof(material) IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION 'review root request unavailable' USING ERRCODE='23514'; END IF;
            SELECT array_agg(k ORDER BY k) INTO keys FROM jsonb_object_keys(material) k;
            IF guard.operation=4 THEN
                IF checked_principal IS NOT NULL OR checked_credential IS NOT NULL OR checked_revision IS NOT NULL
                  OR checked_verifier IS NOT NULL OR checked_floor IS NOT NULL THEN
                    RAISE EXCEPTION 'root issuance cannot invent reauthentication' USING ERRCODE='23514'; END IF;
                IF keys IS DISTINCT FROM ARRAY['backup_digest','card_digest','expires','fingerprint','issued','nonce','pin',
                    'reauth','reauth_nonce','retain','root','statement','unsigned']::text[] THEN
                    RAISE EXCEPTION 'review root issue shape unavailable' USING ERRCODE='23514'; END IF;
                IF EXISTS(SELECT FROM %1$I.sealed_manifest_authorities WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_enrollments WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_receipts WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_custody WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.known_signing_point_reservations WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.known_signing_role_claims WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_challenges WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.review_access_root_reauth WHERE account_id=owner_row.account_id) THEN
                    RAISE EXCEPTION 'review root history exists' USING ERRCODE='23514'; END IF;
                pin:=decode(material->>'pin','hex'); fingerprint:=decode(material->>'fingerprint','hex');
                unsigned:=decode(material->>'unsigned','hex'); statement:=decode(material->>'statement','hex');
                root_nonce:=decode(material->>'nonce','hex'); nonce:=decode(material->>'reauth_nonce','hex');
                root_id:=(material->>'root')::uuid; reauth_id:=(material->>'reauth')::uuid;
                now_ms:=(material->>'issued')::bigint; expiry_ms:=(material->>'expires')::bigint; retain_ms:=(material->>'retain')::bigint;
                IF now_ms<guard.prepared_ms OR now_ms>%1$I.review_access_clock(floor_ms) OR expiry_ms<=floor_ms
                  OR expiry_ms>LEAST(now_ms+300000,guard.create_deadline_ms,guard.delivery_deadline_ms,owner_row.expires_ms)
                  OR retain_ms<expiry_ms OR retain_ms>LEAST(now_ms+604800000,guard.delivery_deadline_ms,owner_row.expires_ms)
                  OR root_id IS NULL OR root_id='00000000-0000-0000-0000-000000000000' OR reauth_id IS NULL OR reauth_id=root_id
                  OR octet_length(root_nonce)<>32 OR octet_length(nonce)<>32 OR octet_length(pin)<>94
                  OR substring(pin FROM 1 FOR 5)<>decode('5a54525002','hex')
                  OR substring(pin FROM 6 FOR 16)<>uuid_send(owner_row.account_id)
                  OR substring(pin FROM 22 FOR 8)<>int8send(1::bigint)
                  OR fingerprint IS DISTINCT FROM sha256(convert_to('ZTSE/root-pin/v2','UTF8')||decode('00','hex')||pin)
                  OR substring(unsigned FROM 1 FOR 5)<>decode('5a54524501','hex')
                  OR substring(unsigned FROM 6 FOR 16)<>uuid_send(owner_row.account_id)
                  OR substring(unsigned FROM 22 FOR 16)<>uuid_send(owner_row.user_id)
                  OR substring(unsigned FROM 38 FOR 16)<>uuid_send(owner_row.id)
                  OR substring(unsigned FROM 54 FOR 16)<>uuid_send(root_id)
                  OR substring(unsigned FROM 70 FOR 32)<>root_nonce OR substring(unsigned FROM 102 FOR 32)<>fingerprint
                  OR substring(unsigned FROM 134 FOR 8)<>int8send(now_ms) OR substring(unsigned FROM 142 FOR 8)<>int8send(expiry_ms)
                  OR substring(unsigned FROM 150 FOR 2)<>int2send(octet_length(wanted_origin)::smallint)
                  OR substring(unsigned FROM 152)<>convert_to(wanted_origin,'UTF8') THEN
                    RAISE EXCEPTION 'review root issue transcript unavailable' USING ERRCODE='23514'; END IF;
                INSERT INTO %1$I.sealed_root_challenges(account_id,challenge_id,user_id,session_id,root_pin,root_fingerprint,
                    nonce_digest,origin,issued_ms,expires_ms)
                  VALUES(owner_row.account_id,root_id,owner_row.user_id,owner_row.id,pin,fingerprint,sha256(root_nonce),wanted_origin,now_ms,expiry_ms);
                INSERT INTO %1$I.review_access_root_reauth(id,realm_id,account_id,user_id,owner_session_id,broker_id,credential_id,
                    credential_revision,broker_session_id,authentication_event_id,browser_digest,delivery_generation,config_revision,
                    preparation_id,request_id,request_digest,root_challenge_id,root_pin,root_fingerprint,encrypted_backup_digest,
                    public_card_digest,unsigned_enrollment,custody_statement,statement_digest,nonce_digest,reauth_nonce,origin,
                    issued_ms,expires_ms,retain_until_ms)
                  VALUES(reauth_id,wanted_realm,owner_row.account_id,owner_row.user_id,owner_row.id,owner_row.broker_id,owner_row.credential_id,
                    owner_row.credential_revision,owner_row.broker_session_id,owner_row.authentication_event_id,wanted_browser,
                    owner_row.delivery_generation,wanted_revision,wanted_preparation,wanted_request,wanted_digest,root_id,pin,fingerprint,
                    decode(material->>'backup_digest','hex'),decode(material->>'card_digest','hex'),unsigned,statement,sha256(statement),sha256(nonce),nonce,
                    wanted_origin,now_ms,expiry_ms,retain_ms);
            ELSE
                IF keys IS DISTINCT FROM ARRAY['backup','backup_id','card','custody_signature','enrollment_signature',
                    'nonce','reauth','root','unsigned']::text[] THEN
                    RAISE EXCEPTION 'review root completion shape unavailable' USING ERRCODE='23514'; END IF;
                IF checked_floor IS NULL OR checked_floor<guard.prepared_ms OR checked_verifier IS NULL
                  OR checked_principal IS NULL OR checked_credential IS NULL OR checked_revision IS NULL THEN
                    RAISE EXCEPTION 'checked review password snapshot required' USING ERRCODE='23514'; END IF;
                floor_ms:=GREATEST(floor_ms,checked_floor);
                now_ms:=%1$I.review_access_clock(floor_ms);
                IF NOT EXISTS(SELECT FROM %1$I.review_brokers b WHERE b.id=owner_row.broker_id
                    AND b.id=checked_principal AND b.credential_id=owner_row.credential_id
                    AND b.credential_id=checked_credential AND b.credential_revision=owner_row.credential_revision
                    AND b.credential_revision=checked_revision
                    AND b.password_verifier=checked_verifier AND b.disabled_ms IS NULL) THEN
                    RAISE EXCEPTION 'review checked password snapshot changed' USING ERRCODE='23514'; END IF;
                SELECT * INTO STRICT reauth FROM %1$I.review_access_root_reauth WHERE id=(material->>'reauth')::uuid FOR UPDATE NOWAIT;
                SELECT * INTO STRICT challenge FROM %1$I.sealed_root_challenges WHERE account_id=owner_row.account_id FOR UPDATE NOWAIT;
                unsigned:=decode(material->>'unsigned','hex'); nonce:=decode(material->>'nonce','hex');
                backup:=decode(material->>'backup','hex'); card:=decode(material->>'card','hex');
                enrollment_signature:=decode(material->>'enrollment_signature','hex'); custody_signature:=decode(material->>'custody_signature','hex');
                IF reauth.state<>'pending' OR reauth.owner_session_id<>owner_row.id OR reauth.account_id<>owner_row.account_id
                  OR reauth.user_id<>owner_row.user_id OR reauth.realm_id<>wanted_realm OR reauth.config_revision<>wanted_revision
                  OR reauth.broker_id<>owner_row.broker_id OR reauth.credential_id<>owner_row.credential_id
                  OR reauth.credential_revision<>owner_row.credential_revision OR reauth.broker_session_id<>wanted_broker_session
                  OR reauth.authentication_event_id<>owner_row.authentication_event_id OR reauth.browser_digest<>wanted_browser
                  OR reauth.delivery_generation<>owner_row.delivery_generation OR reauth.origin<>wanted_origin
                  OR reauth.root_challenge_id IS DISTINCT FROM (material->>'root')::uuid
                  OR reauth.unsigned_enrollment IS DISTINCT FROM unsigned OR reauth.nonce_digest IS DISTINCT FROM sha256(nonce)
                  OR reauth.encrypted_backup_digest IS DISTINCT FROM sha256(backup) OR reauth.public_card_digest IS DISTINCT FROM sha256(card)
                  OR challenge.challenge_id<>reauth.root_challenge_id OR challenge.user_id<>owner_row.user_id OR challenge.session_id<>owner_row.id
                  OR challenge.root_pin<>reauth.root_pin OR challenge.root_fingerprint<>reauth.root_fingerprint
                  OR challenge.origin<>wanted_origin OR challenge.nonce_digest<>sha256(substring(unsigned FROM 70 FOR 32))
                  OR challenge.issued_ms<>reauth.issued_ms OR challenge.expires_ms<>reauth.expires_ms OR challenge.consumed_ms IS NOT NULL
                  OR now_ms<reauth.issued_ms OR now_ms>=reauth.expires_ms OR now_ms>=guard.create_deadline_ms
                  OR octet_length(enrollment_signature)<>64 OR octet_length(custody_signature)<>64
                  OR EXISTS(SELECT FROM %1$I.sealed_manifest_authorities WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_enrollments WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_receipts WHERE account_id=owner_row.account_id)
                  OR EXISTS(SELECT FROM %1$I.sealed_root_custody WHERE account_id=owner_row.account_id) THEN
                    RAISE EXCEPTION 'review root completion unavailable' USING ERRCODE='23514'; END IF;
                INSERT INTO %1$I.sealed_manifest_authorities(account_id,root_pin,root_fingerprint,generation,anchor_digest)
                  VALUES(owner_row.account_id,reauth.root_pin,reauth.root_fingerprint,1,decode(repeat('00',32),'hex'));
                now_ms:=%1$I.review_access_clock(now_ms);
                INSERT INTO %1$I.sealed_root_receipts(account_id,user_id,session_id,challenge_id,root_pin,root_fingerprint,completed_ms)
                  VALUES(owner_row.account_id,owner_row.user_id,owner_row.id,reauth.root_challenge_id,reauth.root_pin,reauth.root_fingerprint,now_ms);
                INSERT INTO %1$I.sealed_root_custody(account_id,challenge_id,backup_id,generation,root_pin,root_fingerprint,
                    encrypted_backup,public_card,backup_sha256,card_sha256,committed_ms,unsigned_enrollment,custody_signature)
                  VALUES(owner_row.account_id,reauth.root_challenge_id,(material->>'backup_id')::uuid,1,reauth.root_pin,reauth.root_fingerprint,
                    backup,card,sha256(backup),sha256(card),now_ms,unsigned,custody_signature);
                UPDATE %1$I.sealed_root_challenges SET consumed_ms=now_ms WHERE account_id=owner_row.account_id AND consumed_ms IS NULL;
                GET DIAGNOSTICS changed=ROW_COUNT;
                IF changed<>1 THEN RAISE EXCEPTION 'review root challenge already consumed' USING ERRCODE='23514'; END IF;
                UPDATE %1$I.review_access_root_reauth SET state='consumed',completed_ms=now_ms,result_digest=sha256(unsigned||enrollment_signature||custody_signature),
                    completion_preparation_id=wanted_preparation,completion_request_id=wanted_request,completion_request_digest=wanted_digest WHERE id=reauth.id AND state='pending';
                GET DIAGNOSTICS changed=ROW_COUNT;
                IF changed<>1 THEN RAISE EXCEPTION 'review reauthentication already consumed' USING ERRCODE='23514'; END IF;
                expiry_ms:=reauth.expires_ms;
            END IF;
            UPDATE %1$I.review_access_preparations SET state='committed' WHERE browser_digest=wanted_browser AND state='checking';
            GET DIAGNOSTICS changed=ROW_COUNT;
            IF changed<>1 THEN RAISE EXCEPTION 'review root preparation already disposed' USING ERRCODE='23514'; END IF;
            owner_row:=%1$I.review_access_owner_current(wanted_realm,wanted_database,wanted_origin,wanted_key,wanted_config,
                wanted_revision,wanted_browser,wanted_broker_session,wanted_broker_token,wanted_broker_csrf,
                wanted_owner_session,wanted_owner_token,wanted_owner_csrf,true);
            now_ms:=%1$I.review_access_clock(GREATEST(floor_ms,now_ms));
            IF now_ms>=guard.create_deadline_ms OR now_ms>=expiry_ms THEN
                RAISE EXCEPTION 'review root expired after persistence' USING ERRCODE='23514'; END IF;
            SELECT * INTO STRICT reauth FROM %1$I.review_access_root_reauth WHERE id=COALESCE(reauth_id,reauth.id);
            now_ms:=%1$I.review_access_clock(now_ms);
            IF now_ms>=guard.create_deadline_ms OR now_ms>=expiry_ms THEN
                RAISE EXCEPTION 'review root expired after result' USING ERRCODE='23514'; END IF;
            RETURN reauth;
        END;
        $function$;
        CREATE FUNCTION %1$I.review_access_prune() RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE candidate record; locked_session %1$I.review_access_sessions; guard %1$I.review_access_preparations;
          floor_ms bigint; now_ms bigint; changed bigint:=0; removed bigint;
        BEGIN
            IF current_setting('transaction_isolation')<>'read committed' THEN
                RAISE EXCEPTION 'review cleanup requires current snapshots' USING ERRCODE='23514'; END IF;
            floor_ms:=%1$I.review_access_clock(0);
            FOR candidate IN SELECT id,account_id,user_id,realm_id,broker_id FROM %1$I.review_access_sessions s
              WHERE floor_ms-LEAST(s.expires_ms,s.last_used_ms+259200000,COALESCE(s.revoked_ms,s.expires_ms))>=3600000
              ORDER BY account_id,id LIMIT 32 LOOP
                IF NOT pg_try_advisory_xact_lock(%1$I.payload_profile_account_fence_key(candidate.account_id)) THEN CONTINUE; END IF;
                -- Re-read after the fence: a committed erasure may have removed
                -- the captured child. Every still-bound row requires its anchor.
                SELECT * INTO locked_session FROM %1$I.review_access_sessions WHERE id=candidate.id;
                IF NOT FOUND THEN CONTINUE; END IF;
                IF locked_session.account_id<>candidate.account_id OR locked_session.user_id<>candidate.user_id
                  OR locked_session.realm_id<>candidate.realm_id OR locked_session.broker_id<>candidate.broker_id THEN
                    RAISE EXCEPTION 'review cleanup identity changed' USING ERRCODE='23514'; END IF;
                PERFORM account_id FROM %1$I.payload_profile_account_anchors WHERE account_id=candidate.account_id FOR SHARE NOWAIT;
                IF NOT FOUND THEN RAISE EXCEPTION 'bound review cleanup anchor missing' USING ERRCODE='23514'; END IF;
                PERFORM realm_id FROM %1$I.review_realm_installation WHERE realm_id=candidate.realm_id FOR SHARE NOWAIT;
                PERFORM id FROM %1$I.review_brokers WHERE id=candidate.broker_id FOR UPDATE NOWAIT;
                SELECT * INTO STRICT locked_session FROM %1$I.review_access_sessions WHERE id=candidate.id FOR UPDATE NOWAIT;
                now_ms:=%1$I.review_access_clock(floor_ms);
                IF now_ms-LEAST(locked_session.expires_ms,locked_session.last_used_ms+259200000,
                    COALESCE(locked_session.revoked_ms,locked_session.expires_ms))>=3600000 THEN
                    DELETE FROM %1$I.review_access_sessions WHERE id=candidate.id;
                    GET DIAGNOSTICS removed=ROW_COUNT;changed:=changed+removed;
                END IF;
                floor_ms:=%1$I.review_access_clock(now_ms);
                RETURN changed; -- Never hold this broker while fencing another account.
            END LOOP;
            -- Broker-only results are the one closed NULL-account branch. They
            -- never carry a workspace/user/session admission result.
            FOR candidate IN SELECT preparation_id,broker_id,realm_id FROM %1$I.review_access_authentications
              WHERE operation=2 AND floor_ms-delivery_deadline_ms>=3600000 ORDER BY broker_id,preparation_id LIMIT 32 LOOP
                PERFORM realm_id FROM %1$I.review_realm_installation WHERE realm_id=candidate.realm_id FOR SHARE NOWAIT;
                PERFORM id FROM %1$I.review_brokers WHERE id=candidate.broker_id FOR UPDATE NOWAIT;
                PERFORM preparation_id FROM %1$I.review_access_authentications WHERE preparation_id=candidate.preparation_id FOR UPDATE NOWAIT;
                now_ms:=%1$I.review_access_clock(floor_ms);
                DELETE FROM %1$I.review_access_authentications WHERE preparation_id=candidate.preparation_id AND operation=2
                    AND account_id IS NULL AND user_id IS NULL AND owner_session_id IS NULL AND now_ms-delivery_deadline_ms>=3600000;
                GET DIAGNOSTICS removed=ROW_COUNT;changed:=changed+removed;floor_ms:=%1$I.review_access_clock(now_ms);
                RETURN changed;
            END LOOP;
            FOR candidate IN SELECT id FROM %1$I.review_bootstrap_attempts
              WHERE (state='reserved' AND floor_ms-expires_ms>=3600000)
                 OR (state='provisioned' AND floor_ms-reconcile_until_ms>=3600000)
              ORDER BY reserved_account_id,id LIMIT 32 LOOP
                IF %1$I.review_workspace_attempt_cleanup(candidate.id) THEN changed:=changed+1; END IF;
                floor_ms:=%1$I.review_access_clock(floor_ms);
                RETURN changed;
            END LOOP;
            FOR candidate IN SELECT DISTINCT b.broker_id FROM %1$I.review_broker_sessions b
              WHERE floor_ms-LEAST(b.expires_ms,b.last_used_ms+259200000,COALESCE(b.revoked_ms,b.expires_ms))>=3600000
                AND NOT EXISTS(SELECT FROM %1$I.review_access_sessions s WHERE s.broker_id=b.broker_id)
                AND NOT EXISTS(SELECT FROM %1$I.review_access_authentications a WHERE a.broker_id=b.broker_id)
              ORDER BY b.broker_id LIMIT 32 LOOP
                changed:=changed+%1$I.review_workspace_session_cleanup(candidate.broker_id);
                floor_ms:=%1$I.review_access_clock(floor_ms);
                RETURN changed;
            END LOOP;
            -- Account-free expired guards arbitrate only their own generation.
            -- Atomic business writers cannot remain Checking after COMMIT.
            FOR candidate IN SELECT browser_digest,realm_id FROM %1$I.review_access_preparations
              WHERE floor_ms-browser_expires_ms>=3600000 ORDER BY browser_digest LIMIT 32 LOOP
                PERFORM realm_id FROM %1$I.review_realm_installation WHERE realm_id=candidate.realm_id FOR SHARE NOWAIT;
                SELECT * INTO guard FROM %1$I.review_access_preparations WHERE browser_digest=candidate.browser_digest FOR UPDATE NOWAIT;
                IF NOT FOUND THEN CONTINUE; END IF;
                now_ms:=%1$I.review_access_clock(GREATEST(floor_ms,guard.created_ms,guard.prepared_ms));
                IF now_ms-guard.browser_expires_ms<3600000 THEN CONTINUE; END IF;
                IF guard.state='checking' THEN
                    IF now_ms<guard.create_deadline_ms THEN RAISE EXCEPTION 'review cleanup creation window remains' USING ERRCODE='23514'; END IF;
                    UPDATE %1$I.review_access_preparations SET state='cancelled_no_effect' WHERE browser_digest=candidate.browser_digest;
                END IF;
                DELETE FROM %1$I.review_access_preparations WHERE browser_digest=candidate.browser_digest;
                GET DIAGNOSTICS removed=ROW_COUNT;changed:=changed+removed;floor_ms:=%1$I.review_access_clock(now_ms);
                RETURN changed;
            END LOOP;
            PERFORM %1$I.review_access_clock(floor_ms);
            RETURN changed;
        END;
        $function$;
    $ddl$,installation,installation,
        pg_catalog.format('%I.accounts',installation),pg_catalog.format('%I.users',installation),
        pg_catalog.format('%I.review_realm_installation',installation),pg_catalog.format('%I.review_brokers',installation),
        pg_catalog.format('%I.review_broker_sessions',installation),pg_catalog.format('%I.review_bootstrap_attempts',installation),
        pg_catalog.format('%I.review_workspaces',installation),
        pg_catalog.format('%I.review_access_sessions',installation),pg_catalog.format('%I.review_access_authentications',installation),
        pg_catalog.format('%I.review_access_root_reauth',installation),pg_catalog.format('%I.review_access_locators',installation),
        pg_catalog.format('%I.review_access_preparations',installation));

    FOREACH relation_name IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_access_preparations','review_access_authentications','review_access_sessions',
        'review_access_root_reauth','review_access_locators'] LOOP
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_catalog.pg_attribute
          WHERE attrelid=pg_catalog.to_regclass(pg_catalog.format('%I.%I',installation,relation_name))
            AND attnum>0 AND NOT attisdropped;
        EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC',installation,relation_name);
        EXECUTE pg_catalog.format('REVOKE ALL (%s) ON TABLE %I.%I FROM PUBLIC',columns_sql,installation,relation_name);
        IF installation='public' AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime') THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.%I FROM zrotext_runtime',installation,relation_name);
            EXECUTE pg_catalog.format('REVOKE ALL (%s) ON TABLE %I.%I FROM zrotext_runtime',columns_sql,installation,relation_name);
            EXECUTE pg_catalog.format('GRANT SELECT ON TABLE %I.%I TO zrotext_runtime',installation,relation_name);
        END IF;
    END LOOP;
    FOR routine IN SELECT p.oid::regprocedure AS signature FROM pg_catalog.pg_proc p
      WHERE p.pronamespace=(SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname=installation)
        AND p.proname LIKE 'review_access_%' LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
        IF installation='public' AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime') THEN
            EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
        END IF;
    END LOOP;
    IF installation='public' AND EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime') THEN
        FOREACH signature IN ARRAY ARRAY[
            'public.review_access_prune()',
            'public.review_access_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)',
            'public.review_access_browser(uuid,bytea,text,bytea,bytea,bigint,bytea,bigint,bigint,boolean)',
            'public.review_access_guard_lock(uuid,bytea,text,bytea,bytea,bigint,bytea)',
            'public.review_access_prepare(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,bigint,bigint,bigint,bytea)',
            'public.review_access_transition(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,text)',
            'public.review_access_login(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,uuid,uuid,bigint,text,uuid,uuid,bytea,bytea,uuid,uuid,uuid,bytea,bytea,bytea,bigint)',
            'public.review_access_broker_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_settlement(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,text,uuid,uuid,bigint,bytea,bytea,bytea)',
            'public.review_access_root_commit(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,uuid,uuid,bigint,bytea,jsonb,uuid,uuid,bigint,text,bigint)'
        ] LOOP
            IF pg_catalog.to_regprocedure(signature) IS NULL THEN
                RAISE EXCEPTION 'review access wrapper missing';
            END IF;
            EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',signature);
        END LOOP;
    END IF;
END;
$migration$;
