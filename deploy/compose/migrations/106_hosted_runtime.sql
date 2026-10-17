-- SPDX-License-Identifier: AGPL-3.0-only
-- Isolated hosted runtime. No namespace, mode, price or enabled state is seeded.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
CREATE TABLE hosted_billing_namespaces (
    namespace_id uuid PRIMARY KEY,
    mode text NOT NULL CHECK (mode IN ('test', 'live')),
    provider_account text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    enabled boolean NOT NULL DEFAULT false,
    old_binary_fenced boolean NOT NULL DEFAULT false
);
CREATE FUNCTION hosted_namespace_identity_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_id IS DISTINCT FROM OLD.namespace_id OR
       NEW.mode IS DISTINCT FROM OLD.mode OR
       NEW.provider_account IS DISTINCT FROM OLD.provider_account THEN
        RAISE EXCEPTION 'hosted namespace identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_namespace_identity_immutable
BEFORE UPDATE ON hosted_billing_namespaces
FOR EACH ROW EXECUTE FUNCTION hosted_namespace_identity_immutable();
CREATE TABLE hosted_billing_projections (
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces(namespace_id),
    account_id uuid NOT NULL,
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    dirty_generation bigint NOT NULL CHECK (dirty_generation >= 0),
    processed_generation bigint NOT NULL CHECK (processed_generation >= 0),
    per_read_sequence bigint NOT NULL CHECK (per_read_sequence >= 0),
    payment_hold boolean NOT NULL,
    review_required boolean NOT NULL,
    phase text NOT NULL CHECK (phase IN ('active', 'grace', 'pending', 'restricted', 'terminal')),
    outbound_limit bigint NOT NULL CHECK (outbound_limit >= 0),
    device_limit bigint NOT NULL CHECK (device_limit >= 0),
    issued_at bigint NOT NULL CHECK (issued_at >= 0),
    valid_until bigint NOT NULL CHECK (valid_until >= 0),
    first_failure_at bigint CHECK (first_failure_at >= 0),
    read_token uuid,
    invoice_id text NOT NULL DEFAULT '',
    price_id text NOT NULL DEFAULT '',
    period_start bigint NOT NULL DEFAULT 0,
    period_end bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace_id, account_id),
    UNIQUE (namespace_id, customer_id),
    UNIQUE (namespace_id, subscription_id),
    CHECK (processed_generation <= dirty_generation),
    CHECK (dirty_generation = per_read_sequence),
    CHECK ((dirty_generation = 0) = (read_token IS NULL)),
    CHECK ((invoice_id='' AND price_id='' AND period_start=0 AND period_end=0) OR
           (invoice_id<>'' AND price_id<>'' AND period_start>=0 AND period_end>period_start)),
    CHECK (phase NOT IN ('active','grace') OR (invoice_id<>'' AND price_id<>'')),
    CHECK (processed_generation > 0 OR
           (phase = 'pending' AND outbound_limit = 0 AND device_limit = 0))
);
CREATE FUNCTION hosted_projection_identity_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_id IS DISTINCT FROM OLD.namespace_id OR
       NEW.account_id IS DISTINCT FROM OLD.account_id OR
       NEW.customer_id IS DISTINCT FROM OLD.customer_id OR
       NEW.subscription_id IS DISTINCT FROM OLD.subscription_id THEN
        RAISE EXCEPTION 'hosted binding identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_projection_identity_immutable
BEFORE UPDATE ON hosted_billing_projections
FOR EACH ROW EXECUTE FUNCTION hosted_projection_identity_immutable();
CREATE FUNCTION hosted_projection_risk_invalidates() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.payment_hold IS DISTINCT FROM OLD.payment_hold OR
       NEW.review_required IS DISTINCT FROM OLD.review_required THEN
        NEW.dirty_generation := OLD.dirty_generation + 1;
        NEW.per_read_sequence := OLD.per_read_sequence + 1;
        NEW.processed_generation := OLD.processed_generation;
        NEW.read_token := gen_random_uuid();
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_projection_risk_invalidates
BEFORE UPDATE ON hosted_billing_projections
FOR EACH ROW EXECUTE FUNCTION hosted_projection_risk_invalidates();

-- One deployment database has one immutable provider identity. TEST and LIVE
-- databases cannot accidentally share opaque provider IDs or legacy bindings.
CREATE UNIQUE INDEX hosted_one_namespace ON hosted_billing_namespaces ((true));
ALTER TABLE hosted_billing_namespaces ADD COLUMN review_required boolean NOT NULL DEFAULT false;
ALTER TABLE hosted_billing_projections ADD FOREIGN KEY (account_id) REFERENCES accounts(id);
CREATE TABLE hosted_billing_customers (
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces,
    account_id uuid NOT NULL REFERENCES accounts,
    customer_id text,
    customer_operation uuid NOT NULL DEFAULT gen_random_uuid(),
    customer_started_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp())),
    checkout_operation uuid,
    checkout_started_at bigint,
    checkout_request_digest bytea CHECK(checkout_request_digest IS NULL OR octet_length(checkout_request_digest)=32),
    checkout_id text,
    checkout_url text,
    checkout_expires_at bigint,
    checkout_state text NOT NULL DEFAULT 'none' CHECK(checkout_state IN ('none','pending','open','complete','expired')),
    queue_generation bigint NOT NULL DEFAULT 1 CHECK (queue_generation>0),
    processed_generation bigint NOT NULL DEFAULT 0 CHECK (processed_generation>=0 AND processed_generation<=queue_generation),
    lease_token uuid,
    lease_until bigint NOT NULL DEFAULT 0,
    next_attempt_at bigint NOT NULL DEFAULT 0,
    recovery_at bigint NOT NULL DEFAULT 0,
    payment_hold boolean NOT NULL DEFAULT false,
    review_required boolean NOT NULL DEFAULT false,
    last_observation_complete boolean NOT NULL DEFAULT false,
    last_nonterminal_count bigint NOT NULL DEFAULT 0 CHECK(last_nonterminal_count>=0),
    PRIMARY KEY(namespace_id,account_id),
    UNIQUE(namespace_id,customer_id),
    CHECK ((checkout_operation IS NULL)=(checkout_started_at IS NULL))
);
CREATE FUNCTION hosted_customer_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_id IS DISTINCT FROM OLD.namespace_id OR NEW.account_id IS DISTINCT FROM OLD.account_id
       OR NEW.customer_operation IS DISTINCT FROM OLD.customer_operation OR NEW.customer_started_at IS DISTINCT FROM OLD.customer_started_at
       OR (OLD.customer_id IS NOT NULL AND NEW.customer_id IS DISTINCT FROM OLD.customer_id) THEN
        RAISE EXCEPTION 'hosted customer identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hosted_customer_identity_immutable BEFORE UPDATE ON hosted_billing_customers
FOR EACH ROW EXECUTE FUNCTION hosted_customer_identity_immutable();
CREATE TABLE hosted_billing_history (
    namespace_id uuid NOT NULL,
    account_id uuid NOT NULL,
    subscription_id text NOT NULL,
    customer_id text NOT NULL,
    retired_at bigint NOT NULL,
    PRIMARY KEY(namespace_id,subscription_id),
    FOREIGN KEY(namespace_id,account_id) REFERENCES hosted_billing_customers
);
CREATE TABLE hosted_billing_events (
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces,
    event_id text NOT NULL,
    body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
    event_type text NOT NULL,
    object_id text NOT NULL,
    customer_id text,
    account_id uuid,
    occurred_at bigint NOT NULL CHECK(occurred_at>=0),
    received_at bigint NOT NULL,
    invoice_id text,
    state text NOT NULL CHECK(state IN ('queued','processed','review','held','resolved','unbound')),
    PRIMARY KEY(namespace_id,event_id),
    FOREIGN KEY(namespace_id,account_id) REFERENCES hosted_billing_customers
);
CREATE INDEX hosted_events_current_invoice ON hosted_billing_events(namespace_id,account_id,invoice_id,occurred_at)
    WHERE event_type='invoice.payment_failed';
CREATE TABLE hosted_billing_audit (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces,
    account_id uuid NOT NULL REFERENCES accounts,
    generation bigint NOT NULL,
    reason text NOT NULL,
    changed_at bigint NOT NULL DEFAULT floor(extract(epoch FROM clock_timestamp()))
);
-- Attribution supplements the existing usage_ledger; it is not a second ledger.
CREATE TABLE hosted_billing_usage (
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces,
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    entry_kind text NOT NULL DEFAULT 'reserve' CHECK(entry_kind='reserve'),
    invoice_id text NOT NULL,
    period_start bigint NOT NULL,
    period_end bigint NOT NULL CHECK(period_end>period_start),
    PRIMARY KEY(namespace_id,account_id,message_id),
    FOREIGN KEY(account_id,message_id,entry_kind) REFERENCES usage_ledger(account_id,message_id,entry_kind)
);
CREATE INDEX hosted_usage_invoice ON hosted_billing_usage(namespace_id,account_id,invoice_id,period_start,period_end);

-- Provisioned by the database owner, never by the runtime or a browser. The
-- application role must not own these tables or have any direct privileges.
CREATE TABLE hosted_runtime_secrets (
    namespace_id uuid PRIMARY KEY REFERENCES hosted_billing_namespaces,
    runtime_key bytea NOT NULL CHECK(octet_length(runtime_key)=32)
);
CREATE TABLE hosted_runtime_sessions (
    backend_pid integer PRIMARY KEY,
    backend_start timestamptz NOT NULL,
    namespace_id uuid NOT NULL REFERENCES hosted_billing_namespaces,
    policy_revision bigint NOT NULL,
    nonce bytea NOT NULL CHECK(octet_length(nonce)=32),
    expires_at timestamptz NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    verified boolean NOT NULL DEFAULT false
);
REVOKE ALL ON hosted_runtime_secrets,hosted_runtime_sessions FROM PUBLIC;

CREATE FUNCTION hosted_runtime_schema_ready() RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT bool_and(EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
       JOIN pg_proc p ON p.oid=t.tgfoid
       WHERE t.tgrelid=to_regclass(e.table_name) AND t.tgname=e.trigger_name AND p.proname=e.function_name
       AND p.pronamespace=c.relnamespace AND t.tgenabled IN ('O','A')
       AND (NOT e.deferred OR (t.tgdeferrable AND t.tginitdeferred))))
    FROM (VALUES ('messages','hosted_admit_message','hosted_admit_message',false),
       ('messages','hosted_final_message','hosted_final_message',true),
       ('devices','hosted_admit_device','hosted_admit_device',true),
       ('billing_customers','hosted_refuse_legacy_customer','hosted_refuse_legacy_billing',false),
       ('hosted_billing_namespaces','hosted_namespace_may_enable','hosted_namespace_may_enable',false),
       ('hosted_billing_namespaces','hosted_namespace_identity_immutable','hosted_namespace_identity_immutable',false),
       ('hosted_billing_customers','hosted_customer_risk_clear','hosted_risk_clear_requires_operator',false),
       ('hosted_billing_projections','hosted_projection_risk_clear','hosted_risk_clear_requires_operator',false),
       ('hosted_billing_namespaces','hosted_namespace_risk_clear','hosted_risk_clear_requires_operator',false))
       AS e(table_name,trigger_name,function_name,deferred)
$$;

CREATE FUNCTION hosted_runtime_role_safe() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path FROM CURRENT AS $$
    SELECT NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
       AND NOT pg_has_role(session_user,c.relowner,'MEMBER')
       AND NOT has_schema_privilege(session_user,c.relnamespace,'CREATE')
       AND hosted_runtime_schema_ready()
       AND NOT EXISTS(SELECT 1 FROM pg_class p WHERE p.oid IN ('messages'::regclass,'devices'::regclass,'usage_ledger'::regclass,'usage_periods'::regclass,'hosted_billing_namespaces'::regclass)
          AND pg_has_role(session_user,p.relowner,'MEMBER'))
       AND NOT has_table_privilege(session_user,'messages','TRIGGER')
       AND NOT has_table_privilege(session_user,'devices','TRIGGER')
       AND NOT has_table_privilege(session_user,'hosted_runtime_secrets','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_table_privilege(session_user,'hosted_runtime_sessions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_any_column_privilege(session_user,'hosted_runtime_secrets','SELECT,INSERT,UPDATE,REFERENCES')
       AND NOT has_any_column_privilege(session_user,'hosted_runtime_sessions','SELECT,INSERT,UPDATE,REFERENCES')
    FROM pg_roles r,pg_class c WHERE r.rolname=session_user AND c.oid='hosted_runtime_secrets'::regclass
$$;
CREATE FUNCTION hosted_runtime_challenge(ns uuid, rev bigint) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT AS $$
DECLARE challenge bytea; started timestamptz;
BEGIN
    IF hosted_runtime_role_safe() IS DISTINCT FROM true OR NOT EXISTS(SELECT 1 FROM hosted_billing_namespaces
       WHERE namespace_id=ns AND policy_revision=rev AND enabled AND old_binary_fenced FOR SHARE) THEN
        RAISE EXCEPTION 'hosted runtime identity unavailable' USING ERRCODE='23514';
    END IF;
    SELECT backend_start INTO STRICT started FROM pg_stat_activity WHERE pid=pg_backend_pid();
    challenge:=uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid());
    DELETE FROM hosted_runtime_sessions s WHERE NOT EXISTS(SELECT 1 FROM pg_stat_activity a
       WHERE a.pid=s.backend_pid AND a.backend_start=s.backend_start);
    INSERT INTO hosted_runtime_sessions VALUES(pg_backend_pid(),started,ns,rev,challenge,clock_timestamp()+interval '60 seconds',false,false)
       ON CONFLICT(backend_pid) DO UPDATE SET backend_start=excluded.backend_start,namespace_id=excluded.namespace_id,
         policy_revision=excluded.policy_revision,nonce=excluded.nonce,expires_at=excluded.expires_at,consumed=false,verified=false;
    RETURN challenge;
END $$;
CREATE TABLE hosted_billing_resolutions (
    namespace_id uuid NOT NULL,
    event_id text NOT NULL,
    account_id uuid,
    operator_role text NOT NULL,
    reason text NOT NULL CHECK(reason IN ('risk_resolved','not_subscription_risk')),
    resolved_at bigint NOT NULL,
    PRIMARY KEY(namespace_id,event_id),
    FOREIGN KEY(namespace_id,event_id) REFERENCES hosted_billing_events
);
CREATE FUNCTION hosted_resolve_review(ns uuid,rev bigint,event text,resolution text) RETURNS void LANGUAGE plpgsql
AS $$
DECLARE owner_oid oid; wanted uuid; state_name text; t bigint;
BEGIN
    SELECT relowner INTO owner_oid FROM pg_class WHERE oid='hosted_runtime_secrets'::regclass;
    IF NOT pg_has_role(session_user,owner_oid,'MEMBER') OR resolution NOT IN ('risk_resolved','not_subscription_risk') THEN
        RAISE EXCEPTION 'authenticated database operator required' USING ERRCODE='42501';
    END IF;
    PERFORM 1 FROM hosted_billing_namespaces WHERE namespace_id=ns AND policy_revision=rev FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'hosted namespace mismatch' USING ERRCODE='23514'; END IF;
    SELECT account_id,state INTO wanted,state_name FROM hosted_billing_events WHERE namespace_id=ns AND event_id=event FOR UPDATE;
    IF NOT FOUND OR state_name NOT IN ('held','review') THEN RAISE EXCEPTION 'unresolved risk event required' USING ERRCODE='23514'; END IF;
    IF wanted IS NOT NULL THEN PERFORM 1 FROM accounts WHERE id=wanted FOR NO KEY UPDATE; END IF;
    t:=floor(extract(epoch FROM clock_timestamp()));
    INSERT INTO hosted_billing_resolutions VALUES(ns,event,wanted,session_user,resolution,t);
    UPDATE hosted_billing_events SET state='resolved' WHERE namespace_id=ns AND event_id=event;
    IF wanted IS NOT NULL THEN
       UPDATE hosted_billing_customers SET
          payment_hold=EXISTS(SELECT 1 FROM hosted_billing_events WHERE namespace_id=ns AND account_id=wanted AND state='held'),
          review_required=EXISTS(SELECT 1 FROM hosted_billing_events WHERE namespace_id=ns AND account_id=wanted AND state='review'),
          queue_generation=queue_generation+1,next_attempt_at=0 WHERE namespace_id=ns AND account_id=wanted;
       UPDATE hosted_billing_projections p SET (payment_hold,review_required,dirty_generation,per_read_sequence,read_token)=
          (c.payment_hold,c.review_required,p.dirty_generation+1,p.per_read_sequence+1,gen_random_uuid())
          FROM hosted_billing_customers c WHERE c.namespace_id=ns AND c.account_id=wanted AND p.namespace_id=c.namespace_id AND p.account_id=c.account_id;
       INSERT INTO hosted_billing_audit(namespace_id,account_id,generation,reason)
          SELECT ns,wanted,queue_generation,'operator_resolution' FROM hosted_billing_customers WHERE namespace_id=ns AND account_id=wanted;
    ELSE
       -- Clearing an unbound namespace latch cannot revive an older cached
       -- grant. Every affected account needs a fresh complete provider read.
       PERFORM a.id FROM accounts a JOIN hosted_billing_customers c ON c.account_id=a.id
          WHERE c.namespace_id=ns ORDER BY a.id FOR NO KEY UPDATE OF a;
       UPDATE hosted_billing_customers SET queue_generation=queue_generation+1,next_attempt_at=0 WHERE namespace_id=ns;
       UPDATE hosted_billing_projections SET (dirty_generation,per_read_sequence,read_token)=
          (dirty_generation+1,per_read_sequence+1,gen_random_uuid()) WHERE namespace_id=ns;
       INSERT INTO hosted_billing_audit(namespace_id,account_id,generation,reason)
          SELECT ns,account_id,queue_generation,'operator_resolution' FROM hosted_billing_customers WHERE namespace_id=ns;
    END IF;
    UPDATE hosted_billing_namespaces SET review_required=EXISTS(SELECT 1 FROM hosted_billing_events WHERE namespace_id=ns AND account_id IS NULL AND state='review') WHERE namespace_id=ns;
END $$;
REVOKE ALL ON hosted_billing_resolutions FROM PUBLIC;
REVOKE ALL ON FUNCTION hosted_resolve_review(uuid,bigint,text,text) FROM PUBLIC;
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION hosted_resolve_review(uuid,bigint,text,text) SET search_path TO pg_catalog,%I,pg_temp',current_schema());
END $$;
CREATE FUNCTION hosted_runtime_bind(ns uuid,rev bigint,proof bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path FROM CURRENT AS $$
DECLARE s hosted_runtime_sessions; secret bytea; inner_pad bytea; outer_pad bytea; expected bytea; diff integer:=0; i integer;
BEGIN
    IF hosted_runtime_role_safe() IS DISTINCT FROM true OR proof IS NULL OR octet_length(proof) IS DISTINCT FROM 32 THEN
       UPDATE hosted_runtime_sessions SET consumed=true,verified=false WHERE backend_pid=pg_backend_pid();
       RETURN false;
    END IF;
    SELECT * INTO s FROM hosted_runtime_sessions WHERE backend_pid=pg_backend_pid() AND namespace_id=ns
       AND policy_revision=rev AND NOT consumed AND expires_at>clock_timestamp()
       AND backend_start=(SELECT backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()) FOR UPDATE;
    IF NOT FOUND THEN UPDATE hosted_runtime_sessions SET verified=false WHERE backend_pid=pg_backend_pid(); RETURN false; END IF;
    UPDATE hosted_runtime_sessions SET consumed=true,verified=false WHERE backend_pid=pg_backend_pid();
    SELECT runtime_key INTO STRICT secret FROM hosted_runtime_secrets WHERE namespace_id=ns;
    inner_pad:=decode(repeat('36',64),'hex'); outer_pad:=decode(repeat('5c',64),'hex');
    FOR i IN 0..31 LOOP
       inner_pad:=set_byte(inner_pad,i,get_byte(inner_pad,i)#get_byte(secret,i));
       outer_pad:=set_byte(outer_pad,i,get_byte(outer_pad,i)#get_byte(secret,i));
    END LOOP;
    expected:=sha256(outer_pad||sha256(inner_pad||convert_to('ZROTEXT-HOSTED-RUNTIME-V1','UTF8')||s.nonce||uuid_send(ns)||int8send(rev)||int4send(pg_backend_pid())));
    FOR i IN 0..31 LOOP diff:=diff|(get_byte(expected,i)#get_byte(proof,i)); END LOOP;
    IF diff IS DISTINCT FROM 0 THEN RETURN false; END IF;
    UPDATE hosted_runtime_sessions SET verified=true WHERE backend_pid=pg_backend_pid();
    PERFORM set_config('zrotext.hosted_namespace',ns::text,false);
    PERFORM set_config('zrotext.hosted_revision',rev::text,false);
    RETURN true;
END $$;
CREATE FUNCTION hosted_runtime_verified(ns uuid,rev bigint) RETURNS boolean LANGUAGE sql SECURITY DEFINER
SET search_path FROM CURRENT AS $$
    SELECT hosted_runtime_role_safe() AND EXISTS(SELECT 1 FROM hosted_runtime_sessions s
       JOIN pg_stat_activity a ON a.pid=s.backend_pid AND a.backend_start=s.backend_start
       WHERE s.backend_pid=pg_backend_pid() AND s.namespace_id=ns AND s.policy_revision=rev AND s.verified AND s.expires_at>clock_timestamp())
$$;
-- Capture only pg_catalog and the exact migration schema. No caller-controlled
-- schema, temporary schema, or mutable role search_path participates in lookup.
DO $$ DECLARE f regprocedure; BEGIN
    FOREACH f IN ARRAY ARRAY['hosted_runtime_role_safe()'::regprocedure,
       'hosted_runtime_challenge(uuid,bigint)'::regprocedure,
       'hosted_runtime_bind(uuid,bigint,bytea)'::regprocedure,
       'hosted_runtime_verified(uuid,bigint)'::regprocedure] LOOP
       EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog,%I,pg_temp',f,current_schema());
       EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
    END LOOP;
END $$;

CREATE FUNCTION hosted_namespace_may_enable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'hosted namespace cannot be removed' USING ERRCODE='23514';
    END IF;
    IF NEW.enabled AND (NOT NEW.old_binary_fenced OR
       EXISTS(SELECT 1 FROM billing_customers) OR EXISTS(SELECT 1 FROM usage_quota_policies WHERE source='stripe_test')) THEN
        RAISE EXCEPTION 'hosted database is not isolated' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hosted_namespace_may_enable BEFORE INSERT OR UPDATE OR DELETE ON hosted_billing_namespaces
FOR EACH ROW EXECUTE FUNCTION hosted_namespace_may_enable();

-- A newly verified runtime binds each pooled connection to namespace+revision.
-- Old binaries cannot write paid messages/devices, even with billing flags off.
CREATE FUNCTION hosted_runtime_marker() RETURNS hosted_billing_namespaces LANGUAGE plpgsql AS $$
DECLARE n hosted_billing_namespaces;
BEGIN
    SELECT * INTO n FROM hosted_billing_namespaces FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF NOT n.enabled OR n.review_required OR NOT n.old_binary_fenced OR
       hosted_runtime_verified(n.namespace_id,n.policy_revision) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'hosted runtime identity unavailable' USING ERRCODE='23514',CONSTRAINT='hosted_runtime_identity';
    END IF;
    RETURN n;
END $$;
CREATE FUNCTION hosted_runtime_projection(owner_id uuid) RETURNS hosted_billing_projections LANGUAGE plpgsql AS $$
DECLARE n hosted_billing_namespaces; p hosted_billing_projections; t bigint;
BEGIN
    n:=hosted_runtime_marker();
    IF n.namespace_id IS NULL THEN RETURN NULL; END IF;
    PERFORM 1 FROM accounts WHERE id=owner_id AND disabled_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'hosted owner unavailable' USING ERRCODE='23514'; END IF;
    PERFORM 1 FROM hosted_billing_customers WHERE namespace_id=n.namespace_id AND account_id=owner_id
       AND NOT payment_hold AND NOT review_required FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'hosted billing restricted' USING ERRCODE='23514',CONSTRAINT='hosted_billing_restricted'; END IF;
    SELECT * INTO p FROM hosted_billing_projections WHERE namespace_id=n.namespace_id AND account_id=owner_id FOR SHARE;
    t:=floor(extract(epoch FROM clock_timestamp()));
    IF NOT FOUND OR p.payment_hold OR p.review_required OR p.phase NOT IN ('active','grace') OR
       p.policy_revision<>n.policy_revision OR p.dirty_generation<>p.processed_generation OR
       t<p.issued_at OR t<p.period_start OR t>=p.period_end OR t>=p.valid_until THEN
        RAISE EXCEPTION 'hosted billing pending' USING ERRCODE='23514',CONSTRAINT='hosted_billing_pending';
    END IF;
    RETURN p;
END $$;
CREATE FUNCTION hosted_admit_message() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p hosted_billing_projections; used bigint; month_start date;
BEGIN
    p:=hosted_runtime_projection(NEW.account_id);
    IF p.namespace_id IS NULL THEN RETURN NEW; END IF;
    SELECT coalesce(sum(l.units),0) INTO used FROM hosted_billing_usage u JOIN usage_ledger l
       ON (l.account_id,l.message_id)=(u.account_id,u.message_id)
       WHERE u.namespace_id=p.namespace_id AND u.account_id=p.account_id AND u.invoice_id=p.invoice_id
       AND u.period_start=p.period_start AND u.period_end=p.period_end;
    IF used>=p.outbound_limit THEN
       RAISE EXCEPTION 'hosted outbound quota exceeded' USING ERRCODE='23514',CONSTRAINT='hosted_outbound_quota';
    END IF;
    month_start:=date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC')::date;
    INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units)
       VALUES(NEW.account_id,'outbound_message',month_start,(month_start+interval '1 month')::date,p.outbound_limit,1)
       ON CONFLICT(account_id,metric,period_start) DO UPDATE SET reserved_units=usage_periods.reserved_units+1;
    INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units)
       VALUES(NEW.account_id,NEW.id,'outbound_message',month_start,'reserve',1);
    INSERT INTO hosted_billing_usage(namespace_id,account_id,message_id,invoice_id,period_start,period_end)
       VALUES(p.namespace_id,NEW.account_id,NEW.id,p.invoice_id,p.period_start,p.period_end);
    RETURN NEW;
END $$;
CREATE TRIGGER hosted_admit_message AFTER INSERT ON messages FOR EACH ROW EXECUTE FUNCTION hosted_admit_message();
CREATE FUNCTION hosted_final_message() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p hosted_billing_projections; used bigint;
BEGIN
    p:=hosted_runtime_projection(NEW.account_id);
    IF p.namespace_id IS NULL THEN RETURN NEW; END IF;
    IF NOT EXISTS(SELECT 1 FROM hosted_billing_usage WHERE namespace_id=p.namespace_id AND account_id=NEW.account_id
       AND message_id=NEW.id AND invoice_id=p.invoice_id AND period_start=p.period_start AND period_end=p.period_end) THEN
       RAISE EXCEPTION 'hosted usage attribution missing' USING ERRCODE='23514';
    END IF;
    SELECT coalesce(sum(l.units),0) INTO used FROM hosted_billing_usage u JOIN usage_ledger l
       ON (l.account_id,l.message_id)=(u.account_id,u.message_id)
       WHERE u.namespace_id=p.namespace_id AND u.account_id=p.account_id AND u.invoice_id=p.invoice_id
       AND u.period_start=p.period_start AND u.period_end=p.period_end;
    IF used>p.outbound_limit THEN RAISE EXCEPTION 'hosted outbound quota exceeded' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER hosted_final_message AFTER INSERT ON messages DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION hosted_final_message();
CREATE FUNCTION hosted_admit_device() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p hosted_billing_projections; used bigint;
BEGIN
    IF NEW.revoked_at IS NOT NULL THEN RETURN NEW; END IF;
    p:=hosted_runtime_projection(NEW.account_id);
    IF p.namespace_id IS NULL THEN RETURN NEW; END IF;
    SELECT count(*) INTO used FROM devices WHERE account_id=NEW.account_id AND revoked_at IS NULL;
    IF used>p.device_limit THEN
       RAISE EXCEPTION 'hosted device cap exceeded' USING ERRCODE='23514',CONSTRAINT='hosted_device_cap';
    END IF;
    RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER hosted_admit_device AFTER INSERT OR UPDATE OF revoked_at ON devices
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hosted_admit_device();

-- Legacy TEST mutation paths must never populate an isolated hosted database.
CREATE FUNCTION hosted_refuse_legacy_billing() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM hosted_billing_namespaces) THEN
       RAISE EXCEPTION 'legacy TEST billing is isolated' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hosted_refuse_legacy_customer BEFORE INSERT OR UPDATE ON billing_customers
    FOR EACH ROW EXECUTE FUNCTION hosted_refuse_legacy_billing();
CREATE FUNCTION hosted_risk_clear_requires_operator() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_oid oid;
BEGIN
    SELECT relowner INTO owner_oid FROM pg_class WHERE oid='hosted_runtime_secrets'::regclass;
    IF ((OLD.review_required AND NOT NEW.review_required) OR
        (to_jsonb(OLD)->>'payment_hold'='true' AND to_jsonb(NEW)->>'payment_hold'='false'))
       AND NOT pg_has_role(session_user,owner_oid,'MEMBER') THEN
        RAISE EXCEPTION 'hosted risk resolution requires database operator' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER hosted_customer_risk_clear BEFORE UPDATE ON hosted_billing_customers FOR EACH ROW EXECUTE FUNCTION hosted_risk_clear_requires_operator();
CREATE TRIGGER hosted_projection_risk_clear BEFORE UPDATE ON hosted_billing_projections FOR EACH ROW EXECUTE FUNCTION hosted_risk_clear_requires_operator();
CREATE TRIGGER hosted_namespace_risk_clear BEFORE UPDATE ON hosted_billing_namespaces FOR EACH ROW EXECUTE FUNCTION hosted_risk_clear_requires_operator();
DO $$ DECLARE f regprocedure; BEGIN
    FOREACH f IN ARRAY ARRAY['hosted_namespace_identity_immutable()'::regprocedure,
       'hosted_projection_identity_immutable()'::regprocedure,'hosted_projection_risk_invalidates()'::regprocedure,
       'hosted_customer_identity_immutable()'::regprocedure,'hosted_namespace_may_enable()'::regprocedure,
       'hosted_runtime_schema_ready()'::regprocedure,
       'hosted_runtime_marker()'::regprocedure,'hosted_runtime_projection(uuid)'::regprocedure,
       'hosted_admit_message()'::regprocedure,'hosted_final_message()'::regprocedure,
       'hosted_admit_device()'::regprocedure,'hosted_refuse_legacy_billing()'::regprocedure,
       'hosted_risk_clear_requires_operator()'::regprocedure] LOOP
       EXECUTE format('ALTER FUNCTION %s SET search_path TO pg_catalog,%I,pg_temp',f,current_schema());
    END LOOP;
END $$;

-- Additive account-anchor participation. No writer factory, epoch advancement,
-- profile selection, or payload authority is introduced here.
DO $migration$
DECLARE installation name; installation_oid oid; relation_name text;
BEGIN
    SELECT n.nspname,n.oid INTO STRICT installation,installation_oid FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid='accounts'::regclass;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace=installation_oid
       AND c.relname='payload_profile_account_anchors' AND c.relkind='r') THEN
       RAISE EXCEPTION 'account anchor foundation required' USING ERRCODE='23514';
    END IF;
    EXECUTE pg_catalog.format($ddl$
       CREATE FUNCTION %1$I.hosted_account_writer_guard() RETURNS trigger
       LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
       DECLARE wanted uuid; old_owner uuid; current_state text; current_epoch bigint; reduction boolean;
       BEGIN
          IF TG_TABLE_SCHEMA<>%2$L OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
             OR TG_TABLE_NAME NOT IN ('hosted_billing_customers','hosted_billing_projections','hosted_billing_history',
                'hosted_billing_events','hosted_billing_audit','hosted_billing_usage','hosted_billing_resolutions')
             OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
             RAISE EXCEPTION 'unexpected hosted writer context' USING ERRCODE='23514';
          END IF;
          IF TG_OP<>'INSERT' THEN old_owner:=OLD.account_id; END IF;
          IF TG_OP='DELETE' THEN wanted:=old_owner; reduction:=true;
          ELSE wanted:=NEW.account_id; reduction:=false; END IF;
          IF TG_OP='UPDATE' AND wanted IS DISTINCT FROM old_owner THEN
             RAISE EXCEPTION 'hosted account identity is immutable' USING ERRCODE='23514';
          END IF;
          -- Unbound provider inbox/review records are deployment scoped. They
          -- cannot later be reassigned to an owner by UPDATE.
          IF wanted IS NULL THEN
             IF TG_TABLE_NAME NOT IN ('hosted_billing_events','hosted_billing_resolutions') THEN
                RAISE EXCEPTION 'nonnull hosted owner required' USING ERRCODE='23514';
             END IF;
          ELSE
             IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(%1$I.payload_profile_account_fence_key(wanted)) THEN
                RAISE EXCEPTION 'hosted account fence busy' USING ERRCODE='55P03';
             END IF;
             SELECT state,selection_epoch INTO current_state,current_epoch FROM %1$I.payload_profile_account_anchors
                WHERE account_id=wanted FOR SHARE NOWAIT;
             IF NOT FOUND OR current_state IS NULL OR current_epoch IS NULL OR current_epoch<0
                OR current_state NOT IN ('live','deleted') OR (current_state='deleted' AND current_epoch=0)
                OR (current_state<>'live' AND NOT reduction) THEN
                RAISE EXCEPTION 'hosted account anchor unavailable' USING ERRCODE='23514';
             END IF;
          END IF;
          IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
       END;
       $function$;
       REVOKE ALL ON FUNCTION %1$I.hosted_account_writer_guard() FROM PUBLIC;
    $ddl$,installation,installation);
    FOREACH relation_name IN ARRAY ARRAY['hosted_billing_customers','hosted_billing_projections','hosted_billing_history',
       'hosted_billing_events','hosted_billing_audit','hosted_billing_usage','hosted_billing_resolutions'] LOOP
       EXECUTE pg_catalog.format('CREATE TRIGGER hosted_account_writer_before_change BEFORE INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION %I.hosted_account_writer_guard()',installation,relation_name,installation);
    END LOOP;
    IF installation='public' AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime') THEN
       REVOKE ALL ON TABLE public.hosted_runtime_secrets,public.hosted_runtime_sessions,public.hosted_billing_resolutions FROM PUBLIC,zrotext_runtime;
       REVOKE ALL ON TABLE public.hosted_billing_namespaces FROM PUBLIC,zrotext_runtime;
       GRANT SELECT,UPDATE(review_required) ON TABLE public.hosted_billing_namespaces TO zrotext_runtime;
       REVOKE ALL ON FUNCTION public.hosted_resolve_review(uuid,bigint,text,text),public.hosted_account_writer_guard() FROM PUBLIC,zrotext_runtime;
    END IF;
END;
$migration$;
