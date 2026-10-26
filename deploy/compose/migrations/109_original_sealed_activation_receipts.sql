-- SPDX-License-Identifier: AGPL-3.0-only
-- Original accepted evidence only. SQL is not a P-256 verifier or permission.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

DO $migration$
DECLARE writer_expected record; relation_name text;
BEGIN
    IF pg_catalog.to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass THEN
        RAISE EXCEPTION 'original evidence requires exact application namespace' USING ERRCODE='23514';
    END IF;
        FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()','f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()','cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1','bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()','b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4','boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()','8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a','boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()','57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('auth_abuse_consume(text, bytea, bytea, integer, integer, integer, integer)','cdac204cd61b30c1c4a7e9513264467da8cd81ebb1b72332a065ad8ab380d6a1','boolean','plpgsql','v',false,false,ARRAY['search_path=pg_catalog'])
        ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,configuration) LOOP
            IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
              JOIN pg_class c ON c.oid='public.accounts'::regclass
              WHERE p.oid=to_regprocedure(writer_expected.signature)
                AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
                AND format_type(p.prorettype,NULL)=writer_expected.result_type
                AND l.lanname=writer_expected.language_name AND p.provolatile::text=writer_expected.volatility
                AND p.proisstrict=writer_expected.is_strict AND p.prosecdef=writer_expected.is_definer
                AND p.proconfig=writer_expected.configuration AND p.proowner=c.relowner
                AND NOT p.proretset AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0) THEN
                RAISE EXCEPTION 'mandatory writer helper body or configuration is inconsistent' USING ERRCODE='23514';
            END IF;
        END LOOP;

    -- Render declared type identities under the same fixed catalog namespace
    -- as the current graph, independent of the migrator's public session path.
    PERFORM pg_catalog.set_config('search_path','pg_catalog',true);
    IF (SELECT sha256(convert_to(public.payload_profile_writer_json(json_agg(json_build_array(p.proname,pg_catalog.oidvectortypes(p.proargtypes),pg_catalog.format_type(p.prorettype,NULL),p.proargnames,p.proargmodes::text[],ARRAY(SELECT pg_catalog.format_type(t,NULL) FROM unnest(p.proallargtypes) t),p.pronargs,p.pronargdefaults,pg_catalog.pg_get_expr(p.proargdefaults,0),CASE WHEN p.provariadic=0 THEN NULL ELSE pg_catalog.format_type(p.provariadic,NULL) END,p.prokind::text,p.proleakproof,p.procost::text,p.prorows::text,p.prosupport::regprocedure::text) ORDER BY p.proname COLLATE "C",pg_catalog.oidvectortypes(p.proargtypes) COLLATE "C")),'UTF8')) FROM pg_catalog.pg_proc p WHERE p.pronamespace='public'::pg_catalog.regnamespace)<>decode('234f28ada903686dc3bc11b9189977889509a230a6a520ccbf62ddb6d3f87ec0','hex') THEN
        RAISE EXCEPTION 'unreviewed predecessor function declaration graph' USING ERRCODE='23514';
    END IF;
    PERFORM pg_catalog.set_config('search_path','pg_catalog, public',true);
    IF NOT (SELECT count(*)=108 AND min(version)=1 AND max(version)=108 FROM public.schema_migrations)
      OR NOT coalesce((SELECT migration_version=108 AND graph_sha256=public.payload_profile_writer_graph()
        FROM public.payload_profile_writer_catalog WHERE singleton),false)
      OR EXISTS(SELECT FROM pg_catalog.pg_class c CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
        WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND a.grantee=0)
      OR EXISTS(SELECT FROM pg_catalog.pg_attribute c JOIN pg_catalog.pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL pg_catalog.aclexplode(c.attacl) a
        WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
        RAISE EXCEPTION 'unreviewed pre-receipt graph or privileges' USING ERRCODE='23514';
    END IF;
    FOR relation_name IN SELECT c.relname FROM pg_catalog.pg_class c
      WHERE c.relnamespace='public'::regnamespace AND c.relkind='r' ORDER BY c.relname COLLATE "C" LOOP
        EXECUTE pg_catalog.format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
    END LOOP;
END;
$migration$;

CREATE TABLE public.payload_profile_v2_activation_receipts (
    binding_id uuid NOT NULL UNIQUE CHECK(binding_id<>'00000000-0000-0000-0000-000000000000'::uuid),
    account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
    challenge_id uuid NOT NULL,
    registration_id uuid NOT NULL,
    initiating_user_id uuid NOT NULL,
    initiating_session_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    protocol_version smallint NOT NULL CHECK(protocol_version=2),
    purpose text NOT NULL CHECK(purpose='sealed'),
    device_statement bytea NOT NULL CHECK(octet_length(device_statement)=255),
    device_signature_der bytea NOT NULL CHECK(octet_length(device_signature_der) BETWEEN 8 AND 80),
    owner_statement bytea NOT NULL CHECK(octet_length(owner_statement)=314),
    owner_signature_der bytea NOT NULL CHECK(octet_length(owner_signature_der) BETWEEN 8 AND 80),
    device_point bytea NOT NULL CHECK(octet_length(device_point)=65 AND get_byte(device_point,0)=4),
    owner_point bytea NOT NULL CHECK(octet_length(owner_point)=65 AND get_byte(owner_point,0)=4),
    device_fingerprint bytea NOT NULL CHECK(device_fingerprint=sha256(device_point)),
    owner_fingerprint bytea NOT NULL CHECK(owner_fingerprint=sha256(owner_point)),
    device_statement_sha256 bytea NOT NULL CHECK(device_statement_sha256=sha256(device_statement)),
    device_signature_sha256 bytea NOT NULL CHECK(device_signature_sha256=sha256(device_signature_der)),
    owner_statement_sha256 bytea NOT NULL CHECK(owner_statement_sha256=sha256(owner_statement)),
    owner_signature_sha256 bytea NOT NULL CHECK(owner_signature_sha256=sha256(owner_signature_der)),
    device_confirmation_digest bytea NOT NULL CHECK(device_confirmation_digest=sha256(device_statement||device_signature_der)),
    owner_approval_digest bytea NOT NULL CHECK(owner_approval_digest=sha256(owner_statement||owner_signature_der)),
    proof_site_id text NOT NULL CHECK(length(proof_site_id) BETWEEN 1 AND 128),
    proof_instance_id text NOT NULL CHECK(length(proof_instance_id) BETWEEN 1 AND 128),
    proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),
    proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
    accepted_ms bigint NOT NULL CHECK(accepted_ms>0),
    PRIMARY KEY(account_id,challenge_id),
    UNIQUE(account_id,registration_id),
    UNIQUE(account_id,line_id,device_id,generation),
    FOREIGN KEY(account_id,registration_id) REFERENCES public.sealed_line_key_receipts(account_id,registration_id) ON DELETE CASCADE,
    CHECK(binding_id<>challenge_id AND device_point<>owner_point)
);

-- A caller supplies only original bytes and selectors. Identity, lease and time
-- come from the actual locked fresh ceremony. No success boolean is accepted.
CREATE FUNCTION public.payload_profile_v2_capture(
    account uuid, challenge uuid, device_statement bytea, device_der bytea,
    owner_statement bytea, owner_der bytea, device_point bytea, owner_point bytea
) RETURNS TABLE(binding_id uuid,accepted_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE
    pending public.line_activation_v2_pending%ROWTYPE;
    original public.sealed_line_key_receipts%ROWTYPE;
    observation public.line_activation_v2_observations%ROWTYPE;
    previous public.payload_profile_v2_activation_receipts%ROWTYPE;
    expected_device bytea; expected_owner bytea; anchor_state text; epoch bigint;
    accepted bigint; binding uuid;
BEGIN
    IF account IS NULL OR challenge IS NULL OR account='00000000-0000-0000-0000-000000000000'::uuid
      OR challenge='00000000-0000-0000-0000-000000000000'::uuid
      OR device_statement IS NULL OR octet_length(device_statement)<>255
      OR owner_statement IS NULL OR octet_length(owner_statement)<>314
      OR device_der IS NULL OR octet_length(device_der) NOT BETWEEN 8 AND 80
      OR owner_der IS NULL OR octet_length(owner_der) NOT BETWEEN 8 AND 80
      OR device_point IS NULL OR octet_length(device_point)<>65 OR get_byte(device_point,0)<>4
      OR owner_point IS NULL OR octet_length(owner_point)<>65 OR get_byte(owner_point,0)<>4
      OR device_point=owner_point OR pg_is_in_recovery() THEN
        RAISE EXCEPTION 'original activation inputs unavailable' USING ERRCODE='23514';
    END IF;
    -- Existing authority first, then account fence and the actual stable anchor.
    PERFORM 1 FROM public.deployment_authority WHERE singleton FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'activation authority unavailable' USING ERRCODE='23514'; END IF;
    IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(account)) THEN
        RAISE EXCEPTION 'activation account fence busy' USING ERRCODE='55P03';
    END IF;
    SELECT state,selection_epoch INTO anchor_state,epoch FROM public.payload_profile_account_anchors
      WHERE account_id=account FOR SHARE NOWAIT;
    IF NOT FOUND OR anchor_state<>'live' OR epoch<>0 THEN
        RAISE EXCEPTION 'original activation account unavailable' USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'original activation account unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO previous FROM public.payload_profile_v2_activation_receipts r
      WHERE r.account_id=account AND r.challenge_id=challenge;
    IF FOUND THEN
        IF (previous.device_statement,previous.device_signature_der,previous.owner_statement,previous.owner_signature_der,previous.device_point,previous.owner_point)
          IS DISTINCT FROM (device_statement,device_der,owner_statement,owner_der,device_point,owner_point) THEN
            RAISE EXCEPTION 'original activation retry differs' USING ERRCODE='23514';
        END IF;
        RETURN QUERY SELECT previous.binding_id,previous.accepted_ms;
        RETURN;
    END IF;
    SELECT * INTO pending FROM public.line_activation_v2_pending p
      WHERE p.account_id=account AND p.challenge_id=challenge FOR UPDATE NOWAIT;
    IF NOT FOUND OR pending.protocol_version<>2 OR pending.purpose<>'sealed'
      OR pending.registration_id IS NULL OR pending.nonce IS NULL
      OR pending.approved_at IS NOT NULL OR pending.installed_at IS NOT NULL OR pending.retired_at IS NOT NULL
      OR pending.expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'fresh original activation unavailable' USING ERRCODE='23514';
    END IF;
    SELECT * INTO original FROM public.sealed_line_key_receipts r
      WHERE r.account_id=account AND r.registration_id=pending.registration_id FOR SHARE NOWAIT;
    IF NOT FOUND OR original.retired_ms IS NOT NULL OR original.activated_ms IS NOT NULL
      OR original.assigned_challenge_id IS DISTINCT FROM challenge
      OR (original.user_id,original.session_id,original.line_id,original.device_id,original.generation)
        IS DISTINCT FROM (pending.initiating_user_id,pending.initiating_session_id,pending.line_id,pending.device_id,pending.generation)
      OR original.approval_point<>owner_point OR original.approval_fingerprint<>sha256(owner_point)
      OR original.paired_fingerprint<>sha256(device_point) THEN
        RAISE EXCEPTION 'fresh original registration unavailable' USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM public.sessions s JOIN public.memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id)
      JOIN public.users u ON u.id=m.user_id
      WHERE s.id=pending.initiating_session_id AND s.account_id=account AND s.user_id=pending.initiating_user_id
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL
        AND u.email_verified_at IS NOT NULL FOR SHARE OF s,m,u NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'original owner session unavailable' USING ERRCODE='23514'; END IF;
    PERFORM 1 FROM public.phone_lines l JOIN public.device_line_bindings b
      ON (b.account_id,b.line_id)=(l.account_id,l.id)
      JOIN public.line_activation_challenges c ON (c.account_id,c.line_id,c.device_id,c.generation)=(b.account_id,b.line_id,b.device_id,b.generation)
      WHERE l.account_id=account AND l.id=pending.line_id AND l.state<>'revoked'
        AND l.last_issued_generation=pending.generation AND l.current_binding_generation<pending.generation
        AND b.device_id=pending.device_id AND b.generation=pending.generation AND b.state='pending' AND b.purpose='sealed'
        AND c.id=challenge AND c.protocol_version=2 AND c.consumed_at IS NULL
        AND c.nonce_digest=sha256(pending.nonce) AND c.expires_at=pending.expires_at AND c.expires_at>clock_timestamp()
      FOR UPDATE OF l,b,c NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'fresh original line unavailable' USING ERRCODE='23514'; END IF;
    SELECT * INTO observation FROM public.line_activation_v2_observations o WHERE o.challenge_id=challenge FOR SHARE NOWAIT;
    IF NOT FOUND OR (observation.account_id,observation.line_id,observation.device_id,observation.generation,observation.protocol_version,observation.purpose)
        IS DISTINCT FROM (account,pending.line_id,pending.device_id,pending.generation,2::smallint,'sealed'::text)
      OR (observation.proof_site_id,observation.proof_instance_id,observation.proof_connection_epoch,observation.proof_deployment_epoch)
        IS DISTINCT FROM (pending.site_id,pending.instance_id,pending.connection_epoch,pending.deployment_epoch)
      OR observation.device_fingerprint<>sha256(device_point) OR pending.device_fingerprint<>sha256(device_point)
      OR pending.owner_fingerprint<>sha256(owner_point) OR observation.device_signature_der<>device_der THEN
        RAISE EXCEPTION 'original device observation unavailable' USING ERRCODE='23514';
    END IF;
    PERFORM 1 FROM public.device_sessions s JOIN public.devices d ON (d.account_id,d.id)=(s.account_id,s.device_id)
      JOIN public.device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id)
      JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
      WHERE s.account_id=account AND s.device_id=pending.device_id AND d.revoked_at IS NULL AND k.revoked_at IS NULL
        AND s.site_id=observation.proof_site_id AND s.instance_id=observation.proof_instance_id
        AND s.connection_epoch=observation.proof_connection_epoch AND s.deployment_epoch=observation.proof_deployment_epoch
        AND s.lease_until>clock_timestamp() AND a.epoch=s.deployment_epoch AND t.enabled AND NOT t.draining
        AND k.signing_key_sec1=device_point FOR SHARE OF s,d,k,t,a NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'original device lease unavailable' USING ERRCODE='23514'; END IF;
    PERFORM 1 FROM public.line_owner_approval_keys k WHERE k.account_id=account AND k.signing_key_sec1=owner_point
      AND k.fingerprint=sha256(owner_point) AND k.revoked_at IS NULL FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'original owner key unavailable' USING ERRCODE='23514'; END IF;
    expected_device := convert_to('ZTSE/line/device-confirm/v2','UTF8')||decode('000202','hex')
      ||uuid_send(account)||uuid_send(pending.line_id)||uuid_send(pending.device_id)||int8send(pending.generation)
      ||uuid_send(challenge)||pending.nonce||observation.observation;
    expected_owner := convert_to('ZTSE/line/owner-approve/v2','UTF8')||decode('00','hex')||expected_device||sha256(device_der);
    IF device_statement<>expected_device OR owner_statement<>expected_owner
      OR observation.device_statement_sha256<>sha256(device_statement)
      OR observation.device_signature_sha256<>sha256(device_der)
      OR observation.confirmation_digest<>sha256(device_statement||device_der) THEN
        RAISE EXCEPTION 'original activation bytes differ' USING ERRCODE='23514';
    END IF;
    accepted := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
    binding := gen_random_uuid();
    INSERT INTO public.payload_profile_v2_activation_receipts VALUES(
      binding,account,challenge,pending.registration_id,pending.initiating_user_id,pending.initiating_session_id,
      pending.line_id,pending.device_id,pending.generation,2,'sealed',device_statement,device_der,owner_statement,owner_der,
      device_point,owner_point,sha256(device_point),sha256(owner_point),sha256(device_statement),sha256(device_der),
      sha256(owner_statement),sha256(owner_der),sha256(device_statement||device_der),sha256(owner_statement||owner_der),
      observation.proof_site_id,observation.proof_instance_id,observation.proof_connection_epoch,observation.proof_deployment_epoch,accepted);
    RETURN QUERY SELECT binding,accepted;
END;
$function$;

CREATE FUNCTION public.payload_profile_v2_receipt_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE state text; epoch bigint; owner_id uuid;
BEGIN
    IF TG_RELID<>'public.payload_profile_v2_activation_receipts'::regclass OR TG_NARGS<>0 OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' THEN
        RAISE EXCEPTION 'unexpected original receipt context' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'original receipt is immutable' USING ERRCODE='23514'; END IF;
    IF TG_OP='DELETE' THEN owner_id:=OLD.account_id; ELSE owner_id:=NEW.account_id; END IF;
    IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(owner_id)) THEN
        RAISE EXCEPTION 'original receipt account fence busy' USING ERRCODE='55P03';
    END IF;
    SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE account_id=owner_id FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'original receipt anchor unavailable' USING ERRCODE='23514'; END IF;
    IF TG_OP='DELETE' THEN
        IF EXISTS(SELECT FROM public.accounts WHERE id=owner_id) THEN
            RAISE EXCEPTION 'original receipt deletion requires actual account erasure' USING ERRCODE='23514';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP<>'INSERT' OR state<>'live' OR epoch<>0 OR NOT EXISTS(
      SELECT FROM public.line_activation_v2_pending p JOIN public.line_activation_challenges c ON c.id=p.challenge_id
      WHERE p.account_id=NEW.account_id AND p.challenge_id=NEW.challenge_id AND p.protocol_version=2 AND p.purpose='sealed'
        AND p.registration_id=NEW.registration_id AND p.initiating_user_id=NEW.initiating_user_id AND p.initiating_session_id=NEW.initiating_session_id
        AND (p.line_id,p.device_id,p.generation)=(NEW.line_id,NEW.device_id,NEW.generation)
        AND p.nonce IS NOT NULL AND p.approved_at IS NULL AND p.installed_at IS NULL AND p.retired_at IS NULL
        AND c.protocol_version=2 AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp()
        AND c.nonce_digest=sha256(substring(NEW.device_statement FROM 103 FOR 32))
        AND NEW.accepted_ms BETWEEN floor(extract(epoch FROM p.created_at)*1000)::bigint AND floor(extract(epoch FROM clock_timestamp())*1000)::bigint
    ) THEN RAISE EXCEPTION 'receipt is not a fresh original capture' USING ERRCODE='23514'; END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER payload_profile_v2_receipt_before_change BEFORE INSERT OR UPDATE OR DELETE
 ON public.payload_profile_v2_activation_receipts FOR EACH ROW EXECUTE FUNCTION public.payload_profile_v2_receipt_guard();

-- INSERT-only deferred coupling: installation ACK/nonce clearing is a later
-- transaction and is deliberately not required here. No legacy backfill phase.
CREATE FUNCTION public.payload_profile_v2_receipt_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
BEGIN
    IF TG_RELID<>'public.payload_profile_v2_activation_receipts'::regclass OR TG_OP<>'INSERT' OR TG_NARGS<>0 OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' THEN
        RAISE EXCEPTION 'unexpected original completion context' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT FROM public.payload_profile_v2_activation_receipts r WHERE (r.account_id,r.challenge_id)=(NEW.account_id,NEW.challenge_id))
      AND NOT EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RETURN NULL; END IF;
    IF NOT EXISTS(
      SELECT FROM public.line_activation_v2_pending p JOIN public.line_activation_challenges c ON c.id=p.challenge_id
      JOIN public.device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(p.account_id,p.line_id,p.device_id,p.generation)
      JOIN public.phone_lines l ON (l.account_id,l.id)=(b.account_id,b.line_id)
      JOIN public.sealed_line_key_receipts r ON (r.account_id,r.registration_id)=(p.account_id,p.registration_id)
      JOIN public.sessions s ON s.id=p.initiating_session_id JOIN public.memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id)
      JOIN public.accounts a ON a.id=p.account_id
      WHERE p.account_id=NEW.account_id AND p.challenge_id=NEW.challenge_id AND p.protocol_version=2 AND p.purpose='sealed'
        AND p.approved_at IS NOT NULL AND p.retired_at IS NULL AND p.owner_signature_sha256=NEW.owner_signature_sha256
        AND c.protocol_version=2 AND c.consumed_at IS NOT NULL AND c.expires_at>clock_timestamp()
        AND floor(extract(epoch FROM p.approved_at)*1000)::bigint>=NEW.accepted_ms
        AND floor(extract(epoch FROM c.consumed_at)*1000)::bigint>=NEW.accepted_ms
        AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest=NEW.owner_approval_digest
        AND b.device_confirmation_digest=NEW.device_confirmation_digest AND b.activated_at IS NOT NULL
        AND l.state='active' AND l.current_binding_generation=NEW.generation
        AND r.activated_ms>=NEW.accepted_ms AND r.retired_ms IS NULL AND r.assigned_challenge_id=NEW.challenge_id
        AND s.account_id=NEW.account_id AND s.user_id=NEW.initiating_user_id AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND m.role='owner' AND m.revoked_at IS NULL AND a.disabled_at IS NULL
    ) THEN RAISE EXCEPTION 'original capture must commit with actual activation' USING ERRCODE='23514'; END IF;
    RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER payload_profile_v2_receipt_after_insert
 AFTER INSERT ON public.payload_profile_v2_activation_receipts DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_v2_receipt_complete();

CREATE OR REPLACE FUNCTION public.payload_profile_writer_graph() RETURNS bytea
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT sha256(convert_to(public.payload_profile_writer_json(json_build_array(
  (SELECT json_agg(json_build_array(c.relname,c.relkind,c.relpersistence,pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity,
    (SELECT json_agg(json_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
    (SELECT json_agg(json_build_array(k.conname,k.contype,CASE WHEN c.relname='sealed_inbound_events' AND k.conname='sealed_inbound_events_envelope_check' AND pg_get_constraintdef(k.oid) IN ('CHECK (((envelope IS NULL) OR (((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082)) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))','CHECK (((envelope IS NULL) OR ((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))') THEN 'CHECK (((envelope IS NULL) OR ((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))' WHEN c.relname='webhook_endpoints' AND k.conname='webhook_endpoints_callback_url_check' AND pg_get_constraintdef(k.oid) IN ('CHECK ((((length(callback_url) >= 9) AND (length(callback_url) <= 2048)) AND (callback_url ~~ ''https://%''::text)))','CHECK (((length(callback_url) >= 9) AND (length(callback_url) <= 2048) AND (callback_url ~~ ''https://%''::text)))') THEN 'CHECK (((length(callback_url) >= 9) AND (length(callback_url) <= 2048) AND (callback_url ~~ ''https://%''::text)))' WHEN c.relname='workflow_action_versions' AND k.conname='workflow_action_versions_check' AND pg_get_constraintdef(k.oid) IN ('CHECK ((((revision >= 1) AND (revision <= 128)) AND (expires_at_ms > not_before_ms)))','CHECK (((revision >= 1) AND (revision <= 128) AND (expires_at_ms > not_before_ms)))') THEN 'CHECK (((revision >= 1) AND (revision <= 128) AND (expires_at_ms > not_before_ms)))' ELSE pg_get_constraintdef(k.oid) END,k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname COLLATE "C") FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype<>'n'),
    (SELECT json_agg(json_build_array(t.tgname,pg_get_triggerdef(t.oid),t.tgenabled::text,t.tgfoid::regprocedure::text) ORDER BY t.tgname COLLATE "C") FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal),
    (SELECT json_agg(json_build_array(i.relname,pg_get_indexdef(x.indexrelid),x.indisvalid,x.indisready,x.indislive) ORDER BY i.relname COLLATE "C") FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid=c.oid),
    (SELECT json_agg(json_build_array(r.rulename,r.ev_enabled::text,pg_get_ruledef(r.oid)) ORDER BY r.rulename COLLATE "C") FROM pg_rewrite r WHERE r.ev_class=c.oid),
    (SELECT json_agg(json_build_array(n.nspname,p.relname,h.inhseqno,h.inhdetachpending) ORDER BY n.nspname COLLATE "C",p.relname COLLATE "C",h.inhseqno) FROM pg_inherits h JOIN pg_class p ON p.oid=h.inhparent JOIN pg_namespace n ON n.oid=p.relnamespace WHERE h.inhrelid=c.oid),
    (SELECT json_agg(json_build_array(n.nspname,p.relname,h.inhseqno,h.inhdetachpending) ORDER BY n.nspname COLLATE "C",p.relname COLLATE "C",h.inhseqno) FROM pg_inherits h JOIN pg_class p ON p.oid=h.inhrelid JOIN pg_namespace n ON n.oid=p.relnamespace WHERE h.inhparent=c.oid),
    (SELECT json_agg(json_build_array(p.polname,p.polcmd::text,p.polpermissive,
       (SELECT json_agg(CASE WHEN role_id=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_id)::text END ORDER BY CASE WHEN role_id=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_id)::text END COLLATE "C") FROM unnest(p.polroles) AS roles(role_id)),
       pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY p.polname COLLATE "C") FROM pg_policy p WHERE p.polrelid=c.oid)
   ) ORDER BY c.relname COLLATE "C") FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p','v','m','f','S')),
  (SELECT json_agg(json_build_array(p.proname,oidvectortypes(p.proargtypes),format_type(p.prorettype,NULL),pg_get_userbyid(p.proowner),p.proretset,p.provolatile,p.proisstrict,p.prosecdef,p.proparallel,l.lanname,p.proargnames,p.proargmodes::text[],ARRAY(SELECT format_type(t,NULL) FROM unnest(p.proallargtypes) t),p.pronargs,p.pronargdefaults,pg_get_expr(p.proargdefaults,0),CASE WHEN p.provariadic=0 THEN NULL ELSE format_type(p.provariadic,NULL) END,p.prokind::text,p.proleakproof,p.procost::text,p.prorows::text,p.prosupport::regprocedure::text,
    CASE WHEN p.proname IN ('device_session_line_activation_version_guard','line_activation_v2_pending_guard','line_activation_v2_observation_guard')
      AND (p.proconfig=ARRAY['search_path=public'] OR p.proconfig=ARRAY['search_path=pg_catalog, public'])
      THEN ARRAY['search_path=pg_catalog, public'] ELSE p.proconfig END,p.prosrc)
    ORDER BY p.proname COLLATE "C",oidvectortypes(p.proargtypes) COLLATE "C") FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.pronamespace='public'::regnamespace)
 )),'UTF8'))
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=109 AND min(version)=1 AND max(version)=109 FROM public.schema_migrations
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=109 AND graph_sha256=public.payload_profile_writer_graph()
  AND (SELECT count(*)=12 AND bool_and(revision>=0) FROM public.payload_profile_writer_global_fences)
  AND NOT EXISTS(SELECT FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND t.tgisinternal AND t.tgenabled<>'O')
  AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND a.grantee=0)
  AND NOT EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0)
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_writer_%' AND a.grantee=0 AND a.privilege_type='EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
  AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=current_user::regrole)
  AND NOT has_schema_privilege(current_user,'public','CREATE')
  AND NOT has_database_privilege(current_user,current_database(),'CREATE,TEMP')
  AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND has_table_privilege(current_user,c.oid,'TRUNCATE,REFERENCES,TRIGGER'))
  AND NOT has_table_privilege(current_user,'public.payload_profile_account_anchors','INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','state','UPDATE')
  AND NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','selection_epoch','UPDATE')
  AND has_column_privilege(current_user,'public.payload_profile_account_anchors','account_id','UPDATE')
  AND NOT has_table_privilege(current_user,'public.payload_profile_writer_catalog','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_table_privilege(current_user,'public.payload_profile_writer_global_fences','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_writer_catalog','INSERT,UPDATE,REFERENCES')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_writer_global_fences','INSERT,UPDATE,REFERENCES')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_guard()','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_global_guard()','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_writer_catalog_guard()','EXECUTE')
  FROM public.payload_profile_writer_catalog WHERE singleton),false)
$function$;

CREATE FUNCTION public.payload_profile_v2_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready()
  AND has_table_privilege(current_user,'public.payload_profile_v2_activation_receipts','SELECT')
  AND NOT has_table_privilege(current_user,'public.payload_profile_v2_activation_receipts','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_v2_activation_receipts','INSERT,UPDATE,REFERENCES')
  AND has_function_privilege(current_user,'public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea)','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_v2_receipt_guard()','EXECUTE')
  AND NOT has_function_privilege(current_user,'public.payload_profile_v2_receipt_complete()','EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_v2_%' AND a.grantee=0)
$function$;

REVOKE ALL ON TABLE public.payload_profile_v2_activation_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_receipt_guard(),public.payload_profile_v2_receipt_complete(),public.payload_profile_v2_ready() FROM PUBLIC;
DO $migration$
DECLARE columns_sql text;
BEGIN
    IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
        SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
          WHERE attrelid='public.payload_profile_v2_activation_receipts'::regclass AND attnum>0 AND NOT attisdropped;
        REVOKE ALL ON TABLE public.payload_profile_v2_activation_receipts FROM zrotext_runtime;
        EXECUTE format('REVOKE ALL (%s) ON TABLE public.payload_profile_v2_activation_receipts FROM PUBLIC,zrotext_runtime',columns_sql);
        GRANT SELECT ON TABLE public.payload_profile_v2_activation_receipts TO zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_v2_receipt_guard(),public.payload_profile_v2_receipt_complete() FROM zrotext_runtime;
        GRANT EXECUTE ON FUNCTION public.payload_profile_v2_capture(uuid,uuid,bytea,bytea,bytea,bytea,bytea,bytea),public.payload_profile_v2_ready() TO zrotext_runtime;
    END IF;
END;
$migration$;

-- Deliberate reviewed schema evolution, never a runtime baseline refresh API.
DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=109);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE
 ON public.payload_profile_writer_catalog FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,109,public.payload_profile_writer_graph());
