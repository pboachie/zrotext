-- SPDX-License-Identifier: AGPL-3.0-only
-- First 02-to-03 selection only. Structural state is not signature/MFA proof.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';

DO $migration$
DECLARE writer_expected record; writer_installation bigint:=109; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'election requires exact primary application namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()','f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation=109 THEN '7979002b7b94fe1f5772d93e511204b1e731ca8eea8776a9a4cf4751af00b5af' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=109 THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=109 THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
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
FOR writer_expected IN SELECT * FROM (VALUES
                ('payload_profile_v2_capture(uuid, uuid, bytea, bytea, bytea, bytea, bytea, bytea)','7736037a8186fd08c7c9b6793295f89d2d627c29643baafc5b47e73c30ffe334','record','plpgsql','v',true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
                ('payload_profile_v2_receipt_guard()','cf69bccfb92f8429763377a802f31b58a0537fedad17baa6e303a8ba0aba4e6f','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
                ('payload_profile_v2_receipt_complete()','0b42255c08770af5440001822aca75e702be896783eddb2b8aeae5f4b9e34a34','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog']),
                ('payload_profile_v2_ready()','ba64199b418b562dbf7ec0763c46e841554f83626971e9b84e645b8a5c665942','boolean','sql','s',false,false,ARRAY['search_path=pg_catalog'])
            ) expected(signature,body_sha256,result_type,language_name,volatility,is_set,is_definer,configuration) LOOP
                IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
                  JOIN pg_class c ON c.oid='public.accounts'::regclass
                  WHERE p.oid=to_regprocedure(writer_expected.signature)
                    AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
                    AND format_type(p.prorettype,NULL)=writer_expected.result_type AND l.lanname=writer_expected.language_name
                    AND p.provolatile::text=writer_expected.volatility AND NOT p.proisstrict
                    AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set
                    AND p.proconfig=writer_expected.configuration AND p.proowner=c.relowner
                    AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
                    AND (NOT p.proretset OR (p.proargnames=ARRAY['account','challenge','device_statement','device_der','owner_statement','owner_der','device_point','owner_point','binding_id','accepted_ms']
                      AND p.proargmodes::text[]=ARRAY['i','i','i','i','i','i','i','i','t','t']
                      AND ARRAY(SELECT format_type(t,NULL) FROM unnest(p.proallargtypes) t)=ARRAY['uuid','uuid','bytea','bytea','bytea','bytea','bytea','bytea','uuid','bigint']))) THEN
                    RAISE EXCEPTION 'original receipt helper body or configuration is inconsistent' USING ERRCODE='23514';
                END IF;
            END LOOP;
 IF NOT(SELECT count(*)=109 AND min(version)=1 AND max(version)=109 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=109 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'election predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

CREATE TABLE public.payload_profile_election_challenges (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL,
 challenge_id uuid NOT NULL UNIQUE,
 initiating_user_id uuid NOT NULL,
 initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 old_binding_id uuid NOT NULL,
 new_binding_id uuid NOT NULL UNIQUE,
 registration_id uuid NOT NULL,
 activation_challenge_id uuid NOT NULL,
 old_binding_generation bigint NOT NULL CHECK(old_binding_generation>0),
 new_binding_generation bigint NOT NULL CHECK(new_binding_generation>old_binding_generation),
 prior_selection_epoch bigint NOT NULL CHECK(prior_selection_epoch=0),
 vault_generation bigint NOT NULL CHECK(vault_generation=1),
 prior_manifest_version bigint NOT NULL CHECK(prior_manifest_version>0 AND prior_manifest_version<9223372036854775807),
 prior_accepted_at_ms bigint NOT NULL CHECK(prior_accepted_at_ms>0),
 accepted_manifest_version bigint NOT NULL CHECK(accepted_manifest_version=prior_manifest_version+1),
 issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
 reserve_deadline_ms bigint NOT NULL CHECK(reserve_deadline_ms>issued_ms AND reserve_deadline_ms<=expires_ms),
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),
 proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 proof_site_id text NOT NULL CHECK(octet_length(proof_site_id) BETWEEN 1 AND 128),
 proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id) BETWEEN 1 AND 128),
 core bytea NOT NULL CHECK(octet_length(core)=500),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32 AND nonce<>decode(repeat('00',32),'hex')),
 root_pin bytea NOT NULL CHECK(octet_length(root_pin)=94),
 root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
 old_binding_proof_digest bytea NOT NULL CHECK(octet_length(old_binding_proof_digest)=32),
 selected_reader_key_id bytea NOT NULL CHECK(octet_length(selected_reader_key_id)=32),
 device_signing_key_id bytea NOT NULL CHECK(octet_length(device_signing_key_id)=32),
 owner_approval_key_id bytea NOT NULL CHECK(octet_length(owner_approval_key_id)=32),
 device_point bytea NOT NULL CHECK(octet_length(device_point)=65 AND get_byte(device_point,0)=4),
 owner_point bytea NOT NULL CHECK(octet_length(owner_point)=65 AND get_byte(owner_point,0)=4),
 configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32),
 owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32),
 device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32),
 prior_manifest_digest bytea NOT NULL CHECK(octet_length(prior_manifest_digest)=32),
 prior_signed_manifest_sha256 bytea NOT NULL CHECK(octet_length(prior_signed_manifest_sha256)=32),
 prior_signed_manifest bytea NOT NULL CHECK(octet_length(prior_signed_manifest) BETWEEN 364 AND 9751),
 accepted_manifest_digest bytea NOT NULL CHECK(octet_length(accepted_manifest_digest)=32),
 accepted_signed_manifest_sha256 bytea NOT NULL CHECK(octet_length(accepted_signed_manifest_sha256)=32),
 accepted_signed_manifest bytea NOT NULL CHECK(octet_length(accepted_signed_manifest) BETWEEN 366 AND 9753),
 device_signature bytea CHECK(device_signature IS NULL OR octet_length(device_signature)=64),
 device_proof_ms bigint,
 closed_unaccepted_ms bigint,
 superseded_by_challenge_id uuid,
 PRIMARY KEY(account_id,opening_id),
 UNIQUE(account_id,challenge_id),
 UNIQUE(account_id,line_id,new_binding_generation),
 FOREIGN KEY(account_id,superseded_by_challenge_id) REFERENCES public.payload_profile_election_challenges(account_id,challenge_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((closed_unaccepted_ms IS NULL)=(superseded_by_challenge_id IS NULL)),
 CHECK(closed_unaccepted_ms IS NULL OR closed_unaccepted_ms>=expires_ms),
 CHECK((device_signature IS NULL)=(device_proof_ms IS NULL)),
 CHECK(device_proof_ms IS NULL OR device_proof_ms>=issued_ms AND device_proof_ms<expires_ms),
 CHECK(challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(new_binding_id<>challenge_id AND new_binding_id<>old_binding_id AND new_binding_id<>opening_id),
 CHECK(new_binding_id<>'00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TABLE public.payload_profile_elections (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL,
 challenge_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 old_binding_id uuid NOT NULL,
 new_binding_id uuid NOT NULL UNIQUE,
 old_binding_generation bigint NOT NULL CHECK(old_binding_generation>0),
 new_binding_generation bigint NOT NULL CHECK(new_binding_generation>old_binding_generation),
 selection_epoch bigint NOT NULL CHECK(selection_epoch=1),
 vault_generation bigint NOT NULL CHECK(vault_generation=1),
 prior_manifest_version bigint NOT NULL CHECK(prior_manifest_version>0 AND prior_manifest_version<9223372036854775807),
 accepted_manifest_version bigint NOT NULL CHECK(accepted_manifest_version=prior_manifest_version+1),
 accepted_at_ms bigint NOT NULL CHECK(accepted_at_ms>0),
 acceptance_deadline_ms bigint NOT NULL CHECK(acceptance_deadline_ms>accepted_at_ms),
 root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
 old_binding_proof_digest bytea NOT NULL CHECK(octet_length(old_binding_proof_digest)=32),
 selected_reader_key_id bytea NOT NULL CHECK(octet_length(selected_reader_key_id)=32),
 prior_manifest_digest bytea NOT NULL CHECK(octet_length(prior_manifest_digest)=32),
 prior_signed_manifest_sha256 bytea NOT NULL CHECK(octet_length(prior_signed_manifest_sha256)=32),
 accepted_manifest_digest bytea NOT NULL CHECK(octet_length(accepted_manifest_digest)=32),
 accepted_signed_manifest_sha256 bytea NOT NULL CHECK(octet_length(accepted_signed_manifest_sha256)=32),
 election_core_sha256 bytea NOT NULL CHECK(octet_length(election_core_sha256)=32),
 election_commitment bytea NOT NULL CHECK(octet_length(election_commitment)=32),
 election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32),
 device_confirmation_digest bytea NOT NULL CHECK(octet_length(device_confirmation_digest)=32),
 owner_approval_digest bytea NOT NULL CHECK(octet_length(owner_approval_digest)=32),
 bundle bytea NOT NULL CHECK(octet_length(bundle)=628),
 device_signature bytea NOT NULL CHECK(octet_length(device_signature)=64),
 owner_signature bytea NOT NULL CHECK(octet_length(owner_signature)=64),
 PRIMARY KEY(account_id,challenge_id),
 UNIQUE(account_id,opening_id),
 UNIQUE(account_id,line_id,new_binding_generation),
 UNIQUE(account_id,selection_epoch),
 FOREIGN KEY(account_id,opening_id) REFERENCES public.payload_profile_election_challenges(account_id,opening_id) ON DELETE CASCADE
);

CREATE FUNCTION public.payload_profile_election_frame(label text,payload bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
 SELECT convert_to(label,'UTF8')||decode('00','hex')||int4send(octet_length(payload))||payload
$function$;
CREATE FUNCTION public.payload_profile_election_number(value bytea) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
BEGIN
 IF octet_length(value)<>8 OR get_byte(value,0)>=128 THEN
  RAISE EXCEPTION 'election integer storage range' USING ERRCODE='23514';
 END IF;
 RETURN ('x'||encode(value,'hex'))::bit(64)::bigint;
END;
$function$;
CREATE FUNCTION public.payload_profile_election_uuid(value bytea) RETURNS uuid
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
BEGIN
 IF octet_length(value)<>16 OR value=decode(repeat('00',16),'hex') THEN
  RAISE EXCEPTION 'election identity shape' USING ERRCODE='23514';
 END IF;
 RETURN encode(value,'hex')::uuid;
END;
$function$;

-- Structural reader metadata only. The application independently verifies the
-- entire original manifest's root signature, roles, ordering, curve and chain.
CREATE FUNCTION public.payload_profile_election_reader(manifest bytea,profile smallint,reader_id bytea,device uuid,line uuid,checked_ms bigint) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE count integer; at integer; i integer; found_point bytea; point bytea; header integer;
BEGIN
 IF checked_ms<=0 OR octet_length(reader_id)<>32 OR profile NOT IN (2,3) THEN
  RAISE EXCEPTION 'reader selection shape' USING ERRCODE='23514';
 END IF;
 IF profile=2 THEN
  header:=151;
  IF octet_length(manifest)<364 OR substring(manifest FROM 1 FOR 5)<>decode('5a544d4102','hex') THEN
   RAISE EXCEPTION 'original02 manifest shape' USING ERRCODE='23514';
  END IF;
 ELSE
  header:=153;
  IF octet_length(manifest)<366 OR substring(manifest FROM 1 FOR 6)<>decode('5a544d410303','hex') THEN
   RAISE EXCEPTION 'successor03 manifest shape' USING ERRCODE='23514';
  END IF;
 END IF;
 count:=get_byte(manifest,header-1);
 IF count NOT BETWEEN 1 AND 64 OR octet_length(manifest)<>header+149*count+64 THEN
  RAISE EXCEPTION 'selected reader manifest length' USING ERRCODE='23514';
 END IF;
 FOR i IN 0..count-1 LOOP
  at:=header+149*i;
  IF get_byte(manifest,at)=1 AND substring(manifest FROM at+2 FOR 32)=reader_id THEN
   IF found_point IS NOT NULL OR substring(manifest FROM at+99 FOR 16)<>uuid_send(device)
     OR substring(manifest FROM at+115 FOR 16)<>uuid_send(line)
     OR substring(manifest FROM at+131 FOR 2)<>decode('0004','hex') OR get_byte(manifest,at+148)<>1
     OR public.payload_profile_election_number(substring(manifest FROM at+133 FOR 8))>checked_ms
     OR public.payload_profile_election_number(substring(manifest FROM at+141 FOR 8))<=checked_ms THEN
    RAISE EXCEPTION 'selected reader scope or interval' USING ERRCODE='23514';
   END IF;
   point:=substring(manifest FROM at+34 FOR 65);
   IF get_byte(point,0)<>4 OR sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000010','hex')||point)<>reader_id THEN
    RAISE EXCEPTION 'selected reader identity' USING ERRCODE='23514';
   END IF;
   found_point:=point;
  END IF;
 END LOOP;
 IF found_point IS NULL THEN RAISE EXCEPTION 'selected reader unavailable' USING ERRCODE='23514'; END IF;
 RETURN found_point;
END;
$function$;

-- Original signed bytes remain original; this codec only fixes row identity.
CREATE FUNCTION public.payload_profile_election_old_binding(account uuid,binding uuid,reader bytea) RETURNS bytea
LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE receipt public.payload_profile_v2_activation_receipts%ROWTYPE; registration public.sealed_line_key_receipts%ROWTYPE; evidence bytea; payload bytea;
BEGIN
 SELECT * INTO receipt FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=binding;
 IF NOT FOUND THEN RAISE EXCEPTION 'original binding receipt unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO registration FROM public.sealed_line_key_receipts r WHERE r.account_id=account AND r.registration_id=receipt.registration_id;
 IF NOT FOUND OR octet_length(registration.transcript) NOT BETWEEN 1 AND 1024 OR octet_length(reader)<>32 THEN
  RAISE EXCEPTION 'original registration unavailable' USING ERRCODE='23514';
 END IF;
 payload:=int4send(octet_length(registration.transcript))||registration.transcript||registration.root_signature||registration.approval_signature
   ||registration.approval_point||registration.approval_fingerprint||registration.paired_fingerprint
   ||int8send(registration.issued_ms)||int8send(registration.expires_ms)||int8send(registration.completed_ms);
 evidence:=sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/registration-evidence/v1',payload));
 payload:=decode('0202','hex')||uuid_send(receipt.binding_id)||uuid_send(account)||uuid_send(receipt.device_id)||uuid_send(receipt.line_id)
   ||int8send(receipt.generation)||uuid_send(receipt.challenge_id)||uuid_send(receipt.registration_id)||evidence
   ||receipt.owner_approval_digest||receipt.device_confirmation_digest||reader;
 RETURN sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/old-binding/v1',payload));
END;
$function$;

-- This proves retained epoch provenance only. It does not make the accepted
-- reader, owner, device or authority currently usable after revocation.
CREATE FUNCTION public.payload_profile_epoch_valid(account uuid,epoch bigint) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT epoch=1 AND EXISTS(SELECT FROM public.payload_profile_elections e
  JOIN public.payload_profile_election_challenges c ON(c.account_id,c.challenge_id)=(e.account_id,e.challenge_id)
  JOIN public.payload_profile_v2_activation_receipts r ON(r.account_id,r.binding_id)=(e.account_id,e.old_binding_id)
  WHERE e.account_id=account AND e.selection_epoch=epoch AND c.closed_unaccepted_ms IS NULL
   AND c.new_binding_id=e.new_binding_id AND c.old_binding_id=e.old_binding_id AND r.generation=e.old_binding_generation
   AND e.bundle=c.core||e.device_signature||e.owner_signature AND e.device_signature=c.device_signature
   AND e.election_bundle_sha256=sha256(e.bundle) AND e.election_core_sha256=sha256(c.core))
$function$;

CREATE FUNCTION public.payload_profile_writer_policy(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE selected public.payload_profile_elections%ROWTYPE; reserved public.payload_profile_election_challenges%ROWTYPE;
 signed_before boolean; is_transition boolean; parent uuid; mode text;
BEGIN
 IF epoch<0 OR operation NOT IN('INSERT','UPDATE','DELETE') THEN RAISE EXCEPTION 'unknown writer operation' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN; END IF;
 IF epoch>0 AND NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'unknown positive selection epoch' USING ERRCODE='23514'; END IF;
 SELECT * INTO selected FROM public.payload_profile_elections e WHERE e.account_id=account AND e.selection_epoch=1;
 signed_before:=EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.device_signature IS NOT NULL);
 is_transition:=selected.account_id IS NOT NULL;
 IF relation_name='device_line_bindings' THEN
  -- Existing monotone revocation is always available; proof bytes never change.
  IF operation='UPDATE' AND new_row->>'state'='revoked' AND(old_row-'state')=(new_row-'state') THEN RETURN; END IF;
  IF operation='INSERT' AND is_transition AND(new_row->>'line_id')::uuid=selected.line_id AND(new_row->>'device_id')::uuid=selected.device_id
   AND(new_row->>'generation')::bigint=selected.new_binding_generation AND new_row->>'state'='active' AND new_row->>'purpose'='sealed'
   AND new_row->>'owner_approval_digest'=to_jsonb(selected)->>'owner_approval_digest'
   AND new_row->>'device_confirmation_digest'=to_jsonb(selected)->>'device_confirmation_digest' THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'untyped binding mutation after election proof' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.closed_unaccepted_ms IS NULL
    AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint) THEN
   RAISE EXCEPTION 'physical binding conflicts with reserved election' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name='phone_lines' THEN
  IF operation='UPDATE' AND(new_row->>'current_binding_generation')::bigint=(old_row->>'current_binding_generation')::bigint
   AND(new_row->>'last_issued_generation')::bigint=(old_row->>'last_issued_generation')::bigint THEN RETURN; END IF;
  IF operation='UPDATE' AND is_transition AND(new_row->>'id')::uuid=selected.line_id
   AND(new_row->>'current_binding_generation')::bigint=selected.new_binding_generation
   AND(new_row->>'last_issued_generation')::bigint=selected.new_binding_generation
   AND(old_row-ARRAY['current_binding_generation','last_issued_generation'])=(new_row-ARRAY['current_binding_generation','last_issued_generation']) THEN RETURN; END IF;
  IF operation='UPDATE' AND epoch=0 AND NOT is_transition AND(new_row->>'current_binding_generation')::bigint=(old_row->>'current_binding_generation')::bigint
   AND(new_row->>'last_issued_generation')::numeric=(old_row->>'last_issued_generation')::numeric+1
   AND(old_row-'last_issued_generation')=(new_row-'last_issued_generation')
   AND EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.line_id=(new_row->>'id')::uuid
     AND c.new_binding_generation=(new_row->>'last_issued_generation')::bigint AND c.closed_unaccepted_ms IS NULL
     AND c.reserve_deadline_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint) THEN RETURN; END IF;
  IF epoch>0 OR signed_before OR EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.closed_unaccepted_ms IS NULL
    AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint) THEN
   RAISE EXCEPTION 'untyped line generation mutation' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name='sealed_manifest_authorities' THEN
  IF operation='UPDATE' AND(old_row-ARRAY['revoked_at','last_verified_ms'])=(new_row-ARRAY['revoked_at','last_verified_ms']) THEN RETURN; END IF;
  IF operation='UPDATE' AND is_transition AND(new_row->>'version')::bigint=selected.accepted_manifest_version
   AND new_row->>'semantic_digest'=to_jsonb(selected)->>'accepted_manifest_digest'
   AND(new_row->>'accepted_at_ms')::bigint=selected.accepted_at_ms
   AND EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=selected.challenge_id
     AND new_row->>'manifest'=to_jsonb(c)->>'accepted_signed_manifest' AND new_row->>'root_pin'=to_jsonb(c)->>'root_pin') THEN RETURN; END IF;
  IF epoch>0 OR signed_before OR EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.closed_unaccepted_ms IS NULL
    AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint) THEN
   RAISE EXCEPTION 'unsupported authority ancestry during election' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name='original_reply_manifest_history' THEN
  IF operation='INSERT' AND is_transition AND(new_row->>'version')::bigint=selected.accepted_manifest_version
   AND new_row->>'digest'=to_jsonb(selected)->>'accepted_manifest_digest'
   AND EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=selected.challenge_id AND new_row->>'manifest'=to_jsonb(c)->>'accepted_signed_manifest') THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'untyped manifest history mutation' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name='line_readiness_observations' THEN
  IF operation='DELETE' THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'legacy readiness fenced by election proof' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name IN('line_activation_v2_pending','line_activation_challenges','sealed_line_key_receipts') THEN
  IF operation='UPDATE' AND relation_name='line_activation_v2_pending' AND new_row->>'nonce' IS NULL
   AND new_row->>'retired_at' IS NOT NULL AND(old_row-ARRAY['nonce','retired_at'])=(new_row-ARRAY['nonce','retired_at']) THEN RETURN; END IF;
  IF operation='UPDATE' AND relation_name='sealed_line_key_receipts' AND new_row->>'retired_ms' IS NOT NULL
   AND(old_row-'retired_ms')=(new_row-'retired_ms') THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'legacy physical activation fenced' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name='messages' THEN
  IF (old_row IS NULL OR old_row->>'transport_mode'='synthetic_alpha') AND(new_row IS NULL OR new_row->>'transport_mode'='synthetic_alpha') THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'legacy sealed message fenced' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name IN('dispatch_jobs','dispatch_fences','message_attempts','message_events','message_submission_receipts','idempotency_keys','provider_send_attempts') THEN
  parent:=coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid);
  SELECT transport_mode INTO mode FROM public.messages WHERE account_id=account AND id=parent;
  IF mode='synthetic_alpha' OR(operation='DELETE' AND NOT FOUND) THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'legacy sealed dispatch fenced' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 -- Exact classes with no profile-selected sealed payload/effect semantics.
 -- Their existing per-table ownership, revocation, monotonicity and retention
 -- guards remain mandatory and are included in the closed writer graph.
 IF relation_name=ANY(ARRAY['accounts','api_keys','auth_abuse_counters','billing_customers','billing_device_cap_audit','billing_device_cap_config','billing_device_caps','billing_events','billing_invoice_audit','billing_invoice_entitlements','billing_invoice_periods','billing_invoice_usage','billing_invoice_usage_observations','billing_payment_holds','billing_quota_audit','billing_reconciliations','billing_risk_events','billing_risk_review_actions','billing_subscriptions','billing_test_config','billing_usage_adjustment_requests','billing_usage_bindings','billing_usage_finalized','billing_usage_meter_error_receipts','billing_usage_meter_errors','billing_usage_outbox','billing_usage_reconciliations','billing_usage_test_policies','connector_audit_events','connector_grants','connector_keys','connector_registrations','contact_consent_records','contacts','deployment_authority','device_keys','device_preconditions','device_sessions','devices','email_verifications','exposure_deployment_budgets','exposure_reservation_scopes','exposure_reservations','exposure_route_policies','exposure_scope_budgets','failover_controller_state','hosted_billing_audit','hosted_billing_customers','hosted_billing_events','hosted_billing_history','hosted_billing_namespaces','hosted_billing_projections','hosted_billing_resolutions','hosted_billing_usage','hosted_runtime_secrets','hosted_runtime_sessions','inbound_events','known_signing_point_reservations','known_signing_role_claims','line_opt_out_events','line_owner_approval_keys','memberships','owner_mfa','owner_mfa_login_challenges','owner_mfa_recovery_codes','owner_opt_out_audit','owner_opt_out_review_decisions','owner_recipient_holds','pairing_requests','password_reset_mail_outbox','password_reset_notice_outbox','password_resets','recipient_suppressions','registration_browser_intents','review_access_authentications','review_access_locators','review_access_preparations','review_access_root_reauth','review_access_sessions','review_bootstrap_attempts','review_broker_sessions','review_brokers','review_realm_installation','review_workspaces','seat_invitations','sessions','sites','sms_line_activation_exchanges','sms_line_owner_approval_keys','sms_owner_key_audit','sms_owner_key_challenges','usage_ledger','usage_periods','usage_plan_assignments','usage_plan_audit','usage_quota_policies','users','verification_mail_outbox','webhook_attempts','webhook_deliveries','webhook_dispatch_accounts','webhook_endpoints','webhook_kek_commitments','webhook_replay_requests']) THEN RETURN; END IF;
 -- Remaining individually inventoried sealed/conversation/workflow/effect
 -- classes have no first03 writer in110. No generic positive-epoch fallback.
 IF relation_name=ANY(ARRAY['agent_authority_actions','agent_authority_approvals','agent_authority_grants','collaboration_draft_grants','collaboration_drafts','conversation_confirmation_records','conversation_execution_records','conversation_inbound_provenance','conversation_intervals','encrypted_template_versions','encrypted_templates','line_activation_v2_observations','original_reply_access','original_reply_consumptions','original_reply_grants','original_reply_requests','original_reply_sources','owner_android_proposals','owner_conversation_consents','sealed_event_deliveries','sealed_event_delivery_attempts','sealed_grant_authorizations','sealed_inbound_events','sealed_line_activation_exchanges','sealed_line_key_challenges','sealed_root_challenges','sealed_root_custody','sealed_root_enrollments','sealed_root_receipts','workflow_action_mutations','workflow_action_versions','workflow_actions','workflow_connector_context_envelopes','workflow_context_audit','workflow_context_fences','workflow_context_versions','workflow_contexts','workflow_exceptions','workflow_integration_access','workflow_integration_grants','workflow_message_links','workflow_opening_allocations','workflow_opening_offers','workflow_opening_requests','workflow_openings','workflow_reply_correlations','workflow_routine_admission_tombstones','workflow_routine_calls','workflow_routine_original_sources','workflow_routine_period_debits','workflow_routine_policies','workflow_routine_turn_debits','workflow_routines','workflow_schedule_audit','workflow_schedule_occurrences','workflow_schedule_policies','workflow_schedule_series']) THEN
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'writer requires a separately typed03 path: %',relation_name USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 RAISE EXCEPTION 'unknown profile writer policy %',relation_name USING ERRCODE='23514';
END;
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_anchor_row_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
BEGIN
 IF TG_RELID<>'public.payload_profile_account_anchors'::regclass OR TG_NARGS<>0 OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' THEN
  RAISE EXCEPTION 'unexpected anchor context' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'live' OR NEW.selection_epoch<>0 OR NOT EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN
   RAISE EXCEPTION 'invalid new account anchor' USING ERRCODE='23514'; END IF;
 ELSIF TG_OP='UPDATE' THEN
  IF NEW.account_id<>OLD.account_id THEN RAISE EXCEPTION 'account anchor identity immutable' USING ERRCODE='23514'; END IF;
  IF NEW.state=OLD.state AND NEW.selection_epoch=OLD.selection_epoch THEN RETURN NEW; END IF;
  IF OLD.state='live' AND NEW.state='live' AND OLD.selection_epoch=0 AND NEW.selection_epoch=1
   AND public.payload_profile_epoch_valid(NEW.account_id,1) THEN RETURN NEW; END IF;
  IF OLD.state<>'live' OR NEW.state<>'deleted' OR NEW.selection_epoch<>OLD.selection_epoch+1 OR EXISTS(SELECT FROM public.accounts WHERE id=OLD.account_id) THEN
   RAISE EXCEPTION 'unsupported account anchor transition' USING ERRCODE='23514'; END IF;
 ELSE RAISE EXCEPTION 'account anchor is retained' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE old_account uuid; new_account uuid; wanted uuid; accounts uuid[];
        old_row jsonb; new_row jsonb; current_state text; current_epoch bigint;
        writer_class text; affected bigint; global_key bigint;
BEGIN
    IF TG_TABLE_SCHEMA<>'public' OR TG_RELID IS DISTINCT FROM to_regclass(format('public.%I',TG_TABLE_NAME))
      OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
      OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
        RAISE EXCEPTION 'unexpected writer participation context' USING ERRCODE='23514';
    END IF;
    IF TG_OP<>'INSERT' THEN old_row:=to_jsonb(OLD); END IF;
    IF TG_OP<>'DELETE' THEN new_row:=to_jsonb(NEW); END IF;
    IF TG_TABLE_NAME=ANY(ARRAY['agent_authority_actions','agent_authority_approvals','agent_authority_grants','api_keys','billing_customers','billing_device_cap_audit','billing_device_caps','billing_invoice_audit','billing_invoice_entitlements','billing_invoice_periods','billing_invoice_usage','billing_invoice_usage_observations','billing_payment_holds','billing_quota_audit','billing_reconciliations','billing_subscriptions','billing_usage_adjustment_requests','billing_usage_bindings','billing_usage_finalized','billing_usage_meter_errors','billing_usage_outbox','billing_usage_reconciliations','billing_usage_test_policies','collaboration_draft_grants','collaboration_drafts','connector_audit_events','connector_grants','connector_keys','connector_registrations','contact_consent_records','contacts','conversation_confirmation_records','conversation_execution_records','conversation_inbound_provenance','conversation_intervals','device_keys','device_line_bindings','device_preconditions','devices','dispatch_jobs','email_verifications','encrypted_template_versions','encrypted_templates','exposure_reservation_scopes','exposure_reservations','exposure_route_policies','exposure_scope_budgets','hosted_billing_audit','hosted_billing_customers','hosted_billing_history','hosted_billing_projections','hosted_billing_usage','idempotency_keys','inbound_events','known_signing_point_reservations','known_signing_role_claims','line_activation_challenges','line_activation_v2_observations','line_activation_v2_pending','line_opt_out_events','line_owner_approval_keys','line_readiness_observations','memberships','message_attempts','message_events','message_submission_receipts','messages','original_reply_access','original_reply_consumptions','original_reply_grants','original_reply_manifest_history','original_reply_requests','original_reply_sources','owner_android_proposals','owner_conversation_consents','owner_mfa','owner_mfa_login_challenges','owner_mfa_recovery_codes','owner_opt_out_audit','owner_opt_out_review_decisions','owner_recipient_holds','pairing_requests','password_reset_notice_outbox','password_resets','phone_lines','provider_send_attempts','recipient_suppressions','registration_browser_intents','sealed_event_deliveries','sealed_grant_authorizations','sealed_inbound_events','sealed_line_activation_exchanges','sealed_line_key_challenges','sealed_line_key_receipts','sealed_manifest_authorities','sealed_root_challenges','sealed_root_custody','sealed_root_enrollments','sealed_root_receipts','seat_invitations','sessions','sms_line_activation_exchanges','sms_line_owner_approval_keys','sms_owner_key_audit','sms_owner_key_challenges','usage_ledger','usage_periods','usage_plan_assignments','usage_plan_audit','usage_quota_policies','webhook_deliveries','webhook_dispatch_accounts','webhook_endpoints','webhook_replay_requests','workflow_action_mutations','workflow_action_versions','workflow_actions','workflow_connector_context_envelopes','workflow_context_audit','workflow_context_fences','workflow_context_versions','workflow_contexts','workflow_exceptions','workflow_integration_access','workflow_integration_grants','workflow_message_links','workflow_opening_allocations','workflow_opening_offers','workflow_opening_requests','workflow_openings','workflow_reply_correlations','workflow_routine_admission_tombstones','workflow_routine_calls','workflow_routine_original_sources','workflow_routine_period_debits','workflow_routine_policies','workflow_routine_turn_debits','workflow_routines','workflow_schedule_audit','workflow_schedule_occurrences','workflow_schedule_policies','workflow_schedule_series']) OR TG_TABLE_NAME=ANY(ARRAY['password_reset_mail_outbox','sealed_event_delivery_attempts','verification_mail_outbox','webhook_attempts']) THEN
        old_account:=(old_row->>'account_id')::uuid;
        new_account:=(new_row->>'account_id')::uuid;
        IF (TG_OP<>'INSERT' AND old_account IS NULL) OR (TG_OP<>'DELETE' AND new_account IS NULL) THEN
            RAISE EXCEPTION 'required writer owner missing' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME=ANY(ARRAY['billing_events','billing_risk_events','device_sessions','dispatch_fences','hosted_billing_events','hosted_billing_resolutions']) THEN
        old_account:=(old_row->>'account_id')::uuid;
        new_account:=(new_row->>'account_id')::uuid;
        IF TG_TABLE_NAME IN ('device_sessions','dispatch_fences') THEN
            -- Legacy coordinator rows can omit account_id. An actual current
            -- device still contributes its real owner; NULL is never default02.
            IF TG_OP<>'INSERT' AND old_account IS NULL THEN
                SELECT account_id INTO old_account FROM public.devices WHERE id=(old_row->>'device_id')::uuid;
            END IF;
            IF TG_OP<>'DELETE' AND new_account IS NULL THEN
                SELECT account_id INTO new_account FROM public.devices WHERE id=(new_row->>'device_id')::uuid;
            END IF;
            writer_class:='legacy_coordination';
        ELSE
            writer_class:='provider_inbox';
        END IF;
    ELSIF TG_TABLE_NAME='accounts' THEN
        old_account:=(old_row->>'id')::uuid;
        new_account:=(new_row->>'id')::uuid;
        IF TG_OP='INSERT' THEN
            IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(new_account)) THEN
                RAISE EXCEPTION 'account creation fence busy' USING ERRCODE='55P03';
            END IF;
            IF EXISTS(SELECT FROM public.payload_profile_account_anchors WHERE account_id=new_account) THEN
                RAISE EXCEPTION 'retained account identity cannot be reused' USING ERRCODE='23514';
            END IF;
            -- Existing100 AFTER INSERT creates the insert-once stable anchor.
            RETURN NEW;
        END IF;
    ELSIF TG_TABLE_NAME=ANY(ARRAY['review_workspaces','review_access_sessions','review_access_authentications','review_access_root_reauth','review_access_locators']) THEN
        old_account:=(old_row->>'account_id')::uuid;
        new_account:=(new_row->>'account_id')::uuid;
        IF TG_TABLE_NAME='review_access_authentications' THEN
            IF (old_row IS NOT NULL AND old_account IS NULL AND old_row->>'operation'<>'2')
              OR (new_row IS NOT NULL AND new_account IS NULL AND new_row->>'operation'<>'2') THEN
                RAISE EXCEPTION 'unbound owner review operation' USING ERRCODE='23514';
            END IF;
            writer_class:='review_continuity';
        ELSIF (old_row IS NOT NULL AND old_account IS NULL) OR (new_row IS NOT NULL AND new_account IS NULL) THEN
            RAISE EXCEPTION 'review writer account unavailable' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='review_bootstrap_attempts' THEN
        -- A prospective reservation is not an existing account or a claim to it.
        -- Only its existing, constrained provisioned association contributes an
        -- account set. Existing owner-only factories and immutable guards stay.
        old_account:=(old_row->>'bound_account_id')::uuid;
        new_account:=(new_row->>'bound_account_id')::uuid;
        writer_class:='review_continuity';
    ELSE
        writer_class:=CASE TG_TABLE_NAME
                WHEN 'auth_abuse_counters' THEN 'auth_budget'
                WHEN 'billing_device_cap_config' THEN 'billing_configuration'
                WHEN 'billing_test_config' THEN 'billing_configuration'
                WHEN 'billing_risk_review_actions' THEN 'billing_audit'
                WHEN 'billing_usage_meter_error_receipts' THEN 'billing_audit'
                WHEN 'deployment_authority' THEN 'current_authority'
                WHEN 'failover_controller_state' THEN 'current_authority'
                WHEN 'sites' THEN 'current_authority'
                WHEN 'exposure_deployment_budgets' THEN 'effect_budget'
                WHEN 'webhook_kek_commitments' THEN 'key_integrity'
                WHEN 'hosted_billing_namespaces' THEN 'hosted_configuration'
                WHEN 'hosted_runtime_secrets' THEN 'hosted_configuration'
                WHEN 'hosted_runtime_sessions' THEN 'hosted_backend_proof'
                WHEN 'review_brokers' THEN 'review_current_authority'
                WHEN 'review_broker_sessions' THEN 'review_continuity'
                WHEN 'review_realm_installation' THEN 'review_current_authority'
                WHEN 'review_access_preparations' THEN 'review_continuity'
                ELSE NULL END;
        IF writer_class IS NULL THEN
            RAISE EXCEPTION 'unknown writer relation' USING ERRCODE='23514';
        END IF;
    END IF;
    SELECT array_agg(candidate ORDER BY candidate) INTO accounts FROM (
        SELECT DISTINCT candidate FROM unnest(ARRAY[old_account,new_account]) candidate WHERE candidate IS NOT NULL
    ) identities;
    FOREACH wanted IN ARRAY coalesce(accounts,ARRAY[]::uuid[]) LOOP
        IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN
            RAISE EXCEPTION 'account writer fence busy' USING ERRCODE='55P03';
        END IF;
        SELECT state,selection_epoch INTO current_state,current_epoch
          FROM public.payload_profile_account_anchors WHERE account_id=wanted FOR SHARE NOWAIT;
        IF NOT FOUND OR current_state IS NULL OR current_epoch IS NULL OR current_epoch<0
          OR current_state NOT IN ('live','deleted') OR (current_state='deleted' AND current_epoch=0)
          OR (current_state='deleted' AND TG_OP<>'DELETE')
          OR (current_state='live' AND current_epoch<>0 AND NOT public.payload_profile_epoch_valid(wanted,current_epoch) AND NOT(TG_OP='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=wanted))) THEN
            RAISE EXCEPTION 'writer state unsupported by installed policy' USING ERRCODE='23514';
        END IF;
        PERFORM public.payload_profile_writer_policy(wanted,current_epoch,TG_TABLE_NAME,TG_OP,old_row,new_row);
        -- The real row lock, rather than a copied epoch or advisory convention,
        -- makes old RR/SSI snapshots fail after the actual row version changes.
    END LOOP;
    IF accounts IS NULL THEN
        IF writer_class IS NULL THEN
            RAISE EXCEPTION 'writer account set unavailable' USING ERRCODE='23514';
        END IF;
        global_key:=('x'||substr(encode(sha256(convert_to('ZTSE/writer/global/v1:'||writer_class,'UTF8')),'hex'),1,16))::bit(64)::bigint;
        IF writer_class IN ('billing_configuration','current_authority','key_integrity','hosted_configuration','review_current_authority') THEN
            IF NOT pg_try_advisory_xact_lock(global_key) THEN
                RAISE EXCEPTION 'global authority writer busy' USING ERRCODE='55P03';
            END IF;
            PERFORM g.operation_class FROM public.payload_profile_writer_global_fences g WHERE g.operation_class=writer_class FOR UPDATE NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'global writer fence unavailable' USING ERRCODE='23514'; END IF;
            UPDATE public.payload_profile_writer_global_fences g SET revision=g.revision+1 WHERE g.operation_class=writer_class;
            GET DIAGNOSTICS affected=ROW_COUNT;
            IF affected<>1 THEN RAISE EXCEPTION 'global writer fence unavailable' USING ERRCODE='23514'; END IF;
        ELSE
            -- Budgets, audit, unbound inbox and browser continuity have no
            -- authority transition. Preserve their independent row concurrency;
            -- still require the explicit class and its actual stable row lock.
            IF NOT pg_try_advisory_xact_lock_shared(global_key) THEN
                RAISE EXCEPTION 'global writer class busy' USING ERRCODE='55P03';
            END IF;
            PERFORM g.operation_class FROM public.payload_profile_writer_global_fences g WHERE g.operation_class=writer_class FOR SHARE NOWAIT;
            IF NOT FOUND THEN RAISE EXCEPTION 'global writer fence unavailable' USING ERRCODE='23514'; END IF;
        END IF;
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$function$;
CREATE OR REPLACE FUNCTION public.user_membership_freshness_guard() RETURNS trigger
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
            IF TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN ('public.users'::regclass,'public.memberships'::regclass)
              OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
              OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
                RAISE EXCEPTION 'unexpected user membership freshness context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID='public.users'::regclass THEN
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
                  FROM public.memberships WHERE user_id=wanted_user;
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
                IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted_account)) THEN
                    RAISE EXCEPTION 'user membership account fence busy' USING ERRCODE='55P03';
                END IF;
                SELECT state,selection_epoch INTO current_state,current_epoch
                  FROM public.payload_profile_account_anchors WHERE account_id=wanted_account FOR SHARE NOWAIT;
                IF NOT FOUND OR current_state IS NULL OR current_epoch IS NULL OR current_epoch<0
                  OR current_state NOT IN ('live','deleted') OR (current_state='deleted' AND current_epoch=0)
                  OR (current_state<>'live' AND NOT reduction)
                  OR (current_state='live' AND current_epoch<>0 AND NOT public.payload_profile_epoch_valid(wanted_account,current_epoch) AND NOT(reduction AND NOT EXISTS(SELECT FROM public.accounts WHERE id=wanted_account))) THEN
                    RAISE EXCEPTION 'user membership anchor unavailable' USING ERRCODE='23514';
                END IF;
                -- Reading/locking the actual tuple is essential: a changed
                -- epoch must cause an old RR/SSI snapshot to refuse, not default02.
            END LOOP;
            IF TG_RELID='public.memberships'::regclass THEN
                IF TG_OP='DELETE' THEN wanted_user:=OLD.user_id; ELSE wanted_user:=NEW.user_id; END IF;
                PERFORM id FROM public.users WHERE id=wanted_user FOR UPDATE NOWAIT;
                IF FOUND THEN
                    -- Locking alone leaves old RR snapshots usable. The real
                    -- version change serializes them even for membership DELETE.
                    -- Its nested users guard reads/locks only; no depth bypass.
                    UPDATE public.users SET id=id WHERE id=wanted_user;
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

-- These locks and structural checks do not verify signatures or MFA. The
-- application holds genuine proofs before entering the narrow mutation.
CREATE FUNCTION public.payload_profile_election_scope(account uuid,owner_user uuid,owner_session uuid,core bytea,successor bytea)
RETURNS public.payload_profile_election_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_election_challenges%ROWTYPE;
 authority public.sealed_manifest_authorities%ROWTYPE;
 original public.payload_profile_v2_activation_receipts%ROWTYPE;
 device_session public.device_sessions%ROWTYPE;
 line public.phone_lines%ROWTYPE;
 now_ms bigint; state text; epoch bigint; session_bytes bytea; root_point bytea;
BEGIN
 IF account IS NULL OR owner_user IS NULL OR owner_session IS NULL OR core IS NULL OR successor IS NULL
   OR octet_length(core)<>500 OR substring(core FROM 1 FOR 8)<>decode('5a54504503010203','hex')
   OR substring(core FROM 497 FOR 4)<>decode('00000000','hex') OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'election core unavailable' USING ERRCODE='23514';
 END IF;
 -- Existing manifest authority first, then the account EXCLUSIVE fence and
 -- actual stable row. Selecting transition mode precedes any shared proof.
 SELECT * INTO authority FROM public.sealed_manifest_authorities a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'election authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN
  RAISE EXCEPTION 'election account busy' USING ERRCODE='55P03';
 END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>0 THEN RAISE EXCEPTION 'original02 anchor unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'election account unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.sessions s JOIN public.memberships m ON(m.account_id,m.user_id)=(s.account_id,s.user_id)
  JOIN public.users u ON u.id=m.user_id JOIN public.owner_mfa f ON(f.account_id,f.user_id)=(m.account_id,m.user_id)
  WHERE s.account_id=account AND s.id=owner_session AND s.user_id=owner_user AND s.revoked_at IS NULL
   AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL
   AND u.mfa_enabled AND f.enabled_at IS NOT NULL AND coalesce(s.last_used_at,s.created_at)<=clock_timestamp()
   AND coalesce(s.last_used_at,s.created_at)>clock_timestamp()-interval '72 hours'
  FOR SHARE OF s,m,u,f NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'election owner unavailable' USING ERRCODE='23514'; END IF;
 row.account_id:=public.payload_profile_election_uuid(substring(core FROM 9 FOR 16));
 row.device_id:=public.payload_profile_election_uuid(substring(core FROM 25 FOR 16));
 row.line_id:=public.payload_profile_election_uuid(substring(core FROM 41 FOR 16));
 row.challenge_id:=public.payload_profile_election_uuid(substring(core FROM 57 FOR 16));
 row.old_binding_id:=public.payload_profile_election_uuid(substring(core FROM 73 FOR 16));
 row.old_binding_generation:=public.payload_profile_election_number(substring(core FROM 89 FOR 8));
 row.new_binding_generation:=public.payload_profile_election_number(substring(core FROM 97 FOR 8));
 row.old_binding_proof_digest:=substring(core FROM 105 FOR 32);
 row.root_fingerprint:=substring(core FROM 137 FOR 32);
 row.vault_generation:=public.payload_profile_election_number(substring(core FROM 169 FOR 8));
 row.prior_manifest_version:=public.payload_profile_election_number(substring(core FROM 177 FOR 8));
 row.prior_manifest_digest:=substring(core FROM 185 FOR 32);
 row.accepted_manifest_version:=public.payload_profile_election_number(substring(core FROM 217 FOR 8));
 row.accepted_manifest_digest:=substring(core FROM 225 FOR 32);
 row.selected_reader_key_id:=substring(core FROM 257 FOR 32);
 row.device_signing_key_id:=substring(core FROM 289 FOR 32);
 row.owner_approval_key_id:=substring(core FROM 321 FOR 32);
 row.nonce:=substring(core FROM 353 FOR 32);
 row.issued_ms:=public.payload_profile_election_number(substring(core FROM 385 FOR 8));
 row.expires_ms:=public.payload_profile_election_number(substring(core FROM 393 FOR 8));
 row.configured_origin_digest:=substring(core FROM 401 FOR 32);
 row.owner_session_digest:=substring(core FROM 433 FOR 32);
 row.device_session_digest:=substring(core FROM 465 FOR 32);
 row.initiating_user_id:=owner_user; row.initiating_session_id:=owner_session; row.prior_selection_epoch:=0;
 row.core:=core; row.accepted_signed_manifest:=successor; row.accepted_signed_manifest_sha256:=sha256(successor);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF row.account_id<>account OR row.old_binding_generation<=0 OR row.new_binding_generation<=row.old_binding_generation
  OR row.vault_generation<>1 OR row.prior_manifest_version<=0 OR row.prior_manifest_version=9223372036854775807
  OR row.accepted_manifest_version<>row.prior_manifest_version+1 OR row.issued_ms<=0 OR row.issued_ms>now_ms
  OR row.expires_ms<=now_ms OR row.expires_ms-row.issued_ms NOT BETWEEN 1 AND 300000
  OR row.nonce=decode(repeat('00',32),'hex') OR row.configured_origin_digest=decode(repeat('00',32),'hex')
  OR row.owner_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner-session/v1',uuid_send(account)||uuid_send(owner_user)||uuid_send(owner_session))) THEN
  RAISE EXCEPTION 'election scope differs' USING ERRCODE='23514';
 END IF;
 IF authority.revoked_at IS NOT NULL OR authority.generation<>1 OR authority.anchor_digest<>decode(repeat('00',32),'hex')
  OR authority.version<>row.prior_manifest_version OR authority.semantic_digest IS DISTINCT FROM row.prior_manifest_digest
  OR authority.root_fingerprint<>row.root_fingerprint OR authority.accepted_at_ms IS NULL
  OR authority.root_fingerprint<>sha256(convert_to('ZTSE/root-pin/v2','UTF8')||decode('00','hex')||authority.root_pin)
  OR authority.last_verified_ms>now_ms OR authority.accepted_at_ms>row.issued_ms
  OR octet_length(authority.manifest) NOT BETWEEN 364 AND 9751
  OR substring(authority.manifest FROM 1 FOR 5)<>decode('5a544d4102','hex')
  OR sha256(substring(authority.manifest FROM 1 FOR octet_length(authority.manifest)-64))<>row.prior_manifest_digest
  OR authority.root_pin<>decode('5a54525002','hex')||uuid_send(account)||substring(authority.manifest FROM 22 FOR 8)||substring(authority.manifest FROM 86 FOR 65)
 THEN RAISE EXCEPTION 'original02 authority differs' USING ERRCODE='23514'; END IF;
 -- The pin's entire original bytes/fingerprint are retained; crypto checks of
 -- the pin, current02 and successor03 remain mandatory in the application.
 row.root_pin:=authority.root_pin; row.prior_signed_manifest:=authority.manifest;
 row.prior_signed_manifest_sha256:=sha256(authority.manifest); row.prior_accepted_at_ms:=authority.accepted_at_ms;
 IF octet_length(successor) NOT BETWEEN 366 AND 9753 OR substring(successor FROM 1 FOR 7)<>decode('5a544d41030302','hex')
  OR substring(successor FROM 8 FOR 16)<>uuid_send(account) OR substring(successor FROM 24 FOR 8)<>int8send(1)
  OR substring(successor FROM 32 FOR 8)<>int8send(row.accepted_manifest_version)
  OR substring(successor FROM 56 FOR 32)<>row.prior_manifest_digest
  OR substring(successor FROM 88 FOR 65)<>substring(authority.manifest FROM 86 FOR 65)
  OR sha256(substring(successor FROM 1 FOR octet_length(successor)-64))<>row.accepted_manifest_digest
  OR public.payload_profile_election_number(substring(successor FROM 40 FOR 8))>now_ms+300000
  OR public.payload_profile_election_number(substring(successor FROM 48 FOR 8))<=now_ms
 THEN RAISE EXCEPTION 'same-root03 successor differs' USING ERRCODE='23514'; END IF;
 root_point:=public.payload_profile_election_reader(authority.manifest,2::smallint,row.selected_reader_key_id,row.device_id,row.line_id,now_ms);
 IF public.payload_profile_election_reader(successor,3::smallint,row.selected_reader_key_id,row.device_id,row.line_id,now_ms)<>root_point THEN
  RAISE EXCEPTION 'selected reader changed during upgrade' USING ERRCODE='23514'; END IF;
 SELECT * INTO original FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=row.old_binding_id;
 IF NOT FOUND OR(original.line_id,original.device_id,original.generation) IS DISTINCT FROM(row.line_id,row.device_id,row.old_binding_generation)
  OR public.payload_profile_election_old_binding(account,row.old_binding_id,row.selected_reader_key_id)<>row.old_binding_proof_digest THEN
  RAISE EXCEPTION 'original binding differs' USING ERRCODE='23514'; END IF;
 row.registration_id:=original.registration_id; row.activation_challenge_id:=original.challenge_id;
 row.device_point:=original.device_point; row.owner_point:=original.owner_point;
 SELECT * INTO line FROM public.phone_lines l WHERE l.account_id=account AND l.id=row.line_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR line.state<>'active' OR line.current_binding_generation<>row.old_binding_generation
  OR(SELECT count(*) FROM public.device_line_bindings b WHERE b.account_id=account AND b.state='active' AND b.purpose='sealed')<>1 THEN
  RAISE EXCEPTION 'single original line unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.device_line_bindings b WHERE(b.account_id,b.line_id,b.device_id,b.generation)=(account,row.line_id,row.device_id,row.old_binding_generation)
  AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest=original.owner_approval_digest
  AND b.device_confirmation_digest=original.device_confirmation_digest FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original active binding unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_activation_v2_pending p JOIN public.line_activation_challenges c ON c.id=p.challenge_id
  JOIN public.sealed_line_key_receipts r ON(r.account_id,r.registration_id)=(p.account_id,p.registration_id)
  WHERE p.account_id=account AND p.challenge_id=original.challenge_id AND p.registration_id=original.registration_id
   AND p.protocol_version=2 AND p.purpose='sealed' AND p.approved_at IS NOT NULL AND p.installed_at IS NOT NULL
   AND p.nonce IS NULL AND p.retired_at IS NULL AND c.consumed_at IS NOT NULL AND r.activated_ms IS NOT NULL AND r.retired_ms IS NULL
  FOR SHARE OF p,c,r NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original installed activation unavailable' USING ERRCODE='23514'; END IF;
 SELECT s.* INTO device_session FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id)
  JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
  WHERE s.account_id=account AND s.device_id=row.device_id AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.signing_key_sec1=original.device_point AND k.fingerprint=sha256(original.device_point)
   AND s.site_id=original.proof_site_id AND s.instance_id=original.proof_instance_id
   AND s.connection_epoch=original.proof_connection_epoch AND s.deployment_epoch=original.proof_deployment_epoch
   AND s.line_activation_version=2 AND s.lease_until>clock_timestamp() AND a.epoch=s.deployment_epoch AND t.enabled AND NOT t.draining
  FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original device continuity unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_owner_approval_keys k WHERE k.account_id=account AND k.signing_key_sec1=original.owner_point
  AND k.fingerprint=sha256(original.owner_point) AND k.revoked_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original approval key unavailable' USING ERRCODE='23514'; END IF;
 IF row.device_signing_key_id<>sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original.device_point)
  OR row.owner_approval_key_id<>sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original.owner_point) THEN
  RAISE EXCEPTION 'election signing identity differs' USING ERRCODE='23514'; END IF;
 row.proof_site_id:=device_session.site_id; row.proof_instance_id:=device_session.instance_id;
 row.proof_connection_epoch:=device_session.connection_epoch; row.proof_deployment_epoch:=device_session.deployment_epoch;
 session_bytes:=uuid_send(account)||uuid_send(row.device_id)||int4send(octet_length(row.proof_site_id))||convert_to(row.proof_site_id,'UTF8')
  ||int4send(octet_length(row.proof_instance_id))||convert_to(row.proof_instance_id,'UTF8')||int8send(row.proof_connection_epoch)
  ||int8send(row.proof_deployment_epoch)||int2send(2::smallint)||row.device_signing_key_id;
 IF row.device_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device-session/v1',session_bytes)) THEN
  RAISE EXCEPTION 'election device session differs' USING ERRCODE='23514'; END IF;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.payload_profile_election_quiescent(account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE relation_name text; occupied boolean;
BEGIN
 -- Deliberately conservative initial cut. Retained sealed effect/history or
 -- open ordinary liabilities are unsupported; nothing is deleted to qualify.
 IF EXISTS(SELECT FROM public.messages m WHERE m.account_id=account AND(m.transport_mode='sealed_candidate02'
   OR m.state NOT IN('delivered','failed','cancelled','expired')))
  OR EXISTS(SELECT FROM public.message_attempts a WHERE a.account_id=account AND a.status NOT IN('failed','proved_no_submit'))
  OR EXISTS(SELECT FROM public.dispatch_jobs j WHERE j.account_id=account AND j.finished_at IS NULL)
  OR EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.outcome NOT IN('failed'))
  OR(SELECT count(*) FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account)<>1
  OR EXISTS(SELECT FROM public.device_line_bindings b WHERE b.account_id=account AND b.purpose='sealed'
    AND NOT EXISTS(SELECT FROM public.payload_profile_v2_activation_receipts r WHERE(r.account_id,r.line_id,r.device_id,r.generation)=(b.account_id,b.line_id,b.device_id,b.generation))
    AND NOT EXISTS(SELECT FROM public.payload_profile_elections e WHERE(e.account_id,e.line_id,e.device_id,e.new_binding_generation)=(b.account_id,b.line_id,b.device_id,b.generation)))
  OR EXISTS(SELECT FROM public.line_activation_v2_pending p WHERE p.account_id=account AND p.purpose='sealed' AND p.installed_at IS NULL AND p.retired_at IS NULL)
  OR EXISTS(SELECT FROM public.sealed_line_key_receipts r WHERE r.account_id=account AND r.activated_ms IS NULL AND r.retired_ms IS NULL)
  OR EXISTS(SELECT FROM public.sealed_line_key_challenges c WHERE c.account_id=account AND c.completed_ms IS NULL) THEN
  RAISE EXCEPTION 'unclosed ordinary or sealed effect liability' USING ERRCODE='23514'; END IF;
 FOREACH relation_name IN ARRAY ARRAY[
  'sealed_grant_authorizations','sealed_inbound_events','sealed_event_deliveries','sealed_event_delivery_attempts',
  'conversation_intervals','conversation_confirmation_records','conversation_execution_records','conversation_inbound_provenance',
  'owner_conversation_consents','owner_android_proposals','agent_authority_grants','agent_authority_actions','agent_authority_approvals',
  'encrypted_templates','encrypted_template_versions','collaboration_drafts','collaboration_draft_grants',
  'original_reply_requests','original_reply_grants','original_reply_sources','original_reply_access','original_reply_consumptions',
  'workflow_contexts','workflow_context_versions','workflow_context_fences','workflow_context_audit','workflow_actions','workflow_action_versions',
  'workflow_openings','workflow_opening_requests','workflow_opening_allocations','workflow_opening_offers','workflow_message_links',
  'workflow_integration_grants','workflow_integration_access','workflow_connector_context_envelopes','workflow_reply_correlations',
  'workflow_routines','workflow_routine_calls','workflow_routine_policies','workflow_routine_admission_tombstones',
  'workflow_schedule_policies','workflow_schedule_series','workflow_schedule_occurrences'] LOOP
  EXECUTE format('SELECT EXISTS(SELECT FROM public.%I WHERE account_id=$1)',relation_name) INTO occupied USING account;
  IF occupied THEN RAISE EXCEPTION 'unsupported retained selection liability %',relation_name USING ERRCODE='23514'; END IF;
 END LOOP;
END;
$function$;

CREATE FUNCTION public.payload_profile_election_reserve(account uuid,opening uuid,user_id uuid,owner_session uuid,new_binding uuid,core bytea,successor bytea,factor_deadline_ms bigint)
RETURNS SETOF public.payload_profile_election_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_election_challenges%ROWTYPE; previous public.payload_profile_election_challenges%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR new_binding IS NULL OR factor_deadline_ms IS NULL
  OR opening='00000000-0000-0000-0000-000000000000'::uuid OR new_binding='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION 'election opening shape' USING ERRCODE='23514'; END IF;
 -- Historical retries do not allocate, debit, renew or restore permission.
 SELECT * INTO previous FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.opening_id=opening;
 IF FOUND THEN
  IF previous.initiating_user_id IS DISTINCT FROM user_id OR previous.initiating_session_id IS DISTINCT FROM owner_session
   OR previous.accepted_signed_manifest IS DISTINCT FROM successor OR core IS NULL
   OR substring(core FROM 41 FOR 16) IS DISTINCT FROM uuid_send(previous.line_id) THEN
   RAISE EXCEPTION 'election opening retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT previous; RETURN;
 END IF;
 row:=public.payload_profile_election_scope(account,user_id,owner_session,core,successor);
 row.opening_id:=opening; row.new_binding_id:=new_binding;
 row.reserve_deadline_ms:=least(row.expires_ms,factor_deadline_ms);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms>=row.reserve_deadline_ms OR row.new_binding_generation<>(SELECT last_issued_generation::numeric+1 FROM public.phone_lines WHERE account_id=account AND id=row.line_id)
  OR new_binding IN(opening,row.challenge_id,row.old_binding_id) OR(SELECT count(*) FROM public.payload_profile_election_challenges c WHERE c.account_id=account)>=16
  OR EXISTS(SELECT FROM public.payload_profile_elections e WHERE e.account_id=account)
  OR EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.closed_unaccepted_ms IS NULL AND c.expires_ms>row.issued_ms)
 THEN RAISE EXCEPTION 'election reservation unavailable' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_election_quiescent(account);
 -- Explicit new opening only. The immutable higher reservation is inserted
 -- before closures so the deferred FK/closure constraint can bind the chain.
 INSERT INTO public.payload_profile_election_challenges SELECT(row).*;
 UPDATE public.payload_profile_election_challenges c SET closed_unaccepted_ms=row.issued_ms,superseded_by_challenge_id=row.challenge_id
  WHERE c.account_id=account AND c.challenge_id<>row.challenge_id AND c.closed_unaccepted_ms IS NULL
   AND c.expires_ms<=row.issued_ms AND c.old_binding_id=row.old_binding_id AND c.line_id=row.line_id AND c.device_id=row.device_id
   AND c.root_fingerprint=row.root_fingerprint AND c.prior_signed_manifest=row.prior_signed_manifest
   AND NOT EXISTS(SELECT FROM public.payload_profile_elections e WHERE e.account_id=account AND e.challenge_id=c.challenge_id);
 UPDATE public.phone_lines l SET last_issued_generation=row.new_binding_generation WHERE l.account_id=account AND l.id=row.line_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'election line disappeared' USING ERRCODE='23514'; END IF;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.payload_profile_election_device_proof(account uuid,challenge uuid,signature bytea)
RETURNS SETOF public.payload_profile_election_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_election_challenges%ROWTYPE; checked public.payload_profile_election_challenges%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR challenge IS NULL OR signature IS NULL OR octet_length(signature)<>64 THEN
  RAISE EXCEPTION 'election device proof shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=challenge;
 IF NOT FOUND THEN RAISE EXCEPTION 'election challenge unavailable' USING ERRCODE='23514'; END IF;
 IF row.device_signature IS NOT NULL THEN
  IF row.device_signature<>signature THEN RAISE EXCEPTION 'election device proof conflict' USING ERRCODE='23514'; END IF;
  RETURN NEXT row; RETURN;
 END IF;
 IF row.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'election challenge closed' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_election_scope(account,row.initiating_user_id,row.initiating_session_id,row.core,row.accepted_signed_manifest);
 IF row.new_binding_generation<>(SELECT last_issued_generation FROM public.phone_lines WHERE account_id=account AND id=row.line_id) THEN
  RAISE EXCEPTION 'election reservation is no longer current' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 UPDATE public.payload_profile_election_challenges c SET device_signature=signature,device_proof_ms=now_ms
  WHERE c.account_id=account AND c.challenge_id=challenge AND c.device_signature IS NULL AND c.closed_unaccepted_ms IS NULL
  RETURNING c.* INTO row;
 IF NOT FOUND THEN RAISE EXCEPTION 'election proof changed' USING ERRCODE='23514'; END IF;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.payload_profile_election_accept(account uuid,opening uuid,challenge uuid,bundle bytea,factor_deadline_ms bigint)
RETURNS SETOF public.payload_profile_elections
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_election_challenges%ROWTYPE; checked public.payload_profile_election_challenges%ROWTYPE;
 accepted public.payload_profile_elections%ROWTYPE; now_ms bigint; at_time timestamptz;
BEGIN
 IF account IS NULL OR opening IS NULL OR challenge IS NULL OR bundle IS NULL OR octet_length(bundle)<>628 OR factor_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'election acceptance shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO accepted FROM public.payload_profile_elections e WHERE e.account_id=account AND e.opening_id=opening;
 IF FOUND THEN
  IF accepted.challenge_id<>challenge OR accepted.bundle<>bundle THEN RAISE EXCEPTION 'accepted election retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT accepted; RETURN;
 END IF;
 SELECT * INTO row FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.opening_id=opening AND c.challenge_id=challenge;
 IF NOT FOUND OR row.closed_unaccepted_ms IS NOT NULL OR row.device_signature IS NULL
  OR substring(bundle FROM 1 FOR 500)<>row.core OR substring(bundle FROM 501 FOR 64)<>row.device_signature THEN
  RAISE EXCEPTION 'original device election proof unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_election_scope(account,row.initiating_user_id,row.initiating_session_id,row.core,row.accepted_signed_manifest);
 IF row.new_binding_generation<>(SELECT last_issued_generation FROM public.phone_lines WHERE account_id=account AND id=row.line_id)
  OR EXISTS(SELECT FROM public.payload_profile_elections e WHERE e.account_id=account) THEN
  RAISE EXCEPTION 'election reservation is no longer current' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_election_quiescent(account);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<row.issued_ms OR now_ms>=least(row.expires_ms,factor_deadline_ms) OR row.device_proof_ms>now_ms THEN
  RAISE EXCEPTION 'election acceptance expired or clock regressed' USING ERRCODE='23514'; END IF;
 at_time:=to_timestamp(now_ms::numeric/1000);
 accepted.account_id:=account; accepted.opening_id:=opening; accepted.challenge_id:=challenge;
 accepted.device_id:=row.device_id; accepted.line_id:=row.line_id; accepted.old_binding_id:=row.old_binding_id; accepted.new_binding_id:=row.new_binding_id;
 accepted.old_binding_generation:=row.old_binding_generation; accepted.new_binding_generation:=row.new_binding_generation;
 accepted.selection_epoch:=1; accepted.vault_generation:=1; accepted.prior_manifest_version:=row.prior_manifest_version;
 accepted.accepted_manifest_version:=row.accepted_manifest_version; accepted.accepted_at_ms:=now_ms;
 accepted.acceptance_deadline_ms:=least(row.expires_ms,factor_deadline_ms); accepted.root_fingerprint:=row.root_fingerprint;
 accepted.old_binding_proof_digest:=row.old_binding_proof_digest; accepted.selected_reader_key_id:=row.selected_reader_key_id;
 accepted.prior_manifest_digest:=row.prior_manifest_digest; accepted.prior_signed_manifest_sha256:=row.prior_signed_manifest_sha256;
 accepted.accepted_manifest_digest:=row.accepted_manifest_digest; accepted.accepted_signed_manifest_sha256:=row.accepted_signed_manifest_sha256;
 accepted.election_core_sha256:=sha256(row.core); accepted.election_bundle_sha256:=sha256(bundle);
 accepted.election_commitment:=sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/commitment/v1',row.core));
 accepted.device_signature:=row.device_signature; accepted.owner_signature:=substring(bundle FROM 565 FOR 64); accepted.bundle:=bundle;
 accepted.device_confirmation_digest:=sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device/v1',row.core)||accepted.device_signature);
 accepted.owner_approval_digest:=sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner/v1',row.core||sha256(accepted.device_signature))||accepted.owner_signature);
 INSERT INTO public.payload_profile_elections SELECT(accepted).*;
 -- Old activation/proof/installation rows are historical and untouched.
 UPDATE public.device_line_bindings b SET state='revoked' WHERE(b.account_id,b.line_id,b.device_id,b.generation)=(account,row.line_id,row.device_id,row.old_binding_generation) AND b.state='active';
 IF NOT FOUND THEN RAISE EXCEPTION 'original binding changed' USING ERRCODE='23514'; END IF;
 INSERT INTO public.device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,created_at,activated_at)
  VALUES(account,row.line_id,row.device_id,row.new_binding_generation,'active','sealed',accepted.owner_approval_digest,accepted.device_confirmation_digest,at_time,at_time);
 UPDATE public.phone_lines l SET current_binding_generation=row.new_binding_generation WHERE l.account_id=account AND l.id=row.line_id;
 UPDATE public.sealed_manifest_authorities a SET version=row.accepted_manifest_version,semantic_digest=row.accepted_manifest_digest,
  manifest=row.accepted_signed_manifest,accepted_at_ms=now_ms,last_verified_ms=now_ms WHERE a.account_id=account;
 DELETE FROM public.line_readiness_observations o WHERE o.account_id=account;
 UPDATE public.payload_profile_account_anchors a SET selection_epoch=1 WHERE a.account_id=account AND a.state='live' AND a.selection_epoch=0;
 IF NOT FOUND THEN RAISE EXCEPTION 'selection anchor changed' USING ERRCODE='23514'; END IF;
 -- Deferred completion repeats structural currentness and the primary deadline
 -- after all remaining transaction waits; no partial ledger can commit.
 RETURN NEXT accepted;
END;
$function$;



CREATE FUNCTION public.payload_profile_election_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.payload_profile_election_challenges%ROWTYPE; original public.payload_profile_election_challenges%ROWTYPE;
 target public.payload_profile_election_challenges%ROWTYPE; wanted uuid; state text; epoch bigint; now_ms bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN('public.payload_profile_election_challenges'::regclass,'public.payload_profile_elections'::regclass)
  OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'unexpected election writer context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN wanted:=OLD.account_id; ELSE wanted:=NEW.account_id; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN
  RAISE EXCEPTION 'election writer fence busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted FOR SHARE NOWAIT;
 IF NOT FOUND OR state NOT IN('live','deleted') OR epoch<0 THEN RAISE EXCEPTION 'election anchor unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=wanted) THEN RAISE EXCEPTION 'election history cannot be deleted' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF state<>'live' OR epoch<>0 THEN RAISE EXCEPTION 'election mutation requires original02' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_RELID='public.payload_profile_election_challenges'::regclass THEN
  IF TG_OP='INSERT' THEN
   checked:=public.payload_profile_election_scope(NEW.account_id,NEW.initiating_user_id,NEW.initiating_session_id,NEW.core,NEW.accepted_signed_manifest);
   IF(to_jsonb(NEW)-ARRAY['opening_id','new_binding_id','reserve_deadline_ms']) IS DISTINCT FROM(to_jsonb(checked)-ARRAY['opening_id','new_binding_id','reserve_deadline_ms'])
    OR NEW.device_signature IS NOT NULL OR NEW.closed_unaccepted_ms IS NOT NULL
    OR NEW.reserve_deadline_ms<=now_ms OR NEW.reserve_deadline_ms>NEW.expires_ms
    OR NEW.new_binding_generation<>(SELECT last_issued_generation::numeric+1 FROM public.phone_lines WHERE account_id=NEW.account_id AND id=NEW.line_id)
    OR(SELECT count(*) FROM public.payload_profile_election_challenges c WHERE c.account_id=NEW.account_id)>=16
    OR EXISTS(SELECT FROM public.payload_profile_elections e WHERE e.account_id=NEW.account_id)
    OR EXISTS(SELECT FROM public.payload_profile_election_challenges c WHERE c.account_id=NEW.account_id AND c.closed_unaccepted_ms IS NULL AND c.expires_ms>NEW.issued_ms) THEN
    RAISE EXCEPTION 'election reservation row differs' USING ERRCODE='23514'; END IF;
   -- A lock alone leaves old RR/SSI snapshots usable after this commit.
   -- Every actual new election mutation versions the retained anchor tuple;
   -- old-snapshot writers must fail before consulting stale policy rows.
   UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
   RETURN NEW;
  END IF;
  IF TG_OP<>'UPDATE' OR(to_jsonb(NEW)-ARRAY['device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_challenge_id']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_challenge_id']) THEN
   RAISE EXCEPTION 'election reservation identity is immutable' USING ERRCODE='23514'; END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF OLD.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'closed election is immutable' USING ERRCODE='23514'; END IF;
  IF NEW.closed_unaccepted_ms IS NOT NULL THEN
   IF NEW.device_signature IS DISTINCT FROM OLD.device_signature OR NEW.device_proof_ms IS DISTINCT FROM OLD.device_proof_ms
    OR NEW.closed_unaccepted_ms<OLD.expires_ms OR NEW.closed_unaccepted_ms>now_ms
    OR EXISTS(SELECT FROM public.payload_profile_elections e WHERE e.account_id=OLD.account_id AND e.challenge_id=OLD.challenge_id) THEN
    RAISE EXCEPTION 'election closure differs' USING ERRCODE='23514'; END IF;
   SELECT * INTO target FROM public.payload_profile_election_challenges c WHERE c.account_id=NEW.account_id AND c.challenge_id=NEW.superseded_by_challenge_id;
   IF NOT FOUND OR target.new_binding_generation<=OLD.new_binding_generation OR target.closed_unaccepted_ms IS NOT NULL
    OR target.expires_ms<=now_ms OR target.reserve_deadline_ms<=now_ms OR NEW.closed_unaccepted_ms<>target.issued_ms
    OR(target.old_binding_id,target.line_id,target.device_id,target.root_pin,target.prior_signed_manifest,target.prior_selection_epoch)
     IS DISTINCT FROM(OLD.old_binding_id,OLD.line_id,OLD.device_id,OLD.root_pin,OLD.prior_signed_manifest,OLD.prior_selection_epoch) THEN
    RAISE EXCEPTION 'election closure requires fresh higher same-scope reservation' USING ERRCODE='23514'; END IF;
   checked:=public.payload_profile_election_scope(target.account_id,target.initiating_user_id,target.initiating_session_id,target.core,target.accepted_signed_manifest);
  ELSE
   IF OLD.device_signature IS NOT NULL OR NEW.device_signature IS NULL OR NEW.device_proof_ms IS NULL
    OR NEW.device_proof_ms<OLD.issued_ms OR NEW.device_proof_ms>now_ms OR now_ms>=OLD.expires_ms THEN
    RAISE EXCEPTION 'election device proof is one-time' USING ERRCODE='23514'; END IF;
   checked:=public.payload_profile_election_scope(OLD.account_id,OLD.initiating_user_id,OLD.initiating_session_id,OLD.core,OLD.accepted_signed_manifest);
  END IF;
  UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'accepted election is immutable' USING ERRCODE='23514'; END IF;
 SELECT * INTO original FROM public.payload_profile_election_challenges c WHERE c.account_id=NEW.account_id AND c.opening_id=NEW.opening_id AND c.challenge_id=NEW.challenge_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR original.closed_unaccepted_ms IS NOT NULL OR original.device_signature IS NULL
  OR NEW.accepted_at_ms<original.issued_ms OR NEW.accepted_at_ms>now_ms OR NEW.acceptance_deadline_ms>original.expires_ms
  OR now_ms>=NEW.acceptance_deadline_ms
  OR(NEW.device_id,NEW.line_id,NEW.old_binding_id,NEW.new_binding_id,NEW.old_binding_generation,NEW.new_binding_generation,NEW.vault_generation,NEW.prior_manifest_version,NEW.accepted_manifest_version,NEW.root_fingerprint,NEW.old_binding_proof_digest,NEW.selected_reader_key_id,NEW.prior_manifest_digest,NEW.prior_signed_manifest_sha256,NEW.accepted_manifest_digest,NEW.accepted_signed_manifest_sha256,NEW.device_signature)
   IS DISTINCT FROM(original.device_id,original.line_id,original.old_binding_id,original.new_binding_id,original.old_binding_generation,original.new_binding_generation,original.vault_generation,original.prior_manifest_version,original.accepted_manifest_version,original.root_fingerprint,original.old_binding_proof_digest,original.selected_reader_key_id,original.prior_manifest_digest,original.prior_signed_manifest_sha256,original.accepted_manifest_digest,original.accepted_signed_manifest_sha256,original.device_signature)
  OR NEW.bundle<>original.core||NEW.device_signature||NEW.owner_signature
  OR NEW.election_core_sha256<>sha256(original.core) OR NEW.election_bundle_sha256<>sha256(NEW.bundle)
  OR NEW.election_commitment<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/commitment/v1',original.core))
  OR NEW.device_confirmation_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device/v1',original.core)||NEW.device_signature)
  OR NEW.owner_approval_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner/v1',original.core||sha256(NEW.device_signature))||NEW.owner_signature) THEN
  RAISE EXCEPTION 'accepted election differs from retained original proof' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_election_scope(original.account_id,original.initiating_user_id,original.initiating_session_id,original.core,original.accepted_signed_manifest);
 PERFORM public.payload_profile_election_quiescent(NEW.account_id);
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
 RETURN NEW;
END;
$function$;

CREATE FUNCTION public.payload_profile_election_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE reservation public.payload_profile_election_challenges%ROWTYPE; target public.payload_profile_election_challenges%ROWTYPE;
 accepted public.payload_profile_elections%ROWTYPE; now_ms bigint; checked public.payload_profile_election_challenges%ROWTYPE;
BEGIN
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_RELID='public.payload_profile_election_challenges'::regclass THEN
  SELECT * INTO reservation FROM public.payload_profile_election_challenges c WHERE c.account_id=NEW.account_id AND c.challenge_id=NEW.challenge_id;
  IF NOT FOUND THEN
   IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'election reservation disappeared' USING ERRCODE='23514'; END IF;
   RETURN NULL;
  END IF;
  IF TG_OP='INSERT' AND(now_ms>=reservation.reserve_deadline_ms OR now_ms<reservation.issued_ms
    OR NOT EXISTS(SELECT FROM public.phone_lines l WHERE l.account_id=NEW.account_id AND l.id=NEW.line_id AND l.last_issued_generation>=NEW.new_binding_generation)) THEN
   RAISE EXCEPTION 'reservation/highwater/deadline did not commit together' USING ERRCODE='23514'; END IF;
  IF reservation.closed_unaccepted_ms IS NOT NULL THEN
   SELECT * INTO target FROM public.payload_profile_election_challenges c WHERE c.account_id=reservation.account_id AND c.challenge_id=reservation.superseded_by_challenge_id;
   IF NOT FOUND OR target.new_binding_generation<=reservation.new_binding_generation OR target.old_binding_id<>reservation.old_binding_id
    OR target.line_id<>reservation.line_id OR target.device_id<>reservation.device_id OR target.root_pin<>reservation.root_pin
    OR target.prior_signed_manifest<>reservation.prior_signed_manifest OR now_ms<reservation.closed_unaccepted_ms OR reservation.closed_unaccepted_ms<>target.issued_ms THEN
    RAISE EXCEPTION 'election closure target did not commit' USING ERRCODE='23514'; END IF;
  ELSIF TG_OP='UPDATE' AND now_ms>=reservation.expires_ms THEN
   RAISE EXCEPTION 'device election proof expired before commit' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO accepted FROM public.payload_profile_elections e WHERE e.account_id=NEW.account_id AND e.challenge_id=NEW.challenge_id;
 IF NOT FOUND THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'accepted election disappeared' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO reservation FROM public.payload_profile_election_challenges c WHERE c.account_id=accepted.account_id AND c.challenge_id=accepted.challenge_id;
 IF NOT FOUND OR reservation.closed_unaccepted_ms IS NOT NULL OR now_ms<accepted.accepted_at_ms OR now_ms>=accepted.acceptance_deadline_ms
  OR NOT EXISTS(SELECT FROM public.payload_profile_account_anchors a WHERE a.account_id=accepted.account_id AND a.state='live' AND a.selection_epoch=accepted.selection_epoch)
  OR NOT EXISTS(SELECT FROM public.sealed_manifest_authorities a WHERE a.account_id=accepted.account_id AND a.root_pin=reservation.root_pin
    AND a.root_fingerprint=accepted.root_fingerprint AND a.generation=1 AND a.revoked_at IS NULL AND a.anchor_digest=decode(repeat('00',32),'hex')
    AND a.version=accepted.accepted_manifest_version AND a.semantic_digest=accepted.accepted_manifest_digest AND a.manifest=reservation.accepted_signed_manifest
    AND a.accepted_at_ms=accepted.accepted_at_ms AND a.last_verified_ms>=accepted.accepted_at_ms AND a.last_verified_ms<=now_ms)
  OR NOT EXISTS(SELECT FROM public.phone_lines l WHERE l.account_id=accepted.account_id AND l.id=accepted.line_id AND l.state='active'
    AND l.current_binding_generation=accepted.new_binding_generation AND l.last_issued_generation=accepted.new_binding_generation)
  OR NOT EXISTS(SELECT FROM public.device_line_bindings b WHERE(b.account_id,b.line_id,b.device_id,b.generation)=(accepted.account_id,accepted.line_id,accepted.device_id,accepted.old_binding_generation) AND b.state='revoked' AND b.purpose='sealed')
  OR NOT EXISTS(SELECT FROM public.device_line_bindings b WHERE(b.account_id,b.line_id,b.device_id,b.generation)=(accepted.account_id,accepted.line_id,accepted.device_id,accepted.new_binding_generation)
    AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest=accepted.owner_approval_digest AND b.device_confirmation_digest=accepted.device_confirmation_digest)
  OR NOT EXISTS(SELECT FROM public.original_reply_manifest_history h WHERE h.account_id=accepted.account_id AND h.root_generation=1
    AND h.version=reservation.prior_manifest_version AND h.digest=reservation.prior_manifest_digest AND h.manifest=reservation.prior_signed_manifest AND h.accepted_at_ms=reservation.prior_accepted_at_ms)
  OR NOT EXISTS(SELECT FROM public.original_reply_manifest_history h WHERE h.account_id=accepted.account_id AND h.root_generation=1
    AND h.version=accepted.accepted_manifest_version AND h.digest=accepted.accepted_manifest_digest AND h.manifest=reservation.accepted_signed_manifest AND h.accepted_at_ms=accepted.accepted_at_ms)
  OR EXISTS(SELECT FROM public.line_readiness_observations o WHERE o.account_id=accepted.account_id) THEN
  RAISE EXCEPTION 'accepted ledger/authority/binding/anchor did not commit together' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.sessions s JOIN public.memberships m ON(m.account_id,m.user_id)=(s.account_id,s.user_id)
  JOIN public.users u ON u.id=m.user_id JOIN public.owner_mfa f ON(f.account_id,f.user_id)=(m.account_id,m.user_id)
  WHERE s.account_id=accepted.account_id AND s.id=reservation.initiating_session_id AND s.user_id=reservation.initiating_user_id
   AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND m.role='owner' AND m.revoked_at IS NULL
   AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL
   AND coalesce(s.last_used_at,s.created_at)<=clock_timestamp() AND coalesce(s.last_used_at,s.created_at)>clock_timestamp()-interval '72 hours'
  FOR SHARE OF s,m,u,f NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'election owner changed before commit' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.sites t ON t.site_id=s.site_id
  JOIN public.deployment_authority a ON a.singleton JOIN public.line_activation_v2_pending p ON p.challenge_id=reservation.activation_challenge_id
  WHERE s.account_id=accepted.account_id AND s.device_id=accepted.device_id AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.signing_key_sec1=reservation.device_point AND s.site_id=reservation.proof_site_id AND s.instance_id=reservation.proof_instance_id
   AND s.connection_epoch=reservation.proof_connection_epoch AND s.deployment_epoch=reservation.proof_deployment_epoch
   AND s.line_activation_version=2 AND s.lease_until>clock_timestamp() AND t.enabled AND NOT t.draining AND a.epoch=s.deployment_epoch
   AND p.account_id=accepted.account_id AND p.installed_at IS NOT NULL AND p.nonce IS NULL AND p.retired_at IS NULL
  FOR SHARE OF s,d,k,t,a,p NOWAIT;
 IF NOT FOUND OR NOT EXISTS(SELECT FROM public.line_owner_approval_keys k WHERE k.account_id=accepted.account_id AND k.signing_key_sec1=reservation.owner_point AND k.revoked_at IS NULL) THEN
  RAISE EXCEPTION 'election device or approval key changed before commit' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_election_quiescent(accepted.account_id);
 PERFORM public.payload_profile_election_reader(reservation.prior_signed_manifest,2::smallint,reservation.selected_reader_key_id,reservation.device_id,reservation.line_id,now_ms);
 PERFORM public.payload_profile_election_reader(reservation.accepted_signed_manifest,3::smallint,reservation.selected_reader_key_id,reservation.device_id,reservation.line_id,now_ms);
 IF public.payload_profile_election_number(substring(reservation.prior_signed_manifest FROM 46 FOR 8))<=now_ms
  OR public.payload_profile_election_number(substring(reservation.accepted_signed_manifest FROM 48 FOR 8))<=now_ms THEN
  RAISE EXCEPTION 'election manifest expired before commit' USING ERRCODE='23514'; END IF;
 IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=accepted.acceptance_deadline_ms THEN
  RAISE EXCEPTION 'election deadline passed after waits' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;

CREATE TRIGGER payload_profile_election_challenge_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_election_challenges
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_election_rows_guard();
CREATE TRIGGER payload_profile_election_accepted_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_elections
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_election_rows_guard();
CREATE CONSTRAINT TRIGGER payload_profile_election_challenge_after_change AFTER INSERT OR UPDATE ON public.payload_profile_election_challenges
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.payload_profile_election_complete();
CREATE CONSTRAINT TRIGGER payload_profile_election_accepted_after_insert AFTER INSERT ON public.payload_profile_elections
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.payload_profile_election_complete();

-- Preserve exact legacy02 bounds. Only the explicitly framed03 successor has
-- its two extra header bytes admitted by this deliberate schema evolution.
ALTER TABLE public.sealed_manifest_authorities DROP CONSTRAINT sealed_manifest_authorities_check1;
ALTER TABLE public.sealed_manifest_authorities ADD CONSTRAINT sealed_manifest_authorities_check1 CHECK(
 (version=0 AND semantic_digest IS NULL AND manifest IS NULL AND accepted_at_ms IS NULL AND last_verified_ms=0)
 OR(version>0 AND semantic_digest IS NOT NULL AND octet_length(semantic_digest)=32 AND manifest IS NOT NULL
  AND((octet_length(manifest)>=364 AND octet_length(manifest)<=9751 AND substring(manifest FROM 1 FOR 5)=decode('5a544d4102','hex'))
   OR(octet_length(manifest)>=366 AND octet_length(manifest)<=9753 AND substring(manifest FROM 1 FOR 6)=decode('5a544d410303','hex')))
  AND accepted_at_ms IS NOT NULL AND accepted_at_ms>0 AND last_verified_ms>=accepted_at_ms));
ALTER TABLE public.original_reply_manifest_history DROP CONSTRAINT original_reply_manifest_history_manifest_check;
ALTER TABLE public.original_reply_manifest_history ADD CONSTRAINT original_reply_manifest_history_manifest_check CHECK(
 (octet_length(manifest)>=364 AND octet_length(manifest)<=9751 AND substring(manifest FROM 1 FOR 5)=decode('5a544d4102','hex'))
 OR(octet_length(manifest)>=366 AND octet_length(manifest)<=9753 AND substring(manifest FROM 1 FOR 6)=decode('5a544d410303','hex')));

CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=110 AND min(version)=1 AND max(version)=110 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=110 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE FUNCTION public.payload_profile_election_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_v2_ready()
  AND has_table_privilege(current_user,'public.payload_profile_election_challenges','SELECT')
  AND has_table_privilege(current_user,'public.payload_profile_elections','SELECT')
  AND NOT has_table_privilege(current_user,'public.payload_profile_election_challenges','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_table_privilege(current_user,'public.payload_profile_elections','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_election_challenges','INSERT,UPDATE,REFERENCES')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_elections','INSERT,UPDATE,REFERENCES')
  AND has_function_privilege(current_user,'public.payload_profile_election_reserve(uuid,uuid,uuid,uuid,uuid,bytea,bytea,bigint)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_election_device_proof(uuid,uuid,bytea)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_election_accept(uuid,uuid,uuid,bytea,bigint)','EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
   AND(p.proname LIKE 'payload_profile_election_%' OR p.proname IN('payload_profile_epoch_valid','payload_profile_writer_policy'))
   AND p.proname NOT IN('payload_profile_election_reserve','payload_profile_election_device_proof','payload_profile_election_accept','payload_profile_election_ready')
   AND has_function_privilege(current_user,p.oid,'EXECUTE'))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND(p.proname LIKE 'payload_profile_election_%' OR p.proname IN('payload_profile_epoch_valid','payload_profile_writer_policy')) AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; relation_name text; columns_sql text;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['payload_profile_election_challenges','payload_profile_elections'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
  AND(p.proname LIKE 'payload_profile_election_%' OR p.proname IN('payload_profile_epoch_valid','payload_profile_writer_policy')) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_election_reserve','payload_profile_election_device_proof','payload_profile_election_accept','payload_profile_election_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

-- This serial migration is the only baseline replacement. No runtime factory
-- may alter a graph, an epoch or an accepted ledger without this exact coupling.
DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=110);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,110,public.payload_profile_writer_graph());
