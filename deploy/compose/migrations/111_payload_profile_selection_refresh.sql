-- SPDX-License-Identifier: AGPL-3.0-only
-- Explicit same-phone physical selection, not message or owner authentication.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';

DO $migration$
DECLARE writer_expected record; writer_installation bigint:=110; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN RAISE EXCEPTION 'physical refresh requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation=110 THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=110 THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=110 THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation=110 THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
                RAISE EXCEPTION 'mandatory writer helper body or configuration is inconsistent';
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
                    RAISE EXCEPTION 'original receipt helper body or configuration is inconsistent';
                END IF;
            END LOOP;
FOR writer_expected IN SELECT * FROM(VALUES
            ('payload_profile_election_frame(text, bytea)','8fd5f8d723cf6677505d6248f9f85c4fec9245aa9236e28381658ffb63f3fc2a','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['label','payload']::text[]),
            ('payload_profile_election_number(bytea)','b1a28fd0a424639493ca0eaacaffc4be71bea8bb4ba56df258986cff11b0141d','bigint','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
            ('payload_profile_election_uuid(bytea)','0bfacb9086bc70824ab4a6278bedf158a8f411cec12b5f4c1f7afadac6dc196b','uuid','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
            ('payload_profile_election_reader(bytea, smallint, bytea, uuid, uuid, bigint)','84be4fbc0947641795dfe6437450926a738bc2f1a56ff0a13d54368b0e180496','bytea','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['manifest','profile','reader_id','device','line','checked_ms']::text[]),
            ('payload_profile_election_old_binding(uuid, uuid, bytea)','d92120a075ce107f938dd52394c623731b61aa9e5a3387011832d7b1de0aa16b','bytea','plpgsql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','binding','reader']::text[]),
            ('payload_profile_epoch_valid(uuid, bigint)','cb08001590eaee6c7b32b4773f47044b8ea446a4268d44bf191c00400841e306','boolean','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_anchor_row_guard()','0ed220f3ff932629aba5f1acbc1326cb8003c2195abb404bcb12c96bf70ac1b4','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_election_scope(uuid, uuid, uuid, bytea, bytea)','9bbe50d7d7bae291d29647573f3473f1f66fa6c19202fb75f749951abdda5f8f','public.payload_profile_election_challenges','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','owner_user','owner_session','core','successor']::text[]),
            ('payload_profile_election_quiescent(uuid)','5e7b9570df8e5b62a665efd0537d9a3deb0ac3a5b5a5efdca6df54613dd0c4f5','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account']::text[]),
            ('payload_profile_election_reserve(uuid, uuid, uuid, uuid, uuid, bytea, bytea, bigint)','3b709b74b610cd703e39b5d87d54e216abed00c99e79796c4bca6d0b94aab07f','public.payload_profile_election_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','user_id','owner_session','new_binding','core','successor','factor_deadline_ms']::text[]),
            ('payload_profile_election_device_proof(uuid, uuid, bytea)','b7734409e473af0b66208a7e3fde5bedc8aa687cc53aadef123626e111a906a1','public.payload_profile_election_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','challenge','signature']::text[]),
            ('payload_profile_election_accept(uuid, uuid, uuid, bytea, bigint)','a23684bc7df00888fe0ee38819c3d4f62d19c04f4638bcd52b7a28d72872128b','public.payload_profile_elections','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','challenge','bundle','factor_deadline_ms']::text[]),
            ('payload_profile_election_rows_guard()','92d3774e7277ddf15130fe277db8239fc25d943507d00c0769e52e1391a334c1','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_election_complete()','a39eca2b0ca230504de16b9659d5c1fa11b265251237bd0be6afd597388221f8','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_election_ready()','88ba46c1275c9948dbe3a1dc6adac73e3fe4c8cd6f4a004b7e06372535b3e2ad','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'election helper declaration or body inconsistent'; END IF;
          END LOOP;
 IF NOT(SELECT count(*)=110 AND min(version)=1 AND max(version)=110 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=110 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'physical refresh predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

CREATE TABLE public.payload_profile_selection_challenges (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL CHECK(opening_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 refresh_id uuid NOT NULL UNIQUE CHECK(refresh_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 initiating_user_id uuid NOT NULL,
 initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 binding_id uuid NOT NULL,
 election_challenge_id uuid NOT NULL,
 original_binding_id uuid NOT NULL,
 activation_challenge_id uuid NOT NULL,
 registration_id uuid NOT NULL,
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 vault_generation bigint NOT NULL CHECK(vault_generation=1),
 manifest_version bigint NOT NULL CHECK(manifest_version>0),
 selection_epoch bigint NOT NULL CHECK(selection_epoch=1),
 manifest_accepted_ms bigint NOT NULL CHECK(manifest_accepted_ms>0),
 issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
 reserve_deadline_ms bigint NOT NULL CHECK(reserve_deadline_ms>issued_ms AND reserve_deadline_ms<=expires_ms),
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),
 proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 original_subscription_id integer NOT NULL CHECK(original_subscription_id>=0),
 proof_site_id text NOT NULL CHECK(octet_length(proof_site_id)>=1 AND octet_length(proof_site_id)<=256),
 proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id)>=1 AND octet_length(proof_instance_id)<=256),
 core bytea NOT NULL CHECK(octet_length(core)=496),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32 AND nonce<>decode(repeat('00',32),'hex')),
 root_pin bytea NOT NULL CHECK(octet_length(root_pin)=94),
 root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
 election_commitment bytea NOT NULL CHECK(octet_length(election_commitment)=32),
 election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32),
 selected_reader_key_id bytea NOT NULL CHECK(octet_length(selected_reader_key_id)=32),
 device_signing_key_id bytea NOT NULL CHECK(octet_length(device_signing_key_id)=32),
 owner_approval_key_id bytea NOT NULL CHECK(octet_length(owner_approval_key_id)=32),
 device_point bytea NOT NULL CHECK(octet_length(device_point)=65 AND get_byte(device_point,0)=4),
 owner_point bytea NOT NULL CHECK(octet_length(owner_point)=65 AND get_byte(owner_point,0)=4),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 signed_manifest_sha256 bytea NOT NULL CHECK(octet_length(signed_manifest_sha256)=32),
 signed_manifest bytea NOT NULL CHECK(octet_length(signed_manifest)>=366 AND octet_length(signed_manifest)<=9753),
 configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32),
 owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32),
 device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32),
 device_observation bytea CHECK(device_observation IS NULL OR octet_length(device_observation)=121),
 device_signature bytea CHECK(device_signature IS NULL OR octet_length(device_signature)=64),
 device_proof_ms bigint,
 closed_unaccepted_ms bigint,
 superseded_by_refresh_id uuid,
 PRIMARY KEY(account_id,opening_id),
 UNIQUE(account_id,refresh_id),
 FOREIGN KEY(account_id,election_challenge_id) REFERENCES public.payload_profile_elections(account_id,challenge_id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,superseded_by_refresh_id) REFERENCES public.payload_profile_selection_challenges(account_id,refresh_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(refresh_id<>opening_id AND refresh_id<>binding_id),
 CHECK((device_observation IS NULL)=(device_signature IS NULL) AND(device_signature IS NULL)=(device_proof_ms IS NULL)),
 CHECK(device_proof_ms IS NULL OR device_proof_ms>=issued_ms AND device_proof_ms<expires_ms),
 CHECK((closed_unaccepted_ms IS NULL)=(superseded_by_refresh_id IS NULL)),
 CHECK(closed_unaccepted_ms IS NULL OR closed_unaccepted_ms>=expires_ms)
);

CREATE TABLE public.payload_profile_selection_receipts (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL,
 refresh_id uuid NOT NULL,
 device_id uuid NOT NULL,
 line_id uuid NOT NULL,
 binding_id uuid NOT NULL,
 election_challenge_id uuid NOT NULL,
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 selection_epoch bigint NOT NULL CHECK(selection_epoch=1),
 accepted_ms bigint NOT NULL CHECK(accepted_ms>0),
 approval_deadline_ms bigint NOT NULL CHECK(approval_deadline_ms>accepted_ms),
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),
 proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 proof_site_id text NOT NULL CHECK(octet_length(proof_site_id)>=1 AND octet_length(proof_site_id)<=256),
 proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id)>=1 AND octet_length(proof_instance_id)<=256),
 device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32),
 device_observation bytea NOT NULL CHECK(octet_length(device_observation)=121),
 device_signature bytea NOT NULL CHECK(octet_length(device_signature)=64),
 owner_signature bytea NOT NULL CHECK(octet_length(owner_signature)=64),
 bundle bytea NOT NULL CHECK(octet_length(bundle)=745),
 bundle_sha256 bytea NOT NULL CHECK(bundle_sha256=sha256(bundle)),
 installed_signature bytea CHECK(installed_signature IS NULL OR octet_length(installed_signature)=64),
 installed_ms bigint CHECK(installed_ms IS NULL OR installed_ms>=accepted_ms),
 PRIMARY KEY(account_id,refresh_id),
 UNIQUE(account_id,opening_id),
 UNIQUE(account_id,binding_id,proof_site_id,proof_instance_id,proof_connection_epoch,proof_deployment_epoch),
 FOREIGN KEY(account_id,refresh_id) REFERENCES public.payload_profile_selection_challenges(account_id,refresh_id) ON DELETE CASCADE,
 CHECK((installed_signature IS NULL)=(installed_ms IS NULL))
);

-- Current structural selection, not a cryptographic or owner-auth witness.
-- Owner selectors may be retained historical IDs during device proof/ACK;
-- fresh owner authentication is a separate mandatory open/approve check.
CREATE FUNCTION public.payload_profile_selection_scope(account uuid,owner_user uuid,owner_session uuid,core bytea)
RETURNS public.payload_profile_selection_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_selection_challenges%ROWTYPE; authority public.sealed_manifest_authorities%ROWTYPE;
 election public.payload_profile_elections%ROWTYPE; reservation public.payload_profile_election_challenges%ROWTYPE;
 original public.payload_profile_v2_activation_receipts%ROWTYPE; device_session public.device_sessions%ROWTYPE;
 state text; epoch bigint; now_ms bigint; session_bytes bytea;
BEGIN
 IF account IS NULL OR owner_user IS NULL OR owner_session IS NULL OR core IS NULL OR octet_length(core)<>496
  OR substring(core FROM 1 FOR 8)<>decode('5a54535201030300','hex') OR substring(core FROM 489 FOR 8)<>decode(repeat('00',8),'hex')
  OR pg_is_in_recovery() THEN RAISE EXCEPTION 'physical selection core unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO authority FROM public.sealed_manifest_authorities a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'physical selection authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN
  RAISE EXCEPTION 'physical selection account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'accepted physical selection anchor unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'physical selection account unavailable' USING ERRCODE='23514'; END IF;
 row.account_id:=public.payload_profile_election_uuid(substring(core FROM 9 FOR 16));
 row.device_id:=public.payload_profile_election_uuid(substring(core FROM 25 FOR 16));
 row.line_id:=public.payload_profile_election_uuid(substring(core FROM 41 FOR 16));
 row.refresh_id:=public.payload_profile_election_uuid(substring(core FROM 57 FOR 16));
 row.binding_id:=public.payload_profile_election_uuid(substring(core FROM 73 FOR 16));
 row.binding_generation:=public.payload_profile_election_number(substring(core FROM 89 FOR 8));
 row.vault_generation:=public.payload_profile_election_number(substring(core FROM 97 FOR 8));
 row.manifest_version:=public.payload_profile_election_number(substring(core FROM 105 FOR 8));
 row.selection_epoch:=public.payload_profile_election_number(substring(core FROM 113 FOR 8));
 row.election_commitment:=substring(core FROM 121 FOR 32);
 row.election_bundle_sha256:=substring(core FROM 153 FOR 32);
 row.selected_reader_key_id:=substring(core FROM 185 FOR 32);
 row.device_signing_key_id:=substring(core FROM 217 FOR 32);
 row.owner_approval_key_id:=substring(core FROM 249 FOR 32);
 row.root_fingerprint:=substring(core FROM 281 FOR 32);
 row.manifest_digest:=substring(core FROM 313 FOR 32);
 row.device_session_digest:=substring(core FROM 345 FOR 32);
 row.owner_session_digest:=substring(core FROM 377 FOR 32);
 row.configured_origin_digest:=substring(core FROM 409 FOR 32);
 row.nonce:=substring(core FROM 441 FOR 32);
 row.issued_ms:=public.payload_profile_election_number(substring(core FROM 473 FOR 8));
 row.expires_ms:=public.payload_profile_election_number(substring(core FROM 481 FOR 8));
 row.core:=core; row.initiating_user_id:=owner_user; row.initiating_session_id:=owner_session;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF row.account_id<>account OR row.binding_generation<=0 OR row.vault_generation<>1 OR row.selection_epoch<>epoch
  OR row.manifest_version<=0 OR row.issued_ms<=0 OR row.issued_ms>now_ms OR row.expires_ms<=now_ms
  OR row.expires_ms-row.issued_ms NOT BETWEEN 1 AND 300000 OR row.nonce=decode(repeat('00',32),'hex')
  OR row.configured_origin_digest=decode(repeat('00',32),'hex')
  OR row.owner_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner-session/v1',uuid_send(account)||uuid_send(owner_user)||uuid_send(owner_session))) THEN
  RAISE EXCEPTION 'physical selection core scope differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO election FROM public.payload_profile_elections e WHERE e.account_id=account AND e.new_binding_id=row.binding_id;
 IF NOT FOUND OR(election.device_id,election.line_id,election.new_binding_generation,election.selection_epoch,election.vault_generation,election.election_commitment,election.election_bundle_sha256,election.selected_reader_key_id,election.root_fingerprint,election.accepted_manifest_version,election.accepted_manifest_digest)
  IS DISTINCT FROM(row.device_id,row.line_id,row.binding_generation,row.selection_epoch,row.vault_generation,row.election_commitment,row.election_bundle_sha256,row.selected_reader_key_id,row.root_fingerprint,row.manifest_version,row.manifest_digest) THEN
  RAISE EXCEPTION 'actual accepted physical selection differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO reservation FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=election.challenge_id;
 IF NOT FOUND OR reservation.closed_unaccepted_ms IS NOT NULL OR reservation.new_binding_id<>row.binding_id
  OR authority.revoked_at IS NOT NULL OR authority.root_pin<>reservation.root_pin OR authority.root_fingerprint<>row.root_fingerprint
  OR authority.generation<>1 OR authority.anchor_digest<>decode(repeat('00',32),'hex')
  OR authority.version<>row.manifest_version OR authority.semantic_digest IS DISTINCT FROM row.manifest_digest
  OR authority.manifest IS DISTINCT FROM reservation.accepted_signed_manifest OR authority.accepted_at_ms<>election.accepted_at_ms
  OR authority.last_verified_ms<election.accepted_at_ms OR authority.last_verified_ms>now_ms OR row.issued_ms<election.accepted_at_ms
  OR sha256(authority.manifest)<>election.accepted_signed_manifest_sha256
  OR sha256(substring(authority.manifest FROM 1 FOR octet_length(authority.manifest)-64))<>row.manifest_digest
  OR public.payload_profile_election_number(substring(authority.manifest FROM 48 FOR 8))<=now_ms THEN
  RAISE EXCEPTION 'current same-root03 physical selection differs' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_election_reader(authority.manifest,3::smallint,row.selected_reader_key_id,row.device_id,row.line_id,now_ms);
 row.root_pin:=authority.root_pin; row.signed_manifest:=authority.manifest; row.signed_manifest_sha256:=sha256(authority.manifest);
 row.manifest_accepted_ms:=authority.accepted_at_ms; row.election_challenge_id:=election.challenge_id; row.original_binding_id:=election.old_binding_id;
 SELECT * INTO original FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=election.old_binding_id;
 IF NOT FOUND OR(original.line_id,original.device_id,original.generation) IS DISTINCT FROM(election.line_id,election.device_id,election.old_binding_generation)
  OR get_byte(original.device_statement,138)>=128 THEN
  RAISE EXCEPTION 'original signed subscription unavailable' USING ERRCODE='23514'; END IF;
 row.original_subscription_id:=('x'||encode(substring(original.device_statement FROM 139 FOR 4),'hex'))::bit(32)::integer;
 row.activation_challenge_id:=original.challenge_id; row.registration_id:=original.registration_id;
 row.device_point:=original.device_point; row.owner_point:=original.owner_point;
 IF row.original_subscription_id<0 OR row.device_signing_key_id<>sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original.device_point)
  OR row.owner_approval_key_id<>sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original.owner_point) THEN
  RAISE EXCEPTION 'original registered physical selection signing keys differ' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.phone_lines l JOIN public.device_line_bindings b ON(b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation)
  WHERE l.account_id=account AND l.id=row.line_id AND l.state='active' AND l.current_binding_generation=row.binding_generation
   AND b.device_id=row.device_id AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest=election.owner_approval_digest
   AND b.device_confirmation_digest=election.device_confirmation_digest FOR SHARE OF l,b NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'current physical selection binding unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_activation_v2_pending p JOIN public.sealed_line_key_receipts r ON(r.account_id,r.registration_id)=(p.account_id,p.registration_id)
  WHERE p.account_id=account AND p.challenge_id=original.challenge_id AND p.registration_id=original.registration_id
   AND p.protocol_version=2 AND p.purpose='sealed' AND p.installed_at IS NOT NULL AND p.nonce IS NULL AND p.retired_at IS NULL
   AND r.activated_ms IS NOT NULL AND r.retired_ms IS NULL AND r.approval_point=original.owner_point
   AND r.approval_fingerprint=sha256(original.owner_point) AND r.paired_fingerprint=sha256(original.device_point)
  FOR SHARE OF p,r NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original installed physical history unavailable' USING ERRCODE='23514'; END IF;
 SELECT s.* INTO device_session FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.sites t ON t.site_id=s.site_id
  JOIN public.deployment_authority a ON a.singleton
  WHERE s.account_id=account AND s.device_id=row.device_id AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.signing_key_sec1=original.device_point AND k.fingerprint=sha256(original.device_point)
   AND s.line_activation_version=2 AND s.lease_until>clock_timestamp() AND a.epoch=s.deployment_epoch AND t.enabled AND NOT t.draining
  FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND OR octet_length(device_session.site_id) NOT BETWEEN 1 AND 256 OR octet_length(device_session.instance_id) NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION 'current device physical session unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_owner_approval_keys k WHERE k.account_id=account AND k.signing_key_sec1=original.owner_point AND k.fingerprint=sha256(original.owner_point)
  AND k.revoked_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'original SEALED physical approval key unavailable' USING ERRCODE='23514'; END IF;
 row.proof_site_id:=device_session.site_id; row.proof_instance_id:=device_session.instance_id;
 row.proof_connection_epoch:=device_session.connection_epoch; row.proof_deployment_epoch:=device_session.deployment_epoch;
 session_bytes:=uuid_send(account)||uuid_send(row.device_id)||int4send(octet_length(row.proof_site_id))||convert_to(row.proof_site_id,'UTF8')
  ||int4send(octet_length(row.proof_instance_id))||convert_to(row.proof_instance_id,'UTF8')||int8send(row.proof_connection_epoch)
  ||int8send(row.proof_deployment_epoch)||int2send(2::smallint)||row.device_signing_key_id;
 IF row.device_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device-session/v1',session_bytes)) THEN
  RAISE EXCEPTION 'current physical device-session identity differs' USING ERRCODE='23514'; END IF;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_owner(account uuid,owner_user uuid,owner_session uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE expiry bigint;
BEGIN
 SELECT least(floor(extract(epoch FROM s.expires_at)*1000)::bigint,
    floor(extract(epoch FROM coalesce(s.last_used_at,s.created_at))*1000)::bigint+259200000) INTO expiry
  FROM public.sessions s JOIN public.memberships m ON(m.account_id,m.user_id)=(s.account_id,s.user_id)
  JOIN public.users u ON u.id=m.user_id JOIN public.owner_mfa f ON(f.account_id,f.user_id)=(m.account_id,m.user_id)
  WHERE s.account_id=account AND s.id=owner_session AND s.user_id=owner_user AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
   AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND f.enabled_at IS NOT NULL
   AND coalesce(s.last_used_at,s.created_at)<=clock_timestamp() AND coalesce(s.last_used_at,s.created_at)>clock_timestamp()-interval '72 hours'
  FOR SHARE OF s,m,u,f NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'current physical approval owner unavailable' USING ERRCODE='23514'; END IF;
 RETURN expiry;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_observation(observation bytea,selected_subscription integer) RETURNS void
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE api integer; active integer;
BEGIN
 IF octet_length(observation)<>121 OR selected_subscription<0 THEN RAISE EXCEPTION 'physical observation shape' USING ERRCODE='23514'; END IF;
 api:=get_byte(observation,0)*256+get_byte(observation,1); active:=get_byte(observation,2)*256+get_byte(observation,3);
 IF api<33 OR active<1 OR active>256 OR get_byte(observation,4)>=128
  OR substring(observation FROM 5 FOR 4)<>int4send(selected_subscription) OR get_byte(observation,8) NOT IN(1,2)
  OR get_byte(observation,41)>=128 OR get_byte(observation,45)>=128
  OR public.payload_profile_election_number(substring(observation FROM 66 FOR 8))<=0 THEN
  RAISE EXCEPTION 'physical observation range differs' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_election_uuid(substring(observation FROM 10 FOR 16));
 PERFORM public.payload_profile_election_uuid(substring(observation FROM 26 FOR 16));
 PERFORM public.payload_profile_election_uuid(substring(observation FROM 50 FOR 16));
 PERFORM public.payload_profile_election_uuid(substring(observation FROM 74 FOR 16));
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_reserve(account uuid,opening uuid,user_id uuid,owner_session uuid,core bytea,factor_deadline_ms bigint)
RETURNS SETOF public.payload_profile_selection_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_selection_challenges%ROWTYPE; previous public.payload_profile_selection_challenges%ROWTYPE; now_ms bigint; owner_until bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR core IS NULL OR octet_length(core)<>496 OR factor_deadline_ms IS NULL
  OR opening='00000000-0000-0000-0000-000000000000'::uuid THEN RAISE EXCEPTION 'physical opening shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.opening_id=opening;
 IF FOUND THEN
  IF previous.initiating_user_id IS DISTINCT FROM user_id OR previous.initiating_session_id IS DISTINCT FROM owner_session
   OR substring(core FROM 41 FOR 16)<>uuid_send(previous.line_id) THEN RAISE EXCEPTION 'physical opening retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT previous; RETURN;
 END IF;
 row:=public.payload_profile_selection_scope(account,user_id,owner_session,core);
 owner_until:=public.payload_profile_selection_owner(account,user_id,owner_session);
 row.opening_id:=opening; row.reserve_deadline_ms:=least(row.expires_ms,factor_deadline_ms,owner_until);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms>=row.reserve_deadline_ms OR opening IN(row.refresh_id,row.binding_id)
  OR(SELECT count(*) FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.binding_id=row.binding_id AND c.device_session_digest=row.device_session_digest)>=16
  OR EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=account AND r.binding_id=row.binding_id AND r.device_session_digest=row.device_session_digest)
  OR EXISTS(SELECT FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.binding_id=row.binding_id
    AND c.device_session_digest=row.device_session_digest AND c.closed_unaccepted_ms IS NULL AND c.expires_ms>row.issued_ms) THEN
  RAISE EXCEPTION 'physical reservation unavailable' USING ERRCODE='23514'; END IF;
 INSERT INTO public.payload_profile_selection_challenges SELECT(row).*;
 UPDATE public.payload_profile_selection_challenges c SET closed_unaccepted_ms=row.issued_ms,superseded_by_refresh_id=row.refresh_id
  WHERE c.account_id=account AND c.refresh_id<>row.refresh_id AND c.binding_id=row.binding_id AND c.device_session_digest=row.device_session_digest
   AND c.closed_unaccepted_ms IS NULL AND c.expires_ms<=row.issued_ms
   AND NOT EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=account AND r.refresh_id=c.refresh_id);
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_device_proof(account uuid,refresh uuid,observation bytea,signature bytea)
RETURNS SETOF public.payload_profile_selection_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_selection_challenges%ROWTYPE; checked public.payload_profile_selection_challenges%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR refresh IS NULL OR observation IS NULL OR signature IS NULL OR octet_length(observation)<>121 OR octet_length(signature)<>64 THEN
  RAISE EXCEPTION 'physical device proof shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.refresh_id=refresh;
 IF NOT FOUND THEN RAISE EXCEPTION 'physical challenge unavailable' USING ERRCODE='23514'; END IF;
 IF row.device_signature IS NOT NULL THEN
  IF row.device_observation<>observation OR row.device_signature<>signature THEN RAISE EXCEPTION 'physical proof conflict' USING ERRCODE='23514'; END IF;
  RETURN NEXT row; RETURN;
 END IF;
 IF row.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'physical challenge closed' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_selection_scope(account,row.initiating_user_id,row.initiating_session_id,row.core);
 PERFORM public.payload_profile_selection_observation(observation,row.original_subscription_id);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 UPDATE public.payload_profile_selection_challenges c SET device_observation=observation,device_signature=signature,device_proof_ms=now_ms
  WHERE c.account_id=account AND c.refresh_id=refresh AND c.device_signature IS NULL AND c.closed_unaccepted_ms IS NULL RETURNING c.* INTO row;
 IF NOT FOUND THEN RAISE EXCEPTION 'physical proof changed' USING ERRCODE='23514'; END IF;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_approve(account uuid,opening uuid,refresh uuid,bundle bytea,factor_deadline_ms bigint)
RETURNS SETOF public.payload_profile_selection_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_selection_challenges%ROWTYPE; checked public.payload_profile_selection_challenges%ROWTYPE;
 receipt public.payload_profile_selection_receipts%ROWTYPE; now_ms bigint; owner_until bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR refresh IS NULL OR bundle IS NULL OR octet_length(bundle)<>745 OR factor_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'physical approval shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO receipt FROM public.payload_profile_selection_receipts r WHERE r.account_id=account AND r.opening_id=opening;
 IF FOUND THEN
  IF receipt.refresh_id<>refresh OR receipt.bundle<>bundle THEN RAISE EXCEPTION 'physical approval retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT receipt; RETURN;
 END IF;
 SELECT * INTO row FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.opening_id=opening AND c.refresh_id=refresh;
 IF NOT FOUND OR row.closed_unaccepted_ms IS NOT NULL OR row.device_signature IS NULL
  OR substring(bundle FROM 1 FOR 496)<>row.core OR substring(bundle FROM 497 FOR 121)<>row.device_observation
  OR substring(bundle FROM 618 FOR 64)<>row.device_signature THEN RAISE EXCEPTION 'original physical device proof unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_selection_scope(account,row.initiating_user_id,row.initiating_session_id,row.core);
 owner_until:=public.payload_profile_selection_owner(account,row.initiating_user_id,row.initiating_session_id);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<row.issued_ms OR now_ms>=least(row.expires_ms,factor_deadline_ms,owner_until) OR row.device_proof_ms>now_ms THEN
  RAISE EXCEPTION 'physical approval expired or clock regressed' USING ERRCODE='23514'; END IF;
 receipt.account_id:=account; receipt.opening_id:=opening; receipt.refresh_id:=refresh;
 receipt.device_id:=row.device_id; receipt.line_id:=row.line_id; receipt.binding_id:=row.binding_id; receipt.election_challenge_id:=row.election_challenge_id;
 receipt.binding_generation:=row.binding_generation; receipt.selection_epoch:=row.selection_epoch; receipt.accepted_ms:=now_ms;
 receipt.approval_deadline_ms:=least(row.expires_ms,factor_deadline_ms,owner_until);
 receipt.proof_connection_epoch:=row.proof_connection_epoch; receipt.proof_deployment_epoch:=row.proof_deployment_epoch;
 receipt.proof_site_id:=row.proof_site_id; receipt.proof_instance_id:=row.proof_instance_id; receipt.device_session_digest:=row.device_session_digest;
 receipt.device_observation:=row.device_observation; receipt.device_signature:=row.device_signature; receipt.owner_signature:=substring(bundle FROM 682 FOR 64);
 receipt.bundle:=bundle; receipt.bundle_sha256:=sha256(bundle);
 INSERT INTO public.payload_profile_selection_receipts SELECT(receipt).*;
 RETURN NEXT receipt;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_install(account uuid,refresh uuid,bundle_sha256 bytea,signature bytea)
RETURNS SETOF public.payload_profile_selection_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE receipt public.payload_profile_selection_receipts%ROWTYPE; row public.payload_profile_selection_challenges%ROWTYPE;
 checked public.payload_profile_selection_challenges%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR refresh IS NULL OR bundle_sha256 IS NULL OR octet_length(bundle_sha256)<>32 OR signature IS NULL OR octet_length(signature)<>64 THEN
  RAISE EXCEPTION 'physical installation shape' USING ERRCODE='23514'; END IF;
 SELECT * INTO receipt FROM public.payload_profile_selection_receipts r WHERE r.account_id=account AND r.refresh_id=refresh;
 IF NOT FOUND OR receipt.bundle_sha256<>bundle_sha256 THEN RAISE EXCEPTION 'physical approval unavailable' USING ERRCODE='23514'; END IF;
 IF receipt.installed_signature IS NOT NULL THEN
  IF receipt.installed_signature<>signature THEN RAISE EXCEPTION 'physical installation retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT receipt; RETURN;
 END IF;
 SELECT * INTO row FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.refresh_id=refresh;
 IF NOT FOUND OR row.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'physical challenge unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_selection_scope(account,row.initiating_user_id,row.initiating_session_id,row.core);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<receipt.accepted_ms OR now_ms>=row.expires_ms THEN RAISE EXCEPTION 'physical installation expired or clock regressed' USING ERRCODE='23514'; END IF;
 UPDATE public.payload_profile_selection_receipts r SET installed_signature=signature,installed_ms=now_ms
  WHERE r.account_id=account AND r.refresh_id=refresh AND r.installed_signature IS NULL RETURNING r.* INTO receipt;
 IF NOT FOUND THEN RAISE EXCEPTION 'physical installation changed' USING ERRCODE='23514'; END IF;
 RETURN NEXT receipt;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_same_scope(older jsonb,newer jsonb)
RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
 SELECT(older-ARRAY['opening_id','refresh_id','initiating_user_id','initiating_session_id','owner_session_digest','nonce','core','issued_ms','expires_ms','reserve_deadline_ms','device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id'])
  =(newer-ARRAY['opening_id','refresh_id','initiating_user_id','initiating_session_id','owner_session_digest','nonce','core','issued_ms','expires_ms','reserve_deadline_ms','device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id'])
$function$;

CREATE FUNCTION public.payload_profile_selection_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.payload_profile_selection_challenges%ROWTYPE; original public.payload_profile_selection_challenges%ROWTYPE;
 target public.payload_profile_selection_challenges%ROWTYPE; wanted uuid; state text; epoch bigint; now_ms bigint; owner_until bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN('public.payload_profile_selection_challenges'::regclass,'public.payload_profile_selection_receipts'::regclass)
  OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN RAISE EXCEPTION 'unexpected physical writer context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN wanted:=OLD.account_id; ELSE wanted:=NEW.account_id; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN RAISE EXCEPTION 'physical writer fence busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted FOR SHARE NOWAIT;
 IF NOT FOUND OR state NOT IN('live','deleted') OR epoch<0 THEN RAISE EXCEPTION 'physical anchor unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=wanted) THEN RAISE EXCEPTION 'physical history cannot be deleted' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(wanted,epoch) THEN RAISE EXCEPTION 'physical mutation requires actual accepted03' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_RELID='public.payload_profile_selection_challenges'::regclass THEN
  IF TG_OP='INSERT' THEN
   checked:=public.payload_profile_selection_scope(NEW.account_id,NEW.initiating_user_id,NEW.initiating_session_id,NEW.core);
   owner_until:=public.payload_profile_selection_owner(NEW.account_id,NEW.initiating_user_id,NEW.initiating_session_id);
   IF(to_jsonb(NEW)-ARRAY['opening_id','reserve_deadline_ms']) IS DISTINCT FROM(to_jsonb(checked)-ARRAY['opening_id','reserve_deadline_ms'])
    OR NEW.device_signature IS NOT NULL OR NEW.closed_unaccepted_ms IS NOT NULL
    OR NEW.reserve_deadline_ms<=now_ms OR NEW.reserve_deadline_ms>least(NEW.expires_ms,owner_until)
    OR(SELECT count(*) FROM public.payload_profile_selection_challenges c WHERE c.account_id=NEW.account_id AND c.binding_id=NEW.binding_id AND c.device_session_digest=NEW.device_session_digest)>=16
    OR EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=NEW.account_id AND r.binding_id=NEW.binding_id AND r.device_session_digest=NEW.device_session_digest)
    OR EXISTS(SELECT FROM public.payload_profile_selection_challenges c WHERE c.account_id=NEW.account_id AND c.binding_id=NEW.binding_id AND c.device_session_digest=NEW.device_session_digest AND c.closed_unaccepted_ms IS NULL AND c.expires_ms>NEW.issued_ms) THEN
    RAISE EXCEPTION 'physical reservation row differs' USING ERRCODE='23514'; END IF;
  ELSE
   IF TG_OP<>'UPDATE' OR(to_jsonb(NEW)-ARRAY['device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id']) THEN
    RAISE EXCEPTION 'physical reservation identity immutable' USING ERRCODE='23514'; END IF;
   IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
   IF OLD.closed_unaccepted_ms IS NOT NULL OR EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=OLD.account_id AND r.refresh_id=OLD.refresh_id) THEN
    RAISE EXCEPTION 'closed or approved physical challenge immutable' USING ERRCODE='23514'; END IF;
   IF NEW.closed_unaccepted_ms IS NOT NULL THEN
    IF NEW.device_observation IS DISTINCT FROM OLD.device_observation OR NEW.device_signature IS DISTINCT FROM OLD.device_signature OR NEW.device_proof_ms IS DISTINCT FROM OLD.device_proof_ms
     OR NEW.closed_unaccepted_ms<OLD.expires_ms OR NEW.closed_unaccepted_ms>now_ms THEN RAISE EXCEPTION 'physical closure differs' USING ERRCODE='23514'; END IF;
    SELECT * INTO target FROM public.payload_profile_selection_challenges c WHERE c.account_id=NEW.account_id AND c.refresh_id=NEW.superseded_by_refresh_id;
    IF NOT FOUND OR target.issued_ms<=OLD.issued_ms OR target.closed_unaccepted_ms IS NOT NULL OR target.expires_ms<=now_ms
     OR target.reserve_deadline_ms<=now_ms OR NEW.closed_unaccepted_ms<>target.issued_ms
     OR NOT public.payload_profile_selection_same_scope(to_jsonb(OLD),to_jsonb(target))
     OR EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=target.account_id AND r.refresh_id=target.refresh_id) THEN
     RAISE EXCEPTION 'physical closure requires fresh later same-scope reservation' USING ERRCODE='23514'; END IF;
    checked:=public.payload_profile_selection_scope(target.account_id,target.initiating_user_id,target.initiating_session_id,target.core);
    PERFORM public.payload_profile_selection_owner(target.account_id,target.initiating_user_id,target.initiating_session_id);
   ELSE
    IF OLD.device_signature IS NOT NULL OR NEW.device_signature IS NULL OR NEW.device_observation IS NULL OR NEW.device_proof_ms IS NULL
     OR NEW.device_proof_ms<OLD.issued_ms OR NEW.device_proof_ms>now_ms OR now_ms>=OLD.expires_ms THEN RAISE EXCEPTION 'physical proof is one-time' USING ERRCODE='23514'; END IF;
    checked:=public.payload_profile_selection_scope(OLD.account_id,OLD.initiating_user_id,OLD.initiating_session_id,OLD.core);
    PERFORM public.payload_profile_selection_observation(NEW.device_observation,OLD.original_subscription_id);
   END IF;
  END IF;
 ELSE
  SELECT * INTO original FROM public.payload_profile_selection_challenges c WHERE c.account_id=NEW.account_id AND c.opening_id=NEW.opening_id AND c.refresh_id=NEW.refresh_id FOR UPDATE NOWAIT;
  IF NOT FOUND OR original.closed_unaccepted_ms IS NOT NULL OR original.device_signature IS NULL THEN RAISE EXCEPTION 'physical proof unavailable' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
   owner_until:=public.payload_profile_selection_owner(NEW.account_id,original.initiating_user_id,original.initiating_session_id);
   IF NEW.installed_signature IS NOT NULL OR NEW.accepted_ms<original.issued_ms OR NEW.accepted_ms>now_ms OR original.device_proof_ms>NEW.accepted_ms
    OR NEW.approval_deadline_ms>least(original.expires_ms,owner_until) OR now_ms>=NEW.approval_deadline_ms
    OR(NEW.device_id,NEW.line_id,NEW.binding_id,NEW.election_challenge_id,NEW.binding_generation,NEW.selection_epoch,NEW.proof_site_id,NEW.proof_instance_id,NEW.proof_connection_epoch,NEW.proof_deployment_epoch,NEW.device_session_digest,NEW.device_observation,NEW.device_signature)
      IS DISTINCT FROM(original.device_id,original.line_id,original.binding_id,original.election_challenge_id,original.binding_generation,original.selection_epoch,original.proof_site_id,original.proof_instance_id,original.proof_connection_epoch,original.proof_deployment_epoch,original.device_session_digest,original.device_observation,original.device_signature)
    OR NEW.bundle<>original.core||original.device_observation||original.device_signature||NEW.owner_signature OR NEW.bundle_sha256<>sha256(NEW.bundle) THEN
    RAISE EXCEPTION 'physical approval differs from retained original proof' USING ERRCODE='23514'; END IF;
  ELSE
   IF TG_OP<>'UPDATE' OR(to_jsonb(NEW)-ARRAY['installed_signature','installed_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['installed_signature','installed_ms']) THEN
    RAISE EXCEPTION 'physical receipt identity immutable' USING ERRCODE='23514'; END IF;
   IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
   IF OLD.installed_signature IS NOT NULL OR NEW.installed_signature IS NULL OR NEW.installed_ms IS NULL
    OR NEW.installed_ms<OLD.accepted_ms OR NEW.installed_ms>now_ms OR now_ms>=original.expires_ms THEN
    RAISE EXCEPTION 'physical installation is one-time before original expiry' USING ERRCODE='23514'; END IF;
  END IF;
  checked:=public.payload_profile_selection_scope(original.account_id,original.initiating_user_id,original.initiating_session_id,original.core);
 END IF;
 -- Actual unchanged-epoch stable-row version: locking alone is insufficient
 -- for writers/readers retaining a snapshot from before proof or installation.
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
 RETURN NEW;
END;
$function$;

CREATE FUNCTION public.payload_profile_selection_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_selection_challenges%ROWTYPE; target public.payload_profile_selection_challenges%ROWTYPE;
 receipt public.payload_profile_selection_receipts%ROWTYPE; checked public.payload_profile_selection_challenges%ROWTYPE; now_ms bigint; owner_until bigint; deadline bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_RELID='public.payload_profile_selection_challenges'::regclass THEN
  SELECT * INTO row FROM public.payload_profile_selection_challenges c WHERE c.account_id=NEW.account_id AND c.refresh_id=NEW.refresh_id;
  IF NOT FOUND THEN
   IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'physical challenge disappeared' USING ERRCODE='23514'; END IF;
   RETURN NULL;
  END IF;
  IF row.closed_unaccepted_ms IS NOT NULL THEN
   SELECT * INTO target FROM public.payload_profile_selection_challenges c WHERE c.account_id=row.account_id AND c.refresh_id=row.superseded_by_refresh_id;
   IF NOT FOUND OR row.closed_unaccepted_ms<>target.issued_ms OR target.issued_ms<=row.issued_ms OR NOT public.payload_profile_selection_same_scope(to_jsonb(row),to_jsonb(target))
    OR EXISTS(SELECT FROM public.payload_profile_selection_receipts r WHERE r.account_id=row.account_id AND r.refresh_id=row.refresh_id) THEN
    RAISE EXCEPTION 'physical closure target did not commit' USING ERRCODE='23514'; END IF;
   checked:=public.payload_profile_selection_scope(target.account_id,target.initiating_user_id,target.initiating_session_id,target.core);
   deadline:=target.reserve_deadline_ms;
   IF now_ms>=target.reserve_deadline_ms THEN RAISE EXCEPTION 'physical closure target expired before commit' USING ERRCODE='23514'; END IF;
  ELSE
   checked:=public.payload_profile_selection_scope(row.account_id,row.initiating_user_id,row.initiating_session_id,row.core);
   IF TG_OP='INSERT' THEN
    owner_until:=public.payload_profile_selection_owner(row.account_id,row.initiating_user_id,row.initiating_session_id);
    deadline:=least(row.reserve_deadline_ms,owner_until);
    IF now_ms>=deadline THEN RAISE EXCEPTION 'physical reservation deadline passed before commit' USING ERRCODE='23514'; END IF;
   ELSE
    deadline:=row.expires_ms;
    IF now_ms>=deadline THEN RAISE EXCEPTION 'physical proof expired before commit' USING ERRCODE='23514'; END IF;
   END IF;
  END IF;
  IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=deadline THEN RAISE EXCEPTION 'physical deadline passed after waits' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO receipt FROM public.payload_profile_selection_receipts r WHERE r.account_id=NEW.account_id AND r.refresh_id=NEW.refresh_id;
 IF NOT FOUND THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'physical receipt disappeared' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO row FROM public.payload_profile_selection_challenges c WHERE c.account_id=receipt.account_id AND c.refresh_id=receipt.refresh_id;
 IF NOT FOUND OR row.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'original physical challenge unavailable at commit' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_selection_scope(row.account_id,row.initiating_user_id,row.initiating_session_id,row.core);
 IF TG_OP='INSERT' THEN
  owner_until:=public.payload_profile_selection_owner(row.account_id,row.initiating_user_id,row.initiating_session_id);
  deadline:=least(receipt.approval_deadline_ms,owner_until);
  IF now_ms<receipt.accepted_ms OR now_ms>=deadline THEN RAISE EXCEPTION 'physical approval deadline passed before commit' USING ERRCODE='23514'; END IF;
 ELSE
  deadline:=row.expires_ms;
  IF receipt.installed_ms IS NULL OR now_ms<receipt.installed_ms OR now_ms>=row.expires_ms THEN RAISE EXCEPTION 'physical installation expired before commit' USING ERRCODE='23514'; END IF;
 END IF;
 IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=least(row.expires_ms,deadline) THEN RAISE EXCEPTION 'physical deadline passed after waits' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;

CREATE TRIGGER payload_profile_selection_challenge_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_selection_challenges
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_selection_rows_guard();
CREATE TRIGGER payload_profile_selection_receipt_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_selection_receipts
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_selection_rows_guard();
CREATE CONSTRAINT TRIGGER payload_profile_selection_challenge_after_change AFTER INSERT OR UPDATE ON public.payload_profile_selection_challenges
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.payload_profile_selection_complete();
CREATE CONSTRAINT TRIGGER payload_profile_selection_receipt_after_change AFTER INSERT OR UPDATE ON public.payload_profile_selection_receipts
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.payload_profile_selection_complete();


CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=111 AND min(version)=1 AND max(version)=111 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=111 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE FUNCTION public.payload_profile_selection_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_election_ready()
  AND has_table_privilege(current_user,'public.payload_profile_selection_challenges','SELECT')
  AND has_table_privilege(current_user,'public.payload_profile_selection_receipts','SELECT')
  AND NOT has_table_privilege(current_user,'public.payload_profile_selection_challenges','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_table_privilege(current_user,'public.payload_profile_selection_receipts','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_selection_challenges','INSERT,UPDATE,REFERENCES')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_selection_receipts','INSERT,UPDATE,REFERENCES')
  AND has_function_privilege(current_user,'public.payload_profile_selection_reserve(uuid,uuid,uuid,uuid,bytea,bigint)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_selection_device_proof(uuid,uuid,bytea,bytea)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_selection_approve(uuid,uuid,uuid,bytea,bigint)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_selection_install(uuid,uuid,bytea,bytea)','EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_selection_%'
   AND p.proname NOT IN('payload_profile_selection_reserve','payload_profile_selection_device_proof','payload_profile_selection_approve','payload_profile_selection_install','payload_profile_selection_ready')
   AND has_function_privilege(current_user,p.oid,'EXECUTE'))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_selection_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; relation_name text; columns_sql text;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['payload_profile_selection_challenges','payload_profile_selection_receipts'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC,zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_selection_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_selection_reserve','payload_profile_selection_device_proof','payload_profile_selection_approve','payload_profile_selection_install','payload_profile_selection_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=111);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,111,public.payload_profile_writer_graph());
