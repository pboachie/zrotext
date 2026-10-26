-- SPDX-License-Identifier: AGPL-3.0-only
-- Root-signed same-root03 successors, never content or physical permission.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=111; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN RAISE EXCEPTION 'manifest successor requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(110,111) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
FOR writer_expected IN SELECT * FROM(VALUES
            ('payload_profile_selection_scope(uuid, uuid, uuid, bytea)','1f983313ec867a5c6763e9b1bc3fb44e8f3ac86b20e38af31af5586dbdbbc988','public.payload_profile_selection_challenges','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','owner_user','owner_session','core']::text[]),
            ('payload_profile_selection_owner(uuid, uuid, uuid)','078248633116e4ceddeb07772c2810ed7d1742df073acb292eb5665b95123587','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','owner_user','owner_session']::text[]),
            ('payload_profile_selection_observation(bytea, integer)','797f068dd42c9479f779bc3606601001bad9b083ef07ea0a643e4e857ff1ef51','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['observation','selected_subscription']::text[]),
            ('payload_profile_selection_reserve(uuid, uuid, uuid, uuid, bytea, bigint)','4dbc40c492e86e679b43c7b1c41f204e1cfed0c14af984163852d236dd3f60ef','public.payload_profile_selection_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','user_id','owner_session','core','factor_deadline_ms']::text[]),
            ('payload_profile_selection_device_proof(uuid, uuid, bytea, bytea)','bc3b26afb36acc2f12b9318a0aa990c116d7ebc2208157881d31a666981070d7','public.payload_profile_selection_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','refresh','observation','signature']::text[]),
            ('payload_profile_selection_approve(uuid, uuid, uuid, bytea, bigint)','abae401f3ff6bfd4fd6b656eceaeb22c1a5052aa7b12c50bc83741a95f1b9b7d','public.payload_profile_selection_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','refresh','bundle','factor_deadline_ms']::text[]),
            ('payload_profile_selection_install(uuid, uuid, bytea, bytea)','ac80e05d31d46a1ac95472947bb79888394a72b42da7a4f8e7de547d82aa14f9','public.payload_profile_selection_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','refresh','bundle_sha256','signature']::text[]),
            ('payload_profile_selection_same_scope(jsonb, jsonb)','aa793e7dcbb91607b1a2b6517eec57e9412f358d5c9a1c1f997914134be950a4','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['older','newer']::text[]),
            ('payload_profile_selection_rows_guard()','21934dcb2319933a1ea85825781600bb8a526b59d042b3da60bd90f1dda83e59','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_selection_complete()','39c37a2db742cdf5317e9958d95aa5873f6917f47246885b02fed8c51f0cb1d7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_version()','6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_selection_ready()','9d147bd44e88dfaec22746f2c12ff45c0eb41814a0672a61680144e1ebb02757','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'physical helper declaration or body inconsistent'; END IF;
          END LOOP;
 IF NOT(SELECT count(*)=111 AND min(version)=1 AND max(version)=111 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=111 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'manifest predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

CREATE TABLE public.payload_profile_manifest_successors (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL CHECK(opening_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 initiating_user_id uuid NOT NULL, initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL, line_id uuid NOT NULL, binding_id uuid NOT NULL, election_challenge_id uuid NOT NULL,
 predecessor_opening_id uuid,
 binding_generation bigint NOT NULL CHECK(binding_generation>0), vault_generation bigint NOT NULL CHECK(vault_generation=1),
 selection_epoch bigint NOT NULL CHECK(selection_epoch=1), predecessor_version bigint NOT NULL CHECK(predecessor_version>0),
 successor_version bigint NOT NULL CHECK(successor_version::numeric=predecessor_version::numeric+1),
 predecessor_accepted_ms bigint NOT NULL CHECK(predecessor_accepted_ms>0), issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
 accepted_ms bigint NOT NULL CHECK(accepted_ms>=issued_ms), acceptance_deadline_ms bigint NOT NULL CHECK(acceptance_deadline_ms>accepted_ms AND acceptance_deadline_ms<=expires_ms),
 operation text NOT NULL CHECK(operation IN('enroll','renew','replace')),
 statement bytea NOT NULL CHECK(octet_length(statement)=513), signature bytea NOT NULL CHECK(octet_length(signature)=64),
 statement_sha256 bytea NOT NULL CHECK(octet_length(statement_sha256)=32 AND statement_sha256=sha256(statement)),
 root_pin bytea NOT NULL CHECK(octet_length(root_pin)=94), root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
 election_commitment bytea NOT NULL CHECK(octet_length(election_commitment)=32), election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32),
 configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32), owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32),
 predecessor_digest bytea NOT NULL CHECK(octet_length(predecessor_digest)=32), successor_digest bytea NOT NULL CHECK(octet_length(successor_digest)=32),
 predecessor_signed_manifest bytea NOT NULL CHECK(octet_length(predecessor_signed_manifest) BETWEEN 366 AND 9753),
 predecessor_signed_manifest_sha256 bytea NOT NULL CHECK(predecessor_signed_manifest_sha256=sha256(predecessor_signed_manifest)),
 successor_signed_manifest bytea NOT NULL CHECK(octet_length(successor_signed_manifest) BETWEEN 366 AND 9753),
 successor_signed_manifest_sha256 bytea NOT NULL CHECK(successor_signed_manifest_sha256=sha256(successor_signed_manifest)),
 browser_signer_key_id bytea NOT NULL CHECK(octet_length(browser_signer_key_id)=32), browser_signer_point bytea NOT NULL CHECK(octet_length(browser_signer_point)=65),
 predecessor_ancestry_sha256 bytea NOT NULL CHECK(octet_length(predecessor_ancestry_sha256)=32), ancestry_sha256 bytea NOT NULL CHECK(octet_length(ancestry_sha256)=32),
 PRIMARY KEY(account_id,opening_id), UNIQUE(account_id,successor_version),
 FOREIGN KEY(account_id,election_challenge_id) REFERENCES public.payload_profile_elections(account_id,challenge_id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,predecessor_opening_id) REFERENCES public.payload_profile_manifest_successors(account_id,opening_id) DEFERRABLE INITIALLY DEFERRED
);

-- Cache provenance only. The cold reader still verifies every original root
-- and possession signature; this digest binds that result to exact history.
CREATE FUNCTION public.payload_profile_manifest_base(account uuid,election uuid) RETURNS bytea
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/manifest-ancestry-base03/v1',
  uuid_send(e.account_id)||uuid_send(e.challenge_id)||uuid_send(e.new_binding_id)||sha256(c.accepted_signed_manifest)||int8send(e.accepted_at_ms)||e.election_bundle_sha256))
 FROM public.payload_profile_elections e JOIN public.payload_profile_election_challenges c ON(c.account_id,c.challenge_id)=(e.account_id,e.challenge_id)
 WHERE e.account_id=$1 AND e.challenge_id=$2
$function$;
CREATE FUNCTION public.payload_profile_manifest_step(prior bytea,opening uuid,statement bytea,signature bytea,successor bytea,accepted_ms bigint) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
 SELECT sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/manifest-ancestry-step03/v1',
  $1||uuid_send($2)||sha256($3)||sha256($4)||sha256($5)||int8send($6)))
$function$;

-- Original accepted row ancestry only; root signatures remain an independent
-- application obligation. Expired historical checkpoints are not current permission.
CREATE FUNCTION public.payload_profile_manifest_ancestry(account uuid,election uuid,version bigint,digest bytea,manifest bytea,accepted_ms bigint) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 WITH RECURSIVE chain AS (
  SELECT r.* FROM public.payload_profile_manifest_successors r WHERE r.account_id=$1 AND r.election_challenge_id=$2
   AND r.successor_version=$3 AND r.successor_digest=$4 AND r.successor_signed_manifest=$5 AND r.accepted_ms=$6
   AND r.ancestry_sha256=public.payload_profile_manifest_step(r.predecessor_ancestry_sha256,r.opening_id,r.statement,r.signature,r.successor_signed_manifest,r.accepted_ms)
  UNION ALL
  SELECT p.* FROM public.payload_profile_manifest_successors p JOIN chain c ON(p.account_id,p.opening_id)=(c.account_id,c.predecessor_opening_id)
   WHERE p.election_challenge_id=c.election_challenge_id AND p.successor_version=c.predecessor_version AND p.successor_digest=c.predecessor_digest
    AND p.successor_signed_manifest=c.predecessor_signed_manifest AND p.accepted_ms=c.predecessor_accepted_ms
    AND p.binding_id=c.binding_id AND p.root_pin=c.root_pin AND p.root_fingerprint=c.root_fingerprint AND p.ancestry_sha256=c.predecessor_ancestry_sha256
    AND p.ancestry_sha256=public.payload_profile_manifest_step(p.predecessor_ancestry_sha256,p.opening_id,p.statement,p.signature,p.successor_signed_manifest,p.accepted_ms)
 )
 SELECT EXISTS(SELECT FROM public.payload_profile_elections e JOIN public.payload_profile_election_challenges c ON(c.account_id,c.challenge_id)=(e.account_id,e.challenge_id)
  WHERE e.account_id=$1 AND e.challenge_id=$2 AND(
   (e.accepted_manifest_version=$3 AND e.accepted_manifest_digest=$4 AND c.accepted_signed_manifest=$5 AND e.accepted_at_ms=$6)
   OR EXISTS(SELECT FROM chain r WHERE r.predecessor_opening_id IS NULL AND r.predecessor_version=e.accepted_manifest_version
    AND r.predecessor_digest=e.accepted_manifest_digest AND r.predecessor_signed_manifest=c.accepted_signed_manifest
    AND r.predecessor_accepted_ms=e.accepted_at_ms AND r.binding_id=e.new_binding_id AND r.election_commitment=e.election_commitment
    AND r.election_bundle_sha256=e.election_bundle_sha256 AND r.root_pin=c.root_pin AND r.root_fingerprint=e.root_fingerprint
    AND r.predecessor_ancestry_sha256=public.payload_profile_manifest_base($1,$2))))
$function$;

-- Read-only cache provenance, never current owner/content/physical permission.
-- Every warm reuse still recomputes exact retained linkage and received hashes.
CREATE FUNCTION public.payload_profile_manifest_retention(account uuid,election uuid,version bigint,digest bytea,manifest bytea,accepted_ms bigint,ancestry_sha256 bytea) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT octet_length($7)=32 AND (
  EXISTS(SELECT FROM public.payload_profile_elections e JOIN public.payload_profile_election_challenges c ON(c.account_id,c.challenge_id)=(e.account_id,e.challenge_id)
   WHERE e.account_id=$1 AND e.challenge_id=$2 AND e.accepted_manifest_version=$3 AND e.accepted_manifest_digest=$4
    AND c.accepted_signed_manifest=$5 AND e.accepted_at_ms=$6 AND public.payload_profile_manifest_base($1,$2)=$7)
  OR EXISTS(SELECT FROM public.payload_profile_manifest_successors r WHERE r.account_id=$1 AND r.election_challenge_id=$2
   AND r.successor_version=$3 AND r.successor_digest=$4 AND r.successor_signed_manifest=$5 AND r.accepted_ms=$6 AND r.ancestry_sha256=$7))
  AND public.payload_profile_manifest_ancestry($1,$2,$3,$4,$5,$6)
$function$;

-- One deliberate record-diff policy, not a generic root-signed update escape.
CREATE FUNCTION public.payload_profile_manifest_keys(prior bytea,successor bytea,line uuid,point bytea,key_id bytea,checked_ms bigint) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE old_count integer; new_count integer; i integer; j integer; old_key bytea; new_key bytea; found_key bytea;
 role integer; old_active integer:=0; new_active integer:=0; added integer:=0; revoked integer:=0; roots integer:=0; archives integer:=0;
 last_id bytea; seen_points bytea[]:=ARRAY[]::bytea[]; expires bigint; issued bigint; until_ms bigint; from_ms bigint; operation text;
BEGIN
 IF octet_length(prior) NOT BETWEEN 366 AND 9753 OR substring(prior FROM 1 FOR 6)<>decode('5a544d410303','hex')
  OR octet_length(successor) NOT BETWEEN 366 AND 9753 OR substring(successor FROM 1 FOR 7)<>decode('5a544d41030303','hex')
  OR octet_length(point)<>65 OR get_byte(point,0)<>4 OR octet_length(key_id)<>32
  OR key_id<>sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||point) THEN
  RAISE EXCEPTION 'manifest successor shape or possession key differs' USING ERRCODE='23514'; END IF;
 old_count:=get_byte(prior,152); new_count:=get_byte(successor,152);
 IF old_count NOT BETWEEN 1 AND 64 OR new_count NOT BETWEEN 1 AND 64 OR octet_length(prior)<>217+149*old_count
  OR octet_length(successor)<>217+149*new_count OR new_count NOT IN(old_count,old_count+1)
  OR substring(prior FROM 8 FOR 24)<>substring(successor FROM 8 FOR 24)
  OR substring(prior FROM 88 FOR 65)<>substring(successor FROM 88 FOR 65)
  OR public.payload_profile_election_number(substring(successor FROM 32 FOR 8))::numeric<>public.payload_profile_election_number(substring(prior FROM 32 FOR 8))::numeric+1
  OR substring(successor FROM 56 FOR 32)<>sha256(substring(prior FROM 1 FOR octet_length(prior)-64)) THEN
  RAISE EXCEPTION 'manifest successor predecessor differs' USING ERRCODE='23514'; END IF;
 issued:=public.payload_profile_election_number(substring(successor FROM 40 FOR 8)); expires:=public.payload_profile_election_number(substring(successor FROM 48 FOR 8));
 IF issued<=0 OR issued>checked_ms OR expires<=checked_ms OR expires-issued NOT BETWEEN 1 AND 86400000 THEN
  RAISE EXCEPTION 'manifest successor validity differs' USING ERRCODE='23514'; END IF;
 FOR i IN 0..old_count-1 LOOP
  old_key:=substring(prior FROM 154+149*i FOR 149); found_key:=NULL;
  IF get_byte(old_key,0)=5 AND substring(old_key FROM 115 FOR 16)=uuid_send(line) AND get_byte(old_key,148)=1 THEN old_active:=old_active+1; END IF;
  FOR j IN 0..new_count-1 LOOP
   new_key:=substring(successor FROM 154+149*j FOR 149);
   IF substring(old_key FROM 1 FOR 33)=substring(new_key FROM 1 FOR 33) THEN
    IF found_key IS NOT NULL THEN RAISE EXCEPTION 'duplicate successor identity' USING ERRCODE='23514'; END IF;
    found_key:=new_key;
   END IF;
  END LOOP;
  IF found_key IS NULL THEN RAISE EXCEPTION 'manifest history cannot drop keys' USING ERRCODE='23514'; END IF;
  IF found_key=old_key THEN CONTINUE; END IF;
  IF get_byte(old_key,0)=5 AND substring(old_key FROM 115 FOR 16)=uuid_send(line) AND get_byte(old_key,148)=1
   AND get_byte(found_key,148)=2 AND substring(old_key FROM 1 FOR 148)=substring(found_key FROM 1 FOR 148) THEN
   revoked:=revoked+1; CONTINUE;
  END IF;
  IF get_byte(old_key,148)<>1 OR get_byte(found_key,148)<>1 OR substring(old_key FROM 1 FOR 140)<>substring(found_key FROM 1 FOR 140)
   OR public.payload_profile_election_number(substring(found_key FROM 141 FOR 8))<public.payload_profile_election_number(substring(old_key FROM 141 FOR 8))
   OR public.payload_profile_election_number(substring(found_key FROM 141 FOR 8))>expires THEN
   RAISE EXCEPTION 'manifest successor changed retained identity or state' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR j IN 0..new_count-1 LOOP
  new_key:=substring(successor FROM 154+149*j FOR 149); role:=get_byte(new_key,0);
  IF role NOT BETWEEN 1 AND 6 OR(last_id IS NOT NULL AND substring(new_key FROM 1 FOR 33)<=last_id)
   OR get_byte(new_key,33)<>4 OR substring(new_key FROM 34 FOR 65)=ANY(seen_points)
   OR substring(new_key FROM 2 FOR 32)<>sha256(convert_to('ZTSE/key/v1','UTF8')||CASE WHEN role<=3 THEN decode('000010','hex') ELSE decode('000101','hex') END||substring(new_key FROM 34 FOR 65)) THEN
   RAISE EXCEPTION 'manifest successor key ordering or identity differs' USING ERRCODE='23514'; END IF;
  last_id:=substring(new_key FROM 1 FOR 33); seen_points:=array_append(seen_points,substring(new_key FROM 34 FOR 65));
  from_ms:=public.payload_profile_election_number(substring(new_key FROM 133 FOR 8)); until_ms:=public.payload_profile_election_number(substring(new_key FROM 141 FOR 8));
  IF from_ms>until_ms OR get_byte(new_key,148) NOT IN(1,2) THEN RAISE EXCEPTION 'manifest successor key interval differs' USING ERRCODE='23514'; END IF;
  IF role=6 THEN
   roots:=roots+1;
   IF substring(new_key FROM 34 FOR 65)<>substring(successor FROM 88 FOR 65) OR get_byte(new_key,148)<>1 OR from_ms>issued OR until_ms<expires THEN
    RAISE EXCEPTION 'manifest successor root coverage differs' USING ERRCODE='23514'; END IF;
  END IF;
  IF role=2 AND get_byte(new_key,148)=1 THEN archives:=archives+1; END IF;
  found_key:=NULL;
  FOR i IN 0..old_count-1 LOOP
   old_key:=substring(prior FROM 154+149*i FOR 149);
   IF substring(old_key FROM 1 FOR 33)=substring(new_key FROM 1 FOR 33) THEN found_key:=old_key; END IF;
  END LOOP;
  IF role=5 AND substring(new_key FROM 115 FOR 16)=uuid_send(line) AND get_byte(new_key,148)=1 THEN
   new_active:=new_active+1;
   IF substring(new_key FROM 2 FOR 32)<>key_id OR substring(new_key FROM 34 FOR 65)<>point
    OR from_ms>checked_ms OR until_ms<=checked_ms THEN RAISE EXCEPTION 'current browser possession selection differs' USING ERRCODE='23514'; END IF;
  END IF;
  IF found_key IS NULL THEN
   added:=added+1;
   IF role<>5 OR substring(new_key FROM 2 FOR 32)<>key_id OR substring(new_key FROM 34 FOR 65)<>point
    OR substring(new_key FROM 99 FOR 16)<>decode(repeat('00',16),'hex') OR substring(new_key FROM 115 FOR 16)<>uuid_send(line)
    OR substring(new_key FROM 131 FOR 2)<>decode('0001','hex') OR get_byte(new_key,148)<>1
    OR from_ms<issued OR from_ms>checked_ms OR until_ms>expires OR until_ms<=checked_ms THEN
    RAISE EXCEPTION 'only explicit current-line browser enrollment can add a key' USING ERRCODE='23514'; END IF;
  END IF;
 END LOOP;
 IF roots<>1 OR archives<>1 OR old_active>1 OR new_active<>1 THEN RAISE EXCEPTION 'manifest successor active signer set differs' USING ERRCODE='23514'; END IF;
 IF old_active=0 AND added=1 AND revoked=0 THEN operation:='enroll';
 ELSIF old_active=1 AND added=0 AND revoked=0 THEN operation:='renew';
 ELSIF old_active=1 AND added=1 AND revoked=1 THEN operation:='replace';
 ELSE RAISE EXCEPTION 'unsupported manifest successor operation' USING ERRCODE='23514'; END IF;
 RETURN operation;
END;
$function$;

-- This selection grants no current device lease, physical handle or message use.
CREATE FUNCTION public.payload_profile_manifest_context(account uuid,user_id uuid,owner_session uuid,election uuid,binding uuid,device uuid,line uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE selected public.payload_profile_elections%ROWTYPE; reservation public.payload_profile_election_challenges%ROWTYPE;
 original public.payload_profile_v2_activation_receipts%ROWTYPE; owner_until bigint;
BEGIN
 SELECT * INTO selected FROM public.payload_profile_elections e WHERE e.account_id=account AND e.challenge_id=election;
 IF NOT FOUND OR(selected.new_binding_id,selected.device_id,selected.line_id,selected.selection_epoch) IS DISTINCT FROM(binding,device,line,1::bigint) THEN
  RAISE EXCEPTION 'manifest actual accepted election differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO reservation FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=election;
 SELECT * INTO original FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=selected.old_binding_id;
 IF NOT FOUND OR reservation.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'manifest original proof unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'manifest account unavailable' USING ERRCODE='23514'; END IF;
 owner_until:=public.payload_profile_selection_owner(account,user_id,owner_session);
 PERFORM 1 FROM public.phone_lines l JOIN public.device_line_bindings b ON(b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation)
  JOIN public.devices d ON(d.account_id,d.id)=(b.account_id,b.device_id) JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id)
  WHERE l.account_id=account AND l.id=line AND l.state='active' AND l.current_binding_generation=selected.new_binding_generation
   AND b.device_id=device AND b.state='active' AND b.purpose='sealed' AND b.owner_approval_digest=selected.owner_approval_digest
   AND b.device_confirmation_digest=selected.device_confirmation_digest AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.signing_key_sec1=original.device_point AND k.fingerprint=sha256(original.device_point) FOR SHARE OF l,b,d,k NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'manifest original elected binding unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_owner_approval_keys k JOIN public.sealed_line_key_receipts r ON r.account_id=k.account_id AND r.approval_point=k.signing_key_sec1
  WHERE k.account_id=account AND k.signing_key_sec1=original.owner_point AND k.revoked_at IS NULL
   AND k.fingerprint=sha256(original.owner_point) AND r.registration_id=original.registration_id AND r.retired_ms IS NULL AND r.activated_ms IS NOT NULL
  FOR SHARE OF k,r NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'manifest original registered approval unavailable' USING ERRCODE='23514'; END IF;
 RETURN owner_until;
END;
$function$;

CREATE FUNCTION public.payload_profile_manifest_scope(account uuid,user_id uuid,owner_session uuid,statement bytea,successor bytea) RETURNS public.payload_profile_manifest_successors
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_manifest_successors%ROWTYPE; authority public.sealed_manifest_authorities%ROWTYPE;
 selected public.payload_profile_elections%ROWTYPE; state text; epoch bigint; now_ms bigint;
BEGIN
 IF statement IS NULL OR octet_length(statement)<>513 OR substring(statement FROM 1 FOR 8)<>decode('5a544d5301030300','hex')
  OR successor IS NULL OR octet_length(successor) NOT BETWEEN 366 AND 9753 OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'manifest possession statement unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO authority FROM public.sealed_manifest_authorities a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR authority.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'manifest root authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'manifest account fence busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN RAISE EXCEPTION 'manifest accepted anchor unavailable' USING ERRCODE='23514'; END IF;
 row.account_id:=public.payload_profile_election_uuid(substring(statement FROM 9 FOR 16));
 row.initiating_user_id:=public.payload_profile_election_uuid(substring(statement FROM 25 FOR 16));
 row.initiating_session_id:=public.payload_profile_election_uuid(substring(statement FROM 41 FOR 16));
 row.device_id:=public.payload_profile_election_uuid(substring(statement FROM 57 FOR 16)); row.line_id:=public.payload_profile_election_uuid(substring(statement FROM 73 FOR 16));
 row.binding_id:=public.payload_profile_election_uuid(substring(statement FROM 89 FOR 16)); row.election_challenge_id:=public.payload_profile_election_uuid(substring(statement FROM 105 FOR 16));
 row.opening_id:=public.payload_profile_election_uuid(substring(statement FROM 121 FOR 16));
 row.binding_generation:=public.payload_profile_election_number(substring(statement FROM 137 FOR 8)); row.vault_generation:=public.payload_profile_election_number(substring(statement FROM 145 FOR 8));
 row.selection_epoch:=public.payload_profile_election_number(substring(statement FROM 153 FOR 8)); row.predecessor_version:=public.payload_profile_election_number(substring(statement FROM 161 FOR 8));
 row.successor_version:=public.payload_profile_election_number(substring(statement FROM 169 FOR 8)); row.issued_ms:=public.payload_profile_election_number(substring(statement FROM 177 FOR 8));
 row.expires_ms:=public.payload_profile_election_number(substring(statement FROM 185 FOR 8)); row.root_fingerprint:=substring(statement FROM 193 FOR 32);
 row.election_commitment:=substring(statement FROM 225 FOR 32); row.election_bundle_sha256:=substring(statement FROM 257 FOR 32);
 row.configured_origin_digest:=substring(statement FROM 289 FOR 32); row.owner_session_digest:=substring(statement FROM 321 FOR 32);
 row.predecessor_digest:=substring(statement FROM 353 FOR 32); row.successor_signed_manifest_sha256:=substring(statement FROM 385 FOR 32);
 row.browser_signer_key_id:=substring(statement FROM 417 FOR 32); row.browser_signer_point:=substring(statement FROM 449 FOR 65);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF(row.account_id,row.initiating_user_id,row.initiating_session_id) IS DISTINCT FROM(account,user_id,owner_session)
  OR row.vault_generation<>1 OR row.selection_epoch<>1 OR row.binding_generation<=0 OR row.predecessor_version<>authority.version
  OR row.successor_version::numeric<>authority.version::numeric+1 OR row.predecessor_digest<>authority.semantic_digest
  OR row.root_fingerprint<>authority.root_fingerprint OR row.configured_origin_digest=decode(repeat('00',32),'hex')
  OR row.owner_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner-session/v1',uuid_send(account)||uuid_send(user_id)||uuid_send(owner_session)))
  OR row.issued_ms<=0 OR row.issued_ms>now_ms OR row.expires_ms<=now_ms OR row.expires_ms-row.issued_ms NOT BETWEEN 1 AND 300000
  OR row.successor_signed_manifest_sha256<>sha256(successor) OR authority.generation<>1 OR authority.anchor_digest<>decode(repeat('00',32),'hex')
  OR authority.last_verified_ms<authority.accepted_at_ms OR authority.last_verified_ms>now_ms OR row.issued_ms<authority.accepted_at_ms THEN
  RAISE EXCEPTION 'manifest possession current scope differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO selected FROM public.payload_profile_elections e WHERE e.account_id=account AND e.challenge_id=row.election_challenge_id;
 IF NOT FOUND OR(selected.new_binding_id,selected.device_id,selected.line_id,selected.new_binding_generation,selected.election_commitment,selected.election_bundle_sha256,selected.root_fingerprint)
  IS DISTINCT FROM(row.binding_id,row.device_id,row.line_id,row.binding_generation,row.election_commitment,row.election_bundle_sha256,row.root_fingerprint)
  OR NOT public.payload_profile_manifest_ancestry(account,row.election_challenge_id,authority.version,authority.semantic_digest,authority.manifest,authority.accepted_at_ms) THEN
  RAISE EXCEPTION 'manifest current accepted ancestry differs' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_manifest_context(account,user_id,owner_session,row.election_challenge_id,row.binding_id,row.device_id,row.line_id);
 row.operation:=public.payload_profile_manifest_keys(authority.manifest,successor,row.line_id,row.browser_signer_point,row.browser_signer_key_id,now_ms);
 PERFORM public.payload_profile_election_reader(successor,3::smallint,selected.selected_reader_key_id,row.device_id,row.line_id,now_ms);
 IF substring(authority.root_pin FROM 30 FOR 65)<>substring(successor FROM 88 FOR 65) THEN RAISE EXCEPTION 'manifest successor root point differs' USING ERRCODE='23514'; END IF;
 row.root_pin:=authority.root_pin; row.predecessor_signed_manifest:=authority.manifest; row.predecessor_signed_manifest_sha256:=sha256(authority.manifest);
 row.predecessor_accepted_ms:=authority.accepted_at_ms; row.successor_signed_manifest:=successor;
 row.successor_digest:=sha256(substring(successor FROM 1 FOR octet_length(successor)-64)); row.statement:=statement; row.statement_sha256:=sha256(statement);
 SELECT r.opening_id,r.ancestry_sha256 INTO row.predecessor_opening_id,row.predecessor_ancestry_sha256 FROM public.payload_profile_manifest_successors r WHERE r.account_id=account AND r.successor_version=authority.version;
 IF NOT FOUND THEN row.predecessor_ancestry_sha256:=public.payload_profile_manifest_base(account,row.election_challenge_id); END IF;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.payload_profile_manifest_install(account uuid,opening uuid,user_id uuid,owner_session uuid,statement bytea,successor bytea,signature bytea,factor_deadline_ms bigint)
RETURNS SETOF public.payload_profile_manifest_successors
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_manifest_successors%ROWTYPE; previous public.payload_profile_manifest_successors%ROWTYPE; now_ms bigint; owner_until bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR user_id IS NULL OR owner_session IS NULL OR statement IS NULL OR successor IS NULL OR signature IS NULL
  OR octet_length(statement)<>513 OR octet_length(signature)<>64 OR factor_deadline_ms IS NULL THEN RAISE EXCEPTION 'manifest install input differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM public.payload_profile_manifest_successors r WHERE r.account_id=account AND r.opening_id=opening;
 IF FOUND THEN
  IF(previous.initiating_user_id,previous.initiating_session_id,previous.statement,previous.successor_signed_manifest,previous.signature)
   IS DISTINCT FROM(user_id,owner_session,statement,successor,signature) THEN RAISE EXCEPTION 'manifest opening retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT previous; RETURN;
 END IF;
 row:=public.payload_profile_manifest_scope(account,user_id,owner_session,statement,successor);
 IF row.opening_id<>opening THEN RAISE EXCEPTION 'manifest opening scope differs' USING ERRCODE='23514'; END IF;
 owner_until:=public.payload_profile_selection_owner(account,user_id,owner_session);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row.signature:=signature; row.accepted_ms:=now_ms;
 row.ancestry_sha256:=public.payload_profile_manifest_step(row.predecessor_ancestry_sha256,row.opening_id,row.statement,row.signature,row.successor_signed_manifest,row.accepted_ms);
 row.acceptance_deadline_ms:=least(row.expires_ms,factor_deadline_ms,owner_until,public.payload_profile_election_number(substring(successor FROM 48 FOR 8)));
 IF now_ms>=row.acceptance_deadline_ms OR factor_deadline_ms>now_ms+300000 THEN RAISE EXCEPTION 'manifest held factor deadline differs' USING ERRCODE='23514'; END IF;
 INSERT INTO public.payload_profile_manifest_successors SELECT row.*;
 INSERT INTO public.known_signing_role_claims(account_id,signing_key_sec1,role) VALUES(account,row.browser_signer_point,'browser_content03') ON CONFLICT DO NOTHING;
 UPDATE public.sealed_manifest_authorities a SET version=row.successor_version,semantic_digest=row.successor_digest,manifest=row.successor_signed_manifest,
   accepted_at_ms=row.accepted_ms,last_verified_ms=row.accepted_ms
  WHERE a.account_id=account AND a.version=row.predecessor_version AND a.semantic_digest=row.predecessor_digest AND a.revoked_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'manifest current tip changed' USING ERRCODE='23514'; END IF;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.payload_profile_manifest_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.payload_profile_manifest_successors%ROWTYPE; wanted uuid; state text; epoch bigint; now_ms bigint; owner_until bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.payload_profile_manifest_successors'::regclass OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'unexpected manifest writer context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN wanted:=OLD.account_id; ELSE wanted:=NEW.account_id; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN RAISE EXCEPTION 'manifest writer fence busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'manifest retained anchor unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=wanted) THEN RETURN OLD; END IF;
 IF TG_OP<>'INSERT' OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(wanted,epoch) THEN
  RAISE EXCEPTION 'manifest accepted history immutable' USING ERRCODE='23514'; END IF;
 checked:=public.payload_profile_manifest_scope(NEW.account_id,NEW.initiating_user_id,NEW.initiating_session_id,NEW.statement,NEW.successor_signed_manifest);
 IF(to_jsonb(NEW)-ARRAY['signature','accepted_ms','acceptance_deadline_ms','ancestry_sha256']) IS DISTINCT FROM(to_jsonb(checked)-ARRAY['signature','accepted_ms','acceptance_deadline_ms','ancestry_sha256'])
  OR NEW.ancestry_sha256<>public.payload_profile_manifest_step(NEW.predecessor_ancestry_sha256,NEW.opening_id,NEW.statement,NEW.signature,NEW.successor_signed_manifest,NEW.accepted_ms) THEN
  RAISE EXCEPTION 'manifest receipt differs from actual predecessor' USING ERRCODE='23514'; END IF;
 owner_until:=public.payload_profile_selection_owner(NEW.account_id,NEW.initiating_user_id,NEW.initiating_session_id);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NEW.accepted_ms<NEW.issued_ms OR NEW.accepted_ms<NEW.predecessor_accepted_ms OR NEW.accepted_ms>now_ms
  OR now_ms>=NEW.acceptance_deadline_ms OR NEW.acceptance_deadline_ms>least(NEW.expires_ms,owner_until,public.payload_profile_election_number(substring(NEW.successor_signed_manifest FROM 48 FOR 8))) THEN
  RAISE EXCEPTION 'manifest acceptance checkpoint differs' USING ERRCODE='23514'; END IF;
 -- A real tuple version prevents old RR/SSI snapshots from ignoring a new
 -- manifest at unchanged selection epoch. Immutable retries never reach here.
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
 RETURN NEW;
END;
$function$;

CREATE FUNCTION public.payload_profile_manifest_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.payload_profile_manifest_successors%ROWTYPE; authority public.sealed_manifest_authorities%ROWTYPE; now_ms bigint; owner_until bigint;
BEGIN
 SELECT * INTO row FROM public.payload_profile_manifest_successors r WHERE r.account_id=NEW.account_id AND r.opening_id=NEW.opening_id;
 IF NOT FOUND THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'manifest receipt disappeared' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 SELECT * INTO authority FROM public.sealed_manifest_authorities a WHERE a.account_id=row.account_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR authority.revoked_at IS NOT NULL OR(authority.root_pin,authority.root_fingerprint,authority.version,authority.semantic_digest,authority.manifest,authority.accepted_at_ms,authority.last_verified_ms)
  IS DISTINCT FROM(row.root_pin,row.root_fingerprint,row.successor_version,row.successor_digest,row.successor_signed_manifest,row.accepted_ms,row.accepted_ms)
  OR NOT EXISTS(SELECT FROM public.original_reply_manifest_history h WHERE h.account_id=row.account_id AND h.root_generation=1 AND h.version=row.successor_version
   AND h.digest=row.successor_digest AND h.manifest=row.successor_signed_manifest AND h.accepted_at_ms=row.accepted_ms)
  OR NOT EXISTS(SELECT FROM public.known_signing_role_claims k JOIN public.known_signing_point_reservations p USING(account_id,signing_key_sec1,family)
   WHERE k.account_id=row.account_id AND k.signing_key_sec1=row.browser_signer_point AND k.role='browser_content03' AND p.family='browser_content03')
  OR NOT public.payload_profile_manifest_ancestry(row.account_id,row.election_challenge_id,row.successor_version,row.successor_digest,row.successor_signed_manifest,row.accepted_ms) THEN
  RAISE EXCEPTION 'manifest authority/history/claim did not commit together' USING ERRCODE='23514'; END IF;
 owner_until:=public.payload_profile_manifest_context(row.account_id,row.initiating_user_id,row.initiating_session_id,row.election_challenge_id,row.binding_id,row.device_id,row.line_id);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF public.payload_profile_manifest_keys(row.predecessor_signed_manifest,row.successor_signed_manifest,row.line_id,row.browser_signer_point,row.browser_signer_key_id,now_ms)<>row.operation
  OR now_ms<row.accepted_ms OR now_ms>=least(owner_until,row.acceptance_deadline_ms) THEN RAISE EXCEPTION 'manifest scope or deadline passed before commit' USING ERRCODE='23514'; END IF;
 IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=least(owner_until,row.acceptance_deadline_ms) THEN RAISE EXCEPTION 'manifest deadline passed after waits' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;

CREATE TRIGGER payload_profile_manifest_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_manifest_successors
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_manifest_rows_guard();
CREATE CONSTRAINT TRIGGER payload_profile_manifest_after_insert AFTER INSERT ON public.payload_profile_manifest_successors
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.payload_profile_manifest_complete();

ALTER TABLE public.known_signing_point_reservations DROP CONSTRAINT known_signing_point_reservations_family_check;
ALTER TABLE public.known_signing_point_reservations ADD CONSTRAINT known_signing_point_reservations_family_check CHECK(family IN('sealed_root','sms_approval','line_device','browser_content03'));
ALTER TABLE public.known_signing_role_claims DROP CONSTRAINT known_signing_role_claims_role_check;
ALTER TABLE public.known_signing_role_claims ADD CONSTRAINT known_signing_role_claims_role_check CHECK(role IN('sealed_root','sms_approval','line_approval','device_auth','browser_content03'));

CREATE OR REPLACE FUNCTION public.payload_profile_writer_policy(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE selected public.payload_profile_elections%ROWTYPE; reserved public.payload_profile_election_challenges%ROWTYPE;
 signed_before boolean; is_transition boolean; parent uuid; mode text;
BEGIN
 IF epoch<0 OR operation NOT IN('INSERT','UPDATE','DELETE') THEN RAISE EXCEPTION 'unknown writer operation' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN; END IF;
 IF epoch>0 AND NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'unknown positive selection epoch' USING ERRCODE='23514'; END IF;

 -- Only the actual newly retained typed successor can change the03 tip or
 -- reserve its purpose-separated browser point. Existing legacy roles retain
 -- their original immutable family/uniqueness guards and no content exception.
 IF epoch=1 AND relation_name='sealed_manifest_authorities' AND operation='UPDATE' AND EXISTS(
  SELECT FROM public.payload_profile_manifest_successors r WHERE r.account_id=account
   AND (old_row->>'version')::bigint=r.predecessor_version AND (new_row->>'version')::bigint=r.successor_version
   AND old_row->>'manifest'=to_jsonb(r)->>'predecessor_signed_manifest' AND new_row->>'manifest'=to_jsonb(r)->>'successor_signed_manifest'
   AND old_row->>'semantic_digest'=to_jsonb(r)->>'predecessor_digest' AND new_row->>'semantic_digest'=to_jsonb(r)->>'successor_digest'
   AND (old_row->>'accepted_at_ms')::bigint=r.predecessor_accepted_ms AND (new_row->>'accepted_at_ms')::bigint=r.accepted_ms
   AND (new_row->>'last_verified_ms')::bigint=r.accepted_ms AND new_row->>'root_pin'=to_jsonb(r)->>'root_pin'
   AND (old_row-ARRAY['version','semantic_digest','manifest','accepted_at_ms','last_verified_ms'])=(new_row-ARRAY['version','semantic_digest','manifest','accepted_at_ms','last_verified_ms'])) THEN RETURN; END IF;
 IF epoch=1 AND relation_name='original_reply_manifest_history' AND operation='INSERT' AND EXISTS(
  SELECT FROM public.payload_profile_manifest_successors r WHERE r.account_id=account AND(new_row->>'root_generation')::bigint=1
   AND(new_row->>'version')::bigint=r.successor_version AND new_row->>'digest'=to_jsonb(r)->>'successor_digest'
   AND new_row->>'manifest'=to_jsonb(r)->>'successor_signed_manifest' AND(new_row->>'accepted_at_ms')::bigint=r.accepted_ms) THEN RETURN; END IF;
 IF relation_name IN('known_signing_point_reservations','known_signing_role_claims') AND(
  coalesce(new_row->>'family',old_row->>'family')='browser_content03' OR coalesce(new_row->>'role',old_row->>'role')='browser_content03') THEN
  IF epoch=1 AND operation='INSERT' AND EXISTS(SELECT FROM public.payload_profile_manifest_successors r WHERE r.account_id=account
   AND new_row->>'signing_key_sec1'=to_jsonb(r)->>'browser_signer_point') THEN RETURN; END IF;
  RAISE EXCEPTION 'browser signing claim requires typed03 successor' USING ERRCODE='23514';
 END IF;
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
CREATE OR REPLACE FUNCTION public.payload_profile_selection_scope(account uuid,owner_user uuid,owner_session uuid,core bytea)
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
 IF NOT FOUND OR(election.device_id,election.line_id,election.new_binding_generation,election.selection_epoch,election.vault_generation,election.election_commitment,election.election_bundle_sha256,election.selected_reader_key_id,election.root_fingerprint)
  IS DISTINCT FROM(row.device_id,row.line_id,row.binding_generation,row.selection_epoch,row.vault_generation,row.election_commitment,row.election_bundle_sha256,row.selected_reader_key_id,row.root_fingerprint) THEN
  RAISE EXCEPTION 'actual accepted physical selection differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO reservation FROM public.payload_profile_election_challenges c WHERE c.account_id=account AND c.challenge_id=election.challenge_id;
 IF NOT FOUND OR reservation.closed_unaccepted_ms IS NOT NULL OR reservation.new_binding_id<>row.binding_id
  OR authority.revoked_at IS NOT NULL OR authority.root_pin<>reservation.root_pin OR authority.root_fingerprint<>row.root_fingerprint
  OR authority.generation<>1 OR authority.anchor_digest<>decode(repeat('00',32),'hex')
  OR authority.version<>row.manifest_version OR authority.semantic_digest IS DISTINCT FROM row.manifest_digest
  OR NOT public.payload_profile_manifest_ancestry(account,election.challenge_id,authority.version,authority.semantic_digest,authority.manifest,authority.accepted_at_ms)
  OR authority.last_verified_ms<authority.accepted_at_ms OR authority.last_verified_ms>now_ms OR row.issued_ms<authority.accepted_at_ms
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
CREATE OR REPLACE FUNCTION public.payload_profile_selection_same_scope(older jsonb,newer jsonb)
RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT (older-ARRAY['opening_id','refresh_id','initiating_user_id','initiating_session_id','owner_session_digest','nonce','core','issued_ms','expires_ms','reserve_deadline_ms','device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id','manifest_version','manifest_digest','manifest_accepted_ms','signed_manifest','signed_manifest_sha256'])
  =(newer-ARRAY['opening_id','refresh_id','initiating_user_id','initiating_session_id','owner_session_digest','nonce','core','issued_ms','expires_ms','reserve_deadline_ms','device_observation','device_signature','device_proof_ms','closed_unaccepted_ms','superseded_by_refresh_id','manifest_version','manifest_digest','manifest_accepted_ms','signed_manifest','signed_manifest_sha256'])
  AND(older->>'manifest_version')::bigint<=(newer->>'manifest_version')::bigint
  AND public.payload_profile_manifest_ancestry((older->>'account_id')::uuid,(older->>'election_challenge_id')::uuid,(older->>'manifest_version')::bigint,decode(substring(older->>'manifest_digest' FROM 3),'hex'),decode(substring(older->>'signed_manifest' FROM 3),'hex'),(older->>'manifest_accepted_ms')::bigint)
  AND public.payload_profile_manifest_ancestry((newer->>'account_id')::uuid,(newer->>'election_challenge_id')::uuid,(newer->>'manifest_version')::bigint,decode(substring(newer->>'manifest_digest' FROM 3),'hex'),decode(substring(newer->>'signed_manifest' FROM 3),'hex'),(newer->>'manifest_accepted_ms')::bigint)
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=112 AND min(version)=1 AND max(version)=112 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=112 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE FUNCTION public.payload_profile_manifest_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_selection_ready()
  AND has_table_privilege(current_user,'public.payload_profile_manifest_successors','SELECT')
  AND NOT has_table_privilege(current_user,'public.payload_profile_manifest_successors','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.payload_profile_manifest_successors','INSERT,UPDATE,REFERENCES')
  AND has_function_privilege(current_user,'public.payload_profile_manifest_install(uuid,uuid,uuid,uuid,bytea,bytea,bytea,bigint)','EXECUTE')
  AND has_function_privilege(current_user,'public.payload_profile_manifest_retention(uuid,uuid,bigint,bytea,bytea,bigint,bytea)','EXECUTE')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_manifest_%'
   AND p.proname NOT IN('payload_profile_manifest_install','payload_profile_manifest_retention','payload_profile_manifest_ready') AND has_function_privilege(current_user,p.oid,'EXECUTE'))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_manifest_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; columns_sql text;
BEGIN
 REVOKE ALL ON TABLE public.payload_profile_manifest_successors FROM PUBLIC;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.payload_profile_manifest_successors'::regclass AND attnum>0 AND NOT attisdropped;
  REVOKE ALL ON TABLE public.payload_profile_manifest_successors FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.payload_profile_manifest_successors FROM PUBLIC,zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.payload_profile_manifest_successors TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'payload_profile_manifest_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('payload_profile_manifest_install','payload_profile_manifest_retention','payload_profile_manifest_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=112);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,112,public.payload_profile_writer_graph());
