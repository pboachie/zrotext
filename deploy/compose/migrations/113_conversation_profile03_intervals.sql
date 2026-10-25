-- SPDX-License-Identifier: AGPL-3.0-only
-- Original profile03 content consent; authentication and crypto stay independent.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=112; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN RAISE EXCEPTION 'conversation03 requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(110,111,112) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=112 THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=112 THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=112 THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_selection_scope(uuid, uuid, uuid, bytea)','5ebe4bdf74cec39ff19cd598e665e585373719230bd67bc505c71db55e44bdc5','public.payload_profile_selection_challenges','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','owner_user','owner_session','core']::text[]),
            ('payload_profile_selection_owner(uuid, uuid, uuid)','078248633116e4ceddeb07772c2810ed7d1742df073acb292eb5665b95123587','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','owner_user','owner_session']::text[]),
            ('payload_profile_selection_observation(bytea, integer)','797f068dd42c9479f779bc3606601001bad9b083ef07ea0a643e4e857ff1ef51','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['observation','selected_subscription']::text[]),
            ('payload_profile_selection_reserve(uuid, uuid, uuid, uuid, bytea, bigint)','4dbc40c492e86e679b43c7b1c41f204e1cfed0c14af984163852d236dd3f60ef','public.payload_profile_selection_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','user_id','owner_session','core','factor_deadline_ms']::text[]),
            ('payload_profile_selection_device_proof(uuid, uuid, bytea, bytea)','bc3b26afb36acc2f12b9318a0aa990c116d7ebc2208157881d31a666981070d7','public.payload_profile_selection_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','refresh','observation','signature']::text[]),
            ('payload_profile_selection_approve(uuid, uuid, uuid, bytea, bigint)','abae401f3ff6bfd4fd6b656eceaeb22c1a5052aa7b12c50bc83741a95f1b9b7d','public.payload_profile_selection_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','refresh','bundle','factor_deadline_ms']::text[]),
            ('payload_profile_selection_install(uuid, uuid, bytea, bytea)','ac80e05d31d46a1ac95472947bb79888394a72b42da7a4f8e7de547d82aa14f9','public.payload_profile_selection_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','refresh','bundle_sha256','signature']::text[]),
            ('payload_profile_selection_same_scope(jsonb, jsonb)','ca31ab2bff47edc34cfd5c55b9d7c30d2bcf1f55bcad3351edc339fc43fd37ac','boolean','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['older','newer']::text[]),
            ('payload_profile_selection_rows_guard()','21934dcb2319933a1ea85825781600bb8a526b59d042b3da60bd90f1dda83e59','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_selection_complete()','39c37a2db742cdf5317e9958d95aa5873f6917f47246885b02fed8c51f0cb1d7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_version()','32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_selection_ready()','9d147bd44e88dfaec22746f2c12ff45c0eb41814a0672a61680144e1ebb02757','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_manifest_retention(uuid, uuid, bigint, bytea, bytea, bigint, bytea)','716160d7da776576d2aa9710275e0632b8cf7eb2b1625460ae0206dbc85b8af6','boolean','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','election','version','digest','manifest','accepted_ms','ancestry_sha256']::text[]),
            ('payload_profile_manifest_base(uuid, uuid)','919970be8a8b9d6f3a0b90b2e2b3c4a36e21f9e801f9717a2404e513304ce3f0','bytea','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','election']::text[]),
            ('payload_profile_manifest_step(bytea, uuid, bytea, bytea, bytea, bigint)','55a2bd8e4957cc86851a7bab5d67cd0e96ddc02a6a7c9632b61f014829e2f106','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['prior','opening','statement','signature','successor','accepted_ms']::text[]),
            ('payload_profile_manifest_ancestry(uuid, uuid, bigint, bytea, bytea, bigint)','a3b5abe9b96cb4ea8e7b86d10ed4f07c59a659c1afee9c159653799fbf0a6a05','boolean','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','election','version','digest','manifest','accepted_ms']::text[]),
            ('payload_profile_manifest_keys(bytea, bytea, uuid, bytea, bytea, bigint)','4ee4392ede4e1af880ee8d9b37639347a9504e3c34ee26cf3897f7639d6cd4cf','text','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['prior','successor','line','point','key_id','checked_ms']::text[]),
            ('payload_profile_manifest_context(uuid, uuid, uuid, uuid, uuid, uuid, uuid)','7b4e413a4cce755dea74f357166b80a85bc4d1f7b812bb4057484aa7a63752ba','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','user_id','owner_session','election','binding','device','line']::text[]),
            ('payload_profile_manifest_scope(uuid, uuid, uuid, bytea, bytea)','0959c7165290d9c1473c76d6c011f4283a8040a129a9a862ca2921921555b362','public.payload_profile_manifest_successors','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','user_id','owner_session','statement','successor']::text[]),
            ('payload_profile_manifest_install(uuid, uuid, uuid, uuid, bytea, bytea, bytea, bigint)','a179acb6b7b03f6f15b40bda86a819359ad11111155c111d1cb73650d33bfb9f','public.payload_profile_manifest_successors','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','user_id','owner_session','statement','successor','signature','factor_deadline_ms']::text[]),
            ('payload_profile_manifest_rows_guard()','78e54cf0c28b5b6ed3e2e5336764f40ea41f75567970b89f31af891494560adb','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_manifest_complete()','ef8dc7f3bf15646a87d2ccca10ab572a486acd56ca2999b0b83686bcaa675748','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_manifest_ready()','3a5490326b48017d622b326f593aba8703126263e8610999aebc18c1de80f925','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'manifest successor declaration or body inconsistent'; END IF;
          END LOOP;
 IF NOT(SELECT count(*)=112 AND min(version)=1 AND max(version)=112 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=112 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'conversation03 predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

CREATE TABLE public.conversation_profile03_intervals (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 opening_id uuid NOT NULL, interval_id uuid NOT NULL, receipt_id uuid NOT NULL UNIQUE,
 initiating_user_id uuid NOT NULL, initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL, line_id uuid NOT NULL, binding_id uuid NOT NULL,
 election_challenge_id uuid NOT NULL, original_binding_id uuid NOT NULL, physical_refresh_id uuid,
 binding_generation bigint NOT NULL CHECK(binding_generation>0), vault_generation bigint NOT NULL CHECK(vault_generation=1),
 manifest_version bigint NOT NULL CHECK(manifest_version>0), selection_epoch bigint NOT NULL CHECK(selection_epoch=1),
 issued_ms bigint NOT NULL CHECK(issued_ms>0), setup_expires_ms bigint NOT NULL CHECK(setup_expires_ms>issued_ms AND setup_expires_ms-issued_ms<=300000),
 interval_starts_ms bigint NOT NULL CHECK(interval_starts_ms=issued_ms),
 interval_expires_ms bigint NOT NULL CHECK(interval_expires_ms>issued_ms AND interval_expires_ms-issued_ms<=86400000),
 reserve_deadline_ms bigint NOT NULL CHECK(reserve_deadline_ms>issued_ms AND reserve_deadline_ms<=setup_expires_ms),
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0), proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 proof_site_id text NOT NULL CHECK(octet_length(proof_site_id) BETWEEN 1 AND 256),
 proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id) BETWEEN 1 AND 256),
 peer text NOT NULL CHECK(peer ~ '^\+[1-9][0-9]{1,14}$'),
 physical_source_kind text NOT NULL CHECK(physical_source_kind IN('original_v2','owner_refresh03')),
 phase text NOT NULL CHECK(phase IN('reserved','requested','install_pending','active','stopped','expired')),
 statement bytea NOT NULL CHECK(octet_length(statement) BETWEEN 695 AND 1092), statement_sha256 bytea NOT NULL CHECK(statement_sha256=sha256(statement)),
 selected_reader_key_id bytea NOT NULL CHECK(octet_length(selected_reader_key_id)=32), archive_reader_key_id bytea NOT NULL CHECK(octet_length(archive_reader_key_id)=32),
 phone_signer_key_id bytea NOT NULL CHECK(octet_length(phone_signer_key_id)=32), browser_signer_key_id bytea NOT NULL CHECK(octet_length(browser_signer_key_id)=32),
 root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32), manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 election_commitment bytea NOT NULL CHECK(octet_length(election_commitment)=32), election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32),
 owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32), configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32),
 device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32), physical_selection_digest bytea NOT NULL CHECK(octet_length(physical_selection_digest)=32),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32), integration_readers bytea NOT NULL CHECK(octet_length(integration_readers) IN(0,64,128,192,256,320,384)),
 signed_manifest bytea NOT NULL CHECK(octet_length(signed_manifest) BETWEEN 366 AND 9753), signed_manifest_sha256 bytea NOT NULL CHECK(signed_manifest_sha256=sha256(signed_manifest)),
 root_pin bytea NOT NULL CHECK(octet_length(root_pin)=94),
 owner_signature bytea CHECK(owner_signature IS NULL OR octet_length(owner_signature)=64), phone_signature bytea CHECK(phone_signature IS NULL OR octet_length(phone_signature)=64),
 installed_signature bytea CHECK(installed_signature IS NULL OR octet_length(installed_signature)=64),
 requested_ms bigint, request_deadline_ms bigint, approved_ms bigint, installed_ms bigint,
 stopped_ms bigint, stopped_by_user_id uuid, stopped_by_session_id uuid, expired_ms bigint, superseded_by_interval_id uuid,
 stop_actor_kind text CHECK(stop_actor_kind IN('owner','device')),
 stopped_by_device_id uuid, stopped_by_site_id text, stopped_by_instance_id text,
 stopped_by_connection_epoch bigint, stopped_by_deployment_epoch bigint, stopped_by_device_session_digest bytea,
 PRIMARY KEY(account_id,interval_id), UNIQUE(account_id,opening_id),
 FOREIGN KEY(account_id,election_challenge_id) REFERENCES public.payload_profile_elections(account_id,challenge_id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,physical_refresh_id) REFERENCES public.payload_profile_selection_receipts(account_id,refresh_id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,superseded_by_interval_id) REFERENCES public.conversation_profile03_intervals(account_id,interval_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(opening_id<>interval_id AND opening_id<>receipt_id AND interval_id<>receipt_id),
 CHECK((physical_source_kind='original_v2')=(physical_refresh_id IS NULL)),
 CHECK((owner_signature IS NULL)=(requested_ms IS NULL) AND(owner_signature IS NULL)=(request_deadline_ms IS NULL)),
 CHECK((phone_signature IS NULL)=(approved_ms IS NULL) AND(installed_signature IS NULL)=(installed_ms IS NULL)),
 CHECK(requested_ms IS NULL OR requested_ms>=issued_ms AND requested_ms<request_deadline_ms AND request_deadline_ms<=setup_expires_ms),
 CHECK(approved_ms IS NULL OR owner_signature IS NOT NULL AND approved_ms>=requested_ms AND approved_ms<setup_expires_ms),
 CHECK(installed_ms IS NULL OR phone_signature IS NOT NULL AND installed_ms>=approved_ms AND installed_ms<setup_expires_ms),
 CHECK((phase IN('stopped','expired')) OR
  (phase='reserved' AND owner_signature IS NULL AND phone_signature IS NULL AND installed_signature IS NULL) OR
  (phase='requested' AND owner_signature IS NOT NULL AND phone_signature IS NULL AND installed_signature IS NULL) OR
  (phase='install_pending' AND owner_signature IS NOT NULL AND phone_signature IS NOT NULL AND installed_signature IS NULL) OR
  (phase='active' AND owner_signature IS NOT NULL AND phone_signature IS NOT NULL AND installed_signature IS NOT NULL)),
 CHECK((phase='stopped')=(stopped_ms IS NOT NULL) AND(phase='expired')=(expired_ms IS NOT NULL)),
 CHECK((expired_ms IS NULL)=(superseded_by_interval_id IS NULL)),
 CHECK(stopped_ms IS NULL OR stopped_ms>=issued_ms),
 CHECK((stopped_ms IS NULL AND stop_actor_kind IS NULL AND stopped_by_user_id IS NULL AND stopped_by_session_id IS NULL
   AND stopped_by_device_id IS NULL AND stopped_by_site_id IS NULL AND stopped_by_instance_id IS NULL
   AND stopped_by_connection_epoch IS NULL AND stopped_by_deployment_epoch IS NULL AND stopped_by_device_session_digest IS NULL)
  OR(stop_actor_kind='owner' AND stopped_ms IS NOT NULL AND stopped_by_user_id=initiating_user_id AND stopped_by_session_id IS NOT NULL
   AND stopped_by_device_id IS NULL AND stopped_by_site_id IS NULL AND stopped_by_instance_id IS NULL
   AND stopped_by_connection_epoch IS NULL AND stopped_by_deployment_epoch IS NULL AND stopped_by_device_session_digest IS NULL)
  OR(stop_actor_kind='device' AND stopped_ms IS NOT NULL AND stopped_by_user_id IS NULL AND stopped_by_session_id IS NULL
   AND stopped_by_device_id=device_id AND stopped_by_site_id IS NOT NULL AND stopped_by_instance_id IS NOT NULL
   AND stopped_by_connection_epoch>0 AND stopped_by_deployment_epoch>0 AND octet_length(stopped_by_device_session_digest)=32))
);
CREATE INDEX conversation_profile03_allocation_budget ON public.conversation_profile03_intervals(account_id,line_id,binding_id,peer,issued_ms);
CREATE INDEX conversation_profile03_live_scope ON public.conversation_profile03_intervals(account_id,binding_id,device_session_digest,peer,phase);

-- Exact selected signed key metadata. No private custody or signature is proved here.
CREATE FUNCTION public.conversation_profile03_key_until(manifest bytea,role integer,key_id bytea,device uuid,line uuid,checked_ms bigint) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE key bytea; i integer; result bigint; expected_device bytea; expected_line bytea; expected_scope bytea;
BEGIN
 IF octet_length(manifest)<366 OR substring(manifest FROM 1 FOR 7)<>decode('5a544d41030303','hex')
  OR get_byte(manifest,152) NOT BETWEEN 1 AND 64 OR octet_length(manifest)<>217+149*get_byte(manifest,152) OR role NOT BETWEEN 1 AND 5 THEN
  RAISE EXCEPTION 'interval selected manifest shape' USING ERRCODE='23514'; END IF;
 expected_device:=CASE WHEN role IN(1,4) THEN uuid_send(device) ELSE decode(repeat('00',16),'hex') END;
 expected_line:=CASE WHEN role IN(2,3) THEN decode(repeat('00',16),'hex') ELSE uuid_send(line) END;
 expected_scope:=CASE role WHEN 1 THEN decode('0004','hex') WHEN 2 THEN decode('000c','hex') WHEN 3 THEN decode('000c','hex') WHEN 4 THEN decode('0002','hex') WHEN 5 THEN decode('0001','hex') END;
 FOR i IN 0..get_byte(manifest,152)-1 LOOP
  key:=substring(manifest FROM 154+149*i FOR 149);
  IF get_byte(key,0)=role AND substring(key FROM 2 FOR 32)=key_id THEN
   IF result IS NOT NULL OR get_byte(key,33)<>4 OR get_byte(key,148)<>1
    OR substring(key FROM 99 FOR 16)<>expected_device OR substring(key FROM 115 FOR 16)<>expected_line
    OR substring(key FROM 131 FOR 2)<>expected_scope
    OR substring(key FROM 2 FOR 32)<>sha256(convert_to('ZTSE/key/v1','UTF8')||CASE WHEN role<=3 THEN decode('000010','hex') ELSE decode('000101','hex') END||substring(key FROM 34 FOR 65))
    OR public.payload_profile_election_number(substring(key FROM 133 FOR 8))>checked_ms
    OR public.payload_profile_election_number(substring(key FROM 141 FOR 8))<=checked_ms THEN
    RAISE EXCEPTION 'interval selected key scope differs' USING ERRCODE='23514'; END IF;
   result:=public.payload_profile_election_number(substring(key FROM 141 FOR 8));
  END IF;
 END LOOP;
 IF result IS NULL THEN RAISE EXCEPTION 'interval selected key unavailable' USING ERRCODE='23514'; END IF;
 RETURN result;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_lock(account uuid,"interval" uuid) RETURNS public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; state text; epoch bigint;
BEGIN
 PERFORM 1 FROM public.sealed_manifest_authorities a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR pg_is_in_recovery() THEN RAISE EXCEPTION 'interval primary authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'interval account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN RAISE EXCEPTION 'interval retained anchor unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts a WHERE a.id=account AND a.disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval account unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.interval_id="interval" FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval original unavailable' USING ERRCODE='23514'; END IF;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_reserve(account uuid,opening uuid,user_id uuid,owner_session uuid,"interval" uuid,receipt uuid,statement bytea,owner_deadline_ms bigint)
RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; previous public.conversation_profile03_intervals%ROWTYPE; checked_ms bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR user_id IS NULL OR owner_session IS NULL OR "interval" IS NULL OR receipt IS NULL OR statement IS NULL OR owner_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'interval reservation input unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.opening_id=opening;
 IF FOUND THEN
  IF(previous.initiating_user_id,previous.initiating_session_id,previous.interval_id,previous.receipt_id,previous.statement) IS DISTINCT FROM(user_id,owner_session,"interval",receipt,statement) THEN
   RAISE EXCEPTION 'interval reservation retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT previous; RETURN;
 END IF;
 row:=public.conversation_profile03_interval_scope(account,user_id,owner_session,statement,true);
 IF(row.opening_id,row.interval_id,row.receipt_id) IS DISTINCT FROM(opening,"interval",receipt) THEN RAISE EXCEPTION 'interval reservation selectors differ' USING ERRCODE='23514'; END IF;
 checked_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row.reserve_deadline_ms:=least(owner_deadline_ms,row.setup_expires_ms,public.payload_profile_selection_owner(account,user_id,owner_session));
 IF row.reserve_deadline_ms<=checked_ms THEN RAISE EXCEPTION 'interval ordinary owner deadline expired' USING ERRCODE='23514'; END IF;
 INSERT INTO public.conversation_profile03_intervals SELECT(row).*;
 -- Only actual elapsed signed time closes a predecessor. It does not delete
 -- originals or cancel/relabel admitted messages, grants or attempts.
 UPDATE public.conversation_profile03_intervals r SET phase='expired',expired_ms=row.issued_ms,superseded_by_interval_id=row.interval_id
  WHERE r.account_id=account AND r.binding_id=row.binding_id AND r.device_session_digest=row.device_session_digest AND r.peer=row.peer
   AND r.interval_id<>row.interval_id AND r.phase IN('reserved','requested','install_pending','active')
   AND CASE WHEN r.phase='active' THEN r.interval_expires_ms ELSE least(r.setup_expires_ms,r.interval_expires_ms) END<=row.issued_ms;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_request(account uuid,opening uuid,"interval" uuid,owner_signature bytea,factor_deadline_ms bigint)
RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; checked public.conversation_profile03_intervals%ROWTYPE; checked_ms bigint; deadline bigint;
BEGIN
 IF account IS NULL OR opening IS NULL OR "interval" IS NULL OR owner_signature IS NULL OR octet_length(owner_signature)<>64 OR factor_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'interval owner request unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.interval_id="interval";
 IF NOT FOUND OR row.opening_id<>opening THEN RAISE EXCEPTION 'interval original owner opening differs' USING ERRCODE='23514'; END IF;
 IF row.owner_signature IS NOT NULL THEN
  IF row.owner_signature<>owner_signature THEN RAISE EXCEPTION 'interval owner request retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row; RETURN;
 END IF;
 row:=public.conversation_profile03_interval_lock(account,"interval");
 IF row.phase<>'reserved' OR row.opening_id<>opening THEN RAISE EXCEPTION 'interval original request closed' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_interval_scope(account,row.initiating_user_id,row.initiating_session_id,row.statement,true);
 checked_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 deadline:=least(factor_deadline_ms,row.setup_expires_ms,public.payload_profile_selection_owner(account,row.initiating_user_id,row.initiating_session_id));
 IF checked_ms>=deadline THEN RAISE EXCEPTION 'interval fresh request deadline expired' USING ERRCODE='23514'; END IF;
 UPDATE public.conversation_profile03_intervals r SET phase='requested',owner_signature=conversation_profile03_interval_request.owner_signature,
  requested_ms=checked_ms,request_deadline_ms=deadline WHERE r.account_id=account AND r.interval_id="interval" RETURNING r.* INTO row;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_approve(account uuid,"interval" uuid,signature bytea) RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; checked public.conversation_profile03_intervals%ROWTYPE;
BEGIN
 IF account IS NULL OR "interval" IS NULL OR signature IS NULL OR octet_length(signature)<>64 THEN RAISE EXCEPTION 'interval phone approval unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.interval_id="interval";
 IF NOT FOUND THEN RAISE EXCEPTION 'interval phone original unavailable' USING ERRCODE='23514'; END IF;
 IF row.phone_signature IS NOT NULL THEN
  IF row.phone_signature<>signature THEN RAISE EXCEPTION 'interval phone approval retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row; RETURN;
 END IF;
 row:=public.conversation_profile03_interval_lock(account,"interval");
 IF row.phase<>'requested' THEN RAISE EXCEPTION 'interval phone approval phase differs' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_interval_scope(account,row.initiating_user_id,row.initiating_session_id,row.statement,true);
 UPDATE public.conversation_profile03_intervals r SET phase='install_pending',phone_signature=signature,approved_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
  WHERE r.account_id=account AND r.interval_id="interval" RETURNING r.* INTO row;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_install(account uuid,"interval" uuid,signature bytea) RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; checked public.conversation_profile03_intervals%ROWTYPE;
BEGIN
 IF account IS NULL OR "interval" IS NULL OR signature IS NULL OR octet_length(signature)<>64 THEN RAISE EXCEPTION 'interval installation unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.interval_id="interval";
 IF NOT FOUND THEN RAISE EXCEPTION 'interval installation original unavailable' USING ERRCODE='23514'; END IF;
 IF row.installed_signature IS NOT NULL THEN
  IF row.installed_signature<>signature THEN RAISE EXCEPTION 'interval installation retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row; RETURN;
 END IF;
 row:=public.conversation_profile03_interval_lock(account,"interval");
 IF row.phase<>'install_pending' THEN RAISE EXCEPTION 'interval installation phase differs' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_interval_scope(account,row.initiating_user_id,row.initiating_session_id,row.statement,true);
 UPDATE public.conversation_profile03_intervals r SET phase='active',installed_signature=signature,installed_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
  WHERE r.account_id=account AND r.interval_id="interval" RETURNING r.* INTO row;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_stop(account uuid,"interval" uuid,user_id uuid,owner_session uuid) RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE;
BEGIN
 IF account IS NULL OR "interval" IS NULL OR user_id IS NULL OR owner_session IS NULL THEN RAISE EXCEPTION 'interval owner stop unavailable' USING ERRCODE='23514'; END IF;
 row:=public.conversation_profile03_interval_lock(account,"interval");
 IF row.initiating_user_id<>user_id THEN RAISE EXCEPTION 'interval stop original user differs' USING ERRCODE='23514'; END IF;
 PERFORM public.payload_profile_selection_owner(account,user_id,owner_session);
 IF row.phase IN('stopped','expired') THEN RETURN NEXT row; RETURN; END IF;
 UPDATE public.conversation_profile03_intervals r SET phase='stopped',stopped_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint,
  stop_actor_kind='owner',stopped_by_user_id=user_id,stopped_by_session_id=owner_session
  WHERE r.account_id=account AND r.interval_id="interval" RETURNING r.* INTO row;
 RETURN NEXT row;
END;
$function$;

-- Withdrawal authenticates the actual socket in Rust, independently of any
-- original owner permission. Actor connection never replaces the original lease.
CREATE FUNCTION public.conversation_profile03_interval_device_actor(account uuid,"interval" uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,statement_sha256 bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; original public.payload_profile_v2_activation_receipts%ROWTYPE; signer bytea; bytes bytea;
BEGIN
 row:=public.conversation_profile03_interval_lock(account,"interval");
 IF device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL OR statement_sha256 IS NULL
  OR row.device_id<>device OR row.statement_sha256<>statement_sha256 THEN RAISE EXCEPTION 'interval device withdrawal scope differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO original FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=row.original_binding_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval original device unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.sealed_manifest_authorities a JOIN public.phone_lines l ON l.account_id=a.account_id
  JOIN public.device_line_bindings b ON(b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation)
  WHERE a.account_id=account AND a.revoked_at IS NULL AND a.root_fingerprint=row.root_fingerprint
   AND l.id=row.line_id AND l.state='active' AND b.state='active' AND b.purpose='sealed' AND b.device_id=device AND b.generation=row.binding_generation
  FOR SHARE OF a,l,b NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval device withdrawal current binding unavailable' USING ERRCODE='23514'; END IF;
 SELECT k.signing_key_sec1 INTO signer FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
  WHERE s.account_id=account AND s.device_id=device AND s.site_id=site AND s.instance_id=instance AND s.connection_epoch=conversation_profile03_interval_device_actor.connection_epoch
   AND s.deployment_epoch=conversation_profile03_interval_device_actor.deployment_epoch AND s.line_activation_version=2 AND s.lease_until>clock_timestamp()
   AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND k.signing_key_sec1=original.device_point AND k.fingerprint=sha256(original.device_point)
   AND t.enabled AND NOT t.draining AND a.epoch=s.deployment_epoch FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval actual withdrawal connection unavailable' USING ERRCODE='23514'; END IF;
 bytes:=uuid_send(account)||uuid_send(device)||int4send(octet_length(site))||convert_to(site,'UTF8')||int4send(octet_length(instance))||convert_to(instance,'UTF8')
  ||int8send(connection_epoch)||int8send(deployment_epoch)||int2send(2::smallint)||sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||signer);
 RETURN sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device-session/v1',bytes));
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_device_stop(account uuid,"interval" uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,statement_sha256 bytea)
RETURNS SETOF public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; digest bytea;
BEGIN
 digest:=public.conversation_profile03_interval_device_actor(account,"interval",device,site,instance,connection_epoch,deployment_epoch,statement_sha256);
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=account AND r.interval_id="interval";
 IF row.phase IN('stopped','expired') THEN RETURN NEXT row; RETURN; END IF;
 UPDATE public.conversation_profile03_intervals r SET phase='stopped',stopped_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint,
  stop_actor_kind='device',stopped_by_device_id=device,stopped_by_site_id=site,stopped_by_instance_id=instance,
  stopped_by_connection_epoch=conversation_profile03_interval_device_stop.connection_epoch,
  stopped_by_deployment_epoch=conversation_profile03_interval_device_stop.deployment_epoch,stopped_by_device_session_digest=digest
  WHERE r.account_id=account AND r.interval_id="interval" RETURNING r.* INTO row;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_parse(statement bytea) RETURNS public.conversation_profile03_intervals
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; i integer; peer_length integer; count integer;
 connector uuid; grant_id uuid; key_id bytea; previous bytea; connectors uuid[]:='{}'; grants uuid[]:='{}';
BEGIN
 IF octet_length(statement) NOT BETWEEN 695 AND 1092 OR substring(statement FROM 1 FOR 8)<>decode('5a54434103030300','hex')
  OR substring(statement FROM 633 FOR 26)<>decode('19','hex')||convert_to('conversation-content03-v1','UTF8')
  OR substring(statement FROM 659 FOR 32)<>sha256(convert_to('With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately.','UTF8')) THEN
  RAISE EXCEPTION 'interval canonical disclosure shape differs' USING ERRCODE='23514'; END IF;
 row.account_id:=public.payload_profile_election_uuid(substring(statement FROM 9 FOR 16));
 row.device_id:=public.payload_profile_election_uuid(substring(statement FROM 25 FOR 16)); row.line_id:=public.payload_profile_election_uuid(substring(statement FROM 41 FOR 16));
 row.binding_id:=public.payload_profile_election_uuid(substring(statement FROM 57 FOR 16)); row.interval_id:=public.payload_profile_election_uuid(substring(statement FROM 73 FOR 16));
 row.receipt_id:=public.payload_profile_election_uuid(substring(statement FROM 89 FOR 16)); row.initiating_user_id:=public.payload_profile_election_uuid(substring(statement FROM 105 FOR 16));
 row.initiating_session_id:=public.payload_profile_election_uuid(substring(statement FROM 121 FOR 16)); row.opening_id:=public.payload_profile_election_uuid(substring(statement FROM 137 FOR 16));
 row.binding_generation:=public.payload_profile_election_number(substring(statement FROM 153 FOR 8)); row.vault_generation:=public.payload_profile_election_number(substring(statement FROM 161 FOR 8));
 row.manifest_version:=public.payload_profile_election_number(substring(statement FROM 169 FOR 8)); row.selection_epoch:=public.payload_profile_election_number(substring(statement FROM 177 FOR 8));
 row.issued_ms:=public.payload_profile_election_number(substring(statement FROM 185 FOR 8)); row.setup_expires_ms:=public.payload_profile_election_number(substring(statement FROM 193 FOR 8));
 row.interval_starts_ms:=public.payload_profile_election_number(substring(statement FROM 201 FOR 8)); row.interval_expires_ms:=public.payload_profile_election_number(substring(statement FROM 209 FOR 8));
 row.selected_reader_key_id:=substring(statement FROM 217 FOR 32); row.archive_reader_key_id:=substring(statement FROM 249 FOR 32);
 row.phone_signer_key_id:=substring(statement FROM 281 FOR 32); row.browser_signer_key_id:=substring(statement FROM 313 FOR 32);
 row.root_fingerprint:=substring(statement FROM 345 FOR 32); row.manifest_digest:=substring(statement FROM 377 FOR 32);
 row.election_commitment:=substring(statement FROM 409 FOR 32); row.election_bundle_sha256:=substring(statement FROM 441 FOR 32);
 row.owner_session_digest:=substring(statement FROM 473 FOR 32); row.configured_origin_digest:=substring(statement FROM 505 FOR 32);
 row.device_session_digest:=substring(statement FROM 537 FOR 32); row.physical_selection_digest:=substring(statement FROM 569 FOR 32); row.nonce:=substring(statement FROM 601 FOR 32);
 FOR i IN 0..12 LOOP
  IF substring(statement FROM 217+32*i FOR 32)=decode(repeat('00',32),'hex') THEN RAISE EXCEPTION 'interval zero digest' USING ERRCODE='23514'; END IF;
 END LOOP;
 peer_length:=get_byte(statement,690);
 IF peer_length NOT BETWEEN 3 AND 16 OR octet_length(statement)<692+peer_length THEN RAISE EXCEPTION 'interval peer length differs' USING ERRCODE='23514'; END IF;
 row.peer:=convert_from(substring(statement FROM 692 FOR peer_length),'UTF8'); count:=get_byte(statement,691+peer_length);
 IF row.peer !~ '^\+[1-9][0-9]{1,14}$' OR count NOT BETWEEN 0 AND 6 OR octet_length(statement)<>692+peer_length+64*count THEN
  RAISE EXCEPTION 'interval peer or reader mapping shape differs' USING ERRCODE='23514'; END IF;
 row.integration_readers:=substring(statement FROM 693+peer_length);
 IF count>0 THEN FOR i IN 0..count-1 LOOP
  connector:=public.payload_profile_election_uuid(substring(row.integration_readers FROM 1+64*i FOR 16));
  grant_id:=public.payload_profile_election_uuid(substring(row.integration_readers FROM 17+64*i FOR 16)); key_id:=substring(row.integration_readers FROM 33+64*i FOR 32);
  IF connector=ANY(connectors) OR grant_id=ANY(grants) OR key_id=decode(repeat('00',32),'hex') OR(previous IS NOT NULL AND key_id<=previous) THEN
   RAISE EXCEPTION 'interval reader mapping duplicate or order differs' USING ERRCODE='23514'; END IF;
  connectors:=array_append(connectors,connector); grants:=array_append(grants,grant_id); previous:=key_id;
 END LOOP; END IF;
 IF row.binding_generation<=0 OR row.vault_generation<>1 OR row.selection_epoch<>1 OR row.manifest_version<=0
  OR row.issued_ms<=0 OR row.interval_starts_ms<>row.issued_ms OR row.setup_expires_ms-row.issued_ms NOT BETWEEN 1 AND 300000
  OR row.interval_expires_ms-row.issued_ms NOT BETWEEN 1 AND 86400000 OR row.opening_id=row.interval_id OR row.opening_id=row.receipt_id OR row.interval_id=row.receipt_id THEN
  RAISE EXCEPTION 'interval canonical identity or window differs' USING ERRCODE='23514'; END IF;
 row.statement:=statement; row.statement_sha256:=sha256(statement); row.phase:='reserved'; RETURN row;
END;
$function$;

-- Actual retained original proof plus present structural selections. The Rust
-- adapter separately verifies signatures, genuine owner/factor and opaque custody.
CREATE FUNCTION public.conversation_profile03_interval_scope(account uuid,user_id uuid,owner_session uuid,statement bytea,require_setup boolean)
RETURNS public.conversation_profile03_intervals
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; authority public.sealed_manifest_authorities%ROWTYPE;
 election public.payload_profile_elections%ROWTYPE; original public.payload_profile_v2_activation_receipts%ROWTYPE;
 refresh public.payload_profile_selection_receipts%ROWTYPE; session public.device_sessions%ROWTYPE;
 state text; epoch bigint; checked_ms bigint; deadline bigint; lease_until bigint; owner_until bigint; bytes bytea; evidence bytea;
 i integer; mapping bytea; connector public.connector_registrations%ROWTYPE; key public.connector_keys%ROWTYPE; grant_row public.connector_grants%ROWTYPE;
BEGIN
 IF account IS NULL OR user_id IS NULL OR owner_session IS NULL OR statement IS NULL OR require_setup IS NULL OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'interval current input unavailable' USING ERRCODE='23514'; END IF;
 row:=public.conversation_profile03_interval_parse(statement);
 IF(row.account_id,row.initiating_user_id,row.initiating_session_id) IS DISTINCT FROM(account,user_id,owner_session) THEN
  RAISE EXCEPTION 'interval actual owner differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO authority FROM public.sealed_manifest_authorities a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR authority.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'interval authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'interval account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN RAISE EXCEPTION 'interval anchor unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO election FROM public.payload_profile_elections e WHERE e.account_id=account AND e.new_binding_id=row.binding_id;
 IF NOT FOUND OR(election.device_id,election.line_id,election.new_binding_generation,election.selected_reader_key_id,election.election_commitment,election.election_bundle_sha256,election.root_fingerprint)
  IS DISTINCT FROM(row.device_id,row.line_id,row.binding_generation,row.selected_reader_key_id,row.election_commitment,row.election_bundle_sha256,row.root_fingerprint) THEN
  RAISE EXCEPTION 'interval accepted election differs' USING ERRCODE='23514'; END IF;
 row.election_challenge_id:=election.challenge_id; row.original_binding_id:=election.old_binding_id;
 owner_until:=public.payload_profile_manifest_context(account,user_id,owner_session,election.challenge_id,row.binding_id,row.device_id,row.line_id);
 checked_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF row.issued_ms>checked_ms OR row.interval_expires_ms<=checked_ms OR(require_setup AND row.setup_expires_ms<=checked_ms)
  OR authority.generation<>1 OR authority.anchor_digest<>decode(repeat('00',32),'hex') OR authority.version<>row.manifest_version
  OR authority.semantic_digest<>row.manifest_digest OR authority.root_fingerprint<>row.root_fingerprint
  OR sha256(substring(authority.manifest FROM 1 FOR octet_length(authority.manifest)-64))<>row.manifest_digest
  OR NOT public.payload_profile_manifest_ancestry(account,election.challenge_id,authority.version,authority.semantic_digest,authority.manifest,authority.accepted_at_ms)
  OR authority.last_verified_ms<authority.accepted_at_ms OR authority.last_verified_ms>checked_ms OR row.issued_ms<authority.accepted_at_ms
  OR row.owner_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/owner-session/v1',uuid_send(account)||uuid_send(user_id)||uuid_send(owner_session))) THEN
  RAISE EXCEPTION 'interval current manifest or owner selection differs' USING ERRCODE='23514'; END IF;
 row.signed_manifest:=authority.manifest; row.signed_manifest_sha256:=sha256(authority.manifest); row.root_pin:=authority.root_pin;
 deadline:=least(owner_until,public.payload_profile_election_number(substring(authority.manifest FROM 48 FOR 8)));
 deadline:=least(deadline,public.conversation_profile03_key_until(authority.manifest,1,row.selected_reader_key_id,row.device_id,row.line_id,checked_ms),
  public.conversation_profile03_key_until(authority.manifest,2,row.archive_reader_key_id,row.device_id,row.line_id,checked_ms),
  public.conversation_profile03_key_until(authority.manifest,4,row.phone_signer_key_id,row.device_id,row.line_id,checked_ms),
  public.conversation_profile03_key_until(authority.manifest,5,row.browser_signer_key_id,row.device_id,row.line_id,checked_ms));
 SELECT * INTO original FROM public.payload_profile_v2_activation_receipts r WHERE r.account_id=account AND r.binding_id=election.old_binding_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval original activation unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.line_activation_v2_pending p WHERE p.account_id=account AND p.challenge_id=original.challenge_id
  AND p.protocol_version=2 AND p.purpose='sealed' AND p.registration_id=original.registration_id AND p.installed_at IS NOT NULL AND p.nonce IS NULL AND p.retired_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'interval original installation unavailable' USING ERRCODE='23514'; END IF;
 SELECT s.* INTO session FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
  WHERE s.account_id=account AND s.device_id=row.device_id AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.signing_key_sec1=original.device_point AND k.fingerprint=sha256(original.device_point) AND s.line_activation_version=2
   AND s.lease_until>clock_timestamp() AND a.epoch=s.deployment_epoch AND t.enabled AND NOT t.draining FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND OR octet_length(session.site_id) NOT BETWEEN 1 AND 256 OR octet_length(session.instance_id) NOT BETWEEN 1 AND 256 THEN
  RAISE EXCEPTION 'interval actual device connection unavailable' USING ERRCODE='23514'; END IF;
 row.proof_site_id:=session.site_id; row.proof_instance_id:=session.instance_id; row.proof_connection_epoch:=session.connection_epoch; row.proof_deployment_epoch:=session.deployment_epoch;
 bytes:=uuid_send(account)||uuid_send(row.device_id)||int4send(octet_length(session.site_id))||convert_to(session.site_id,'UTF8')||int4send(octet_length(session.instance_id))||convert_to(session.instance_id,'UTF8')
  ||int8send(session.connection_epoch)||int8send(session.deployment_epoch)||int2send(2::smallint)||sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original.device_point);
 IF row.device_session_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device-session/v1',bytes)) THEN
  RAISE EXCEPTION 'interval full device connection differs' USING ERRCODE='23514'; END IF;
 lease_until:=floor(extract(epoch FROM session.lease_until)*1000)::bigint;
 SELECT * INTO refresh FROM public.payload_profile_selection_receipts r WHERE r.account_id=account AND r.binding_id=row.binding_id
  AND r.device_session_digest=row.device_session_digest AND r.installed_ms IS NOT NULL;
 IF FOUND THEN
  PERFORM 1 FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.refresh_id=refresh.refresh_id
   AND c.closed_unaccepted_ms IS NULL AND(c.device_id,c.line_id,c.binding_id,c.election_challenge_id,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch)
    =(row.device_id,row.line_id,row.binding_id,election.challenge_id,session.site_id,session.instance_id,session.connection_epoch,session.deployment_epoch)
   AND public.payload_profile_manifest_ancestry(account,election.challenge_id,c.manifest_version,c.manifest_digest,c.signed_manifest,c.manifest_accepted_ms);
  IF NOT FOUND OR refresh.installed_ms<refresh.accepted_ms OR refresh.installed_ms>checked_ms OR refresh.bundle_sha256<>sha256(refresh.bundle) THEN
   RAISE EXCEPTION 'interval retained physical refresh differs' USING ERRCODE='23514'; END IF;
  row.physical_source_kind:='owner_refresh03'; row.physical_refresh_id:=refresh.refresh_id;
  bytes:=decode('02','hex')||uuid_send(account)||uuid_send(row.device_id)||uuid_send(row.line_id)||uuid_send(row.binding_id)||row.election_commitment||row.device_session_digest
   ||uuid_send(refresh.refresh_id)||sha256(refresh.bundle)||int8send(refresh.accepted_ms)||int8send(refresh.installed_ms);
 ELSE
  IF(original.proof_site_id,original.proof_instance_id,original.proof_connection_epoch,original.proof_deployment_epoch)
   IS DISTINCT FROM(session.site_id,session.instance_id,session.connection_epoch,session.deployment_epoch)
   OR EXISTS(SELECT FROM public.payload_profile_selection_challenges c WHERE c.account_id=account AND c.binding_id=row.binding_id AND c.device_session_digest=row.device_session_digest AND c.device_signature IS NOT NULL) THEN
   RAISE EXCEPTION 'interval original physical fallback fenced' USING ERRCODE='23514'; END IF;
  row.physical_source_kind:='original_v2';
  bytes:=uuid_send(original.registration_id)||uuid_send(original.binding_id)||original.device_point||original.owner_point||original.device_statement
   ||int2send(octet_length(original.device_signature_der)::smallint)||original.device_signature_der||original.owner_statement
   ||int2send(octet_length(original.owner_signature_der)::smallint)||original.owner_signature_der||int8send(original.accepted_ms);
  evidence:=public.payload_profile_election_frame('ZTSE/line/payload-profile/activation-evidence/v1',bytes);
  bytes:=decode('01','hex')||uuid_send(account)||uuid_send(row.device_id)||uuid_send(row.line_id)||uuid_send(row.binding_id)||row.election_commitment||row.device_session_digest||uuid_send(original.binding_id)||sha256(evidence);
 END IF;
 IF row.physical_selection_digest<>sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/physical-selection/v1',bytes)) THEN
  RAISE EXCEPTION 'interval original physical commitment differs' USING ERRCODE='23514'; END IF;
 IF octet_length(row.integration_readers)>0 THEN FOR i IN 0..octet_length(row.integration_readers)/64-1 LOOP
  mapping:=substring(row.integration_readers FROM 1+64*i FOR 64);
  SELECT * INTO connector FROM public.connector_registrations c WHERE c.account_id=account AND c.connector_id=public.payload_profile_election_uuid(substring(mapping FROM 1 FOR 16)) FOR SHARE NOWAIT;
  IF NOT FOUND OR connector.state<>'active' OR connector.revoked_ms IS NOT NULL OR connector.manifest_generation<>1 OR connector.key_id<>substring(mapping FROM 33 FOR 32)
   OR connector.approved_ms IS NULL OR connector.approved_ms>checked_ms OR connector.expires_ms<=checked_ms THEN RAISE EXCEPTION 'interval connector registration unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO key FROM public.connector_keys k WHERE k.account_id=account AND k.connector_id=connector.connector_id AND k.key_id=connector.key_id FOR SHARE NOWAIT;
  IF NOT FOUND OR key.key_point<>connector.key_point OR key.retired_ms IS NOT NULL OR key.valid_from_ms>checked_ms OR key.valid_until_ms<=checked_ms THEN
   RAISE EXCEPTION 'interval connector key unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO grant_row FROM public.connector_grants g WHERE g.account_id=account AND g.connector_id=connector.connector_id AND g.grant_id=public.payload_profile_election_uuid(substring(mapping FROM 17 FOR 16)) FOR SHARE NOWAIT;
  IF NOT FOUND OR grant_row.kind<>'read' OR grant_row.read_directions<>12 OR grant_row.line_id<>row.line_id OR grant_row.revoked_ms IS NOT NULL
   OR grant_row.created_ms>checked_ms OR grant_row.expires_ms<=checked_ms OR(cardinality(grant_row.conversation_restriction)>0 AND NOT row.interval_id=ANY(grant_row.conversation_restriction)) THEN
   RAISE EXCEPTION 'interval connector read grant unavailable' USING ERRCODE='23514'; END IF;
  deadline:=least(deadline,connector.expires_ms,key.valid_until_ms,grant_row.expires_ms,
   public.conversation_profile03_key_until(authority.manifest,3,key.key_id,row.device_id,row.line_id,checked_ms));
  IF NOT EXISTS(SELECT FROM generate_series(0,get_byte(authority.manifest,152)-1) n WHERE substring(authority.manifest FROM 155+149*n FOR 32)=key.key_id
   AND substring(authority.manifest FROM 187+149*n FOR 65)=key.key_point) THEN RAISE EXCEPTION 'interval connector manifest point differs' USING ERRCODE='23514'; END IF;
 END LOOP; END IF;
 IF row.interval_expires_ms>deadline OR row.setup_expires_ms>lease_until OR floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=least(row.interval_expires_ms,lease_until,CASE WHEN require_setup THEN row.setup_expires_ms ELSE row.interval_expires_ms END) THEN
  RAISE EXCEPTION 'interval actual permission bound expired' USING ERRCODE='23514'; END IF;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.conversation_profile03_intervals%ROWTYPE; target public.conversation_profile03_intervals%ROWTYPE;
 wanted uuid; state text; epoch bigint; now_ms bigint; digest bytea;
 mutable text[]:=ARRAY['phase','owner_signature','phone_signature','installed_signature','requested_ms','request_deadline_ms','approved_ms','installed_ms','stopped_ms','stopped_by_user_id','stopped_by_session_id','expired_ms','superseded_by_interval_id','stop_actor_kind','stopped_by_device_id','stopped_by_site_id','stopped_by_instance_id','stopped_by_connection_epoch','stopped_by_deployment_epoch','stopped_by_device_session_digest'];
BEGIN
 IF TG_RELID<>'public.conversation_profile03_intervals'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'unexpected interval writer context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN wanted:=OLD.account_id; ELSE wanted:=NEW.account_id; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN RAISE EXCEPTION 'interval erasure fence busy' USING ERRCODE='55P03'; END IF;
  PERFORM 1 FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted AND a.state IN('live','deleted') FOR SHARE NOWAIT;
  IF NOT FOUND OR EXISTS(SELECT FROM public.accounts WHERE id=wanted) THEN RAISE EXCEPTION 'interval original retained until account erasure' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 -- Authority first, then exclusive account fence and actual stable anchor.
 PERFORM 1 FROM public.sealed_manifest_authorities a WHERE a.account_id=wanted FOR UPDATE NOWAIT;
 IF NOT FOUND OR pg_is_in_recovery() THEN RAISE EXCEPTION 'interval primary authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(wanted)) THEN RAISE EXCEPTION 'interval writer busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(wanted,epoch) THEN RAISE EXCEPTION 'interval actual accepted epoch unavailable' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_OP='INSERT' THEN
  checked:=public.conversation_profile03_interval_scope(wanted,NEW.initiating_user_id,NEW.initiating_session_id,NEW.statement,true);
  IF(to_jsonb(NEW)-mutable-'reserve_deadline_ms') IS DISTINCT FROM(to_jsonb(checked)-mutable-'reserve_deadline_ms')
   OR NEW.phase<>'reserved' OR NEW.owner_signature IS NOT NULL OR NEW.phone_signature IS NOT NULL OR NEW.installed_signature IS NOT NULL
   OR NEW.stopped_ms IS NOT NULL OR NEW.expired_ms IS NOT NULL OR NEW.reserve_deadline_ms<=now_ms
   OR NEW.reserve_deadline_ms>least(NEW.setup_expires_ms,public.payload_profile_selection_owner(wanted,NEW.initiating_user_id,NEW.initiating_session_id)) THEN
   RAISE EXCEPTION 'interval reservation row differs' USING ERRCODE='23514'; END IF;
  IF(SELECT count(*) FROM public.conversation_profile03_intervals r WHERE r.account_id=wanted AND r.binding_id=NEW.binding_id AND r.device_session_digest=NEW.device_session_digest AND r.peer=NEW.peer
    AND r.phase IN('reserved','requested','install_pending','active') AND CASE WHEN r.phase='active' THEN r.interval_expires_ms ELSE least(r.setup_expires_ms,r.interval_expires_ms) END>now_ms)>=16
   OR(SELECT count(*) FROM public.conversation_profile03_intervals r WHERE r.account_id=wanted AND r.line_id=NEW.line_id AND r.binding_id=NEW.binding_id AND r.peer=NEW.peer AND r.issued_ms>now_ms-86400000)>=16 THEN
   RAISE EXCEPTION 'interval allocation budget exhausted' USING ERRCODE='23514'; END IF;
 ELSE
  IF TG_OP<>'UPDATE' OR(to_jsonb(NEW)-mutable) IS DISTINCT FROM(to_jsonb(OLD)-mutable) THEN RAISE EXCEPTION 'interval original identity immutable' USING ERRCODE='23514'; END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF OLD.phase IN('stopped','expired') THEN RAISE EXCEPTION 'interval terminal history immutable' USING ERRCODE='23514'; END IF;
  IF NEW.phase='stopped' THEN
   IF(to_jsonb(NEW)-ARRAY['phase','stopped_ms','stopped_by_user_id','stopped_by_session_id','stop_actor_kind','stopped_by_device_id','stopped_by_site_id','stopped_by_instance_id','stopped_by_connection_epoch','stopped_by_deployment_epoch','stopped_by_device_session_digest'])
    IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['phase','stopped_ms','stopped_by_user_id','stopped_by_session_id','stop_actor_kind','stopped_by_device_id','stopped_by_site_id','stopped_by_instance_id','stopped_by_connection_epoch','stopped_by_deployment_epoch','stopped_by_device_session_digest'])
    OR NEW.stopped_ms<OLD.issued_ms OR NEW.stopped_ms>now_ms THEN RAISE EXCEPTION 'interval stop rewrites originals' USING ERRCODE='23514'; END IF;
   IF NEW.stop_actor_kind='owner' THEN
    IF NEW.stopped_by_user_id IS DISTINCT FROM OLD.initiating_user_id THEN RAISE EXCEPTION 'interval stop original user differs' USING ERRCODE='23514'; END IF;
    PERFORM public.payload_profile_selection_owner(wanted,NEW.stopped_by_user_id,NEW.stopped_by_session_id);
   ELSIF NEW.stop_actor_kind='device' THEN
    digest:=public.conversation_profile03_interval_device_actor(wanted,OLD.interval_id,NEW.stopped_by_device_id,NEW.stopped_by_site_id,NEW.stopped_by_instance_id,NEW.stopped_by_connection_epoch,NEW.stopped_by_deployment_epoch,OLD.statement_sha256);
    IF digest IS DISTINCT FROM NEW.stopped_by_device_session_digest THEN RAISE EXCEPTION 'interval actual stop connection differs' USING ERRCODE='23514'; END IF;
   ELSE RAISE EXCEPTION 'interval stop actor unavailable' USING ERRCODE='23514'; END IF;
  ELSIF NEW.phase='expired' THEN
   IF(to_jsonb(NEW)-ARRAY['phase','expired_ms','superseded_by_interval_id']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['phase','expired_ms','superseded_by_interval_id'])
    OR NEW.expired_ms>now_ms OR(CASE WHEN OLD.phase='active' THEN OLD.interval_expires_ms ELSE least(OLD.setup_expires_ms,OLD.interval_expires_ms) END)>NEW.expired_ms THEN
    RAISE EXCEPTION 'interval closure lacks actual elapsed time' USING ERRCODE='23514'; END IF;
   SELECT * INTO target FROM public.conversation_profile03_intervals r WHERE r.account_id=wanted AND r.interval_id=NEW.superseded_by_interval_id;
   IF NOT FOUND OR target.interval_id=OLD.interval_id OR(target.binding_id,target.device_session_digest,target.peer) IS DISTINCT FROM(OLD.binding_id,OLD.device_session_digest,OLD.peer)
    OR target.phase<>'reserved' OR target.issued_ms<>NEW.expired_ms OR target.issued_ms<=OLD.issued_ms OR target.reserve_deadline_ms<=now_ms THEN
    RAISE EXCEPTION 'interval closure requires fresh exact-scope opening' USING ERRCODE='23514'; END IF;
   checked:=public.conversation_profile03_interval_scope(wanted,target.initiating_user_id,target.initiating_session_id,target.statement,true);
  ELSE
   checked:=public.conversation_profile03_interval_scope(wanted,OLD.initiating_user_id,OLD.initiating_session_id,OLD.statement,true);
   IF(to_jsonb(NEW)-mutable-'reserve_deadline_ms') IS DISTINCT FROM(to_jsonb(checked)-mutable-'reserve_deadline_ms') THEN
    RAISE EXCEPTION 'interval current original scope differs' USING ERRCODE='23514'; END IF;
   IF OLD.phase='reserved' AND NEW.phase='requested' THEN
    IF(to_jsonb(NEW)-ARRAY['phase','owner_signature','requested_ms','request_deadline_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['phase','owner_signature','requested_ms','request_deadline_ms'])
     OR NEW.owner_signature IS NULL OR NEW.requested_ms<OLD.issued_ms OR NEW.requested_ms>now_ms OR NEW.request_deadline_ms<=now_ms
     OR NEW.request_deadline_ms>least(OLD.setup_expires_ms,public.payload_profile_selection_owner(wanted,OLD.initiating_user_id,OLD.initiating_session_id))
     OR EXISTS(SELECT FROM public.conversation_profile03_intervals r WHERE r.account_id=wanted AND r.interval_id<>OLD.interval_id AND r.binding_id=OLD.binding_id AND r.device_session_digest=OLD.device_session_digest AND r.peer=OLD.peer
       AND r.phase IN('requested','install_pending','active')) THEN
     RAISE EXCEPTION 'interval request is not fresh unique original approval' USING ERRCODE='23514'; END IF;
   ELSIF OLD.phase='requested' AND NEW.phase='install_pending' THEN
    IF(to_jsonb(NEW)-ARRAY['phase','phone_signature','approved_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['phase','phone_signature','approved_ms'])
     OR NEW.phone_signature IS NULL OR NEW.approved_ms<OLD.requested_ms OR NEW.approved_ms>now_ms THEN RAISE EXCEPTION 'interval phone proof is not one-time original' USING ERRCODE='23514'; END IF;
   ELSIF OLD.phase='install_pending' AND NEW.phase='active' THEN
    IF(to_jsonb(NEW)-ARRAY['phase','installed_signature','installed_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['phase','installed_signature','installed_ms'])
     OR NEW.installed_signature IS NULL OR NEW.installed_ms<OLD.approved_ms OR NEW.installed_ms>now_ms THEN RAISE EXCEPTION 'interval installed ACK is not original' USING ERRCODE='23514'; END IF;
   ELSE RAISE EXCEPTION 'unsupported interval phase transition' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 -- Actual unchanged-epoch tuple version defeats stale RR/SSI snapshots.
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=wanted;
 RETURN NEW;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_interval_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_intervals%ROWTYPE; target public.conversation_profile03_intervals%ROWTYPE;
 checked public.conversation_profile03_intervals%ROWTYPE; deadline bigint; digest bytea; now_ms bigint;
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NULL; END IF;
 SELECT * INTO row FROM public.conversation_profile03_intervals r WHERE r.account_id=NEW.account_id AND r.interval_id=NEW.interval_id;
 IF NOT FOUND THEN
  IF EXISTS(SELECT FROM public.accounts WHERE id=NEW.account_id) THEN RAISE EXCEPTION 'interval original disappeared' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF row.phase='stopped' THEN
  IF row.stop_actor_kind='owner' THEN PERFORM public.payload_profile_selection_owner(row.account_id,row.stopped_by_user_id,row.stopped_by_session_id);
  ELSE digest:=public.conversation_profile03_interval_device_actor(row.account_id,row.interval_id,row.stopped_by_device_id,row.stopped_by_site_id,row.stopped_by_instance_id,row.stopped_by_connection_epoch,row.stopped_by_deployment_epoch,row.statement_sha256);
   IF digest IS DISTINCT FROM row.stopped_by_device_session_digest THEN RAISE EXCEPTION 'interval stop actor changed before commit' USING ERRCODE='23514'; END IF;
  END IF;
  IF row.stopped_ms>now_ms THEN RAISE EXCEPTION 'interval stop clock regressed before commit' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 ELSIF row.phase='expired' THEN
  SELECT * INTO target FROM public.conversation_profile03_intervals r WHERE r.account_id=row.account_id AND r.interval_id=row.superseded_by_interval_id;
  IF NOT FOUND OR target.issued_ms<>row.expired_ms OR target.issued_ms<=row.issued_ms OR target.phase IN('stopped','expired')
   OR(target.binding_id,target.device_session_digest,target.peer) IS DISTINCT FROM(row.binding_id,row.device_session_digest,row.peer) THEN
   RAISE EXCEPTION 'interval permanent closure target changed before commit' USING ERRCODE='23514'; END IF;
  checked:=public.conversation_profile03_interval_scope(target.account_id,target.initiating_user_id,target.initiating_session_id,target.statement,true);
  deadline:=target.reserve_deadline_ms;
 ELSE
  checked:=public.conversation_profile03_interval_scope(row.account_id,row.initiating_user_id,row.initiating_session_id,row.statement,true);
  deadline:=least(row.setup_expires_ms,row.interval_expires_ms);
  IF TG_OP='INSERT' THEN deadline:=least(deadline,row.reserve_deadline_ms); END IF;
  IF TG_OP='UPDATE' AND OLD.owner_signature IS NULL AND NEW.owner_signature IS NOT NULL THEN deadline:=least(deadline,row.request_deadline_ms); END IF;
 END IF;
 IF floor(extract(epoch FROM clock_timestamp())*1000)::bigint>=deadline THEN RAISE EXCEPTION 'interval original acceptance deadline passed after waits' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;
CREATE TRIGGER conversation_profile03_interval_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.conversation_profile03_intervals
 FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_interval_rows_guard();
CREATE CONSTRAINT TRIGGER conversation_profile03_interval_after_change AFTER INSERT OR UPDATE ON public.conversation_profile03_intervals
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_interval_complete();

CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=113 AND min(version)=1 AND max(version)=113 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=113 AND graph_sha256=public.payload_profile_writer_graph()
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
CREATE FUNCTION public.conversation_profile03_interval_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_manifest_ready()
  AND has_table_privilege(current_user,'public.conversation_profile03_intervals','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_profile03_interval_reserve','conversation_profile03_interval_request','conversation_profile03_interval_approve','conversation_profile03_interval_install','conversation_profile03_interval_stop','conversation_profile03_interval_device_stop','conversation_profile03_interval_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; columns_sql text;
BEGIN
 REVOKE ALL ON TABLE public.conversation_profile03_intervals FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_profile03_intervals'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_intervals FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_profile03_intervals FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_intervals FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_profile03_intervals TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_profile03_interval_reserve','conversation_profile03_interval_request','conversation_profile03_interval_approve','conversation_profile03_interval_install','conversation_profile03_interval_stop','conversation_profile03_interval_device_stop','conversation_profile03_interval_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=113);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,113,public.payload_profile_writer_graph());
