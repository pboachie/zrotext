-- SPDX-License-Identifier: AGPL-3.0-only
-- One-use03 grant provenance; authentication and all signatures stay independent.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=114; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN RAISE EXCEPTION 'grant03 requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(110,111,112,113,114) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113,114) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113,114) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113,114) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113,114) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113,114) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113,114) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE CASE WHEN writer_installation IN(112,113,114) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_profile03_key_until(bytea, integer, bytea, uuid, uuid, bigint)','ced7cf2fedbb37ff6e6e048eb872d494fa41c327e85b3d843d92e2e1878c1d32','bigint','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['manifest','role','key_id','device','line','checked_ms']::text[]),
            ('conversation_profile03_interval_lock(uuid, uuid)','2f8727e90a215b137d902b03b55dc8223cea7f5607bfbae9dd692ad9545a20b3','public.conversation_profile03_intervals','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval']::text[]),
            ('conversation_profile03_interval_reserve(uuid, uuid, uuid, uuid, uuid, uuid, bytea, bigint)','50382b10053c77d41d78e48584271028df3f838756fea805c37a99a968156a82','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','user_id','owner_session','interval','receipt','statement','owner_deadline_ms']::text[]),
            ('conversation_profile03_interval_request(uuid, uuid, uuid, bytea, bigint)','a1d616e3740df0030ff81e4e635c9435d9eac6a1e2402325c7234845268cf7f5','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','interval','owner_signature','factor_deadline_ms']::text[]),
            ('conversation_profile03_interval_approve(uuid, uuid, bytea)','c10425a6fdd4188f2f6426ddccc0ac56933334e9c7bd09125ccbc61c06b26d1d','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','signature']::text[]),
            ('conversation_profile03_interval_install(uuid, uuid, bytea)','97f0b45dc938f02aaf99729b224f5bd42413d9bb8913115acb63326839b30528','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','signature']::text[]),
            ('conversation_profile03_interval_stop(uuid, uuid, uuid, uuid)','7aafba98df9f757ff1cb4136ef93d91116a3b198b3caf5786de64b099addae5f','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','user_id','owner_session']::text[]),
            ('conversation_profile03_interval_device_actor(uuid, uuid, uuid, text, text, bigint, bigint, bytea)','9d21cbadd5d8149a59c11c0c9c6e59426f223826c9e439ea4f10bb8323fbe5e3','bytea','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','device','site','instance','connection_epoch','deployment_epoch','statement_sha256']::text[]),
            ('conversation_profile03_interval_device_stop(uuid, uuid, uuid, text, text, bigint, bigint, bytea)','2df3076183e093e8f5b4833aec58aeeb95e78f124cfa5adc03373e9fcd420f0c','public.conversation_profile03_intervals','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','device','site','instance','connection_epoch','deployment_epoch','statement_sha256']::text[]),
            ('conversation_profile03_interval_parse(bytea)','ca9e812876de99a76a83f747f869c0a9294f3023ba0f0a59c22c80710d0a29be','public.conversation_profile03_intervals','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['statement']::text[]),
            ('conversation_profile03_interval_scope(uuid, uuid, uuid, bytea, boolean)','42cad0d2667a194dacfe7a308afa55dab8ea927e47c04ca5610939522b059902','public.conversation_profile03_intervals','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','user_id','owner_session','statement','require_setup']::text[]),
            ('conversation_profile03_interval_rows_guard()','ca2175a65bd71f8c658f314309e8a00deab10ff5741bba56da2a7bebc917b0e1','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_interval_complete()','b34c1f395e5419f765a4479e78a15da131a0afebb1eb76771a7059cd0b5cc207','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','d2304db59ce15d94badb7e26f4a0e536a4551575b8b758db104fd4b4bdce1ab1','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'conversation03 helper declaration or body inconsistent'; END IF;
          END LOOP;
FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_reviewed_send03_parse(bytea)','f75324ab23e43721bf7fdbc107fa336f6b9b389033e552c083bfde2562105b7e','public.conversation_reviewed_sends03','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['intent']::text[]),
            ('conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03, bytea)','5b2d548fb73912d9bcfa86e7e1b9ca760c3b649e2ecd6a236e500d9bbd2a77cc','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['row','envelope']::text[]),
            ('conversation_reviewed_send03_scope(uuid, bytea, bytea, bigint, bigint)','82a31a37e6b99d29b97293f4303e0c189475ea744b67f3b5cd15f9b2051ab55d','public.conversation_reviewed_sends03','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','intent','signature','permission_deadline_ms','admitted_ms']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)','4f27879e1b1e350c79b0b8f661faefce941f6f1e4f852927fbe4b12ae06975a6','public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()','483fe860358ee38b2ff5cf293aedaf18c2cc17ee1cafeb6dac0b8c9aefd1735d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)','006527b20f97d56582b26d006f80771a10a3d6007a154a990d45899803cbbb5f','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()','013423fe961e7c3d396be0bc4db8b238c295f233862c57f64c002df208cddf7d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()','3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_reviewed_send03_ready()','d5bdd952112811191cc45684ce73c451d75983f3245ecedfccf229b6daae5850','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'reviewed03 helper declaration or body inconsistent'; END IF;
          END LOOP;
 IF NOT(SELECT count(*)=114 AND min(version)=1 AND max(version)=114 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=114 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'grant03 predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
  WHERE p.oid='public.alpha_message_effect_guard()'::regprocedure AND p.proowner=c.relowner AND p.prorettype='trigger'::regtype
   AND l.lanname='plpgsql' AND p.provolatile='v' AND NOT p.proisstrict AND NOT p.prosecdef AND NOT p.proretset
   AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL AND p.pronargs=0 AND p.pronargdefaults=0
   AND p.prokind='f' AND p.proparallel='u' AND p.proconfig=ARRAY['search_path=public']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') IN('687498a6c9f6e343dde1eef865cf757d3ada0ef97f1896fcee4a41b15ba1d827','736ffafc0250e6f2d32e99d8c2e2454037eda0fb1069ec11d1f47a4775c7e3c8')) THEN
  RAISE EXCEPTION 'grant03 exact predecessor effect guard unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

-- Nonpersonal one-attempt identity survives message erasure until account erasure.
CREATE TABLE public.conversation_profile03_grants (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 message_id uuid NOT NULL, attempt_id uuid NOT NULL, interval_id uuid NOT NULL, interval_receipt_id uuid NOT NULL,
 initiating_user_id uuid NOT NULL, initiating_session_id uuid NOT NULL, device_id uuid NOT NULL, line_id uuid NOT NULL,
 binding_id uuid NOT NULL, election_challenge_id uuid NOT NULL, original_binding_id uuid NOT NULL, physical_refresh_id uuid,
 binding_generation bigint NOT NULL CHECK(binding_generation>0), attempt_generation bigint NOT NULL CHECK(attempt_generation=1),
 connection_epoch bigint NOT NULL CHECK(connection_epoch>0), deployment_epoch bigint NOT NULL CHECK(deployment_epoch>0),
 trust_generation bigint NOT NULL CHECK(trust_generation=1), manifest_version bigint NOT NULL CHECK(manifest_version>0),
 selection_epoch bigint NOT NULL CHECK(selection_epoch=1), admitted_ms bigint NOT NULL CHECK(admitted_ms>0),
 issued_ms bigint NOT NULL CHECK(issued_ms>=admitted_ms), expires_at_ms bigint NOT NULL,
 authority_deadline_ms bigint NOT NULL CHECK(authority_deadline_ms>issued_ms),
 site_id text NOT NULL CHECK(octet_length(site_id) BETWEEN 1 AND 256), instance_id text NOT NULL CHECK(octet_length(instance_id) BETWEEN 1 AND 256),
 lease_owner text NOT NULL CHECK(lease_owner='profile03:'||attempt_id::text),
 physical_source_kind text NOT NULL CHECK(physical_source_kind IN('original_v2','owner_refresh03')),
 authenticated_segment_ceiling smallint NOT NULL CHECK(authenticated_segment_ceiling BETWEEN 1 AND 6),
 reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32), envelope_sha256 bytea NOT NULL CHECK(octet_length(envelope_sha256)=32),
 unsigned_sha256 bytea NOT NULL CHECK(octet_length(unsigned_sha256)=32), manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32), election_digest bytea NOT NULL CHECK(octet_length(election_digest)=32),
 election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32), owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32),
 configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32), device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32),
 physical_selection_digest bytea NOT NULL CHECK(octet_length(physical_selection_digest)=32), interval_statement_sha256 bytea NOT NULL CHECK(octet_length(interval_statement_sha256)=32),
 intent_sha256 bytea NOT NULL CHECK(octet_length(intent_sha256)=32), signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
 PRIMARY KEY(account_id,attempt_id), UNIQUE(attempt_id), UNIQUE(account_id,message_id),
 CHECK(expires_at_ms>issued_ms AND expires_at_ms<=authority_deadline_ms AND expires_at_ms-issued_ms<=30000),
 CHECK((physical_source_kind='original_v2')=(physical_refresh_id IS NULL))
);

-- Locks select a transaction mode, never an owner, socket or cryptographic proof.
CREATE FUNCTION public.conversation_profile03_grant_mode(account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE state text; epoch bigint;
BEGIN
 IF account IS NULL OR pg_is_in_recovery() OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'grant current transaction unsupported' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.sealed_manifest_authorities a WHERE a.account_id=account AND a.revoked_at IS NULL FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant authority unavailable' USING ERRCODE='23514'; END IF;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'grant account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'grant retained epoch unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts a WHERE a.id=account AND a.disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant account unavailable' USING ERRCODE='23514'; END IF;
END;
$function$;

-- Existing issued work must still be the sole complete granted attempt. This
-- reader creates no lease, clock, generation, retry or radio permission.
CREATE FUNCTION public.conversation_profile03_grant_issued(account uuid,attempt uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; checked public.conversation_profile03_grants%ROWTYPE;
 job public.dispatch_jobs%ROWTYPE; msg public.messages%ROWTYPE; execution public.message_attempts%ROWTYPE; fence public.dispatch_fences%ROWTYPE; now_ms bigint;
BEGIN
 PERFORM public.conversation_profile03_grant_mode(account);
 SELECT * INTO row FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.attempt_id=attempt;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant retained attempt unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_grant_scope(account,row.message_id,row.device_id,row.site_id,row.instance_id,row.connection_epoch,row.deployment_epoch);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT public.conversation_profile03_grant_same_scope(to_jsonb(row),to_jsonb(checked)) OR row.authority_deadline_ms>checked.authority_deadline_ms
  OR now_ms<row.issued_ms OR now_ms>=row.expires_at_ms THEN RAISE EXCEPTION 'grant exact issued permission expired or changed' USING ERRCODE='23514'; END IF;
 SELECT * INTO msg FROM public.messages m WHERE m.account_id=account AND m.id=row.message_id FOR SHARE NOWAIT;
 IF NOT FOUND OR msg.state<>'claimed' OR msg.state_version<>2 OR msg.updated_at<>to_timestamp(row.issued_ms::double precision/1000) THEN
  RAISE EXCEPTION 'grant actual claimed message differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO job FROM public.dispatch_jobs j WHERE j.account_id=account AND j.message_id=row.message_id FOR SHARE NOWAIT;
 IF NOT FOUND OR job.device_id<>row.device_id OR job.generation<>row.attempt_generation OR job.lease_owner IS DISTINCT FROM row.lease_owner
  OR job.lease_until IS DISTINCT FROM to_timestamp(row.expires_at_ms::double precision/1000)
  OR job.grant_issued_at IS DISTINCT FROM to_timestamp(row.issued_ms::double precision/1000) OR job.finished_at IS NOT NULL THEN
  RAISE EXCEPTION 'grant actual claim differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO execution FROM public.message_attempts a WHERE a.id=attempt FOR SHARE NOWAIT;
 IF NOT FOUND OR(execution.account_id,execution.message_id,execution.device_id,execution.generation,execution.session_epoch,execution.deployment_epoch,execution.status,
   execution.created_at,execution.updated_at) IS DISTINCT FROM(account,row.message_id,row.device_id,row.attempt_generation,row.connection_epoch,row.deployment_epoch,'granted'::text,
   to_timestamp(row.issued_ms::double precision/1000),to_timestamp(row.issued_ms::double precision/1000)) THEN
  RAISE EXCEPTION 'grant actual attempt differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO fence FROM public.dispatch_fences f WHERE f.account_id=account AND f.message_id=row.message_id FOR SHARE NOWAIT;
 IF NOT FOUND OR(fence.device_id,fence.attempt_id,fence.generation,fence.session_epoch,fence.deployment_epoch,fence.grant_expires_at,fence.outcome,fence.recipient_digest)
  IS DISTINCT FROM(row.device_id,attempt,row.attempt_generation,row.connection_epoch,row.deployment_epoch,to_timestamp(row.expires_at_ms::double precision/1000),'granted'::text,msg.recipient_digest) THEN
  RAISE EXCEPTION 'grant actual one-use fence differs' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<row.issued_ms OR now_ms>=least(row.expires_at_ms,row.authority_deadline_ms,checked.authority_deadline_ms) THEN
  RAISE EXCEPTION 'grant final primary deadline expired' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_grant_lock(account uuid,attempt uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint)
RETURNS SETOF public.conversation_profile03_grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE;
BEGIN
 IF attempt IS NULL OR device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL
  OR octet_length(site) NOT BETWEEN 1 AND 256 OR octet_length(instance) NOT BETWEEN 1 AND 256 OR connection_epoch<=0 OR deployment_epoch<=0 THEN
  RAISE EXCEPTION 'grant mode selector unavailable' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_grant_mode(account);
 SELECT * INTO row FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.attempt_id=attempt;
 -- A new Rust-CSPRNG attempt has no original owner to select. Only root,
 -- exclusive account, anchor and account-row mode locks have been acquired.
 IF NOT FOUND THEN RETURN; END IF;
 IF(row.device_id,row.site_id,row.instance_id,row.connection_epoch,row.deployment_epoch)
  IS DISTINCT FROM(device,site,instance,connection_epoch,deployment_epoch) THEN RAISE EXCEPTION 'grant actual socket differs' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_grant_issued(account,attempt);
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_grant_issue(account uuid,message uuid,attempt uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,permission_deadline_ms bigint)
RETURNS SETOF public.conversation_profile03_grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; previous public.conversation_profile03_grants%ROWTYPE;
 msg public.messages%ROWTYPE; job public.dispatch_jobs%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR message IS NULL OR attempt IS NULL OR device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL
  OR permission_deadline_ms IS NULL OR attempt='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION 'grant exact issue input unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM public.conversation_profile03_grants g WHERE g.account_id=account AND(g.message_id=message OR g.attempt_id=attempt);
 IF FOUND THEN
  IF(previous.message_id,previous.attempt_id,previous.device_id,previous.site_id,previous.instance_id,previous.connection_epoch,previous.deployment_epoch)
   IS DISTINCT FROM(message,attempt,device,site,instance,connection_epoch,deployment_epoch) THEN
   RAISE EXCEPTION 'grant one-attempt original differs' USING ERRCODE='23514'; END IF;
  -- Historical receipt only: no current permission, new work or renewal.
  RETURN NEXT previous;RETURN;
 END IF;
 PERFORM public.conversation_profile03_grant_mode(account);
 row:=public.conversation_profile03_grant_scope(account,message,device,site,instance,connection_epoch,deployment_epoch);
 SELECT * INTO msg FROM public.messages m WHERE m.account_id=account AND m.id=message FOR UPDATE NOWAIT;
 IF NOT FOUND OR msg.state<>'queued' OR msg.state_version<>1 THEN RAISE EXCEPTION 'grant initial message unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO job FROM public.dispatch_jobs j WHERE j.account_id=account AND j.message_id=message FOR UPDATE NOWAIT;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT FOUND OR job.device_id<>device OR job.generation<>0 OR job.lease_owner IS NOT NULL OR job.lease_until IS NOT NULL OR job.grant_issued_at IS NOT NULL
  OR job.finished_at IS NOT NULL OR job.next_attempt_at>clock_timestamp()
  OR EXISTS(SELECT FROM public.message_attempts a WHERE a.account_id=account AND a.message_id=message)
  OR EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.message_id=message)
  OR now_ms<row.issued_ms OR now_ms>=least(row.authority_deadline_ms,permission_deadline_ms) THEN
  RAISE EXCEPTION 'grant initial unleased job or deadline unavailable' USING ERRCODE='23514'; END IF;
 row.attempt_id:=attempt;row.attempt_generation:=1;row.lease_owner:='profile03:'||attempt::text;row.issued_ms:=now_ms;
 row.authority_deadline_ms:=least(row.authority_deadline_ms,permission_deadline_ms);row.expires_at_ms:=least(now_ms+30000,row.authority_deadline_ms);
 INSERT INTO public.conversation_profile03_grants SELECT(row).*;
 UPDATE public.messages m SET state='claimed',state_version=2,updated_at=to_timestamp(row.issued_ms::double precision/1000) WHERE m.account_id=account AND m.id=message;
 UPDATE public.dispatch_jobs j SET generation=1,lease_owner=row.lease_owner,lease_until=to_timestamp(row.expires_at_ms::double precision/1000),
  grant_issued_at=to_timestamp(row.issued_ms::double precision/1000) WHERE j.account_id=account AND j.message_id=message;
 INSERT INTO public.message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status,created_at,updated_at)
  VALUES(attempt,account,message,device,1,connection_epoch,deployment_epoch,'granted',to_timestamp(row.issued_ms::double precision/1000),to_timestamp(row.issued_ms::double precision/1000));
 INSERT INTO public.dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,recipient_digest,grant_expires_at,outcome)
  VALUES(message,account,device,attempt,1,connection_epoch,deployment_epoch,msg.recipient_digest,to_timestamp(row.expires_at_ms::double precision/1000),'granted');
 PERFORM public.conversation_profile03_grant_issued(account,attempt);
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_grant_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.conversation_profile03_grants%ROWTYPE; now_ms bigint; wanted uuid;
BEGIN
 IF TG_RELID<>'public.conversation_profile03_grants'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'unexpected grant receipt trigger context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  wanted:=OLD.account_id;
  IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted)) THEN RAISE EXCEPTION 'grant account erasure busy' USING ERRCODE='55P03'; END IF;
  PERFORM 1 FROM public.payload_profile_account_anchors a WHERE a.account_id=wanted AND a.state IN('live','deleted') FOR SHARE NOWAIT;
  IF NOT FOUND OR EXISTS(SELECT FROM public.accounts a WHERE a.id=wanted) THEN
   RAISE EXCEPTION 'grant original retained until account erasure' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'grant original immutable' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_grant_scope(NEW.account_id,NEW.message_id,NEW.device_id,NEW.site_id,NEW.instance_id,NEW.connection_epoch,NEW.deployment_epoch);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT public.conversation_profile03_grant_same_scope(to_jsonb(NEW),to_jsonb(checked)) OR NEW.attempt_generation<>1
  OR NEW.lease_owner<>'profile03:'||NEW.attempt_id::text OR NEW.authority_deadline_ms>checked.authority_deadline_ms
  OR NEW.issued_ms>now_ms OR NEW.issued_ms<NEW.admitted_ms OR now_ms>=NEW.expires_at_ms THEN
  RAISE EXCEPTION 'grant original current source differs' USING ERRCODE='23514'; END IF;
 -- A real tuple version closes stale RR/SSI snapshots after new grant authority.
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=NEW.account_id;
 RETURN NEW;
END;
$function$;
CREATE TRIGGER conversation_profile03_grant_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.conversation_profile03_grants
 FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_grant_rows_guard();

CREATE FUNCTION public.conversation_profile03_grant_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 IF TG_RELID<>'public.conversation_profile03_grants'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_NARGS<>0 OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'unexpected grant completion trigger context' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM public.accounts a WHERE a.id=NEW.account_id) THEN RETURN NULL; END IF;
 PERFORM public.conversation_profile03_grant_issued(NEW.account_id,NEW.attempt_id);
 RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER conversation_profile03_grant_after_change AFTER INSERT ON public.conversation_profile03_grants
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_grant_complete();

-- Read current payment permission for an ALREADY reserved unit. No new debit,
-- unused-capacity test, invoice reassignment or caller dispatch hint is accepted.
CREATE FUNCTION public.conversation_profile03_grant_billing(account uuid,message uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE namespace public.hosted_billing_namespaces%ROWTYPE; projection public.hosted_billing_projections%ROWTYPE;
 customer public.billing_customers%ROWTYPE; policy public.usage_quota_policies%ROWTYPE; subscription public.billing_subscriptions%ROWTYPE;
 original_reserve public.usage_ledger%ROWTYPE; period public.usage_periods%ROWTYPE;
 protected_units bigint; candidate_units bigint;
 now_ms bigint; backend_until bigint; deadline bigint:=9223372036854775807; bound boolean; recon_total bigint; recon_clean bigint;
BEGIN
 SELECT * INTO original_reserve FROM public.usage_ledger u WHERE u.account_id=account AND u.message_id=message
  AND u.metric='outbound_message' AND u.entry_kind='reserve' AND u.units=1 FOR SHARE NOWAIT;
 IF NOT FOUND OR EXISTS(SELECT FROM public.usage_ledger u WHERE u.account_id=account AND u.message_id=message AND u.entry_kind='refund') THEN
  RAISE EXCEPTION 'grant original reservation unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO period FROM public.usage_periods p WHERE(p.account_id,p.metric,p.period_start)=
  (original_reserve.account_id,original_reserve.metric,original_reserve.period_start) FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant original reservation period unavailable' USING ERRCODE='23514'; END IF;
 SELECT count(*) INTO protected_units FROM public.conversation_profile03_grants g JOIN public.usage_ledger u
  ON(u.account_id,u.message_id)=(g.account_id,g.message_id) WHERE u.account_id=account AND u.metric=period.metric
   AND u.period_start=period.period_start AND u.entry_kind='reserve' AND u.units=1;
 candidate_units:=CASE WHEN EXISTS(SELECT FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.message_id=message) THEN 0 ELSE 1 END;
 IF period.reserved_units-period.refunded_units<protected_units+candidate_units THEN
  RAISE EXCEPTION 'grant original reservation aggregate was released' USING ERRCODE='23514'; END IF;
 SELECT * INTO namespace FROM public.hosted_billing_namespaces FOR SHARE NOWAIT;
 IF FOUND THEN
  PERFORM 1 FROM public.hosted_billing_customers c WHERE c.namespace_id=namespace.namespace_id AND c.account_id=account
   FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'grant hosted customer unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO projection FROM public.hosted_billing_projections p WHERE p.namespace_id=namespace.namespace_id AND p.account_id=account FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'grant hosted projection unavailable' USING ERRCODE='23514'; END IF;
  -- Preserve106's protected backend verification and current active/grace
  -- semantics. Its exact installation path is already pinned by106. Every
  -- row it locks is first acquired NOWAIT here under the chosen account mode.
  PERFORM 1 FROM public.accounts a WHERE a.id=account AND a.disabled_at IS NULL FOR NO KEY UPDATE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'grant hosted account unavailable' USING ERRCODE='23514'; END IF;
  SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint INTO backend_until
   FROM public.hosted_runtime_sessions s JOIN pg_catalog.pg_stat_activity a ON(a.pid,a.backend_start)=(s.backend_pid,s.backend_start)
   WHERE s.backend_pid=pg_backend_pid() AND s.namespace_id=namespace.namespace_id AND s.policy_revision=namespace.policy_revision
    AND s.verified AND s.expires_at>clock_timestamp() FOR SHARE OF s NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'grant actual hosted backend window unavailable' USING ERRCODE='23514'; END IF;
  -- The stored expiry is only an additional temporal ceiling. The unchanged
  -- protected106 helper below must independently authenticate this backend.
  projection:=public.hosted_runtime_projection(account);
  IF projection.namespace_id IS DISTINCT FROM namespace.namespace_id OR projection.account_id IS DISTINCT FROM account
   OR projection.period_end>9223372036854775 OR projection.valid_until>9223372036854775 THEN
   RAISE EXCEPTION 'grant protected hosted projection differs' USING ERRCODE='23514'; END IF;
  PERFORM 1 FROM public.hosted_billing_usage u WHERE u.namespace_id=namespace.namespace_id AND u.account_id=account AND u.message_id=message FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'grant original hosted attribution unavailable' USING ERRCODE='23514'; END IF;
  RETURN least(least(projection.period_end,projection.valid_until)*1000,backend_until);
 END IF;
 SELECT * INTO customer FROM public.billing_customers c WHERE c.account_id=account FOR SHARE NOWAIT;
 bound:=FOUND;
 IF NOT bound THEN
  -- Protect an actually absent binding without reversing customer->account order.
  PERFORM 1 FROM public.accounts a WHERE a.id=account AND a.disabled_at IS NULL FOR UPDATE NOWAIT;
  IF NOT FOUND OR EXISTS(SELECT FROM public.billing_customers c WHERE c.account_id=account) THEN
   RAISE EXCEPTION 'grant billing binding changed' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT * INTO policy FROM public.usage_quota_policies p WHERE p.account_id=account AND p.metric='outbound_message' FOR SHARE NOWAIT;
 IF NOT FOUND OR policy.limit_units IS NULL OR(bound AND policy.source<>'stripe_test') OR(policy.invoice_bound_test AND NOT bound) THEN
  RAISE EXCEPTION 'grant configured finite policy unavailable' USING ERRCODE='23514'; END IF;
 IF bound THEN
  PERFORM 1 FROM public.billing_risk_events r WHERE r.account_id=account FOR SHARE NOWAIT;
  PERFORM 1 FROM public.billing_payment_holds h WHERE h.account_id=account FOR SHARE NOWAIT;
  PERFORM 1 FROM public.billing_reconciliations r WHERE r.account_id=account FOR SHARE NOWAIT;
  SELECT count(*),count(*) FILTER(WHERE dirty_generation=processed_generation) INTO recon_total,recon_clean
   FROM public.billing_reconciliations r WHERE r.account_id=account;
  IF EXISTS(SELECT FROM public.billing_risk_events r WHERE r.account_id=account AND r.state IN('queued','held','needs_review'))
   OR EXISTS(SELECT FROM public.billing_payment_holds h WHERE h.account_id=account) OR recon_total=0 OR recon_total<>recon_clean THEN
   RAISE EXCEPTION 'grant current payment risk pending' USING ERRCODE='23514'; END IF;
  FOR subscription IN SELECT * FROM public.billing_subscriptions s WHERE s.account_id=account FOR SHARE NOWAIT LOOP
   IF subscription.stripe_status='past_due' THEN
    IF subscription.payment_grace_started_at IS NULL OR subscription.payment_grace_invoice_id IS DISTINCT FROM subscription.latest_invoice_id THEN
     RAISE EXCEPTION 'grant payment grace ambiguous' USING ERRCODE='23514'; END IF;
    deadline:=least(deadline,floor(extract(epoch FROM subscription.payment_grace_started_at+interval '7 days')*1000)::bigint);
   END IF;
  END LOOP;
  IF policy.invoice_bound_test THEN
   PERFORM 1 FROM public.billing_invoice_usage u JOIN public.billing_invoice_periods p ON(p.account_id,p.id)=(u.account_id,u.period_id)
    WHERE u.account_id=account AND u.message_id=message AND NOT u.refunded AND NOT u.terminal FOR SHARE OF u,p NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION 'grant original invoice liability unavailable' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms>=deadline THEN RAISE EXCEPTION 'grant current payment grace expired' USING ERRCODE='23514'; END IF;
 RETURN deadline;
END;
$function$;

-- The one-use grant retains a charged unit until a future separately typed
-- financial release. Other messages keep their real legacy billing writers.
-- Mandatory OLD/NEW account participation happens before this narrow policy;
-- repeat its shared stable-anchor lock without upgrading billing lock order.
CREATE FUNCTION public.conversation_profile03_grant_usage_writer(account uuid,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE state text; epoch bigint; period record; protected_units bigint;
BEGIN
 IF account IS NULL OR relation_name NOT IN('usage_ledger','usage_periods') OR operation NOT IN('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'grant usage writer input differs' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' AND NOT EXISTS(SELECT FROM public.accounts a WHERE a.id=account) THEN RETURN; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(account)) THEN
  RAISE EXCEPTION 'grant usage writer account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR SHARE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch<>1 OR NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'grant usage writer actual anchor unavailable' USING ERRCODE='23514'; END IF;
 IF relation_name='usage_ledger' THEN
  IF EXISTS(SELECT FROM public.conversation_profile03_grants g CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(old_row,new_row)) r(value)
   WHERE g.account_id=account AND(r.value->>'account_id')::uuid=account AND g.message_id=(r.value->>'message_id')::uuid) THEN
   RAISE EXCEPTION 'grant charged reserve identity cannot be released or reassigned' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 FOR period IN SELECT DISTINCT r.value->>'metric' AS metric,(r.value->>'period_start')::date AS period_start
  FROM jsonb_array_elements(jsonb_build_array(old_row,new_row)) r(value) WHERE(r.value->>'account_id')::uuid=account LOOP
  SELECT count(*) INTO protected_units FROM public.conversation_profile03_grants g JOIN public.usage_ledger u
   ON(u.account_id,u.message_id)=(g.account_id,g.message_id) WHERE u.account_id=account AND u.metric=period.metric
    AND u.period_start=period.period_start AND u.entry_kind='reserve' AND u.units=1;
  -- Stock reserve_outbound uses INSERT ON CONFLICT DO UPDATE. PostgreSQL runs
  -- BEFORE INSERT on its discarded candidate first. Only an existing exact
  -- protected parent permits that provisional row; its immutable unique key
  -- forces the conflict, then the actual UPDATE below checks the real counters.
  IF protected_units>0 AND operation='INSERT' AND EXISTS(SELECT FROM public.usage_periods p
   WHERE(p.account_id,p.metric,p.period_start,p.period_end)=
    (account,new_row->>'metric',(new_row->>'period_start')::date,(new_row->>'period_end')::date)) THEN CONTINUE; END IF;
  IF protected_units>0 AND(operation<>'UPDATE' OR old_row IS NULL OR new_row IS NULL
   OR(old_row->>'account_id',old_row->>'metric',old_row->>'period_start',old_row->>'period_end')
    IS DISTINCT FROM(new_row->>'account_id',new_row->>'metric',new_row->>'period_start',new_row->>'period_end')
   OR(new_row->>'reserved_units')::bigint<(old_row->>'reserved_units')::bigint
   OR(new_row->>'refunded_units')::bigint<(old_row->>'refunded_units')::bigint
   OR(new_row->>'reserved_units')::bigint-(new_row->>'refunded_units')::bigint<protected_units) THEN
   RAISE EXCEPTION 'grant charged aggregate floor cannot be released or reset' USING ERRCODE='23514'; END IF;
 END LOOP;
END;
$function$;

-- Independently compare all original114 intent/context fields and current113
-- installed permission. Signature/authentication remain mandatory in Rust.
CREATE FUNCTION public.conversation_profile03_grant_scope(account uuid,message uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint)
RETURNS public.conversation_profile03_grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; admission public.conversation_reviewed_sends03%ROWTYPE;
 parsed public.conversation_reviewed_sends03%ROWTYPE; consent public.conversation_profile03_intervals%ROWTYPE; checked public.conversation_profile03_intervals%ROWTYPE;
 msg public.messages%ROWTYPE; lease_until bigint; owner_until bigint; deadline bigint; now_ms bigint;
BEGIN
 PERFORM public.conversation_profile03_grant_mode(account);
 IF message IS NULL OR device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL
  OR octet_length(site) NOT BETWEEN 1 AND 256 OR octet_length(instance) NOT BETWEEN 1 AND 256 OR connection_epoch<=0 OR deployment_epoch<=0 THEN
  RAISE EXCEPTION 'grant actual socket input unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO admission FROM public.conversation_reviewed_sends03 a WHERE a.account_id=account AND a.message_id=message;
 IF NOT FOUND OR admission.redacted_ms IS NOT NULL OR admission.intent IS NULL OR admission.signature IS NULL OR admission.peer IS NULL THEN
  RAISE EXCEPTION 'grant original admission erased or unavailable' USING ERRCODE='23514'; END IF;
 owner_until:=public.payload_profile_selection_owner(account,admission.initiating_user_id,admission.initiating_session_id);
 consent:=public.conversation_profile03_interval_lock(account,admission.interval_id);
 IF consent.phase<>'active' OR consent.owner_signature IS NULL OR consent.phone_signature IS NULL OR consent.installed_signature IS NULL OR consent.installed_ms IS NULL THEN
  RAISE EXCEPTION 'grant installed interval unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_interval_scope(account,admission.initiating_user_id,admission.initiating_session_id,consent.statement,false);
 parsed:=public.conversation_reviewed_send03_parse(admission.intent);
 IF(to_jsonb(admission)-ARRAY['interval_receipt_id','election_challenge_id','original_binding_id','physical_refresh_id','physical_source_kind','device_session_digest','physical_selection_digest','interval_statement_sha256','proof_site_id','proof_instance_id','proof_connection_epoch','proof_deployment_epoch','signature','signature_sha256','admitted_ms','permission_deadline_ms','redacted_ms'])
  IS DISTINCT FROM(to_jsonb(parsed)-ARRAY['interval_receipt_id','election_challenge_id','original_binding_id','physical_refresh_id','physical_source_kind','device_session_digest','physical_selection_digest','interval_statement_sha256','proof_site_id','proof_instance_id','proof_connection_epoch','proof_deployment_epoch','signature','signature_sha256','admitted_ms','permission_deadline_ms','redacted_ms'])
  OR sha256(admission.signature)<>admission.signature_sha256 OR admission.admitted_ms<admission.review_issued_ms OR admission.admitted_ms>=admission.review_expires_ms
  OR(admission.device_id,admission.line_id,admission.binding_id,admission.interval_id,admission.interval_receipt_id,admission.initiating_user_id,admission.initiating_session_id,
    admission.binding_generation,admission.vault_generation,admission.manifest_version,admission.selection_epoch,admission.selected_reader_key_id,admission.signer_key_id,
    admission.root_fingerprint,admission.manifest_digest,admission.election_commitment,admission.election_bundle_sha256,admission.owner_session_digest,admission.configured_origin_digest,
    admission.election_challenge_id,admission.original_binding_id,admission.physical_refresh_id,admission.physical_source_kind,admission.device_session_digest,admission.physical_selection_digest,
    admission.interval_statement_sha256,admission.proof_site_id,admission.proof_instance_id,admission.proof_connection_epoch,admission.proof_deployment_epoch,admission.peer)
   IS DISTINCT FROM(consent.device_id,consent.line_id,consent.binding_id,consent.interval_id,consent.receipt_id,consent.initiating_user_id,consent.initiating_session_id,
    consent.binding_generation,consent.vault_generation,consent.manifest_version,consent.selection_epoch,consent.selected_reader_key_id,consent.browser_signer_key_id,
    consent.root_fingerprint,consent.manifest_digest,consent.election_commitment,consent.election_bundle_sha256,consent.owner_session_digest,consent.configured_origin_digest,
    consent.election_challenge_id,consent.original_binding_id,consent.physical_refresh_id,consent.physical_source_kind,consent.device_session_digest,consent.physical_selection_digest,
    consent.statement_sha256,consent.proof_site_id,consent.proof_instance_id,consent.proof_connection_epoch,consent.proof_deployment_epoch,consent.peer)
  OR(checked.physical_source_kind,checked.physical_refresh_id,checked.physical_selection_digest,checked.device_session_digest,checked.proof_site_id,checked.proof_instance_id,checked.proof_connection_epoch,checked.proof_deployment_epoch)
   IS DISTINCT FROM(consent.physical_source_kind,consent.physical_refresh_id,consent.physical_selection_digest,consent.device_session_digest,consent.proof_site_id,consent.proof_instance_id,consent.proof_connection_epoch,consent.proof_deployment_epoch)
  OR(admission.device_id,admission.proof_site_id,admission.proof_instance_id,admission.proof_connection_epoch,admission.proof_deployment_epoch)
   IS DISTINCT FROM(device,site,instance,connection_epoch,deployment_epoch) THEN
  RAISE EXCEPTION 'grant original permission or actual full socket differs' USING ERRCODE='23514'; END IF;
 SELECT floor(extract(epoch FROM s.lease_until)*1000)::bigint INTO lease_until FROM public.device_sessions s
  JOIN public.deployment_authority d ON d.singleton AND d.epoch=s.deployment_epoch AND d.dispatch_enabled
  WHERE s.account_id=account AND s.device_id=device AND(s.site_id,s.instance_id,s.connection_epoch,s.deployment_epoch)
   =(site,instance,conversation_profile03_grant_scope.connection_epoch,conversation_profile03_grant_scope.deployment_epoch)
  AND s.lease_until>clock_timestamp() FOR SHARE OF s,d NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant current dispatch lease unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO msg FROM public.messages m WHERE m.account_id=account AND m.id=message FOR SHARE NOWAIT;
 IF NOT FOUND OR msg.transport_mode<>'sealed_profile03' OR msg.device_id<>device OR msg.transport_payload IS NULL OR msg.recipient_e164 IS NULL
  OR msg.recipient_e164<>admission.peer OR msg.recipient_digest<>sha256(convert_to(admission.peer,'UTF8')) OR msg.request_digest<>admission.unsigned_digest
  OR(msg.sealed_line_id,msg.sealed_binding_generation,msg.sealed_manifest_generation,msg.sealed_manifest_version,msg.sealed_manifest_digest,msg.sealed_signer_key_id,msg.sealed_segment_limit)
   IS DISTINCT FROM(admission.line_id,admission.binding_generation,admission.vault_generation,admission.manifest_version,admission.manifest_digest,admission.signer_key_id,admission.authenticated_segment_ceiling)
  OR msg.expires_at<>to_timestamp(admission.message_expires_ms::double precision/1000) THEN RAISE EXCEPTION 'grant exact retained message differs' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_reviewed_send03_envelope(admission,msg.transport_payload);
 PERFORM 1 FROM public.recipient_suppressions s WHERE s.account_id=account AND s.recipient_e164=admission.peer AND s.active FOR SHARE NOWAIT;
 IF FOUND THEN RAISE EXCEPTION 'grant recipient suppressed' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.owner_recipient_holds h WHERE h.account_id=account AND h.recipient_e164=admission.peer AND h.released_at IS NULL FOR SHARE NOWAIT;
 IF FOUND THEN RAISE EXCEPTION 'grant recipient held' USING ERRCODE='23514'; END IF;
 deadline:=least(admission.message_expires_ms,consent.interval_expires_ms,owner_until,lease_until,public.conversation_profile03_grant_billing(account,message));
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<admission.admitted_ms OR admission.observed_ms<consent.installed_ms OR now_ms>=deadline THEN
  RAISE EXCEPTION 'grant current permission expired or clock regressed' USING ERRCODE='23514'; END IF;
 row.account_id:=account;row.message_id:=message;row.interval_id:=admission.interval_id;row.interval_receipt_id:=admission.interval_receipt_id;
 row.initiating_user_id:=admission.initiating_user_id;row.initiating_session_id:=admission.initiating_session_id;row.device_id:=device;row.line_id:=admission.line_id;
 row.binding_id:=admission.binding_id;row.election_challenge_id:=admission.election_challenge_id;row.original_binding_id:=admission.original_binding_id;row.physical_refresh_id:=admission.physical_refresh_id;
 row.binding_generation:=admission.binding_generation;row.connection_epoch:=connection_epoch;row.deployment_epoch:=deployment_epoch;row.trust_generation:=1;
 row.manifest_version:=admission.manifest_version;row.selection_epoch:=1;row.admitted_ms:=admission.admitted_ms;row.issued_ms:=now_ms;row.authority_deadline_ms:=deadline;
 row.site_id:=site;row.instance_id:=instance;row.physical_source_kind:=admission.physical_source_kind;row.authenticated_segment_ceiling:=admission.authenticated_segment_ceiling;
 row.reader_key_id:=admission.selected_reader_key_id;row.envelope_sha256:=admission.envelope_sha256;row.unsigned_sha256:=admission.unsigned_digest;
 row.manifest_digest:=admission.manifest_digest;row.root_fingerprint:=admission.root_fingerprint;row.election_digest:=admission.election_commitment;
 row.election_bundle_sha256:=admission.election_bundle_sha256;row.owner_session_digest:=admission.owner_session_digest;row.configured_origin_digest:=admission.configured_origin_digest;
 row.device_session_digest:=admission.device_session_digest;row.physical_selection_digest:=admission.physical_selection_digest;row.interval_statement_sha256:=admission.interval_statement_sha256;
 row.intent_sha256:=admission.intent_sha256;row.signature_sha256:=admission.signature_sha256;
 RETURN row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_grant_same_scope(original jsonb,current_scope jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
 SELECT(original-ARRAY['attempt_id','attempt_generation','lease_owner','issued_ms','expires_at_ms','authority_deadline_ms'])
  IS NOT DISTINCT FROM(current_scope-ARRAY['attempt_id','attempt_generation','lease_owner','issued_ms','expires_at_ms','authority_deadline_ms'])
$function$;

-- Only the exact initial claim recorded by the immutable grant is writable.
-- No update-to-submit, callback, timeout, unknown reset or generic retry is
-- authorized here. Those effects require separately typed phone evidence.
CREATE FUNCTION public.conversation_profile03_grant_writer(account uuid,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; checked public.conversation_profile03_grants%ROWTYPE;
 wanted uuid; msg public.messages%ROWTYPE; job public.dispatch_jobs%ROWTYPE; now_ms bigint; stamp timestamptz;
BEGIN
 IF account IS NULL OR relation_name NOT IN('messages','dispatch_jobs','message_attempts','dispatch_fences') OR operation NOT IN('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'grant typed writer input differs' USING ERRCODE='23514'; END IF;
 wanted:=CASE WHEN relation_name='messages' THEN coalesce((new_row->>'id')::uuid,(old_row->>'id')::uuid)
  ELSE coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid) END;
 SELECT * INTO row FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.message_id=wanted;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant typed original unavailable' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' THEN
  IF relation_name IN('messages','dispatch_jobs','message_attempts','dispatch_fences') AND EXISTS(SELECT FROM public.messages m WHERE m.account_id=account AND m.id=wanted)
   AND(NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=account AND m.id=wanted AND m.state IN('delivered','failed','cancelled','expired'))
    OR EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.message_id=wanted AND f.outcome IN('granted','submitting','unknown'))
    OR EXISTS(SELECT FROM public.message_attempts a WHERE a.account_id=account AND a.message_id=wanted AND a.status IN('granted','submitting','unknown'))) THEN
   RAISE EXCEPTION 'grant unresolved effect liability cannot be erased' USING ERRCODE='23514'; END IF;
  PERFORM public.conversation_reviewed_send03_erasure_fence(account);RETURN;
 END IF;
 -- Terminal content redaction is the original114 policy; it cannot alter the
 -- retained grant or release any unresolved dispatch fence.
 IF relation_name='messages' AND operation='UPDATE' AND new_row->>'recipient_e164' IS NULL AND new_row->>'transport_payload' IS NULL THEN
  PERFORM public.conversation_reviewed_send03_writer(account,1,relation_name,operation,old_row,new_row);RETURN;
 END IF;
 checked:=public.conversation_profile03_grant_scope(account,wanted,row.device_id,row.site_id,row.instance_id,row.connection_epoch,row.deployment_epoch);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 stamp:=to_timestamp(row.issued_ms::double precision/1000);
 IF NOT public.conversation_profile03_grant_same_scope(to_jsonb(row),to_jsonb(checked)) OR row.authority_deadline_ms>checked.authority_deadline_ms
  OR now_ms<row.issued_ms OR now_ms>=least(row.expires_at_ms,row.authority_deadline_ms) THEN
  RAISE EXCEPTION 'grant typed current selection unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO msg FROM public.messages m WHERE m.account_id=account AND m.id=wanted FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant typed message unavailable' USING ERRCODE='23514'; END IF;
 IF relation_name='messages' THEN
  IF operation<>'UPDATE' OR old_row IS NULL OR new_row IS NULL
   OR(old_row-ARRAY['state','state_version','updated_at']) IS DISTINCT FROM(new_row-ARRAY['state','state_version','updated_at'])
   OR(old_row->>'state',(old_row->>'state_version')::bigint,new_row->>'state',(new_row->>'state_version')::bigint,(new_row->>'updated_at')::timestamptz)
    IS DISTINCT FROM('queued'::text,1::bigint,'claimed'::text,2::bigint,stamp)
   OR to_jsonb(msg) IS DISTINCT FROM old_row THEN
   RAISE EXCEPTION 'grant exact initial message claim differs' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 IF msg.state<>'claimed' OR msg.state_version<>2 OR msg.updated_at<>stamp THEN
  RAISE EXCEPTION 'grant typed claimed message unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO job FROM public.dispatch_jobs j WHERE j.account_id=account AND j.message_id=wanted FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant typed job unavailable' USING ERRCODE='23514'; END IF;
 IF relation_name='dispatch_jobs' THEN
  IF operation<>'UPDATE' OR old_row IS NULL OR new_row IS NULL
   OR(old_row-ARRAY['generation','lease_owner','lease_until','grant_issued_at']) IS DISTINCT FROM(new_row-ARRAY['generation','lease_owner','lease_until','grant_issued_at'])
   OR((old_row->>'generation')::bigint,old_row->>'lease_owner',(old_row->>'lease_until')::timestamptz,(old_row->>'grant_issued_at')::timestamptz,old_row->>'finished_at')
    IS DISTINCT FROM(0::bigint,NULL::text,NULL::timestamptz,NULL::timestamptz,NULL::text)
   OR((new_row->>'generation')::bigint,new_row->>'lease_owner',(new_row->>'lease_until')::timestamptz,(new_row->>'grant_issued_at')::timestamptz)
    IS DISTINCT FROM(row.attempt_generation,row.lease_owner,to_timestamp(row.expires_at_ms::double precision/1000),stamp)
   OR(old_row->>'next_attempt_at')::timestamptz>stamp OR to_jsonb(job) IS DISTINCT FROM old_row THEN
   RAISE EXCEPTION 'grant exact initial job claim differs' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 IF(job.device_id,job.generation,job.lease_owner,job.lease_until,job.grant_issued_at,job.finished_at)
  IS DISTINCT FROM(row.device_id,row.attempt_generation,row.lease_owner,to_timestamp(row.expires_at_ms::double precision/1000),stamp,NULL::timestamptz)
  OR operation<>'INSERT' OR old_row IS NOT NULL OR new_row IS NULL THEN
  RAISE EXCEPTION 'grant exact initial effect phase differs' USING ERRCODE='23514'; END IF;
 IF relation_name='message_attempts' THEN
  IF new_row IS DISTINCT FROM jsonb_build_object('id',row.attempt_id,'account_id',account,'message_id',wanted,'device_id',row.device_id,
   'generation',row.attempt_generation,'session_epoch',row.connection_epoch,'deployment_epoch',row.deployment_epoch,'status','granted','created_at',stamp,'updated_at',stamp) THEN
   RAISE EXCEPTION 'grant exact initial attempt differs' USING ERRCODE='23514'; END IF;
 ELSE
  IF new_row IS DISTINCT FROM jsonb_build_object('message_id',wanted,'account_id',account,'device_id',row.device_id,'attempt_id',row.attempt_id,
   'generation',row.attempt_generation,'session_epoch',row.connection_epoch,'deployment_epoch',row.deployment_epoch,
   'recipient_digest',msg.recipient_digest,'grant_expires_at',to_timestamp(row.expires_at_ms::double precision/1000),'outcome','granted')
   OR NOT EXISTS(SELECT FROM public.message_attempts a WHERE a.id=row.attempt_id AND a.account_id=account AND a.message_id=wanted
    AND(a.device_id,a.generation,a.session_epoch,a.deployment_epoch,a.status,a.created_at,a.updated_at)
     =(row.device_id,row.attempt_generation,row.connection_epoch,row.deployment_epoch,'granted'::text,stamp,stamp)) THEN
   RAISE EXCEPTION 'grant exact initial one-use fence differs' USING ERRCODE='23514'; END IF;
 END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_policy(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE selected public.payload_profile_elections%ROWTYPE; reserved public.payload_profile_election_challenges%ROWTYPE;
 signed_before boolean; is_transition boolean; parent uuid; mode text;
BEGIN
 IF epoch<0 OR operation NOT IN('INSERT','UPDATE','DELETE') THEN RAISE EXCEPTION 'unknown writer operation' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN; END IF;
 IF epoch>0 AND NOT public.payload_profile_epoch_valid(account,epoch) THEN
  RAISE EXCEPTION 'unknown positive selection epoch' USING ERRCODE='23514'; END IF;

 -- An immutable03 grant may authorize only its exact initial claim/effects.
 -- Existing114 admission/redaction and every legacy policy remain separate.
 IF epoch=1 AND relation_name IN('usage_ledger','usage_periods') THEN
  PERFORM public.conversation_profile03_grant_usage_writer(account,relation_name,operation,old_row,new_row);RETURN;
 END IF;
 IF epoch=1 AND relation_name IN('messages','dispatch_jobs','message_attempts','dispatch_fences') AND EXISTS(
  SELECT FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.message_id=
   CASE WHEN relation_name='messages' THEN coalesce((new_row->>'id')::uuid,(old_row->>'id')::uuid)
    ELSE coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid) END) THEN
  PERFORM public.conversation_profile03_grant_writer(account,relation_name,operation,old_row,new_row);RETURN;
 END IF;

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
  IF coalesce(new_row->>'transport_mode',old_row->>'transport_mode')='sealed_profile03' THEN
   PERFORM public.conversation_reviewed_send03_writer(account,epoch,relation_name,operation,old_row,new_row);RETURN;
  END IF;
  IF (old_row IS NULL OR old_row->>'transport_mode'='synthetic_alpha') AND(new_row IS NULL OR new_row->>'transport_mode'='synthetic_alpha') THEN RETURN; END IF;
  IF epoch>0 OR signed_before THEN RAISE EXCEPTION 'legacy sealed message fenced' USING ERRCODE='23514'; END IF;
  RETURN;
 ELSIF relation_name IN('dispatch_jobs','dispatch_fences','message_attempts','message_events','message_submission_receipts','idempotency_keys','provider_send_attempts') THEN
  parent:=coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid);
  SELECT transport_mode INTO mode FROM public.messages WHERE account_id=account AND id=parent;
  IF mode='sealed_profile03' AND relation_name='dispatch_jobs' THEN
   PERFORM public.conversation_reviewed_send03_writer(account,epoch,relation_name,operation,old_row,new_row);RETURN;
  END IF;
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
CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_admit(account uuid,"interval" uuid,message uuid,intent bytea,signature bytea,envelope bytea,permission_deadline_ms bigint)
RETURNS SETOF public.conversation_reviewed_sends03
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; previous public.conversation_reviewed_sends03%ROWTYPE; checked_ms bigint;
BEGIN
 IF account IS NULL OR "interval" IS NULL OR message IS NULL OR intent IS NULL OR signature IS NULL OR envelope IS NULL OR permission_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'reviewed03 original admission input unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM public.conversation_reviewed_sends03 r WHERE r.account_id=account AND r.message_id=message;
 IF FOUND THEN
  IF previous.interval_id<>"interval" OR previous.intent_sha256<>sha256(intent) OR previous.signature_sha256<>sha256(signature) OR previous.envelope_sha256<>sha256(envelope) THEN
   RAISE EXCEPTION 'reviewed03 original retry differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT previous;RETURN;
 END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_grants g WHERE g.account_id=account AND g.message_id=message) THEN
  RAISE EXCEPTION 'reviewed03 retained issued identity cannot be readmitted' USING ERRCODE='23514'; END IF;
 checked_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row:=public.conversation_reviewed_send03_scope(account,intent,signature,permission_deadline_ms,checked_ms);
 IF(row.interval_id,row.message_id) IS DISTINCT FROM("interval",message) THEN RAISE EXCEPTION 'reviewed03 original selectors differ' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_reviewed_send03_envelope(row,envelope);
 -- A real tuple version defeats stale RR/SSI authority snapshots; original retries never touch it.
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=account;
 INSERT INTO public.conversation_reviewed_sends03 SELECT(row).*;
 -- Actual Rust03enqueue and existing billing policy run before the deferred
 -- completeness check. This return alone is not a committed admission.
 RETURN NEXT row;
END;
$function$;
CREATE OR REPLACE FUNCTION public.alpha_message_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path TO pg_catalog,public,pg_temp AS $function$
DECLARE r conversation_execution_records; attempt uuid; before_status text; after_status text; wanted uuid;
BEGIN
 IF TG_TABLE_SCHEMA='public' AND TG_LEVEL='ROW' AND TG_WHEN='BEFORE' AND TG_NARGS=0 AND TG_OP IN('INSERT','UPDATE')
  AND((TG_TABLE_NAME='message_attempts' AND TG_RELID='public.message_attempts'::regclass)
   OR(TG_TABLE_NAME='dispatch_fences' AND TG_RELID='public.dispatch_fences'::regclass))
  AND EXISTS(SELECT FROM public.messages m WHERE m.account_id=NEW.account_id AND m.id=NEW.message_id AND m.transport_mode='sealed_profile03') THEN
  PERFORM public.conversation_profile03_grant_writer(NEW.account_id,TG_TABLE_NAME,TG_OP,CASE WHEN TG_OP='UPDATE' THEN to_jsonb(OLD) ELSE NULL END,to_jsonb(NEW));RETURN NEW;
 END IF;
 IF EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
 AND device_id=NEW.device_id AND transport_mode='synthetic_alpha' FOR SHARE) THEN RETURN NEW; END IF;
 -- Retained confirmation identity, including redacted proof, selects the conversation lane.
 -- Other sealed effects keep every migration 071 provenance and freshness check.
 IF NOT EXISTS(SELECT 1 FROM conversation_confirmation_records
 WHERE account_id=NEW.account_id AND message_id=NEW.message_id) THEN
    IF TG_TABLE_NAME='message_attempts' THEN wanted:=NEW.id; ELSE wanted:=NEW.attempt_id; END IF;
    IF TG_OP='UPDATE' AND (
        ROW(NEW.account_id,NEW.message_id,NEW.device_id,NEW.generation,NEW.session_epoch,NEW.deployment_epoch)
        IS DISTINCT FROM
        ROW(OLD.account_id,OLD.message_id,OLD.device_id,OLD.generation,OLD.session_epoch,OLD.deployment_epoch)) THEN
        RAISE EXCEPTION 'sealed attempt identity cannot change' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF TG_TABLE_NAME='message_attempts' THEN
            IF NEW.id<>OLD.id THEN
                RAISE EXCEPTION 'sealed attempt identity cannot change' USING ERRCODE='23514';
            END IF;
        ELSE
            IF ROW(NEW.attempt_id,NEW.grant_expires_at,NEW.recipient_digest) IS DISTINCT FROM
               ROW(OLD.attempt_id,OLD.grant_expires_at,OLD.recipient_digest) THEN
                RAISE EXCEPTION 'sealed fence identity cannot change' USING ERRCODE='23514';
            END IF;
        END IF;
    END IF;
    IF NOT EXISTS(SELECT 1 FROM sealed_grant_authorizations g JOIN messages m
        ON (m.account_id,m.id)=(g.account_id,g.message_id)
        WHERE g.attempt_id=wanted AND g.account_id=NEW.account_id AND g.message_id=NEW.message_id
        AND g.device_id=NEW.device_id AND g.attempt_generation=NEW.generation
        AND g.connection_epoch=NEW.session_epoch AND g.deployment_epoch=NEW.deployment_epoch
        AND m.transport_mode='sealed_candidate02' AND m.sealed_segment_limit=g.segment_limit) THEN
        RAISE EXCEPTION 'sealed effects require exact grant provenance' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' AND NOT sealed_grant_current(wanted) THEN
        RAISE EXCEPTION 'sealed grant authority is stale' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' THEN
        IF TG_TABLE_NAME='message_attempts' THEN
            IF NEW.status<>'granted' THEN
                RAISE EXCEPTION 'sealed attempt starts granted' USING ERRCODE='23514';
            END IF;
        ELSE
            IF NEW.outcome<>'granted' OR NEW.grant_expires_at<=clock_timestamp()
                OR NEW.grant_expires_at>clock_timestamp()+interval '30 seconds'
                OR NOT EXISTS(SELECT 1 FROM sealed_grant_authorizations g JOIN messages m
                    ON (m.account_id,m.id)=(g.account_id,g.message_id)
                    WHERE g.attempt_id=wanted AND NEW.recipient_digest=m.recipient_digest
                    AND NEW.grant_expires_at<=to_timestamp(g.authority_expires_at_ms::double precision/1000)) THEN
                RAISE EXCEPTION 'sealed fence exceeds exact authority' USING ERRCODE='23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='message_attempts' THEN attempt:=NEW.id; after_status:=NEW.status;
 ELSE attempt:=NEW.attempt_id; after_status:=NEW.outcome; END IF;
 SELECT * INTO r FROM conversation_execution_records WHERE account_id=NEW.account_id AND message_id=NEW.message_id;
 IF NOT FOUND OR (NEW.device_id,attempt,NEW.generation,NEW.session_epoch,NEW.deployment_epoch)<>
 (r.device_id,r.attempt_id,r.generation,r.session_epoch,r.deployment_epoch) THEN
  RAISE EXCEPTION 'effects require exact confirmed execution identity' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='dispatch_fences' THEN
 IF (NEW.recipient_digest IS DISTINCT FROM
 (SELECT recipient_digest FROM messages WHERE account_id=r.account_id AND id=r.message_id)
 OR NEW.grant_expires_at<>to_timestamp(r.expires_at_ms::double precision/1000)) THEN
  RAISE EXCEPTION 'execution fence cannot replace recipient or expiry' USING ERRCODE='23514';
 END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF after_status<>'granted' OR NOT conversation_execution_initial_valid(r) OR NOT EXISTS(
  SELECT 1 FROM dispatch_jobs j JOIN messages m ON (m.account_id,m.id)=(j.account_id,j.message_id)
  WHERE (j.account_id,j.message_id,j.device_id,j.generation)=(r.account_id,r.message_id,r.device_id,r.generation)
  AND j.lease_owner='conversation:'||r.phone_session::text AND j.lease_until=to_timestamp(r.expires_at_ms::double precision/1000)
  AND j.grant_issued_at IS NOT NULL AND j.finished_at IS NULL AND m.state='claimed') THEN
   RAISE EXCEPTION 'execution effects require complete fresh claim' USING ERRCODE='23514';
  END IF;
 ELSE
  IF TG_TABLE_NAME='message_attempts' THEN before_status:=OLD.status;
  ELSE before_status:=OLD.outcome; END IF;
  IF (to_jsonb(NEW)-ARRAY['status','outcome','updated_at'])<>(to_jsonb(OLD)-ARRAY['status','outcome','updated_at'])
  OR (before_status<>'granted' AND after_status='granted')
  OR (before_status NOT IN ('granted','submitting') AND after_status='submitting')
  OR (before_status<>after_status AND NOT (
   (before_status='granted' AND after_status IN ('submitting','unknown','proved_no_submit')) OR
   (before_status='submitting' AND after_status IN ('submitted','failed','unknown','proved_no_submit')) OR
   (before_status='unknown' AND after_status IN ('submitted','failed','proved_no_submit')) OR
   (before_status IN ('submitted','failed') AND after_status='unknown'))) THEN
   RAISE EXCEPTION 'historical execution cannot reopen or replace identity' USING ERRCODE='23514';
  END IF;
  IF before_status='granted' AND after_status='submitting' AND NOT conversation_execution_initial_valid(r) THEN
   RAISE EXCEPTION 'submit intent requires current confirmed authority' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_profile03_interval_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_manifest_ready()
  AND has_table_privilege(current_user,'public.conversation_profile03_intervals','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_profile03_interval_reserve','conversation_profile03_interval_request','conversation_profile03_interval_approve','conversation_profile03_interval_install','conversation_profile03_interval_stop','conversation_profile03_interval_device_stop','conversation_profile03_interval_ready','conversation_profile03_grant_issue','conversation_profile03_grant_lock','conversation_profile03_grant_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%' AND a.grantee=0)
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=115 AND min(version)=1 AND max(version)=115 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=115 AND graph_sha256=public.payload_profile_writer_graph()
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
CREATE FUNCTION public.conversation_profile03_grant_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.conversation_reviewed_send03_ready()
  AND has_table_privilege(current_user,'public.conversation_profile03_grants','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_profile03_grants','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_profile03_grants','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_grant_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_profile03_grant_issue','conversation_profile03_grant_lock','conversation_profile03_grant_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_grant_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; columns_sql text;
BEGIN
 REVOKE ALL ON TABLE public.conversation_profile03_grants FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_profile03_grants'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_grants FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_profile03_grants FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_profile03_grants FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_profile03_grants TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_grant_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_profile03_grant_issue','conversation_profile03_grant_lock','conversation_profile03_grant_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=115);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,115,public.payload_profile_writer_graph());
