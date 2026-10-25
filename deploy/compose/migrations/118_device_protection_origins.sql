-- SPDX-License-Identifier: AGPL-3.0-only
-- Fresh first-origin protection setup; accepted profile/content history remains unchanged.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=117; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'protection origins require exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(116,117) THEN 'f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116,117) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116,117) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()',CASE WHEN writer_installation IN(115,116,117) THEN 'e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f' ELSE 'd2304db59ce15d94badb7e26f4a0e536a4551575b8b758db104fd4b4bdce1ab1' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
            ('conversation_reviewed_send03_parse(bytea)',CASE WHEN writer_installation=117 THEN '9fc0eb8cfd60bb7296f7a34446e244573df2cbc3a519a6b0a0469e824e207b28' ELSE 'f75324ab23e43721bf7fdbc107fa336f6b9b389033e552c083bfde2562105b7e' END,'public.conversation_reviewed_sends03','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['intent']::text[]),
            ('conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03, bytea)','5b2d548fb73912d9bcfa86e7e1b9ca760c3b649e2ecd6a236e500d9bbd2a77cc','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['row','envelope']::text[]),
            ('conversation_reviewed_send03_scope(uuid, bytea, bytea, bigint, bigint)',CASE WHEN writer_installation=117 THEN '838c3bd2760cb533b219cf19ec816a6f8e581499bf28ebc0a5683ae8eff86141' ELSE '82a31a37e6b99d29b97293f4303e0c189475ea744b67f3b5cd15f9b2051ab55d' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','intent','signature','permission_deadline_ms','admitted_ms']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation=117 THEN 'b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb' ELSE CASE WHEN writer_installation IN(115,116,117) THEN 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' ELSE '4f27879e1b1e350c79b0b8f661faefce941f6f1e4f852927fbe4b12ae06975a6' END END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()',CASE WHEN writer_installation=117 THEN '6c9d1664c4e261cc2a5f5e3f6d5b7f704d9a1f598333b8f3f49a262a85dc6213' ELSE '483fe860358ee38b2ff5cf293aedaf18c2cc17ee1cafeb6dac0b8c9aefd1735d' END,'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=117 THEN 'e41f43888594803a29744a49173201ce1831d3997706a9a02e3dcc14a8bc5b05' ELSE '006527b20f97d56582b26d006f80771a10a3d6007a154a990d45899803cbbb5f' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()',CASE WHEN writer_installation=117 THEN 'dca2173f22a2128120c22dd1bc96f3ae9e0519b671d9d5b569b7800137709bb1' ELSE '013423fe961e7c3d396be0bc4db8b238c295f233862c57f64c002df208cddf7d' END,'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116,117) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_reviewed_send03_ready()',CASE WHEN writer_installation=117 THEN '9b1ea5e893b4be156e764c25d34237d0057a7fdd30b79b813ba7a65980921e79' ELSE 'd5bdd952112811191cc45684ce73c451d75983f3245ecedfccf229b6daae5850' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_profile03_grant_mode(uuid)','88cc435625b02027cf88e09b93a5ece91be164073876b837750c6232d211c4f3','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_profile03_grant_issued(uuid, uuid)','660270fb3f84cc662d67a8734c49b254e460d82f3535975970c133aa8f73626e','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt']::text[]),
            ('conversation_profile03_grant_lock(uuid, uuid, uuid, text, text, bigint, bigint)','35544e458bd295ea65c292f85c165f7a68ab54833f39005fa6eb9072f97c4b1d','public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_issue(uuid, uuid, uuid, uuid, text, text, bigint, bigint, bigint)',CASE WHEN writer_installation=117 THEN '9d16e12ae65072a8eaefaa43ab17b14b360ed914f2c90c03af83e15a8538fc32' ELSE 'd8694b4bd07a786211d3fc7b310a647f419e81703474ce4380faded7ad9e86f3' END,'public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','attempt','device','site','instance','connection_epoch','deployment_epoch','permission_deadline_ms']::text[]),
            ('conversation_profile03_grant_rows_guard()','b3a9375ed664177dfb032755071667fa3ceb14dac1ce5e37c1712bb2f31cd427','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_complete()','027bcdfb9e932d3b00efde8cef3bafe6859d1681d82568b0b09bb42ab9085964','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_billing(uuid, uuid)',CASE WHEN writer_installation IN(116,117) THEN '2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3' ELSE 'cc1e70c70f7c3e2554eb14573dbeccc3307d1dad1b3cb049f979a20c11cdab1a' END,'bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('conversation_profile03_grant_usage_writer(uuid, text, text, jsonb, jsonb)','686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_profile03_grant_scope(uuid, uuid, uuid, text, text, bigint, bigint)',CASE WHEN writer_installation=117 THEN '7f4861c2b72b04b787fbe03dba9ea0df1b453dd90fc63181ed37b707d081231b' ELSE '675959b6686692e2dde0995b4883cfffc45fbe47bbc1d31cd2bf425f50f9afa2' END,'public.conversation_profile03_grants','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_same_scope(jsonb, jsonb)','89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['original','current_scope']::text[]),
            ('conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)','fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation=117 THEN 'b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb' ELSE 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('alpha_message_effect_guard()','f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_grant_ready()','7a7920d347bb93453f6d11c2044060ba46642135f41dab8223446cafee017448','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
          ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL) THEN
            RAISE EXCEPTION 'grant03 helper declaration or body inconsistent'; END IF;
          END LOOP;
FOR writer_expected IN SELECT * FROM(VALUES
            ('public.hosted_runtime_native_start()',ARRAY['ec771eafcc009af67e4dcb156d3b5406c8cec64ea5e045ba624e6850d7614b54']::text[],'timestamptz','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_native_schema_valid()',CASE WHEN writer_installation=117 THEN ARRAY['6fe7bf0ce4d4cb6f4113c45a2397502d99afafec4c4f026a9af6c37c5e610b4e']::text[] ELSE ARRAY['899ca98ace0d006efc0fde4e0fba02ef2f207fc112ad94f091013d2e9e503644']::text[] END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_identity_ready()',CASE WHEN writer_installation=117 THEN ARRAY['7fda07320588b52036fe5002b3c4082f5fce7c19f57d9763ecda85beb02a343f']::text[] ELSE ARRAY['88de695db32691204e5126b0b5e003aadced6f61ec77918a00618f1e2f59a532']::text[] END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_scope()',CASE WHEN writer_installation=117 THEN ARRAY['5af80385e9460db2d4381a082df2e6a1c63059b66019678518bf4133f5b5673f']::text[] ELSE ARRAY['604e7c39da10e1c34c5193dd04d5742637c611a40e3d7a28bf300ec066756dbe']::text[] END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_marker()',ARRAY['22de9f7196cc521eecffc5652aac84040597db4f7a247cfd91ab208aed4c2082']::text[],'public.hosted_billing_namespaces','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_request_apply()',ARRAY['71e1abc66badc284df0804536950134dc07560eb7ca9453876ebfd4c801b85e2']::text[],'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_request_remove()',ARRAY['116d1461147797b8272d44684d9e85e7ce1ba5d515d9a2b36440287dac94dcb6']::text[],'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_challenge(uuid, bigint)',ARRAY['da750b1b75c8cd0b61ea45e0502eaf421d29e9d46bf0ef21f504ea6c4b3adf37']::text[],'bytea','sql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['ns','rev']::text[]),
            ('public.hosted_runtime_bind(uuid, bigint, bytea)',ARRAY['fa7997c018ee674b417e09472bac835a69b0cd965f7b9859f89536b0cb2c5317']::text[],'boolean','sql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['ns','rev','proof']::text[]),
            ('public.hosted_runtime_enter(uuid, bigint)',ARRAY['bcf16eeaf2b711c362ad7b65baa09276dd80cba1341529f7f94f004b0ddbf810']::text[],'bigint','sql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['ns','rev']::text[]),
            ('public.hosted_runtime_verified(uuid, bigint)',ARRAY['7dfb68c9052feb74e09a214fc2151a45766874d5e87ad0a36af18d695a0bb16c']::text[],'boolean','sql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['ns','rev']::text[]),
            ('public.hosted_runtime_expiry(uuid, bigint)',ARRAY['7b8ec8ff0ce04d481b95b815b9b44bc2416db7b6185af6a6d249e7f8e520edb9']::text[],'bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['ns','rev']::text[]),
            ('public.conversation_profile03_grant_billing(uuid, uuid)',ARRAY['2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3']::text[],'bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('public.payload_profile_writer_guard()',ARRAY['f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37']::text[],'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('public.payload_profile_writer_version()',CASE WHEN writer_installation=117 THEN ARRAY['887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6']::text[] ELSE ARRAY['ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9']::text[] END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_ready()',CASE WHEN writer_installation=117 THEN ARRAY['10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458']::text[] ELSE ARRAY['04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3']::text[] END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_json(json)',ARRAY['33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227']::text[],'text','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
            ('public.payload_profile_writer_global_guard()',ARRAY['b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106']::text[],'trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_catalog_guard()',ARRAY['07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a']::text[],'trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_graph()',ARRAY['93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061']::text[],'bytea','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_schema_ready()',ARRAY['7aa17580ac81a8f630b55797daee4fd22b178b236605f71c21491cb85e30865b','f4317324a9ba8ed8799696d4944d9382a847eaa98251e8d147353b159433102b']::text[],'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('public.hosted_runtime_role_safe()',ARRAY['898ddd403142d0b048b0e528c2b2ab9832ed3197ca86f1dc271e7d0ed7a26b9b','3aa8eb73d8355243b5181d500582d38609e5f5effe681bd14a8c8383f5db48c3']::text[],'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('public.hosted_runtime_projection(uuid)',ARRAY['25cd5c35228ee26a82bda8d04084a763681d209b4f17ec8e0e92b51e417ed72e','ba7fcf05e3069d2766bf90f7a868c52e55b2d9c1278bc9bb2279ce30e3b794c0']::text[],'public.hosted_billing_projections','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],ARRAY['owner_id']::text[])
          ) expected(signature,body_hashes,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
           IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=ANY(writer_expected.body_hashes)
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
              AND(SELECT count(*) FROM pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1) THEN
            RAISE EXCEPTION 'native hosted declaration or body inconsistent'; END IF;
          END LOOP;
 IF NOT(SELECT count(*)=117 AND min(version)=1 AND max(version)=117 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
   FROM public.payload_profile_writer_catalog WHERE singleton),false) THEN
  RAISE EXCEPTION 'reviewed V2 exact predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
  JOIN pg_class c ON c.oid='public.accounts'::regclass
  WHERE p.oid=to_regprocedure('public.conversation_reviewed_send03_v2_ready()')
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='8a55e518f59d690418ec2bb6ca60b8b2c4ce51dce1759bfdc579887c5772f3ec'
   AND p.proowner=c.relowner AND p.prorettype='boolean'::regtype
   AND l.lanname='sql' AND p.provolatile='s' AND NOT p.proisstrict
   AND NOT p.prosecdef AND NOT p.proretset AND p.proparallel='u' AND p.prokind='f'
   AND p.pronargdefaults=0 AND p.provariadic=0 AND p.pronargs=0
   AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
   AND p.proconfig=ARRAY['search_path=pg_catalog']
   AND(SELECT count(*) FROM pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1) THEN
  RAISE EXCEPTION 'reviewed V2 predecessor helper inconsistent' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;


-- Fresh first-origin metadata only. This does not initialize Android providers,
-- verify a signature, adopt legacy aliases, create a capture counter or permit SMS.
-- Original pairing metadata is copied before its normal pruning; no secrets or
-- invented approver/session/SPKI evidence are retained. All history lasts until
-- account erasure, independently of device, pairing and content deletion.

CREATE TABLE public.device_protection_origins (
account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
device_id uuid NOT NULL,setup_id uuid NOT NULL,opening_id uuid NOT NULL,command_id uuid NOT NULL,
source_pairing_id uuid NOT NULL,created_by_user_id uuid NOT NULL,
origin_digest bytea NOT NULL CHECK(octet_length(origin_digest)=32),
enrolled_point bytea NOT NULL CHECK(octet_length(enrolled_point)=65 AND get_byte(enrolled_point,0)=4),
enrolled_key_id bytea NOT NULL CHECK(octet_length(enrolled_key_id)=32),
enrolled_fingerprint bytea NOT NULL CHECK(enrolled_fingerprint=sha256(enrolled_point)),
opening_nonce bytea NOT NULL CHECK(octet_length(opening_nonce)=32),created_ms bigint NOT NULL CHECK(created_ms>0),
pairing_created_ms bigint NOT NULL CHECK(pairing_created_ms>0),pairing_claimed_ms bigint NOT NULL,
pairing_proof_verified_ms bigint NOT NULL,pairing_approved_ms bigint NOT NULL,pairing_expires_ms bigint NOT NULL,
opened_site_id text NOT NULL CHECK(octet_length(opened_site_id) BETWEEN 1 AND 256),
opened_instance_id text NOT NULL CHECK(octet_length(opened_instance_id) BETWEEN 1 AND 256),
opened_connection_epoch bigint NOT NULL CHECK(opened_connection_epoch>0),
opened_deployment_epoch bigint NOT NULL CHECK(opened_deployment_epoch>0),
PRIMARY KEY(account_id,opening_id),UNIQUE(account_id,device_id),UNIQUE(account_id,enrolled_point),
UNIQUE(account_id,source_pairing_id),UNIQUE(account_id,setup_id),UNIQUE(account_id,command_id),
CHECK(created_ms>=pairing_approved_ms AND pairing_created_ms<=pairing_claimed_ms AND pairing_claimed_ms<=pairing_proof_verified_ms
 AND pairing_proof_verified_ms<=pairing_approved_ms AND pairing_approved_ms<pairing_expires_ms),
CHECK(enrolled_key_id=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||enrolled_point))
);

ALTER TABLE public.device_protection_origins ADD CONSTRAINT device_protection_origins_identities CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid AND setup_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid AND command_id<>'00000000-0000-0000-0000-000000000000'::uuid AND source_pairing_id<>'00000000-0000-0000-0000-000000000000'::uuid AND created_by_user_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE TABLE public.device_protection_associations (
account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,opening_id uuid NOT NULL,
association bytea NOT NULL CHECK(octet_length(association)=329),
association_sha256 bytea NOT NULL CHECK(association_sha256=sha256(association)),
hmac_probe bytea NOT NULL CHECK(octet_length(hmac_probe)=32),aes_probe bytea NOT NULL CHECK(octet_length(aes_probe)=120),
aes_probe_sha256 bytea NOT NULL CHECK(aes_probe_sha256=sha256(aes_probe)),
canary_point bytea NOT NULL CHECK(octet_length(canary_point)=65 AND get_byte(canary_point,0)=4),
canary_key_id bytea NOT NULL CHECK(canary_key_id=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||canary_point)),
created_ms bigint NOT NULL CHECK(created_ms>0),PRIMARY KEY(account_id,opening_id),UNIQUE(account_id,canary_point),
FOREIGN KEY(account_id,opening_id) REFERENCES public.device_protection_origins(account_id,opening_id)
 DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE public.device_protection_associations ADD CONSTRAINT device_protection_associations_identities CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE TABLE public.device_protection_attempts (
account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,device_id uuid NOT NULL,
setup_id uuid NOT NULL,opening_id uuid NOT NULL,command_id uuid NOT NULL,proof_request_id uuid NOT NULL,attempt_id uuid NOT NULL,
nonce bytea NOT NULL CHECK(octet_length(nonce)=32),association_sha256 bytea NOT NULL CHECK(octet_length(association_sha256)=32),
core bytea NOT NULL CHECK(octet_length(core)=393),core_sha256 bytea NOT NULL CHECK(core_sha256=sha256(core)),
issued_ms bigint NOT NULL CHECK(issued_ms>0),expires_ms bigint NOT NULL CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=30000),
proof_site_id text NOT NULL CHECK(octet_length(proof_site_id) BETWEEN 1 AND 256),
proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id) BETWEEN 1 AND 256),
proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
previous_attempt_id uuid,previous_core_sha256 bytea CHECK(previous_core_sha256 IS NULL OR octet_length(previous_core_sha256)=32),
previous_bundle_sha256 bytea CHECK(previous_bundle_sha256 IS NULL OR octet_length(previous_bundle_sha256)=32),
recovery_window_started_ms bigint,recovery_window_ordinal smallint,
closed_ms bigint,closed_bundle_sha256 bytea CHECK(closed_bundle_sha256 IS NULL OR octet_length(closed_bundle_sha256)=32),
superseded_by_proof_request_id uuid,superseded_by_attempt_id uuid,
PRIMARY KEY(account_id,proof_request_id),UNIQUE(account_id,attempt_id),
FOREIGN KEY(account_id,opening_id) REFERENCES public.device_protection_associations(account_id,opening_id) DEFERRABLE INITIALLY DEFERRED,
FOREIGN KEY(account_id,previous_attempt_id) REFERENCES public.device_protection_attempts(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
FOREIGN KEY(account_id,superseded_by_attempt_id) REFERENCES public.device_protection_attempts(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
CHECK((previous_attempt_id IS NULL)=(previous_core_sha256 IS NULL)
 AND(previous_attempt_id IS NULL)=(recovery_window_started_ms IS NULL)
 AND(previous_attempt_id IS NULL)=(recovery_window_ordinal IS NULL)),
CHECK(previous_attempt_id IS NOT NULL OR previous_bundle_sha256 IS NULL),
CHECK(recovery_window_started_ms IS NULL OR recovery_window_started_ms>0 AND recovery_window_started_ms<=issued_ms
 AND issued_ms-recovery_window_started_ms<86400000 AND recovery_window_ordinal BETWEEN 1 AND 16),
CHECK((closed_ms IS NULL)=(superseded_by_proof_request_id IS NULL) AND(closed_ms IS NULL)=(superseded_by_attempt_id IS NULL)),
CHECK(closed_ms IS NOT NULL OR closed_bundle_sha256 IS NULL),CHECK(closed_ms IS NULL OR closed_ms>=issued_ms),
CHECK(previous_attempt_id IS NULL OR previous_attempt_id<>attempt_id),
CHECK(superseded_by_attempt_id IS NULL OR superseded_by_attempt_id<>attempt_id)
);

ALTER TABLE public.device_protection_attempts ADD CONSTRAINT device_protection_attempts_identities CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid AND setup_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid AND command_id<>'00000000-0000-0000-0000-000000000000'::uuid AND proof_request_id<>'00000000-0000-0000-0000-000000000000'::uuid AND attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE TABLE public.device_protection_receipts (
account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,device_id uuid NOT NULL,
setup_id uuid NOT NULL,opening_id uuid NOT NULL,command_id uuid NOT NULL,proof_request_id uuid NOT NULL,attempt_id uuid NOT NULL,
association_sha256 bytea NOT NULL CHECK(octet_length(association_sha256)=32),core_sha256 bytea NOT NULL CHECK(octet_length(core_sha256)=32),
bundle bytea NOT NULL CHECK(octet_length(bundle)=521),bundle_sha256 bytea NOT NULL CHECK(bundle_sha256=sha256(bundle)),
accepted_ms bigint NOT NULL CHECK(accepted_ms>0),
accepted_site_id text NOT NULL CHECK(octet_length(accepted_site_id) BETWEEN 1 AND 256),
accepted_instance_id text NOT NULL CHECK(octet_length(accepted_instance_id) BETWEEN 1 AND 256),
accepted_connection_epoch bigint NOT NULL CHECK(accepted_connection_epoch>0),accepted_deployment_epoch bigint NOT NULL CHECK(accepted_deployment_epoch>0),
PRIMARY KEY(account_id,opening_id),UNIQUE(account_id,attempt_id),UNIQUE(account_id,proof_request_id),
FOREIGN KEY(account_id,opening_id) REFERENCES public.device_protection_origins(account_id,opening_id) DEFERRABLE INITIALLY DEFERRED,
FOREIGN KEY(account_id,attempt_id) REFERENCES public.device_protection_attempts(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE public.device_protection_receipts ADD CONSTRAINT device_protection_receipts_identities CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid AND setup_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid AND command_id<>'00000000-0000-0000-0000-000000000000'::uuid AND proof_request_id<>'00000000-0000-0000-0000-000000000000'::uuid AND attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE TABLE public.device_protection_retirements (
account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,opening_id uuid NOT NULL,
device_id uuid NOT NULL,enrolled_key_id bytea NOT NULL CHECK(octet_length(enrolled_key_id)=32),
reason text NOT NULL CHECK(reason IN('device_revoked','device_deleted','device_identity_changed',
 'enrollment_revoked','enrollment_deleted','enrollment_identity_changed')),
retired_ms bigint NOT NULL CHECK(retired_ms>0),PRIMARY KEY(account_id,opening_id),
FOREIGN KEY(account_id,opening_id) REFERENCES public.device_protection_origins(account_id,opening_id) DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE public.device_protection_retirements ADD CONSTRAINT device_protection_retirements_identities CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid AND opening_id<>'00000000-0000-0000-0000-000000000000'::uuid AND device_id<>'00000000-0000-0000-0000-000000000000'::uuid);

CREATE UNIQUE INDEX device_protection_one_unclosed ON public.device_protection_attempts(account_id,opening_id) WHERE closed_ms IS NULL;

-- Only a distinct, source-coupled family can reserve the installation canary.
ALTER TABLE public.known_signing_point_reservations DROP CONSTRAINT known_signing_point_reservations_family_check;
ALTER TABLE public.known_signing_point_reservations ADD CONSTRAINT known_signing_point_reservations_family_check
 CHECK(family IN('sealed_root','sms_approval','line_device','browser_content03','protection_canary'));
ALTER TABLE public.known_signing_role_claims DROP CONSTRAINT known_signing_role_claims_role_check;
ALTER TABLE public.known_signing_role_claims ADD CONSTRAINT known_signing_role_claims_role_check
 CHECK(role IN('sealed_root','sms_approval','line_approval','device_auth','browser_content03','protection_canary'));

-- No caller flag, role copy or lock-ownership observation supplies authority.
CREATE FUNCTION public.device_protection_mode(account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE state text; epoch bigint;
BEGIN
 IF account IS NULL OR account='00000000-0000-0000-0000-000000000000'::uuid OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'protection account unavailable' USING ERRCODE='23514'; END IF;
 PERFORM public.hosted_runtime_marker();
 -- A root may not exist yet. If present, retain the established root-first order.
 PERFORM 1 FROM public.sealed_manifest_authorities WHERE account_id=account FOR SHARE NOWAIT;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN
  RAISE EXCEPTION 'protection account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR state<>'live' OR epoch NOT IN(0,1) OR(epoch=1 AND NOT public.payload_profile_epoch_valid(account,epoch)) THEN
  RAISE EXCEPTION 'protection account anchor unavailable' USING ERRCODE='23514'; END IF;
 -- Known-role insertion takes this same lock. NOWAIT avoids a later blocking upgrade.
 PERFORM 1 FROM public.accounts WHERE id=account FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'protection account absent' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.device_protection_actor(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE point bytea; expiry bigint; namespace public.hosted_billing_namespaces%ROWTYPE;
BEGIN
 PERFORM public.device_protection_mode(account);
 PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'protection account disabled' USING ERRCODE='23514'; END IF;
 IF device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL
  OR octet_length(site) NOT BETWEEN 1 AND 256 OR octet_length(instance) NOT BETWEEN 1 AND 256
  OR connection_epoch<=0 OR deployment_epoch<=0 THEN RAISE EXCEPTION 'protection actor input differs' USING ERRCODE='23514'; END IF;
 SELECT k.signing_key_sec1,floor(extract(epoch FROM s.lease_until)*1000)::bigint INTO point,expiry
  FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id)
  JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id)
  JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
  WHERE s.account_id=account AND s.device_id=device AND s.site_id=site AND s.instance_id=instance
   AND s.connection_epoch=device_protection_actor.connection_epoch AND s.deployment_epoch=device_protection_actor.deployment_epoch AND s.deployment_epoch=a.epoch
   AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL
   AND k.fingerprint=sha256(k.signing_key_sec1) AND t.enabled AND NOT t.draining
  FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'current protection actor unavailable' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT FROM public.device_protection_origins o LEFT JOIN public.device_protection_retirements r USING(account_id,opening_id)
   WHERE o.account_id=account AND(o.device_id=device OR o.enrolled_point=point)
    AND(r.opening_id IS NOT NULL OR o.device_id<>device OR o.enrolled_point<>point)) THEN
  RAISE EXCEPTION 'original protection actor retired or changed' USING ERRCODE='23514'; END IF;
 namespace:=public.hosted_runtime_marker();
 IF namespace.namespace_id IS NOT NULL THEN expiry:=least(expiry,public.hosted_runtime_expiry(namespace.namespace_id,namespace.policy_revision)); END IF;
 IF expiry<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN
  RAISE EXCEPTION 'protection actor lease expired after waits' USING ERRCODE='23514'; END IF;
 RETURN expiry;
END;
$function$;

CREATE FUNCTION public.device_protection_lock(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 PERFORM public.device_protection_actor(account,device,site,instance,connection_epoch,deployment_epoch);
END;
$function$;

CREATE FUNCTION public.device_protection_open(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,setup uuid,opening uuid,command uuid,origin_digest bytea)
RETURNS SETOF public.device_protection_origins
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.device_protection_origins%ROWTYPE; pairing public.pairing_requests%ROWTYPE; key public.device_keys%ROWTYPE;
BEGIN
 PERFORM public.device_protection_lock(account,device,site,instance,connection_epoch,deployment_epoch);
 IF setup IS NULL OR opening IS NULL OR command IS NULL OR origin_digest IS NULL OR octet_length(origin_digest)<>32 THEN
  RAISE EXCEPTION 'protection opening input differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.device_protection_origins o WHERE o.account_id=account AND o.device_id=device;
 IF FOUND THEN
  IF(row.setup_id,row.opening_id,row.command_id,row.origin_digest) IS DISTINCT FROM(setup,opening,command,origin_digest) THEN
   RAISE EXCEPTION 'original protection opening differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row;RETURN;
 END IF;
 SELECT * INTO STRICT key FROM public.device_keys k WHERE k.account_id=account AND k.device_id=device FOR SHARE NOWAIT;
 SELECT * INTO pairing FROM public.pairing_requests p WHERE p.account_id=account AND p.id=key.source_pairing_id
  AND p.device_id=device AND p.signing_key_sec1=key.signing_key_sec1 AND p.key_fingerprint=key.fingerprint
  AND p.cancelled_at IS NULL AND p.created_at<=p.claimed_at AND p.claimed_at<=p.proof_verified_at
  AND p.proof_verified_at<=p.approved_at AND p.approved_at<p.expires_at FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'genuine retained pairing source unavailable' USING ERRCODE='23514'; END IF;
 row.account_id:=account;row.device_id:=device;row.setup_id:=setup;row.opening_id:=opening;row.command_id:=command;
 row.source_pairing_id:=pairing.id;row.created_by_user_id:=pairing.created_by_user_id;row.origin_digest:=origin_digest;
 row.enrolled_point:=key.signing_key_sec1;row.enrolled_fingerprint:=key.fingerprint;
 row.enrolled_key_id:=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||key.signing_key_sec1);
 row.opening_nonce:=uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid());
 row.created_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row.pairing_created_ms:=floor(extract(epoch FROM pairing.created_at)*1000)::bigint;
 row.pairing_claimed_ms:=floor(extract(epoch FROM pairing.claimed_at)*1000)::bigint;
 row.pairing_proof_verified_ms:=floor(extract(epoch FROM pairing.proof_verified_at)*1000)::bigint;
 row.pairing_approved_ms:=floor(extract(epoch FROM pairing.approved_at)*1000)::bigint;
 row.pairing_expires_ms:=floor(extract(epoch FROM pairing.expires_at)*1000)::bigint;
 row.opened_site_id:=site;row.opened_instance_id:=instance;row.opened_connection_epoch:=connection_epoch;row.opened_deployment_epoch:=deployment_epoch;
 INSERT INTO public.device_protection_origins SELECT row.*;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.device_protection_association(account uuid,opening uuid,association bytea,aes_probe bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE o public.device_protection_origins%ROWTYPE;
BEGIN
 SELECT * INTO STRICT o FROM public.device_protection_origins r WHERE r.account_id=account AND r.opening_id=opening;
 IF association IS NULL OR aes_probe IS NULL OR octet_length(association)<>329 OR octet_length(aes_probe)<>120
  OR substring(association FROM 1 FOR 8)<>decode('5a54504101010000','hex')
  OR substring(association FROM 9 FOR 256) IS DISTINCT FROM(uuid_send(o.account_id)||uuid_send(o.device_id)||uuid_send(o.setup_id)
   ||uuid_send(o.opening_id)||uuid_send(o.command_id)||uuid_send(o.source_pairing_id)||o.origin_digest||o.enrolled_key_id||sha256(o.opening_nonce)
   ||substring(association FROM 201 FOR 32)||sha256(aes_probe))
  OR get_byte(association,264)<>4 OR substring(association FROM 265 FOR 65)=o.enrolled_point THEN
  RAISE EXCEPTION 'protection association original scope differs' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.device_protection_attempt(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,setup uuid,opening uuid,command uuid,proof_request uuid,association bytea,aes_probe bytea,previous_attempt uuid,previous_core_sha256 bytea,previous_bundle_sha256 bytea)
RETURNS SETOF public.device_protection_attempts
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.device_protection_attempts%ROWTYPE; prior public.device_protection_attempts%ROWTYPE;
 original public.device_protection_origins%ROWTYPE; linked public.device_protection_associations%ROWTYPE;
 expiry bigint; now_ms bigint; window_ms bigint; ordinal smallint;
BEGIN
 expiry:=public.device_protection_actor(account,device,site,instance,connection_epoch,deployment_epoch);
 SELECT * INTO original FROM public.device_protection_origins o WHERE o.account_id=account AND o.device_id=device
  AND(o.setup_id,o.opening_id,o.command_id)=(setup,opening,command);
 IF NOT FOUND OR proof_request IS NULL THEN RAISE EXCEPTION 'protection original opening unavailable' USING ERRCODE='23514'; END IF;
 PERFORM public.device_protection_association(account,opening,association,aes_probe);
 IF(previous_attempt IS NULL)<>(previous_core_sha256 IS NULL) OR(previous_attempt IS NULL AND previous_bundle_sha256 IS NOT NULL)
  OR(previous_core_sha256 IS NOT NULL AND octet_length(previous_core_sha256)<>32)
  OR(previous_bundle_sha256 IS NOT NULL AND octet_length(previous_bundle_sha256)<>32) THEN
  RAISE EXCEPTION 'protection prior command shape differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.device_protection_attempts a WHERE a.account_id=account AND a.proof_request_id=proof_request;
 IF FOUND THEN
  SELECT * INTO STRICT linked FROM public.device_protection_associations a WHERE a.account_id=account AND a.opening_id=opening;
  IF(row.device_id,row.setup_id,row.opening_id,row.command_id,row.previous_attempt_id,row.previous_core_sha256,row.previous_bundle_sha256)
    IS DISTINCT FROM(device,setup,opening,command,previous_attempt,previous_core_sha256,previous_bundle_sha256)
   OR linked.association<>association OR linked.aes_probe<>aes_probe THEN
   RAISE EXCEPTION 'protection exact proof command differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row;RETURN;
 END IF;
 IF EXISTS(SELECT FROM public.device_protection_receipts r WHERE r.account_id=account AND r.opening_id=opening) THEN
  RAISE EXCEPTION 'original protection already accepted' USING ERRCODE='23514'; END IF;
 SELECT * INTO linked FROM public.device_protection_associations a WHERE a.account_id=account AND a.opening_id=opening;
 IF FOUND THEN
  IF linked.association<>association OR linked.aes_probe<>aes_probe OR previous_attempt IS NULL THEN
   RAISE EXCEPTION 'retained protection association differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO prior FROM public.device_protection_attempts a WHERE a.account_id=account AND a.opening_id=opening
   AND a.attempt_id=previous_attempt AND a.core_sha256=device_protection_attempt.previous_core_sha256 AND a.closed_ms IS NULL FOR UPDATE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'direct protection predecessor unavailable' USING ERRCODE='23514'; END IF;
 ELSE
  IF previous_attempt IS NOT NULL THEN RAISE EXCEPTION 'initial protection proof has predecessor' USING ERRCODE='23514'; END IF;
  linked.account_id:=account;linked.opening_id:=opening;linked.association:=association;linked.association_sha256:=sha256(association);
  linked.hmac_probe:=substring(association FROM 201 FOR 32);linked.aes_probe:=aes_probe;linked.aes_probe_sha256:=sha256(aes_probe);
  linked.canary_point:=substring(association FROM 265 FOR 65);
  linked.canary_key_id:=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||linked.canary_point);
  linked.created_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  INSERT INTO public.device_protection_associations SELECT linked.*;
  INSERT INTO public.known_signing_role_claims(account_id,signing_key_sec1,role) VALUES(account,linked.canary_point,'protection_canary');
 END IF;
 -- Actual primary sampling occurs after source/registry/ledger waits. A clock
 -- regression refuses rather than manufacturing a later clock or reopening history.
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF now_ms<original.created_ms OR now_ms<linked.created_ms OR expiry<=now_ms THEN
  RAISE EXCEPTION 'protection primary time unavailable' USING ERRCODE='23514'; END IF;
 IF prior.attempt_id IS NOT NULL THEN
  IF now_ms<prior.issued_ms THEN RAISE EXCEPTION 'protection recovery clock regressed' USING ERRCODE='23514'; END IF;
  SELECT a.recovery_window_started_ms,a.recovery_window_ordinal INTO window_ms,ordinal
   FROM public.device_protection_attempts a WHERE a.account_id=account AND a.device_id=device AND a.recovery_window_started_ms IS NOT NULL
   ORDER BY a.issued_ms DESC,a.recovery_window_ordinal DESC LIMIT 1;
  IF window_ms IS NULL OR now_ms-window_ms>=86400000 THEN window_ms:=now_ms;ordinal:=0; END IF;
  IF now_ms<window_ms OR ordinal>=16 THEN RAISE EXCEPTION 'protection explicit recovery budget exhausted' USING ERRCODE='23514'; END IF;
 END IF;
 row.account_id:=account;row.device_id:=device;row.setup_id:=setup;row.opening_id:=opening;row.command_id:=command;
 row.proof_request_id:=proof_request;row.attempt_id:=gen_random_uuid();row.nonce:=uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid());
 row.association_sha256:=linked.association_sha256;row.issued_ms:=now_ms;row.expires_ms:=least(now_ms+30000,expiry);
 row.proof_site_id:=site;row.proof_instance_id:=instance;row.proof_connection_epoch:=connection_epoch;row.proof_deployment_epoch:=deployment_epoch;
 row.previous_attempt_id:=previous_attempt;row.previous_core_sha256:=previous_core_sha256;row.previous_bundle_sha256:=previous_bundle_sha256;
 IF prior.attempt_id IS NOT NULL THEN row.recovery_window_started_ms:=window_ms;row.recovery_window_ordinal:=ordinal+1; END IF;
 row.core:=decode('5a54505201010000','hex')||substring(association FROM 9)||uuid_send(row.attempt_id)||int8send(row.issued_ms)||int8send(row.expires_ms)||sha256(row.nonce);
 row.core_sha256:=sha256(row.core);
 IF prior.attempt_id IS NOT NULL THEN
  UPDATE public.device_protection_attempts a SET closed_ms=now_ms,closed_bundle_sha256=device_protection_attempt.previous_bundle_sha256,
   superseded_by_proof_request_id=proof_request,superseded_by_attempt_id=row.attempt_id
   WHERE a.account_id=account AND a.attempt_id=prior.attempt_id;
 END IF;
 INSERT INTO public.device_protection_attempts SELECT row.*;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.device_protection_accept(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,setup uuid,opening uuid,command uuid,proof_request uuid,attempt uuid,bundle bytea)
RETURNS SETOF public.device_protection_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.device_protection_receipts%ROWTYPE; challenge public.device_protection_attempts%ROWTYPE; expiry bigint; now_ms bigint;
BEGIN
 expiry:=public.device_protection_actor(account,device,site,instance,connection_epoch,deployment_epoch);
 SELECT * INTO challenge FROM public.device_protection_attempts a WHERE a.account_id=account AND a.device_id=device
  AND(a.setup_id,a.opening_id,a.command_id,a.proof_request_id,a.attempt_id)=(setup,opening,command,proof_request,attempt);
 IF NOT FOUND OR bundle IS NULL OR octet_length(bundle)<>521 OR substring(bundle FROM 1 FOR 393)<>challenge.core THEN
  RAISE EXCEPTION 'protection original proof differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.device_protection_receipts r WHERE r.account_id=account AND r.opening_id=opening;
 IF FOUND THEN
  IF row.proof_request_id<>proof_request OR row.attempt_id<>attempt OR row.bundle<>bundle THEN
   RAISE EXCEPTION 'original protection acceptance differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row;RETURN;
 END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF challenge.closed_ms IS NOT NULL OR now_ms<challenge.issued_ms OR now_ms>=least(challenge.expires_ms,expiry) THEN
  RAISE EXCEPTION 'current protection proof window unavailable' USING ERRCODE='23514'; END IF;
 row.account_id:=account;row.device_id:=device;row.setup_id:=setup;row.opening_id:=opening;row.command_id:=command;
 row.proof_request_id:=proof_request;row.attempt_id:=attempt;row.association_sha256:=challenge.association_sha256;row.core_sha256:=challenge.core_sha256;
 row.bundle:=bundle;row.bundle_sha256:=sha256(bundle);row.accepted_ms:=now_ms;
 row.accepted_site_id:=site;row.accepted_instance_id:=instance;row.accepted_connection_epoch:=connection_epoch;row.accepted_deployment_epoch:=deployment_epoch;
 INSERT INTO public.device_protection_receipts SELECT row.*;
 RETURN NEXT row;
END;
$function$;

-- Every new record/closure changes the genuine same account-anchor tuple. An
-- old RR/SSI snapshot therefore cannot see a pre-opening/pre-retirement state
-- after obtaining the unchanged epoch. Historical reads/retries never touch it.
CREATE FUNCTION public.device_protection_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE account uuid; opening uuid; original public.device_protection_origins%ROWTYPE;
 linked public.device_protection_associations%ROWTYPE; challenge public.device_protection_attempts%ROWTYPE;
 pairing public.pairing_requests%ROWTYPE; key public.device_keys%ROWTYPE; expiry bigint; now_ms bigint; prior public.device_protection_attempts%ROWTYPE;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME NOT IN('device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements')
  OR TG_LEVEL<>'ROW' OR TG_OP NOT IN('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'protection row operation unsupported' USING ERRCODE='23514'; END IF;
 account:=coalesce(NEW.account_id,OLD.account_id);opening:=coalesce(NEW.opening_id,OLD.opening_id);
 IF TG_OP='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN OLD; END IF;
 PERFORM public.device_protection_mode(account);
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_NAME<>'device_protection_attempts' OR OLD.closed_ms IS NOT NULL OR NEW.closed_ms IS NULL
   OR NEW.superseded_by_attempt_id IS NULL OR NEW.superseded_by_proof_request_id IS NULL
   OR(to_jsonb(OLD)-ARRAY['closed_ms','closed_bundle_sha256','superseded_by_attempt_id','superseded_by_proof_request_id'])
    IS DISTINCT FROM(to_jsonb(NEW)-ARRAY['closed_ms','closed_bundle_sha256','superseded_by_attempt_id','superseded_by_proof_request_id'])
   OR EXISTS(SELECT FROM public.device_protection_receipts r WHERE r.account_id=account AND r.opening_id=opening) THEN
   RAISE EXCEPTION 'protection history cannot change' USING ERRCODE='23514'; END IF;
 ELSIF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'protection history cannot be erased' USING ERRCODE='23514';
 ELSIF TG_TABLE_NAME='device_protection_origins' THEN
  expiry:=public.device_protection_actor(account,NEW.device_id,NEW.opened_site_id,NEW.opened_instance_id,NEW.opened_connection_epoch,NEW.opened_deployment_epoch);
  SELECT * INTO STRICT key FROM public.device_keys k WHERE k.account_id=account AND k.device_id=NEW.device_id FOR SHARE NOWAIT;
  SELECT * INTO pairing FROM public.pairing_requests p WHERE p.account_id=account AND p.id=key.source_pairing_id
   AND p.id=NEW.source_pairing_id AND p.device_id=NEW.device_id AND p.cancelled_at IS NULL
   AND p.signing_key_sec1=key.signing_key_sec1 AND p.key_fingerprint=key.fingerprint
   AND p.created_by_user_id=NEW.created_by_user_id AND p.created_at<=p.claimed_at AND p.claimed_at<=p.proof_verified_at
   AND p.proof_verified_at<=p.approved_at AND p.approved_at<p.expires_at FOR SHARE NOWAIT;
  IF NOT FOUND OR NEW.enrolled_point<>key.signing_key_sec1 OR NEW.enrolled_fingerprint<>key.fingerprint
   OR(NEW.pairing_created_ms,NEW.pairing_claimed_ms,NEW.pairing_proof_verified_ms,NEW.pairing_approved_ms,NEW.pairing_expires_ms)
    IS DISTINCT FROM(floor(extract(epoch FROM pairing.created_at)*1000)::bigint,floor(extract(epoch FROM pairing.claimed_at)*1000)::bigint,
     floor(extract(epoch FROM pairing.proof_verified_at)*1000)::bigint,floor(extract(epoch FROM pairing.approved_at)*1000)::bigint,floor(extract(epoch FROM pairing.expires_at)*1000)::bigint) THEN
   RAISE EXCEPTION 'original protection source differs' USING ERRCODE='23514'; END IF;
  now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF NEW.created_ms>now_ms OR now_ms>=expiry THEN RAISE EXCEPTION 'protection opening time unavailable' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT original FROM public.device_protection_origins o WHERE o.account_id=account AND o.opening_id=opening;
  IF TG_TABLE_NAME='device_protection_associations' THEN
   PERFORM public.device_protection_association(account,opening,NEW.association,NEW.aes_probe);
   IF NEW.canary_point<>substring(NEW.association FROM 265 FOR 65) OR NEW.hmac_probe<>substring(NEW.association FROM 201 FOR 32)
    OR NEW.created_ms<original.created_ms OR NEW.created_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN
    RAISE EXCEPTION 'protection association differs' USING ERRCODE='23514'; END IF;
  ELSIF TG_TABLE_NAME='device_protection_attempts' THEN
   expiry:=public.device_protection_actor(account,NEW.device_id,NEW.proof_site_id,NEW.proof_instance_id,NEW.proof_connection_epoch,NEW.proof_deployment_epoch);
   SELECT * INTO STRICT linked FROM public.device_protection_associations a WHERE a.account_id=account AND a.opening_id=opening;
   now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
   IF(NEW.device_id,NEW.setup_id,NEW.command_id) IS DISTINCT FROM(original.device_id,original.setup_id,original.command_id)
    OR NEW.association_sha256<>linked.association_sha256 OR NEW.issued_ms<linked.created_ms OR NEW.issued_ms>now_ms
    OR now_ms>=NEW.expires_ms OR NEW.expires_ms>expiry
    OR NEW.core IS DISTINCT FROM(decode('5a54505201010000','hex')||substring(linked.association FROM 9)||uuid_send(NEW.attempt_id)
     ||int8send(NEW.issued_ms)||int8send(NEW.expires_ms)||sha256(NEW.nonce)) THEN
    RAISE EXCEPTION 'protection proof reservation differs' USING ERRCODE='23514'; END IF;
   IF NEW.previous_attempt_id IS NULL THEN
    IF EXISTS(SELECT FROM public.device_protection_attempts a WHERE a.account_id=account AND a.opening_id=opening) THEN
     RAISE EXCEPTION 'protection initial attempt already exists' USING ERRCODE='23514'; END IF;
   ELSE
    SELECT * INTO prior FROM public.device_protection_attempts a WHERE a.account_id=account AND a.opening_id=opening
     AND a.attempt_id=NEW.previous_attempt_id AND a.core_sha256=NEW.previous_core_sha256;
    IF NOT FOUND OR(prior.closed_ms,prior.closed_bundle_sha256,prior.superseded_by_proof_request_id,prior.superseded_by_attempt_id)
      IS DISTINCT FROM(NEW.issued_ms,NEW.previous_bundle_sha256,NEW.proof_request_id,NEW.attempt_id)
     OR NEW.recovery_window_started_ms>NEW.issued_ms THEN
     RAISE EXCEPTION 'protection direct recovery differs' USING ERRCODE='23514'; END IF;
    -- Budget is independently source-derived while the actual account fence is
    -- held; no caller ordinal/window can buy another explicit recovery.
    SELECT * INTO challenge FROM public.device_protection_attempts a WHERE a.account_id=account AND a.device_id=NEW.device_id
     AND a.recovery_window_started_ms IS NOT NULL ORDER BY a.issued_ms DESC,a.recovery_window_ordinal DESC LIMIT 1;
    IF challenge.attempt_id IS NULL OR NEW.issued_ms-challenge.recovery_window_started_ms>=86400000 THEN
     IF(NEW.recovery_window_started_ms,NEW.recovery_window_ordinal) IS DISTINCT FROM(NEW.issued_ms,1::smallint) THEN
      RAISE EXCEPTION 'protection recovery window differs' USING ERRCODE='23514'; END IF;
    ELSIF NEW.issued_ms<challenge.recovery_window_started_ms
     OR(NEW.recovery_window_started_ms,NEW.recovery_window_ordinal) IS DISTINCT FROM(challenge.recovery_window_started_ms,(challenge.recovery_window_ordinal+1)::smallint) THEN
     RAISE EXCEPTION 'protection recovery ordinal differs' USING ERRCODE='23514'; END IF;
   END IF;
  ELSIF TG_TABLE_NAME='device_protection_receipts' THEN
   expiry:=public.device_protection_actor(account,NEW.device_id,NEW.accepted_site_id,NEW.accepted_instance_id,NEW.accepted_connection_epoch,NEW.accepted_deployment_epoch);
   SELECT * INTO challenge FROM public.device_protection_attempts a WHERE a.account_id=account AND a.opening_id=opening
    AND a.proof_request_id=NEW.proof_request_id AND a.attempt_id=NEW.attempt_id;
   now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
   IF NOT FOUND OR(NEW.device_id,NEW.setup_id,NEW.command_id) IS DISTINCT FROM(original.device_id,original.setup_id,original.command_id)
    OR challenge.closed_ms IS NOT NULL OR NEW.association_sha256<>challenge.association_sha256 OR NEW.core_sha256<>challenge.core_sha256
    OR substring(NEW.bundle FROM 1 FOR 393)<>challenge.core OR NEW.accepted_ms<challenge.issued_ms OR NEW.accepted_ms>now_ms
    OR now_ms>=least(challenge.expires_ms,expiry) THEN RAISE EXCEPTION 'protection accepted original differs' USING ERRCODE='23514'; END IF;
  ELSIF TG_TABLE_NAME='device_protection_retirements' THEN
   IF(NEW.device_id,NEW.enrolled_key_id) IS DISTINCT FROM(original.device_id,original.enrolled_key_id)
    OR NOT(CASE NEW.reason
     WHEN 'device_deleted' THEN NOT EXISTS(SELECT FROM public.devices d WHERE(d.account_id,d.id)=(account,original.device_id))
     WHEN 'device_identity_changed' THEN NOT EXISTS(SELECT FROM public.devices d WHERE(d.account_id,d.id)=(account,original.device_id))
     WHEN 'device_revoked' THEN EXISTS(SELECT FROM public.devices d WHERE(d.account_id,d.id)=(account,original.device_id) AND d.revoked_at IS NOT NULL)
     WHEN 'enrollment_deleted' THEN NOT EXISTS(SELECT FROM public.device_keys k WHERE(k.account_id,k.device_id)=(account,original.device_id))
     WHEN 'enrollment_revoked' THEN EXISTS(SELECT FROM public.device_keys k WHERE(k.account_id,k.device_id)=(account,original.device_id) AND k.revoked_at IS NOT NULL)
     WHEN 'enrollment_identity_changed' THEN NOT EXISTS(SELECT FROM public.device_keys k WHERE(k.account_id,k.device_id)=(account,original.device_id)
      AND k.signing_key_sec1=original.enrolled_point AND k.fingerprint=original.enrolled_fingerprint AND k.source_pairing_id=original.source_pairing_id)
     ELSE false END) THEN RAISE EXCEPTION 'protection retirement lacks actual source transition' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 UPDATE public.payload_profile_account_anchors SET account_id=account_id WHERE account_id=account;
 RETURN NEW;
END;
$function$;

-- Deferred coupling never treats the SQL hash/row as a signature proof. It
-- prevents partial association/claim/attempt, forked closure or late acceptance.
CREATE FUNCTION public.device_protection_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE account uuid; opening uuid; linked public.device_protection_associations%ROWTYPE;
 challenge public.device_protection_attempts%ROWTYPE; successor public.device_protection_attempts%ROWTYPE;
 receipt public.device_protection_receipts%ROWTYPE; expiry bigint; now_ms bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'protection completion operation differs' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='known_signing_role_claims' THEN
  IF NEW.role<>'protection_canary' THEN RETURN NULL; END IF;
  account:=NEW.account_id;
  SELECT a.opening_id INTO opening FROM public.device_protection_associations a WHERE a.account_id=account AND a.canary_point=NEW.signing_key_sec1;
 ELSE account:=NEW.account_id;opening:=NEW.opening_id; END IF;
 IF NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN NULL; END IF;
 IF opening IS NULL THEN RAISE EXCEPTION 'protection canary claim orphaned' USING ERRCODE='23514'; END IF;
 PERFORM public.device_protection_mode(account);
 SELECT * INTO linked FROM public.device_protection_associations a WHERE a.account_id=account AND a.opening_id=opening;
 IF FOUND AND(NOT EXISTS(SELECT FROM public.device_protection_attempts a WHERE a.account_id=account AND a.opening_id=opening AND a.previous_attempt_id IS NULL)
  OR NOT EXISTS(SELECT FROM public.known_signing_role_claims k WHERE k.account_id=account AND k.signing_key_sec1=linked.canary_point AND k.role='protection_canary')) THEN
  RAISE EXCEPTION 'protection association incomplete' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='device_protection_attempts' THEN
  SELECT * INTO STRICT challenge FROM public.device_protection_attempts a WHERE a.account_id=account AND a.proof_request_id=NEW.proof_request_id;
  IF challenge.closed_ms IS NOT NULL THEN
   SELECT * INTO successor FROM public.device_protection_attempts a WHERE a.account_id=account
    AND a.proof_request_id=challenge.superseded_by_proof_request_id AND a.attempt_id=challenge.superseded_by_attempt_id;
   IF NOT FOUND OR(successor.opening_id,successor.previous_attempt_id,successor.previous_core_sha256,successor.previous_bundle_sha256,successor.issued_ms)
     IS DISTINCT FROM(opening,challenge.attempt_id,challenge.core_sha256,challenge.closed_bundle_sha256,challenge.closed_ms)
    OR EXISTS(SELECT FROM public.device_protection_receipts r WHERE r.account_id=account AND r.attempt_id=challenge.attempt_id) THEN
    RAISE EXCEPTION 'protection closure incomplete' USING ERRCODE='23514'; END IF;
  ELSIF TG_OP='INSERT' THEN
   expiry:=public.device_protection_actor(account,challenge.device_id,challenge.proof_site_id,challenge.proof_instance_id,challenge.proof_connection_epoch,challenge.proof_deployment_epoch);
   now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
   IF now_ms<challenge.issued_ms OR now_ms>=least(challenge.expires_ms,expiry) THEN
    RAISE EXCEPTION 'protection proof reservation expired before commit' USING ERRCODE='23514'; END IF;
  END IF;
 ELSIF TG_TABLE_NAME='device_protection_receipts' THEN
  SELECT * INTO STRICT receipt FROM public.device_protection_receipts r WHERE r.account_id=account AND r.opening_id=opening;
  SELECT * INTO STRICT challenge FROM public.device_protection_attempts a WHERE a.account_id=account AND a.attempt_id=receipt.attempt_id;
  expiry:=public.device_protection_actor(account,receipt.device_id,receipt.accepted_site_id,receipt.accepted_instance_id,receipt.accepted_connection_epoch,receipt.accepted_deployment_epoch);
  now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  IF challenge.closed_ms IS NOT NULL OR now_ms<receipt.accepted_ms OR now_ms>=least(challenge.expires_ms,expiry) THEN
   RAISE EXCEPTION 'protection acceptance expired before commit' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END;
$function$;

CREATE FUNCTION public.device_protection_retire() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE original public.device_protection_origins%ROWTYPE; reason text;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME NOT IN('devices','device_keys') OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP NOT IN('UPDATE','DELETE') THEN
  RAISE EXCEPTION 'protection retirement source differs' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM public.accounts WHERE id=OLD.account_id) THEN RETURN NULL; END IF;
 IF TG_TABLE_NAME='devices' THEN
  IF TG_OP='DELETE' THEN reason:='device_deleted';
  ELSIF(NEW.account_id,NEW.id) IS DISTINCT FROM(OLD.account_id,OLD.id) THEN reason:='device_identity_changed';
  ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN reason:='device_revoked'; END IF;
 ELSE
  IF TG_OP='DELETE' THEN reason:='enrollment_deleted';
  ELSIF(NEW.account_id,NEW.device_id,NEW.signing_key_sec1,NEW.fingerprint,NEW.source_pairing_id)
    IS DISTINCT FROM(OLD.account_id,OLD.device_id,OLD.signing_key_sec1,OLD.fingerprint,OLD.source_pairing_id) THEN reason:='enrollment_identity_changed';
  ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN reason:='enrollment_revoked'; END IF;
 END IF;
 IF reason IS NULL THEN RETURN NULL; END IF;
 FOR original IN SELECT o.* FROM public.device_protection_origins o WHERE o.account_id=OLD.account_id
  AND o.device_id=CASE WHEN TG_TABLE_NAME='devices' THEN(to_jsonb(OLD)->>'id')::uuid ELSE(to_jsonb(OLD)->>'device_id')::uuid END
  AND NOT EXISTS(SELECT FROM public.device_protection_retirements r WHERE(r.account_id,r.opening_id)=(o.account_id,o.opening_id)) LOOP
  PERFORM public.device_protection_mode(original.account_id);
  INSERT INTO public.device_protection_retirements VALUES(original.account_id,original.opening_id,original.device_id,original.enrolled_key_id,
   reason,floor(extract(epoch FROM clock_timestamp())*1000)::bigint);
 END LOOP;
 RETURN NULL;
END;
$function$;

DO $migration$
DECLARE relation_name text;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements'] LOOP
  EXECUTE format('CREATE TRIGGER device_protection_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.device_protection_rows_guard()',relation_name);
  EXECUTE format('CREATE TRIGGER device_protection_before_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.device_protection_rows_guard()',relation_name);
  EXECUTE format('CREATE CONSTRAINT TRIGGER device_protection_after_change AFTER INSERT OR UPDATE ON public.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.device_protection_complete()',relation_name);
 END LOOP;
END;
$migration$;
CREATE TRIGGER device_protection_device_changed AFTER UPDATE OR DELETE ON public.devices FOR EACH ROW EXECUTE FUNCTION public.device_protection_retire();
CREATE TRIGGER device_protection_enrollment_changed AFTER UPDATE OR DELETE ON public.device_keys FOR EACH ROW EXECUTE FUNCTION public.device_protection_retire();
CREATE CONSTRAINT TRIGGER device_protection_claim_complete AFTER INSERT ON public.known_signing_role_claims
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.device_protection_complete();

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
 IF relation_name IN('known_signing_point_reservations','known_signing_role_claims') AND(
  coalesce(new_row->>'family',old_row->>'family')='protection_canary' OR coalesce(new_row->>'role',old_row->>'role')='protection_canary') THEN
  IF operation='INSERT' AND EXISTS(SELECT FROM public.device_protection_associations a WHERE a.account_id=account
   AND new_row->>'signing_key_sec1'=to_jsonb(a)->>'canary_point') THEN RETURN; END IF;
  RAISE EXCEPTION 'protection canary requires its immutable original association' USING ERRCODE='23514';
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

CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=118 AND min(version)=1 AND max(version)=118 FROM public.schema_migrations
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE OR REPLACE FUNCTION public.hosted_runtime_native_schema_valid() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT public.hosted_runtime_role_safe() AND public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
 FROM public.payload_profile_writer_catalog WHERE singleton),false) AND NOT EXISTS(SELECT FROM pg_roles WHERE oid=(SESSION_USER::regrole)::oid AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SESSION_USER::regrole)::oid)
 AND NOT has_database_privilege((SESSION_USER::regrole)::oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass) AND a.grantee<>c.relowner)
 AND NOT EXISTS(SELECT FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass)
   AND x.grantee<>c.relowner AND(c.relname<>'hosted_runtime_requests' OR x.grantee<>(SESSION_USER::regrole)::oid))
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass)
  AND(has_table_privilege((SESSION_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege((SESSION_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT has_table_privilege((SESSION_USER::regrole)::oid,'public.hosted_runtime_requests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege((SESSION_USER::regrole)::oid,'public.hosted_runtime_requests','UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.hosted_runtime_requests'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND(has_column_privilege((SESSION_USER::regrole)::oid,a.attrelid,a.attname,'INSERT') IS DISTINCT FROM(a.attname IN('operation','namespace_id','policy_revision','proof'))
   OR has_column_privilege((SESSION_USER::regrole)::oid,a.attrelid,a.attname,'SELECT') IS DISTINCT FROM(a.attname='result')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
  AND has_function_privilege((SESSION_USER::regrole)::oid,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
   AND(a.grantee<>p.proowner AND(a.grantee<>(SESSION_USER::regrole)::oid OR p.proname NOT IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope'))))
$function$;

CREATE OR REPLACE FUNCTION public.hosted_runtime_identity_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready() AND public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
 FROM public.payload_profile_writer_catalog WHERE singleton),false) AND NOT EXISTS(SELECT FROM pg_roles WHERE oid=(CURRENT_USER::regrole)::oid AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(CURRENT_USER::regrole)::oid)
 AND NOT has_database_privilege((CURRENT_USER::regrole)::oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass) AND a.grantee<>c.relowner)
 AND NOT EXISTS(SELECT FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass,'public.hosted_runtime_requests'::regclass)
   AND x.grantee<>c.relowner AND(c.relname<>'hosted_runtime_requests' OR x.grantee<>(CURRENT_USER::regrole)::oid))
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.oid IN('public.hosted_runtime_secrets'::regclass,'public.hosted_runtime_sessions'::regclass,'public.hosted_runtime_entries'::regclass)
  AND(has_table_privilege((CURRENT_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege((CURRENT_USER::regrole)::oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT has_table_privilege((CURRENT_USER::regrole)::oid,'public.hosted_runtime_requests','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_any_column_privilege((CURRENT_USER::regrole)::oid,'public.hosted_runtime_requests','UPDATE,REFERENCES')
 AND NOT EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.hosted_runtime_requests'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND(has_column_privilege((CURRENT_USER::regrole)::oid,a.attrelid,a.attname,'INSERT') IS DISTINCT FROM(a.attname IN('operation','namespace_id','policy_revision','proof'))
   OR has_column_privilege((CURRENT_USER::regrole)::oid,a.attrelid,a.attname,'SELECT') IS DISTINCT FROM(a.attname='result')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
  AND has_function_privilege((CURRENT_USER::regrole)::oid,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%'
   AND(a.grantee<>p.proowner AND(a.grantee<>(CURRENT_USER::regrole)::oid OR p.proname NOT IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope'))))
$function$;

CREATE OR REPLACE FUNCTION public.hosted_runtime_scope() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE fence bigint;
BEGIN
 IF (public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
 FROM public.payload_profile_writer_catalog WHERE singleton),false) AND(SELECT count(*)=12 AND bool_and(revision>=0) FROM public.payload_profile_writer_global_fences)) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'hosted namespace scope schema unavailable' USING ERRCODE='23514'; END IF;
 -- This is an actual transaction-held absence/selection fence, not identity.
 -- Namespace transitions already take EXCLUSIVE and version this SAME tuple.
 fence:=('x'||substr(encode(sha256(convert_to('ZTSE/writer/global/v1:hosted_configuration','UTF8')),'hex'),1,16))::bit(64)::bigint;
 IF NOT pg_try_advisory_xact_lock_shared(fence) THEN
  RAISE EXCEPTION 'hosted namespace scope busy' USING ERRCODE='55P03'; END IF;
 PERFORM operation_class FROM public.payload_profile_writer_global_fences
  WHERE operation_class='hosted_configuration' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'hosted namespace scope missing' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_v2_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.conversation_reviewed_send03_ready()
 AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
  FROM public.payload_profile_writer_catalog WHERE singleton),false)
 AND EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.conversation_reviewed_sends03'::regclass
  AND a.attname='intent_version' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='smallint'::regtype
  AND a.attnotnull AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated=''
  -- Fast constant metadata defaults preserve existing V1 tuples without a
  -- rewrite. Logical restore materializes the value and removes this marker.
  AND(NOT a.atthasmissing OR a.attmissingval::text='{1}'))
 AND EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid='public.conversation_reviewed_sends03'::regclass
  AND a.attname='body_digest' AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid='bytea'::regtype
  AND NOT a.attnotnull AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated='')
$function$;


CREATE FUNCTION public.device_protection_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready()
 AND coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
  FROM public.payload_profile_writer_catalog WHERE singleton),false)
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname IN
  ('device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements')
  AND(NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%'
  AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN
   ('device_protection_lock','device_protection_open','device_protection_attempt','device_protection_accept','device_protection_ready')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE relation_name text;columns_sql text;routine record;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['device_protection_origins','device_protection_associations','device_protection_attempts','device_protection_receipts','device_protection_retirements'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
   WHERE attrelid=format('public.%I',relation_name)::regclass AND attnum>0 AND NOT attisdropped;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC',columns_sql,relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'device_protection_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('device_protection_lock','device_protection_open','device_protection_attempt','device_protection_accept','device_protection_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=118);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,118,public.payload_profile_writer_graph());
