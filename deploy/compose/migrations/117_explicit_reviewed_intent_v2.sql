-- SPDX-License-Identifier: AGPL-3.0-only
-- Explicit reviewed-intent V2; historical V1 remains passive and immutable.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=116; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'reviewed V2 requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation=116 THEN 'f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=116 THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113,114,115,116) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=116 THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113,114,115,116) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113,114,115,116) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE CASE WHEN writer_installation IN(112,113,114,115,116) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=116 THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=116 THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=116 THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=116 THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()',CASE WHEN writer_installation IN(115,116) THEN 'e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f' ELSE 'd2304db59ce15d94badb7e26f4a0e536a4551575b8b758db104fd4b4bdce1ab1' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation IN(115,116) THEN 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' ELSE '4f27879e1b1e350c79b0b8f661faefce941f6f1e4f852927fbe4b12ae06975a6' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()','483fe860358ee38b2ff5cf293aedaf18c2cc17ee1cafeb6dac0b8c9aefd1735d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)','006527b20f97d56582b26d006f80771a10a3d6007a154a990d45899803cbbb5f','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()','013423fe961e7c3d396be0bc4db8b238c295f233862c57f64c002df208cddf7d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(115,116) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=116 THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=116 THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_profile03_grant_mode(uuid)','88cc435625b02027cf88e09b93a5ece91be164073876b837750c6232d211c4f3','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_profile03_grant_issued(uuid, uuid)','660270fb3f84cc662d67a8734c49b254e460d82f3535975970c133aa8f73626e','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt']::text[]),
            ('conversation_profile03_grant_lock(uuid, uuid, uuid, text, text, bigint, bigint)','35544e458bd295ea65c292f85c165f7a68ab54833f39005fa6eb9072f97c4b1d','public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_issue(uuid, uuid, uuid, uuid, text, text, bigint, bigint, bigint)','d8694b4bd07a786211d3fc7b310a647f419e81703474ce4380faded7ad9e86f3','public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','attempt','device','site','instance','connection_epoch','deployment_epoch','permission_deadline_ms']::text[]),
            ('conversation_profile03_grant_rows_guard()','b3a9375ed664177dfb032755071667fa3ceb14dac1ce5e37c1712bb2f31cd427','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_complete()','027bcdfb9e932d3b00efde8cef3bafe6859d1681d82568b0b09bb42ab9085964','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_billing(uuid, uuid)',CASE WHEN writer_installation=116 THEN '2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3' ELSE 'cc1e70c70f7c3e2554eb14573dbeccc3307d1dad1b3cb049f979a20c11cdab1a' END,'bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('conversation_profile03_grant_usage_writer(uuid, text, text, jsonb, jsonb)','686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_profile03_grant_scope(uuid, uuid, uuid, text, text, bigint, bigint)','675959b6686692e2dde0995b4883cfffc45fbe47bbc1d31cd2bf425f50f9afa2','public.conversation_profile03_grants','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_same_scope(jsonb, jsonb)','89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['original','current_scope']::text[]),
            ('conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)','fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)','f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78','public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('alpha_message_effect_guard()','f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=116 THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=116 THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('public.hosted_runtime_native_schema_valid()',ARRAY['899ca98ace0d006efc0fde4e0fba02ef2f207fc112ad94f091013d2e9e503644']::text[],'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_identity_ready()',ARRAY['88de695db32691204e5126b0b5e003aadced6f61ec77918a00618f1e2f59a532']::text[],'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_scope()',ARRAY['604e7c39da10e1c34c5193dd04d5742637c611a40e3d7a28bf300ec066756dbe']::text[],'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('public.payload_profile_writer_version()',ARRAY['ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9']::text[],'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_ready()',ARRAY['04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3']::text[],'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_json(json)',ARRAY['fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba']::text[],'text','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
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
 IF NOT(SELECT count(*)=116 AND min(version)=1 AND max(version)=116 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph()
   FROM public.payload_profile_writer_catalog WHERE singleton),false) THEN
  RAISE EXCEPTION 'reviewed V2 exact predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;


-- Existing114 records are exactlyV1. Constant metadata default preserves
-- their original rows; no body, signature or acceptance history is rewritten.
ALTER TABLE public.conversation_reviewed_sends03
 ADD COLUMN intent_version smallint NOT NULL DEFAULT 1 CHECK(intent_version IN(1,2));
ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN intent_version DROP DEFAULT;
ALTER TABLE public.conversation_reviewed_sends03 ALTER COLUMN body_digest DROP NOT NULL;
ALTER TABLE public.conversation_reviewed_sends03 DROP CONSTRAINT conversation_reviewed_sends03_intent_check;
ALTER TABLE public.conversation_reviewed_sends03 ADD CONSTRAINT conversation_reviewed_sends03_intent_format_check CHECK(
 (intent_version=1 AND(body_digest IS NOT NULL OR redacted_ms IS NOT NULL)
  AND(intent IS NULL OR(octet_length(intent)>=624 AND octet_length(intent)<=835 AND substring(intent FROM 1 FOR 8)=decode('5a54524901030300','hex'))))
 OR(intent_version=2 AND body_digest IS NULL
  AND(intent IS NULL OR(octet_length(intent)>=592 AND octet_length(intent)<=803 AND substring(intent FROM 1 FOR 8)=decode('5a54524902030300','hex'))))
);


CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_parse(intent bytea) RETURNS public.conversation_reviewed_sends03
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; i integer; peer_length integer; count integer; tail integer;
 recipient bytea; previous bytea; role integer; device_count integer:=0; archive_count integer:=0;
BEGIN
 IF substring(intent FROM 1 FOR 8)=decode('5a54524901030300','hex') AND octet_length(intent) BETWEEN 624 AND 835 THEN
  row.intent_version:=1;tail:=552;
 ELSIF substring(intent FROM 1 FOR 8)=decode('5a54524902030300','hex') AND octet_length(intent) BETWEEN 592 AND 803 THEN
  row.intent_version:=2;tail:=520;
 ELSE RAISE EXCEPTION 'reviewed03 original versioned intent framing' USING ERRCODE='23514'; END IF;
 FOR i IN 0..7 LOOP IF substring(intent FROM 9+16*i FOR 16)=decode(repeat('00',16),'hex') THEN
  RAISE EXCEPTION 'reviewed03 zero identity' USING ERRCODE='23514'; END IF; END LOOP;
 FOR i IN 0..(CASE WHEN row.intent_version=1 THEN 10 ELSE 9 END) LOOP IF substring(intent FROM 201+32*i FOR 32)=decode(repeat('00',32),'hex') THEN
  RAISE EXCEPTION 'reviewed03 zero commitment' USING ERRCODE='23514'; END IF; END LOOP;
 row.account_id:=public.payload_profile_election_uuid(substring(intent FROM 9 FOR 16));
 row.device_id:=public.payload_profile_election_uuid(substring(intent FROM 25 FOR 16));
 row.line_id:=public.payload_profile_election_uuid(substring(intent FROM 41 FOR 16));
 row.binding_id:=public.payload_profile_election_uuid(substring(intent FROM 57 FOR 16));
 row.initiating_user_id:=public.payload_profile_election_uuid(substring(intent FROM 73 FOR 16));
 row.initiating_session_id:=public.payload_profile_election_uuid(substring(intent FROM 89 FOR 16));
 row.interval_id:=public.payload_profile_election_uuid(substring(intent FROM 105 FOR 16));
 row.message_id:=public.payload_profile_election_uuid(substring(intent FROM 121 FOR 16));
 row.binding_generation:=public.payload_profile_election_number(substring(intent FROM 137 FOR 8));
 row.vault_generation:=public.payload_profile_election_number(substring(intent FROM 145 FOR 8));
 row.manifest_version:=public.payload_profile_election_number(substring(intent FROM 153 FOR 8));
 row.selection_epoch:=public.payload_profile_election_number(substring(intent FROM 161 FOR 8));
 row.observed_ms:=public.payload_profile_election_number(substring(intent FROM 169 FOR 8));
 row.message_expires_ms:=public.payload_profile_election_number(substring(intent FROM 177 FOR 8));
 row.review_issued_ms:=public.payload_profile_election_number(substring(intent FROM 185 FOR 8));
 row.review_expires_ms:=public.payload_profile_election_number(substring(intent FROM 193 FOR 8));
 IF row.vault_generation<>1 OR row.selection_epoch<>1 OR row.observed_ms>row.review_issued_ms
  OR row.review_issued_ms>=row.review_expires_ms OR row.review_expires_ms>row.message_expires_ms
  OR row.review_expires_ms-row.review_issued_ms>30000 OR row.message_expires_ms-row.observed_ms>900000 THEN
  RAISE EXCEPTION 'reviewed03 original time scope' USING ERRCODE='23514'; END IF;
 row.selected_reader_key_id:=substring(intent FROM 201 FOR 32); row.root_fingerprint:=substring(intent FROM 233 FOR 32);
 row.manifest_digest:=substring(intent FROM 265 FOR 32); row.election_commitment:=substring(intent FROM 297 FOR 32);
 row.election_bundle_sha256:=substring(intent FROM 329 FOR 32); row.owner_session_digest:=substring(intent FROM 361 FOR 32);
 row.configured_origin_digest:=substring(intent FROM 393 FOR 32); row.signer_key_id:=substring(intent FROM 425 FOR 32);
 row.envelope_sha256:=substring(intent FROM 457 FOR 32); row.unsigned_digest:=substring(intent FROM 489 FOR 32); row.body_digest:=CASE WHEN row.intent_version=1 THEN substring(intent FROM 521 FOR 32) ELSE NULL END;
 peer_length:=get_byte(intent,tail);
 IF peer_length NOT BETWEEN 3 AND 16 THEN RAISE EXCEPTION 'reviewed03 peer width' USING ERRCODE='23514'; END IF;
 row.peer:=convert_from(substring(intent FROM tail+2 FOR peer_length),'UTF8');
 IF row.peer !~ '^\+[1-9][0-9]{1,14}$' THEN RAISE EXCEPTION 'reviewed03 peer shape' USING ERRCODE='23514'; END IF;
 count:=get_byte(intent,tail+1+peer_length);
 IF count NOT BETWEEN 2 AND 8 OR octet_length(intent)<>tail+3+peer_length+33*count THEN RAISE EXCEPTION 'reviewed03 recipient framing' USING ERRCODE='23514'; END IF;
 row.recipients:=substring(intent FROM tail+3+peer_length FOR 33*count);
 FOR i IN 0..count-1 LOOP
  recipient:=substring(row.recipients FROM 1+33*i FOR 33); role:=get_byte(recipient,0);
  IF role NOT BETWEEN 1 AND 3 OR substring(recipient FROM 2 FOR 32)=decode(repeat('00',32),'hex')
   OR(previous IS NOT NULL AND recipient<=previous) THEN RAISE EXCEPTION 'reviewed03 recipient selection order' USING ERRCODE='23514'; END IF;
  device_count:=device_count+CASE WHEN role=1 THEN 1 ELSE 0 END; archive_count:=archive_count+CASE WHEN role=2 THEN 1 ELSE 0 END;
  IF role=1 AND substring(recipient FROM 2 FOR 32)<>row.selected_reader_key_id THEN RAISE EXCEPTION 'reviewed03 physical reader differs' USING ERRCODE='23514'; END IF;
  previous:=recipient;
 END LOOP;
 IF device_count<>1 OR archive_count<>1 THEN RAISE EXCEPTION 'reviewed03 physical and archive readers required' USING ERRCODE='23514'; END IF;
 row.authenticated_segment_ceiling:=get_byte(intent,octet_length(intent)-1);
 IF row.authenticated_segment_ceiling NOT BETWEEN 1 AND 6 THEN RAISE EXCEPTION 'reviewed03 signed segment ceiling' USING ERRCODE='23514'; END IF;
 row.intent:=intent;row.intent_sha256:=sha256(intent);RETURN row;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_scope(account uuid,intent bytea,signature bytea,permission_deadline_ms bigint,admitted_ms bigint)
RETURNS public.conversation_reviewed_sends03
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; consent public.conversation_profile03_intervals%ROWTYPE;
 checked public.conversation_profile03_intervals%ROWTYPE; checked_ms bigint; deadline bigint; lease_until bigint; i integer; recipient bytea; expected bytea;
BEGIN
 IF account IS NULL OR intent IS NULL OR signature IS NULL OR octet_length(signature)<>64 OR permission_deadline_ms IS NULL OR admitted_ms IS NULL OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'reviewed03 admission input unavailable' USING ERRCODE='23514'; END IF;
 row:=public.conversation_reviewed_send03_parse(intent);
 IF row.intent_version<>2 THEN RAISE EXCEPTION 'reviewed03 new admission requires explicit V2 intent' USING ERRCODE='23514'; END IF;
 IF row.account_id<>account THEN RAISE EXCEPTION 'reviewed03 account differs' USING ERRCODE='23514'; END IF;
 consent:=public.conversation_profile03_interval_lock(account,row.interval_id);
 IF consent.phase<>'active' OR consent.owner_signature IS NULL OR consent.phone_signature IS NULL OR consent.installed_signature IS NULL OR consent.installed_ms IS NULL THEN
  RAISE EXCEPTION 'reviewed03 installed consent unavailable' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_profile03_interval_scope(account,consent.initiating_user_id,consent.initiating_session_id,consent.statement,false);
 IF(row.device_id,row.line_id,row.binding_id,row.initiating_user_id,row.initiating_session_id,row.binding_generation,row.vault_generation,row.manifest_version,
   row.selection_epoch,row.selected_reader_key_id,row.signer_key_id,row.root_fingerprint,row.manifest_digest,row.election_commitment,row.election_bundle_sha256,
   row.owner_session_digest,row.configured_origin_digest,row.peer)
  IS DISTINCT FROM(consent.device_id,consent.line_id,consent.binding_id,consent.initiating_user_id,consent.initiating_session_id,consent.binding_generation,consent.vault_generation,
   consent.manifest_version,consent.selection_epoch,consent.selected_reader_key_id,consent.browser_signer_key_id,consent.root_fingerprint,consent.manifest_digest,
   consent.election_commitment,consent.election_bundle_sha256,consent.owner_session_digest,consent.configured_origin_digest,consent.peer)
  OR(checked.device_session_digest,checked.physical_selection_digest,checked.proof_site_id,checked.proof_instance_id,checked.proof_connection_epoch,checked.proof_deployment_epoch)
   IS DISTINCT FROM(consent.device_session_digest,consent.physical_selection_digest,consent.proof_site_id,consent.proof_instance_id,consent.proof_connection_epoch,consent.proof_deployment_epoch) THEN
  RAISE EXCEPTION 'reviewed03 original consent selection differs' USING ERRCODE='23514'; END IF;
 expected:=decode('01','hex')||consent.selected_reader_key_id||decode('02','hex')||consent.archive_reader_key_id;
 IF octet_length(consent.integration_readers)>0 THEN FOR i IN 0..octet_length(consent.integration_readers)/64-1 LOOP
  expected:=expected||decode('03','hex')||substring(consent.integration_readers FROM 33+64*i FOR 32);
 END LOOP; END IF;
 IF row.recipients<>expected THEN RAISE EXCEPTION 'reviewed03 complete installed reader set differs' USING ERRCODE='23514'; END IF;
 SELECT floor(extract(epoch FROM s.lease_until)*1000)::bigint INTO lease_until FROM public.device_sessions s WHERE s.account_id=account AND s.device_id=consent.device_id
  AND(s.site_id,s.instance_id,s.connection_epoch,s.deployment_epoch)=(consent.proof_site_id,consent.proof_instance_id,consent.proof_connection_epoch,consent.proof_deployment_epoch);
 deadline:=least(consent.interval_expires_ms,public.payload_profile_selection_owner(account,consent.initiating_user_id,consent.initiating_session_id),lease_until);
 checked_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF lease_until IS NULL OR row.observed_ms<consent.installed_ms OR row.review_issued_ms>admitted_ms OR admitted_ms>checked_ms
  OR admitted_ms>=row.review_expires_ms OR row.message_expires_ms>deadline OR permission_deadline_ms>least(deadline,row.review_expires_ms)
  OR checked_ms>=permission_deadline_ms OR permission_deadline_ms<=admitted_ms THEN RAISE EXCEPTION 'reviewed03 actual admission deadline expired' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.usage_quota_policies p WHERE p.account_id=account AND p.metric='outbound_message' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'reviewed03 finite outbound quota not configured' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT FROM public.recipient_suppressions s WHERE s.account_id=account AND s.recipient_e164=row.peer AND s.active)
  OR EXISTS(SELECT FROM public.owner_recipient_holds h WHERE h.account_id=account AND h.recipient_e164=row.peer AND h.released_at IS NULL) THEN
  RAISE EXCEPTION 'reviewed03 recipient unavailable' USING ERRCODE='23514'; END IF;
 row.interval_receipt_id:=consent.receipt_id;row.election_challenge_id:=consent.election_challenge_id;row.original_binding_id:=consent.original_binding_id;
 row.physical_refresh_id:=consent.physical_refresh_id;row.physical_source_kind:=consent.physical_source_kind;
 row.device_session_digest:=consent.device_session_digest;row.physical_selection_digest:=consent.physical_selection_digest;row.interval_statement_sha256:=consent.statement_sha256;
 row.proof_site_id:=consent.proof_site_id;row.proof_instance_id:=consent.proof_instance_id;row.proof_connection_epoch:=consent.proof_connection_epoch;row.proof_deployment_epoch:=consent.proof_deployment_epoch;
 row.signature:=signature;row.signature_sha256:=sha256(signature);row.admitted_ms:=admitted_ms;row.permission_deadline_ms:=permission_deadline_ms;
 RETURN row;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_admit(account uuid,"interval" uuid,message uuid,intent bytea,signature bytea,envelope bytea,permission_deadline_ms bigint)
RETURNS SETOF public.conversation_reviewed_sends03
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; previous public.conversation_reviewed_sends03%ROWTYPE; checked_ms bigint;
BEGIN
 IF account IS NULL OR "interval" IS NULL OR message IS NULL OR intent IS NULL OR signature IS NULL OR envelope IS NULL OR permission_deadline_ms IS NULL THEN
  RAISE EXCEPTION 'reviewed03 original admission input unavailable' USING ERRCODE='23514'; END IF;
 IF substring(intent FROM 1 FOR 8)<>decode('5a54524902030300','hex') THEN
  RAISE EXCEPTION 'reviewed03 historical V1 is not a new admission' USING ERRCODE='23514'; END IF;
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

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE checked public.conversation_reviewed_sends03%ROWTYPE;
BEGIN
 IF TG_RELID<>'public.conversation_reviewed_sends03'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'reviewed03 original trigger context' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT FROM public.accounts a WHERE a.id=OLD.account_id)
   OR NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=OLD.account_id AND m.id=OLD.message_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'reviewed03 retained identity requires actual parent erasure' USING ERRCODE='23514';
 ELSIF TG_OP='INSERT' THEN
  checked:=public.conversation_reviewed_send03_scope(NEW.account_id,NEW.intent,NEW.signature,NEW.permission_deadline_ms,NEW.admitted_ms);
  IF NEW IS DISTINCT FROM checked THEN RAISE EXCEPTION 'reviewed03 captured source differs' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' THEN
  IF OLD.redacted_ms IS NOT NULL OR NEW.redacted_ms IS NULL OR NEW.redacted_ms<OLD.admitted_ms
   OR NEW.redacted_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR NEW.intent IS NOT NULL OR NEW.signature IS NOT NULL OR NEW.peer IS NOT NULL OR NEW.body_digest IS NOT NULL
   OR(to_jsonb(NEW)-ARRAY['intent','signature','peer','body_digest','redacted_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['intent','signature','peer','body_digest','redacted_ms'])
   OR NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=OLD.account_id AND m.id=OLD.message_id AND m.transport_mode='sealed_profile03'
    AND m.recipient_e164 IS NULL AND m.transport_payload IS NULL AND m.state IN('delivered','failed','cancelled','expired'))
   OR EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=OLD.account_id AND f.message_id=OLD.message_id AND f.outcome IN('granted','submitting','unknown')) THEN
   RAISE EXCEPTION 'reviewed03 originals cannot change or resurrect' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'reviewed03 unsupported original mutation' USING ERRCODE='23514';
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_message_redact() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 IF TG_RELID<>'public.messages'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP<>'UPDATE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'reviewed03 content redaction trigger differs' USING ERRCODE='23514'; END IF;
 IF OLD.transport_mode='sealed_profile03' AND OLD.transport_payload IS NOT NULL AND NEW.transport_payload IS NULL AND NEW.recipient_e164 IS NULL THEN
  UPDATE public.conversation_reviewed_sends03 r SET intent=NULL,signature=NULL,peer=NULL,body_digest=NULL,redacted_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
   WHERE r.account_id=NEW.account_id AND r.message_id=NEW.id AND r.redacted_ms IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'reviewed03 original content erasure unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_writer(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; checked public.conversation_reviewed_sends03%ROWTYPE; wanted uuid;
BEGIN
 IF epoch<>1 OR account IS NULL OR relation_name NOT IN('messages','dispatch_jobs') OR operation NOT IN('INSERT','UPDATE','DELETE') THEN
  RAISE EXCEPTION 'reviewed03 typed writer context differs' USING ERRCODE='23514'; END IF;
 wanted:=CASE WHEN relation_name='messages' THEN coalesce((new_row->>'id')::uuid,(old_row->>'id')::uuid)
  ELSE coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid) END;
 SELECT * INTO row FROM public.conversation_reviewed_sends03 r WHERE r.account_id=account AND r.message_id=wanted;
 IF NOT FOUND THEN RAISE EXCEPTION 'reviewed03 retained admission unavailable' USING ERRCODE='23514'; END IF;
 IF operation='DELETE' THEN PERFORM public.conversation_reviewed_send03_erasure_fence(account);RETURN; END IF;
 IF relation_name='messages' AND operation='UPDATE' THEN
  IF old_row->>'recipient_e164' IS NOT NULL AND old_row->>'transport_payload' IS NOT NULL AND new_row->>'recipient_e164' IS NULL AND new_row->>'transport_payload' IS NULL
   AND(old_row-ARRAY['recipient_e164','transport_payload'])=(new_row-ARRAY['recipient_e164','transport_payload'])
   AND old_row->>'state' IN('delivered','failed','cancelled','expired') AND row.redacted_ms IS NULL
   AND NOT EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.message_id=wanted AND f.outcome IN('granted','submitting','unknown')) THEN
   PERFORM public.conversation_reviewed_send03_erasure_fence(account);RETURN; END IF;
  RAISE EXCEPTION 'reviewed03 message update requires separate typed effect or erasure' USING ERRCODE='23514';
 END IF;
 IF row.intent_version<>2 THEN RAISE EXCEPTION 'reviewed03 V1 is historical only' USING ERRCODE='23514'; END IF;
 IF operation<>'INSERT' OR row.redacted_ms IS NOT NULL THEN RAISE EXCEPTION 'reviewed03 cannot requeue or restore erased content' USING ERRCODE='23514'; END IF;
 checked:=public.conversation_reviewed_send03_scope(account,row.intent,row.signature,row.permission_deadline_ms,row.admitted_ms);
 IF row IS DISTINCT FROM checked THEN RAISE EXCEPTION 'reviewed03 current source differs' USING ERRCODE='23514'; END IF;
 IF relation_name='messages' THEN
  IF(new_row->>'account_id')::uuid<>account OR(new_row->>'device_id')::uuid<>row.device_id OR new_row->>'transport_mode'<>'sealed_profile03'
   OR new_row->>'state'<>'queued' OR(new_row->>'state_version')::bigint<>1 OR new_row->>'recipient_e164'<>row.peer
   OR new_row->>'recipient_digest'<>to_jsonb(sha256(convert_to(row.peer,'UTF8')))#>>'{}'
   OR new_row->>'request_digest'<>to_jsonb(row.unsigned_digest)#>>'{}'
   OR(new_row->>'sealed_line_id')::uuid<>row.line_id OR(new_row->>'sealed_binding_generation')::bigint<>row.binding_generation
   OR(new_row->>'sealed_manifest_generation')::bigint<>row.vault_generation OR(new_row->>'sealed_manifest_version')::bigint<>row.manifest_version
   OR new_row->>'sealed_manifest_digest'<>to_jsonb(row.manifest_digest)#>>'{}' OR new_row->>'sealed_signer_key_id'<>to_jsonb(row.signer_key_id)#>>'{}'
   OR(new_row->>'sealed_segment_limit')::smallint IS DISTINCT FROM row.authenticated_segment_ceiling
   OR(new_row->>'expires_at')::timestamptz<>to_timestamp(row.message_expires_ms::double precision/1000)
   OR new_row->>'agent_grant_id' IS NOT NULL OR new_row->>'workflow_action_id' IS NOT NULL OR new_row->>'workflow_executor_grant' IS NOT NULL
   OR new_row->>'transport_payload' IS NULL THEN RAISE EXCEPTION 'reviewed03 exact message admission differs' USING ERRCODE='23514'; END IF;
  PERFORM public.conversation_reviewed_send03_envelope(row,(new_row->>'transport_payload')::bytea);
 ELSE
  IF(new_row->>'account_id')::uuid<>account OR(new_row->>'device_id')::uuid<>row.device_id OR(new_row->>'generation')::bigint<>0
   OR new_row->>'lease_owner' IS NOT NULL OR new_row->>'lease_until' IS NOT NULL OR new_row->>'grant_issued_at' IS NOT NULL OR new_row->>'finished_at' IS NOT NULL
   OR NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=account AND m.id=wanted AND m.transport_mode='sealed_profile03' AND m.state='queued') THEN
   RAISE EXCEPTION 'reviewed03 initial dispatch admission differs' USING ERRCODE='23514'; END IF;
 END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_scope(account uuid,message uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint)
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
 IF NOT FOUND OR admission.intent_version<>2 OR admission.redacted_ms IS NOT NULL OR admission.intent IS NULL OR admission.signature IS NULL OR admission.peer IS NULL THEN
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

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_issue(account uuid,message uuid,attempt uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,permission_deadline_ms bigint)
RETURNS SETOF public.conversation_profile03_grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; previous public.conversation_profile03_grants%ROWTYPE;
 msg public.messages%ROWTYPE; job public.dispatch_jobs%ROWTYPE; now_ms bigint;
BEGIN
 IF account IS NULL OR message IS NULL OR attempt IS NULL OR device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL
  OR permission_deadline_ms IS NULL OR attempt='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION 'grant exact issue input unavailable' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM public.conversation_reviewed_sends03 a WHERE a.account_id=account AND a.message_id=message AND a.intent_version=2) THEN
  RAISE EXCEPTION 'grant original explicit V2 admission unavailable' USING ERRCODE='23514'; END IF;
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


CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=117 AND min(version)=1 AND max(version)=117 FROM public.schema_migrations
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
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
 AND coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
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
 AND coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
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
 AND coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE OR REPLACE FUNCTION public.conversation_reviewed_send03_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.conversation_profile03_interval_ready()
  AND has_table_privilege(current_user,'public.conversation_reviewed_sends03','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_reviewed_sends03','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_reviewed_sends03','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_reviewed_send03_admit','conversation_reviewed_send03_ready','conversation_reviewed_send03_v2_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%' AND a.grantee=0)
$function$;

CREATE FUNCTION public.conversation_reviewed_send03_v2_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.conversation_reviewed_send03_ready()
 AND coalesce((SELECT migration_version=117 AND graph_sha256=public.payload_profile_writer_graph()
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


DO $migration$
DECLARE routine record; columns_sql text;
BEGIN
 REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
  WHERE attrelid='public.conversation_reviewed_sends03'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_reviewed_sends03 TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_reviewed_send03_admit','conversation_reviewed_send03_ready','conversation_reviewed_send03_v2_ready') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;


DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=117);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,117,public.payload_profile_writer_graph());
