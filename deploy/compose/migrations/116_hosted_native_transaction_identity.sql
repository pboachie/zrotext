-- SPDX-License-Identifier: AGPL-3.0-only
-- Native backend identity and exact-transaction entry; no content authority.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=115; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'native hosted identity requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(110,111,112,113,114,115) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113,114,115) THEN '7979002b7b94fe1f5772d93e511204b1e731ca8eea8776a9a4cf4751af00b5af' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=115 THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113,114,115) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=115 THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113,114,115) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113,114,115) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=115 THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE CASE WHEN writer_installation IN(112,113,114,115) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=115 THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=115 THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=115 THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=115 THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=115 THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()',CASE WHEN writer_installation=115 THEN 'e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f' ELSE 'd2304db59ce15d94badb7e26f4a0e536a4551575b8b758db104fd4b4bdce1ab1' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation=115 THEN 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' ELSE '4f27879e1b1e350c79b0b8f661faefce941f6f1e4f852927fbe4b12ae06975a6' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()','483fe860358ee38b2ff5cf293aedaf18c2cc17ee1cafeb6dac0b8c9aefd1735d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)','006527b20f97d56582b26d006f80771a10a3d6007a154a990d45899803cbbb5f','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()','013423fe961e7c3d396be0bc4db8b238c295f233862c57f64c002df208cddf7d','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=115 THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=115 THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=115 THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('conversation_profile03_grant_billing(uuid, uuid)','cc1e70c70f7c3e2554eb14573dbeccc3307d1dad1b3cb049f979a20c11cdab1a','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('conversation_profile03_grant_usage_writer(uuid, text, text, jsonb, jsonb)','686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_profile03_grant_scope(uuid, uuid, uuid, text, text, bigint, bigint)','675959b6686692e2dde0995b4883cfffc45fbe47bbc1d31cd2bf425f50f9afa2','public.conversation_profile03_grants','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_same_scope(jsonb, jsonb)','89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['original','current_scope']::text[]),
            ('conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)','fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)','f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78','public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('alpha_message_effect_guard()','f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_version()','d947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
 IF NOT(SELECT count(*)=115 AND min(version)=1 AND max(version)=115 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=115 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false) THEN
  RAISE EXCEPTION 'native hosted predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR writer_expected IN SELECT * FROM(VALUES
  ('public.hosted_runtime_schema_ready()','boolean','sql','s',false,ARRAY['7aa17580ac81a8f630b55797daee4fd22b178b236605f71c21491cb85e30865b','f4317324a9ba8ed8799696d4944d9382a847eaa98251e8d147353b159433102b']::text[]),
  ('public.hosted_runtime_role_safe()','boolean','sql','s',true,ARRAY['898ddd403142d0b048b0e528c2b2ab9832ed3197ca86f1dc271e7d0ed7a26b9b','3aa8eb73d8355243b5181d500582d38609e5f5effe681bd14a8c8383f5db48c3']::text[]),
  ('public.hosted_runtime_challenge(uuid, bigint)','bytea','plpgsql','v',true,ARRAY['51025920a5050177d745198aa365c69f1a478057338dd64dac94025a10465614','6fac3bf88fca7e1fb8d91f917b12768ac4a0a4d8060c524000973df1b0d75f87']::text[]),
  ('public.hosted_runtime_bind(uuid, bigint, bytea)','boolean','plpgsql','v',true,ARRAY['9d7bd20470d3c5dcec81df895f3e5c661c0b9377a7751aa505b26e96efee1d72','594396acaa2314f94bcbdfc7d56976a57fc5f691b61aa3fcbf3341b5422be699']::text[]),
  ('public.hosted_runtime_verified(uuid, bigint)','boolean','sql','v',true,ARRAY['42383f501989efd7dad53173a8837305c36261c33d58eab6aca9758b4b95f050','d859f1a92b389b41854af61e739cd935fb67b1b488d19ed60be37bb8e187ed14']::text[]),
  ('public.hosted_runtime_marker()','public.hosted_billing_namespaces','plpgsql','v',false,ARRAY['6ed412810b8666e2d8c840e9f9b0fb66ea93d7a44469b5fc9595f3fec53b10af','9edcfd6380a5466ad81b7010f154f5560989da2cae89dfaf7c907390b5dbf3e5']::text[]),
  ('public.hosted_runtime_projection(uuid)','public.hosted_billing_projections','plpgsql','v',false,ARRAY['25cd5c35228ee26a82bda8d04084a763681d209b4f17ec8e0e92b51e417ed72e','ba7fcf05e3069d2766bf90f7a868c52e55b2d9c1278bc9bb2279ce30e3b794c0']::text[])
 ) e(signature,result_type,language_name,volatility,is_definer,body_hashes) LOOP
  IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
   WHERE p.oid=to_regprocedure(writer_expected.signature) AND p.proowner=c.relowner
    AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
    AND p.provolatile::text=writer_expected.volatility AND p.prosecdef=writer_expected.is_definer
    AND NOT p.proisstrict AND NOT p.proretset AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
    AND p.prokind='f' AND p.proparallel='u' AND p.pronargdefaults=0
    AND p.proconfig=ARRAY['search_path=pg_catalog, public, pg_temp']
    AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=ANY(writer_expected.body_hashes)) THEN
   RAISE EXCEPTION 'native hosted exact106 predecessor declaration unavailable' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

-- Native backend context is ephemeral proof bookkeeping, not selected content
-- authority. The existing global hosted_backend_proof class remains mandatory.
CREATE TABLE public.hosted_runtime_entries (
 backend_pid integer NOT NULL CHECK(backend_pid>0), native_xid xid8 NOT NULL, backend_start timestamptz NOT NULL,
 namespace_id uuid NOT NULL REFERENCES public.hosted_billing_namespaces(namespace_id), policy_revision bigint NOT NULL CHECK(policy_revision>0),
 expires_at timestamptz NOT NULL, PRIMARY KEY(backend_pid,native_xid)
);
CREATE INDEX hosted_runtime_entries_expiry ON public.hosted_runtime_entries(expires_at,backend_pid,native_xid);

CREATE OR REPLACE FUNCTION public.hosted_runtime_native_start() RETURNS timestamptz
LANGUAGE plpgsql SECURITY INVOKER
SET search_path TO pg_catalog AS $function$
DECLARE started timestamptz;
BEGIN
 SELECT a.backend_start INTO STRICT started FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid();
 IF started IS NULL THEN RAISE EXCEPTION 'native backend identity unavailable' USING ERRCODE='23514'; END IF;
 RETURN started;
END;
$function$;
CREATE TABLE public.hosted_runtime_requests (
 operation text NOT NULL CHECK(operation IN ('challenge','bind','enter')),
 namespace_id uuid NOT NULL, policy_revision bigint NOT NULL, proof bytea,
 native_pid integer NOT NULL DEFAULT pg_catalog.pg_backend_pid(),
 native_start timestamptz NOT NULL DEFAULT public.hosted_runtime_native_start(),
 native_xid xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
 native_role oid NOT NULL DEFAULT (CURRENT_USER::regrole)::oid,
 result jsonb
);
CREATE FUNCTION public.hosted_runtime_native_schema_valid() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT public.hosted_runtime_role_safe() AND public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE FUNCTION public.hosted_runtime_identity_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready() AND public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE FUNCTION public.hosted_runtime_scope() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE fence bigint;
BEGIN
 IF (public.payload_profile_writer_version()
 AND coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE OR REPLACE FUNCTION public.hosted_runtime_marker() RETURNS public.hosted_billing_namespaces
LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
DECLARE n public.hosted_billing_namespaces;
BEGIN
 PERFORM public.hosted_runtime_scope();
 SELECT * INTO n FROM public.hosted_billing_namespaces FOR SHARE NOWAIT;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF NOT n.enabled OR n.review_required OR NOT n.old_binary_fenced OR
  public.hosted_runtime_verified(n.namespace_id,n.policy_revision) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'hosted runtime identity unavailable' USING ERRCODE='23514',CONSTRAINT='hosted_runtime_identity'; END IF;
 RETURN n;
END;
$function$;

CREATE OR REPLACE FUNCTION public.hosted_runtime_request_apply() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO pg_catalog AS $function$
DECLARE s public.hosted_runtime_sessions; n public.hosted_billing_namespaces; secret bytea; inner_pad bytea; outer_pad bytea;
 expected bytea; diff integer:=0; i integer; current_at timestamptz;
BEGIN
 IF TG_RELID<>'public.hosted_runtime_requests'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW'
  OR TG_WHEN<>'BEFORE' OR TG_OP<>'INSERT' OR TG_NARGS<>0 OR NEW.operation IS NULL
  OR NEW.operation NOT IN('challenge','bind','enter') THEN
  RAISE EXCEPTION 'native request trigger context differs' USING ERRCODE='23514'; END IF;
 IF public.hosted_runtime_native_schema_valid() IS DISTINCT FROM true OR NEW.native_role IS DISTINCT FROM (SESSION_USER::regrole)::oid
  OR NEW.native_pid IS DISTINCT FROM pg_backend_pid() OR NEW.native_xid IS DISTINCT FROM pg_current_xact_id()
  OR NEW.native_start IS NULL OR NEW.result IS NOT NULL THEN
  RAISE EXCEPTION 'closed native entry unavailable' USING ERRCODE='23514';
 END IF;
 PERFORM public.hosted_runtime_scope();
 SELECT * INTO n FROM public.hosted_billing_namespaces WHERE namespace_id=NEW.namespace_id FOR SHARE NOWAIT;
 IF NEW.operation<>'bind' AND (NOT FOUND OR n.policy_revision IS DISTINCT FROM NEW.policy_revision OR NOT n.enabled OR NOT n.old_binary_fenced) THEN
  RAISE EXCEPTION 'namespace unavailable' USING ERRCODE='23514';
 END IF;
 -- Expired ephemeral entries carry no content history. Bounded SKIP LOCKED
 -- cleanup never waits behind another actual protected transaction.
 WITH expired AS(SELECT e.backend_pid,e.native_xid FROM public.hosted_runtime_entries e
  WHERE e.expires_at<=clock_timestamp() ORDER BY e.expires_at,e.backend_pid,e.native_xid LIMIT 128 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.hosted_runtime_entries e USING expired x WHERE(e.backend_pid,e.native_xid)=(x.backend_pid,x.native_xid);
 current_at:=clock_timestamp();
 IF NEW.operation='challenge' THEN
  IF NEW.proof IS NOT NULL THEN RAISE EXCEPTION 'unexpected proof' USING ERRCODE='23514'; END IF;
  DELETE FROM public.hosted_runtime_entries WHERE backend_pid=NEW.native_pid;
  INSERT INTO public.hosted_runtime_sessions VALUES(NEW.native_pid,NEW.native_start,NEW.namespace_id,NEW.policy_revision,
   uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid()),current_at+interval '60 seconds',false,false)
  ON CONFLICT(backend_pid) DO UPDATE SET backend_start=EXCLUDED.backend_start,namespace_id=EXCLUDED.namespace_id,
   policy_revision=EXCLUDED.policy_revision,nonce=EXCLUDED.nonce,expires_at=EXCLUDED.expires_at,consumed=false,verified=false;
  SELECT * INTO STRICT s FROM public.hosted_runtime_sessions WHERE backend_pid=NEW.native_pid;
  NEW.result:=jsonb_build_object('challenge',encode(s.nonce,'hex'));
 ELSIF NEW.operation='bind' THEN
  DELETE FROM public.hosted_runtime_entries WHERE backend_pid=NEW.native_pid;
  IF NEW.proof IS NULL OR octet_length(NEW.proof) IS DISTINCT FROM 32 THEN
   UPDATE public.hosted_runtime_sessions SET consumed=true,verified=false WHERE backend_pid=NEW.native_pid;
   NEW.result:=jsonb_build_object('bound',false); RETURN NEW;
  END IF;
  SELECT * INTO s FROM public.hosted_runtime_sessions WHERE backend_pid=NEW.native_pid AND backend_start=NEW.native_start
   AND namespace_id=NEW.namespace_id AND policy_revision=NEW.policy_revision AND NOT consumed AND expires_at>clock_timestamp() FOR UPDATE NOWAIT;
  IF NOT FOUND THEN
   UPDATE public.hosted_runtime_sessions SET verified=false WHERE backend_pid=NEW.native_pid;
   NEW.result:=jsonb_build_object('bound',false); RETURN NEW;
  END IF;
  UPDATE public.hosted_runtime_sessions SET consumed=true,verified=false WHERE backend_pid=NEW.native_pid;
  SELECT runtime_key INTO STRICT secret FROM public.hosted_runtime_secrets WHERE namespace_id=NEW.namespace_id;
  -- Same byte-for-byte106 HMAC domain, nonce, UUID, bigint policy_revision, native PID
  -- and constant-time32-byte comparison. No start-time substitute is signed.
  inner_pad:=decode(repeat('36',64),'hex'); outer_pad:=decode(repeat('5c',64),'hex');
  FOR i IN 0..31 LOOP
   inner_pad:=set_byte(inner_pad,i,get_byte(inner_pad,i)#get_byte(secret,i));
   outer_pad:=set_byte(outer_pad,i,get_byte(outer_pad,i)#get_byte(secret,i));
  END LOOP;
  expected:=sha256(outer_pad||sha256(inner_pad||convert_to('ZROTEXT-HOSTED-RUNTIME-V1','UTF8')||s.nonce||uuid_send(NEW.namespace_id)||int8send(NEW.policy_revision)||int4send(NEW.native_pid)));
  FOR i IN 0..31 LOOP diff:=diff|(get_byte(expected,i)#get_byte(NEW.proof,i)); END LOOP;
  IF diff IS DISTINCT FROM 0 THEN NEW.result:=jsonb_build_object('bound',false); RETURN NEW; END IF;
  UPDATE public.hosted_runtime_sessions SET verified=true WHERE backend_pid=NEW.native_pid;
  PERFORM set_config('zrotext.hosted_namespace',NEW.namespace_id::text,false);
  PERFORM set_config('zrotext.hosted_revision',NEW.policy_revision::text,false);
  NEW.result:=jsonb_build_object('bound',true);
 ELSE
  IF NEW.proof IS NOT NULL THEN RAISE EXCEPTION 'unexpected proof' USING ERRCODE='23514'; END IF;
  SELECT * INTO s FROM public.hosted_runtime_sessions WHERE backend_pid=NEW.native_pid AND backend_start=NEW.native_start
   AND namespace_id=NEW.namespace_id AND policy_revision=NEW.policy_revision AND consumed AND verified AND expires_at>clock_timestamp() FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'bound same-backend proof required' USING ERRCODE='23514'; END IF;
  INSERT INTO public.hosted_runtime_entries VALUES(NEW.native_pid,NEW.native_xid,NEW.native_start,NEW.namespace_id,NEW.policy_revision,s.expires_at)
   ON CONFLICT(backend_pid,native_xid) DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM public.hosted_runtime_entries e WHERE e.backend_pid=NEW.native_pid AND e.native_xid=NEW.native_xid
   AND e.backend_start=NEW.native_start AND e.namespace_id=NEW.namespace_id AND e.policy_revision=NEW.policy_revision AND e.expires_at=s.expires_at) THEN
   RAISE EXCEPTION 'transaction entry mismatch' USING ERRCODE='23514';
  END IF;
  NEW.result:=jsonb_build_object('entered',true,'expires_ms',floor(extract(epoch FROM s.expires_at)*1000)::bigint);
 END IF;
 RETURN NEW;
END;
$function$;
CREATE OR REPLACE FUNCTION public.hosted_runtime_request_remove() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO pg_catalog AS $function$
BEGIN
 IF TG_RELID<>'public.hosted_runtime_requests'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW'
  OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'native cleanup trigger context differs' USING ERRCODE='23514'; END IF;
 DELETE FROM public.hosted_runtime_requests f WHERE f.ctid=NEW.ctid;
 IF NEW.operation='enter' AND public.hosted_runtime_verified(NEW.namespace_id,NEW.policy_revision) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'native transaction proof expired before release' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;
CREATE OR REPLACE FUNCTION public.hosted_runtime_challenge(ns uuid,rev bigint) RETURNS bytea
LANGUAGE sql SECURITY INVOKER
SET search_path TO pg_catalog AS $function$
 INSERT INTO public.hosted_runtime_requests(operation,namespace_id,policy_revision) VALUES('challenge',ns,rev) RETURNING decode(result->>'challenge','hex')
$function$;
CREATE OR REPLACE FUNCTION public.hosted_runtime_bind(ns uuid,rev bigint,proof bytea) RETURNS boolean
LANGUAGE sql SECURITY INVOKER
SET search_path TO pg_catalog AS $function$
 INSERT INTO public.hosted_runtime_requests(operation,namespace_id,policy_revision,proof) VALUES('bind',ns,rev,proof) RETURNING (result->>'bound')::boolean
$function$;
CREATE OR REPLACE FUNCTION public.hosted_runtime_enter(ns uuid,rev bigint) RETURNS bigint
LANGUAGE sql SECURITY INVOKER
SET search_path TO pg_catalog AS $function$
 INSERT INTO public.hosted_runtime_requests(operation,namespace_id,policy_revision) VALUES('enter',ns,rev) RETURNING (result->>'expires_ms')::bigint
$function$;
CREATE OR REPLACE FUNCTION public.hosted_runtime_verified(ns uuid,rev bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path TO pg_catalog AS $function$
 SELECT public.hosted_runtime_native_schema_valid() AND EXISTS(SELECT 1 FROM public.hosted_runtime_entries e JOIN public.hosted_runtime_sessions s
  ON s.backend_pid=e.backend_pid AND s.backend_start=e.backend_start AND s.namespace_id=e.namespace_id AND s.policy_revision=e.policy_revision
  JOIN public.hosted_billing_namespaces n ON n.namespace_id=s.namespace_id AND n.policy_revision=s.policy_revision
  WHERE e.backend_pid=pg_backend_pid() AND e.native_xid=pg_current_xact_id_if_assigned()
   AND e.xmin=pg_current_xact_id_if_assigned()::xid
   AND e.namespace_id=ns AND e.policy_revision=rev AND s.consumed AND s.verified AND n.enabled AND n.old_binary_fenced
   AND e.expires_at=s.expires_at AND s.expires_at>clock_timestamp())
$function$;
CREATE FUNCTION public.hosted_runtime_expiry(ns uuid,rev bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE until_ms bigint;
BEGIN
 IF public.hosted_runtime_verified(ns,rev) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'same-transaction hosted proof unavailable' USING ERRCODE='23514'; END IF;
 SELECT floor(extract(epoch FROM s.expires_at)*1000)::bigint INTO STRICT until_ms
  FROM public.hosted_runtime_entries e JOIN public.hosted_runtime_sessions s
   ON(s.backend_pid,s.backend_start,s.namespace_id,s.policy_revision,s.expires_at)=
    (e.backend_pid,e.backend_start,e.namespace_id,e.policy_revision,e.expires_at)
  WHERE e.backend_pid=pg_backend_pid() AND e.native_xid=pg_current_xact_id_if_assigned()
   AND e.xmin=pg_current_xact_id_if_assigned()::xid
   AND e.namespace_id=ns AND e.policy_revision=rev AND s.consumed AND s.verified AND s.expires_at>clock_timestamp()
  FOR SHARE OF e,s NOWAIT;
 RETURN until_ms;
END;
$function$;

CREATE TRIGGER hosted_runtime_request_apply BEFORE INSERT ON public.hosted_runtime_requests
 FOR EACH ROW EXECUTE FUNCTION public.hosted_runtime_request_apply();
CREATE TRIGGER hosted_runtime_request_remove AFTER INSERT ON public.hosted_runtime_requests
 FOR EACH ROW EXECUTE FUNCTION public.hosted_runtime_request_remove();
CREATE TRIGGER zz_payload_profile_writer_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_runtime_requests
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_guard();
CREATE TRIGGER zz_payload_profile_writer_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.hosted_runtime_entries
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_guard();

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_billing(account uuid,message uuid) RETURNS bigint
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
  -- Exact native same-transaction entry authenticates the retained backend;
  -- its unchanged original expiry is only an additional temporal ceiling.
  backend_until:=public.hosted_runtime_expiry(namespace.namespace_id,namespace.policy_revision);
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
                WHEN 'hosted_runtime_entries' THEN 'hosted_backend_proof'
                WHEN 'hosted_runtime_requests' THEN 'hosted_backend_proof'
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
CREATE OR REPLACE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=116 AND min(version)=1 AND max(version)=116 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=116 AND graph_sha256=public.payload_profile_writer_graph()
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
DO $migration$
DECLARE relation_name text; columns_sql text; routine record;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['hosted_runtime_entries','hosted_runtime_requests'] LOOP
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute
   WHERE attrelid=to_regclass(format('public.%I',relation_name)) AND attnum>0 AND NOT attisdropped;
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC',columns_sql,relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM zrotext_runtime',columns_sql,relation_name);
  END IF;
 END LOOP;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  GRANT INSERT(operation,namespace_id,policy_revision,proof),SELECT(result) ON public.hosted_runtime_requests TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'hosted_runtime_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('hosted_runtime_role_safe','hosted_runtime_challenge','hosted_runtime_bind','hosted_runtime_verified','hosted_runtime_marker','hosted_runtime_projection','hosted_runtime_native_start','hosted_runtime_enter','hosted_runtime_identity_ready','hosted_runtime_scope') THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature);
   END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=116);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,116,public.payload_profile_writer_graph());
