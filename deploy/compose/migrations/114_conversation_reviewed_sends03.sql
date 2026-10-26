-- SPDX-License-Identifier: AGPL-3.0-only
-- Original reviewed03 admission. Crypto, auth and real billing stay independent.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';
DO $migration$
DECLARE writer_expected record; writer_installation bigint:=113; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN RAISE EXCEPTION 'reviewed03 requires exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(110,111,112,113) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(112,113) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_version()','fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
 IF NOT(SELECT count(*)=113 AND min(version)=1 AND max(version)=113 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=113 AND graph_sha256=public.payload_profile_writer_graph() FROM public.payload_profile_writer_catalog WHERE singleton),false)
  OR EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN('r','p') AND a.grantee=0)
  OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
  RAISE EXCEPTION 'reviewed03 predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 FOR relation_name IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
  EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',relation_name);
 END LOOP;
END;
$migration$;

-- Original reviewed admission is not a grant, fetch or effect capability.
CREATE TABLE public.conversation_reviewed_sends03 (
 account_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE CASCADE,
 message_id uuid NOT NULL, interval_id uuid NOT NULL, interval_receipt_id uuid NOT NULL,
 initiating_user_id uuid NOT NULL, initiating_session_id uuid NOT NULL,
 device_id uuid NOT NULL, line_id uuid NOT NULL, binding_id uuid NOT NULL,
 election_challenge_id uuid NOT NULL, original_binding_id uuid NOT NULL, physical_refresh_id uuid,
 binding_generation bigint NOT NULL CHECK(binding_generation>0), vault_generation bigint NOT NULL CHECK(vault_generation=1),
 manifest_version bigint NOT NULL CHECK(manifest_version>0), selection_epoch bigint NOT NULL CHECK(selection_epoch=1),
 admitted_ms bigint NOT NULL CHECK(admitted_ms>0), permission_deadline_ms bigint NOT NULL CHECK(permission_deadline_ms>admitted_ms),
 observed_ms bigint NOT NULL CHECK(observed_ms>0), message_expires_ms bigint NOT NULL,
 review_issued_ms bigint NOT NULL, review_expires_ms bigint NOT NULL,
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0), proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 proof_site_id text NOT NULL CHECK(octet_length(proof_site_id) BETWEEN 1 AND 256),
 proof_instance_id text NOT NULL CHECK(octet_length(proof_instance_id) BETWEEN 1 AND 256),
 peer text CHECK(peer ~ '^\+[1-9][0-9]{1,14}$'), physical_source_kind text NOT NULL CHECK(physical_source_kind IN('original_v2','owner_refresh03')),
 authenticated_segment_ceiling smallint NOT NULL CHECK(authenticated_segment_ceiling BETWEEN 1 AND 6),
 intent bytea CHECK(intent IS NULL OR octet_length(intent) BETWEEN 624 AND 835), intent_sha256 bytea NOT NULL CHECK(octet_length(intent_sha256)=32),
 signature bytea CHECK(signature IS NULL OR octet_length(signature)=64), signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
 envelope_sha256 bytea NOT NULL CHECK(octet_length(envelope_sha256)=32), unsigned_digest bytea NOT NULL CHECK(octet_length(unsigned_digest)=32),
 body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32), selected_reader_key_id bytea NOT NULL CHECK(octet_length(selected_reader_key_id)=32),
 signer_key_id bytea NOT NULL CHECK(octet_length(signer_key_id)=32), root_fingerprint bytea NOT NULL CHECK(octet_length(root_fingerprint)=32),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32), election_commitment bytea NOT NULL CHECK(octet_length(election_commitment)=32),
 election_bundle_sha256 bytea NOT NULL CHECK(octet_length(election_bundle_sha256)=32), owner_session_digest bytea NOT NULL CHECK(octet_length(owner_session_digest)=32),
 configured_origin_digest bytea NOT NULL CHECK(octet_length(configured_origin_digest)=32), device_session_digest bytea NOT NULL CHECK(octet_length(device_session_digest)=32),
 physical_selection_digest bytea NOT NULL CHECK(octet_length(physical_selection_digest)=32), interval_statement_sha256 bytea NOT NULL CHECK(octet_length(interval_statement_sha256)=32),
 recipients bytea NOT NULL CHECK(octet_length(recipients) IN(66,99,132,165,198,231,264)), redacted_ms bigint,
 PRIMARY KEY(account_id,message_id),
 FOREIGN KEY(account_id,interval_id) REFERENCES public.conversation_profile03_intervals(account_id,interval_id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,message_id) REFERENCES public.messages(account_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,election_challenge_id) REFERENCES public.payload_profile_elections(account_id,challenge_id) ON DELETE CASCADE,
 CHECK(observed_ms<=review_issued_ms AND review_issued_ms<review_expires_ms AND review_expires_ms<=message_expires_ms
  AND review_expires_ms-review_issued_ms<=30000 AND message_expires_ms-observed_ms<=900000),
 CHECK(admitted_ms>=review_issued_ms AND admitted_ms<review_expires_ms AND permission_deadline_ms<=review_expires_ms),
 CHECK((physical_source_kind='original_v2')=(physical_refresh_id IS NULL)),
 CHECK((redacted_ms IS NULL AND intent IS NOT NULL AND signature IS NOT NULL AND peer IS NOT NULL
   AND intent_sha256=sha256(intent) AND signature_sha256=sha256(signature))
  OR(redacted_ms IS NOT NULL AND redacted_ms>=admitted_ms AND intent IS NULL AND signature IS NULL AND peer IS NULL))
);
CREATE INDEX conversation_reviewed_sends03_interval ON public.conversation_reviewed_sends03(account_id,interval_id,admitted_ms,message_id);

-- Closed original ZTRI01 structure. No signature, plaintext or caller is authenticated here.
CREATE FUNCTION public.conversation_reviewed_send03_parse(intent bytea) RETURNS public.conversation_reviewed_sends03
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; i integer; peer_length integer; count integer;
 recipient bytea; previous bytea; role integer; device_count integer:=0; archive_count integer:=0;
BEGIN
 IF octet_length(intent) NOT BETWEEN 624 AND 835 OR substring(intent FROM 1 FOR 8)<>decode('5a54524901030300','hex') THEN
  RAISE EXCEPTION 'reviewed03 original intent framing' USING ERRCODE='23514'; END IF;
 FOR i IN 0..7 LOOP IF substring(intent FROM 9+16*i FOR 16)=decode(repeat('00',16),'hex') THEN
  RAISE EXCEPTION 'reviewed03 zero identity' USING ERRCODE='23514'; END IF; END LOOP;
 FOR i IN 0..10 LOOP IF substring(intent FROM 201+32*i FOR 32)=decode(repeat('00',32),'hex') THEN
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
 row.envelope_sha256:=substring(intent FROM 457 FOR 32); row.unsigned_digest:=substring(intent FROM 489 FOR 32); row.body_digest:=substring(intent FROM 521 FOR 32);
 peer_length:=get_byte(intent,552);
 IF peer_length NOT BETWEEN 3 AND 16 THEN RAISE EXCEPTION 'reviewed03 peer width' USING ERRCODE='23514'; END IF;
 row.peer:=convert_from(substring(intent FROM 554 FOR peer_length),'UTF8');
 IF row.peer !~ '^\+[1-9][0-9]{1,14}$' THEN RAISE EXCEPTION 'reviewed03 peer shape' USING ERRCODE='23514'; END IF;
 count:=get_byte(intent,553+peer_length);
 IF count NOT BETWEEN 2 AND 8 OR octet_length(intent)<>555+peer_length+33*count THEN RAISE EXCEPTION 'reviewed03 recipient framing' USING ERRCODE='23514'; END IF;
 row.recipients:=substring(intent FROM 555+peer_length FOR 33*count);
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

-- Independently couple the exact envelope's public structure to the reviewed intent.
CREATE FUNCTION public.conversation_reviewed_send03_envelope("row" public.conversation_reviewed_sends03,envelope bytea) RETURNS void
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE peer_length integer; protected_length integer; prefix_length integer; body_length bigint; count integer; at integer; i integer; recipient bytea;
BEGIN
 IF octet_length(envelope) NOT BETWEEN 557 AND 34213 OR substring(envelope FROM 1 FOR 8)<>decode('5a54534503010000','hex')
  OR sha256(envelope)<>row.envelope_sha256 OR sha256(substring(envelope FROM 1 FOR octet_length(envelope)-64))<>row.unsigned_digest THEN
  RAISE EXCEPTION 'reviewed03 exact envelope differs' USING ERRCODE='23514'; END IF;
 peer_length:=get_byte(envelope,163);protected_length:=get_byte(envelope,8)*256+get_byte(envelope,9);prefix_length:=164+peer_length;
 IF peer_length NOT BETWEEN 3 AND 16 OR protected_length<>154+peer_length OR get_byte(envelope,162)<>1
  OR substring(envelope FROM 11 FOR 16)<>uuid_send(row.account_id) OR substring(envelope FROM 27 FOR 16)<>uuid_send(row.message_id)
  OR substring(envelope FROM 43 FOR 16)<>uuid_send(row.device_id) OR substring(envelope FROM 59 FOR 16)<>uuid_send(row.line_id)
  OR public.payload_profile_election_number(substring(envelope FROM 75 FOR 8))<>row.manifest_version
  OR substring(envelope FROM 83 FOR 32)<>row.manifest_digest OR substring(envelope FROM 115 FOR 32)<>row.signer_key_id
  OR public.payload_profile_election_number(substring(envelope FROM 147 FOR 8))<>row.observed_ms
  OR public.payload_profile_election_number(substring(envelope FROM 155 FOR 8))<>row.message_expires_ms
  OR substring(envelope FROM 165 FOR peer_length)<>convert_to(row.peer,'UTF8') THEN
  RAISE EXCEPTION 'reviewed03 protected envelope scope differs' USING ERRCODE='23514'; END IF;
 at:=prefix_length+12;
 body_length:=get_byte(envelope,at)::bigint*16777216+get_byte(envelope,at+1)::bigint*65536+get_byte(envelope,at+2)::bigint*256+get_byte(envelope,at+3);
 IF body_length NOT BETWEEN 17 AND 32784 OR at+4+body_length+1+64>octet_length(envelope) THEN
  RAISE EXCEPTION 'reviewed03 encrypted body framing' USING ERRCODE='23514'; END IF;
 at:=at+4+body_length;count:=get_byte(envelope,at);at:=at+1;
 IF count NOT BETWEEN 2 AND 8 OR count*33<>octet_length(row.recipients) OR at+146*count+64<>octet_length(envelope) THEN
  RAISE EXCEPTION 'reviewed03 exact wrapped reader framing' USING ERRCODE='23514'; END IF;
 FOR i IN 0..count-1 LOOP
  recipient:=substring(envelope FROM at+1+146*i FOR 33);
  IF recipient<>substring(row.recipients FROM 1+33*i FOR 33) OR get_byte(envelope,at+33+146*i)<>4 THEN
   RAISE EXCEPTION 'reviewed03 exact wrapped reader differs' USING ERRCODE='23514'; END IF;
 END LOOP;
END;
$function$;

CREATE FUNCTION public.conversation_reviewed_send03_scope(account uuid,intent bytea,signature bytea,permission_deadline_ms bigint,admitted_ms bigint)
RETURNS public.conversation_reviewed_sends03
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; consent public.conversation_profile03_intervals%ROWTYPE;
 checked public.conversation_profile03_intervals%ROWTYPE; checked_ms bigint; deadline bigint; lease_until bigint; i integer; recipient bytea; expected bytea;
BEGIN
 IF account IS NULL OR intent IS NULL OR signature IS NULL OR octet_length(signature)<>64 OR permission_deadline_ms IS NULL OR admitted_ms IS NULL OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'reviewed03 admission input unavailable' USING ERRCODE='23514'; END IF;
 row:=public.conversation_reviewed_send03_parse(intent);
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

CREATE FUNCTION public.conversation_reviewed_send03_admit(account uuid,"interval" uuid,message uuid,intent bytea,signature bytea,envelope bytea,permission_deadline_ms bigint)
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

CREATE FUNCTION public.conversation_reviewed_send03_rows_guard() RETURNS trigger
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
   OR NEW.redacted_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint OR NEW.intent IS NOT NULL OR NEW.signature IS NOT NULL OR NEW.peer IS NOT NULL
   OR(to_jsonb(NEW)-ARRAY['intent','signature','peer','redacted_ms']) IS DISTINCT FROM(to_jsonb(OLD)-ARRAY['intent','signature','peer','redacted_ms'])
   OR NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=OLD.account_id AND m.id=OLD.message_id AND m.transport_mode='sealed_profile03'
    AND m.recipient_e164 IS NULL AND m.transport_payload IS NULL AND m.state IN('delivered','failed','cancelled','expired'))
   OR EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=OLD.account_id AND f.message_id=OLD.message_id AND f.outcome IN('granted','submitting','unknown')) THEN
   RAISE EXCEPTION 'reviewed03 originals cannot change or resurrect' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'reviewed03 unsupported original mutation' USING ERRCODE='23514';
END;
$function$;

-- Erasure withdraws retained data from old RR/SSI views without advancing the
-- election epoch. Ordinary retention can arrive holding a row tuple first:
-- fail fast on any conflicting account/anchor holder instead of lock inversion.
CREATE FUNCTION public.conversation_reviewed_send03_erasure_fence(account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE state text; epoch bigint;
BEGIN
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'reviewed03 erasure account busy' USING ERRCODE='55P03'; END IF;
 SELECT a.state,a.selection_epoch INTO state,epoch FROM public.payload_profile_account_anchors a WHERE a.account_id=account FOR UPDATE NOWAIT;
 IF NOT FOUND OR epoch<>1 THEN RAISE EXCEPTION 'reviewed03 retained erasure anchor unavailable' USING ERRCODE='23514'; END IF;
 IF state='deleted' THEN RETURN; END IF;
 IF state<>'live' THEN RAISE EXCEPTION 'reviewed03 erasure anchor state differs' USING ERRCODE='23514'; END IF;
 UPDATE public.payload_profile_account_anchors a SET account_id=a.account_id WHERE a.account_id=account;
END;
$function$;

-- Explicit typed predicates for this admission only. Later effects need their
-- own immutable attempt provenance; no generic positive-epoch writer is opened.
CREATE FUNCTION public.conversation_reviewed_send03_writer(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
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

CREATE FUNCTION public.conversation_reviewed_send03_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_reviewed_sends03%ROWTYPE; checked public.conversation_reviewed_sends03%ROWTYPE; message public.messages%ROWTYPE; job public.dispatch_jobs%ROWTYPE;
BEGIN
 IF TG_RELID<>'public.conversation_reviewed_sends03'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_NARGS<>0 OR TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'reviewed03 deferred trigger context differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_reviewed_sends03 r WHERE r.account_id=NEW.account_id AND r.message_id=NEW.message_id;
 IF NOT FOUND THEN
  IF NOT EXISTS(SELECT FROM public.accounts a WHERE a.id=NEW.account_id) OR NOT EXISTS(SELECT FROM public.messages m WHERE m.account_id=NEW.account_id AND m.id=NEW.message_id) THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'reviewed03 original disappeared before commit' USING ERRCODE='23514'; END IF;
 SELECT * INTO message FROM public.messages m WHERE m.account_id=row.account_id AND m.id=row.message_id FOR SHARE NOWAIT;
 IF NOT FOUND OR message.transport_mode<>'sealed_profile03' THEN RAISE EXCEPTION 'reviewed03 actual message missing' USING ERRCODE='23514'; END IF;
 IF row.redacted_ms IS NOT NULL THEN
  IF message.recipient_e164 IS NOT NULL OR message.transport_payload IS NOT NULL THEN RAISE EXCEPTION 'reviewed03 personal content redaction incomplete' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 checked:=public.conversation_reviewed_send03_scope(row.account_id,row.intent,row.signature,row.permission_deadline_ms,row.admitted_ms);
 IF row IS DISTINCT FROM checked THEN RAISE EXCEPTION 'reviewed03 deferred current selection differs' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_reviewed_send03_writer(row.account_id,row.selection_epoch,'messages','INSERT',NULL,to_jsonb(message));
 SELECT * INTO job FROM public.dispatch_jobs j WHERE j.account_id=row.account_id AND j.message_id=row.message_id FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'reviewed03 actual dispatch admission missing' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_reviewed_send03_writer(row.account_id,row.selection_epoch,'dispatch_jobs','INSERT',NULL,to_jsonb(job));
 PERFORM 1 FROM public.usage_ledger u WHERE u.account_id=row.account_id AND u.message_id=row.message_id AND u.metric='outbound_message' AND u.entry_kind='reserve' AND u.units=1 FOR SHARE NOWAIT;
 IF NOT FOUND OR EXISTS(SELECT FROM public.usage_ledger u WHERE u.account_id=row.account_id AND u.message_id=row.message_id AND u.entry_kind='refund') THEN
  RAISE EXCEPTION 'reviewed03 actual outbound reservation missing or released' USING ERRCODE='23514'; END IF;
 IF(SELECT count(*) FROM public.messages m WHERE m.account_id=row.account_id AND m.device_id=row.device_id AND m.state IN('queued','claimed') AND m.expires_at>clock_timestamp())>16
  OR(SELECT count(*) FROM public.messages m WHERE m.account_id=row.account_id AND m.state IN('queued','claimed') AND m.expires_at>clock_timestamp())>128 THEN
  RAISE EXCEPTION 'reviewed03 actual pending queue full' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;

CREATE FUNCTION public.conversation_reviewed_send03_message_redact() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 IF TG_RELID<>'public.messages'::regclass OR TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP<>'UPDATE' OR TG_NARGS<>0 THEN
  RAISE EXCEPTION 'reviewed03 content redaction trigger differs' USING ERRCODE='23514'; END IF;
 IF OLD.transport_mode='sealed_profile03' AND OLD.transport_payload IS NOT NULL AND NEW.transport_payload IS NULL AND NEW.recipient_e164 IS NULL THEN
  UPDATE public.conversation_reviewed_sends03 r SET intent=NULL,signature=NULL,peer=NULL,redacted_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
   WHERE r.account_id=NEW.account_id AND r.message_id=NEW.id AND r.redacted_ms IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'reviewed03 original content erasure unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END;
$function$;

CREATE TRIGGER conversation_reviewed_send03_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.conversation_reviewed_sends03
 FOR EACH ROW EXECUTE FUNCTION public.conversation_reviewed_send03_rows_guard();
CREATE CONSTRAINT TRIGGER conversation_reviewed_send03_after_change AFTER INSERT OR UPDATE ON public.conversation_reviewed_sends03
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.conversation_reviewed_send03_complete();
CREATE TRIGGER conversation_reviewed_send03_after_redaction AFTER UPDATE OF recipient_e164,transport_payload ON public.messages
 FOR EACH ROW EXECUTE FUNCTION public.conversation_reviewed_send03_message_redact();

ALTER TABLE public.messages DROP CONSTRAINT messages_transport_mode_check;
ALTER TABLE public.messages ADD CONSTRAINT messages_transport_mode_check CHECK(transport_mode IN('synthetic_alpha','sealed_candidate02','sealed_profile03'));
ALTER TABLE public.messages DROP CONSTRAINT messages_transport_payload_check;
ALTER TABLE public.messages ADD CONSTRAINT messages_transport_payload_check CHECK(transport_payload IS NULL
 OR(transport_mode='synthetic_alpha' AND octet_length(transport_payload) BETWEEN 1 AND 32768)
 OR(transport_mode='sealed_candidate02' AND octet_length(transport_payload) BETWEEN 426 AND 34213 AND substring(transport_payload FROM 1 FOR 6)=decode('5a5453450201','hex'))
 OR(transport_mode='sealed_profile03' AND octet_length(transport_payload) BETWEEN 557 AND 34213 AND substring(transport_payload FROM 1 FOR 8)=decode('5a54534503010000','hex')));
ALTER TABLE public.messages DROP CONSTRAINT messages_segment_limit_transport;
ALTER TABLE public.messages ADD CONSTRAINT messages_segment_limit_transport CHECK(sealed_segment_limit IS NULL OR transport_mode IN('sealed_candidate02','sealed_profile03'));
ALTER TABLE public.messages DROP CONSTRAINT messages_sealed_metadata;
ALTER TABLE public.messages ADD CONSTRAINT messages_sealed_metadata CHECK(
 (transport_mode='synthetic_alpha' AND num_nonnulls(sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=0)
 OR(transport_mode='sealed_candidate02' AND num_nonnulls(sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=6
  AND sealed_binding_generation>0 AND sealed_manifest_generation>0 AND sealed_manifest_version>0 AND octet_length(sealed_manifest_digest)=32 AND octet_length(sealed_signer_key_id)=32
  AND(sealed_segment_limit IS NOT NULL OR state IN('queued','cancelled','expired') OR public.conversation_execution_is_message(account_id,id)))
 OR(transport_mode='sealed_profile03' AND num_nonnulls(sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id)=6
  AND sealed_binding_generation>0 AND sealed_manifest_generation=1 AND sealed_manifest_version>0 AND octet_length(sealed_manifest_digest)=32 AND octet_length(sealed_signer_key_id)=32
  AND sealed_segment_limit IS NOT NULL AND sealed_segment_limit BETWEEN 1 AND 6));

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
 SELECT count(*)=114 AND min(version)=1 AND max(version)=114 FROM public.schema_migrations
$function$;
CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=114 AND graph_sha256=public.payload_profile_writer_graph()
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
CREATE FUNCTION public.conversation_reviewed_send03_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.conversation_profile03_interval_ready()
  AND has_table_privilege(current_user,'public.conversation_reviewed_sends03','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_reviewed_sends03','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_reviewed_sends03','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_reviewed_send03_admit','conversation_reviewed_send03_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE routine record; columns_sql text;
BEGIN
 REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC;
 SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid='public.conversation_reviewed_sends03'::regclass AND attnum>0 AND NOT attisdropped;
 EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM PUBLIC',columns_sql);
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
  REVOKE ALL ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.conversation_reviewed_sends03 FROM zrotext_runtime',columns_sql);
  GRANT SELECT ON TABLE public.conversation_reviewed_sends03 TO zrotext_runtime;
 END IF;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_reviewed_send03_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_reviewed_send03_admit','conversation_reviewed_send03_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=114);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog
 FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,114,public.payload_profile_writer_graph());
