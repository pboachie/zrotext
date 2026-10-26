-- SPDX-License-Identifier: AGPL-3.0-only
-- Run as runtime in the disposable smoke database. All writes roll back.
BEGIN;
DO $$
DECLARE
    statement text;
    anchor_account uuid;
    review_relation text;
    review_column record;
    review_routine record;
    review_allowed oid[] := ARRAY[]::oid[];
    writer_expected record;
    writer_installation bigint;
BEGIN
    IF to_regclass('public.payload_profile_writer_catalog') IS NOT NULL THEN
        SELECT migration_version INTO writer_installation FROM public.payload_profile_writer_catalog WHERE singleton;
        IF writer_installation NOT IN (108,109,110,111,112,113,114,115,116,117,118,119) OR writer_installation IS NULL THEN RAISE EXCEPTION 'unsupported writer installation'; END IF;
        -- Pin exact compiled108/109/110/111/112/113/114/115/116/117/118 bodies before invoking a readiness helper.
        -- A substituted helper returning true cannot validate its own body.
        FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','fa9b79ea943397063fffabc2ca20b33c9a988d6cd0768a8774c7eb9713619bba','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()',CASE WHEN writer_installation IN(116,117,118,119) THEN 'f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN 'e17595d3e26a9d87766539c90dcc55f036fb8cd1a31037a59154a7659087da23' ELSE 'f47f6d64ef583f2f5272128aa02c7bd5974d2e9f06b6bfff743a5b0a29e3c18a' END END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()',CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN '93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061' ELSE 'cc9acfd80e3b38f0bd821047921b0fb08511f1a5169c62c6e1fe2ebacb4aa9a1' END,'bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117,118,119) THEN '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' ELSE CASE WHEN writer_installation=111 THEN '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN 'ba7338435eb9e0c609710f545fe0c500a331da3c8e20b639ea440ae1bac45420' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN '1f550dff94173c25c4a99be070549a88fcf35710954ea9ef547dd0cd8655029a' ELSE 'b09c934ba13422e2ef7c11436822f20561a2aedb5534f00801ceca853a6639b4' END END END END END END END END END END END,'boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117,118,119) THEN '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' ELSE CASE WHEN writer_installation=111 THEN 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' ELSE CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN '1e33bc75520f91cf30bacb842b59eb5e764bb36dec89b04bd152fedb9e423fb6' ELSE CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN '69c01fcc19c8f470870c66e5483ff5e07c6755e08fc9b74611fdf96775316068' ELSE '8759842715d6f164f2533cbd2778d0ba0a67450d53f0874203e3c66d4d80488a' END END END END END END END END END END END,'boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()',CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN '081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321' ELSE '57392dcb3337dfcc09266f17a6135d3d45c9d086fba03f860a3ac18ee56cef51' END,'trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
        IF public.payload_profile_writer_ready() IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'mandatory writer graph or runtime authority is inconsistent';
        END IF;
        IF writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN
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
            IF public.payload_profile_v2_ready() IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'original receipt schema or runtime authority is inconsistent';
            END IF;
        END IF;
        IF writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN
          FOR writer_expected IN SELECT * FROM(VALUES
            ('payload_profile_election_frame(text, bytea)','8fd5f8d723cf6677505d6248f9f85c4fec9245aa9236e28381658ffb63f3fc2a','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['label','payload']::text[]),
            ('payload_profile_election_number(bytea)','b1a28fd0a424639493ca0eaacaffc4be71bea8bb4ba56df258986cff11b0141d','bigint','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
            ('payload_profile_election_uuid(bytea)','0bfacb9086bc70824ab4a6278bedf158a8f411cec12b5f4c1f7afadac6dc196b','uuid','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['value']::text[]),
            ('payload_profile_election_reader(bytea, smallint, bytea, uuid, uuid, bigint)','84be4fbc0947641795dfe6437450926a738bc2f1a56ff0a13d54368b0e180496','bytea','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['manifest','profile','reader_id','device','line','checked_ms']::text[]),
            ('payload_profile_election_old_binding(uuid, uuid, bytea)','d92120a075ce107f938dd52394c623731b61aa9e5a3387011832d7b1de0aa16b','bytea','plpgsql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','binding','reader']::text[]),
            ('payload_profile_epoch_valid(uuid, bigint)','cb08001590eaee6c7b32b4773f47044b8ea446a4268d44bf191c00400841e306','boolean','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=119 THEN '0ff5722a8072c00e04b2aaf5f1701a46f244c857743f73ec557e64b94eb46667' ELSE CASE WHEN writer_installation IN(118,119) THEN '3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE CASE WHEN writer_installation IN(112,113,114,115,116,117,118,119) THEN '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' ELSE '72b4dd65a4b875c849b7ba73f26683e666365a99146eeaa953ffcf96204c5c00' END END END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
          IF public.payload_profile_election_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'election schema or runtime authority inconsistent'; END IF;
        END IF;
        IF writer_installation=111 THEN
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' END END END END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' END END END END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
          IF public.payload_profile_selection_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'physical schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation IN(112,113,114,115,116,117,118,119) THEN
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '32eac9c87653a3f35cc5cd3f45279c2d872d75092935a1ed068f2755f7edf2f0' END END END END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE '3bb5d3927657e21f209f6deb8ea7a21155bb70c2cdfd3c5cc4a133fbdafd1659' END END END END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=119 THEN '0ff5722a8072c00e04b2aaf5f1701a46f244c857743f73ec557e64b94eb46667' ELSE CASE WHEN writer_installation IN(118,119) THEN '3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE CASE WHEN writer_installation=114 THEN 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' ELSE '93267627afdd420de67b4b87e6a46fcd946a3274b7fb8d4df077d74dc25e4191' END END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
          IF public.payload_profile_manifest_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'manifest successor schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation IN(113,114,115,116,117,118,119) THEN
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE CASE WHEN writer_installation=114 THEN '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' ELSE 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' END END END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE CASE WHEN writer_installation=114 THEN '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' ELSE '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' END END END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()',CASE WHEN writer_installation=119 THEN '962ffbf3817bbe46913b371b787914a218f69b918b678e886db01bdd2e73c247' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f' ELSE 'd2304db59ce15d94badb7e26f4a0e536a4551575b8b758db104fd4b4bdce1ab1' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
          IF public.conversation_profile03_interval_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'conversation03 schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation IN(114,115,116,117,118,119) THEN
          FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_reviewed_send03_parse(bytea)',CASE WHEN writer_installation IN(117,118,119) THEN '9fc0eb8cfd60bb7296f7a34446e244573df2cbc3a519a6b0a0469e824e207b28' ELSE 'f75324ab23e43721bf7fdbc107fa336f6b9b389033e552c083bfde2562105b7e' END,'public.conversation_reviewed_sends03','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['intent']::text[]),
            ('conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03, bytea)','5b2d548fb73912d9bcfa86e7e1b9ca760c3b649e2ecd6a236e500d9bbd2a77cc','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['row','envelope']::text[]),
            ('conversation_reviewed_send03_scope(uuid, bytea, bytea, bigint, bigint)',CASE WHEN writer_installation IN(117,118,119) THEN '838c3bd2760cb533b219cf19ec816a6f8e581499bf28ebc0a5683ae8eff86141' ELSE '82a31a37e6b99d29b97293f4303e0c189475ea744b67f3b5cd15f9b2051ab55d' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','intent','signature','permission_deadline_ms','admitted_ms']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation IN(117,118,119) THEN 'b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' ELSE '4f27879e1b1e350c79b0b8f661faefce941f6f1e4f852927fbe4b12ae06975a6' END END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()',CASE WHEN writer_installation IN(117,118,119) THEN '6c9d1664c4e261cc2a5f5e3f6d5b7f704d9a1f598333b8f3f49a262a85dc6213' ELSE '483fe860358ee38b2ff5cf293aedaf18c2cc17ee1cafeb6dac0b8c9aefd1735d' END,'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation IN(117,118,119) THEN 'e41f43888594803a29744a49173201ce1831d3997706a9a02e3dcc14a8bc5b05' ELSE '006527b20f97d56582b26d006f80771a10a3d6007a154a990d45899803cbbb5f' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()',CASE WHEN writer_installation IN(117,118,119) THEN 'dca2173f22a2128120c22dd1bc96f3ae9e0519b671d9d5b569b7800137709bb1' ELSE '013423fe961e7c3d396be0bc4db8b238c295f233862c57f64c002df208cddf7d' END,'trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=119 THEN '0ff5722a8072c00e04b2aaf5f1701a46f244c857743f73ec557e64b94eb46667' ELSE CASE WHEN writer_installation IN(118,119) THEN '3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' ELSE 'b4c2ddf1ccc626bb19eac45215a5bf709a02ba8145e0ea13939569b87a50d13c' END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' ELSE '3fa858e73f52f7fe54380805de594f46a64de5fbd9dcbe8b1a1b45216f2aa484' END END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE CASE WHEN writer_installation IN(115,116,117,118,119) THEN '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' ELSE '550702db785002eb21a8e9fff770bd13a1c75f9cfbed5ec1f87cc6d30beee3bd' END END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_reviewed_send03_ready()',CASE WHEN writer_installation IN(117,118,119) THEN '9b1ea5e893b4be156e764c25d34237d0057a7fdd30b79b813ba7a65980921e79' ELSE 'd5bdd952112811191cc45684ce73c451d75983f3245ecedfccf229b6daae5850' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
          IF public.conversation_reviewed_send03_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'reviewed03 schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation IN(115,116,117,118,119) THEN
          FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_profile03_grant_mode(uuid)','88cc435625b02027cf88e09b93a5ece91be164073876b837750c6232d211c4f3','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_profile03_grant_issued(uuid, uuid)',CASE WHEN writer_installation=119 THEN 'b514e3fd0bc7399e1ee237b5b115fb879110781568e4fa18690d148a9eb2dc8b' ELSE '660270fb3f84cc662d67a8734c49b254e460d82f3535975970c133aa8f73626e' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt']::text[]),
            ('conversation_profile03_grant_lock(uuid, uuid, uuid, text, text, bigint, bigint)','35544e458bd295ea65c292f85c165f7a68ab54833f39005fa6eb9072f97c4b1d','public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_issue(uuid, uuid, uuid, uuid, text, text, bigint, bigint, bigint)',CASE WHEN writer_installation=119 THEN '662948ed179db3ee8ecc81b8b38d2be6a8c25ec638fd563489c72a01f42da031' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '9d16e12ae65072a8eaefaa43ab17b14b360ed914f2c90c03af83e15a8538fc32' ELSE 'd8694b4bd07a786211d3fc7b310a647f419e81703474ce4380faded7ad9e86f3' END END,'public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','attempt','device','site','instance','connection_epoch','deployment_epoch','permission_deadline_ms']::text[]),
            ('conversation_profile03_grant_rows_guard()','b3a9375ed664177dfb032755071667fa3ceb14dac1ce5e37c1712bb2f31cd427','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_complete()','027bcdfb9e932d3b00efde8cef3bafe6859d1681d82568b0b09bb42ab9085964','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_billing(uuid, uuid)',CASE WHEN writer_installation IN(116,117,118,119) THEN '2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3' ELSE 'cc1e70c70f7c3e2554eb14573dbeccc3307d1dad1b3cb049f979a20c11cdab1a' END,'bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('conversation_profile03_grant_usage_writer(uuid, text, text, jsonb, jsonb)','686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_profile03_grant_scope(uuid, uuid, uuid, text, text, bigint, bigint)',CASE WHEN writer_installation IN(117,118,119) THEN '7f4861c2b72b04b787fbe03dba9ea0df1b453dd90fc63181ed37b707d081231b' ELSE '675959b6686692e2dde0995b4883cfffc45fbe47bbc1d31cd2bf425f50f9afa2' END,'public.conversation_profile03_grants','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_same_scope(jsonb, jsonb)','89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['original','current_scope']::text[]),
            ('conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)',CASE WHEN writer_installation=119 THEN '0666a76a343d03d4e0b1efac55e6d2f56cfe2133db7461dc6e644b637926841f' ELSE 'fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60' END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)',CASE WHEN writer_installation=119 THEN '0ff5722a8072c00e04b2aaf5f1701a46f244c857743f73ec557e64b94eb46667' ELSE CASE WHEN writer_installation IN(118,119) THEN '3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb' ELSE '1f0acf81fd7550826184f8627c50095b9fb17678b12725106c143f765b929300' END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)',CASE WHEN writer_installation IN(117,118,119) THEN 'b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb' ELSE 'f4996ae9e467fd4d77ea696ac08b3311dc8301f82a7dff452c849334dcc40e78' END,'public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('alpha_message_effect_guard()','f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()',CASE WHEN writer_installation=119 THEN '962ffbf3817bbe46913b371b787914a218f69b918b678e886db01bdd2e73c247' ELSE 'e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c' ELSE CASE WHEN writer_installation IN(118,119) THEN 'bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN 'ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9' ELSE 'd947a7947cc9717a5dd820824c466cbbea374f433e027fadccc35a46c2b0c641' END END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918' ELSE CASE WHEN writer_installation IN(118,119) THEN '891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6' ELSE CASE WHEN writer_installation IN(117,118,119) THEN '10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458' ELSE CASE WHEN writer_installation IN(116,117,118,119) THEN '04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3' ELSE '627182c7cf92410e097804d99e46e6c8a68db4c63e088322bb509b2ed5aca86c' END END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
          IF public.conversation_profile03_grant_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'grant03 schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation IN(116,117,118,119) THEN
          FOR writer_expected IN SELECT * FROM(VALUES
            ('public.hosted_runtime_native_start()',ARRAY['ec771eafcc009af67e4dcb156d3b5406c8cec64ea5e045ba624e6850d7614b54']::text[],'timestamptz','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_native_schema_valid()',CASE WHEN writer_installation=119 THEN ARRAY['be255c4a7269de17dbe975d019411481806e68eb590ac5fa66ef901f1d87f26d']::text[] ELSE CASE WHEN writer_installation IN(118,119) THEN ARRAY['89be2b62b7ce164cccef13d37b25921e873172cd5323a978429dcc7aba7b99c0']::text[] ELSE CASE WHEN writer_installation IN(117,118,119) THEN ARRAY['6fe7bf0ce4d4cb6f4113c45a2397502d99afafec4c4f026a9af6c37c5e610b4e']::text[] ELSE ARRAY['899ca98ace0d006efc0fde4e0fba02ef2f207fc112ad94f091013d2e9e503644']::text[] END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_identity_ready()',CASE WHEN writer_installation=119 THEN ARRAY['fe05742031ad01f8ec25539bfd2af310d76e31e60421eb8143e33eb91d5d21b2']::text[] ELSE CASE WHEN writer_installation IN(118,119) THEN ARRAY['044f6e1b7b29d7be2932926b81156271862f07e92d2ed5ab2c7173da8fc2491b']::text[] ELSE CASE WHEN writer_installation IN(117,118,119) THEN ARRAY['7fda07320588b52036fe5002b3c4082f5fce7c19f57d9763ecda85beb02a343f']::text[] ELSE ARRAY['88de695db32691204e5126b0b5e003aadced6f61ec77918a00618f1e2f59a532']::text[] END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_scope()',CASE WHEN writer_installation=119 THEN ARRAY['b6d01cd95aa574d52d5d81b02aa2786cd56b0c4df630c1abd123501dd1e83f7b']::text[] ELSE CASE WHEN writer_installation IN(118,119) THEN ARRAY['bc3de24b275c1789c231e5969f2dbe68947d3bae6145c74a7d0982b51ebab9f7']::text[] ELSE CASE WHEN writer_installation IN(117,118,119) THEN ARRAY['5af80385e9460db2d4381a082df2e6a1c63059b66019678518bf4133f5b5673f']::text[] ELSE ARRAY['604e7c39da10e1c34c5193dd04d5742637c611a40e3d7a28bf300ec066756dbe']::text[] END END END,'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('public.payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN ARRAY['703e51184c5636473c9f79e46785ba98c01755f35587967ac6842a9352aecc1c']::text[] ELSE CASE WHEN writer_installation IN(118,119) THEN ARRAY['bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce']::text[] ELSE CASE WHEN writer_installation IN(117,118,119) THEN ARRAY['887ad6ecb8df729687fb1ba9d05436eb7511f035f7cafc8b27685d9d5c9b2bc6']::text[] ELSE ARRAY['ed66b42a6a2dea25f770957e7c502f16adb31e784bd9fe8776e0c8f416388dd9']::text[] END END END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN ARRAY['5a5351fe82ecedb3285577549e470b24aaecef7fd2da94f8dbf1ca2a9c64c918']::text[] ELSE CASE WHEN writer_installation IN(118,119) THEN ARRAY['891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6']::text[] ELSE CASE WHEN writer_installation IN(117,118,119) THEN ARRAY['10d2f8fa9ab50a4440ff98b529637fb92f71b79743a3b23ea763b585e7d98458']::text[] ELSE ARRAY['04a3ce5ea884a1e1a62971a833e2d15e7687a137a86846395275c6bdd53fc2f3']::text[] END END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
          IF writer_installation IN(117,118,119) THEN
           FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_reviewed_send03_v2_ready()',CASE WHEN writer_installation=119 THEN '913249dc22a3aaa2d2cf904f82a9c2e73822f051445a91144407b439e8945997' ELSE CASE WHEN writer_installation IN(118,119) THEN 'b464415eb86a8498a8a2da6becc624d8a6cb42051c6161c42e3ab3e3aa24e379' ELSE '8a55e518f59d690418ec2bb6ca60b8b2c4ce51dce1759bfdc579887c5772f3ec' END END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
           ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
            IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
              AND(SELECT count(*) FROM pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1) THEN
             RAISE EXCEPTION 'reviewed V2 declaration or body inconsistent'; END IF;
           END LOOP;
           IF public.conversation_reviewed_send03_v2_ready() IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'reviewed V2 column or runtime capability inconsistent'; END IF;
          END IF;

          IF writer_installation IN(118,119) THEN
           FOR writer_expected IN SELECT * FROM(VALUES
            ('public.device_protection_mode(uuid)','322e00db3f06b5ad074549a0b0aee195fda333b3c4c9da56f00c524dc4bd02df','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('public.device_protection_actor(uuid, uuid, text, text, bigint, bigint)','85fe0c825d913bdc0fb60000b15525ce11197819ffead08c078c54252a3b105e','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('public.device_protection_lock(uuid, uuid, text, text, bigint, bigint)','c59c519eb41802618d17113eab6931d87841a52169ea43f211ffacc4ce9c44ec','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('public.device_protection_open(uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, bytea)','a5b63607715566f6f148d16e182fa797f5693d436eb8950656d1d99ea53704bb','public.device_protection_origins','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','setup','opening','command','origin_digest']::text[]),
            ('public.device_protection_association(uuid, uuid, bytea, bytea)','0b0233983d2cbc58f5f62f38faf412cd92e6ef6a7820070565650341a3463831','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','opening','association','aes_probe']::text[]),
            ('public.device_protection_attempt(uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, uuid, bytea, bytea, uuid, bytea, bytea)','91131f0e39be397b35c7af8843bda1d0f6ff054a0e90a30b4a0112e992b3d8ce','public.device_protection_attempts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','setup','opening','command','proof_request','association','aes_probe','previous_attempt','previous_core_sha256','previous_bundle_sha256']::text[]),
            ('public.device_protection_accept(uuid, uuid, text, text, bigint, bigint, uuid, uuid, uuid, uuid, uuid, bytea)','8ae393057e08e73fcd7600e6b09ce142b9ffc58a4443c82560348a2ece40ab63','public.device_protection_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','setup','opening','command','proof_request','attempt','bundle']::text[]),
            ('public.device_protection_rows_guard()','2fcf0019dbe0cc6f59e45e733e22e8fe87f1c02babaa8c25d05cd9ba1d95d3f1','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('public.device_protection_complete()','a06f702ad69d2a899c4d64da0e77cb356043a34797ab5c4b49c7a18dad25a669','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('public.device_protection_retire()','13ea73a39d4ba51291028b8151cddf174bb34e4a99ccaa26a6e9ad6180454c85','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('public.device_protection_ready()',CASE WHEN writer_installation=119 THEN 'b32597624f0409599a76f4711dea9adae0a041f98d91e0c0f25eb96419a470d9' ELSE 'c9ae9ef981e3d93c19e47237345a93c0f4fcadf4df94b24dd53295dcae3c67fa' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
           ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names) LOOP
            IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name
              AND p.provolatile::text=writer_expected.volatility AND p.proisstrict=writer_expected.is_strict
              AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
              AND(SELECT count(*) FROM pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1) THEN
             RAISE EXCEPTION 'device protection declaration or body inconsistent'; END IF;
           END LOOP;
           IF public.device_protection_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'device protection runtime capability inconsistent'; END IF;
          END IF;

          IF writer_installation=119 THEN
           FOR writer_expected IN SELECT * FROM(VALUES
            ('public.conversation_profile03_effect_fetch(public.conversation_profile03_grants)','46d5570b5118ee73d6968d1e6004a5b574c188a13663004de8ba2b1c777e7a78','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['grant_row']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_mode(uuid)','6b59433120a1e8a2bea315ddbf5970b272fe693ea42783ca2c5344a97f19f022','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_actor(uuid, uuid, text, text, bigint, bigint)','9aea9da8af7a64ceb3ecf9513941e3e757bbecae0fd9e4f1e423be93961e28e0','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_history_lock(uuid, uuid, uuid, text, text, bigint, bigint)','eb8e490e3c5b6ff86631f2fef9ace0b83285da30228f7bbbe2aadc5591e03015','public.conversation_profile03_effect_actors','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','device','site','instance','connection_epoch','deployment_epoch']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_not_quarantined(uuid, uuid, bytea, bytea)','0531273cb6c602eb5599634608e3438d5b554386d22de74df56849ca4eecd556','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','point','key_id']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_submit_bytes(uuid, uuid, uuid, uuid, uuid, bytea, bytea, smallint, bigint)','84f843efc1ee479109ff2252971fa80b717c1be5abc56dadd7e316b356beae28','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','device','event','message','attempt','fetch_sha','session_sha','segments','observed']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_identity(uuid, uuid, bytea)','db62bfbc313ca4d9594f993314b79b9e3ab4ed9d5191ca55e39b1905bbfbf8a4','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','command']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_current(uuid, uuid)','b845626068cd2a9b86db28fd5c9b926046d9c51f58459b7b1ec98f605cc5e72d','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_submit(uuid, uuid, text, text, bigint, bigint, bytea)','940c707d3dad998d28f01838390bef46060d04d09ad1a34a7ed21c2d73c26176','record','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','command_bytes','inserted','account_id','device_id','message_id','attempt_id','event_id','command','command_sha256','fetch_transcript_sha256','original_device_session_digest','segment_count','observed_ms','accepted_ms']::text[],ARRAY['i','i','i','i','i','i','i','t','t','t','t','t','t','t','t','t','t','t','t','t']::text[],ARRAY['uuid','uuid','text','text','bigint','bigint','bytea','boolean','uuid','uuid','uuid','uuid','uuid','bytea','bytea','bytea','bytea','smallint','bigint','bigint']::text[]),
            ('public.conversation_profile03_effect_state(uuid, uuid, bytea)','84e23bde85348bdd796cab1ce3ff38d9fca7366f34e4cf7197eb063d5929df24','text','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','candidate']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_project(uuid, uuid, text, bigint)','ef12f10fc5344a3507a33af747e8e9fc99be35f33dca6ba5281e183b77f605b0','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt','target','stamp_ms']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_outcome(uuid, uuid, text, text, bigint, bigint, bytea)','1d8cc03cd4a42b689282cf973a019acb2633e8e4b5f5cdd1700e8cb8bc17152d','record','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','command_bytes','inserted','account_id','device_id','message_id','attempt_id','event_id','submit_event_id','command','event_sha256','submit_command_sha256','fetch_transcript_sha256','original_device_session_digest','submit_observed_ms','segment_count','evidence','observed_ms','segment_index','recorded_ms','resulting_state']::text[],ARRAY['i','i','i','i','i','i','i','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t','t']::text[],ARRAY['uuid','uuid','text','text','bigint','bigint','bytea','boolean','uuid','uuid','uuid','uuid','uuid','uuid','bytea','bytea','bytea','bytea','bytea','bigint','smallint','smallint','bigint','smallint','bigint','text']::text[]),
            ('public.conversation_profile03_effect_session(uuid, uuid, text, text, bigint, bigint, bytea)','ab028cd81576e17e1de0e4bfa0d78592f713d333fa79fbfe048e642618d4c8b7','bytea','sql','s',true,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','key_id']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_closure_core(public.conversation_profile03_grants, public.conversation_profile03_effect_actors, public.conversation_profile03_closure_records, public.conversation_profile03_closure_challenges)','393b6ac32abe20fdd2d13b7a40793a3da61218e1d4b82fc1a4c17044326988ea','bytea','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['g','a','r','c']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_closure_challenge(uuid, uuid, text, text, bigint, bigint, uuid, bytea, uuid)','268b13735b86066ca58117dc016f1af612e632551541c54b68cc0b9ba7bf4a29','public.conversation_profile03_closure_challenges','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','proof_request','record','previous_challenge']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_closure_accept(uuid, uuid, text, text, bigint, bigint, uuid, bytea, bytea)','7b01fb22b52d7607c9f56c06b10c69ee9a11deca2abf47c0930e6342716b17ba','public.conversation_profile03_closure_receipts','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','device','site','instance','connection_epoch','deployment_epoch','proof_request','core','signature']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_pending(uuid, uuid)','d838bc9e19c423494d1b9476b27a3cfea020e54f19cee8d2f2615688f2ce4ca2','boolean','sql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','attempt']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_target(uuid, uuid)','183038293e19875f3a8912b104d1de045dd4bfb26ce5bfd743c689d9583ce886','text','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','attempt']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_writer(uuid, text, text, jsonb, jsonb)','5f9a702de26f5d62ebb1057e6e94ebe4cacb999b424e270e5072f8ae93d710d0','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_rows_guard()','27bdf3ca66e4a93d97e2049ddf6bd9040a86ee9c409afd886b59c2dff71d2ea6','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_complete()','bdacdf5a8d5582dcd0d13ed7ac9f0e43b3526821a8f0258e41b0e0622b318ea6','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[],NULL::text[],NULL::text[]),
            ('public.conversation_profile03_effect_ready()','841fd43a8c9b8821f5ab80984b5486749052315570de713854b5be3e016842ba','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[],NULL::text[],NULL::text[])
           ) expected(signature,body_sha256,result_type,language_name,volatility,is_strict,is_definer,is_set,configuration,argument_names,argument_modes,all_argument_types) LOOP
            IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_class c ON c.oid='public.accounts'::regclass
             WHERE p.oid=to_regprocedure(writer_expected.signature) AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=writer_expected.body_sha256
              AND p.prorettype=writer_expected.result_type::regtype AND l.lanname=writer_expected.language_name AND p.provolatile::text=writer_expected.volatility
              AND p.proisstrict=writer_expected.is_strict AND p.prosecdef=writer_expected.is_definer AND p.proretset=writer_expected.is_set AND p.proconfig=writer_expected.configuration
              AND p.proowner=c.relowner AND p.proparallel='u' AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0 AND NOT p.proleakproof
              AND p.proargnames IS NOT DISTINCT FROM writer_expected.argument_names AND p.proargmodes::text[] IS NOT DISTINCT FROM writer_expected.argument_modes
              AND(CASE WHEN p.proallargtypes IS NULL THEN NULL ELSE ARRAY(SELECT format_type(t,NULL) FROM unnest(p.proallargtypes) t) END) IS NOT DISTINCT FROM writer_expected.all_argument_types
              AND(SELECT count(*) FROM pg_proc x WHERE x.pronamespace=p.pronamespace AND x.proname=p.proname)=1) THEN
             RAISE EXCEPTION 'typed effect exact declaration or body inconsistent'; END IF;
           END LOOP;
           IF public.conversation_profile03_effect_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'typed effect ordinary capability inconsistent'; END IF;
          END IF;
          IF public.hosted_runtime_identity_ready() IS DISTINCT FROM true THEN
           RAISE EXCEPTION 'native hosted schema or column capability inconsistent'; END IF;
        END IF;
    END IF;
    IF to_regprocedure('public.user_membership_freshness_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.user_membership_freshness_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime can directly execute the user membership freshness helper';
    END IF;
    IF to_regprocedure('public.parent_account_mirror_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.parent_account_mirror_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime can directly execute the ownership mirror helper';
    END IF;
    FOREACH review_relation IN ARRAY ARRAY['review_realm_installation','review_brokers',
        'review_broker_sessions','review_bootstrap_attempts','review_workspaces',
        'review_access_preparations','review_access_sessions','review_access_authentications',
        'review_access_root_reauth','review_access_locators'] LOOP
        IF to_regclass(format('public.%I',review_relation)) IS NULL THEN CONTINUE; END IF;
        IF NOT has_table_privilege(current_user,format('public.%I',review_relation),'SELECT')
          OR has_table_privilege(current_user,format('public.%I',review_relation),'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
            RAISE EXCEPTION 'review persistence runtime privileges are not select-only';
        END IF;
        IF EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
            WHERE c.oid=to_regclass(format('public.%I',review_relation)) AND a.grantee=0)
          OR EXISTS(SELECT FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a
            WHERE c.attrelid=to_regclass(format('public.%I',review_relation)) AND a.grantee=0) THEN
            RAISE EXCEPTION 'public review relation or column privileges remain';
        END IF;
        FOR review_column IN SELECT attname FROM pg_attribute
          WHERE attrelid=to_regclass(format('public.%I',review_relation)) AND attnum>0 AND NOT attisdropped LOOP
            IF has_column_privilege(current_user,format('public.%I',review_relation),review_column.attname,'INSERT,UPDATE,REFERENCES') THEN
                RAISE EXCEPTION 'review persistence column write privileges remain';
            END IF;
        END LOOP;
    END LOOP;
    IF to_regclass('public.review_access_preparations') IS NOT NULL THEN
        SELECT array_agg(to_regprocedure(signature)::oid) INTO review_allowed
          FROM unnest(ARRAY[
            'public.review_access_prune()',
            'public.review_access_abuse_consume(text,bytea,bytea,integer,integer,integer,integer)',
            'public.review_access_browser(uuid,bytea,text,bytea,bytea,bigint,bytea,bigint,bigint,boolean)',
            'public.review_access_guard_lock(uuid,bytea,text,bytea,bytea,bigint,bytea)',
            'public.review_access_prepare(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,bigint,bigint,bigint,bytea)',
            'public.review_access_transition(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,text)',
            'public.review_access_login(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,uuid,smallint,bytea,bigint,uuid,uuid,bigint,text,uuid,uuid,bytea,bytea,uuid,uuid,uuid,bytea,bytea,bytea,bigint)',
            'public.review_access_broker_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_current(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,boolean)',
            'public.review_access_owner_settlement(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,text,uuid,uuid,bigint,bytea,bytea,bytea)',
            'public.review_access_root_commit(uuid,bytea,text,bytea,bytea,bigint,bytea,uuid,bytea,bytea,uuid,bytea,bytea,uuid,uuid,bigint,bytea,jsonb,uuid,uuid,bigint,text,bigint)'
        ]) AS expected(signature);
        IF array_position(review_allowed,NULL::oid) IS NOT NULL THEN
            RAISE EXCEPTION 'review access wrapper missing';
        END IF;
    END IF;
    FOR review_routine IN SELECT p.oid,p.proname FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
      AND p.proname LIKE 'review_access_%' LOOP
        IF EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            WHERE p.oid=review_routine.oid AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN
            RAISE EXCEPTION 'public review helper execution remains';
        END IF;
        IF has_function_privilege(current_user,review_routine.oid,'EXECUTE') IS DISTINCT FROM
            (review_routine.oid=ANY(review_allowed)) THEN
            RAISE EXCEPTION 'runtime review wrapper privileges are not narrow';
        END IF;
    END LOOP;
    FOR review_routine IN SELECT p.oid FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
      AND p.proname LIKE 'review_workspace_%' LOOP
        IF has_function_privilege(current_user,review_routine.oid,'EXECUTE') THEN
            RAISE EXCEPTION 'runtime can execute owner-only review persistence helper';
        END IF;
    END LOOP;
    IF current_user <> 'zrotext_runtime' OR EXISTS (
        SELECT FROM pg_roles WHERE rolname = current_user AND
        (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'unexpected runtime identity or privileges';
    END IF;
    INSERT INTO sites(site_id) VALUES ('runtime-role-smoke');
    UPDATE sites SET draining = true WHERE site_id = 'runtime-role-smoke';
    IF NOT EXISTS (SELECT FROM sites WHERE site_id = 'runtime-role-smoke' AND draining) THEN
        RAISE EXCEPTION 'runtime CRUD failed';
    END IF;
    DELETE FROM sites WHERE site_id = 'runtime-role-smoke';
    IF to_regclass('public.hosted_runtime_secrets') IS NOT NULL THEN
        IF has_any_column_privilege(current_user,'public.hosted_runtime_secrets','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_any_column_privilege(current_user,'public.hosted_runtime_sessions','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_any_column_privilege(current_user,'public.hosted_billing_resolutions','SELECT,INSERT,UPDATE,REFERENCES')
           OR has_table_privilege(current_user,'public.hosted_runtime_secrets','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_runtime_sessions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_billing_resolutions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_table_privilege(current_user,'public.hosted_billing_namespaces','INSERT,DELETE,TRUNCATE,TRIGGER')
           OR has_function_privilege(current_user,'public.hosted_resolve_review(uuid,bigint,text,text)','EXECUTE') THEN
            RAISE EXCEPTION 'hosted authority privileges are not isolated';
        END IF;
    END IF;
    IF NOT auth_abuse_consume('runtime-role-smoke', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 2, 60, 1, 60) THEN
        RAISE EXCEPTION 'runtime function execution failed';
    END IF;
    FOREACH statement IN ARRAY ARRAY[
        'CREATE TABLE public.runtime_forbidden(id integer)',
        'CREATE TEMP TABLE runtime_forbidden(id integer)',
        'CREATE SCHEMA runtime_forbidden',
        'CREATE ROLE runtime_forbidden',
        'ALTER TABLE public.sites ADD COLUMN runtime_forbidden integer',
        'TRUNCATE public.sites CASCADE',
        'DELETE FROM public.schema_migrations',
        'SET ROLE zrotext',
        'SELECT pg_read_file(''/etc/passwd'')',
        'COPY (SELECT 1) TO PROGRAM ''true'''
    ] LOOP
        BEGIN
            EXECUTE statement;
            RAISE EXCEPTION 'runtime unexpectedly allowed: %', statement;
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END LOOP;
    IF to_regclass('public.payload_profile_account_anchors') IS NOT NULL THEN
        IF has_table_privilege(current_user,'public.payload_profile_account_anchors','INSERT')
          OR has_table_privilege(current_user,'public.payload_profile_account_anchors','DELETE')
          OR has_table_privilege(current_user,'public.payload_profile_account_anchors','TRUNCATE')
          OR has_column_privilege(current_user,'public.payload_profile_account_anchors','state','UPDATE')
          OR has_column_privilege(current_user,'public.payload_profile_account_anchors','selection_epoch','UPDATE')
          OR NOT has_column_privilege(current_user,'public.payload_profile_account_anchors','account_id','UPDATE') THEN
            RAISE EXCEPTION 'runtime anchor privileges are not narrow';
        END IF;
        anchor_account := gen_random_uuid();
        INSERT INTO public.accounts(id) VALUES(anchor_account);
        PERFORM account_id FROM public.payload_profile_account_anchors
          WHERE account_id=anchor_account AND state='live' AND selection_epoch=0
          FOR SHARE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'runtime account creation did not create a live anchor';
        END IF;
        FOREACH statement IN ARRAY ARRAY[
            'UPDATE public.payload_profile_account_anchors SET selection_epoch=1',
            'UPDATE public.payload_profile_account_anchors SET state=''deleted''',
            'DELETE FROM public.payload_profile_account_anchors',
            'INSERT INTO public.payload_profile_account_anchors(account_id) SELECT id FROM public.accounts',
            'TRUNCATE public.payload_profile_account_anchors',
            'SELECT public.payload_profile_anchor_row_guard()',
            'SELECT public.payload_profile_anchor_account_created()',
            'SELECT public.payload_profile_anchor_account_changing()',
            'SELECT public.payload_profile_anchor_account_deleted()'
        ] LOOP
            BEGIN
                EXECUTE statement;
                RAISE EXCEPTION 'runtime unexpectedly allowed anchor operation';
            EXCEPTION WHEN insufficient_privilege THEN
                NULL;
            END;
        END LOOP;
        DELETE FROM public.accounts WHERE id=anchor_account;
        IF NOT EXISTS (SELECT FROM public.payload_profile_account_anchors
          WHERE account_id=anchor_account AND state='deleted' AND selection_epoch=1) THEN
            RAISE EXCEPTION 'runtime account deletion did not retain its tombstone';
        END IF;
    END IF;
END $$;
DO $$
BEGIN
    IF to_regprocedure('public.registration_browser_intent_binding_guard()') IS NOT NULL
      AND has_function_privilege(current_user,'public.registration_browser_intent_binding_guard()','EXECUTE') THEN
        RAISE EXCEPTION 'runtime registration trigger privilege is not narrow';
    END IF;
END $$;
ROLLBACK;
