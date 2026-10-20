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
        IF writer_installation NOT IN (108,109,110,111,112,113) OR writer_installation IS NULL THEN RAISE EXCEPTION 'unsupported writer installation'; END IF;
        -- Pin exact compiled108/109/110/111/112/113 bodies before invoking a readiness helper.
        -- A substituted helper returning true cannot validate its own body.
        FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','ba20a6a52c8e77012dc41546475ab19f0d1743bd4675a3184108b78abdfb4b45','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
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
        IF public.payload_profile_writer_ready() IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'mandatory writer graph or runtime authority is inconsistent';
        END IF;
        IF writer_installation IN(109,110,111,112,113) THEN
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
        IF writer_installation IN(110,111,112,113) THEN
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
            ('payload_profile_writer_version()',CASE WHEN writer_installation=113 THEN 'fb8a7d7442e6005a74a907291deb96519345d72f4fc4ce697f570c953f353b06' ELSE '6b63a842a2df506926044fe090af019931a7af02cbe957ba684341cc97dd0ee3' END,'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()',CASE WHEN writer_installation=113 THEN '5f81fc72803c531bf71bf6ae1481f14b38f8b5ddeccb9ea35b5ec6323fc0f1e0' ELSE 'fe3ed74d8d0eb38dd116aafcf6f78ec420f9ca55714587f5ce38ce9dae5122e8' END,'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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

        IF writer_installation IN(112,113) THEN
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
          IF public.payload_profile_manifest_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'manifest successor schema or runtime authority inconsistent'; END IF;
        END IF;

        IF writer_installation=113 THEN
          FOR writer_expected IN SELECT * FROM(VALUES
            ('conversation_profile03_key_until(bytea, integer, bytea, uuid, uuid, bigint)','8d60ac4df782b628a0b56375f55899c8e89564c6e2859303f85795cec88b07b9','bigint','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['manifest','role','key_id','device','line','checked_ms']::text[]),
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
          IF public.conversation_profile03_interval_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'conversation03 schema or runtime authority inconsistent'; END IF;
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
