-- SPDX-License-Identifier: AGPL-3.0-only
-- Immutable one-use effects, denial-only closure assertions and signed closure
-- receipts. SQL checks structural source, never socket authentication or ECDSA.
SET LOCAL lock_timeout='3s';
SET LOCAL statement_timeout='30s';

DO $migration$
DECLARE writer_expected record; writer_installation bigint:=118; relation_name text;
BEGIN
 IF to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'typed effects require exact primary namespace' USING ERRCODE='23514'; END IF;
FOR writer_expected IN SELECT * FROM (VALUES
            ('payload_profile_writer_json(json)','33c468e0b9077291b6b6cd4f0816952d32aa8848ddf74141eed3379c1a237227','text','plpgsql','i',true,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_guard()','f0cc270d7de8b3c0cf1335c310bae04ab2653aa8cb0ce07c56e07d74e6b1af37','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
            ('payload_profile_writer_global_guard()','b8837a0f8a53c45722524ff8082ffaebb3d992cac441a69f02e9750b2a9ee106','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_catalog_guard()','07fb697ab77abd9ae2142bb44ca59d0fdf3515a5507f0ab74c57b2d42d73bc8a','trigger','plpgsql','v',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_graph()','93654ee42134f973861336539b90c0b4f6727355c087e6d25cb86617aa6e2061','bytea','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_version()','bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce','boolean','sql','s',false,true,ARRAY['search_path=pg_catalog']),
            ('payload_profile_writer_ready()','891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6','boolean','sql','s',false,false,ARRAY['search_path=pg_catalog']),
            ('user_membership_freshness_guard()','081e92d162753786adf748356924887d6c0f896d2a885602572fb74859e47321','trigger','plpgsql','v',false,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()','bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
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
            ('payload_profile_writer_version()','bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
            ('conversation_reviewed_send03_parse(bytea)','9fc0eb8cfd60bb7296f7a34446e244573df2cbc3a519a6b0a0469e824e207b28','public.conversation_reviewed_sends03','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['intent']::text[]),
            ('conversation_reviewed_send03_envelope(public.conversation_reviewed_sends03, bytea)','5b2d548fb73912d9bcfa86e7e1b9ca760c3b649e2ecd6a236e500d9bbd2a77cc','void','plpgsql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['row','envelope']::text[]),
            ('conversation_reviewed_send03_scope(uuid, bytea, bytea, bigint, bigint)','838c3bd2760cb533b219cf19ec816a6f8e581499bf28ebc0a5683ae8eff86141','public.conversation_reviewed_sends03','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','intent','signature','permission_deadline_ms','admitted_ms']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)','b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb','public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('conversation_reviewed_send03_rows_guard()','6c9d1664c4e261cc2a5f5e3f6d5b7f704d9a1f598333b8f3f49a262a85dc6213','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_erasure_fence(uuid)','bbead3faa8de6c74998d4d2adc56f2938e26e4ef57cb66bf4b3a9ff8c7b36f94','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account']::text[]),
            ('conversation_reviewed_send03_writer(uuid, bigint, text, text, jsonb, jsonb)','e41f43888594803a29744a49173201ce1831d3997706a9a02e3dcc14a8bc5b05','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_complete()','f2422d9f1d47d10cfbf8b46f0b3177365726a3c2d1f2ce895a86c3f1701b42c7','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_reviewed_send03_message_redact()','dca2173f22a2128120c22dd1bc96f3ae9e0519b671d9d5b569b7800137709bb1','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_version()','bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('conversation_reviewed_send03_ready()','9b1ea5e893b4be156e764c25d34237d0057a7fdd30b79b813ba7a65980921e79','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[])
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
            ('conversation_profile03_grant_issue(uuid, uuid, uuid, uuid, text, text, bigint, bigint, bigint)','9d16e12ae65072a8eaefaa43ab17b14b360ed914f2c90c03af83e15a8538fc32','public.conversation_profile03_grants','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','attempt','device','site','instance','connection_epoch','deployment_epoch','permission_deadline_ms']::text[]),
            ('conversation_profile03_grant_rows_guard()','b3a9375ed664177dfb032755071667fa3ceb14dac1ce5e37c1712bb2f31cd427','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_complete()','027bcdfb9e932d3b00efde8cef3bafe6859d1681d82568b0b09bb42ab9085964','trigger','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],NULL::text[]),
            ('conversation_profile03_grant_billing(uuid, uuid)','2e9f58851146928cebfe79ec54160f0718d6cdd6ed05b3fcec29e414c84e7bf3','bigint','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message']::text[]),
            ('conversation_profile03_grant_usage_writer(uuid, text, text, jsonb, jsonb)','686ac7d0916e22b825e233f9dec01e38b5cf0bdbae7225e704ed44c18f2271ed','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_profile03_grant_scope(uuid, uuid, uuid, text, text, bigint, bigint)','7f4861c2b72b04b787fbe03dba9ea0df1b453dd90fc63181ed37b707d081231b','public.conversation_profile03_grants','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','message','device','site','instance','connection_epoch','deployment_epoch']::text[]),
            ('conversation_profile03_grant_same_scope(jsonb, jsonb)','89ee126bc416034db17eaf5596ce622dd651524f741b0012d7987e202d30b523','boolean','sql','i',true,false,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['original','current_scope']::text[]),
            ('conversation_profile03_grant_writer(uuid, text, text, jsonb, jsonb)','fcaf2e8c7e8f74f1a492c1d55c2b569470d40009c431a28e5e1b4cbb40756a60','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','relation_name','operation','old_row','new_row']::text[]),
            ('payload_profile_writer_policy(uuid, bigint, text, text, jsonb, jsonb)','3bfe4355154b72ee7b3dfb071ebf388422dde94f604096323cb248e31ab0b9bb','void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],ARRAY['account','epoch','relation_name','operation','old_row','new_row']::text[]),
            ('conversation_reviewed_send03_admit(uuid, uuid, uuid, bytea, bytea, bytea, bigint)','b7376d9339996f1ee35d3c4d786abd4507098c9fa8d4f2aa874eee797db985cb','public.conversation_reviewed_sends03','plpgsql','v',false,true,true,ARRAY['search_path=pg_catalog','lock_timeout=3s']::text[],ARRAY['account','interval','message','intent','signature','envelope','permission_deadline_ms']::text[]),
            ('alpha_message_effect_guard()','f875332d9ad2bb15cf348ef422176e65bc6d74974f27766a38b0c7513dd63bda','trigger','plpgsql','v',false,false,false,ARRAY['search_path=pg_catalog, public, pg_temp']::text[],NULL::text[]),
            ('conversation_profile03_interval_ready()','e097ea53760cb750baef4ef1df7208f548db98791845d2daf36f396598f41b3f','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_version()','bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce','boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('payload_profile_writer_ready()','891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6','boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('public.hosted_runtime_native_schema_valid()',ARRAY['89be2b62b7ce164cccef13d37b25921e873172cd5323a978429dcc7aba7b99c0']::text[],'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_identity_ready()',ARRAY['044f6e1b7b29d7be2932926b81156271862f07e92d2ed5ab2c7173da8fc2491b']::text[],'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.hosted_runtime_scope()',ARRAY['bc3de24b275c1789c231e5969f2dbe68947d3bae6145c74a7d0982b51ebab9f7']::text[],'void','plpgsql','v',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
            ('public.payload_profile_writer_version()',ARRAY['bb9c2d1b44c102469551bf37e994e8991c81469853de31e8a26d74c2d8d4e7ce']::text[],'boolean','sql','s',false,true,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
            ('public.payload_profile_writer_ready()',ARRAY['891cc3a4b7cd1ecef03f778010020af57075acdc5b7f79ae9d0208d0529a1ae6']::text[],'boolean','sql','s',false,false,false,ARRAY['search_path=pg_catalog']::text[],NULL::text[]),
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
 IF NOT(SELECT count(*)=118 AND min(version)=1 AND max(version)=118 FROM public.schema_migrations)
  OR NOT coalesce((SELECT migration_version=118 AND graph_sha256=public.payload_profile_writer_graph()
   FROM public.payload_profile_writer_catalog WHERE singleton),false) THEN
  RAISE EXCEPTION 'typed effects exact predecessor graph unavailable' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
  JOIN pg_class c ON c.oid='public.accounts'::regclass
  WHERE p.oid=to_regprocedure('public.conversation_reviewed_send03_v2_ready()')
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='b464415eb86a8498a8a2da6becc624d8a6cb42051c6161c42e3ab3e3aa24e379'
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

CREATE TABLE public.conversation_profile03_effect_actors (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 original_enrolled_point bytea NOT NULL CHECK(octet_length(original_enrolled_point)=65),
 original_enrolled_key_id bytea NOT NULL CHECK(octet_length(original_enrolled_key_id)=32),
 fetch_transcript_sha256 bytea NOT NULL CHECK(octet_length(fetch_transcript_sha256)=32),
 original_device_session_digest bytea NOT NULL CHECK(octet_length(original_device_session_digest)=32),
 minted_ms bigint NOT NULL CHECK(minted_ms>0),
 PRIMARY KEY(account_id,attempt_id),
 UNIQUE(attempt_id),
 UNIQUE(account_id,message_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,attempt_id) REFERENCES public.conversation_profile03_grants(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(get_byte(original_enrolled_point,0)=4 AND original_enrolled_key_id=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original_enrolled_point))
);

CREATE TABLE public.conversation_profile03_submits (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 event_id uuid NOT NULL CHECK(event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 command bytea NOT NULL CHECK(octet_length(command)=153),
 command_sha256 bytea NOT NULL CHECK(octet_length(command_sha256)=32),
 fetch_transcript_sha256 bytea NOT NULL CHECK(octet_length(fetch_transcript_sha256)=32),
 original_device_session_digest bytea NOT NULL CHECK(octet_length(original_device_session_digest)=32),
 segment_count smallint NOT NULL,
 observed_ms bigint NOT NULL CHECK(observed_ms>0),
 accepted_ms bigint NOT NULL CHECK(accepted_ms>0),
 PRIMARY KEY(account_id,attempt_id),
 UNIQUE(account_id,event_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,attempt_id) REFERENCES public.conversation_profile03_effect_actors(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(segment_count BETWEEN 1 AND 6)
);

CREATE TABLE public.conversation_profile03_outcomes (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 event_id uuid NOT NULL CHECK(event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 submit_event_id uuid NOT NULL CHECK(submit_event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 command bytea NOT NULL CHECK(octet_length(command)=211),
 event_sha256 bytea NOT NULL CHECK(octet_length(event_sha256)=32),
 submit_command_sha256 bytea NOT NULL CHECK(octet_length(submit_command_sha256)=32),
 fetch_transcript_sha256 bytea NOT NULL CHECK(octet_length(fetch_transcript_sha256)=32),
 original_device_session_digest bytea NOT NULL CHECK(octet_length(original_device_session_digest)=32),
 submit_observed_ms bigint NOT NULL CHECK(submit_observed_ms>0),
 segment_count smallint NOT NULL,
 evidence smallint NOT NULL,
 observed_ms bigint NOT NULL CHECK(observed_ms>0),
 segment_index smallint,
 recorded_ms bigint NOT NULL CHECK(recorded_ms>0),
 resulting_state text,
 PRIMARY KEY(account_id,event_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,attempt_id) REFERENCES public.conversation_profile03_effect_actors(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(segment_count BETWEEN 1 AND 6 AND evidence BETWEEN 0 AND 5),
 CHECK((evidence IN(0,1) AND segment_index IS NOT NULL AND segment_index>=0 AND segment_index<segment_count) OR(evidence IN(2,3,4,5) AND segment_index IS NULL)),
 CHECK(resulting_state IN('submitting','submitted','delivered','delivery_unknown','unknown','failed'))
);

CREATE UNIQUE INDEX conversation_profile03_outcomes_fact ON public.conversation_profile03_outcomes(account_id,attempt_id,evidence,coalesce(segment_index,-1));

CREATE TABLE public.conversation_profile03_closure_records (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 closure_id uuid NOT NULL CHECK(closure_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 submit_event_id uuid NOT NULL CHECK(submit_event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 record bytea NOT NULL CHECK(octet_length(record)=210),
 record_sha256 bytea NOT NULL CHECK(octet_length(record_sha256)=32),
 submit_command_sha256 bytea NOT NULL CHECK(octet_length(submit_command_sha256)=32),
 fetch_transcript_sha256 bytea NOT NULL CHECK(octet_length(fetch_transcript_sha256)=32),
 original_device_session_digest bytea NOT NULL CHECK(octet_length(original_device_session_digest)=32),
 segment_count smallint NOT NULL,
 submit_observed_ms bigint NOT NULL CHECK(submit_observed_ms>0),
 closed_from smallint NOT NULL,
 closed_ms bigint NOT NULL CHECK(closed_ms>0),
 created_ms bigint NOT NULL CHECK(created_ms>0),
 PRIMARY KEY(account_id,closure_id),
 UNIQUE(account_id,attempt_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,attempt_id) REFERENCES public.conversation_profile03_effect_actors(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(segment_count BETWEEN 1 AND 6 AND closed_from IN(0,1) AND closed_ms>=submit_observed_ms)
);

CREATE TABLE public.conversation_profile03_closure_challenges (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 closure_id uuid NOT NULL CHECK(closure_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 proof_request_id uuid NOT NULL CHECK(proof_request_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 challenge_id uuid NOT NULL CHECK(challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=32),
 core bytea NOT NULL CHECK(octet_length(core)=441),
 core_sha256 bytea NOT NULL CHECK(octet_length(core_sha256)=32),
 issued_ms bigint NOT NULL CHECK(issued_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>0),
 proof_site_id text NOT NULL,
 proof_instance_id text NOT NULL,
 proof_connection_epoch bigint NOT NULL CHECK(proof_connection_epoch>0),
 proof_deployment_epoch bigint NOT NULL CHECK(proof_deployment_epoch>0),
 proof_device_session_digest bytea NOT NULL CHECK(octet_length(proof_device_session_digest)=32),
 previous_challenge_id uuid CHECK(previous_challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 recovery_window_started_ms bigint CHECK(recovery_window_started_ms>0),
 recovery_window_ordinal smallint,
 closed_unaccepted_ms bigint CHECK(closed_unaccepted_ms>0),
 superseded_by_challenge_id uuid CHECK(superseded_by_challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 PRIMARY KEY(account_id,challenge_id),
 UNIQUE(account_id,proof_request_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,closure_id) REFERENCES public.conversation_profile03_closure_records(account_id,closure_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,previous_challenge_id) REFERENCES public.conversation_profile03_closure_challenges(account_id,challenge_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,superseded_by_challenge_id) REFERENCES public.conversation_profile03_closure_challenges(account_id,challenge_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(expires_ms>issued_ms AND expires_ms-issued_ms<=30000),
 CHECK((previous_challenge_id IS NULL AND recovery_window_started_ms IS NULL AND recovery_window_ordinal IS NULL) OR(previous_challenge_id IS NOT NULL AND recovery_window_started_ms IS NOT NULL AND recovery_window_ordinal BETWEEN 1 AND 16)),
 CHECK((closed_unaccepted_ms IS NULL)=(superseded_by_challenge_id IS NULL)),
 CHECK(closed_unaccepted_ms IS NULL OR closed_unaccepted_ms>=expires_ms),
 CHECK(octet_length(proof_site_id) BETWEEN 1 AND 256 AND octet_length(proof_instance_id) BETWEEN 1 AND 256)
);

CREATE UNIQUE INDEX conversation_profile03_closure_challenges_open ON public.conversation_profile03_closure_challenges(account_id,closure_id) WHERE closed_unaccepted_ms IS NULL;

CREATE INDEX conversation_profile03_closure_challenges_clock ON public.conversation_profile03_closure_challenges(account_id,attempt_id,issued_ms DESC);

CREATE INDEX conversation_profile03_closure_challenges_budget ON public.conversation_profile03_closure_challenges(account_id,device_id,issued_ms DESC,recovery_window_ordinal DESC) WHERE recovery_window_started_ms IS NOT NULL;

CREATE TABLE public.conversation_profile03_closure_receipts (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 message_id uuid NOT NULL CHECK(message_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 attempt_id uuid NOT NULL CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 closure_id uuid NOT NULL CHECK(closure_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 proof_request_id uuid NOT NULL CHECK(proof_request_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 challenge_id uuid NOT NULL CHECK(challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 submit_command_sha256 bytea NOT NULL CHECK(octet_length(submit_command_sha256)=32),
 record_sha256 bytea NOT NULL CHECK(octet_length(record_sha256)=32),
 core bytea NOT NULL CHECK(octet_length(core)=441),
 core_sha256 bytea NOT NULL CHECK(octet_length(core_sha256)=32),
 signature bytea NOT NULL CHECK(octet_length(signature)=64),
 signature_sha256 bytea NOT NULL CHECK(octet_length(signature_sha256)=32),
 accepted_ms bigint NOT NULL CHECK(accepted_ms>0),
 PRIMARY KEY(account_id,closure_id),
 UNIQUE(account_id,attempt_id),
 UNIQUE(account_id,challenge_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,attempt_id) REFERENCES public.conversation_profile03_effect_actors(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,closure_id) REFERENCES public.conversation_profile03_closure_records(account_id,closure_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,challenge_id) REFERENCES public.conversation_profile03_closure_challenges(account_id,challenge_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(substring(signature,1,32)>decode(repeat('00',32),'hex') AND substring(signature,1,32)<decode('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551','hex') AND substring(signature,33,32)>decode(repeat('00',32),'hex') AND substring(signature,33,32)<=decode('7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8','hex'))
);

CREATE TABLE public.conversation_profile03_effect_quarantines (
 account_id uuid NOT NULL CHECK(account_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 device_id uuid NOT NULL CHECK(device_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 original_enrolled_point bytea NOT NULL CHECK(octet_length(original_enrolled_point)=65),
 original_enrolled_key_id bytea NOT NULL CHECK(octet_length(original_enrolled_key_id)=32),
 first_attempt_id uuid NOT NULL CHECK(first_attempt_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 first_event_id uuid NOT NULL CHECK(first_event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 closure_id uuid NOT NULL CHECK(closure_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 challenge_id uuid NOT NULL CHECK(challenge_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 recorded_ms bigint NOT NULL CHECK(recorded_ms>0),
 PRIMARY KEY(account_id,device_id),
 FOREIGN KEY(account_id) REFERENCES public.accounts(id) ON DELETE CASCADE,
 FOREIGN KEY(account_id,first_attempt_id) REFERENCES public.conversation_profile03_effect_actors(account_id,attempt_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,first_event_id) REFERENCES public.conversation_profile03_outcomes(account_id,event_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(account_id,closure_id) REFERENCES public.conversation_profile03_closure_receipts(account_id,closure_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE FUNCTION public.conversation_profile03_effect_fetch(grant_row public.conversation_profile03_grants) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
SELECT convert_to('ZT/sealed-envelope-fetch/v3','UTF8')||decode('000103030301','hex')||decode(lpad(to_hex((grant_row).authenticated_segment_ceiling::integer),2,'0'),'hex')
 ||uuid_send((grant_row).account_id)||uuid_send((grant_row).device_id)||uuid_send((grant_row).line_id)||uuid_send((grant_row).message_id)||uuid_send((grant_row).attempt_id)
 ||int8send((grant_row).connection_epoch)||int8send((grant_row).deployment_epoch)||int8send((grant_row).binding_generation)||int8send((grant_row).attempt_generation)
 ||int8send((grant_row).expires_at_ms)||int8send((grant_row).trust_generation)||int8send((grant_row).manifest_version)
 ||(grant_row).reader_key_id||(grant_row).envelope_sha256||(grant_row).unsigned_sha256||(grant_row).manifest_digest||(grant_row).root_fingerprint||(grant_row).election_digest
$function$;

CREATE FUNCTION public.conversation_profile03_effect_mode(account uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 PERFORM public.hosted_runtime_marker();
 IF account IS NULL OR pg_is_in_recovery() THEN RAISE EXCEPTION 'effect primary account unavailable' USING ERRCODE='23514'; END IF;
 -- The root may have been revoked or erased; history is not content permission.
 PERFORM 1 FROM public.sealed_manifest_authorities WHERE account_id=account FOR UPDATE NOWAIT;
 IF NOT pg_try_advisory_xact_lock(public.payload_profile_account_fence_key(account)) THEN RAISE EXCEPTION 'effect account busy' USING ERRCODE='55P03'; END IF;
 PERFORM 1 FROM public.payload_profile_account_anchors WHERE account_id=account AND state='live' AND selection_epoch=1 FOR UPDATE NOWAIT;
 IF NOT FOUND OR NOT public.payload_profile_epoch_valid(account,1) THEN RAISE EXCEPTION 'effect actual anchor unavailable' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.accounts WHERE id=account AND disabled_at IS NULL FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'effect account unavailable' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_actor(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE expiry bigint; namespace public.hosted_billing_namespaces%ROWTYPE;
BEGIN
 PERFORM public.conversation_profile03_effect_mode(account);
 IF device IS NULL OR site IS NULL OR instance IS NULL OR connection_epoch IS NULL OR deployment_epoch IS NULL OR connection_epoch<=0 OR deployment_epoch<=0
  OR octet_length(site) NOT BETWEEN 1 AND 256 OR octet_length(instance) NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'effect actor input differs' USING ERRCODE='23514'; END IF;
 SELECT floor(extract(epoch FROM s.lease_until)*1000)::bigint INTO expiry FROM public.device_sessions s
 JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id) JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id)
 JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority a ON a.singleton
 WHERE s.account_id=account AND s.device_id=device AND s.site_id=site AND s.instance_id=instance
  AND s.connection_epoch=conversation_profile03_effect_actor.connection_epoch AND s.deployment_epoch=conversation_profile03_effect_actor.deployment_epoch
  AND s.deployment_epoch=a.epoch AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL
  AND k.fingerprint=sha256(k.signing_key_sec1) AND t.enabled AND NOT t.draining FOR SHARE OF s,d,k,t,a NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'effect current enrolled actor unavailable' USING ERRCODE='23514'; END IF;
 namespace:=public.hosted_runtime_marker();
 IF namespace.namespace_id IS NOT NULL THEN expiry:=least(expiry,public.hosted_runtime_expiry(namespace.namespace_id,namespace.policy_revision)); END IF;
 IF expiry<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN RAISE EXCEPTION 'effect actor expired after waits' USING ERRCODE='23514'; END IF;
 RETURN expiry;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_history_lock(account uuid,attempt uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint) RETURNS SETOF public.conversation_profile03_effect_actors
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_effect_actors%ROWTYPE;
BEGIN
 PERFORM public.conversation_profile03_effect_actor(account,device,site,instance,connection_epoch,deployment_epoch);
 SELECT * INTO row FROM public.conversation_profile03_effect_actors a WHERE a.account_id=account AND a.attempt_id=attempt;
 IF NOT FOUND THEN RETURN; END IF;
 IF row.device_id<>device OR NOT EXISTS(SELECT FROM public.device_keys k WHERE k.account_id=account AND k.device_id=device AND k.revoked_at IS NULL
  AND k.signing_key_sec1=row.original_enrolled_point AND row.original_enrolled_key_id=sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||k.signing_key_sec1)) THEN
  RAISE EXCEPTION 'effect original enrolled identity differs' USING ERRCODE='23514'; END IF;
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_not_quarantined(account uuid,device uuid,point bytea,key_id bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 IF point IS NULL OR key_id IS NULL OR octet_length(point)<>65 OR octet_length(key_id)<>32 OR EXISTS(
  SELECT FROM public.conversation_profile03_effect_quarantines q WHERE q.account_id=account
   AND(q.device_id=device OR(q.original_enrolled_point=point AND q.original_enrolled_key_id=key_id))) THEN
  RAISE EXCEPTION 'effect original actor quarantined or unavailable' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_submit_bytes(account uuid,device uuid,event uuid,message uuid,attempt uuid,fetch_sha bytea,session_sha bytea,segments smallint,observed bigint) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
SELECT uuid_send(account)||uuid_send(device)||uuid_send(event)||uuid_send(message)||uuid_send(attempt)
 ||fetch_sha||session_sha||decode(lpad(to_hex(segments::integer),2,'0'),'hex')||int8send(observed)
$function$;

CREATE FUNCTION public.conversation_profile03_effect_identity(account uuid,attempt uuid,command bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE actor public.conversation_profile03_effect_actors%ROWTYPE; g public.conversation_profile03_grants%ROWTYPE;
 observed bigint; segments integer; event uuid; digest bytea;
BEGIN
 SELECT * INTO actor FROM public.conversation_profile03_effect_actors a WHERE a.account_id=account AND a.attempt_id=attempt;
 SELECT * INTO g FROM public.conversation_profile03_grants r WHERE r.account_id=account AND r.attempt_id=attempt;
 IF actor.account_id IS NULL OR g.account_id IS NULL OR command IS NULL OR octet_length(command)<>153
  OR substring(command,1,32)<>uuid_send(account)||uuid_send(actor.device_id) OR substring(command,49,32)<>uuid_send(actor.message_id)||uuid_send(attempt)
  OR substring(command,81,64)<>actor.fetch_transcript_sha256||actor.original_device_session_digest THEN RAISE EXCEPTION 'effect exact original command differs' USING ERRCODE='23514'; END IF;
 event:=public.payload_profile_election_uuid(substring(command,33,16));segments:=get_byte(command,144);observed:=public.payload_profile_election_number(substring(command,146,8));
 IF segments NOT BETWEEN 1 AND g.authenticated_segment_ceiling OR observed<greatest(1,g.issued_ms-2000) OR observed>g.expires_at_ms+2000 THEN
  RAISE EXCEPTION 'effect original diagnostic bounds differ' USING ERRCODE='23514'; END IF;
 digest:=sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',command));
 IF EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=attempt AND s.command<>conversation_profile03_effect_identity.command)
  OR EXISTS(SELECT FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=attempt AND(o.submit_event_id,o.submit_command_sha256,o.segment_count,o.submit_observed_ms) IS DISTINCT FROM(event,digest,segments::smallint,observed))
  OR EXISTS(SELECT FROM public.conversation_profile03_closure_records c WHERE c.account_id=account AND c.attempt_id=attempt AND(c.submit_event_id,c.submit_command_sha256,c.segment_count,c.submit_observed_ms) IS DISTINCT FROM(event,digest,segments::smallint,observed)) THEN
  RAISE EXCEPTION 'effect retained original identity conflicts' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_current(account uuid,attempt uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE g public.conversation_profile03_grants%ROWTYPE; checked public.conversation_profile03_grants%ROWTYPE; a public.conversation_profile03_effect_actors%ROWTYPE; now_ms bigint;
BEGIN
 SELECT * INTO g FROM public.conversation_profile03_grants r WHERE r.account_id=account AND r.attempt_id=attempt;
 SELECT * INTO a FROM public.conversation_profile03_effect_actors r WHERE r.account_id=account AND r.attempt_id=attempt;
 IF g.account_id IS NULL OR a.account_id IS NULL THEN RAISE EXCEPTION 'typed grant actor unavailable' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_effect_not_quarantined(account,g.device_id,a.original_enrolled_point,a.original_enrolled_key_id);
 checked:=public.conversation_profile03_grant_scope(account,g.message_id,g.device_id,g.site_id,g.instance_id,g.connection_epoch,g.deployment_epoch);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT public.conversation_profile03_grant_same_scope(to_jsonb(g),to_jsonb(checked)) OR checked.authority_deadline_ms<g.expires_at_ms
  OR now_ms<g.issued_ms OR now_ms>=g.expires_at_ms OR a.fetch_transcript_sha256<>sha256(public.conversation_profile03_effect_fetch(g))
  OR NOT EXISTS(SELECT FROM public.device_keys k WHERE k.account_id=account AND k.device_id=g.device_id AND k.revoked_at IS NULL AND k.signing_key_sec1=a.original_enrolled_point) THEN
  RAISE EXCEPTION 'typed current permission changed or expired' USING ERRCODE='23514'; END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_issue(account uuid,message uuid,attempt uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,permission_deadline_ms bigint)
RETURNS SETOF public.conversation_profile03_grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; previous public.conversation_profile03_grants%ROWTYPE;
 msg public.messages%ROWTYPE; job public.dispatch_jobs%ROWTYPE; now_ms bigint; original_point bytea;
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
 SELECT r.device_point INTO original_point FROM public.conversation_reviewed_sends03 a
 JOIN public.payload_profile_v2_activation_receipts r ON(r.account_id,r.binding_id)=(a.account_id,a.original_binding_id)
 JOIN public.device_keys k ON(k.account_id,k.device_id)=(a.account_id,a.device_id) AND k.signing_key_sec1=r.device_point AND k.revoked_at IS NULL
 WHERE a.account_id=account AND a.message_id=message AND a.device_id=device FOR SHARE OF k NOWAIT;
 PERFORM public.conversation_profile03_effect_not_quarantined(account,device,original_point,sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original_point));

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
 INSERT INTO public.conversation_profile03_effect_actors(account_id,attempt_id,message_id,device_id,original_enrolled_point,original_enrolled_key_id,fetch_transcript_sha256,original_device_session_digest,minted_ms)
 VALUES(account,attempt,message,device,original_point,sha256(convert_to('ZTSE/key/v1','UTF8')||decode('000101','hex')||original_point),sha256(public.conversation_profile03_effect_fetch(row)),row.device_session_digest,row.issued_ms);
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

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_issued(account uuid,attempt uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE row public.conversation_profile03_grants%ROWTYPE; checked public.conversation_profile03_grants%ROWTYPE;
 job public.dispatch_jobs%ROWTYPE; msg public.messages%ROWTYPE; execution public.message_attempts%ROWTYPE; fence public.dispatch_fences%ROWTYPE; now_ms bigint;
BEGIN
 IF NOT EXISTS(SELECT FROM public.conversation_profile03_effect_actors a WHERE a.account_id=account AND a.attempt_id=attempt) THEN
  RAISE EXCEPTION 'typed original grant actor missing' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_effect_current(account,attempt);
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

CREATE FUNCTION public.conversation_profile03_effect_submit(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,command_bytes bytea) RETURNS TABLE(inserted boolean,account_id uuid,device_id uuid,message_id uuid,attempt_id uuid,event_id uuid,command bytea,command_sha256 bytea,fetch_transcript_sha256 bytea,original_device_session_digest bytea,segment_count smallint,observed_ms bigint,accepted_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE a public.conversation_profile03_effect_actors%ROWTYPE; row public.conversation_profile03_submits%ROWTYPE; wanted uuid; now_ms bigint;
BEGIN
 IF command_bytes IS NULL OR octet_length(command_bytes)<>153 THEN RAISE EXCEPTION 'submit exact command_bytes size differs' USING ERRCODE='23514'; END IF;
 wanted:=public.payload_profile_election_uuid(substring(command_bytes,65,16));
 SELECT * INTO a FROM public.conversation_profile03_effect_history_lock(account,wanted,device,site,instance,connection_epoch,deployment_epoch);
 IF NOT FOUND THEN RAISE EXCEPTION 'submit retained original actor missing' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_effect_identity(account,wanted,command_bytes);
 SELECT * INTO row FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=wanted;
 IF FOUND THEN
  IF row.command<>command_bytes THEN RAISE EXCEPTION 'submit original command_bytes conflicts' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT false,(row).*;RETURN;
 END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=wanted)
  OR EXISTS(SELECT FROM public.conversation_profile03_closure_records c WHERE c.account_id=account AND c.attempt_id=wanted) THEN
  RAISE EXCEPTION 'submit original denial or outcome already retained' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_grant_issued(account,wanted);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row.account_id:=account;row.device_id:=device;row.message_id:=a.message_id;row.attempt_id:=wanted;
 row.event_id:=public.payload_profile_election_uuid(substring(command_bytes,33,16));row.command:=command_bytes;
 row.command_sha256:=sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',command_bytes));
 row.fetch_transcript_sha256:=a.fetch_transcript_sha256;row.original_device_session_digest:=a.original_device_session_digest;
 row.segment_count:=get_byte(command_bytes,144);row.observed_ms:=public.payload_profile_election_number(substring(command_bytes,146,8));row.accepted_ms:=now_ms;
 IF row.observed_ms>now_ms+2000 THEN RAISE EXCEPTION 'submit diagnostic upper differs after waits' USING ERRCODE='23514'; END IF;
 INSERT INTO public.conversation_profile03_submits SELECT(row).*;
 PERFORM public.conversation_profile03_effect_project(account,wanted,'submitting',now_ms);
 PERFORM public.conversation_profile03_effect_current(account,wanted);
 RETURN QUERY SELECT true,(row).*;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_state(account uuid,attempt uuid,candidate bytea) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE n integer; ok integer; bad integer; conflict boolean; delivery boolean; timed_out boolean; unsettled boolean;
BEGIN
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_records x WHERE x.account_id=account AND x.attempt_id=attempt) THEN RETURN 'unknown'; END IF;
 WITH facts AS(SELECT command FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=attempt
  UNION SELECT candidate WHERE candidate IS NOT NULL), decoded AS(
  SELECT get_byte(command,200) AS segments,get_byte(command,201) AS evidence,get_byte(command,210) AS position FROM facts)
 SELECT max(segments),count(DISTINCT position) FILTER(WHERE evidence=0),count(DISTINCT position) FILTER(WHERE evidence=1),
  coalesce(bool_or(evidence IN(4,5)),false),coalesce(bool_or(evidence=2),false),coalesce(bool_or(evidence=3),false),
  EXISTS(SELECT FROM decoded x JOIN decoded y ON x.position=y.position AND x.evidence=0 AND y.evidence=1)
 INTO n,ok,bad,conflict,delivery,timed_out,unsettled FROM decoded;
 IF NOT EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=attempt) THEN RETURN 'unknown'; END IF;
 IF conflict OR unsettled OR(bad>0 AND n>1) THEN RETURN 'unknown'; END IF;
 IF bad>0 THEN RETURN 'failed'; END IF;
 IF ok=n AND n IS NOT NULL THEN
  IF delivery THEN RETURN 'delivered'; END IF;
  IF timed_out THEN RETURN 'delivery_unknown'; END IF;
  RETURN 'submitted';
 END IF;
 IF EXISTS(SELECT FROM public.message_attempts m WHERE m.account_id=account AND m.id=attempt AND m.status='unknown') THEN RETURN 'unknown'; END IF;
 RETURN 'submitting';
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_project(account uuid,attempt uuid,target text,stamp_ms bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE g public.conversation_profile03_grants%ROWTYPE; msg public.messages%ROWTYPE; old_fence text; attempt_state text; fence_state text; stamp timestamptz;
BEGIN
 IF target NOT IN('submitting','submitted','delivered','delivery_unknown','unknown','failed') OR stamp_ms IS NULL THEN
  RAISE EXCEPTION 'typed projection state unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO g FROM public.conversation_profile03_grants r WHERE r.account_id=account AND r.attempt_id=attempt;
 IF NOT FOUND THEN RAISE EXCEPTION 'typed projection original grant missing' USING ERRCODE='23514'; END IF;
 stamp:=to_timestamp(stamp_ms::double precision/1000);
 attempt_state:=CASE WHEN target IN('delivered','delivery_unknown') THEN 'submitted' ELSE target END;
 SELECT outcome INTO old_fence FROM public.dispatch_fences f WHERE f.account_id=account AND f.attempt_id=attempt FOR UPDATE NOWAIT;
 fence_state:=CASE WHEN old_fence IN('submitted','failed') THEN old_fence ELSE attempt_state END;
 SELECT * INTO msg FROM public.messages m WHERE m.account_id=account AND m.id=g.message_id FOR UPDATE NOWAIT;
 IF FOUND AND msg.state<>target THEN UPDATE public.messages m SET state=target,state_version=m.state_version+1,updated_at=stamp WHERE m.account_id=account AND m.id=g.message_id; END IF;
 UPDATE public.message_attempts a SET status=attempt_state,updated_at=stamp WHERE a.account_id=account AND a.id=attempt AND a.status<>attempt_state;
 UPDATE public.dispatch_fences f SET outcome=fence_state WHERE f.account_id=account AND f.attempt_id=attempt AND f.outcome<>fence_state;
 IF fence_state IN('submitted','failed') THEN UPDATE public.dispatch_jobs j SET finished_at=coalesce(j.finished_at,stamp),lease_owner=NULL,lease_until=NULL
  WHERE j.account_id=account AND j.message_id=g.message_id AND j.finished_at IS NULL; END IF;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_outcome(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,command_bytes bytea) RETURNS TABLE(inserted boolean,account_id uuid,device_id uuid,message_id uuid,attempt_id uuid,event_id uuid,submit_event_id uuid,command bytea,event_sha256 bytea,submit_command_sha256 bytea,fetch_transcript_sha256 bytea,original_device_session_digest bytea,submit_observed_ms bigint,segment_count smallint,evidence smallint,observed_ms bigint,segment_index smallint,recorded_ms bigint,resulting_state text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE a public.conversation_profile03_effect_actors%ROWTYPE; row public.conversation_profile03_outcomes%ROWTYPE; original bytea; wanted uuid; now_ms bigint; target text;
BEGIN
 IF command_bytes IS NULL OR octet_length(command_bytes)<>211 THEN RAISE EXCEPTION 'outcome exact command_bytes size differs' USING ERRCODE='23514'; END IF;
 wanted:=public.payload_profile_election_uuid(substring(command_bytes,65,16));
 SELECT * INTO a FROM public.conversation_profile03_effect_history_lock(account,wanted,device,site,instance,connection_epoch,deployment_epoch);
 IF NOT FOUND OR substring(command_bytes,1,32)<>uuid_send(account)||uuid_send(device) OR substring(command_bytes,49,16)<>uuid_send(a.message_id) THEN
  RAISE EXCEPTION 'outcome original actor differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.event_id=public.payload_profile_election_uuid(substring(command_bytes,33,16));
 IF FOUND THEN
  IF row.command<>command_bytes THEN RAISE EXCEPTION 'outcome event bytes conflict' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT false,(row).*;RETURN;
 END IF;
 original:=public.conversation_profile03_effect_submit_bytes(account,device,public.payload_profile_election_uuid(substring(command_bytes,81,16)),a.message_id,wanted,
  substring(command_bytes,129,32),substring(command_bytes,161,32),get_byte(command_bytes,200)::smallint,public.payload_profile_election_number(substring(command_bytes,193,8)));
 PERFORM public.conversation_profile03_effect_identity(account,wanted,original);
 IF substring(command_bytes,97,32)<>sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',original)) THEN
  RAISE EXCEPTION 'outcome original submit commitment differs' USING ERRCODE='23514'; END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 row.account_id:=account;row.device_id:=device;row.message_id:=a.message_id;row.attempt_id:=wanted;row.event_id:=public.payload_profile_election_uuid(substring(command_bytes,33,16));
 row.submit_event_id:=public.payload_profile_election_uuid(substring(command_bytes,81,16));row.command:=command_bytes;
 row.event_sha256:=sha256(public.payload_profile_election_frame('ZTSE/conversation/outcome-command03/v1',command_bytes));
 row.submit_command_sha256:=substring(command_bytes,97,32);row.fetch_transcript_sha256:=substring(command_bytes,129,32);row.original_device_session_digest:=substring(command_bytes,161,32);
 row.submit_observed_ms:=public.payload_profile_election_number(substring(command_bytes,193,8));row.segment_count:=get_byte(command_bytes,200);row.evidence:=get_byte(command_bytes,201);
 row.observed_ms:=public.payload_profile_election_number(substring(command_bytes,203,8));row.segment_index:=CASE WHEN get_byte(command_bytes,210)=255 THEN NULL ELSE get_byte(command_bytes,210) END;
 row.recorded_ms:=now_ms;
 IF row.observed_ms<row.submit_observed_ms OR row.observed_ms>now_ms+2000 THEN RAISE EXCEPTION 'outcome diagnostic clock differs' USING ERRCODE='23514'; END IF;
 target:=public.conversation_profile03_effect_state(account,wanted,command_bytes);
 SELECT target INTO row.resulting_state FROM public.messages m WHERE m.account_id=account AND m.id=a.message_id;
 INSERT INTO public.conversation_profile03_outcomes SELECT(row).*;
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_receipts c WHERE c.account_id=account AND c.attempt_id=wanted) THEN
  INSERT INTO public.conversation_profile03_effect_quarantines(account_id,device_id,original_enrolled_point,original_enrolled_key_id,first_attempt_id,first_event_id,closure_id,challenge_id,recorded_ms)
  SELECT account,device,a.original_enrolled_point,a.original_enrolled_key_id,wanted,row.event_id,c.closure_id,c.challenge_id,now_ms
  FROM public.conversation_profile03_closure_receipts c WHERE c.account_id=account AND c.attempt_id=wanted
  ON CONFLICT ON CONSTRAINT conversation_profile03_effect_quarantines_pkey DO NOTHING;
 END IF;
 PERFORM public.conversation_profile03_effect_project(account,wanted,target,now_ms);
 RETURN QUERY SELECT true,(row).*;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_session(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,key_id bytea) RETURNS bytea
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path TO pg_catalog AS $function$
SELECT sha256(public.payload_profile_election_frame('ZTSE/line/payload-profile/device-session/v1',
 uuid_send($1)||uuid_send($2)||int4send(octet_length($3))||convert_to($3,'UTF8')||int4send(octet_length($4))||convert_to($4,'UTF8')
 ||int8send($5)||int8send($6)||int2send(s.line_activation_version::smallint)||$7))
 FROM public.device_sessions s WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4
  AND s.connection_epoch=$5 AND s.deployment_epoch=$6
$function$;

CREATE FUNCTION public.conversation_profile03_effect_closure_core(g public.conversation_profile03_grants,a public.conversation_profile03_effect_actors,r public.conversation_profile03_closure_records,c public.conversation_profile03_closure_challenges) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
SELECT decode('5a544e5301030300','hex')||uuid_send((c).account_id)||uuid_send((c).device_id)||uuid_send((r).submit_event_id)||uuid_send((c).message_id)
 ||uuid_send((c).attempt_id)||uuid_send((c).closure_id)||uuid_send((c).proof_request_id)||uuid_send((c).challenge_id)
 ||int8send((g).connection_epoch)||int8send((g).deployment_epoch)||int8send((c).proof_connection_epoch)||int8send((c).proof_deployment_epoch)
 ||int8send((g).attempt_generation)||int8send((r).segment_count::bigint)||int8send((r).submit_observed_ms)||int8send((r).closed_ms)||int8send((c).issued_ms)||int8send((c).expires_ms)
 ||(a).fetch_transcript_sha256||(r).submit_command_sha256||(a).original_device_session_digest||(c).proof_device_session_digest||(a).original_enrolled_key_id||sha256((c).nonce)||(r).record_sha256
 ||decode(lpad(to_hex((r).closed_from::integer),2,'0'),'hex')
$function$;

CREATE FUNCTION public.conversation_profile03_effect_closure_challenge(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,proof_request uuid,record bytea,previous_challenge uuid) RETURNS SETOF public.conversation_profile03_closure_challenges
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE a public.conversation_profile03_effect_actors%ROWTYPE; g public.conversation_profile03_grants%ROWTYPE;
 r public.conversation_profile03_closure_records%ROWTYPE; c public.conversation_profile03_closure_challenges%ROWTYPE; prior public.conversation_profile03_closure_challenges%ROWTYPE;
 original bytea; wanted uuid; expiry bigint; now_ms bigint; window_ms bigint; ordinal smallint;
BEGIN
 IF record IS NULL OR octet_length(record)<>210 OR proof_request IS NULL THEN RAISE EXCEPTION 'closure exact command input differs' USING ERRCODE='23514'; END IF;
 wanted:=public.payload_profile_election_uuid(substring(record,65,16));
 SELECT * INTO a FROM public.conversation_profile03_effect_history_lock(account,wanted,device,site,instance,connection_epoch,deployment_epoch);
 IF NOT FOUND OR substring(record,1,32)<>uuid_send(account)||uuid_send(device) OR substring(record,49,16)<>uuid_send(a.message_id) THEN
  RAISE EXCEPTION 'closure original actor differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM public.conversation_profile03_closure_records x WHERE x.account_id=account AND x.attempt_id=wanted;
 SELECT * INTO c FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.proof_request_id=proof_request;
 IF c.challenge_id IS NOT NULL THEN
  IF r.record IS DISTINCT FROM record OR(c.attempt_id,c.previous_challenge_id) IS DISTINCT FROM(wanted,previous_challenge) THEN
   RAISE EXCEPTION 'closure proof request original differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT c;RETURN;
 END IF;
 IF r.closure_id IS NOT NULL AND r.record<>record THEN RAISE EXCEPTION 'closure permanent assertion differs' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_receipts x WHERE x.account_id=account AND x.attempt_id=wanted) THEN
  RAISE EXCEPTION 'closure already accepted' USING ERRCODE='23514'; END IF;
 original:=public.conversation_profile03_effect_submit_bytes(account,device,public.payload_profile_election_uuid(substring(record,33,16)),a.message_id,wanted,
  substring(record,97,32),substring(record,161,32),get_byte(record,192)::smallint,public.payload_profile_election_number(substring(record,194,8)));
 PERFORM public.conversation_profile03_effect_identity(account,wanted,original);
 IF substring(record,129,32)<>sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',original)) THEN
  RAISE EXCEPTION 'closure submit commitment differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO g FROM public.conversation_profile03_grants x WHERE x.account_id=account AND x.attempt_id=wanted;
 expiry:=public.conversation_profile03_effect_actor(account,device,site,instance,connection_epoch,deployment_epoch);
 SELECT * INTO prior FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.closure_id=public.payload_profile_election_uuid(substring(record,81,16)) AND x.closed_unaccepted_ms IS NULL;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF(previous_challenge IS NULL) IS DISTINCT FROM(prior.challenge_id IS NULL) OR(previous_challenge IS NOT NULL AND(previous_challenge<>prior.challenge_id OR now_ms<prior.expires_ms)) THEN
  RAISE EXCEPTION 'closure exact expired predecessor unavailable' USING ERRCODE='23514'; END IF;
 IF prior.challenge_id IS NOT NULL THEN
  SELECT x.recovery_window_started_ms,x.recovery_window_ordinal INTO window_ms,ordinal FROM public.conversation_profile03_closure_challenges x
   WHERE x.account_id=account AND x.device_id=device AND x.recovery_window_started_ms IS NOT NULL ORDER BY x.issued_ms DESC,x.recovery_window_ordinal DESC LIMIT 1;
  IF window_ms IS NULL OR now_ms-window_ms>=86400000 THEN window_ms:=now_ms;ordinal:=0; END IF;
  IF now_ms<window_ms OR ordinal>=16 THEN RAISE EXCEPTION 'closure explicit recovery budget exhausted' USING ERRCODE='23514'; END IF;
 END IF;
 IF r.closure_id IS NULL THEN
  r.account_id:=account;r.device_id:=device;r.message_id:=a.message_id;r.attempt_id:=wanted;r.closure_id:=public.payload_profile_election_uuid(substring(record,81,16));
  r.submit_event_id:=public.payload_profile_election_uuid(substring(record,33,16));r.record:=record;r.record_sha256:=sha256(public.payload_profile_election_frame('ZTSE/conversation/no-submit-record03/v1',record));
  r.submit_command_sha256:=substring(record,129,32);r.fetch_transcript_sha256:=a.fetch_transcript_sha256;r.original_device_session_digest:=a.original_device_session_digest;
  r.segment_count:=get_byte(record,192);r.submit_observed_ms:=public.payload_profile_election_number(substring(record,194,8));r.closed_from:=get_byte(record,201);
  r.closed_ms:=public.payload_profile_election_number(substring(record,203,8));r.created_ms:=now_ms;
  IF r.closed_ms>now_ms+2000 THEN RAISE EXCEPTION 'closure diagnostic time unavailable' USING ERRCODE='23514'; END IF;
  IF r.closed_from=1 AND NOT EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=wanted AND s.xmin::text<>pg_current_xact_id()::text) THEN
   RAISE EXCEPTION 'closure ACK-authorized phase lacks original committed submit' USING ERRCODE='23514'; END IF;
  INSERT INTO public.conversation_profile03_closure_records SELECT(r).*;
 END IF;
 c.account_id:=account;c.device_id:=device;c.message_id:=a.message_id;c.attempt_id:=wanted;c.closure_id:=r.closure_id;c.proof_request_id:=proof_request;
 c.challenge_id:=gen_random_uuid();c.nonce:=uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid());c.issued_ms:=now_ms;c.expires_ms:=least(now_ms+30000,expiry);
 c.proof_site_id:=site;c.proof_instance_id:=instance;c.proof_connection_epoch:=connection_epoch;c.proof_deployment_epoch:=deployment_epoch;
 c.proof_device_session_digest:=public.conversation_profile03_effect_session(account,device,site,instance,connection_epoch,deployment_epoch,a.original_enrolled_key_id);
 c.previous_challenge_id:=previous_challenge;
 IF prior.challenge_id IS NOT NULL THEN
  c.recovery_window_started_ms:=window_ms;c.recovery_window_ordinal:=ordinal+1;
  UPDATE public.conversation_profile03_closure_challenges x SET closed_unaccepted_ms=now_ms,superseded_by_challenge_id=c.challenge_id WHERE x.account_id=account AND x.challenge_id=prior.challenge_id;
 END IF;
 c.core:=public.conversation_profile03_effect_closure_core(g,a,r,c);c.core_sha256:=sha256(c.core);
 INSERT INTO public.conversation_profile03_closure_challenges SELECT(c).*;
 -- A local assertion is denial only; it never creates a submit or releases busy.
 IF NOT EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.attempt_id=wanted AND f.outcome IN('submitted','failed')) THEN
  PERFORM public.conversation_profile03_effect_project(account,wanted,'unknown',now_ms);
 END IF;
 RETURN NEXT c;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_closure_accept(account uuid,device uuid,site text,instance text,connection_epoch bigint,deployment_epoch bigint,proof_request uuid,core bytea,signature bytea) RETURNS SETOF public.conversation_profile03_closure_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE a public.conversation_profile03_effect_actors%ROWTYPE; c public.conversation_profile03_closure_challenges%ROWTYPE;
 r public.conversation_profile03_closure_records%ROWTYPE; row public.conversation_profile03_closure_receipts%ROWTYPE; wanted uuid; expiry bigint; now_ms bigint;
BEGIN
 IF core IS NULL OR octet_length(core)<>441 OR signature IS NULL OR octet_length(signature)<>64 OR proof_request IS NULL THEN
  RAISE EXCEPTION 'closure exact proof input unavailable' USING ERRCODE='23514'; END IF;
 wanted:=public.payload_profile_election_uuid(substring(core,73,16));
 SELECT * INTO a FROM public.conversation_profile03_effect_history_lock(account,wanted,device,site,instance,connection_epoch,deployment_epoch);
 IF NOT FOUND THEN RAISE EXCEPTION 'closure retained original actor missing' USING ERRCODE='23514'; END IF;
 SELECT * INTO row FROM public.conversation_profile03_closure_receipts x WHERE x.account_id=account AND x.attempt_id=wanted;
 IF FOUND THEN
  IF(row.proof_request_id,row.core,row.signature) IS DISTINCT FROM(proof_request,core,signature) THEN RAISE EXCEPTION 'closure accepted proof differs' USING ERRCODE='23514'; END IF;
  RETURN NEXT row;RETURN;
 END IF;
 SELECT * INTO c FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.proof_request_id=proof_request;
 SELECT * INTO r FROM public.conversation_profile03_closure_records x WHERE x.account_id=account AND x.closure_id=c.closure_id;
 expiry:=public.conversation_profile03_effect_actor(account,device,site,instance,connection_epoch,deployment_epoch);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF c.challenge_id IS NULL OR c.attempt_id<>wanted OR c.core<>core OR c.closed_unaccepted_ms IS NOT NULL
  OR(c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch) IS DISTINCT FROM(site,instance,connection_epoch,deployment_epoch)
  OR c.proof_device_session_digest IS DISTINCT FROM public.conversation_profile03_effect_session(account,device,site,instance,connection_epoch,deployment_epoch,a.original_enrolled_key_id)
  OR now_ms<c.issued_ms OR now_ms>=least(c.expires_ms,expiry)
  OR EXISTS(SELECT FROM public.conversation_profile03_outcomes x WHERE x.account_id=account AND x.attempt_id=wanted) THEN
  RAISE EXCEPTION 'closure current exact challenge or no-contrary scope unavailable' USING ERRCODE='23514'; END IF;
 -- Structural canonical raw P256 bounds; ECDSA verification stays in Rust.
 IF substring(signature,1,32)<=decode(repeat('00',32),'hex') OR substring(signature,1,32)>=decode('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551','hex')
  OR substring(signature,33,32)<=decode(repeat('00',32),'hex') OR substring(signature,33,32)>decode('7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8','hex') THEN
  RAISE EXCEPTION 'closure raw low-S signature bounds differ' USING ERRCODE='23514'; END IF;
 row.account_id:=account;row.device_id:=device;row.message_id:=a.message_id;row.attempt_id:=wanted;row.closure_id:=c.closure_id;row.proof_request_id:=proof_request;row.challenge_id:=c.challenge_id;
 row.submit_command_sha256:=r.submit_command_sha256;row.record_sha256:=r.record_sha256;row.core:=core;row.core_sha256:=sha256(core);row.signature:=signature;row.signature_sha256:=sha256(signature);row.accepted_ms:=now_ms;
 INSERT INTO public.conversation_profile03_closure_receipts SELECT(row).*;
 PERFORM public.conversation_profile03_effect_project(account,wanted,'failed',now_ms);
 RETURN NEXT row;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_pending(account uuid,attempt uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
SELECT EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=attempt AND s.xmin::text=pg_current_xact_id()::text)
 OR EXISTS(SELECT FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=attempt AND o.xmin::text=pg_current_xact_id()::text)
 OR EXISTS(SELECT FROM public.conversation_profile03_closure_challenges c WHERE c.account_id=account AND c.attempt_id=attempt AND c.xmin::text=pg_current_xact_id()::text)
 OR EXISTS(SELECT FROM public.conversation_profile03_closure_receipts r WHERE r.account_id=account AND r.attempt_id=attempt AND r.xmin::text=pg_current_xact_id()::text)
$function$;

CREATE FUNCTION public.conversation_profile03_effect_target(account uuid,attempt uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
BEGIN
 IF EXISTS(SELECT FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=attempt) THEN RETURN public.conversation_profile03_effect_state(account,attempt,NULL); END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_receipts r WHERE r.account_id=account AND r.attempt_id=attempt) THEN RETURN 'failed'; END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_records r WHERE r.account_id=account AND r.attempt_id=attempt) THEN
  IF EXISTS(SELECT FROM public.dispatch_fences f WHERE f.account_id=account AND f.attempt_id=attempt AND f.outcome IN('submitted','failed')) THEN RETURN NULL; END IF;
  RETURN 'unknown';
 END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=attempt) THEN RETURN 'submitting'; END IF;
 RAISE EXCEPTION 'typed transition original provenance absent' USING ERRCODE='23514';
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_writer(account uuid,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE g public.conversation_profile03_grants%ROWTYPE; wanted uuid; target text; projected text; source_ms bigint; actual_ms bigint; before_state text; after_state text; old_fence text;
BEGIN
 wanted:=CASE WHEN relation_name='messages' THEN coalesce((new_row->>'id')::uuid,(old_row->>'id')::uuid) ELSE coalesce((new_row->>'message_id')::uuid,(old_row->>'message_id')::uuid) END;
 SELECT * INTO g FROM public.conversation_profile03_grants r WHERE r.account_id=account AND r.message_id=wanted;
 IF NOT FOUND OR operation<>'UPDATE' OR old_row IS NULL OR new_row IS NULL OR relation_name NOT IN('messages','dispatch_jobs','message_attempts','dispatch_fences')
  OR NOT public.conversation_profile03_effect_pending(account,g.attempt_id) THEN RAISE EXCEPTION 'typed exact pending transition absent' USING ERRCODE='23514'; END IF;
 IF((old_row->>'account_id')::uuid,(old_row->>'device_id')::uuid) IS DISTINCT FROM(account,g.device_id) THEN RAISE EXCEPTION 'typed original owner or device differs' USING ERRCODE='23514'; END IF;
 PERFORM public.conversation_profile03_effect_mode(account);
 target:=public.conversation_profile03_effect_target(account,g.attempt_id);
 SELECT max(stamp) INTO source_ms FROM(
  SELECT s.accepted_ms AS stamp FROM public.conversation_profile03_submits s WHERE s.account_id=account AND s.attempt_id=g.attempt_id AND s.xmin::text=pg_current_xact_id()::text
  UNION ALL SELECT o.recorded_ms FROM public.conversation_profile03_outcomes o WHERE o.account_id=account AND o.attempt_id=g.attempt_id AND o.xmin::text=pg_current_xact_id()::text
  UNION ALL SELECT c.issued_ms FROM public.conversation_profile03_closure_challenges c WHERE c.account_id=account AND c.attempt_id=g.attempt_id AND c.xmin::text=pg_current_xact_id()::text
  UNION ALL SELECT r.accepted_ms FROM public.conversation_profile03_closure_receipts r WHERE r.account_id=account AND r.attempt_id=g.attempt_id AND r.xmin::text=pg_current_xact_id()::text) x;
 IF target IS NULL OR source_ms IS NULL THEN RAISE EXCEPTION 'typed terminal assertion permits no transition' USING ERRCODE='23514'; END IF;
 IF relation_name='messages' THEN
  IF(old_row-ARRAY['state','state_version','updated_at']) IS DISTINCT FROM(new_row-ARRAY['state','state_version','updated_at'])
   OR new_row->>'state'<>target OR old_row->>'state'=target OR(new_row->>'state_version')::bigint<>(old_row->>'state_version')::bigint+1
   OR(new_row->>'updated_at')::timestamptz<>to_timestamp(source_ms::double precision/1000) THEN RAISE EXCEPTION 'typed message projection differs' USING ERRCODE='23514'; END IF;
  IF target='submitting' AND old_row->>'state'='claimed' AND(old_row->>'state_version')::bigint<>2 THEN RAISE EXCEPTION 'typed initial claim differs' USING ERRCODE='23514'; END IF;
 ELSIF relation_name='message_attempts' THEN
  projected:=CASE WHEN target IN('delivered','delivery_unknown') THEN 'submitted' ELSE target END;
  IF(old_row-ARRAY['status','updated_at']) IS DISTINCT FROM(new_row-ARRAY['status','updated_at']) OR(new_row->>'id')::uuid<>g.attempt_id
   OR((old_row->>'generation')::bigint,(old_row->>'session_epoch')::bigint,(old_row->>'deployment_epoch')::bigint) IS DISTINCT FROM(g.attempt_generation,g.connection_epoch,g.deployment_epoch)
   OR new_row->>'status'<>projected OR old_row->>'status'=projected OR(new_row->>'updated_at')::timestamptz<>to_timestamp(source_ms::double precision/1000) THEN
   RAISE EXCEPTION 'typed attempt projection differs' USING ERRCODE='23514'; END IF;
 ELSIF relation_name='dispatch_fences' THEN
  projected:=CASE WHEN target IN('delivered','delivery_unknown') THEN 'submitted' ELSE target END;
  IF(old_row-'outcome') IS DISTINCT FROM(new_row-'outcome') OR(new_row->>'attempt_id')::uuid<>g.attempt_id OR old_row->>'outcome' IN('submitted','failed')
   OR((old_row->>'generation')::bigint,(old_row->>'session_epoch')::bigint,(old_row->>'deployment_epoch')::bigint,(old_row->>'grant_expires_at')::timestamptz)
    IS DISTINCT FROM(g.attempt_generation,g.connection_epoch,g.deployment_epoch,to_timestamp(g.expires_at_ms::double precision/1000))
   OR new_row->>'outcome'<>projected OR old_row->>'outcome'=projected THEN RAISE EXCEPTION 'typed busy fence projection differs' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT outcome INTO old_fence FROM public.dispatch_fences f WHERE f.account_id=account AND f.attempt_id=g.attempt_id;
  IF old_fence NOT IN('submitted','failed') OR old_row->>'finished_at' IS NOT NULL
   OR(old_row-ARRAY['finished_at','lease_owner','lease_until']) IS DISTINCT FROM(new_row-ARRAY['finished_at','lease_owner','lease_until'])
   OR new_row->>'lease_owner' IS NOT NULL OR new_row->>'lease_until' IS NOT NULL OR(new_row->>'finished_at')::timestamptz<>to_timestamp(source_ms::double precision/1000)
   OR((old_row->>'generation')::bigint,old_row->>'lease_owner',(old_row->>'lease_until')::timestamptz,(old_row->>'grant_issued_at')::timestamptz)
    IS DISTINCT FROM(g.attempt_generation,g.lease_owner,to_timestamp(g.expires_at_ms::double precision/1000),to_timestamp(g.issued_ms::double precision/1000)) THEN
    RAISE EXCEPTION 'typed terminal job projection differs' USING ERRCODE='23514'; END IF;
 END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.conversation_profile03_grant_writer(account uuid,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
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
 IF operation='UPDATE' AND public.conversation_profile03_effect_pending(account,row.attempt_id) THEN
  PERFORM public.conversation_profile03_effect_writer(account,relation_name,operation,old_row,new_row);RETURN;
 END IF;
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

CREATE FUNCTION public.conversation_profile03_effect_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE wanted uuid; attempt uuid; data jsonb; a public.conversation_profile03_effect_actors%ROWTYPE; g public.conversation_profile03_grants%ROWTYPE;
 c public.conversation_profile03_closure_challenges%ROWTYPE; r public.conversation_profile03_closure_records%ROWTYPE;
 original bytea; bytes bytea; now_ms bigint; stamp_ms bigint; expected_state text; current_point bytea; prior_window bigint; prior_ordinal smallint; latest_ms bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>to_regclass(format('public.%I',TG_TABLE_NAME)) OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
  OR TG_TABLE_NAME NOT IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines') THEN
  RAISE EXCEPTION 'typed ledger trigger context differs' USING ERRCODE='23514'; END IF;
 data:=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;wanted:=(data->>'account_id')::uuid;
 IF TG_OP='DELETE' AND NOT EXISTS(SELECT FROM public.accounts WHERE id=wanted) THEN RETURN OLD; END IF;
 PERFORM public.conversation_profile03_effect_mode(wanted);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_NAME<>'conversation_profile03_closure_challenges' THEN RAISE EXCEPTION 'typed original immutable' USING ERRCODE='23514'; END IF;
  IF OLD.closed_unaccepted_ms IS NOT NULL OR NEW.closed_unaccepted_ms IS NULL
   OR NEW.superseded_by_challenge_id IS NULL OR NEW.closed_unaccepted_ms<OLD.expires_ms OR NEW.closed_unaccepted_ms>now_ms
   OR(to_jsonb(OLD)-ARRAY['closed_unaccepted_ms','superseded_by_challenge_id']) IS DISTINCT FROM(data-ARRAY['closed_unaccepted_ms','superseded_by_challenge_id'])
   OR EXISTS(SELECT FROM public.conversation_profile03_closure_receipts x WHERE x.account_id=wanted AND x.closure_id=OLD.closure_id) THEN
   RAISE EXCEPTION 'typed challenge history immutable' USING ERRCODE='23514'; END IF;
 ELSIF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'typed originals retained until account erasure' USING ERRCODE='23514';
 ELSE
  attempt:=coalesce((data->>'attempt_id')::uuid,(data->>'first_attempt_id')::uuid);
  SELECT * INTO g FROM public.conversation_profile03_grants x WHERE x.account_id=wanted AND x.attempt_id=attempt;
  IF NOT FOUND OR g.device_id<>(data->>'device_id')::uuid OR(TG_TABLE_NAME<>'conversation_profile03_effect_quarantines' AND g.message_id<>(data->>'message_id')::uuid) THEN
   RAISE EXCEPTION 'typed immutable original grant differs' USING ERRCODE='23514'; END IF;
  SELECT max(stamp) INTO latest_ms FROM(
   SELECT x.accepted_ms AS stamp FROM public.conversation_profile03_submits x WHERE x.account_id=wanted AND x.attempt_id=attempt
   UNION ALL SELECT x.recorded_ms FROM public.conversation_profile03_outcomes x WHERE x.account_id=wanted AND x.attempt_id=attempt
   UNION ALL SELECT x.created_ms FROM public.conversation_profile03_closure_records x WHERE x.account_id=wanted AND x.attempt_id=attempt
   UNION ALL SELECT x.issued_ms FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=wanted AND x.attempt_id=attempt
   UNION ALL SELECT x.accepted_ms FROM public.conversation_profile03_closure_receipts x WHERE x.account_id=wanted AND x.attempt_id=attempt) stamps;
  IF latest_ms IS NOT NULL AND now_ms<latest_ms THEN RAISE EXCEPTION 'typed original primary clock regressed' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='conversation_profile03_effect_actors' THEN
   SELECT p.device_point INTO current_point FROM public.payload_profile_v2_activation_receipts p JOIN public.device_keys k
    ON(k.account_id,k.device_id)=(p.account_id,p.device_id) AND k.signing_key_sec1=p.device_point AND k.revoked_at IS NULL
    WHERE p.account_id=wanted AND p.binding_id=g.original_binding_id AND p.device_id=g.device_id FOR SHARE OF k NOWAIT;
   IF NOT FOUND OR NEW.original_enrolled_point<>current_point OR NEW.minted_ms<>g.issued_ms OR NEW.minted_ms>now_ms
    OR NEW.fetch_transcript_sha256<>sha256(public.conversation_profile03_effect_fetch(g)) OR NEW.original_device_session_digest<>g.device_session_digest
    OR NOT EXISTS(SELECT FROM public.conversation_profile03_grants x WHERE x.account_id=wanted AND x.attempt_id=attempt AND x.xmin::text=pg_current_xact_id()::text) THEN
    RAISE EXCEPTION 'typed actor requires same-transaction genuine new grant' USING ERRCODE='23514'; END IF;
  ELSE
   SELECT * INTO a FROM public.conversation_profile03_effect_actors x WHERE x.account_id=wanted AND x.attempt_id=attempt;
   IF NOT FOUND THEN RAISE EXCEPTION 'typed actor unavailable' USING ERRCODE='23514'; END IF;
   IF TG_TABLE_NAME='conversation_profile03_submits' THEN
    PERFORM public.conversation_profile03_grant_issued(wanted,attempt);
    PERFORM public.conversation_profile03_effect_identity(wanted,attempt,NEW.command);
    IF NEW.command<>public.conversation_profile03_effect_submit_bytes(wanted,g.device_id,NEW.event_id,g.message_id,attempt,NEW.fetch_transcript_sha256,NEW.original_device_session_digest,NEW.segment_count,NEW.observed_ms)
     OR NEW.command_sha256<>sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',NEW.command))
     OR NEW.accepted_ms<g.issued_ms OR NEW.accepted_ms>now_ms OR NEW.observed_ms>now_ms+2000 OR now_ms>=g.expires_at_ms
     OR EXISTS(SELECT FROM public.conversation_profile03_outcomes x WHERE x.account_id=wanted AND x.attempt_id=attempt)
     OR EXISTS(SELECT FROM public.conversation_profile03_closure_records x WHERE x.account_id=wanted AND x.attempt_id=attempt) THEN
     RAISE EXCEPTION 'typed submit exact current source differs' USING ERRCODE='23514'; END IF;
   ELSIF TG_TABLE_NAME='conversation_profile03_outcomes' THEN
    original:=public.conversation_profile03_effect_submit_bytes(wanted,g.device_id,NEW.submit_event_id,g.message_id,attempt,NEW.fetch_transcript_sha256,NEW.original_device_session_digest,NEW.segment_count,NEW.submit_observed_ms);
    PERFORM public.conversation_profile03_effect_identity(wanted,attempt,original);
    bytes:=uuid_send(wanted)||uuid_send(g.device_id)||uuid_send(NEW.event_id)||uuid_send(g.message_id)||uuid_send(attempt)||uuid_send(NEW.submit_event_id)
     ||NEW.submit_command_sha256||NEW.fetch_transcript_sha256||NEW.original_device_session_digest||int8send(NEW.submit_observed_ms)
     ||decode(lpad(to_hex(NEW.segment_count::integer),2,'0')||lpad(to_hex(NEW.evidence::integer),2,'0'),'hex')||int8send(NEW.observed_ms)||decode(lpad(to_hex(coalesce(NEW.segment_index::integer,255)),2,'0'),'hex');
    expected_state:=public.conversation_profile03_effect_state(wanted,attempt,NEW.command);
    IF NEW.command<>bytes OR NEW.event_sha256<>sha256(public.payload_profile_election_frame('ZTSE/conversation/outcome-command03/v1',bytes))
     OR NEW.submit_command_sha256<>sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',original)) OR NEW.recorded_ms<g.issued_ms OR NEW.recorded_ms>now_ms
     OR NEW.observed_ms<NEW.submit_observed_ms OR NEW.observed_ms>now_ms+2000
     OR NEW.resulting_state IS DISTINCT FROM(SELECT expected_state FROM public.messages m WHERE m.account_id=wanted AND m.id=g.message_id) THEN
     RAISE EXCEPTION 'typed outcome exact evidence differs' USING ERRCODE='23514'; END IF;
   ELSIF TG_TABLE_NAME='conversation_profile03_closure_records' THEN
    original:=public.conversation_profile03_effect_submit_bytes(wanted,g.device_id,NEW.submit_event_id,g.message_id,attempt,NEW.fetch_transcript_sha256,NEW.original_device_session_digest,NEW.segment_count,NEW.submit_observed_ms);
    PERFORM public.conversation_profile03_effect_identity(wanted,attempt,original);
    bytes:=substring(original,1,80)||uuid_send(NEW.closure_id)||NEW.fetch_transcript_sha256||NEW.submit_command_sha256||NEW.original_device_session_digest
     ||decode(lpad(to_hex(NEW.segment_count::integer),2,'0'),'hex')||int8send(NEW.submit_observed_ms)||decode(lpad(to_hex(NEW.closed_from::integer),2,'0'),'hex')||int8send(NEW.closed_ms);
    IF NEW.record<>bytes OR NEW.record_sha256<>sha256(public.payload_profile_election_frame('ZTSE/conversation/no-submit-record03/v1',bytes))
     OR NEW.submit_command_sha256<>sha256(public.payload_profile_election_frame('ZTSE/conversation/submit-command03/v1',original)) OR NEW.created_ms<g.issued_ms OR NEW.created_ms>now_ms OR NEW.closed_ms>now_ms+2000 THEN
     RAISE EXCEPTION 'typed permanent closure assertion differs' USING ERRCODE='23514'; END IF;
    IF NEW.closed_from=1 AND NOT EXISTS(SELECT FROM public.conversation_profile03_submits s WHERE s.account_id=wanted AND s.attempt_id=attempt AND s.xmin::text<>pg_current_xact_id()::text) THEN
     RAISE EXCEPTION 'typed ACK-authorized phase lacks committed submit' USING ERRCODE='23514'; END IF;
   ELSIF TG_TABLE_NAME='conversation_profile03_closure_challenges' THEN
    SELECT * INTO r FROM public.conversation_profile03_closure_records x WHERE x.account_id=wanted AND x.closure_id=NEW.closure_id;
    c:=NEW;
    IF r.attempt_id IS DISTINCT FROM attempt OR NEW.core<>public.conversation_profile03_effect_closure_core(g,a,r,c) OR NEW.core_sha256<>sha256(NEW.core)
     OR NEW.issued_ms<r.created_ms OR NEW.issued_ms>now_ms OR NEW.expires_ms<=now_ms
     OR NEW.expires_ms>public.conversation_profile03_effect_actor(wanted,g.device_id,NEW.proof_site_id,NEW.proof_instance_id,NEW.proof_connection_epoch,NEW.proof_deployment_epoch)
     OR NEW.proof_device_session_digest<>public.conversation_profile03_effect_session(wanted,g.device_id,NEW.proof_site_id,NEW.proof_instance_id,NEW.proof_connection_epoch,NEW.proof_deployment_epoch,a.original_enrolled_key_id)
     OR NEW.closed_unaccepted_ms IS NOT NULL THEN RAISE EXCEPTION 'typed actual proof challenge differs' USING ERRCODE='23514'; END IF;
    IF NEW.previous_challenge_id IS NULL THEN
     IF EXISTS(SELECT FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=wanted AND x.closure_id=NEW.closure_id) THEN
      RAISE EXCEPTION 'typed initial challenge cannot reset history' USING ERRCODE='23514'; END IF;
    ELSE
     IF NOT EXISTS(SELECT FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=wanted AND x.challenge_id=NEW.previous_challenge_id
       AND x.closure_id=NEW.closure_id AND x.attempt_id=attempt AND x.device_id=g.device_id AND x.closed_unaccepted_ms=NEW.issued_ms AND x.expires_ms<=NEW.issued_ms
       AND x.superseded_by_challenge_id=NEW.challenge_id) THEN RAISE EXCEPTION 'typed recovery direct predecessor differs' USING ERRCODE='23514'; END IF;
     SELECT x.recovery_window_started_ms,x.recovery_window_ordinal INTO prior_window,prior_ordinal FROM public.conversation_profile03_closure_challenges x
      WHERE x.account_id=wanted AND x.device_id=g.device_id AND x.recovery_window_started_ms IS NOT NULL ORDER BY x.issued_ms DESC,x.recovery_window_ordinal DESC LIMIT 1;
     IF prior_window IS NULL OR NEW.issued_ms-prior_window>=86400000 THEN prior_window:=NEW.issued_ms;prior_ordinal:=0; END IF;
     IF NEW.issued_ms<prior_window OR prior_ordinal>=16 OR(NEW.recovery_window_started_ms,NEW.recovery_window_ordinal) IS DISTINCT FROM(prior_window,(prior_ordinal+1)::smallint) THEN
      RAISE EXCEPTION 'typed actual explicit recovery budget differs' USING ERRCODE='23514'; END IF;
    END IF;
   ELSIF TG_TABLE_NAME='conversation_profile03_closure_receipts' THEN
    SELECT * INTO c FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=wanted AND x.challenge_id=NEW.challenge_id;
    SELECT * INTO r FROM public.conversation_profile03_closure_records x WHERE x.account_id=wanted AND x.closure_id=NEW.closure_id;
    IF(c.device_id,c.message_id,c.attempt_id,c.closure_id,c.proof_request_id,c.core,c.core_sha256,r.submit_command_sha256,r.record_sha256)
     IS DISTINCT FROM(NEW.device_id,NEW.message_id,NEW.attempt_id,NEW.closure_id,NEW.proof_request_id,NEW.core,NEW.core_sha256,NEW.submit_command_sha256,NEW.record_sha256)
     OR c.closed_unaccepted_ms IS NOT NULL OR NEW.signature_sha256<>sha256(NEW.signature) OR NEW.accepted_ms<c.issued_ms OR NEW.accepted_ms>now_ms OR now_ms>=c.expires_ms
     OR c.proof_device_session_digest IS DISTINCT FROM public.conversation_profile03_effect_session(wanted,g.device_id,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch,a.original_enrolled_key_id)
     OR EXISTS(SELECT FROM public.conversation_profile03_outcomes x WHERE x.account_id=wanted AND x.attempt_id=attempt) THEN
     RAISE EXCEPTION 'typed exact closure receipt differs' USING ERRCODE='23514'; END IF;
   ELSE
    IF(NEW.original_enrolled_point,NEW.original_enrolled_key_id) IS DISTINCT FROM(a.original_enrolled_point,a.original_enrolled_key_id)
     OR NOT EXISTS(SELECT FROM public.conversation_profile03_outcomes o JOIN public.conversation_profile03_closure_receipts x USING(account_id,attempt_id)
      WHERE o.account_id=wanted AND o.event_id=NEW.first_event_id AND o.attempt_id=attempt AND x.closure_id=NEW.closure_id AND x.challenge_id=NEW.challenge_id
       AND o.recorded_ms=NEW.recorded_ms AND o.recorded_ms>=x.accepted_ms AND o.xmin::text=pg_current_xact_id()::text) THEN
     RAISE EXCEPTION 'typed quarantine lacks actual contrary accepted closure' USING ERRCODE='23514'; END IF;
   END IF;
  END IF;
 END IF;
 -- Actual tuple versioning is required even when the selection epoch stays one.
 UPDATE public.payload_profile_account_anchors x SET account_id=x.account_id WHERE x.account_id=wanted;
 RETURN NEW;
END;
$function$;

CREATE FUNCTION public.conversation_profile03_effect_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
DECLARE data jsonb; account uuid; attempt uuid; device uuid; target text; projected text; g public.conversation_profile03_grants%ROWTYPE;
 a public.conversation_profile03_effect_actors%ROWTYPE; c public.conversation_profile03_closure_challenges%ROWTYPE; next_row public.conversation_profile03_closure_challenges%ROWTYPE;
 now_ms bigint; actor_expiry bigint; actual_state text; actual_fence text; latest_ms bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>to_regclass(format('public.%I',TG_TABLE_NAME)) OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_NARGS<>0 OR TG_OP NOT IN('INSERT','UPDATE')
  OR TG_TABLE_NAME NOT IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines') THEN
  RAISE EXCEPTION 'typed completion context differs' USING ERRCODE='23514'; END IF;
 data:=to_jsonb(NEW);account:=(data->>'account_id')::uuid;attempt:=coalesce((data->>'attempt_id')::uuid,(data->>'first_attempt_id')::uuid);device:=(data->>'device_id')::uuid;
 IF NOT EXISTS(SELECT FROM public.accounts WHERE id=account) THEN RETURN NULL; END IF;
 PERFORM public.conversation_profile03_effect_mode(account);
 SELECT * INTO g FROM public.conversation_profile03_grants x WHERE x.account_id=account AND x.attempt_id=attempt;
 SELECT * INTO a FROM public.conversation_profile03_effect_actors x WHERE x.account_id=account AND x.attempt_id=attempt;
 IF a.account_id IS NULL OR g.account_id IS NULL THEN RAISE EXCEPTION 'typed completion immutable original unavailable' USING ERRCODE='23514'; END IF;
 -- Locks acquired at actual receipt time keep this current row stable. The
 -- deferred check still samples actual primary expiry after any later waits.
 SELECT floor(extract(epoch FROM s.lease_until)*1000)::bigint INTO actor_expiry FROM public.device_sessions s
  JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id) JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id)
  JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority p ON p.singleton AND p.epoch=s.deployment_epoch
  WHERE s.account_id=account AND s.device_id=device AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND k.signing_key_sec1=a.original_enrolled_point
   AND k.fingerprint=sha256(a.original_enrolled_point) AND t.enabled AND NOT t.draining FOR SHARE OF s,d,k,t,p NOWAIT;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF actor_expiry IS NULL OR now_ms>=actor_expiry OR now_ms<g.issued_ms THEN RAISE EXCEPTION 'typed deferred current actor expired or changed' USING ERRCODE='23514'; END IF;
 SELECT max(stamp) INTO latest_ms FROM(
  SELECT x.accepted_ms AS stamp FROM public.conversation_profile03_submits x WHERE x.account_id=account AND x.attempt_id=attempt
  UNION ALL SELECT x.recorded_ms FROM public.conversation_profile03_outcomes x WHERE x.account_id=account AND x.attempt_id=attempt
  UNION ALL SELECT x.created_ms FROM public.conversation_profile03_closure_records x WHERE x.account_id=account AND x.attempt_id=attempt
  UNION ALL SELECT x.issued_ms FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.attempt_id=attempt
  UNION ALL SELECT x.accepted_ms FROM public.conversation_profile03_closure_receipts x WHERE x.account_id=account AND x.attempt_id=attempt) stamps;
 IF latest_ms IS NOT NULL AND now_ms<latest_ms THEN RAISE EXCEPTION 'typed deferred primary clock regressed' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='conversation_profile03_effect_actors' THEN
  IF a.minted_ms<>g.issued_ms OR a.fetch_transcript_sha256<>sha256(public.conversation_profile03_effect_fetch(g)) THEN RAISE EXCEPTION 'typed grant actor completion differs' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME='conversation_profile03_submits' THEN PERFORM public.conversation_profile03_effect_current(account,attempt); END IF;
 IF TG_TABLE_NAME='conversation_profile03_closure_records' THEN
  IF NOT EXISTS(SELECT FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.closure_id=NEW.closure_id) THEN
   RAISE EXCEPTION 'typed orphan closure assertion cannot commit' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_TABLE_NAME='conversation_profile03_closure_challenges' THEN
  SELECT * INTO c FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.challenge_id=NEW.challenge_id;
  IF c.closed_unaccepted_ms IS NOT NULL THEN
   SELECT * INTO next_row FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.challenge_id=c.superseded_by_challenge_id;
   IF(next_row.closure_id,next_row.attempt_id,next_row.previous_challenge_id,next_row.issued_ms) IS DISTINCT FROM(c.closure_id,c.attempt_id,c.challenge_id,c.closed_unaccepted_ms)
    OR c.closed_unaccepted_ms<c.expires_ms THEN RAISE EXCEPTION 'typed direct closure completion differs' USING ERRCODE='23514'; END IF;
  ELSIF c.previous_challenge_id IS NOT NULL THEN
   IF NOT EXISTS(SELECT FROM public.conversation_profile03_closure_challenges p WHERE p.account_id=account AND p.challenge_id=c.previous_challenge_id
    AND p.closure_id=c.closure_id AND p.superseded_by_challenge_id=c.challenge_id AND p.closed_unaccepted_ms=c.issued_ms AND p.expires_ms<=c.issued_ms) THEN
    RAISE EXCEPTION 'typed predecessor completion differs' USING ERRCODE='23514'; END IF;
  END IF;
  IF EXISTS(SELECT FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.challenge_id=c.challenge_id AND x.xmin::text=pg_current_xact_id()::text)
   AND c.closed_unaccepted_ms IS NULL AND now_ms>=c.expires_ms THEN RAISE EXCEPTION 'typed challenge expired at commit' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_TABLE_NAME='conversation_profile03_closure_receipts' THEN
  SELECT * INTO c FROM public.conversation_profile03_closure_challenges x WHERE x.account_id=account AND x.challenge_id=NEW.challenge_id;
  IF c.closed_unaccepted_ms IS NOT NULL OR now_ms>=c.expires_ms OR NEW.accepted_ms<c.issued_ms
   OR c.proof_device_session_digest IS DISTINCT FROM public.conversation_profile03_effect_session(account,device,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch,a.original_enrolled_key_id)
   OR EXISTS(SELECT FROM public.conversation_profile03_outcomes x WHERE x.account_id=account AND x.attempt_id=attempt) THEN
   RAISE EXCEPTION 'typed signed closure expired or contradicted before commit' USING ERRCODE='23514'; END IF;
  PERFORM public.conversation_profile03_effect_actor(account,device,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch);
 END IF;
 target:=public.conversation_profile03_effect_target(account,attempt);
 IF target IS NOT NULL THEN
  SELECT state INTO actual_state FROM public.messages m WHERE m.account_id=account AND m.id=g.message_id;
  IF FOUND AND actual_state<>target THEN RAISE EXCEPTION 'typed message completion differs' USING ERRCODE='23514'; END IF;
  projected:=CASE WHEN target IN('delivered','delivery_unknown') THEN 'submitted' ELSE target END;
  IF EXISTS(SELECT FROM public.message_attempts x WHERE x.account_id=account AND x.id=attempt AND x.status<>projected) THEN RAISE EXCEPTION 'typed attempt completion differs' USING ERRCODE='23514'; END IF;
  SELECT outcome INTO actual_fence FROM public.dispatch_fences f WHERE f.account_id=account AND f.attempt_id=attempt;
  IF actual_fence IS NOT NULL AND actual_fence NOT IN('submitted','failed') AND actual_fence<>projected THEN RAISE EXCEPTION 'typed busy completion differs' USING ERRCODE='23514'; END IF;
  IF actual_fence IN('submitted','failed') AND EXISTS(SELECT FROM public.dispatch_jobs j WHERE j.account_id=account AND j.message_id=g.message_id AND(j.finished_at IS NULL OR j.lease_owner IS NOT NULL OR j.lease_until IS NOT NULL)) THEN
   RAISE EXCEPTION 'typed terminal job completion differs' USING ERRCODE='23514'; END IF;
 END IF;
 IF EXISTS(SELECT FROM public.conversation_profile03_closure_receipts x JOIN public.conversation_profile03_outcomes o USING(account_id,attempt_id)
   WHERE x.account_id=account AND x.attempt_id=attempt) AND NOT EXISTS(SELECT FROM public.conversation_profile03_effect_quarantines q
   WHERE q.account_id=account AND q.device_id=device AND q.original_enrolled_point=a.original_enrolled_point AND q.original_enrolled_key_id=a.original_enrolled_key_id) THEN
  RAISE EXCEPTION 'typed contrary closed outcome requires retained quarantine' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$function$;

DO $migration$
DECLARE relation_name text;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines'] LOOP
  EXECUTE format('CREATE TRIGGER conversation_profile03_effect_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_effect_rows_guard()',relation_name);
  EXECUTE format('CREATE TRIGGER conversation_profile03_effect_before_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.conversation_profile03_effect_rows_guard()',relation_name);
  EXECUTE format('CREATE CONSTRAINT TRIGGER conversation_profile03_effect_after_change AFTER INSERT OR UPDATE ON public.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.conversation_profile03_effect_complete()',relation_name);
 END LOOP;
END;
$migration$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_policy(account uuid,epoch bigint,relation_name text,operation text,old_row jsonb,new_row jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog AS $function$
DECLARE selected public.payload_profile_elections%ROWTYPE; reserved public.payload_profile_election_challenges%ROWTYPE;
 signed_before boolean; is_transition boolean; parent uuid; mode text;
BEGIN
 IF relation_name IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines') THEN
  IF epoch<>1 OR operation NOT IN('INSERT','UPDATE','DELETE') THEN RAISE EXCEPTION 'typed ledger profile operation differs' USING ERRCODE='23514'; END IF;
  -- The closed BEFORE/DEFERRED guards enforce each operation independently.
  -- There is no caller-selected writer mode or general effect exception.
  RETURN;
 END IF;
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
 SELECT count(*)=119 AND min(version)=1 AND max(version)=119 FROM public.schema_migrations
$function$;

CREATE OR REPLACE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=119 AND graph_sha256=public.payload_profile_writer_graph()
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
 AND coalesce((SELECT migration_version=119 AND graph_sha256=public.payload_profile_writer_graph()
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
 AND NOT EXISTS(SELECT FROM pg_roles WHERE oid=(CURRENT_USER::regrole)::oid AND(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
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
 AND coalesce((SELECT migration_version=119 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE OR REPLACE FUNCTION public.device_protection_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_ready()
 AND coalesce((SELECT migration_version=119 AND graph_sha256=public.payload_profile_writer_graph()
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

CREATE OR REPLACE FUNCTION public.conversation_profile03_interval_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_manifest_ready()
  AND has_table_privilege(current_user,'public.conversation_profile03_intervals','SELECT')
  AND NOT has_table_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(current_user,'public.conversation_profile03_intervals','INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%'
   AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_profile03_interval_reserve','conversation_profile03_interval_request','conversation_profile03_interval_approve','conversation_profile03_interval_install','conversation_profile03_interval_stop','conversation_profile03_interval_device_stop','conversation_profile03_interval_ready','conversation_profile03_grant_issue','conversation_profile03_grant_lock','conversation_profile03_grant_ready','conversation_profile03_effect_history_lock','conversation_profile03_effect_submit','conversation_profile03_effect_outcome','conversation_profile03_effect_closure_challenge','conversation_profile03_effect_closure_accept','conversation_profile03_effect_ready')))
  AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_%' AND a.grantee=0)
$function$;

CREATE FUNCTION public.conversation_profile03_effect_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
SELECT public.conversation_reviewed_send03_v2_ready()
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND EXISTS(SELECT FROM unnest(ARRAY['conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines']::text[]) AS f(name) WHERE starts_with(c.relname::text,f.name)) AND(c.relkind NOT IN('r','i')
 OR(c.relkind='r' AND c.relname::text NOT IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines'))
 OR(c.relkind='i' AND NOT EXISTS(SELECT FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid WHERE i.indexrelid=c.oid AND t.relnamespace='public'::regnamespace AND t.relname::text IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines')))))
 AND NOT EXISTS(SELECT FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname IN('conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines')
  AND(NOT has_table_privilege(current_user,c.oid,'SELECT') OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_effect_%'
  AND has_function_privilege(current_user,p.oid,'EXECUTE') IS DISTINCT FROM(p.proname IN('conversation_profile03_effect_history_lock','conversation_profile03_effect_submit','conversation_profile03_effect_outcome','conversation_profile03_effect_closure_challenge','conversation_profile03_effect_closure_accept','conversation_profile03_effect_ready')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_effect_%' AND a.grantee=0)
$function$;

DO $migration$
DECLARE relation_name text;columns_sql text;routine record;
BEGIN
 FOREACH relation_name IN ARRAY ARRAY['conversation_profile03_effect_actors','conversation_profile03_submits','conversation_profile03_outcomes','conversation_profile03_closure_records','conversation_profile03_closure_challenges','conversation_profile03_closure_receipts','conversation_profile03_effect_quarantines'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',relation_name);
  SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) INTO columns_sql FROM pg_attribute WHERE attrelid=format('public.%I',relation_name)::regclass AND attnum>0 AND NOT attisdropped;
  EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM PUBLIC',columns_sql,relation_name);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON TABLE public.%I FROM zrotext_runtime',relation_name);
   EXECUTE format('REVOKE ALL (%s) ON TABLE public.%I FROM zrotext_runtime',columns_sql,relation_name);
   EXECUTE format('GRANT SELECT ON TABLE public.%I TO zrotext_runtime',relation_name);
  END IF;
 END LOOP;
 FOR routine IN SELECT p.oid::regprocedure AS signature,p.proname FROM pg_proc p
  WHERE p.pronamespace='public'::regnamespace AND p.proname LIKE 'conversation_profile03_effect_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
  IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zrotext_runtime',routine.signature);
   IF routine.proname IN('conversation_profile03_effect_history_lock','conversation_profile03_effect_submit','conversation_profile03_effect_outcome','conversation_profile03_effect_closure_challenge','conversation_profile03_effect_closure_accept','conversation_profile03_effect_ready') THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zrotext_runtime',routine.signature); END IF;
  END IF;
 END LOOP;
END;
$migration$;

-- Terminal projections run with a catalog-only path. Keep the existing
-- invoker trigger and accounting, resolving only the accepted public tables.
CREATE OR REPLACE FUNCTION public.close_billing_invoice_liability() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p_id uuid;
BEGIN
    IF NEW.state IN ('delivered','failed','cancelled','expired') AND NEW.state IS DISTINCT FROM OLD.state THEN
        SELECT period_id INTO p_id FROM public.billing_invoice_usage WHERE account_id=NEW.account_id AND message_id=NEW.id;
        IF FOUND THEN
            PERFORM 1 FROM public.billing_invoice_periods WHERE id=p_id FOR UPDATE;
            UPDATE public.billing_invoice_usage SET terminal=true WHERE account_id=NEW.account_id AND message_id=NEW.id AND NOT terminal;
            IF FOUND THEN
                UPDATE public.billing_invoice_periods SET open_units=open_units-1 WHERE id=p_id
                    AND NOT EXISTS(SELECT 1 FROM public.billing_invoice_usage WHERE account_id=NEW.account_id AND message_id=NEW.id AND refunded);
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER payload_profile_writer_catalog_before_change ON public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog DROP CONSTRAINT payload_profile_writer_catalog_migration_version_check;
DELETE FROM public.payload_profile_writer_catalog;
ALTER TABLE public.payload_profile_writer_catalog ADD CONSTRAINT payload_profile_writer_catalog_migration_version_check CHECK(migration_version=119);
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.payload_profile_writer_catalog FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256) VALUES(true,119,public.payload_profile_writer_graph());
