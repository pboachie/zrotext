-- SPDX-License-Identifier: AGPL-3.0-only
-- Mandatory legacy writer participation. This migration accepts no election,
-- creates no current Profile03 authority and never advances an account epoch.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';

-- Closed canonical arrays: traverse two array levels per invocation, then
-- recurse on proper subtrees. Preserve original scalar bytes and object refusal.
CREATE FUNCTION public.payload_profile_writer_json(value json) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path TO pg_catalog AS $function$
DECLARE result text;
BEGIN
IF json_typeof(value)='array' THEN
SELECT '['||coalesce(string_agg(CASE json_typeof(element)
WHEN 'array' THEN (SELECT '['||coalesce(string_agg(CASE WHEN json_typeof(child1) IN ('array','object') THEN public.payload_profile_writer_json(child1) ELSE child1::text END,',' ORDER BY ordinal1),'')||']'
FROM json_array_elements(element) WITH ORDINALITY items1(child1,ordinal1))
WHEN 'object' THEN public.payload_profile_writer_json(element) ELSE element::text END,',' ORDER BY ordinal),'')||']'
INTO result FROM json_array_elements(value) WITH ORDINALITY items(element,ordinal);
RETURN result;
END IF;
IF json_typeof(value)='object' THEN RAISE EXCEPTION 'writer canonical array required' USING ERRCODE='23514';END IF;
RETURN value::text;
END;
$function$;
REVOKE ALL ON FUNCTION public.payload_profile_writer_json(json) FROM PUBLIC;

-- Migration-local verifier: the complete accepted107 definition graph also
-- includes defaults, CHECK/UNIQUE constraints, indexes, inheritance and rules.
-- Its qualified rendering is independent of the migrator's session path.
CREATE FUNCTION public.payload_profile_writer_prior_graph() RETURNS bytea
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT sha256(convert_to(public.payload_profile_writer_json((SELECT json_agg(json_build_array(c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,
 (SELECT json_agg(json_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
 (SELECT json_agg(json_build_array(k.conname,k.contype,pg_get_constraintdef(k.oid),k.convalidated,k.condeferrable,k.condeferred,CASE WHEN k.contype='c' THEN k.connoinherit ELSE NULL END) ORDER BY k.conname COLLATE "C") FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype<>'n'),
 (SELECT json_agg(json_build_array(t.tgname,pg_get_triggerdef(t.oid),t.tgenabled::text,t.tgfoid::regprocedure::text) ORDER BY t.tgname COLLATE "C") FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal),
 (SELECT json_agg(json_build_array(i.relname,pg_get_indexdef(x.indexrelid),x.indisvalid,x.indisready,x.indislive) ORDER BY i.relname COLLATE "C") FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid=c.oid),
 EXISTS(SELECT FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),EXISTS(SELECT FROM pg_rewrite WHERE ev_class=c.oid)
 ) ORDER BY c.relname COLLATE "C") FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p','v','m','f','S'))),'UTF8'))
$function$;
REVOKE ALL ON FUNCTION public.payload_profile_writer_prior_graph() FROM PUBLIC;

DO $migration$
DECLARE expected record; observed record; actual_count bigint; installed_functions bytea;
BEGIN
    -- The current shipping adapter and this exact graph support public only.
    -- A foreign namespace must never supply application rows through search_path.
    IF pg_catalog.to_regclass('accounts') IS DISTINCT FROM 'public.accounts'::regclass THEN
        RAISE EXCEPTION 'writer installation requires exact application namespace' USING ERRCODE='23514';
    END IF;
    SELECT count(*) INTO actual_count FROM pg_catalog.pg_class
      WHERE relnamespace='public'::regnamespace AND relkind IN ('r','p');
    IF actual_count<>179 THEN
        RAISE EXCEPTION 'unreviewed pre-writer relation graph' USING ERRCODE='23514';
    END IF;
    IF public.payload_profile_writer_prior_graph()<>decode('d2348d448965a4c8fa28116a89571fa932bf8f05dc5eb5927c8aceb308c78d2b','hex') THEN
        RAISE EXCEPTION 'unreviewed complete pre-writer definition graph' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND a.grantee=0)
      OR EXISTS(SELECT FROM pg_attribute c JOIN pg_class r ON r.oid=c.attrelid CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE r.relnamespace='public'::regnamespace AND a.grantee=0) THEN
        RAISE EXCEPTION 'public application write/read grants are unsupported' USING ERRCODE='23514';
    END IF;
    -- Check the accepted107 columns, FKs and complete existing trigger graph
    -- before adding any helper. Unknown/missing/disabled/mutated graph refuses.
    FOR expected IN SELECT * FROM (VALUES
            ('accounts','27667a0fcde3c1682163ce77ccdf9fef9a8766dde79e33ebc890b4bc3b35b34e','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','f0071922478b03fc1acb67ab5048bb492b8690e91cff86820b42630f50a36da1'),
            ('agent_authority_actions','b28d4f1c6a5a3bb71540d97aa1f4b90d832163035cd0bf0fd87529b7354228a6','a8d6f0b415241b89b2cab4f017a0fd7b0f991e1bec38bd5ab467c74230accf58','c9d68d3c2564897066e50dcc4cbb8559f762b5a4638a42ee2501ae25b3df52b9'),
            ('agent_authority_approvals','743eddfc92782c88081760164887daa1e6aadd0d22711edc708ce676a3806b3d','f2093a78114bacc5312a4662a7bffc71cd216e3b302f90bbc2d1ec17abff0f88','1200af2c554711a2fd0840b4f3e4ffdbfb70ca9781c98db9b85d9a83cba986e6'),
            ('agent_authority_grants','a8b5a164e8e242f2de95304eb6632cb91c5faa516c2fa4d6a87f1a71d3d50dda','d6fda4172591a30a84304ec7eea0b871e2a06f84b320798a3dab3d21a3004f5d','235ea3128be384c5a420feaaae16bcd936da538daee34a6ad2675d59b9f4b0c9'),
            ('api_keys','c671c5c15927e826dbaf12f94a38df7f362ef92a99a3579ed8562e50437b2231','f25ca76f6ee3091e0efdb435264218188d832b33bad5e96e8bbbb36c8ca45665','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('auth_abuse_counters','6c2e9e7d52b36b5a86f57bbdeebdd6116914cbf8f1c6c8d5ad83152603910f7d','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_customers','007b9633577859a08c94572015d77cd0b65d89aacd009fd574e9a8abb23d634e','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','3b8bed1245a56178a978105c9ef99bd8e14c7e9d3e85686d28793f72dc2f2bf7'),
            ('billing_device_cap_audit','b0a82a720fa85c12ea7293b6cd400277624548815bad18753df53744f6187e2f','131e1753b1246ed9fb6a16e803d6f386c97f70f2802193e9249b3bf321b997f6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_device_cap_config','657dcb187a594c6d80bca226dec46d7658dd00afc9cd7d739474077f0423f104','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_device_caps','2d9d7e9f51b6a1807787be926064492821e30e9c3f072924cf047768a48fae66','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_events','1dce629463c0cfe78c354e57fd0db10d12774dca10ef3475e42fe6e46c59c5a3','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_invoice_audit','c61630a7381d8d6065690aed8a0d8b8fe86357daa3d6e77ec08e834ad2001ed1','c64aa422c23616f17213c09b27c3d5253db2c635e3f5f7ef44d5c9e0a99920be','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_invoice_entitlements','0632bcdd4ac7ce90021536600af97d3cd9073776cbc8cad6985df7fc788ec397','63c00a9a753af8b230cd6f32c8ea4b8c77a1bc2bc1c1680aa84968f2e05ef986','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_invoice_periods','9ce10b09cb169b3ec6ea7c75a633aae7ccff6794c8810b0b694666fffa453300','7d5c70166b076b36efc74b1c3430488ec8fb42109f8de0ce277251c196708a88','2da8948e847ec4b2051df62efe8a6c78347f1a9edee2647dde601733324e606a'),
            ('billing_invoice_usage','fbaf997bc25806cbfa76e448b637173153c536c8c12bb3da98e16822d44c80f6','c64aa422c23616f17213c09b27c3d5253db2c635e3f5f7ef44d5c9e0a99920be','e072eb4ca819f3dad645a82fa3501f82d8d137fa7c3fd6f50b4174fb30f9684e'),
            ('billing_invoice_usage_observations','b83c574a2357f15e4e52e007cd3542350a7bab94b70d5598af504e7a72f35f21','c63b92deea32ee3074f20ebdc2886f41963470b9ace7248152729eb3382b416c','7fa4ca9ee2f0255263060936def84f98ea538c6412e45b2e23b24ff0a76dac07'),
            ('billing_payment_holds','b694a282f53a7f0fec13e59076164a0b9ea340b91e1f21d4557d281657fc35ac','8585e282ceca25092a453972fcc8b2210911df3a73890cef57a6dcd1e0e45376','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_quota_audit','9f6e96ee4a2b1346b9654a799a5d44d5cd3c4279d82f12e711249f6d691493aa','131e1753b1246ed9fb6a16e803d6f386c97f70f2802193e9249b3bf321b997f6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_reconciliations','e5e2ed515277e96c17daafc6a71a352e320397708cd7d05e5f0ef61c9830c712','015b46e24bcb4ed2f758e8c19f2a461ea6a5e01e9733ce8e12a08153ead59021','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_risk_events','777832c84f3b260d213d109fec24d54ce1b0249becbce4e3911c118d0fad97a9','b10532eb9ba5c784281049d0d1313960b3a327d31ec05aa29151a0a9630e8ec2','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_risk_review_actions','59163f6f16227528b581567a431ae91af2cf58d513348899931b0c9651fb49da','74b20401ee82b57b81d17a8df8a20aca9bcbbde7a10bdfedbbccbce21a79bac5','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_subscriptions','28ce6dd43758c64899bdfffc644c792799ec51cc968ab2c98fb38c4fae2211cd','bbe5fffb9cb13b3d302b217cb3f213d2eabede32f4c670623d419c56c8f99bbb','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_test_config','dc61f7c841cd3d67d0e26f312edf9c4418831fac248a34623cee0b27e87f23d8','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('billing_usage_adjustment_requests','5f40b4fa0d18a684394158a88fbc7d410f4c07faa7fb4548344e861c55cc4679','229aa4c1c99c4415dd6436c9ae5674b8749ff3676aa7a8f5f2a4df36e35ee0e3','299568950d6fa77d02bda705dda7a4d955bbb996f58dad53448a24d8b5f674b9'),
            ('billing_usage_bindings','48ed2f5557f5399fb79ba09c5cf118220c90abd8a2c35629ee9655702bbc9ef6','494174d4331d95d821333e0ce3bc21d1a3a78601aaea299fae9e626cd8c9a4f3','bd90b00dad28cb9ef10b5351f58287047bbb545d46a437cdb509853861216053'),
            ('billing_usage_finalized','ab62e142e4f39e83296548e83868b35825b9fc5db8cd31e6f8a304a484b89d12','d8c0f518fe1d4c373b2d354bdbcb0dd59c2546a2a4e6b3f141c3ea63fdb52c59','89d5c54b5369fb9a50cd953175f0eadfaf229bfb125ca1db48f08757cb2d67df'),
            ('billing_usage_meter_error_receipts','fa48366180171b18e9e2aff905e50fb0bb1d435a3022aac7ffccecd17dc29b75','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','7131fad2ec6b6867d07a974c76767c01e78451f73b07082825198bc9ec8d2d5e'),
            ('billing_usage_meter_errors','2a1df80e55a58fd31070be0ca17373924b74f87447fe8a7105d49270ac7d9889','10d3bdb98c1ac9bd4b9eb3ce0c2615c6aae12791174a43e34941558c68b515f2','9f923417b1423098c170003ee9077f00725350e69b0b78ba7db3c5ea3e976883'),
            ('billing_usage_outbox','06acf4634f8bc5afc46311672fc42cf1d2cae34452a65743aac0f7b729c4353a','229aa4c1c99c4415dd6436c9ae5674b8749ff3676aa7a8f5f2a4df36e35ee0e3','0de8c1a29d70f6134101f8340305b079b9044f0d257778c60527cbe67966f907'),
            ('billing_usage_reconciliations','d243896d7871a3c1283bd7d2503918af231512e25fca17c79fa224562e84802d','9e9882ca36b2e40bc429c30ab1f78018fbe671bbf3156772d61d7ebc2848966d','4300e263903811fcfb9f10311d9603bdc5148205bcfa27607b676a17388a9f03'),
            ('billing_usage_test_policies','1969819bf9ba1466c55a6970791ba8304dc481901162b61f48dd4fa8cfcf277d','8f1c009fffc34bf6fec54823e4a77b3f3ab1d55d1654c20668e03d047f3eca93','bb9265df0c2b9bfa082dfc829746617f1df743316a1130dc754544df763d51b6'),
            ('collaboration_draft_grants','0bc9b785d01b1aa4eb5aaa42ca94acb495517e7b3320baab71b12c4875ccde1a','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','d3733fe9dc65ccff1a3e3a2cbff81b40e745f5046e9eed598d4e33206e4bca70'),
            ('collaboration_drafts','4c006a7897872394bbb6ec1f6c1513b1a6f1cd61cf7df2bf34f97de13392a3bd','ec779d6038f3277dea7f5921aa4f93749a7762e2da282933d94e6dbefd141264','309980a12087b0c9658393ee176e7441d420e2db466d99cfdd80319bf366db0a'),
            ('connector_audit_events','b6286772d8fe6851050340b2789eda6c5ae2624ccfd9deffc3d03e068e4be2f1','a4d977d22f4f69ba70282f3b92abcea0192f6584068a2673a11a851e2f762460','36d992c849e0daf9af972840bad297443307a7c9dd45d14134965d797587fcac'),
            ('connector_grants','db9ce1b9d4ab51c7216d1770939873a0135f600ce9d1b0169a0d64d34977daeb','a4d977d22f4f69ba70282f3b92abcea0192f6584068a2673a11a851e2f762460','4d1be4d1387b4c1551c668f6bab4bd812c623926b44ef73f45c6204fd7e76359'),
            ('connector_keys','a604ad717e8d0bb5ab27925da9b5a951a92c12730cb75254aef4c1b0525691a0','a4d977d22f4f69ba70282f3b92abcea0192f6584068a2673a11a851e2f762460','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('connector_registrations','db4ac7367dcab2b212fe6db51018b5d220886a4d3b35edd91c65d848b58ebc67','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','ace12a637ae53d8b27de2a9e8cb7bbf04782c20b67baae35ade1cb1bfc5b4d6a'),
            ('contact_consent_records','9331bccdd7ea5fa431785eea09312288916ebeba64a4aeb4beb4bd5d02fb6bf5','96c83a942353adfecf83a9e2ed1295daeb09feb18aed29e1d296c689169abd27','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('contacts','74f95025dfc450cddcf8dfef4c720a5e2746d000bc79047a82d6c12b7997b2d2','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('conversation_confirmation_records','f0232f2cdcf7a6a474e732b4b4abd7440c2b6993eee9bed394d3ea90f38c650c','45895d910ca21dfe17cc75a2d654ef16ce4c25ffa1724261060f607cf5f0132d','e1cf75d8a6c18f8e00831dea86d11207132d3aafd8f38f5a7af391ee24dc9de3'),
            ('conversation_execution_records','82ec276e95421bac22fb8b2489b0a27c443ed86889d69712736d1c1d1c9e5f5f','2f4f7db40521f0a6d080565da5259b96b7c731a0c4abb352aa122a2b26022381','1c0ec001bdf63abed7d13765bcf10bc93cd6c48ba121f037c042fb39361cb25c'),
            ('conversation_inbound_provenance','b125b7373af1c3b6671b7fe59ddd5a0a24a48adaf49f1cc653f7539f8e74f574','7626dfb9adf2d6f15fca1d4f0e042367bc5f20e1a69b4750ba26e677c106c4fe','b46871ab346a0ed0d6e4e91d730fbfd6df9397297c3e2c00a5028e2cd82cc286'),
            ('conversation_intervals','df33ed25894f9e5dd6d7bc60dcde3848f2828fff8c6775d0b6b7f48534c5aca4','f9edecbd8d565428e25857c908fd2329447efea9f00bcb926297f7c1e0623b4b','9973a4626a58fad4063149d99b73dc22c9943ab43062bbc4b9969c25d365d290'),
            ('deployment_authority','02df41059097b9fea8cfe7e81a853abe40e3bd8d40158eda2af87039c514fea6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('device_keys','786b26a721c4b92a2b484b03f5448957448ac557afe25b15c7c9e6d824c1de36','0d7e93c93f0b7c6daf79aaf8ecf7bf0e27822466a3c883cfd5a31d5c2a6446a2','1b1e435e1132a9440739ead47523be941fd59d3863f1f0a730cf05da6079f20f'),
            ('device_line_bindings','4df362f9060343ad39e69f7626b138ee71ce277a61cb10f1f456a25111d57806','fa9e152970cd2129b75b7f003f0bafb849936b15bf49a4fa0697c950958286a8','49f971d804a3c23eab5fe58a2962c54eaf37fe68202e0140c6062faf0c31e8b6'),
            ('device_preconditions','aa8ddf2f9aede41c895c42c3d24ff3e39829468fc3a03e6870cdbc6bcbae795a','5d8187cf2defd5211bf2ac6a5668aca216464a54d6d1f071e885c09c6299e290','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('device_sessions','3dfb3c279c2aaaecc4f77df5176a3b43cb3c6ee766e20118f7849e3a3bd91d06','1e733dc11cab60ca63c67370937c8e6882aa3621dfd593124cad4918f5a4362c','c92fee80843dfabc2c5a9e2ef6d91166775730430b6d47a6b34ddc6ba8719865'),
            ('devices','b782050903cd70a5c25897e29fbd7c03695439e1484800b1d5ab18936b187efd','1e6b33700df15c4f3c950953fd77cdd3ec7fb9e9a999f6a210bca6fc24ebba50','e34a695655e1a2fa818b4a4f085c389c5a90583e143f2b54960279090233bc85'),
            ('dispatch_fences','b69527684da1bd7bf3c8d7b1c8f3b52f1c97c40541c55fff17f800bdf9172bc5','4c5ae3e553322b8944db9175775ec26f20f2672c8a996f9d4a92ed6a1e174db8','ed8fec267044391553c91560f226a171299372b9324f898b331c06a862c50f9d'),
            ('dispatch_jobs','63d7ce17a20dccc1e204372beb74252ca833f8db25afdcda7908fe69a887d94c','8d1e13586912d8bbe5da72878edf079bf0ecbf7df114eacc4ddc60175e030fca','4af82c8cd834776f7ad7a7f938af4c7ae0d985aa18e54adea8323400afe9c71b'),
            ('email_verifications','4c7d6e738e953f9c0bc3f5bd80d7a8e4b6fef2f6747b0d00d238c8a39e198839','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('encrypted_template_versions','e043f93cc3e828fee71943d4d656e0a5348fd8f37c07de7af00784acebf107ab','c2fcbcace16415a2c834d2abcbbf470e67042549730d0522ae591f00e3a7b1d3','6eb6a63466caccf19bff6c14224f420c925fcb1fbefbf48e77ec9b90279824ed'),
            ('encrypted_templates','9574485dc6b45eca217fbbcff7b90570de9e46adca467df5f70d5c1a42289f03','3812854996340fd47cbffc7c0845e1ddde64684d5e2661ccb74a70d8a7f08dfc','3590421f317bc809a25d644780b7e397bac18fdba8728db9c2ab1361d0e50045'),
            ('exposure_deployment_budgets','3d74118bdbf882e2efc4c4369c70b9d7e314a6138f6493ad28ce1c255716451c','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','2741e8a7bb989b17a32cb3c519e3c82f8acd5dcce0a498798efc796fab3e2efb'),
            ('exposure_reservation_scopes','eabf84b9ad30d3069620166e01a87790e47e66571420821e42579a6997f7c65f','c2c74526021335c07f50eb0f2bf1b9202dcce1a06b4e814c080de69bb11ee1f3','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('exposure_reservations','e34f0cd22ee178d19b3828ba5c197f3af130833efcb56908c2852a89ff962be9','5c5659836cee4207b9eba0ac2f1852d6fdd35e3962e7a7e7c4435a49e6da4ff4','47ea32dca6405c3ece65f481212c1d632925e54cd0a7f6d1722a2d7220ce32d9'),
            ('exposure_route_policies','62413a58f86128745a0a792c58a3e323851d5dbe4186e4d918a70b1cb64a60c2','8e5ff58f713b062c3d93abb0b54e1c0684ca3882b353af3362a40508866a2810','ec087c0b0a2bfaf465541afdf79a5643c9e5b7325e94a6413a6a23f3c2d804c6'),
            ('exposure_scope_budgets','903145c617d981bdb3fa5eb6c2da6f4a8d0768e829e11bc01ae3714db12e8f10','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','413b1926f27d251927563b574e3e304b99d06cdddbe910af24946d4b6ad696c7'),
            ('failover_controller_state','0722ef30973f9c7ded0da6172465552d5116f00de5136c5a16e9606be69db5b9','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('hosted_billing_audit','b27295ddec0702e95e80f70dae5a8a7a574639aa7de80af20ad63b84c4060c1f','1520ff1b62c69631037bc4f27d41df554529473953003e10c0cd96a7f1deb226','4327462ff3a5c4120bc3072c531e96cf9280e92d83c1a6b1b0b686033de6bdc8'),
            ('hosted_billing_customers','3096a5920caecc0a4bf3d7f5916e9e766a27776f361aa0ed26b6987944f45160','1520ff1b62c69631037bc4f27d41df554529473953003e10c0cd96a7f1deb226','814391580c210de0b9fd382c99a8faafdd3a351e40b9fe2faff4dd6636eea00f'),
            ('hosted_billing_events','ba0a92b23c990661d62c4223fd7ac9e467327ec92428a42c9b3ff9cb063b1bb1','593cea81c5f4dfdb7cf3132b0d07a55e751601f7a33d8be5626761592ec6e5ac','9f2b76dc673743f9ba58cf780715ac3bf6546f71b32a11655219336fd0da7554'),
            ('hosted_billing_history','5803f3c8df979c1ba11cd8cb3cac666c453a8ab98f828bd4681257ccbd282e9f','7fed057eae6436eaab22522908c49e686e6263a0fa793eb5e494d4ab88ba77e6','d0c96da20afa2c31f1263d9f25b1987b768a0af7f7e1a799f048e0ace133ca9a'),
            ('hosted_billing_namespaces','b81c0de219b3715b5fa26fe9b954702a57e1620cdba8df9acdd67f4c9d8c7a96','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','07f0a41509e102d9f8f5097c1250843f7cd5126b615bda9f291f20923ea5ab0d'),
            ('hosted_billing_projections','a8a16a62ef86d6af39f3e5f44950f5f3b8485c4659ad525cc5059daeda6a8cac','1520ff1b62c69631037bc4f27d41df554529473953003e10c0cd96a7f1deb226','0ee378189bc774803d2f307be18ab054072c81c8ba5863c60bac458a49eb5f0d'),
            ('hosted_billing_resolutions','ef7084bb8ab7ecfae536571577bf15e40055c531a76dca7f35c82afd288b49ec','f28f9f6ab7b30a01186cd1155f10e50836097ab467af747ab89b950c08bd1959','6f80cf244145e08fdd164936ec2cdbdd575c4faf2b1057c6ddea25ad5fdae041'),
            ('hosted_billing_usage','81feb5d52f7505cc2a64c6022b4ff30899c1d470fa0ac18a2f3793af2da9240b','fa63a816d76e1d456dae1ca0916912455332560b9f86f4c26e9218ebeeb80531','abe15432df1e4f4ce6613bd795c1c87e9c0ac6194a0e303325c28aacc20c820e'),
            ('hosted_runtime_secrets','1f36664c069622aab5c22b55264442c3db265868c55127beb57b5f9db8872114','a8393da07a442c49b7fd36e488b53df1ef6f38183972ef0eb4be11b5bfc6aa58','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('hosted_runtime_sessions','59a12d962b211a78d6c799db37ad65b4e41271ebde107ff94c4e66f0f9673367','a8393da07a442c49b7fd36e488b53df1ef6f38183972ef0eb4be11b5bfc6aa58','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('idempotency_keys','d33bacb550409b92f10b8e5d30a4f1bdc3a3797bc8fdf26bdec11302a54004ec','263fb7fc25c0a45537bc9ee5cda8087c6cb1fc11435480af0e05edfd22eeec7d','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('inbound_events','a2b41290b8f49f45bb9d842a0c85bc7269be75555b461c21f8d635e8bcb3b827','b61c7d1af961d743dcff32a1c8ab404ac9c995b9e9ce62e5747b6652c2025c6a','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('known_signing_point_reservations','c83dae65c89f48e6cdef6a82b13e1cb9b138799d5508bd76e3d47f478117040a','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','7f7c868dcf48340b84aaa006157db81ba48234a3a88cbc5379316321e397292b'),
            ('known_signing_role_claims','348924b8e8dfe81a179ca145fcb9269466e0fe7c2b593bae913065895b67c3e2','ef1ce7bb93961592ee2aac03203f62f1b666a7949681d08dd7e79b3574e1a563','3c1165b70f7594a6b3ef81ee992961c3a530038323dbb836fa5d6a67fa66b21e'),
            ('line_activation_challenges','99d455c70ff0a1a6662ccfaa5a43e2f73a17978df1820333f830a9840cf85086','2d2e81e2ab3d067c639e1b318d7de913db823bdb59d80c1ee76817594e97b717','03af3a967164591e2112222f796fb74e135e319022b38105c50259b8ead44410'),
            ('line_activation_v2_observations','f806c83ff3c8c5000aab1b54078f1d09c35b2e4dc4b986c78b9ecbf1bfe8e426','0823aa8414d13dcc888671d3aabc1f8e99a00dd56bacaf16fd150986eb320062','7393a246c9899f93ceed4f3a55921290252240bfb69137e0185375deb476adf9'),
            ('line_activation_v2_pending','33d997f2eee1a8f1646058213ffa2d6797ffe142453073c7e92578a63e7d378f','851237c36db6226ce43b3316863990f6c2b234e9823f0d4ded40f46441ed8a6f','446aee39b3b77c6ab464720e45f72732fb3b1a4500db3050033bdbd0530c1037'),
            ('line_opt_out_events','5590315cac40a798db2991ea1f9ccd2b340c17e20f6ab8f9ee02b5e05ee6173f','f600d6daec4ffff2bfb688533fee4e204f3fe417066081ea7920306a320aafce','e9006f9ba3fb13ad5f4b211643cc10b09816a0bcaa446f5b7802e5c655453fa6'),
            ('line_owner_approval_keys','e963f80b02ddf964a24f485219ee2c300b5ae7b9ae62e3c7a1859a106d4702bc','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','235a14949d485eb0d684acbedb630475e168555b85c3ba138c5502b68b5f999b'),
            ('line_readiness_observations','529bc8471b0e22fb8ccb4b16870facbc1bb88749395002795c077aa92a2a1e47','fa9e152970cd2129b75b7f003f0bafb849936b15bf49a4fa0697c950958286a8','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('memberships','b81f6bd943c50c7b5912a95ae4149c4f84b4c1e2bead01db3285986432d221f5','8ebc49390d707445cd71856de8456cc3c7d14b4c6e4fbcedb1379cf475801fa2','e2c9568ee7933ae500aae118d4bbfdb22595adb2fe4d3ae5a8c27772c2be40ec'),
            ('message_attempts','c267b73d978a984d5aaf136625cba877eaa2527f88efbf7fd1b3f344d1fb8cfd','8d1e13586912d8bbe5da72878edf079bf0ecbf7df114eacc4ddc60175e030fca','3b429e0be2df15b1ee9d0ca786d2ce89ca84e16307cc5b16e6fa6ca128ceb70f'),
            ('message_events','4b110adf505e5ae2ffd1297eede9455f09103f8207009d8e2bfebced08d2095a','cb6c000a08c0f7da8261156537795e72167e7ba3fd21c9a2acd59131fbc25021','3fff6dbde950180f300207fc75f0287bbcb6fd0efb78ad62c9963502376cfca7'),
            ('message_submission_receipts','974dadf0f358e4b360873d0642331ef054191455531d0faa885ac334852ef74e','ec5d02da50a03aabf6d4017b86bda01154944253b1a7eef5a81e2e86121869b6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('messages','910bfb1354f9e627f471746511fff4876228584b919dc7b65116624853bb14d0','cbf3350c844004e5240179ddfaff912deabdc9438637fa717e7e1a7d0631a706','43b4d6b25bb6be0766b1109c6b734ef83b82687ae17b5038b25b174dccf4a01a'),
            ('original_reply_access','bb2822ba612ca6db1e8713131a85256dc2a653ab1fba3d273e12d794bcdc445c','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('original_reply_consumptions','3bd9b41c8e6da6bc6bf6f76c06def20b0fde7d364529fe27f93ed613e13b99e0','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f6bb2e46d2f037065179c9875ba8af83fcfb559e06591ec834bf5dc0f98deb8'),
            ('original_reply_grants','531c8f1be74301df6314d798a94a949ab3681580739606c44cf5f14f7519f6b6','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','d58a19332e8b47110d3ff7249c6a1a77d734b53aab8053565b8003387ea4102d'),
            ('original_reply_manifest_history','3576fbe2eac193dd70ddcc5aa3149d67908f9d22b9cd29c1667eefa90fe05952','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','5ab39c7d296f3d2b830fca3e9129b03686482a1e02f8c121ef3e1fe948581f2b'),
            ('original_reply_requests','56fed730f1ab2a7d13c38020e085590ff59134e91a7b825c40954fcce257bea8','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','b10f624125538809e85dfa0b39f5cab6b9103fc1b0c0a499dbf094e31cdc8724'),
            ('original_reply_sources','a8ad158cb08630300b1320772c2f7041f65570a003986942ac680447c5bacc63','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','c705a3dd5969f9d106d2e4064ade8586838c3be00e052c918ac6ce47247d8d1f'),
            ('owner_android_proposals','92aca53577ddbc656bcf7c4f06a515226f7dc0a903abe2d4f5658ea48fdf752e','cac68e52ed871bc1aa837fcdf03e7a6c5084cd40788b5b278fa539e610038cd3','88eae38208f07b464479edefd05b06776000847f615c18995e80dd33b80ae1f1'),
            ('owner_conversation_consents','c5a0a31bc4d3b667230cc602ceec1824fc1b8e8967ccca7c45636525fd478321','ead460b0b62892d9892c6564b6297927c72e1436e7f5733a539bdf9b64c0d1fc','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('owner_mfa','600fa2c0d04646c83f1ee74ad03a6b1a91ea27f00283099ed3945557061f66eb','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('owner_mfa_login_challenges','c48ef59d92fca2a92d430c0b2dfc17619d37795896fd87175fec96d3ac03af99','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('owner_mfa_recovery_codes','5ca23424789843a8f90d447767624b98abc0328925256462f6a3478c3aaaafd8','af1285a5cacd16b64838b6369108203b5ceb1601b4bd110eda8a71aa07e787cc','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('owner_opt_out_audit','24cb63e8275a9e19c73b3a60323a1dfa5e5ae5eef12f63d38a5fc2fc1f400023','8d58ef2983bf312f8fc458ae59c1f5a8d4e5da439f85ae1c5e752e7a6a0f8d42','7032238753585d5b97188431b5ff1ef1751d0ba79433abffb340be0e7f472b0e'),
            ('owner_opt_out_review_decisions','69ec079fc96d00b446fac700915a0ad06efc2e850753d1c8e502b0fe4ed5249a','fcd289c8ded4c386ce291398c434a591517182a7b72ab07c30e73da6118a370f','eb108dff1b2d627b8537a6dabb657548e5e9e4db0ff86e2de35a427535eb13ed'),
            ('owner_recipient_holds','7e5155cacc576c79cce42e66ed1badb725713238e39e97d147e8f108647ed937','642da89d3ffd17fbb1880b61c8109c0ad0d37fa738c9ab8c5481012eeacd03fb','11a7de923f322855c74b24b281af862bc3f81a5d030e83c420da00801d4569f1'),
            ('pairing_requests','35a3a7948e569f5eeb3eb5e44789703f2cde54f225442ebfe4600392231016a5','b15272b1fcdcf920cec324845946aeee6b271827171a370805465682d3aa5e63','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('password_reset_mail_outbox','bb2e0af1ecc7baff722f253d51c7dce33f5b8ea165924633166672ef595ddcd0','13af7a2600240a1cac6e086285a749c5fee4c043817622f5ad1ae03c734336f7','5fb183cd7893edfdd6f55c8176ba3c1fa66c783a631036da79fd6736357920ec'),
            ('password_reset_notice_outbox','6d1dab25ed17387dd815555ecd2cd96998da28d5cc4607936617dc305b74e670','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('password_resets','4c7d6e738e953f9c0bc3f5bd80d7a8e4b6fef2f6747b0d00d238c8a39e198839','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('payload_profile_account_anchors','5d26e991ddf4ea110a1cfe1816324753ea380874be30f44d80d6a4ba8808e04f','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','6260a3d9946e0475087c23453e74ed8daa9fc8cfa8c88925b2f50802e2742476'),
            ('phone_lines','9735e867eb00c111b167a3827d55cfb334bd5894e7f75d801ec64e6edb333140','392f4a9eadcc4448e102c787e6374396d2575aa29a3c06796c537aac0925afa3','bf00c26fc544d70fa9000311c685a420fafeefb7a145b1f15eaba48a7b4b1498'),
            ('provider_send_attempts','02c56cd5ba81adb5f343cffd88929a9b6497dc21fc5b949dcad7d0ec671b6c70','b81e161b5b9e695d1dd987a9fbd6585c7e41eec4bb80419f059232d841854c52','88a8aee1149f9bd3449b801238d2a5ea5a60ace551702e8a2247c64382f76d3f'),
            ('recipient_suppressions','27b8b6ce556c1805ce5ac73861040c621606f4813084c2ed8aad135a2ada98d1','e3ec5e5af0f10dc702745e018e1750126a9099c4c5e6acfdab6f5fddf569f85b','020242dd186cc21b78cdce93ebcca85da271a97cfd8ef675cc6e6e8ddc53fb9c'),
            ('registration_browser_intents','e61f8f5716aea69a87a92a33d6eaf9b9a33fc68842b69454decb15eec5472f28','56b669ff8289b8f20dd9bfe8e54879c2f2da58eb8e7b48f99642bc6b73d299ca','3519d0b6a233d8c8e03d3c4d34dc9a7003fe9e023584a9acab4de4cd9ee1e0c8'),
            ('review_access_authentications','43356f7aa72db4ae55d46badddbf0d791f934243b3984569145bf20a3980b556','0f14e0f2d85776fe4d4a86bd2f432ebd79ca9bfe315e9bca08898da32126bddd','204faf1e77edb8074e6dddd5830f45e33f0ef1401f2beb99f879a1f036ce05a7'),
            ('review_access_locators','6f88664ee36b472aca3aaea70d6d599bda08a4966197f1e8b6accba21ab9694b','a4be47b7a1dd874fb9ebef42c1964c09bccb48a8f0011b6a93211d2603098770','f4557713e72d8794f3e079738fbca7da349cacd80b77a75413df1ccd02ef431a'),
            ('review_access_preparations','c1867191572ba8d22d7c9ed6f5e48c7467cd585ab3d902d09caf9ccb9630a3de','02ce9ac5b120133311b9261ff63ca93b6120c304b53cab5cb82b20595bebaf51','2d0357db68fbe6f83a0282ef3aea90e17aee9621729a714d1834ec6db3b4ebd3'),
            ('review_access_root_reauth','a8873354b396fdd664b93f71cc553ac67768bcd42285035c4ea30c56a856fbab','512123a25b5bfb0cde2eed504b708609085996639deb586f299a7b00dbbff57b','21c63bdd791f974b17c0ab05ed10707f35b081f6203fd70798d9e44e82fb331e'),
            ('review_access_sessions','4058436f3a45fb768db1c8393a3d86afa546385fd38df06af87ea900a7f9fde3','ee778f8b8bc728901a8c22f9f7875c4d9dfaf2aca1874aac21d735c6dc2fd2ce','e20fef3ae1177702411b95b3e5d41b9a6fb7e4c5ecdef135bbbda813b97613ef'),
            ('review_bootstrap_attempts','dcc979c8fa82a80f49902660e68b63f49b39ac0e276a55cee4cb5b33d5f71e17','4a993cdd58dbcc92bbd001cdf0334a8a3736c66bea8953e5ee37c7ffaf6bec38','b70ecce11470d412d7ed67a6dd92a931fa56c56b22a2481d7dbd7f0693bdcbff'),
            ('review_broker_sessions','b859a2a7c46f02b71aff0854d4ec11010b092e101c5d8e51f03d9328f1e01fe7','3c44176fe0f1f76e315f8aa6f5bea5855d342b6d0dee412c0a223b7a92a92165','00f1f5f5eba3f6f4796d92dbe0d2802ceb4ab4e1ada873a09cb63abeebeabe97'),
            ('review_brokers','09af8197e99be2036e3268fe58618a56c1e71d413deabc2d1506f5ae78da1c71','b0e5a7b966df6ff72c0ffb0433abd88c1a463f45a812dad845c2d706d6e80a3a','9001f42dafcb4af92b317d1a9a2eef0de872cbfcba441e0a3b2ed505d029511e'),
            ('review_realm_installation','c1a3d30ebaf70a39f34e861919593c609cd4a3bddeda3665abb4978c5f6af9fc','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','d80671be78e7eb0496dc69360776459020d86aca8725f83aae1f57a1d6c2751e'),
            ('review_workspaces','7de00ec61e612e26d652d9ff057709b7b095cc30627c21f4af9084aef498a4d3','44f3b47a7f2037a11d0cf5368ee8eac047c889ff26056a190eea40045115b531','c450d7d3ea13725abf236ac4a1c2721e551e5924e642bf7cea56819bec32d74a'),
            ('schema_migrations','606be0ca4fc76f69dab27483aa367752bf59851ada1c5a2dfe375aaae7e0d475','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sealed_event_deliveries','25d7f2a329f25ea2ef9c8f92e21f76c06075f7c736c986377d4322633733956b','6241f375397eac95cca0f65e4fbd6173a48faba56bd562f8581b95f203bfc8e2','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sealed_event_delivery_attempts','14225ef6ff2a2f03d14d7c188f2818e3b2501045151ce01035303f6f61aee7f6','cd2c3987ba6f7373d0f087e55845145e15fb329ae0771cf8983b070515330675','75e430871036080b59cd2cc170a961e1f7011deb881911f10af36cb179bc533a'),
            ('sealed_grant_authorizations','7a6d13707cb5417a618e241245f96748c158c557ab55540a44b46b74b338378d','5e639124a24189c4e2d74ca5643508a1e88eb9ec87f4104f5605895fbf7c0f74','4517947ecdcfdd9628c546715870dfefa9e4082316bdc4bea16ecc830e7316c5'),
            ('sealed_inbound_events','25f18bc54feaeadc4e9f9f115bdaba3a1a60d23c3783ce63ba04141f417d554a','11cfa77f1be88ec7fa02c70fa84a8289231685fa2658aa4463678748246f8943','ad7e769a32d9b44cff732c04f34c6abd908e68bc05291f9acb758325af3c820c'),
            ('sealed_line_activation_exchanges','47d270094fa7e435c9732fe788fff54ccfd1b143636e6573f2b9f68d15d61f1c','70e00417d614f2c796bc9044be4f2604647473594720b7df046349b90271f278','0b9eb78d65dcc03a65e58216c487cd04bb885258e0c25e01410ca1feda170952'),
            ('sealed_line_key_challenges','a4f423d729d5bd0fd42ab61f24e695e3b606dcaea0ef67271ba6a620f1712edc','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sealed_line_key_receipts','729946dedc83ff3494b00dccaa275014466c066389681155b1ac8ee337bfd9bb','b4d094ca71e044088541ef4ffea40af2976938bc69588c98e654c1fad6c71ed2','9f98171f98503ad0f6a44deb07a639990c435d9206437d38fe3147f513f43cc3'),
            ('sealed_manifest_authorities','97406673404f5ee507ca4f66a6a1c07e7e2a5a726ed7ef08ee0954c1ef38b695','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','cc8383fb00da70d6e38ebe0762bd8036a4cc250d5595550d7f15a2ab7af33815'),
            ('sealed_root_challenges','7bdc95f8c930ddd4a64404251d76982290d6625ebed3528b9c18f2fa4378b9a0','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sealed_root_custody','a8995c69fcb9f3d6ff9a0d6efe09139d0be8e3c18a6eb6ee00643274f22eb1c8','9e27755d100a05d6115fb5d3c205dda1e7e39be2111852c13b15fc718e439e92','4de1d9aa39fab5d8936a8e108ee558ef9bc8a6d6baa0d3f6730db314c0733048'),
            ('sealed_root_enrollments','d6b4f10fa427e366df43fa0f8f2de3e1b4c70ee111f2c4fbdcc66f65551b18d9','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','cda920040f06515fc152bb5f80b154dc60e06c952f454f12d541c16b5e7b335f'),
            ('sealed_root_receipts','e0a3b8170cac5650fab895abaecedcf95d3cef2a1c621c4c8415f15f9604b1d4','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','7e8c4890a2f9d3c633057cd3b8dff8700d5704cef3589c8f3235566b8fb9ab74'),
            ('seat_invitations','2c126ee9cf1fecbe4826cc90355dc2a5c9453a3ea9b42f24d53327bf516b3caf','66c94e030811b59ed9fcc3118fc0682183a1ef34d81247427d5dc1660a6265a6','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sessions','862fc9304657b0adf367c2aa71a2d428ce20b67bac2d290a87ba0e56cd246950','7a1ebf0cb4650160847ee057c193656b999f5d2d460ed34e0db97b292bf8a192','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sites','8a473c3063077a013ca5564708938c40b48963712e935d3e5927427862ceba56','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('sms_line_activation_exchanges','f6e98fdadba896ac4957fec138402522b774b681f3b0fb932702efa06d1b012b','ab2d2e6928037b8763303fbbbfb33920e6154ab4052a55c101bb671a2ee704a8','9a1c8f79cd8763fb5e99b51aa59ca2c239ee31f88d8e6ce89b53bff4dabba2d2'),
            ('sms_line_owner_approval_keys','e963f80b02ddf964a24f485219ee2c300b5ae7b9ae62e3c7a1859a106d4702bc','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','97864cb4f002c9c982244991ff8590df3ffa8c36884cb036b8e108b8ae4f1c18'),
            ('sms_owner_key_audit','a2b317e9e52a614f51c7470a3d48581e5b1cffa8fd770f7c67a84ae6c72a98fa','fc6ace470008373983281fe2ac50a5f1d04ddf17f61acbc60a43ed7eba6fcfba','c481dabe4002d35783252f37278efe186db3b1f6b0cc1296465b0337823319fb'),
            ('sms_owner_key_challenges','9cb6e54710c2be2cbe4508a5c4ebbcdb3c78ef22b39a89a09058d073d52bf2f9','045e5a161c28fc8a900512e6e28e44c4fff7838cbc631f3f294f57d4ddb1fd78','ee1e0a54eb846e64aaa643b55451a7a01393c78c2c4ddace179dfd69d04b80f2'),
            ('usage_ledger','1e8fab9bd81f6aaca5540b6c7b230bba7fa351de41826a968d8f2f471251f5e1','1349b56caf8025faea63d06d64dd18addaf982b23b7d342a2d9d084dc224ae96','349b387fa60765ac7f56ef21263008948bd8850875a013adb425f62c9d281816'),
            ('usage_periods','7308f5a37b9981301727f1f3af92196aa58288697739c7df7089c250b5ac9662','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('usage_plan_assignments','4dbe0951eebb440033ad79b2fc42ef6dec204c0f0863ccf3e0361671e28cd491','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('usage_plan_audit','be6e6a51d6b5eb87dee00674ba13f4e0e28f49508b8e94e1c7f43c78dbc99aa8','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('usage_quota_policies','a745783c01b46c1a434d4dafc7ad40aac860d85cae0264a96f1e7378b4878869','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('users','52b5b3cf4778a52be13138c473b84558a75867942add2b8fb226778643db8d7d','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','520640b53c38a728a1faa51400abedd969829a853ebbef47dfbc50c0c190443e'),
            ('verification_mail_outbox','0bf8502c7ceaecf1326182f4be66f95e9e2b278681ab4893c6a9fa239ea94104','4fbe67bcc5f1d58c49f31320e2fff09d8cf97e2d5652862d2c28aca53bdeadc9','2c2de89f58e67a628293a8d582b6db60e515cfa57de80c3589037b27f45128c3'),
            ('webhook_attempts','52685a9aee21088007de3fbf8a61e2f621b65abee9160ef31f301f92fd017d23','080e827ecce66406d9f81f8106a1b527c3afd37acc3c99d38642afdf8e066c3b','c57e0ec0d9d692747e5ec19dc303c604676b8d07d29a5cf281b7807d09b5c9e2'),
            ('webhook_deliveries','6f60a828814bcaede31183a51b7f88de3217d7022717efe87e4c0aa714ce05af','232f607cf6831e8e12f115f355de84dc453086344fba64e9d072bfc0efedc061','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('webhook_dispatch_accounts','c2a7de18f1e2c32cdd3dd5b83081551c173e6f7b79d287ecc5bbb45a01c04488','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('webhook_endpoints','e04fd9335de6f6edb88bb8c04e0d1217159a3e0e23eb9d862b30878bbc46c8ed','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','f06f4de91a6bace985771fc3c2dbc8ee26616493d03157564dddee580e5c5d27'),
            ('webhook_kek_commitments','c2785a580069caa0be78ee5464bd3db47cd85c4d80db7aa2dd3145712af489b7','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('webhook_replay_requests','a41f2736df5754fd70672fc2bdc0fe26602b19712c0d14e82f0e15e2a89d4bcf','d49eda9b3cfb149cf83a95c903a0083af09e53f8f3a024981ba57b3870e4ca01','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('workflow_action_mutations','533b807951028a97e5f9e4d670bd7b46c3c3c0500f4984f528591119af9a6ce7','90ef32588cd5eaf7062358320cad870a1d6db27410867463606fc0a80bdd95a8','5271f5cebd61bd2d6de88914d44499c70618cfd52cafbe1ee069a120e24ecd4a'),
            ('workflow_action_versions','83fbd45cbcf3273b476359edbf45226b1a8ce9a20cdc05ac138ad592415d8761','fe55862c2be7dbaf403e70d0df7ba5ca7fce47501c054346eca3e65c782962e1','73e5887a5ac4a6d041c666efdec746900ccd6576559cbab9796934d9cf6d2b35'),
            ('workflow_actions','675c59d217c4357f3e92948d2dec8629cc92fc9aa547535c02a29b273829660f','e07eb4d924be6aaae013d13fb5d271f387cbf82a4ef7e0e71ea4ee1b95411fb2','33d485cd07c70e9681b048d6bc68fd9788846b6cd4d964b7be9f22a218cf7e48'),
            ('workflow_connector_context_envelopes','92453957d9a34e9cd2a9747550845fb334c2de26817bf025a6134f14299010cb','7558f777b78a091dc1b638585bad5343930ce6cce5b1f1ba85a1fcd5f72f5279','018e6d65231b7e38486491b726f05e7a3f696a82973d14d2f7711e4dede01bbf'),
            ('workflow_context_audit','0ac1e1413a93036a0694c97f3659d77f924bdb1647965ca7e414c27382f7286b','77278ec519f705b7a64a4836cada0da33cd088f2a3fef8d1730d79558362d660','196ce85b2658e13b3b50502cf0513411c8d3e61e3feca64060f2a13053dcd5b9'),
            ('workflow_context_fences','23078c2308aba13035de45abfa9ab60b5ce62d1f3e9656ed03c11fc970aa193f','77278ec519f705b7a64a4836cada0da33cd088f2a3fef8d1730d79558362d660','b83d010d1b8407687aeeab919741a02e060989ce84aa333f9aa5c975c91bcd6c'),
            ('workflow_context_versions','3b05704c677d29250aea6e919b8d65075bca6a188bff15332c4d2d881adf9bd8','77278ec519f705b7a64a4836cada0da33cd088f2a3fef8d1730d79558362d660','8119f91c94c3bcf25cf4c252896154113d307f415bda63d4faf892b732659149'),
            ('workflow_contexts','70bda89a7f573f7a09c7221566bc843753ac2bd512a2d42cf8adfc56559a401d','6666e0585dc9517b13f5a48a218a0a7cc6ccefa6b6c6f6355418409441d7ce7a','c6b0f109618f2df4e553f1abe3ade3c919b47c167256a48112e30baa2dd3322e'),
            ('workflow_exceptions','dd5024c4c6bf2e755a821a487ec49c406a7ac293217e4ed70455280dbd70982a','399d4b2c45e24559141ee91a6248de94990189130548fef70216614d1a003b7b','8da8dc536ba6fa2d6d015a11efae65161ced6ca7402374a090a4f8723859372c'),
            ('workflow_integration_access','e08f231eb03a741a4b70e0866e0b6f39a89a52f3706823e1d6c2f49b48b48c6b','c085d595683622a5fdac49c11cdfa2762a5e1f166417381bcf827ee7a3c538d3','d79012aada786cbd754bf4b318675d682977930ecc00337bc9c4a48c77d2ec0c'),
            ('workflow_integration_grants','f0a378027c31a6c9fcbb6ff42a420c82a2430e8ae30cfb3f9d193645966cd4c0','5d31556f4f3633542ccce7cd7ddb25c2c22243d67b69c9e2e41b9fce01f9c4bb','bed7108d060a97d3d0645a6bc5ee803c6cfe1a3684ff2eb690dd64e992a23dd7'),
            ('workflow_message_links','c9dd23cd5e7661a950adbc963899f4adf28ff6b1e9609dfc61f17798bea10d93','2af266bddab479624e622510b0966ef408ea3a56ec99dfc7374e427f58f24645','2e01205999f654af1c64305e2d5299c3ba8f9f5fdf23262eb37b9f7a5f95b2c1'),
            ('workflow_opening_allocations','b2b3353c804a528c5340756bdd5cd0e1a0e60412b8d703a7814fa97d1c6ba916','c0ffc92ea045e9f7be777652449a51a398ef9f19919525f81f387851e13300ad','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('workflow_opening_offers','b13365390667574f829c691f7dad929ebedf31935be8fad93c1f7fbc7c6209a5','1ca30257c9597bdf40ce0169cd854e18fc4fdfcfac4b02ea2da5cdc9f4081866','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('workflow_opening_requests','dfd0a05fa7b4991148b8ede503f114a1f6947c4504b953105bdf48d54c930b7b','6352813e268b223ec2e1b60ffdf20472218001b4168e8196f3246a69736db464','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('workflow_openings','540d0a2e865349bcc9c9d2c49159625bbaf8bda084a43eaab738f10a6fa40435','d7456f40070f6e55716cc988fbd89b7687e48da7a605f0c801d8c8d45abafe7e','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'),
            ('workflow_reply_correlations','4f3af2ae2d3d171d2f0cc5f655dbafe40cd3bfb5a9c6b8515f0c18bf8e45ed21','ac934be346e38e1164abb5613d619c22ce06db5832deaee521c7f9662f1d2fa2','552bfacd45eee9f072804b00e9fa7e26f4737f56104389c0a63546378b54d1f6'),
            ('workflow_routine_admission_tombstones','100790fc96af6d657b9bf6aba7beac4a169fffca162b4d27106cdf1c027c2e8f','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','9b33079520e736d3267dca8ee6ca2a356e8de2982d3cbc78de53af47581118c4'),
            ('workflow_routine_calls','f54372a02c07b5db6c59cf71ebf669f80b14fcc64ef56a38f61ac6100254aea9','d42c8273608f5ad90644082960e88246d29110ef5c08603826b8496f89d4a719','3844287bb0d701104d320d72880d52b76ee779e80c5621e050e27b127705699b'),
            ('workflow_routine_original_sources','c3118a742680752eafe06d243ef6cdcb9322665101016e3b8f3515d0b62c07e9','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','c306bb9a43d6996490d20c6bbf05acc7648f1431d2fc07cea23983f95ae1ed69'),
            ('workflow_routine_period_debits','deaa1703ac12720750964602b9ececca0a6773d3c4841321d4df26e4b7783b13','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','f7a656efc928956ebaf85aab9fa2ea6dd4a160590e9a34feb38589c09e1ec2b8'),
            ('workflow_routine_policies','358445ac84a1a756258325813404a095b1a20d7d05cdb28f00b0cbaad385aea3','092a527c63494a6e0aa1ae091a6200c8cef7a78b0b72212d9efe5901b07adddd','a4c027e9343b8a303a4741652954dc5324f21577faf8b324c80aed85c92d8f1f'),
            ('workflow_routine_turn_debits','bd0212e73257cbf1433443dd812a90726508909e42ddfb31d0549e0e54ae0071','7c99914e649b54241920ce8abde6578d40b1ee44a367d478e9298bdb292d6164','e85df00a26ad05fa063378cd52eaf4331780e3a80873c852596fe3f98ca5e6bb'),
            ('workflow_routines','daa40ddd6e9ac9219e8fb1e29561043c28b287e596a6c5431e807808b740cbde','77278ec519f705b7a64a4836cada0da33cd088f2a3fef8d1730d79558362d660','2a92021df38e4d57354ada247100e2a6e532e45c4ef415436e4dbb9b811417cd'),
            ('workflow_schedule_audit','3b67930b01bde6d914a062d7a9d037b240dc452f178ca2f699cf146c931c3b6b','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','93ee96f4cefc33b23c39420a2eb1a7133baf3cfd64380caf3d9013d791e4ab20'),
            ('workflow_schedule_occurrences','39d24240964b7b2f26d5d1991d3189d3c2ee7700a51ba497b5b3196dd28e5f01','d14c05133df150a9ba162b711b3f7af1fc2a2256c9fcefb996cc91fb552293b7','ee73b9f4d7f25e29b0e498533e48de497e7276743371af0dd66bf64b0dc256ae'),
            ('workflow_schedule_policies','b9d50a07297810ea10a90568bd13c3c15b0004505d147798a95ab1f2cc5b946c','79e2de2c31c3f1f8a0f14dc825dd05f0e526df3195fb1d42c897e20d973753ab','2dce0d363fff695f1696f0927742d5c75c2b73303f299a699a6e6387345253b7'),
            ('workflow_schedule_series','24cbad9fac297b729c1f5aaf1b0b10d6aae094667bf0a697c677d87f59b6e56a','4492564fc3d1605310690059d3c9ceeb15fb4a134d3d13520d157e36b677d45a','407024a4c109137cb449a96c2dd7396e654471913e0db38035977abc24ca05b0')
    ) graph(relation_name,columns_digest,foreign_digest,triggers_digest) LOOP
        SELECT
          encode(sha256(convert_to(public.payload_profile_writer_json(coalesce((SELECT json_agg(json_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::json)),'UTF8')),'hex') AS columns_digest,
          encode(sha256(convert_to(public.payload_profile_writer_json(coalesce((SELECT json_agg(json_build_array(p.relname,pg_get_constraintdef(k.oid)) ORDER BY p.relname COLLATE "C",pg_get_constraintdef(k.oid) COLLATE "C") FROM pg_constraint k JOIN pg_class p ON p.oid=k.confrelid WHERE k.conrelid=c.oid AND k.contype='f'),'[]'::json)),'UTF8')),'hex') AS foreign_digest,
          encode(sha256(convert_to(public.payload_profile_writer_json(coalesce((SELECT json_agg(json_build_array(t.tgname,p.proname,pg_get_triggerdef(t.oid),t.tgenabled::text) ORDER BY t.tgname COLLATE "C",p.proname COLLATE "C",pg_get_triggerdef(t.oid) COLLATE "C") FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=c.oid AND NOT t.tgisinternal),'[]'::json)),'UTF8')),'hex') AS triggers_digest
          INTO observed FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relname=expected.relation_name AND c.relkind='r';
        IF NOT FOUND OR observed IS DISTINCT FROM ROW(expected.columns_digest,expected.foreign_digest,expected.triggers_digest) THEN
            RAISE EXCEPTION 'unreviewed writer relation %',expected.relation_name USING ERRCODE='23514';
        END IF;
    END LOOP;
    SELECT sha256(convert_to(public.payload_profile_writer_json(json_agg(json_build_array(p.proname,oidvectortypes(p.proargtypes),format_type(p.prorettype,NULL),p.proretset,p.provolatile,p.proisstrict,p.prosecdef,p.proparallel,l.lanname,p.proconfig,p.prosrc) ORDER BY p.proname COLLATE "C",oidvectortypes(p.proargtypes) COLLATE "C")),'UTF8'))
      INTO installed_functions FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
      WHERE p.pronamespace='public'::regnamespace AND p.proname NOT IN ('payload_profile_writer_json','payload_profile_writer_prior_graph');
    -- Two explicit exact predecessor snapshots: the accepted source uniformly
    -- checked out as LF or uniformly as CRLF. No installed body is normalized;
    -- an inserted CR in a literal, mixed endings or other body change refuses.
    IF installed_functions IS NULL OR installed_functions NOT IN (
        decode('8f81bbd4036e73f08f326aec4511d9affc50cced5c70a218aeac9d2befd097a9','hex'),decode('0162002d4e67b7d90da7a06026c7816a148cead8a6dfe1fe12a538b6b123e132','hex')
    ) THEN
        RAISE EXCEPTION 'unreviewed pre-writer function bodies' USING ERRCODE='23514';
    END IF;
    -- All ordinary writers are excluded while triggers and baseline are installed.
    -- This is migration-time DDL only; no runtime table-lock factory exists.
    FOR expected IN SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname COLLATE "C" LOOP
        EXECUTE format('LOCK TABLE public.%I IN SHARE ROW EXCLUSIVE MODE',expected.relname);
    END LOOP;
END;
$migration$;
DROP FUNCTION public.payload_profile_writer_prior_graph();

-- Preserve016's exact atomic policy and invoker authority while removing its
-- caller-controlled table lookup. The accepted function ACL remains unchanged.
CREATE OR REPLACE FUNCTION public.auth_abuse_consume(
    p_scope text,
    p_global_hash bytea,
    p_subject_hash bytea,
    p_global_max integer,
    p_global_seconds integer,
    p_subject_max integer,
    p_subject_seconds integer
) RETURNS boolean LANGUAGE plpgsql SET search_path TO pg_catalog AS $$
DECLARE
    v_started timestamptz;
    v_attempts integer;
    v_allowed boolean;
BEGIN
    -- This read avoids inserting a new subject row for every request after a
    -- route is exhausted. The guarded global UPSERT below remains authoritative
    -- when requests race near the limit.
    SELECT window_started_at, attempts INTO v_started, v_attempts
    FROM public.auth_abuse_counters
    WHERE scope = p_scope AND subject_hash = p_global_hash;
    IF FOUND AND v_started > clock_timestamp() - make_interval(secs => p_global_seconds)
             AND v_attempts >= p_global_max THEN
        RETURN false;
    END IF;

    BEGIN
        IF p_subject_hash IS NOT NULL THEN
            v_allowed := false;
            INSERT INTO public.auth_abuse_counters(scope, subject_hash, window_started_at, attempts, updated_at)
            VALUES (p_scope, p_subject_hash, clock_timestamp(), 1, clock_timestamp())
            ON CONFLICT(scope, subject_hash) DO UPDATE SET
                window_started_at = CASE WHEN public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
                    THEN clock_timestamp() ELSE public.auth_abuse_counters.window_started_at END,
                attempts = CASE WHEN public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
                    THEN 1 ELSE public.auth_abuse_counters.attempts + 1 END,
                updated_at = clock_timestamp()
            WHERE public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_subject_seconds)
               OR public.auth_abuse_counters.attempts < p_subject_max
            RETURNING true INTO v_allowed;
            IF NOT COALESCE(v_allowed, false) THEN
                RETURN false;
            END IF;
        END IF;

        v_allowed := false;
        INSERT INTO public.auth_abuse_counters(scope, subject_hash, window_started_at, attempts, updated_at)
        VALUES (p_scope, p_global_hash, clock_timestamp(), 1, clock_timestamp())
        ON CONFLICT(scope, subject_hash) DO UPDATE SET
            window_started_at = CASE WHEN public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
                THEN clock_timestamp() ELSE public.auth_abuse_counters.window_started_at END,
            attempts = CASE WHEN public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
                THEN 1 ELSE public.auth_abuse_counters.attempts + 1 END,
            updated_at = clock_timestamp()
        WHERE public.auth_abuse_counters.window_started_at <= clock_timestamp() - make_interval(secs => p_global_seconds)
           OR public.auth_abuse_counters.attempts < p_global_max
        RETURNING true INTO v_allowed;
        IF NOT COALESCE(v_allowed, false) THEN
            IF p_subject_hash IS NOT NULL THEN
                RAISE EXCEPTION 'global budget exhausted' USING ERRCODE = 'ZX001';
            END IF;
            RETURN false;
        END IF;
        RETURN true;
    EXCEPTION WHEN SQLSTATE 'ZX001' THEN
        -- PostgreSQL rolls back this block's subject and global writes.
        RETURN false;
    END;
END;
$$;


-- Retain103's complete user/membership stable-set protocol, while refusing
-- unsupported positive live epochs until an accepted-ledger policy is installed.
CREATE OR REPLACE FUNCTION public.user_membership_freshness_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog SET lock_timeout TO '3s' AS $function$
        DECLARE wanted_user uuid;
                wanted_account uuid;
                old_account uuid;
                new_account uuid;
                account_set uuid[];
                reduction boolean;
                current_state text;
                current_epoch bigint;
        BEGIN
            IF TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN ('public.users'::regclass,'public.memberships'::regclass)
              OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_NARGS<>0
              OR TG_OP NOT IN ('INSERT','UPDATE','DELETE') THEN
                RAISE EXCEPTION 'unexpected user membership freshness context' USING ERRCODE='23514';
            END IF;
            IF TG_RELID='public.users'::regclass THEN
                IF TG_OP='UPDATE' AND NEW.id IS DISTINCT FROM OLD.id THEN
                    RAISE EXCEPTION 'current user identity is immutable' USING ERRCODE='23514';
                END IF;
                IF TG_OP='DELETE' THEN wanted_user:=OLD.id; reduction:=true;
                ELSE
                    wanted_user:=NEW.id;
                    -- A real no-op tuple touch changes no permission or payload.
                    reduction:=TG_OP='UPDATE' AND to_jsonb(NEW)=to_jsonb(OLD);
                END IF;
                IF wanted_user IS NULL THEN
                    RAISE EXCEPTION 'nonnull user identity required' USING ERRCODE='23514';
                END IF;
                SELECT pg_catalog.array_agg(account_id ORDER BY account_id) INTO account_set
                  FROM public.memberships WHERE user_id=wanted_user;
                -- Empty membership is genuine bootstrap/unassociated state.
                -- Every concurrent membership writer below changes this exact
                -- user tuple, forcing an old RR/SSI mutation to refuse40001.
            ELSE
                -- Migration 048 already forbids seat reassignment. Preserve the
                -- identity locally too: every allowed operation touches exactly
                -- the same current user, never only one side of a move.
                IF TG_OP='UPDATE' AND (NEW.account_id,NEW.user_id)
                  IS DISTINCT FROM (OLD.account_id,OLD.user_id) THEN
                    RAISE EXCEPTION 'membership identity is immutable' USING ERRCODE='23514';
                END IF;
                IF TG_OP<>'INSERT' AND (OLD.account_id IS NULL OR OLD.user_id IS NULL) THEN
                    RAISE EXCEPTION 'nonnull old membership identity required' USING ERRCODE='23514';
                END IF;
                IF TG_OP<>'INSERT' THEN old_account:=OLD.account_id; END IF;
                IF TG_OP<>'DELETE' THEN
                    new_account:=NEW.account_id;
                    IF NEW.account_id IS NULL OR NEW.user_id IS NULL THEN
                        RAISE EXCEPTION 'nonnull membership identity required' USING ERRCODE='23514';
                    END IF;
                END IF;
                SELECT pg_catalog.array_agg(candidate ORDER BY candidate) INTO account_set FROM (
                    SELECT DISTINCT candidate FROM pg_catalog.unnest(ARRAY[old_account,new_account]) candidate
                      WHERE candidate IS NOT NULL
                ) accounts;
                reduction:=TG_OP='DELETE';
            END IF;
            FOREACH wanted_account IN ARRAY COALESCE(account_set,ARRAY[]::uuid[]) LOOP
                IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(public.payload_profile_account_fence_key(wanted_account)) THEN
                    RAISE EXCEPTION 'user membership account fence busy' USING ERRCODE='55P03';
                END IF;
                SELECT state,selection_epoch INTO current_state,current_epoch
                  FROM public.payload_profile_account_anchors WHERE account_id=wanted_account FOR SHARE NOWAIT;
                IF NOT FOUND OR current_state IS NULL OR current_epoch IS NULL OR current_epoch<0
                  OR current_state NOT IN ('live','deleted') OR (current_state='deleted' AND current_epoch=0)
                  OR (current_state<>'live' AND NOT reduction)
                  OR (current_state='live' AND current_epoch<>0) THEN
                    RAISE EXCEPTION 'user membership anchor unavailable' USING ERRCODE='23514';
                END IF;
                -- Reading/locking the actual tuple is essential: a changed
                -- epoch must cause an old RR/SSI snapshot to refuse, not default02.
            END LOOP;
            IF TG_RELID='public.memberships'::regclass THEN
                IF TG_OP='DELETE' THEN wanted_user:=OLD.user_id; ELSE wanted_user:=NEW.user_id; END IF;
                PERFORM id FROM public.users WHERE id=wanted_user FOR UPDATE NOWAIT;
                IF FOUND THEN
                    -- Locking alone leaves old RR snapshots usable. The real
                    -- version change serializes them even for membership DELETE.
                    -- Its nested users guard reads/locks only; no depth bypass.
                    UPDATE public.users SET id=id WHERE id=wanted_user;
                ELSIF TG_OP<>'DELETE' THEN
                    RAISE EXCEPTION 'membership user unavailable' USING ERRCODE='23514';
                END IF;
                -- A parent-user DELETE cascade may already have removed users.
                -- Its OLD account was still fenced above; absence grants nothing.
            END IF;
            IF TG_OP='DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END;
        $function$;

CREATE TABLE public.payload_profile_writer_global_fences (
    operation_class text PRIMARY KEY CHECK(operation_class IN ('auth_budget','billing_configuration','billing_audit','current_authority','effect_budget','key_integrity','hosted_configuration','hosted_backend_proof','review_current_authority','review_continuity','provider_inbox','legacy_coordination')),
    revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)
);
INSERT INTO public.payload_profile_writer_global_fences(operation_class) VALUES
 ('auth_budget'),('billing_configuration'),('billing_audit'),('current_authority'),
 ('effect_budget'),('key_integrity'),('hosted_configuration'),('hosted_backend_proof'),
 ('review_current_authority'),('review_continuity'),('provider_inbox'),('legacy_coordination');

CREATE FUNCTION public.payload_profile_writer_global_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
BEGIN
    IF TG_RELID<>'public.payload_profile_writer_global_fences'::regclass OR TG_LEVEL<>'ROW'
      OR TG_WHEN<>'BEFORE' OR TG_OP<>'UPDATE' OR TG_NARGS<>0
      OR NEW.operation_class IS DISTINCT FROM OLD.operation_class
      OR NEW.revision IS DISTINCT FROM OLD.revision+1 THEN
        RAISE EXCEPTION 'unsupported global writer fence mutation' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER payload_profile_writer_global_before_change BEFORE INSERT OR UPDATE OR DELETE
 ON public.payload_profile_writer_global_fences FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_global_guard();

-- Explicit operation classes do not establish account or cryptographic authority.
-- Account-free records also participate, using their own durable singleton row.
CREATE FUNCTION public.payload_profile_writer_guard() RETURNS trigger
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
          OR (current_state='live' AND current_epoch<>0) THEN
            RAISE EXCEPTION 'writer state unsupported by installed policy' USING ERRCODE='23514';
        END IF;
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

DO $migration$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['accounts','agent_authority_actions','agent_authority_approvals','agent_authority_grants','api_keys','auth_abuse_counters','billing_customers','billing_device_cap_audit','billing_device_cap_config','billing_device_caps','billing_events','billing_invoice_audit','billing_invoice_entitlements','billing_invoice_periods','billing_invoice_usage','billing_invoice_usage_observations','billing_payment_holds','billing_quota_audit','billing_reconciliations','billing_risk_events','billing_risk_review_actions','billing_subscriptions','billing_test_config','billing_usage_adjustment_requests','billing_usage_bindings','billing_usage_finalized','billing_usage_meter_error_receipts','billing_usage_meter_errors','billing_usage_outbox','billing_usage_reconciliations','billing_usage_test_policies','collaboration_draft_grants','collaboration_drafts','connector_audit_events','connector_grants','connector_keys','connector_registrations','contact_consent_records','contacts','conversation_confirmation_records','conversation_execution_records','conversation_inbound_provenance','conversation_intervals','deployment_authority','device_keys','device_line_bindings','device_preconditions','device_sessions','devices','dispatch_fences','dispatch_jobs','email_verifications','encrypted_template_versions','encrypted_templates','exposure_deployment_budgets','exposure_reservation_scopes','exposure_reservations','exposure_route_policies','exposure_scope_budgets','failover_controller_state','hosted_billing_audit','hosted_billing_customers','hosted_billing_events','hosted_billing_history','hosted_billing_namespaces','hosted_billing_projections','hosted_billing_resolutions','hosted_billing_usage','hosted_runtime_secrets','hosted_runtime_sessions','idempotency_keys','inbound_events','known_signing_point_reservations','known_signing_role_claims','line_activation_challenges','line_activation_v2_observations','line_activation_v2_pending','line_opt_out_events','line_owner_approval_keys','line_readiness_observations','message_attempts','message_events','message_submission_receipts','messages','original_reply_access','original_reply_consumptions','original_reply_grants','original_reply_manifest_history','original_reply_requests','original_reply_sources','owner_android_proposals','owner_conversation_consents','owner_mfa','owner_mfa_login_challenges','owner_mfa_recovery_codes','owner_opt_out_audit','owner_opt_out_review_decisions','owner_recipient_holds','pairing_requests','password_reset_mail_outbox','password_reset_notice_outbox','password_resets','phone_lines','provider_send_attempts','recipient_suppressions','registration_browser_intents','review_access_authentications','review_access_locators','review_access_preparations','review_access_root_reauth','review_access_sessions','review_bootstrap_attempts','review_broker_sessions','review_brokers','review_realm_installation','review_workspaces','sealed_event_deliveries','sealed_event_delivery_attempts','sealed_grant_authorizations','sealed_inbound_events','sealed_line_activation_exchanges','sealed_line_key_challenges','sealed_line_key_receipts','sealed_manifest_authorities','sealed_root_challenges','sealed_root_custody','sealed_root_enrollments','sealed_root_receipts','seat_invitations','sessions','sites','sms_line_activation_exchanges','sms_line_owner_approval_keys','sms_owner_key_audit','sms_owner_key_challenges','usage_ledger','usage_periods','usage_plan_assignments','usage_plan_audit','usage_quota_policies','verification_mail_outbox','webhook_attempts','webhook_deliveries','webhook_dispatch_accounts','webhook_endpoints','webhook_kek_commitments','webhook_replay_requests','workflow_action_mutations','workflow_action_versions','workflow_actions','workflow_connector_context_envelopes','workflow_context_audit','workflow_context_fences','workflow_context_versions','workflow_contexts','workflow_exceptions','workflow_integration_access','workflow_integration_grants','workflow_message_links','workflow_opening_allocations','workflow_opening_offers','workflow_opening_requests','workflow_openings','workflow_reply_correlations','workflow_routine_admission_tombstones','workflow_routine_calls','workflow_routine_original_sources','workflow_routine_period_debits','workflow_routine_policies','workflow_routine_turn_debits','workflow_routines','workflow_schedule_audit','workflow_schedule_occurrences','workflow_schedule_policies','workflow_schedule_series'] LOOP
        -- Alphabetical last is deliberate:101's parent mirror must populate a
        -- legacy INSERT's omitted immutable account_id before this exact check.
        EXECUTE format('CREATE TRIGGER zz_payload_profile_writer_before_change BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_guard()',relation_name);
    END LOOP;
END;
$migration$;

-- Current graph and function metadata are retained only as a schema baseline.
-- A matching digest cannot authenticate a root, signer, election or grant.
CREATE TABLE public.payload_profile_writer_catalog (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    migration_version bigint NOT NULL CHECK(migration_version=108),
    graph_sha256 bytea NOT NULL CHECK(octet_length(graph_sha256)=32)
);
CREATE FUNCTION public.payload_profile_writer_catalog_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path TO pg_catalog AS $function$
BEGIN
    IF TG_RELID<>'public.payload_profile_writer_catalog'::regclass OR TG_NARGS<>0
      OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_OP<>'INSERT'
      OR EXISTS(SELECT FROM public.payload_profile_writer_catalog) THEN
        RAISE EXCEPTION 'writer catalog is insert-once migration state' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER payload_profile_writer_catalog_before_change BEFORE INSERT OR UPDATE OR DELETE
 ON public.payload_profile_writer_catalog FOR EACH ROW EXECUTE FUNCTION public.payload_profile_writer_catalog_guard();

CREATE FUNCTION public.payload_profile_writer_graph() RETURNS bytea
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT sha256(convert_to(public.payload_profile_writer_json(json_build_array(
  (SELECT json_agg(json_build_array(c.relname,c.relkind,c.relpersistence,pg_get_userbyid(c.relowner),c.relrowsecurity,c.relforcerowsecurity,
    (SELECT json_agg(json_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
    (SELECT json_agg(json_build_array(k.conname,k.contype,CASE WHEN c.relname='sealed_inbound_events' AND k.conname='sealed_inbound_events_envelope_check' AND pg_get_constraintdef(k.oid) IN ('CHECK (((envelope IS NULL) OR (((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082)) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))','CHECK (((envelope IS NULL) OR ((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))') THEN 'CHECK (((envelope IS NULL) OR ((octet_length(envelope) >= 426) AND (octet_length(envelope) <= 34082) AND (((envelope_profile = 1) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450102''::text, ''hex''::text))) OR ((envelope_profile = 2) AND (SUBSTRING(envelope FROM 1 FOR 6) = decode(''5a5453450202''::text, ''hex''::text)))))))' WHEN c.relname='webhook_endpoints' AND k.conname='webhook_endpoints_callback_url_check' AND pg_get_constraintdef(k.oid) IN ('CHECK ((((length(callback_url) >= 9) AND (length(callback_url) <= 2048)) AND (callback_url ~~ ''https://%''::text)))','CHECK (((length(callback_url) >= 9) AND (length(callback_url) <= 2048) AND (callback_url ~~ ''https://%''::text)))') THEN 'CHECK (((length(callback_url) >= 9) AND (length(callback_url) <= 2048) AND (callback_url ~~ ''https://%''::text)))' WHEN c.relname='workflow_action_versions' AND k.conname='workflow_action_versions_check' AND pg_get_constraintdef(k.oid) IN ('CHECK ((((revision >= 1) AND (revision <= 128)) AND (expires_at_ms > not_before_ms)))','CHECK (((revision >= 1) AND (revision <= 128) AND (expires_at_ms > not_before_ms)))') THEN 'CHECK (((revision >= 1) AND (revision <= 128) AND (expires_at_ms > not_before_ms)))' ELSE pg_get_constraintdef(k.oid) END,k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.conname COLLATE "C") FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype<>'n'),
    (SELECT json_agg(json_build_array(t.tgname,pg_get_triggerdef(t.oid),t.tgenabled::text,t.tgfoid::regprocedure::text) ORDER BY t.tgname COLLATE "C") FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal),
    (SELECT json_agg(json_build_array(i.relname,pg_get_indexdef(x.indexrelid),x.indisvalid,x.indisready,x.indislive) ORDER BY i.relname COLLATE "C") FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid=c.oid),
    (SELECT json_agg(json_build_array(r.rulename,r.ev_enabled::text,pg_get_ruledef(r.oid)) ORDER BY r.rulename COLLATE "C") FROM pg_rewrite r WHERE r.ev_class=c.oid),
    (SELECT json_agg(json_build_array(n.nspname,p.relname,h.inhseqno,h.inhdetachpending) ORDER BY n.nspname COLLATE "C",p.relname COLLATE "C",h.inhseqno) FROM pg_inherits h JOIN pg_class p ON p.oid=h.inhparent JOIN pg_namespace n ON n.oid=p.relnamespace WHERE h.inhrelid=c.oid),
    (SELECT json_agg(json_build_array(n.nspname,p.relname,h.inhseqno,h.inhdetachpending) ORDER BY n.nspname COLLATE "C",p.relname COLLATE "C",h.inhseqno) FROM pg_inherits h JOIN pg_class p ON p.oid=h.inhrelid JOIN pg_namespace n ON n.oid=p.relnamespace WHERE h.inhparent=c.oid),
    (SELECT json_agg(json_build_array(p.polname,p.polcmd::text,p.polpermissive,
       (SELECT json_agg(CASE WHEN role_id=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_id)::text END ORDER BY CASE WHEN role_id=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_id)::text END COLLATE "C") FROM unnest(p.polroles) AS roles(role_id)),
       pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY p.polname COLLATE "C") FROM pg_policy p WHERE p.polrelid=c.oid)
   ) ORDER BY c.relname COLLATE "C") FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p','v','m','f','S')),
  (SELECT json_agg(json_build_array(p.proname,oidvectortypes(p.proargtypes),format_type(p.prorettype,NULL),pg_get_userbyid(p.proowner),p.proretset,p.provolatile,p.proisstrict,p.prosecdef,p.proparallel,l.lanname,
    CASE WHEN p.proname IN ('device_session_line_activation_version_guard','line_activation_v2_pending_guard','line_activation_v2_observation_guard')
      AND (p.proconfig=ARRAY['search_path=public'] OR p.proconfig=ARRAY['search_path=pg_catalog, public'])
      THEN ARRAY['search_path=pg_catalog, public'] ELSE p.proconfig END,p.prosrc)
    ORDER BY p.proname COLLATE "C",oidvectortypes(p.proargtypes) COLLATE "C") FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.pronamespace='public'::regnamespace)
 )),'UTF8'))
$function$;

-- Runtime deliberately has no direct migration-ledger SELECT privilege.
-- This read-only, fixed-namespace helper reveals only the supported version.
CREATE FUNCTION public.payload_profile_writer_version() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog AS $function$
 SELECT count(*)=108 AND min(version)=1 AND max(version)=108 FROM public.schema_migrations
$function$;

CREATE FUNCTION public.payload_profile_writer_ready() RETURNS boolean
LANGUAGE sql STABLE SET search_path TO pg_catalog AS $function$
 SELECT public.payload_profile_writer_version() AND coalesce((SELECT migration_version=108 AND graph_sha256=public.payload_profile_writer_graph()
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

REVOKE ALL ON TABLE public.payload_profile_writer_catalog,public.payload_profile_writer_global_fences FROM PUBLIC;
REVOKE ALL ON FUNCTION public.payload_profile_writer_guard(),public.payload_profile_writer_global_guard(),public.payload_profile_writer_catalog_guard(),public.payload_profile_writer_graph(),public.payload_profile_writer_version(),public.payload_profile_writer_ready() FROM PUBLIC;
DO $migration$
BEGIN
    IF EXISTS(SELECT FROM pg_roles WHERE rolname='zrotext_runtime') THEN
        REVOKE ALL ON TABLE public.payload_profile_writer_catalog,public.payload_profile_writer_global_fences FROM zrotext_runtime;
        GRANT SELECT ON TABLE public.payload_profile_writer_catalog,public.payload_profile_writer_global_fences TO zrotext_runtime;
        REVOKE ALL ON FUNCTION public.payload_profile_writer_json(json),public.payload_profile_writer_guard(),public.payload_profile_writer_global_guard(),public.payload_profile_writer_catalog_guard() FROM zrotext_runtime;
        GRANT EXECUTE ON FUNCTION public.payload_profile_writer_graph(),public.payload_profile_writer_version(),public.payload_profile_writer_ready() TO zrotext_runtime;
        -- graph()/ready() invoke the canonical serializer with invoker rights.
        GRANT EXECUTE ON FUNCTION public.payload_profile_writer_json(json) TO zrotext_runtime;
    END IF;
END;
$migration$;
INSERT INTO public.payload_profile_writer_catalog(singleton,migration_version,graph_sha256)
 VALUES(true,108,public.payload_profile_writer_graph());
