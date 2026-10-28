import io, re

# ---------- verify_runtime_role.sql ----------
p = 'deploy/compose/verify_runtime_role.sql'
v = io.open(p, encoding='utf-8', newline='').read().replace('\r\n', '\n')

old = "IF writer_installation NOT IN (108,109,110,111,112,113,114,115,116,117,118,119) OR writer_installation IS NULL"
new = "IF writer_installation NOT IN (108,109,110,111,112,113,114,115,116,117,118,119,120) OR writer_installation IS NULL"
assert v.count(old) == 1
v = v.replace(old, new)

# cumulative gating blocks gain 120 (their expectations are unchanged)
for line_start in [
    'IF writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN',
    'IF writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN',
    'IF writer_installation IN(112,113,114,115,116,117,118,119) THEN',
    'IF writer_installation IN(113,114,115,116,117,118,119) THEN',
    'IF writer_installation IN(114,115,116,117,118,119) THEN',
    'IF writer_installation IN(115,116,117,118,119) THEN',
    'IF writer_installation IN(116,117,118,119) THEN',
]:
    assert v.count(line_start) == 1, line_start
    v = v.replace(line_start, line_start.replace(',119)', ',119,120)'))

# same-hash pins: extend their version sets
for old_pin, extra in [
    ("CASE WHEN writer_installation IN(116,117,118,119) THEN 'f0cc270d", 'f0cc-arm'),
    ("CASE WHEN writer_installation IN(109,110,111,112,113,114,115,116,117,118,119) THEN '7979002b", 'graph-arm'),
    ("CASE WHEN writer_installation IN(110,111,112,113,114,115,116,117,118,119) THEN '081e92d1", 'freshness-arm'),
]:
    assert v.count(old_pin) == 1, extra
    v = v.replace(old_pin, old_pin.replace(',118,119)', ',118,119,120)'))

# redefined functions: prepend a 120 branch to every pin ladder
V120 = '6fe12b267c3dbf934071e6aab6988e9ea958f2349cfb789a781b490eef669b71'
R120 = '5e775185aeb131de769c11e0320f1a0a065bb43586d15ffd78a6ddabca5d2b45'
N120 = 'db6233843cfbed991e2ca5523513fa8b6c0ecbc1d001ec5e2fe9b3caabdfdb83'
I120 = 'fe05742031ad01f8ec25539bfd2af310d76e31e60421eb8143e33eb91d5d21b2'
S120 = '5fcc11dfcad299a51b4042ff3538fe3b6e354a771d91c70d13d10873f42a1668'

old = "('payload_profile_writer_version()',CASE WHEN writer_installation=119 THEN '703e5118"
assert v.count(old) == 6, v.count(old)
v = v.replace(old, "('payload_profile_writer_version()',CASE WHEN writer_installation=120 THEN '" + V120 + "' ELSE CASE WHEN writer_installation=119 THEN '703e5118")

old = "('payload_profile_writer_ready()',CASE WHEN writer_installation=119 THEN '5a5351fe"
assert v.count(old) == 6, v.count(old)
v = v.replace(old, "('payload_profile_writer_ready()',CASE WHEN writer_installation=120 THEN '" + R120 + "' ELSE CASE WHEN writer_installation=119 THEN '5a5351fe")

old = "('public.hosted_runtime_native_schema_valid()',CASE WHEN writer_installation=119 THEN ARRAY['be255c4a"
assert v.count(old) == 1
v = v.replace(old, "('public.hosted_runtime_native_schema_valid()',CASE WHEN writer_installation=120 THEN ARRAY['" + N120 + "']::text[] ELSE CASE WHEN writer_installation=119 THEN ARRAY['be255c4a")

old = "('public.hosted_runtime_identity_ready()',CASE WHEN writer_installation=119 THEN ARRAY['fe057420"
assert v.count(old) == 1
v = v.replace(old, "('public.hosted_runtime_identity_ready()',CASE WHEN writer_installation=120 THEN ARRAY['" + I120 + "']::text[] ELSE CASE WHEN writer_installation=119 THEN ARRAY['fe057420")

old = "('public.hosted_runtime_scope()',CASE WHEN writer_installation=119 THEN ARRAY['b6d01cd9"
assert v.count(old) == 1
v = v.replace(old, "('public.hosted_runtime_scope()',CASE WHEN writer_installation=120 THEN ARRAY['" + S120 + "']::text[] ELSE CASE WHEN writer_installation=119 THEN ARRAY['b6d01cd9")

io.open(p, 'w', encoding='utf-8', newline='\n').write(v)
print('verify_runtime_role.sql updated')

# ---------- Rust matchers ----------
FILES = [
    'crates/delivery-store/src/hosted_runtime_identity.rs',
    'crates/server/src/payload_profile_writer.rs',
    'crates/server/src/payload_profile_elections.rs',
    'crates/server/src/payload_profile_selections.rs',
    'crates/server/src/payload_profile_manifests.rs',
    'crates/server/src/conversation_profile03_storage.rs',
    'crates/server/src/conversation_profile03_grant_storage.rs',
    'crates/server/src/conversation_reviewed_send03_storage.rs',
    'crates/server/src/device_protection_storage.rs',
]

ARM = '''    let source = if version == 120
        && matches!(
            name,
            "payload_profile_writer_version"
                | "payload_profile_writer_ready"
                | "hosted_runtime_native_schema_valid"
                | "hosted_runtime_identity_ready"
                | "hosted_runtime_scope"
        )
    {
        include_str!("{file}")
    } else if version == 119'''

for path in FILES:
    src = io.open(path, encoding='utf-8', newline='').read().replace('\r\n', '\n')
    changed = False
    if 'version == 120' not in src:
        anchor = 'if version == 119'
        if anchor in src:
            # figure out the include path depth from an existing include in this file
            m = re.search(r'include_str!\("(\.\./[^\)]+119_conversation_profile03_effects\.sql)"\)', src)
            rel = m.group(1).replace('119_conversation_profile03_effects.sql', '120_messages_line.sql')
            arm = ARM.format(file=rel)
            src = src.replace(anchor, arm, 1)
            changed = True
    if changed:
        # extend ranges and equality gates so installation 120 resolves
        src = re.sub(r'matches!\(version, (\d+)\.\.=119\)', r'matches!(version, \1..=120)', src)
        src = src.replace('} else if version == 119', '} else if matches!(version, 119..=120)')
        io.open(path, 'w', encoding='utf-8', newline='\n').write(src)
        print('patched', path)
    else:
        print('SKIPPED (no anchor or already patched)', path)
