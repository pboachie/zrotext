# Local template content and preview

The Rust and Go candidate companions implement the maintained template content
contract without network, storage, encryption, approval or send effects.
`TemplateContent` owns its validated template and substitution snapshot.

Go exposes `NewTemplateContent`, `ParseTemplateContent`, `Canonical`, `Digest`,
`Values` and `Preview`; Rust exposes `TemplateContent::new`, `parse`, `canonical`,
`digest`, `values` and `preview`. Returned bytes and maps are independent copies.
The parser accepts only exact canonical UTF-8 content, at most 65536 bytes, with
the closed `v:1`, `template`, `values` object and sorted substitution keys.
Noncanonical whitespace, duplicate fields, invalid Unicode and extra fields
are refused. Construction captures native strings and a map; it emits the same
canonical bytes and SHA-256 as the maintained TypeScript SDK.

Limits count UTF-16 units, including two units per supplementary character:
4096 template units, 32 substitutions, 512 units per value, 4096 aggregate
substitution units, and 8192 rendered units. Identifiers match
`[A-Za-z_][A-Za-z0-9_]{0,31}` and cannot be `__proto__`, `prototype` or
`constructor`. Every brace must belong to a complete `{{identifier}}` token.
Preview requires all referenced values and substitutes once; braces in a value
are literal and are never evaluated recursively. Unused valid values remain
part of the canonical content digest.

`EstimateSegments` / `estimate_segments` applies the maintained bounded GSM
default/extension and UCS-2 counting algorithm. Empty text estimates one part.
Most control characters, invalid Unicode and more than six parts refuse.
Preview returns text only when this estimate succeeds. The estimate is local
composition feedback, not a carrier or billing guarantee; the selected Android
subscription must still check its actual `divideMessage` result before dispatch.

`produce-template-content.mjs` executes the independently pinned maintained
TypeScript implementation. `test-template-content.py` compares native output
with that oracle and never sends expected answers to the probes. The dedicated
workflow exercises ASCII/control/Unicode cases, canonical escaping, both kinds
of length bounds, reserved names, substitution behavior and segment thresholds.

The canonical content parser bound is distinct from the later encrypted
transport plaintext limit. Large valid local content can still be unsuitable
for encrypted storage.

ZTWT01 encryption, current manifest/reader authorization, protected key opening,
owner template persistence and installed package qualification remain separate
gates. Canonical content and preview confer none of those authorities. Plaintext
content and its digest remain in the caller's trusted client.
