# Candidate managed template content

`TemplateContent` in Java, C#, and Ruby snapshots plain local template text and substitution values. This foundation implements the maintained template contract: 4096 UTF-16 code units of template text, at most 32 values of at most 512 units each, and the 4096-unit aggregate substitution bound. Tokens are exactly `{{identifier}}`; stray braces, malformed identifiers, reserved names, and lone surrogates refuse.

Construct content from native strings and a string map, or call `parse` / `Parse` with exact canonical UTF-8 storage bytes. Canonical JSON has ordered `v`, `template`, and `values` fields, version 1, and ordinal ASCII-sorted value keys. Its SHA-256 digest identifies content only. Parsing rejects alternate JSON spellings, extra or duplicate fields, and invalid UTF-8; returned canonical arrays/maps are copies. The local canonical parser bounds input to 65536 bytes: escaped control characters can make valid local content exceed the separate 32768-byte encrypted transport limit. This helper does not relax that transport limit or implement encryption.

`preview` / `Preview` substitutes each original token once, requires every used value, and bounds the rendered text to 8192 UTF-16 units. Value text containing tokens is not recursively expanded. A template can be valid stored content while its preview refuses because of a missing value, unsupported control character, or segment limit.

`estimate` (Java/Ruby) / `EstimateSegments` (C#) returns a local GSM or UCS-2 estimate, including extension-table septets, multipart capacities, and a six-part cap. Empty text estimates one part, matching the maintained contract. These estimates are not carrier or billing guarantees; the selected device must check actual message parts before dispatch.

No save, template HTTP/store persistence, ZTWT01 encryption/decryption, workflow authority, approval, or sending occurs here. Candidate source availability is separate from installed archive qualification and registry publication.

## Qualification

Run `python sdk/native/crypto-envelope/template-content-run.py --language java --fixture <reviewed-native-template-checkout> --producer <reviewed-maintained-checkout>`; substitute `csharp` or `ruby`, with optional `--ruby` executable. Exact clean source pins are checked. Java reuses the existing pinned Gson dependencies; C#/Ruby add no runtime dependency.

The independent maintained TypeScript oracle creates 47 canonical content cases and 158 segment cases. The runner sends only inputs to native probes, then compares their acceptance, exact bytes/digests, previews, and estimates with the oracle. Cases cover UTF-16 limits, paired/unpaired surrogates, reserved/token grammar, single-pass substitution, JSON escapes and literal escape sequences, aggregate/output limits, and local canonical content exceeding the encrypted transport maximum. A Windows/Linux source workflow runs all three targets. Executed local Windows checks do not establish Linux execution, installed package qualification, or live service acceptance.
