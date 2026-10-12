# Android candidate03 dispatch wire component

This component implements the closed syntax and public signature portion of the
[proposed dispatch03 contract](sealed-dispatch-03-candidate.md). It does not
implement an authenticated execution grant or make sealed dispatch available.
Existing02 types, callers and vectors remain unchanged. There is no profile or
provider fallback after refusal.

`SealedDispatch03Frames.grant` and `.ready` consume raw JSON text, before a
`JSONObject` or another projection can discard duplicate properties. They require
exactly25 Grant03 or15 Ready03 fields. `SealedEnvelopeFetch03.parse` requires
exactly `grant` and `signature_der`, with the complete Grant03 object nested once.
Decoded duplicate names, unknown/missing/null/wrong-type fields, comments,
trailing commas and trailing data refuse. Standard JSON whitespace is allowed.
JSON string escapes that decode to the same supported ASCII spelling are allowed;
duplicate checks apply after that decoding. Strings outside printable ASCII are
unsupported because every specified field is an ASCII identifier or digest.

Parsing is bounded to16384 UTF-16 code units,25 fields per object, one nested
object level,64 decoded characters per name and256 per string. Integers are read
directly from canonical decimal tokens into positive `Long` values: no float,
numeric string, exponent, fraction, leading zero, sign or overflow coercion.
Every positive signed64 value through9223372036854775807 is preserved exactly,
including values above JavaScript's safe Number range. UUIDs must be nonzero,
lowercase hyphenated36-character round trips. Digests must be exact canonical
unpadded base64url encoding of32 bytes. Versions, role and segment bounds are
checked independently of those scalar rules.

The fetch transcript is exactly362 bytes: ASCII `ZT/sealed-envelope-fetch/v3`
plus one NUL, six control bytes, five raw UUIDs, seven u64be values and six decoded
digests in the contract's order. JSON property order is irrelevant. Typed frames
own their parsed scalar values; digest, signature and transcript byte accessors
return independent arrays. Frame renderings contain only validated ASCII values.
Redacted `toString` values never include grants or signatures.

Fetch03 evidence uses minimal positive P-256 DER INTEGERs, exact short-form
SEQUENCE/INTEGER lengths, scalar ranges, exact EOF and low-s BEFORE public
signature verification. Received high-s signatures are refused, even when
mathematically valid. No received signature is normalized. Valid DER shape alone
does not imply a valid proof. Verification uses an independently selected65-byte
P-256 public point and the exact new transcript; a received Grant03 does not
select its own signer.

The component intentionally accepts syntactically valid historical expiration
values: it has no clock or current-authority adapter. A verified public signature
does not prove session eligibility, current manifest/election/binding, signer
authorization, one-use consumption, exact server-stored bytes or permission to
fetch, decrypt, journal or send. Those comparisons must come from actual H2/H4/H6
adapters; `Ready` is syntax, not authorization. HTTP/socket negotiation and error
mapping, signing-key access, H6 installation/CAS/ACK, the same-Room installed03
reader, journal-before-Wolf, body opening and radio UNKNOWN handling remain
separate integration dependencies. The current local profile02 binding cannot
manufacture the missing03 checkpoint. No runtime mounts are added here.

## Defined controls and execution status

The shared corpus is discovered by the existing Robolectric JVM test source set
and compiled through the existing AndroidJUnit4 device wrapper. It reconstructs
the public synthetic contract vector, verifies its public fetch signature and
defines independent raw-JSON, full signed64, UUID/base64url, framing, DER and
signature-binding cases. Fresh process-memory software signing in the corpus is
synthetic public-verification testing; no private scalar is exported, no Keystore
alias is used and no hardware custody or maintained-provider pairing is claimed.

The first ordinary offline focused build completed all four required native
custody ABI checks and app compilation, then stopped at unit-test compilation:
two test renderers used `JSONObject.valueToString`, which Android does not expose.
The corpus now uses the public `JSONArray` writer around one value, preserving
the reordered-field and raw duplicate-key cases. A separately reviewed ordinary
offline continuation passed all ten JVM controls with zero failures, errors or
skips and compiled the actual device wrapper. It completed all four native
custody ABI checks; of44 actionable tasks,22 executed and22 were up-to-date.
No CMake task was selected. Owned compiler processes settled naturally and the
executed source remained unchanged. These are focused component results, not a
full Android or lint run. No instrumentation, network, device, key, receiver,
plaintext, SMS or Play acceptance is established by this component.
