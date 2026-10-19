# First profile03 public upgrade proposal

`ZTPU01` is a typed public file for explicit approval by an existing offline root
custodian. It creates no root, activation, election, owner authentication or
permission. It is source integration for the initial generation-one, zero-anchor
02-to03 cut; live HTTP, phone and durable selection remain separate obligations.

The exact framing is `ZTPU` plus byte1, account/device/line UUIDs (16 bytes each),
canonical HTTPS ASCII origin (u16 length plus bytes, at most512), independently
compared root fingerprint32, independently accepted predecessor version u64,
predecessor semantic digest32, selected phone reader ID32, selected phone signer
ID32, issued time u64, exact signed02 predecessor (u16 length plus bytes) and exact
unsigned03 successor (u16 length plus bytes). Integers are big-endian, positive
and within signed64 storage; UUIDs/digests are nonzero. Maximum file size is20480
bytes. No extra fields or trailing bytes are accepted.

The builder requires a genuine verified02 handle and its separately retained
original signed bytes, the compared root, selected existing phone identities and
trusted time. The custodian must supply intended scope and predecessor high-water
independently; decoding a downloaded proposal cannot supply those expectations.
The predecessor signature, original root, selected active role1 reader and role4
signer and their exact device/line are verified. Original02 chain provenance and
the supported initial generation remain installation obligations.

Only the following bytes change: the existing03 profile/predecessor header,
version increments by one, issued time becomes the explicitly reviewed value,
and previous digest becomes the original02 semantic digest. Account, root, expiry,
record order and every complete key record remain byte-identical. The result is
signed only under the existing framed `ZTSE/manifest/v3` domain. No key validity
is extended and no archive reader or role5 signer is added. Both predecessor and
new output must remain valid at the post-wait comparison time.

The browser verifies the returned exact unsigned delta and genuine03 signature
before reserving an election. The manifest does not sign an HTTP owner session,
line binding generation, selected SIM observation or message. The separate
authenticated E500/bundle628 ceremony, original receipt verification and current
authority checks remain mandatory. A root signature supplies no durable server
acceptance or phone readiness.
