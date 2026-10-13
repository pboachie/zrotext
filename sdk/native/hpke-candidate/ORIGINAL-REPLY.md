# Candidate selected original-reply reader

Rust `original_reply` and Go `OriginalScope`, `ReplySelection` and the
`Open*OriginalReply02` functions implement local selected role-3 opening. The
selection verifier checks canonical framing, distinct ordered reader grants,
the disclosure digest, exact activation identity and both low-S phone approval
and installation signatures. The result owns immutable verified scope and
activation provenance; caller mutation cannot turn it into another selection.

Opening requires independently accepted historical manifests and a trusted
callback that supplies freshly authenticated current grant scope, revision,
deadline, clock and manifest. The reader checks original enrollment/current root
and generation, accepted activation and historical ancestry, the exact event,
peer, line/device, and the entire signed archive/selected-reader wrap set. All
historical recipients and the phone signer must be active at the observed time;
the selected role-3 reader must remain active now.

After authenticated HPKE and AES-GCM decryption, a second callback must retain
the same scope, revision and current manifest identity with a nondecreasing
clock and unexpired deadline/reader. Only then is strict body text returned.
Temporary CEK/plaintext buffers are cleared; Rust also clears returned owned
text on drop. Go strings and caller copies are outside that cleanup guarantee.

Software opening explicitly takes an exportable scalar. On Windows the hardware
entry point accepts the existing qualified PCP recipient, with no key export or
software fallback. The shared hardware test's `--original` mode uses the native
public point with the maintained producer's `--reader-point`; the selected
scalar must be absent. It retains receipt-before-create, reopened-key binding,
closed-key refusal and exact newly owned key deletion checks.

Run `run-original.py --language rust|go --producer REVIEWED_CHECKOUT` with the
documented native toolchains and the pinned producer's TypeScript build ready.
It executes actual maintained TypeScript ciphertext, selection mutation/high-S,
wrong event/key/wrap, current revocation and final scope/revision/expiry/clock
controls. Windows capability absence is explicitly unqualified; hosted software
checks do not prove protected hardware acceptance.

This surface performs no network calls or retries. Its callback is a trusted
integration boundary, not evidence of an HTTP grant response. Dedicated
role-3 authenticated read/current/consume/status transport, persisted accepted
history and comparison high-water integration remain separate work under #1128.
An opaque phone selection alone does not authorize current server access, consume
an event, or confer archive-key authority. Profile03 inbound and cross-root
historical opening remain unsupported.
