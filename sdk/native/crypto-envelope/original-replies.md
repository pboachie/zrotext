# Selected original-reply candidate readers

Java `OriginalReplyReader`, C# `OriginalReplyReader`, and Ruby
`ZrotextCandidate::OriginalReplyReader` verify canonical profile02 selected-reader
approval and installation signatures, then open inbound ciphertext for the
independently selected role-3 reader. This is an experimental native companion.

Construct a `Scope` from independently authenticated account, device, line,
interval, connector, read-grant, reader-key and peer identities. Verify selection
against the accepted activation manifest and acceptance time. Both phone
signatures use their exact separate approval/installation domains and canonical
low-S P256 signatures. The selected connector/grant/key tuple must appear in the
ordered selection; selection bytes cannot create a live grant.

Opening takes historical verified manifest provenance and an application-owned
authority callback. The callback must supply independently authenticated current
grant scope, revision, comparison time, expiry and current verified manifest.
The implementation checks manifest ancestry, signed event routing, historical
phone authorization, the exact archive-plus-selected-reader wrap set and current
selected-reader activation before HPKE and AES-GCM opening. It rechecks grant
scope/revision, comparison time, expiry and exact current manifest after decryption
before returning text. A changed/revoked authority refuses the result.

Software private keys remain an explicit option. Qualified `ProtectedRecipient`
instances support the same operation: Java/Ruby use their existing unwrap
interfaces; C# adds `OpenOriginalReply02` under the qualified provider's lock.
No new signing domain or private export fallback is introduced. Generic injected
recipient interfaces carry no hardware qualification claim. Ruby clears its
owned mutable plaintext after final-authority refusal; Java/C# returned strings
and crypto-library internal allocations cannot promise physical erasure.

This callback integration does **not** implement HTTP request/response proof,
accepted-history persistence, restart high-water/freshness fencing, consume/status
recovery or cross-root historical reading. The caller owns those authority and
persistence boundaries. Existing archive and elected profile03 APIs retain their
separate contracts. No SMS permission follows from decryption.

Run the maintained TypeScript fixture acceptance with a clean checkout at
`72124e1a3ff28e782f870eeddbdc33cacf8ca3b4` (build `sdk/typescript` first):

```sh
python sdk/native/crypto-envelope/original-reply-run.py --language java --producer PRODUCER
python sdk/native/crypto-envelope/original-reply-run.py --language csharp --producer PRODUCER
python sdk/native/crypto-envelope/original-reply-run.py --language ruby --producer PRODUCER
```

Java needs Java17+ and pinned JNA5.17.0; C# needs .NET8; Ruby needs Ruby3.3 with
OpenSSL. `--jna` accepts an already downloaded archive with the same verified
hash; `--ruby` selects an executable. Software controls run on every platform.
Windows qualification creates one fresh owned non-exportable PCP recipient,
asks the maintained producer to encrypt for its public point, checks opening,
reopening, revoked/final authority, wrong point and closed/deleted handles, then
deletes only that owned key. Pending receipts survive unsuccessful cleanup.
`--require-hardware` turns pre-creation capability absence into failure. Otherwise
that absence reports `UNQUALIFIED`; it does not establish hardware acceptance.

The closed native package inventory includes the new reader module. The source
runner qualifies this API; new installed-package original-reply acceptance is a
separate gate before claiming complete installed native parity.
