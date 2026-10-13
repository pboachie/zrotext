# Candidate managed reviewed template persistence

`OwnerTemplate` now supports explicit preparation, commit, retry and GET
reconciliation in Java, C# and Ruby. The constructor accepts a trusted ciphertext
review callback in addition to the independent owner session and current
authority sources described in [owner-template.md](owner-template.md). Existing
read-only construction remains available; it cannot prepare a write without a
review callback.

Preparation captures a copied envelope, request ID, expected revision, exact
scope and encrypted digest. It validates current permission before and after
the review callback. The returned ticket is an instance-bound capability for
those exact bytes, not a serializable credential. It cannot be restored after
restart or used on another client. The caller's mutable input is never reused
for dispatch.

Only `commit` / `Commit` sends the first POST. `retryUnknown` / `RetryUnknown` /
`retry_unknown` sends another attempt explicitly, with identical encrypted bytes,
idempotency identity and expected revision. At most three POST attempts are
allowed. Every attempted write becomes unknown before dispatch; all failed HTTP
outcomes retain that uncertainty, including refusal statuses. This is the
maintained **template** policy and must not be generalized to other API policies.
Authentication rejection also closes the live retry capability.

A canonical successful receipt and fresh final authority check may produce an
acknowledgement. Pending metadata is cleared only at the foreground success
fence. Closing or expiring the call before that fence preserves uncertainty,
even if the server may have committed. GET reconciliation never acknowledges a
write: equal bytes set `matchesPending`, while the pending identity remains.
At most three unknown-state GET checks are allowed; `readLatest` uses the same
budget when a write is unknown. Contradictory same-revision bytes cannot be
acknowledged by a later receipt.

All operations share one client lifetime and the original preparation deadline.
Current checks may shorten that deadline but cannot renew it. A losing prepare
cannot discard another reviewed ticket or unknown record. Busy state and the
shared eight-worker admission remain held until both the actual worker and
foreground call have settled. A blocked application callback is not forcibly
terminated. Closing releases the live record after settlement; immutable pending
metadata remains available to explain uncertainty. These records are in memory
only and do not provide durable recovery or rollback resistance.

Java/C# use the same bounded single-connection TLS parser for GET and POST, with
a 256-byte receipt cap. Ruby disables standard-library retries. Session origin,
cookie and CSRF are rechecked; no login, bearer credential discovery, redirect,
implicit retry, decryption or SMS send occurs.

## Source acceptance

Use clean shared fixture checkout `c98dc2ffc3ab77b74295b9057807e5b51bc17a76`,
template producer `26e876da9f34372d9cf26511993cf633971e0037` and maintained save
oracle `5a25bac026bebee5eba20dc6048ddc1c773c41ed`. Build `sdk/typescript` in both
producer checkouts with `npm ci --ignore-scripts` and `npm run build`.

```sh
python sdk/native/crypto-envelope/template-save-run.py --language java --fixture FIXTURE --producer PRODUCER --save-oracle SAVE_ORACLE
python sdk/native/crypto-envelope/template-save-run.py --language csharp --fixture FIXTURE --producer PRODUCER --save-oracle SAVE_ORACLE
python sdk/native/crypto-envelope/template-save-run.py --language ruby --fixture FIXTURE --producer PRODUCER --save-oracle SAVE_ORACLE
```

Each runtime runs 49 real loopback TLS controls and 37 maintained state-machine
comparisons. Controls include concurrent prepare, closing during the final
post-write authority callback, caller-input mutation, malformed receipts,
statuses, dropped responses, exact retries and GET reconciliation. The runner
explicitly selects a 1000 ms post-handshake test budget for Java/C# and the
shared 100 ms profile for Ruby. Short pre-dispatch review and ticket-expiry tests
remain unchanged. Runtime defaults are unchanged.

Run `owner-template-run.py` as well for the inherited cold reads, admission,
framing and contradictory-head controls. Installed packages, hosted CI, live
owner service acceptance, current protected opening and reviewed plaintext
authoring remain separate gates.
