# Experimental Java Windows protected recipient

The native adapter supports a 64-bit Windows JVM and Microsoft Platform Crypto
Provider P-256 keys. It pins JNA 5.17.0 with a SHA-256 check because Java 17 has no
built-in NCrypt binding. System libraries load only from System32. The generic
`HpkeRecipient.Recipient` interface is a trusted application adapter and makes no
hardware claim. Existing software entry points retain their JCA ECDSA binding
proof. The protected implementation separately binds the native public point
and supplies native ECDH to the same HPKE schedule without a fake private key.

Qualification requires the hardware-provider bit, exact public blob and valid
curve, zero export policy, private export rejection, and successful ECDH against
an independent software peer. Unsupported platforms and qualification failures
refuse; there is no fallback. This is local qualification, not remote attestation.
The private scalar stays in the provider; shared secrets and plaintext enter
Java memory. Array clearing cannot guarantee erasure of provider/internal copies.

Creation requires a durable flushed alias receipt before native creation.
`close()` releases handles without deleting a persistent key. Only the creating
instance can `deleteCreated()`. Reopening checks an independently trusted public
point and grants no deletion permission. An application must retain failed
cleanup receipts and verify ownership before any recovery deletion.

With Java 17+, Python, Node and the exact maintained producer checkout available:

```text
python sdk/native/crypto-envelope/java/custody/run.py --producer PRODUCER_CHECKOUT
```

The runner verifies the producer revision and JNA digest, builds in a temporary
directory, and probes capability before creating a key. It emits only a fresh
public point to the independent producer, refuses any selected private scalar in
its response, exercises profile02 inbound/outbound and elected profile03 readers,
and verifies owned deletion. The receipt lives outside the build directory so
timeouts preserve recovery information. Any failure after creation fails the
test. Hosted CI without PCP capability proves compilation/refusal only. Other
providers, 32-bit JVMs and Java protected signing are not qualified here.
