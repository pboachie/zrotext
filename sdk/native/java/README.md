# Java webhook companion

Java 17+ experimental companion for Tungsten-generated clients. No runtime or
third-party dependencies. The Maven coordinate is
`io.github.pboachie.zrotext:zrotext-webhooks:0.1.0-alpha.1`; the public Java package
is `org.zrotext`. Candidate archives are built with the command below.

```java
byte[] key = java.util.Base64.getUrlDecoder().decode(signingSecretBase64url);
org.zrotext.Webhook.verify(key, timestampHeader, signatureHeader, rawRequestBytes);
```

The key must contain exactly 32 decoded bytes. Capture the request body before
parsing JSON. Verification checks canonical header syntax, a symmetric inclusive
300-second window and HMAC-SHA256 using constant-time comparison. Failures expose
`VerificationException.reason`. Treat them as refusal; never log keys or bodies.
Keep the system clock synchronized and deduplicate event IDs after verification.
This authenticates webhooks; it provides no sealed-envelope reader, Android
compatibility guarantee, replay database or SMS delivery guarantee.

From the repository root, with a temporary build directory:

```sh
build=$(mktemp -d)
javac --release 17 -Xlint:all -Werror -d "$build" sdk/native/java/src/org/zrotext/Webhook.java sdk/native/java/test/WebhookTest.java
java -cp "$build" WebhookTest sdk/native/webhook-vectors.tsv
```

The shared vectors bind the existing server HMAC vector and a binary body with
NUL, invalid UTF-8 and Unicode bytes. Native tests additionally reject newline
suffixes and a wrong key. This package is not published to Maven Central.


Build a licensed candidate feed and verify an isolated ordinary Maven consumer:
`python sdk/native/package-webhooks.py --target java --out <external-directory>`.
The source staging is removed before dependency resolution and all shared vectors
run against the installed jar. Add the generated feed as a Maven repository and
use the coordinate above; no sibling source checkout is needed. Public registry
availability and release publication remain separate gates.
