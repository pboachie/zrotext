# C# webhook companion

Experimental package for .NET 8 or newer, independent of generated code and with
no third-party dependencies. Candidate NuGet identity: `Zrotext.Webhooks` version
`0.1.0-alpha.1`.
Tungsten's generated C# SDK has its own runtime requirements.

```csharp
Zrotext.Webhook.Verify(decodedSigningKey, timestampHeader, signatureHeader, rawRequestBytes);
```

Supply the 32 decoded bytes from `signing_secret_b64url`. Capture bytes before
JSON parsing. Verification checks exact canonical headers, an inclusive
300-second window in both directions and constant-time HMAC-SHA256 comparison.
`Zrotext.VerificationException.Reason` identifies refusal without including
the key or body. Keep the clock synchronized; deduplicate event IDs after
successful verification. No sealed-envelope cryptography, replay database or
SMS delivery guarantee is supplied. This package is not published to NuGet.

Run from the repository root:

```sh
dotnet run --project sdk/native/csharp/tests/Tests.csproj
```

The shared server/binary vectors and extra newline/wrong-key checks execute
against the actual companion project.


Build and verify a licensed candidate NuGet archive:
`python sdk/native/package-webhooks.py --target csharp --out <external-directory>`.
The isolated consumer restores an ordinary PackageReference from the archive
with fresh caches after source staging removal, then runs the shared vectors.
Point NuGet at the output directory to consume the candidate package. The harness
allows major runtime roll-forward when the build host has a newer .NET runtime;
compilation still targets net8.0. CI also runs with the .NET 8 SDK/runtime.
Registry publication and native sealed-content packages remain separate gates.
