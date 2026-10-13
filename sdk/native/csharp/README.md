# C# webhook companion

Source project for .NET 8 or newer, independent of generated code and with no
third-party dependencies. Add a project reference to `Zrotext.Webhooks.csproj`.
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
