# C# candidate HPKE recipient

See [the shared managed component contract](../java/README.md) for the exact
suite, trust boundary, limitations, and stdin test fixture format. This source
requires .NET8 or later and uses native ECDH, HMAC-SHA256 and AES-GCM. The test
project imports only fresh synthetic scalar material; it is not a custody API.
