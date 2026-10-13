# Ruby candidate HPKE recipient

See [the shared managed component contract](../java/README.md) for the exact
suite, trust boundary, limitations, and stdin test fixture format. This source
requires Ruby3.2 or later with OpenSSL3 and uses native ECDH, HMAC-SHA256 and
AES-GCM. The test script imports only fresh synthetic scalar material; it is not
a custody API.
