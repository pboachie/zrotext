# Ruby candidate HPKE recipient

See [the shared managed component contract](../java/README.md) for the exact
suite, trust boundary, limitations, and stdin test fixture format. This source
requires Ruby3.2 or later with OpenSSL3 and uses native ECDH, HMAC-SHA256 and
AES-GCM. The test script imports only fresh synthetic scalar material; it is not
a custody API.

Binary journals select `File::BINARY` when creating or reopening the file.
On Windows, setting `binmode` only after opening a read/write file can remove
a trailing `0x1A` byte before validation. The binary open preserves exact
checksummed bytes; journal formats and fail-closed corruption checks are
unchanged. This prevents new truncation but cannot repair an already truncated
journal; restore such a journal only from an independently trusted complete copy.
