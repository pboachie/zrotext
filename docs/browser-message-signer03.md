<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Retained browser message signing key

`BrowserMessageSigner03KeyStore` retains a nonextractable P-256 message-signing
key in a separate IndexedDB database and object store. Its purpose marker,
possession domain and role05 key identity are distinct from SEALED line approval.
It accepts no imported private key and cannot sign as an existing root or reader.

Creation requires an explicit decision to retain a new message signer. The caller
must first reconcile server enrollment: a missing already-enrolled key is a
recovery problem, never a reason to create a replacement. Creation is add-only;
competing tabs have one committed winner. Capacity exhaustion preserves existing
records. Public metadata is published only after transaction completion and a
successful possession check using the actual structured-cloned private key.

Scope includes exact HTTPS origin, account, original owner user, device, line and
root fingerprint. A new sign-in for the same user can reopen custody; that local
operation grants no authenticated session, manifest enrollment, content interval
or permission to send. Loading requires the exact independently root-verified
role05 key ID. The embedding application must separately verify the accepted
current manifest, original election, active content interval, full current phone
selection and explicit operation decision before and after each use.

The key lease provides a trusted application callback with the nonextractable
key; that callback is part of the trusted application, not an untrusted plugin or
server response. Closing, origin changes and aborts suppress further publication.
A five-second operation deadline closes custody even if underlying trusted work
does not cooperate. Crypto already started cannot be undone; late results and
failures are observed but never published as a successful operation.

These local primitives do not install a role05 manifest, advance an authority,
create an interval or expose any sending route. Actual same-root03 enrollment,
durable accepted ancestry, offline root authorization, foreground phone consent
and browser mounting are separate composition work. No retained private key is
exported as a recovery file. Tests use actual WebCrypto keys and simulated
IndexedDB; they do not establish persistent storage in a real browser.

`manifest-install03.ts` separately encodes and verifies the exact513-byte public
possession statement. It binds the original owner/session, selected election and
binding, predecessor and exact signed successor commitments, five-minute
ceremony and actual role05 point/key ID. Received signatures must already be
canonical low-S. The returned decoded data proves that stated key's signature;
it does not authenticate a user, verify the root-signed successor or commit it.
The embedding application must verify all those independent inputs first.

The shared synthetic vector starts with the actual four-role initial manifest
shape, then exercises enrollment, renewal after prior expiry and replacement of
a lost browser key with a root-signed successor. It contains genuine public
signatures, while its timestamps and routing/election commitments are synthetic
inputs. It supplies no accepted database, original election, MFA or local custody
evidence. Every old content interval and admitted message must remain pinned to
its original manifest; a newer key never translates or retries that work.
