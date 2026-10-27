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

`OwnerProfileElectionClient03.installManifest` provides the fixed same-origin
installation request. It verifies the independently pinned root signature,
the exact successor commitment and its selected active role05 possession key
before passing a public recovery record to a required durable-storage callback.
Only after that callback completes can the single request carry the transient
password and factor. Preparation, storage, transport and response verification
share one absolute deadline; no automatic retry occurs. The callback is trusted
application code and must actually persist the record before resolving.

An uncertain reply preserves the original bytes. `manifestStatus` permits a
fresh sign-in by the same original user to observe that exact opening without
replaying credentials or mutating it through the new session. A missing or
unverifiable observation remains unknown. Returned receipts are candidates:
their exact proof, acceptance window and ancestry-prefix commitment are checked,
but full predecessor policy, accepted ancestry, current permission and actual
server installation remain separate verification obligations. Tests use signed
public vectors and a simulated HTTP endpoint, not a live authenticated server.

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
