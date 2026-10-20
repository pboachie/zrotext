# Android profile03 capture journal and ingress fences

The ordinary SMS receiver now commits a permanent, keyed PDU route before entering
legacy conversation or ordinary body storage. The shared process reservation gate
covers only the short storage decision. Keystore, encryption, provider and network
work stays outside it. The legacy content database remains separate: this ordering
is not a cross-database atomic transaction.

An existing legacy metadata event, conversation receipt or potentially signed
wire capture excludes profile03 for that PDU, including after content deletion.
An unreadable existing journal blocks content rather than proving absence. A
missing legacy file is only an exclusion-read result; it cannot initialize an
allocator or prove that a previously enrolled device has no history.

A pending or released profile03 election is never permission to fall back to an
older content protocol. Initial03 setup withdraws that older account/device/line
RAM scope before its first Room or signing wait. Actual legacy setup also restores
the negative fence from pending/ever-signed history; old runtime and crypto guards
recheck it around blocking work. A returned old signature/plaintext after this
withdrawal is refused. No process fence can grant03 or be reset by a timer. A retained device-signed election, independently compared
root and existing enrolled hardware identity can supply a **negative-only** mode
witness. Wrong scope, missing SIM attribution, lost keys, partial history and
mismatched signatures block content. Neither this witness nor a stored accepted
flag authorizes capture. A protected copy of the exact original evidence is
retained only after the shipping original-proof reader completes its independent
historical verification. That immutable record is history, not present authority.

Each PDU route is one-way: a duplicate never enters content capture again, even
when a later connection or approval would otherwise allow it. Profile03 drop and
blocked routes have no body, capture identifier or sequence. Explicit STOP,
ambiguous opt-out review and opt-in reporting remain independent of that content
choice. Local withdrawal is recorded before content reservation. The default SMS
application still owns inbox writes and notification.

The receiver classifies consent actions before HMAC or Room access. STOP and
ambiguous withdrawal synchronously invalidate every older suppression-health RAM
epoch, then create a content-free negative crash marker before waiting for keys.
Only a durably recorded original recipient withdrawal may complete that marker.
Completion cannot restore an older effect lease. A key or storage failure instead
keeps installation-wide quarantine and aggregate opt-out, review or opt-in debt.
The independent negative filesystem journal also survives a Room failure. A cold
or partially written withdrawal marker is uncertainty and cannot be adopted by a
new process. If the filesystem itself is unavailable, successful durable retention
is not claimed. No original sender/PDU identity or recipient-specific report is
invented after protection loss.

Actual SMS, sealed messaging and debug MMS platform paths check the same health
lifetime after blocking work and immediately before their platform call. Runtime
guards use retained epochs, so a temporary withdrawal followed by a successful
read cannot revive old authority. Cold setup reads negative state outside storage
writers. Those reads neither require a content key merely to inspect setup history
nor establish a positive capture or radio permission.

Room version19 adds separate route, immutable original-mode, capture-phase and
first-ever counter tables. It migrates existing version18 state without creating
any counter or ready protection row. A separate negative protection-state table
retains quarantine and aggregate consent debt. All production HMAC callers use
one existing-only continuity reader; receiving, grant reservation, suppression
lookup and radio entry never create a missing HMAC alias. Explicit setup no longer
creates protection keys from inside a Room transaction. Genuine first provisioning
and pre-pin legacy adoption still need their own verified once-only contract;
this slice has no ready/pin insertion or usable positive provisioning factory.
Every positive HMAC read requires its retained expected identity and origin; absent
state refuses even when an alias or an otherwise empty database exists. Therefore
this draft is not complete default legacy support or an available first setup.
There is deliberately **no usable counter-initialization API**.
The actual two-sided bootstrap, hardware canary and original matching committed
receipt must be implemented and installed before a producer can use this counter.
Empty tables, database maxima, a downloaded response and missing legacy files are
never substitutes. Loss of the protected original history refuses recovery;
privileged restoration of an older otherwise valid complete local snapshot is
outside the supported crash/loss model and is not detected by canary existence.

The storage primitive atomically burns the next positive account/device sequence
with its original capture identity. It never resets for another line, binding,
interval, connection or Stop. Envelope-signing reservation, completed envelope,
intent-signing reservation and exact final packet have separate forward-only
phases. A crash or unknown key call cannot repeat a phase. Scope, original hashes,
sequence and permission deadline cannot change during progression. A historical
ACK can finish an exact retained packet after Stop or redaction; it cannot clear
an unknown burn, restore personal material or mint a current RAM ticket.

Content redaction removes only the protected payload. The route, counter, phase
and commitment tombstones remain. No automatic history pruning or lifetime
allocation limit is added. The complete live capture publisher, genuine bootstrap
factory, capture-specific current permission consumer, maintained signing/upload
and independently verified ACK consumer are still required before profile03
inbound content becomes available. This source slice intentionally drops elected
profile03 content when those prerequisites are absent.

JVM tests exercise real Room transactions, migration/schema validation, phase
CAS, rollback after withdrawal, overflow, retained hashes, cold reopen and
concurrent route ordering. Cryptographic exclusion tests use genuinely signed
synthetic elections and an explicitly compared synthetic root; they are not
hardware custody or hosted service qualification. Instrumented schema tests also
include the additive migration. Actual execution results belong to their test
receipts; authored tests and packaged APKs alone do not prove device or carrier
behavior.
