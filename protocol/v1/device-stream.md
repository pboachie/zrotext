# Device stream v1: authenticated session

This is the implemented M1 phone-to-hub handshake. A production endpoint must
use WSS. The current Android client requires a manually entered approved
device UUID and a `wss://` URL ending in `/v1/device-stream`. No live WSS
interoperability or carrier test has passed yet. A guarded server-side
[synthetic-alpha extension](synthetic-alpha-stream.md) is in progress; the
Android stream client currently implements heartbeat only. There is no live
SMS or inbound path.

1. Phone sends `{"v":1,"type":"hello","device_id":"UUID"}`.
2. Hub returns `{"v":1,"type":"challenge","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD"}`. The nonce is 32 random bytes.
3. Phone signs the exact byte string below with its enrolled, non-exportable
   P-256 Android Keystore key using `SHA256withECDSA`. The signature is DER.
   It returns `{"v":1,"type":"proof","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD","signature_der":"BASE64URL_NO_PAD"}`.
4. The writer consumes the challenge once, checks the enrolled key, active
   device/account, enabled site, and deployment epoch, and increments the
   device session epoch. Hub returns
   `{"v":1,"type":"session","connection_epoch":1,"heartbeat_seconds":30}`.
5. Phone sends `{"v":1,"type":"heartbeat"}` every 30 seconds. The hub
   renews the writer-owned lease only while that epoch remains current and
   replies `{"v":1,"type":"heartbeat_ack","connection_epoch":1}`.

Signed bytes are ASCII `zrotext-device-auth-v1` followed by a single zero
byte, the raw 16-byte account UUID, raw 16-byte device UUID, raw 16-byte
challenge UUID, and the raw 32-byte nonce. UUID bytes use network order.
The JSON text itself is not signed. Both clients must reject a changed
challenge ID, account, device, nonce, version, or epoch. Base64url values
have no padding. Client frames reject unknown fields; frames are limited to
4 KiB and the hello/proof steps to 10 seconds each.

The hub checks session status against PostgreSQL on every heartbeat and at
most 10 seconds between heartbeats. A new valid connection fences the older
epoch; release of an old socket cannot clear the newer lease. A drained,
disabled, revoked, or writer-isolated hub closes its session. The phone stops
its foreground heartbeat on protocol failure or timeout; automatic reconnect
has not been implemented. Neither a session nor a heartbeat authorizes SMS.
