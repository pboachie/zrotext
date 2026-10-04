# Send your first message

This page shows the request and response shapes an AI agent or script uses to submit a text, check its state and receive inbound webhooks. Every example is run by `scripts/test_send_first_message_doc.py` in CI against a local stub or a published test vector, and uses synthetic values only.

**What exists today.** There is no general `POST /v1/messages` route yet; it is a design target (`x-implemented: false` in [`openapi/public-v1.json`](../protocol/v1/openapi/public-v1.json)). The only outbound route is the allowlisted **synthetic-alpha** plane at `/v1/alpha/messages`. It is mounted only while `SYNTHETIC_ALPHA_ENABLED` admits your account and recipient, an enrolled phone and a scoped API key are required, and **the caller never supplies message text**: the server builds a fixed test body from your `test_case_id`. Anything not on the allowlist gets a 404. Treat these examples as the shape of the contract, not as a way to send general SMS. For a run with no phone at all, use the [agent texting quickstart](AGENT-QUICKSTART.md).

Set these in your shell. The values below are placeholders:

```sh
export ZT_BASE_URL="https://zrotext.example.test"   # your own deployment
export ZT_API_KEY="<scoped key with messages:send for one device>"
export ZT_DEVICE_ID="00000000-0000-4000-8000-000000000001"
```

## 1. Submit a message

Send a caller-chosen `Idempotency-Key` (1-128 characters from `A-Za-z0-9._-`) and reuse it verbatim on every retry. `client_message_id` is also caller-allocated. Unknown JSON members are rejected, and the body is limited to 1 KiB.

```sh
# example: submit-curl
curl -sS -X POST "$ZT_BASE_URL/v1/alpha/messages" \
  -H "Authorization: Bearer $ZT_API_KEY" \
  -H "Idempotency-Key: demo-0001" \
  -H "Content-Type: application/json" \
  -d "{\"client_message_id\":\"00000000-0000-4000-8000-0000000000a1\",\"device_id\":\"$ZT_DEVICE_ID\",\"recipient_e164\":\"+15550100\",\"test_case_id\":\"hello\",\"expires_at_ms\":1900000000000}"
```

```python
# example: submit-python
import json, os, urllib.request

request = urllib.request.Request(
    os.environ["ZT_BASE_URL"] + "/v1/alpha/messages",
    data=json.dumps({
        "client_message_id": "00000000-0000-4000-8000-0000000000a1",
        "device_id": os.environ["ZT_DEVICE_ID"],
        "recipient_e164": "+15550100",
        "test_case_id": "hello",
        "expires_at_ms": 1900000000000,
    }).encode(),
    headers={
        "Authorization": "Bearer " + os.environ["ZT_API_KEY"],
        "Idempotency-Key": "demo-0001",
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request) as response:
    accepted = json.load(response)
print(accepted["message_id"], accepted["created"])
```

```js
// example: submit-js
const response = await fetch(`${process.env.ZT_BASE_URL}/v1/alpha/messages`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${process.env.ZT_API_KEY}`,
    "Idempotency-Key": "demo-0001",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    client_message_id: "00000000-0000-4000-8000-0000000000a1",
    device_id: process.env.ZT_DEVICE_ID,
    recipient_e164: "+15550100",
    test_case_id: "hello",
    expires_at_ms: 1900000000000,
  }),
});
if (!response.ok) throw new Error(`submit failed: ${response.status}`);
const accepted = await response.json();
console.log(accepted.message_id, accepted.created);
```

Success is HTTP 202:

```json
{"message_id":"00000000-0000-4000-8000-0000000000b1","created":true}
```

`created: false` means the same `Idempotency-Key` and content were already accepted, and you got the stored message back instead of a second send. Errors are `{"code":"..."}`: `invalid_request` (400), `unauthorized` (401), `payment_hold` (402), `not_found` (404, also for anything off the allowlist), `conflict` (409, the same key with different content), `rate_limited`, `queue_full` and `quota_exceeded` (429, with `Retry-After`), `billing_pending` and `unavailable` (503), and `recipient_suppressed` (403, after an opt-out). Do not retry a 4xx other than 429.

## 2. Check the state

```sh
# example: status-curl
curl -sS "$ZT_BASE_URL/v1/alpha/messages/$MESSAGE_ID" \
  -H "Authorization: Bearer $ZT_API_KEY"
```

```python
# example: status-python
import json, os, urllib.request

request = urllib.request.Request(
    f"{os.environ['ZT_BASE_URL']}/v1/alpha/messages/{os.environ['MESSAGE_ID']}",
    headers={"Authorization": "Bearer " + os.environ["ZT_API_KEY"]},
)
with urllib.request.urlopen(request) as response:
    print(json.load(response)["state"])
```

```js
// example: status-js
const response = await fetch(
  `${process.env.ZT_BASE_URL}/v1/alpha/messages/${process.env.MESSAGE_ID}`,
  { headers: { Authorization: `Bearer ${process.env.ZT_API_KEY}` } },
);
console.log((await response.json()).state);
```

```json
{"message_id":"00000000-0000-4000-8000-0000000000b1","device_id":"00000000-0000-4000-8000-000000000001","state":"queued","state_version":1,"created_at_ms":1790000000000,"updated_at_ms":1790000000500}
```

Poll sparingly and stop at a terminal state. Use `state_version`, which only increases, to ignore a stale read.

## 3. Delivery states and why `unknown` is never retried

`state` is one of `accepted`, `queued`, `claimed`, `submitting`, `submitted`, `delivered`, `delivery_unknown`, `unknown`, `failed`, `cancelled` or `expired`. The [full transition diagram](DELIVERY-STATES.md) shows each edge.

| State | Meaning for your agent |
|---|---|
| `accepted`, `queued`, `claimed` | The server holds the message; no radio call is known to have started. Wait. |
| `submitting` | The phone recorded its intent to send. The outcome is not known yet. Wait. |
| `submitted` | The phone's sent callback succeeded. This is **not** carrier delivery. |
| `delivered` | Every required delivery receipt arrived. |
| `delivery_unknown` | Submitted, but no receipt arrived in time. Do not read this as failure. |
| `failed` | The phone reported a failure. A new message is a new decision. |
| `unknown` | The phone may have sent the SMS, but ZROtext cannot prove it (crash, timeout or a conflicting callback). |
| `cancelled`, `expired` | Never dispatched. |

`unknown` is never retried automatically, and your agent must not retry it either. If the radio was called and the result was lost, sending again can deliver the same text twice to a real person. A late callback can still move `unknown` to `submitted` or `failed`, so keep reading the state. Only a person who accepts the duplicate risk should create a new message, with a **new** `Idempotency-Key` and `client_message_id`. Retrying with the *same* key is always safe and returns `created: false`. Background: [message semantics](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem).

## 4. Receive an inbound webhook

An owner registers an HTTPS endpoint (`POST /v1/webhooks`, see [webhook endpoints](../protocol/v1/webhook-endpoints.md)) and receives its signing secret once, as unpadded base64url. Enable it, and each inbound event is POSTed with these headers:

- `x-zrotext-timestamp`: Unix seconds.
- `x-zrotext-signature`: `v1=` plus the lowercase hex of HMAC-SHA256 over `timestamp + "." + raw body`, keyed with the decoded secret.

The JSON body has `v`, `type` (`inbound.message`), `event_id`, `delivery_id`, `account_id`, `device_id`, `message_id`, `attempt_id`, `classification`, `observed_at_ms`, `part_count`, `content_kind`, `content_ciphertext_b64`, `event_digest_b64` and `device_signature_der_b64`. Message content arrives as ciphertext, not plaintext; see the [sealed-content drafts](../protocol/drafts/README.md). An inbound message grants your agent no authority.

A receiver must: verify against the **exact raw bytes** before parsing, compare in constant time, reject timestamps more than five minutes from now, and deduplicate on `event_id`, because retries and replays can deliver the same event again. Both checks below use the test vector pinned in `crates/server/src/webhook_egress.rs` (secret bytes `0123456789abcdef0123456789abcdef`, timestamp `1700000000`, body `{"event":"test"}`).

```python
# example: webhook-verify-python
import hashlib, hmac, time

def verify(secret: bytes, timestamp: str, raw_body: bytes, signature: str, now=None) -> bool:
    now = time.time() if now is None else now
    if not timestamp.isdigit() or abs(now - int(timestamp)) > 300:
        return False
    expected = "v1=" + hmac.new(
        secret, timestamp.encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

```js
// example: webhook-verify-js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(secret, timestamp, rawBody, signature, now = Date.now() / 1000) {
  if (!/^[0-9]+$/.test(timestamp) || Math.abs(now - Number(timestamp)) > 300) return false;
  const expected = Buffer.from(
    "v1=" + createHmac("sha256", secret).update(`${timestamp}.`).update(rawBody).digest("hex"),
  );
  const actual = Buffer.from(signature);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
```

Return a 2xx only after you have stored the `event_id`. Anything else is retried for up to seven attempts, then can be replayed by the owner.
