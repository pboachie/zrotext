# SMS compliance and current limits

ZROtext currently has a restricted, allowlisted synthetic send pilot. It does not offer a general send API. Recognized replies within a verified pilot reply window now produce account-scoped recipient suppression; replies outside that window and requests through other channels still require operator handling. Do not connect it to a marketing or bulk messaging workflow.

## Operator checklist

- Determine which rules apply where you and your recipients are located, and to the purpose of each message. Document when and how each recipient agreed to receive that type of SMS. A phone number supplied for one purpose is not blanket permission for another.
- Provide a simple way to withdraw consent or opt out. Monitor replies and other contact channels for STOP or equivalent requests, record them promptly, and prevent further messages covered by each request. Handle requests outside the pilot's authenticated reply window separately. Do not assume keyword matching alone handles every request.
- Identify the sender where required, state how to opt out when applicable, and review local rules for message timing, frequency, content and record retention.
- Check your carrier's terms for the SIM and messaging plan. A consumer plan may restrict automated or high-volume traffic. Check the registration and campaign requirements for your route, including US A2P/10DLC when applicable, before sending.
- Keep a reachable contact for recipients and abuse reports. Investigate complaints and delivery anomalies before resuming traffic.

For example, US robotext consent and revocation rules are covered by the [FCC](https://www.fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts); the UK [ICO explains PECR rules for marketing texts](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guide-to-pecr/electronic-and-telephone-marketing/); and Canada's [CRTC explains CASL consent, sender identification and unsubscribe requirements](https://crtc.gc.ca/eng/com500/faq500.htm). Requirements differ by message type, country and route. This page is operational guidance, not legal advice; obtain advice for your use case.

## Gate for general sending

The pilot recognizes exact, case-insensitive STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, REVOKE and OPTOUT. Likely free-text withdrawals create a conservative block marked for review. Exact START or UNSTOP can clear only an existing server suppression from a trusted reply in the same outbound-attempt reply window; this transition does not establish consent for a new message purpose. The phone does not send automatic confirmation SMS. A local block applies as soon as a recognized opt-out is captured, including while the relay is offline. The phone also decodes SMS_RECEIVED PDUs when the optional format extra is missing, accepting only an unambiguous result. A server START acknowledgement leaves a local STOP block active because the current local record lacks a verified line and enrollment generation. Clearing that block requires a future signed line-bound transition. Once its signed event reaches the writer, the account-scoped `recipient_suppressions` table is checked during acceptance under the same account lock used for transitions; exact retries are rejected while active.

An authenticated owner can view active ambiguous SMS suppressions at `/owner/devices` in a review queue. The queue shows the recipient number, whether the signed action matched a pilot reply window, event times and any owner decision; it never shows SMS content.

The owner API also records two kinds of durable owner input. Every write needs the owner session, the exact Origin and the CSRF token, and each is written with an append-only audit record:

- **Off-channel holds.** `POST /v1/owner/opt-out-holds` records that a recipient withdrew consent outside a signed SMS, for example by email or a phone call. The request carries only the E.164 number, a channel code (`email`, `phone_call`, `web_form`, `postal_mail`, `in_person`, `other`), a reason code (`opt_out`, `consent_withdrawn`, `complaint`, `wrong_number`) and the report time. Free-text notes are rejected. A hold is stored apart from signed suppressions, and acceptance checks both under the same account lock, so a hold also rejects an exact retry. Only verified new consent releases a hold: a signed START reply from that recipient observed after the hold was recorded. No owner action releases it. `GET /v1/owner/opt-out-holds` lists active holds 20 at a time.
- **Review decisions.** `POST /v1/owner/opt-out-review/decisions` records one immutable decision, `confirmed_opt_out` or `not_opt_out`, for an item in the review queue. A decision never changes the suppression. A signed STOP is not a review item and cannot receive a decision.

Neither path establishes consent or lifts a block. A non-allowlisted route still requires production line activation and end-to-end device evidence. Keep the general route closed until those gaps are resolved.
