# SMS compliance and current limits

ZROtext currently has a restricted, allowlisted synthetic send pilot. It does not offer a general send API, automatically process STOP/START replies, or maintain a recipient suppression list. Its inbound pilot does not make opt-out handling automatic. Do not connect it to a marketing or bulk messaging workflow.

## Operator checklist

- Determine which rules apply where you and your recipients are located, and to the purpose of each message. Document when and how each recipient agreed to receive that type of SMS. A phone number supplied for one purpose is not blanket permission for another.
- Provide a simple way to withdraw consent or opt out. Monitor replies and other contact channels for STOP or equivalent requests, record them promptly, and prevent further messages covered by each request. Do this outside ZROtext until suppression is implemented. Do not assume keyword matching alone handles every request.
- Identify the sender where required, state how to opt out when applicable, and review local rules for message timing, frequency, content and record retention.
- Check your carrier's terms for the SIM and messaging plan. A consumer plan may restrict automated or high-volume traffic. Check the registration and campaign requirements for your route, including US A2P/10DLC when applicable, before sending.
- Keep a reachable contact for recipients and abuse reports. Investigate complaints and delivery anomalies before resuming traffic.

For example, US robotext consent and revocation rules are covered by the [FCC](https://www.fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts); the UK [ICO explains PECR rules for marketing texts](https://ico.org.uk/for-organisations/direct-marketing-and-privacy-and-electronic-communications/guide-to-pecr/electronic-and-telephone-marketing/); and Canada's [CRTC explains CASL consent, sender identification and unsubscribe requirements](https://crtc.gc.ca/eng/com500/faq500.htm). Requirements differ by message type, country and route. This page is operational guidance, not legal advice; obtain advice for your use case.

## Gate for general sending

A non-allowlisted send route must wait for phone-side opt-out capture, authenticated suppression events, durable account-scoped `suppression_entries`, and an acceptance-time rejection of suppressed recipients. It also needs an operator workflow for withdrawal requests received outside SMS and tests proving that concurrent sends cannot bypass a newly recorded suppression. These controls are planned in the [roadmap](ROADMAP.md); none are available in the current synthetic pilot.
