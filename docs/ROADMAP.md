# Roadmap

ZROtext is an open-source Android SMS gateway in active development. The order below reflects product direction, not release dates or a promise that every feature is available today. Contributions are welcome through [issues and pull requests](../CONTRIBUTING.md).

## Gateway messaging

- Connect a dedicated Android phone and SIM to an authenticated server.
- Accept outbound requests with durable idempotency and clear queued, submitted, delivered, failed, and unknown states.
- Before a general, non-allowlisted send route: extend the restricted pilot's STOP/START and suppression controls beyond outbound-attempt reply windows, bind inbound actions to a durable line ID, and provide owner handling for off-channel or ambiguous requests. The current pilot persists account-scoped suppression and rejects suppressed recipients at acceptance, but those remaining controls keep general sending closed.
- Capture inbound messages and deliver signed webhook events.
- Show device health and message history in the owner dashboard.

## Self-hosting and integrations

- Provide a documented Compose deployment, configuration examples, and upgrade instructions.
- Publish stable API and device protocol contracts, client libraries, and release artifacts.
- Improve setup, diagnostics, accessibility, and supported-device guidance.

## Privacy and account controls

- Build a versioned sealed-content protocol with client-side keys and recovery flows.
- Add account administration, scoped API credentials, and practical data export and deletion controls.

## Managed service and resilience

- Offer hosted accounts, usage limits, subscriptions, and customer support around the same public gateway code.
- Support API and device hubs in two locations with one authoritative database writer and fenced device sessions.

See the [architecture](ARCHITECTURE.md), [two-location design](MULTI-LOCATION.md), and [security design](SECURITY-DESIGN.md) for technical details. These design documents describe a mix of implemented and proposed behavior; inspect the code and release notes for availability.
