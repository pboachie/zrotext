# Synthetic Python and callable HTTP adapter foundation

**Experimental simulator only; not a released agent messaging SDK.** This
foundation for #619 exercises the existing profile-01 TypeScript HTTP client
through a provider-neutral callable function and a Python process wrapper.
Neither adapter has a network transport or accepts credentials. All results carry
`synthetic: true`; acceptance is simulated queue admission, never radio submission
or carrier delivery. This adapter does not implement encryption or signing.

From `sdk/typescript`, run `npm ci --ignore-scripts` and `npm test`.
Node.js 22 and Python 3.12 are CI targets; the PR records actual local versions.
Tests include Python cross-language checks over shared protocol vectors. Keep the
Python wrapper beside the TypeScript source/build tree; no package is published.

Import `simulate_submission` from `sdk/python/agent_simulator.py`. Supply raw
envelope bytes, a list of synthetic HTTP fixtures (`status` and `body`, or
`disconnect`), and an optional attempt cap of 1 through 3. It invokes the built SDK
through bounded stdin. `simulateSubmission` in the TypeScript `agent-adapter`
module is the same callable interface without the process bridge.

The fixed fixture transport delegates syntax/kind validation and HTTP response
classification to the existing SDK. Syntax validation does not prove manifest
trust or signature authorization. Retryable admission failures resend the same
immutable envelope snapshot. Disconnects and malformed responses return `unknown`
after one attempt and require review; they never cause another submission. Policy
refusals stop immediately. Response bodies and exception text are never returned
to the model. `agentReadiness()` always reports unavailable.

This testing seam cannot grant server-side agent authority. Missing acceptance
for #619: scoped readiness/preview/draft/status runtime; #615 policy enforcement;
the #616 shared MCP tool model/schema negotiation; profile-02 encryption,
signature and manifest cross-client verification; customer secret-store
integration; and controlled compatibility/release testing. Python has no independent
HTTP or crypto implementation. Do not supply owner tokens, private keys, plaintext
SMS or real recipient data. Real traffic remains behind the existing general-send,
sealed-content, line-activation and release gates. Report suspected vulnerabilities
through [SECURITY.md](../SECURITY.md).
