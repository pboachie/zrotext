# Local synthetic scenarios

Run `python scripts/tungsten_sdk.py --source <clean-pinned-tungsten> --mock-check`
from the repository root. This verifies the generator revision and clean checkout,
builds its CLI and external Go emitter, checks the public manifests, starts a
loopback mock on an ephemeral port, runs scenarios, and stops its owned process.
The same command runs in the generation workflow. Cargo and Go must be installed.

For interactive development, `--mock` starts the default-off local mock and serves
until stdin closes. Use only synthetic credentials and data: the mock records
request bodies and authorization headers in its bounded local call history.
Never expose its control endpoints or use it as an authenticated service.

`scenarios.json` supplies ten reusable baseline request fixtures. The runner adds
seeded response consistency across restarts, idempotent replay/conflict, deliberate
response loss and exact replay, rate and bounded timeout failures, scripted cursor
pages, and workflow RPC/gate checks. Default and explicitly enabled gates are
separate disposable processes; no deployment environment variable is changed.
Responses are generated from the current compiled IR. Scripted pages and injected
failures are explicit synthetic fixtures.

The mock checks credential presence/prefix and cookie/CSRF shape. It does not verify
real tokens, permissions, workflow grants, account/device ownership, cryptographic
custody, SMS delivery, billing or server transactions. Programmed responses and
failure injections intentionally run before the normal gate/auth/validation
pipeline, so they cannot qualify those controls. Baseline authentication and gate
cases use the ordinary mock pipeline, without programs or injections.

Idempotency storage is bounded and in-memory (sixteen entries in this suite), not
a production durability guarantee. The scenario driver never automatically
retries; the loss case explicitly replays the identical caller key and body only
after verifying that the first request was recorded. Local read timeouts do not
prove that a mutation failed. None of these tests replace SDK wire, protected-key,
real server, browser-application or controlled-device acceptance.
