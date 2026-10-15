# TypeScript and Python migration comparisons

Keep the existing supported SDK entrypoints. Tungsten clients are experimental,
additive candidates; these examples are not authorization to replace a client or
publish a package. They execute actual clients against synthetic transports.
They do not prove live gateway, carrier, custody, or release readiness.

This comparison targets foundation `1786b4bc4dcbf5351e3b08a42846f049e470f07c`
and the revision in [generator.lock.json](../generator.lock.json), currently
`b5d308db8327ce0a5feede77927176a7b0168e92`. Regenerate and rerun when the pin changes.

## Package boundaries

| Client | Coordinates | Consumer requirement |
|---|---|---|
| Existing TypeScript alpha/webhook | `@elysra/zrotext@0.1.7-rc.1` | Node 24+; retain supported exports |
| Existing Python alpha/webhook | `zrotext_client` import; proposed distribution `zrotext-client==0.1.7rc1` in [#1114](https://github.com/pboachie/zrotext/pull/1114) | Python 3.11+; existing source remains usable |
| Generated TypeScript | `@elysra/zrotext@0.1.0`; runtime `@elysra/tungsten-runtime@0.1.1` | Generated metadata says Node 22+; examples tested on Node 24 |
| Generated Python | `zrotext-sdk==0.1.0`, import `zrotext_sdk`; `tungsten-runtime==0.1.0` | Python 3.12+; Pydantic and HTTPX dependencies |

Generated TypeScript currently reuses the existing npm name with a different
version. Use separate build directories; do not publish it over the supported
package. Tests install Python's exact runtime source from the generator checkout
and its generated wheel, without relying on registry availability. Upstream
[distribution tracking #62](https://github.com/pboachie/tungsten/issues/62)
remains a separate release gate. A source build or wheel install is not publication.

## Methods, results and credentials

The executable functions in [alpha-typescript.mjs](alpha-typescript.mjs) and
[alpha_python.py](alpha_python.py) accept caller-configured clients. Never supply
real credentials to the synthetic tests.

| Operation | Existing TypeScript / Python | Generated TypeScript / Python |
|---|---|---|
| Status | `getStatus(id)` / `get_status(id)` | `public.alphaMessages.getStatus({messageId: id})` / `public.alpha_messages.get_status(message_id=id)` |
| Submit | `submit(intent, key)` / `submit(**intent, idempotency_key=key)` | `public.alphaMessages.submit(args, {idempotencyKey: key, confirm: token})` / `public.alpha_messages.submit(**args, opts={"idempotency_key": key, "confirm": token})` |
| Preview | No corresponding local confirmation API | `public.alphaMessages.submit.preview(args, {idempotencyKey: key})` / `public.alpha_messages.preview_submit(**args, opts={"idempotency_key": key})` |
| Successful value | TypeScript camelCase object; Python dataclass | `Result`: inspect `ok` first; TypeScript wire snake_case object; Python Pydantic model |
| Error | `AlphaApiError` and outcome-unknown exceptions | `Err` with diagnostic category; Python diagnostic is a dictionary |

TypeScript maps the existing camelCase submission intent to the exact snake_case
wire body. Python already uses snake_case. The tests compare actual requests,
including scoped bearer headers and the replay key. Do not assume every API uses
the alpha credential: `bearerAuth` is the alpha API key; workflow uses the separate
`workflowCredential` scheme; owner management uses the `ownerSession` composite
cookie/CSRF/Origin contract. Do not grant a tool owner credentials to work around
a workflow refusal. Preview confirmation is a local runtime check, not server
owner approval or permission to perform radio actions. Review the preview before
passing its token; a preview sends no HTTP request for these alpha operations.

Generated clients default to response validation `warn`; configure
`validateResponses: "strict"` (TS) or `validate_responses="strict"` (Python) as in
the tests. Normal transport/API errors become Results, but configuration misuse
or explicitly unwrapping errors can still raise. Close Python clients or use
their context manager.

## Behavior that must survive migration

Persist the logical intent, `client_message_id`, and caller-selected idempotency
key before submission. Neither comparison path automatically retries a mutation.
If the result is ambiguous, reconcile; do not create a fresh key or intent.
An identical replay must preserve the complete request and remain inside the
server's replay and request validity windows. Poll only after the message ID is
known. Stored `unknown` and `delivery_unknown` states never authorize automatic
resending. Sealed submission has its own exact-envelope replay contract: a
generic HTTP SDK does not create envelopes, recover keys, or establish custody.

Existing alpha timeouts default to 35 seconds (TypeScript milliseconds option,
Python seconds option). Generated clients default to 30,000 milliseconds. The
tests explicitly choose 35,000 milliseconds; equal numbers do not establish equal
deadline semantics. Python's generated driver applies HTTPX phase timeouts and
checks elapsed time after body chunks; it has no enclosing cancellation timer
covering the entire call. Redirect hops get new attempt budgets. Existing Python
alpha also uses urllib socket timeout semantics. Neither is a substitute for the
bounded total workflow deadline in the separate native workflow proposal.
The real loopback reproduction in
[Tungsten #66](https://github.com/pboachie/tungsten/issues/66) demonstrates delayed
Python timeout settlement during body reads; eventual failure is not a total
deadline guarantee.

**Redirect policy is a replacement blocker.** Existing alpha clients refuse all
redirects. The pinned generated clients refuse mutation and cross-origin
redirects but follow same-origin redirects for reads. Neither manifest types nor
client options expose a disable-all switch. Zero retries does not prevent these
hops. Tests deliberately demonstrate the difference, rather than treating a
successful redirected response as parity. Track
[Tungsten #65](https://github.com/pboachie/tungsten/issues/65).

**Request refinements are a replacement blocker.**
[Tungsten #63](https://github.com/pboachie/tungsten/issues/63) tracks conditional
JSON Schema validation, including webhook selection requiring encrypted-transfer
confirmation. Strict response validation cannot repair missing request
refinements. Preserve existing executable validators and server checks.
[Native Python workflow #1125](https://github.com/pboachie/zrotext/pull/1125)
separately preserves closed schemas, canonical action digests, response
correlations and bounded rate-limit retries. Generic generated `tools.call`
does not establish those authority guarantees. The proposal is referenced as a
proposal, not as a merged replacement.

## Pagination has a different scope

Alpha status is an individual message lookup; it has no list method to migrate.
Generated owner metadata offers
`client.public.ownerMessages.list.pages({})` in TypeScript and
`client.public.owner_messages.list_pages()` in Python. These require owner
session authority, return page Results, and map `before` to response
`next_cursor`. The owner response contains `messages` and nullable `next_cursor`.
Stop on an error or an application page limit; do not silently flatten partial
results or use an alpha key as owner authority. These pagination signatures are
source-inspected; the alpha examples do not execute owner pagination.

## Run the comparisons

Generate with the locked Tungsten checkout using
`python scripts/tungsten_sdk.py --source <checkout> --check`. Build the existing
TypeScript SDK with its lockfile, then copy `sdk/tungsten/typescript.package-lock.json`
to `sdk/tungsten/generated/typescript/package-lock.json` and run `npm ci` and
`npm run build` there. Run from the repository root:

```sh
node --test sdk/tungsten/migration/typescript.test.mjs
python -m venv /tmp/zrotext-migration
/tmp/zrotext-migration/bin/python -m pip install <checkout>/runtimes/python ./sdk/tungsten/generated/python
/tmp/zrotext-migration/bin/python sdk/tungsten/migration/test_python.py
```

Use the corresponding `Scripts/python.exe` on Windows. The dedicated
`tungsten-migration.yml` workflow generates from a clean checkout and executes
these commands without service credentials. Coverage includes status result
shapes, submission request identity, local confirmation, ambiguous outcomes,
strict malformed-response refusal, and the same-origin redirect blocker. It
does not cover live authentication, owner pagination, workflow authority,
native sealed-content cryptography, registry publication, or carrier delivery.
