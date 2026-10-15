# Experimental service-backed WebMCP application

This separate single-operator application authenticates browser access while
keeping the scoped ZROtext workflow credential on its server. It is intended for
candidate integration and testing. It does not use or impersonate the ZROtext
owner dashboard session. Signing in never registers tools; the user must choose
**Register workflow tools** in a browser supporting the native document API.
Browsers without native WebMCP show an unsupported-browser message and disable
sign-in and registration before accepting an application access key. No polyfill
or alternate browser authority is installed.

The app supports Node 22 or later and is locally qualified with Node 24 and
Chromium 153. WebMCP remains experimental. Build the generated catalog using the
pinned generation command and compile the maintained TypeScript SDK first:

```sh
python scripts/tungsten_sdk.py --source <clean-pinned-tungsten> --check
npm --prefix sdk/typescript ci --ignore-scripts
npm --prefix sdk/typescript run build
node sdk/tungsten/webmcp/app/server.mjs
```

Configure these values in the server's private environment before starting:

| Variable | Meaning |
|---|---|
| `ZT_WEBMCP_APP_ORIGIN` | Exact canonical HTTPS application origin, including a nondefault port |
| `ZT_WEBMCP_APP_ACCESS_KEY` | Independently generated 32-byte random base64url access key, without padding |
| `ZT_WEBMCP_WORKFLOW_ORIGIN` | Existing HTTPS ZROtext workflow service origin |
| `ZT_WEBMCP_WORKFLOW_CREDENTIAL` | Existing scoped `ztw_` workflow credential; never enter this in the page |
| `ZT_WEBMCP_TLS_KEY` | Private path to the application TLS key |
| `ZT_WEBMCP_TLS_CERT` | Private path to its TLS certificate chain |
| `ZT_WEBMCP_ALLOWLIST` | Optional comma-separated exact workflow methods; defaults to contact read and action status |

Generate the separate application access key using a cryptographic random source
and store it privately. Enter only that application access key on the sign-in
page. Do not reuse the workflow credential or an owner credential. The launcher
binds loopback at the configured origin's port; it does not configure an ingress,
trust forwarded headers, change TLS verification or expose a public deployment.
The TLS listener and exact Host/Origin checks remain required behind an ingress.

The app owns opaque five-minute sessions with Secure, HttpOnly, SameSite=Strict,
host-only cookies. Every tool request checks the session, CSRF value, exact
origin, explicit method allowlist and existing workflow request/response
contracts. The upstream service checks its grant on every call. A page's local
authorization flag never replaces these checks. Only the eight existing
workflow methods are selectable; no owner approval or raw send endpoint exists.
Mutation methods require explicit server configuration as well as user tool
registration, and retain their existing proposal/owner-review semantics.

There is at most one in-flight request per session, sixteen sessions and twenty
login attempts per minute for this single-operator process. Request bodies,
headers, connections and time are bounded. Sessions are memory-only: restarting
the process signs every browser out. This is not a multi-tenant identity provider
or a horizontally shared session service. Grant revocation remains enforced by
ZROtext; the browser also tears down local tools on logout, expiry or page exit.

Requests make one attempt. Logout and disconnection abort active transport, but
cannot prove a dispatched operation did not commit. Reconcile uncertain outcomes
using the original workflow identity. A failed sign-out closes local tools and
reports that server sign-out was not confirmed; the server session still expires.
Responses and errors never include the workflow credential or private diagnostics.

## Installed artifact

The existing `package-webmcp.py` command includes this app in the licensed,
bounded `@elysra/zrotext-webmcp` candidate archive, with zero runtime dependencies.
After installing that archive in a clean project, run `zrotext-webmcp-app` with
the private configuration above, or import `createWorkflowApplication` from
`@elysra/zrotext-webmcp/app`. The factory returns a Node HTTPS server for a
trusted application host. Its optional `workflowFetch` receives the credential
and is a trusted server-only testing/integration seam; never supply it from a
browser or model input. The embedded generated catalog is digest-checked at
startup. No private checkout path is needed at runtime.

The package gate removes build staging before installing and tests actual HTTPS
application login, cookie flags, native registration/execution, origin/CSRF
refusals, expiry, logout, concurrency, rate refusal, and obsolete-session result
suppression using the installed code. Its workflow upstream and credentials are
synthetic, and its disposable browser alone accepts the synthetic TLS certificate.
These checks establish candidate application behavior; they do not establish a
live grant, production deployment, stable browser support, or physical SMS.

For source acceptance, install the pinned owner Playwright dependency, make
OpenSSL available for synthetic certificates, set `ZT_WEBMCP_BROWSER` to the
supported Chromium executable when necessary, and run:

```sh
node --test sdk/tungsten/webmcp/app/app.test.mjs sdk/tungsten/webmcp/app/capability.test.mjs
```

Install the pinned Playwright Chromium, Firefox and WebKit engines for the
capability suite. It runs actual browsers: Chromium with WebMCP enabled and
disabled, plus Firefox and WebKit without a native registration API. A changed
capability fails the gate and requires native registration qualification before
expanding support. The installed package report records the exact engine
versions and capabilities. These desktop engine checks do not qualify branded
Safari, mobile browsers, or a physical device.
