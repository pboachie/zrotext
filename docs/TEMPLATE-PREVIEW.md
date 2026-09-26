# Local owner template preview

Open **Account → Local template preview** after signing in as an owner.
The page at `/owner/template-preview` expands a template locally so you can
inspect personalized text. Nothing is sent, scheduled, saved or uploaded.
This is a partial preview tool, not a template library or messaging workflow.

## Input format

Put variables such as `{{name}}` in the template. In the values box, enter one
`identifier=value` pair per line, for example `name=Alex`. Names are case-sensitive
and match `[A-Za-z_][A-Za-z0-9_]{0,31}`. The names `__proto__`, `prototype` and
`constructor` are reserved. Duplicate or missing values and malformed variables
are refused. Empty values are allowed; blank lines between entries are ignored.
Spaces in values are preserved. Values cannot contain line breaks, but the
template may span multiple lines. LF and CRLF separate entries.

Only `{{identifier}}` is a variable: there are no expressions, nested variables,
property paths or brace escapes. Replacement values are literal text, even if
they contain braces or HTML. Rendering uses `textContent`, never HTML evaluation.

Limits are measured in UTF-16 code units, so a supplementary character such as
an emoji uses two units:

| Input or result | Limit |
|---|---:|
| Template | 4,096 |
| Values box, including names and separators | 4,096 |
| Unique values | 32 |
| Each value | 512 |
| Rendered output | 8,192 |

Unpaired Unicode surrogates are refused. These are editor bounds, not SMS
carrier limits. The tool gives no segment, cost, encoding or delivery estimate;
it does not validate the Android gateway's segment cap.

## Sign-in and text lifetime

The static page contains no account data and remains readable without a session;
its editor starts disabled. The existing owner-session endpoint verifies access
before enabling inputs, before each preview and every 15 seconds while visible.
The page also checks the session's account, owner and session identity, and clears
old text if that identity changes. A network/authentication failure locks the
editor and clears its contents. Revocation elsewhere is detected on the next
check, not by a push notification.

Text is held only in the page's DOM and short-lived JavaScript values. The app
uses no storage, analytics or content requests. The only API calls are the existing
session check and optional sign-out (which has no body). Inputs and output clear
on sign-out, navigation, tab hiding, or a detected session change/loss. Returning
from browser history starts empty and rechecks access; older asynchronous results
cannot restore text from a previous owner. This is application-level clearing,
not a secure erasure guarantee for browser or operating-system memory.

## Verification and scope

Run `node --test web/owner/template-preview*.test.js` for bounded rendering,
Unicode, prototype/getter rejection, literal output, no content requests and
session/lifecycle races. Existing owner-browser CI discovers these files.
`cargo test --locked -p zrotext-server owner_ui::tests` covers static asset
headers, restrictive CSP, disabled controls and rejected native submission.

Reusable saved templates, segment previews, recipient-local scheduling, expiry,
cancellation and delivery remain separate open roadmap work. This tool grants no
SMS permission and changes no account, message or Android state beyond an explicit
sign-out of the current session.
