# Bounded SMS segment estimates

Status: contract for composition-time estimates. This is **not** a carrier,
billing, or delivery guarantee, and it never approves, schedules, or sends
anything. The device re-checks the real segment bounds immediately before
dispatch (Android `SmsManager.divideMessage` on the selected subscription,
accepting 1..6 parts); where the estimate and the device disagree, the device
wins and the send is refused.

The estimate exists so a template author can see, next to the local preview,
roughly how many message parts a rendered template would cost. It is defined
here so every implementation (browser preview, TypeScript SDK, and any later
device-side adoption) produces the same numbers from the same text.

Shared vectors: [`vectors/sms-segment-estimate-01.json`](vectors/sms-segment-estimate-01.json).

## Input rules

The input is UTF-16 text (a rendered template or any draft text):

- A lone surrogate (high without a following low, or a low alone) is invalid;
  a well-formed surrogate pair is one character and **two** code units.
- Control characters are invalid except LF (`U+000A`), CR (`U+000D`) and FF
  (`U+000C`); those three are carriable. Tab, NUL and other C0 controls are
  rejected rather than silently re-encoded.

## Encoding choice

- If **every** character is in the GSM 03.38 default alphabet or its
  extension table, the text is **GSM** (7-bit packed).
- Otherwise the text is **UCS-2** (16-bit code units). A single non-GSM
  character switches the whole message; there is no per-part fallback.

## GSM septet accounting

- Each default-alphabet character costs **1** septet.
- Each extension-table character (`FF`, `^`, `{`, `}`, `\`, `[`, `~`, `]`,
  `|`, `€`) costs **2** septets: one escape plus one character.

## Part counts

| Encoding | Single part | Multipart part size | Hard cap |
|---|---|---|---|
| GSM | 160 septets | 153 septets | 6 parts |
| UCS-2 | 70 code units | 67 code units | 6 parts |

- Length at or below the single-part budget is **1** part.
- Otherwise parts = ceil(length / multipart size).
- More than 6 parts is an error ("too long"), matching the device-side
  1..6 gate, so a template the device could never dispatch cannot be
  previewed as sendable.
- Empty text is 1 part (the device also produces one empty part).

The multipart budgets (153 / 67) are the concatenated-SMS per-part sizes
after the part headers; they are the standard composition estimate and
still make no billing claim — carriers may count differently.

## Versioned template digest

Saved templates are content-addressed: the digest is SHA-256 over the
canonical UTF-8 bytes of `{"v":1,"template":...,"values":{sorted pairs}}`
(template text plus its personalization input contract, keys sorted,
no whitespace). Saving identical content yields the identical digest;
any change to template text or the personalization contract yields a new
digest, which is how a changed template is detected as a new version.
Personalization values follow the browser preview's bounded contract
(template ≤ 4096 units, ≤ 32 entries, value ≤ 512 units, rendered output
≤ 8192 units, `{{identifier}}` tokens only).

The relay never stores or evaluates template plaintext: the digest and the
estimate are computed where the plaintext already lives (the owner's
browser), and the device re-checks before dispatch.
