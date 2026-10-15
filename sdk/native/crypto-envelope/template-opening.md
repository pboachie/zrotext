# Current owner-template opening

Java `OwnerTemplateOpening`, C# `OwnerTemplate.Opening`, and Ruby
`OwnerTemplate::Opening` add explicit local preview to a dedicated concrete
owner-template client. Construction performs no read. The supplied client's
origin, complete owner binding, and template identity must match the opening
options. Independent current and owner-session callbacks remain required.

The default opening entrypoint accepts the existing locally qualified Windows
PCP `ProtectedRecipient`. It verifies the selected public point before GET,
checks recipient liveness after authenticated opening and before publication,
and refuses a closed supplied client even if its GET already completed. The
separate software entrypoint is candidate software custody. Java proves its
private/public handle binding with a domain-separated native signature before
GET; providers unable to perform that proof refuse rather than export a scalar.

The opening layer reuses bounded admission and total operation deadlines. It
owns closing its dedicated client; call close or invalidate on owner loss,
custody replacement, or UI removal. It never closes or deletes the caller's
recipient. Closing the opening or client suppresses late results. Workers that
have not settled retain admission, including blocked trusted callbacks.

Each returned immutable preview contains text, segment estimate, encrypted
digest, revision, and whether ciphertext matches a pending save. Reading or
opening never acknowledges that save. A preview is not persistence, workflow,
approval, or send authority. Current snapshots and scope bytes are captured;
signed history alone does not replace live application authority.

Ciphertext and raw decrypted working buffers are cleared where owned. Java/C#
immutable strings and Ruby frozen content strings cannot promise physical
secure erasure. Host callbacks and caller-owned keys remain trusted application
boundaries. No remote custody attestation, live owner-service acceptance,
durable save recovery, or complete legacy SDK parity is claimed.

`template-opening-run.py` compiles isolated source consumers and invokes a pinned
shared synthetic TLS suite plus maintained TypeScript lifecycle comparisons.
`--hardware` instead requires an available PCP provider and exercises actual
protected recipient opening, closure, and interrupted setup cleanup. Test keys
have private receipt-before-create records and exact owned deletion checks;
those are test cleanup, not opening lifecycle behavior. Hosted software checks
do not establish native hardware qualification. Java/C#/Ruby use an explicitly
declared 1000ms post-handshake fixture budget; the separate 100ms pre-dispatch
refusal remains enabled and library defaults are unchanged.
