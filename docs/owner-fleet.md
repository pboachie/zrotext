# Fleet snapshots and selected device details

The owner fleet uses the [shared shell](owner-shell.md) and keeps approved devices
at the entry point. Wide screens place selected details beside the device cards;
compact screens stack the same panel below them. View details selects a device
by its identity, not its position. The pressed button identifies the selection
and points to the panel for keyboard and assistive-technology users.

The overview count covers only loaded pages. It is not an account-wide total.
Authenticated socket leases are server observations that can lag a dropped
connection, not SMS-readiness indicators. Each card retains its bounded pending
and in-flight counts and observation timestamp. The detail panel repeats the
existing selected-SIM, permission, airplane-mode and network observations with
their freshness and blocker explanations. Local aging continues when polling is
paused; an old report cannot become current again after a clock change or resume.

Refresh retains rows by device identity, selection, focused row controls and
unrelated pending form input. Automatic refresh still respects the existing
focused-row and older-page pauses, live-event coalescing, reconnect backoff and
snapshot fallback. Failed or malformed responses retain the prior loaded page
with an explicit stale warning. If the selection is absent from a refreshed
page, its old details are cleared; absence is not presented as proof of revocation.
Revoked devices remain inspectable but cannot be revoked again. Sign-out clears
the selection and detail values with the existing owner-state cleanup.

The concept's sample battery, charging, exact heartbeat age and SIM phone digits
have no supported owner projection and are explicitly unavailable. Default SMS
role is also not reported. Remote Pause has no owner API; Revoke remains a
confirmed removal of gateway authorization. SMS-line activation remains a link
to the existing owner flow, and private-pilot sending stays gated. No display
observation proves carrier readiness or delivery.

Rendered Chromium tests use synthetic multi-device, loading, empty, blocked,
historical, failed-refresh and revoked fixtures. They verify the side panel and
stacked layout, doubled text, selected identity, focused controls, pending input,
local report aging without extra requests, cancellation and CSRF revocation.
Screenshots are temporary opt-in captures, never public evidence files. The
layout deliberately keeps existing security and administration below the fleet;
the concept's marketing header and unsupported hardware controls are absent.
