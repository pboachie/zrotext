# Owner message activity

The owner console presents `/v1/owner/messages` as a responsive activity list
with time, outbound direction, device context, recipient availability and
text-labelled writer state. Wide screens align the columns; compact screens
stack the same labelled metadata. Writer events remain expandable, including
segment numbers and the indication that only the most recent bounded events
are shown. Queries retain the existing twenty-message page and thirty-two-event
bounds, cursor paging and owner/CSRF authorization.

This endpoint intentionally returns neither recipient values nor message
content. The recipient column therefore says unavailable. All and Inbound
filters are unavailable pending a scoped unified feed contract. The existing
UUID-required inbound event history and webhook delivery/replay workflows
remain separate controls. This presentation does not add a sealed conversation
reader, server content search or analytics.

Accepted, queued and claimed states do not establish sending. Submitting means
a radio attempt remains unconfirmed. Submitted means a sent callback was recorded,
with delivery unconfirmed. A delivered callback does not establish that a
recipient read the message. Failed, cancelled and expired remain distinct.
Unknown, delivery unknown and unrecognized states receive explicit uncertainty
warnings; retrying a possibly sent message can duplicate it. The event list
shows recorded evidence, including grants or radio-attempt evidence when the
writer actually provides it, rather than inferring it from connectivity.

Refresh retains the previous metadata until a valid response arrives. Failure
labels retained rows as historical and current states unknown. Empty valid
responses clear the previous rows. Row identities retain expanded writer
history and restore focused controls on an explicit refresh. Live updates keep
the existing focus, expanded-history and older-page refresh pauses. No pending
pairing input or history selection is cleared by an activity refresh.

Messages whose device is present in loaded fleet pages offer a device context
button. It selects the existing fleet detail panel while retaining focus on
the button and preserving message paging. Absent devices are explicitly absent
from the loaded pages; the console does not fetch unscoped device details or
invent a device status. Authorization expiry clears both activity and fleet
state and late responses cannot restore a previous session's metadata.

Compared with the fleet concept, the console uses the existing dark green and
lime shell and compact metadata columns. Unsupported recipient and unified
inbox features are visibly unavailable, and UUID and writer history remain
available for controlled-test investigation. Browser tests render synthetic
states at compact and wide widths with doubled text, and exercise paging,
expansion, focus, device linking, empty/loading/error states and history controls.
Captures stay in the operating system temporary directory.
