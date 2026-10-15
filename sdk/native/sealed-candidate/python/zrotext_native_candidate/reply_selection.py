"""Phone-signed original-reply selections; no role-3 grant or live authority."""
from dataclasses import dataclass
import re
from weakref import WeakKeyDictionary
from . import sealed_candidate as s

DISCLOSURE = ('With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation '
              'to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture '
              'and transfer; retained encrypted content is deleted separately.')


@dataclass(frozen=True)
class _Selection:
    account: bytes
    device: bytes
    line: bytes
    interval: bytes
    peer: str
    archive: bytes
    signer: bytes
    generation: int
    version: int
    digest: bytes
    expires: int
    readers: tuple
    activation: object


_selections = WeakKeyDictionary()


def verify_archive_reply_selection02(raw, approval, installation, activation, accepted_ms, *,
                                    account, device, line, interval, peer, archive_reader):
    """Verify both signatures against an independently accepted activation token.

    Acceptance time and scope are independent caller inputs. The opaque result
    authorizes only the exact archive wrap set, never a reader grant or dispatch.
    """
    raw = s.capture(raw, 380, 1536)
    approval, installation = s.capture(approval, 64), s.capture(installation, 64)
    scope = tuple(s.capture(v, 16) for v in (account, device, line, interval))
    archive_reader = s.capture(archive_reader, 32)
    at = 0

    def take(n, nonzero=False):
        nonlocal at
        s.require(at + n <= len(raw), 'selection truncated')
        value = raw[at:at+n]; at += n
        s.require(not nonzero or any(value), 'selection zero identifier')
        return value

    def number():
        value = s.integer(int.from_bytes(take(8), 'big'))
        s.require(value > 0, 'selection positive integer')
        return value

    def text():
        value = None
        try:
            value = take(take(1)[0]).decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            pass
        s.require(value is not None, 'selection UTF-8')
        return value

    s.require(take(5) == b'ZTCA\x02', 'selection profile')
    selected_account, selected_device, selected_line = (take(16, True) for _ in range(3))
    number()  # capture generation, bound by both signatures
    selected_interval = take(16, True)
    take(16, True); take(16, True); take(32, True)  # receipt, session, nonce
    expires, selected_peer = number(), text()
    s.require(re.fullmatch(r'\+[1-9][0-9]{1,14}', selected_peer) is not None and
              text() == 'conversation-content-v1', 'selection peer/content')
    s.require(take(32) == s.sha(DISCLOSURE.encode('utf-8')), 'selection disclosure')
    archive, signer = take(32, True), take(32, True)
    generation, predecessor = number(), number()
    take(32, True)  # signed predecessor digest; activation chain is independently verified
    version, digest = number(), take(32, True)
    number(); number()  # signed connection/deployment epochs, not live authority
    site, instance = text(), text()
    s.require(version == predecessor + 1 and all(re.fullmatch(r'[\x21-\x7e]{1,64}', v)
              for v in (site, instance)), 'selection activation/site')
    count = take(1)[0]
    s.require(1 <= count <= 6, 'selection reader count')
    readers = []
    for _ in range(count):
        record = (take(16, True), take(16, True), take(32, True))
        s.require(not readers or record[2] > readers[-1][2], 'selection reader order')
        s.require(all(all(record[i] != old[i] for i in range(3)) for old in readers), 'selection duplicate')
        readers.append(record)
    s.require(at == len(raw), 'selection trailing bytes')
    now = s.integer(accepted_ms)
    s.require(0 < now < expires and (selected_account, selected_device, selected_line, selected_interval) == scope
              and selected_peer == peer and archive == archive_reader, 'selection scope/expiry')
    original = s._bound(s._manifests, activation)
    manifest = s._parse_manifest(original.raw, original.trust, now)
    s.require(manifest.profile == 2 and (manifest.trust.account, manifest.trust.generation,
              manifest.trust.version, manifest.trust.digest) == (selected_account, generation, version, digest),
              'selection activation identity')
    key = next((k for k in manifest.keys if k.role == 4 and k.id == signer), None)
    s.require(key is not None and key.active(now) and key.scope & 2 and
              (key.device, key.line) == (selected_device, selected_line), 'selection signer authority')
    for name, signature in (('approve', approval), ('install', installation)):
        s.verify_signature(key.point, signature, 'zrotext/conversation/' + name + '/v2', raw)
    return s._accept(_selections, _Selection(*scope[:3], selected_interval, peer, archive, signer,
                     generation, version, digest, expires, tuple(readers), manifest))


def _authorize_archive(selection, envelope, historical, current, interval, reader):
    selected = s._bound(_selections, selection)
    s.require((selected.account, selected.device, selected.line, selected.peer, selected.archive) ==
              (envelope.account, envelope.device, envelope.line, envelope.peer, reader) and
              selected.interval == s.capture(interval, 16), 'selection archive scope')
    s.require(selected.generation == current.trust.generation and historical.trust.version >= selected.version and
              selected.activation.trust.root == current.trust.root and
              (selected.generation, selected.version, selected.digest) in historical.trust.lineage,
              'selection activation lineage')
    expected = ((2, reader),) + tuple((3, r[2]) for r in selected.readers)
    s.require(tuple(w[:2] for w in envelope.wraps) == expected, 'selection exact wraps')
