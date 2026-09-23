"""Executable shape examples for the unapproved ZT-009 draft.

These dummy bytes deliberately have invalid cryptographic points/signatures. This
checks only field offsets, bounds and identity relationships in the draft; it is
not a production parser or cryptographic vector set.
Run: python -m unittest discover -s protocol/v1/tests -p 'test_zt_sealed_draft_shape.py'
"""

import hashlib
import unittest


WRAP_SIZE = 146
MANIFEST_RECORD_SIZE = 149
ZERO = b"\x00"
MAX_SIGNED_64 = (1 << 63) - 1


def u16(value):
    return value.to_bytes(2, "big")


def u32(value):
    return value.to_bytes(4, "big")


def u64(value):
    return value.to_bytes(8, "big")


def check_envelope_shape(data):
    if not 426 <= len(data) <= 36_864 or data[:5] != b"ZTSE\x01":
        raise ValueError("envelope bound or version")
    kind = data[5]
    if kind not in (1, 2) or data[6:8] != ZERO * 2:
        raise ValueError("kind or flags")
    protected_len = int.from_bytes(data[8:10], "big")
    if protected_len not in (range(157, 171) if kind == 1 else range(172, 186)):
        raise ValueError("protected bound")
    end = 10 + protected_len
    if end > len(data):
        raise ValueError("truncated protected")
    protected = data[10:end]
    peer_offset = 153 if kind == 1 else 168
    peer_len = protected[peer_offset]
    if protected_len != (154 if kind == 1 else 169) + peer_len:
        raise ValueError("protected length")
    peer = protected[peer_offset + 1 :]
    if not (3 <= len(peer) <= 16 and peer[:1] == b"+"
            and peer[1:2] in b"123456789" and peer[2:].isdigit()):
        raise ValueError("peer")
    if kind == 1 and protected[152] != 1:
        raise ValueError("intent")
    if kind == 2 and protected[16:32] != protected[144:160]:
        raise ValueError("inbound IDs")
    if int.from_bytes(protected[64:72], "big") > MAX_SIGNED_64:
        raise ValueError("unrepresentable keyset version")
    if int.from_bytes(protected[136:144], "big") > MAX_SIGNED_64:
        raise ValueError("unrepresentable timestamp")
    if kind == 1:
        created = int.from_bytes(protected[136:144], "big")
        expires = int.from_bytes(protected[144:152], "big")
        if expires > MAX_SIGNED_64 or not created < expires <= created + 900_000:
            raise ValueError("outbound expiry")
    else:
        sequence = int.from_bytes(protected[160:168], "big")
        if not 1 <= sequence <= MAX_SIGNED_64:
            raise ValueError("inbound sequence")
    if end + 12 + 4 + 1 + 64 > len(data):
        raise ValueError("truncated body header")
    ct_len = int.from_bytes(data[end + 12 : end + 16], "big")
    if not 17 <= ct_len <= 32_784:
        raise ValueError("body ciphertext bound")
    count_offset = end + 16 + ct_len
    if count_offset >= len(data):
        raise ValueError("truncated body ciphertext")
    count = data[count_offset]
    if not ((2 <= count <= 8) if kind == 1 else (1 <= count <= 7)):
        raise ValueError("wrap count")
    if count_offset + 1 + count * WRAP_SIZE + 64 != len(data):
        raise ValueError("truncated or trailing bytes")
    roles = []
    previous = None
    for index in range(count):
        start = count_offset + 1 + index * WRAP_SIZE
        pair = (data[start], data[start + 1 : start + 33])
        if previous is not None and pair <= previous:
            raise ValueError("wrap ordering or duplicate")
        if pair[0] not in (1, 2, 3):
            raise ValueError("wrap role")
        previous = pair
        roles.append(pair[0])
    if roles.count(2) != 1 or roles.count(1) != (1 if kind == 1 else 0):
        raise ValueError("required recipient roles")
    return kind


def key_id(role, point):
    algorithm = 0x0101 if role in (4, 5, 6) else 0x0010
    return hashlib.sha256(b"ZTSE/key/v1\x00" + u16(algorithm) + point).digest()


def check_manifest_shape(data):
    if not 364 <= len(data) <= 9_751 or data[:5] != b"ZTMA\x01":
        raise ValueError("manifest bound or version")
    count = data[150]
    if not 1 <= count <= 64 or len(data) != 215 + MANIFEST_RECORD_SIZE * count:
        raise ValueError("manifest count, truncation or trailing bytes")
    if int.from_bytes(data[37:45], "big") > int.from_bytes(data[45:53], "big"):
        raise ValueError("manifest validity")
    if any(int.from_bytes(data[start:start + 8], "big") > MAX_SIGNED_64
           for start in (21, 29, 37, 45)):
        raise ValueError("unrepresentable manifest integer")
    root_point = data[85:150]
    previous = None
    roots = 0
    seen_points = set()
    for index in range(count):
        record = data[151 + MANIFEST_RECORD_SIZE * index : 151 + MANIFEST_RECORD_SIZE * (index + 1)]
        role, record_id, point = record[0], record[1:33], record[33:98]
        pair = (role, record_id)
        if role not in range(1, 7) or (previous is not None and pair <= previous):
            raise ValueError("manifest role or order")
        if len(point) != 65 or point[0] != 4 or record_id != key_id(role, point):
            raise ValueError("manifest key encoding or ID")
        if point in seen_points:
            raise ValueError("public key reused across roles")
        seen_points.add(point)
        if int.from_bytes(record[132:140], "big") > int.from_bytes(record[140:148], "big"):
            raise ValueError("key validity")
        if any(int.from_bytes(record[start:start + 8], "big") > MAX_SIGNED_64
               for start in (132, 140)):
            raise ValueError("unrepresentable key validity")
        if record[148] not in (1, 2) or int.from_bytes(record[130:132], "big") & ~3:
            raise ValueError("state or reserved scope")
        roots += role == 6 and point == root_point
        previous = pair
    if roots != 1:
        raise ValueError("owner root record")
    return count


def dummy_wrap(role, seed):
    return bytes([role]) + bytes([seed]) * 32 + b"\x04" + ZERO * 64 + ZERO * 48


def dummy_envelope(kind, peer=b"+12", ct_len=17, roles=None):
    if roles is None:
        roles = (1, 2) if kind == 1 else (2,)
    protected = bytearray(144)
    if kind == 1:
        protected += u64(1) + b"\x01" + bytes([len(peer)]) + peer
    else:
        protected[16:32] = b"E" * 16
        protected += b"E" * 16 + u64(1) + bytes([len(peer)]) + peer
    return (b"ZTSE\x01" + bytes([kind]) + ZERO * 2 + u16(len(protected))
            + protected + ZERO * 12 + u32(ct_len) + ZERO * ct_len
            + bytes([len(roles)])
            + b"".join(dummy_wrap(role, index + 1) for index, role in enumerate(roles))
            + ZERO * 64)


def dummy_manifest(count=1):
    point = b"\x04" + b"R" * 64

    def record(role, public_point):
        return (bytes([role]) + key_id(role, public_point) + public_point
                + ZERO * 32 + u16(0) + u64(0) + u64(1) + b"\x01")

    readers = [record(3, b"\x04" + bytes([index]) * 64)
               for index in range(1, count)]
    readers.sort(key=lambda item: item[1:33])
    records = b"".join(readers) + record(6, point)
    return (b"ZTMA\x01" + ZERO * 16 + u64(0) + u64(1) + u64(0)
            + u64(1) + ZERO * 32 + point + bytes([count]) + records + ZERO * 64)


class DraftShapeTests(unittest.TestCase):
    def test_envelope_minima_and_maxima(self):
        for kind, minimum, maximum, roles in ((1, 557, 34_213, (1, 2, 3, 3, 3, 3, 3, 3)),
                                               (2, 426, 34_082, (2, 3, 3, 3, 3, 3, 3))):
            self.assertEqual(len(dummy_envelope(kind)), minimum)
            self.assertEqual(check_envelope_shape(dummy_envelope(kind)), kind)
            largest = dummy_envelope(kind, b"+" + b"1" * 15, 32_784, roles)
            self.assertEqual(len(largest), maximum)
            self.assertEqual(check_envelope_shape(largest), kind)

    def test_envelope_rejects_ambiguous_layout(self):
        sample = dummy_envelope(2)
        for bad in (sample[:-1], sample + ZERO, sample[:8] + u16(173) + sample[10:],
                    sample[:10 + 144] + b"X" + sample[10 + 145:]):
            with self.assertRaises(ValueError):
                check_envelope_shape(bad)
        self.assertEqual(check_envelope_shape(dummy_envelope(1)), 1)

    def test_manifest_exact_size_and_fields(self):
        sample = dummy_manifest()
        self.assertEqual(len(sample), 364)
        self.assertEqual(check_manifest_shape(sample), 1)
        for bad in (sample[:-1], sample + ZERO, sample[:150] + b"\x02" + sample[151:],
                    sample[:85] + b"X" + sample[86:]):
            with self.assertRaises(ValueError):
                check_manifest_shape(bad)
        largest = dummy_manifest(64)
        self.assertEqual(len(largest), 9_751)
        self.assertEqual(check_manifest_shape(largest), 64)
        with self.assertRaises(ValueError):
            check_manifest_shape(largest + ZERO)

    def test_cross_role_public_key_reuse_is_rejected(self):
        sample = dummy_manifest()
        root_record = sample[151:300]
        integration_alias = bytes([5]) + key_id(5, root_record[33:98]) + root_record[33:]
        aliased = sample[:150] + b"\x02" + integration_alias + root_record + sample[-64:]
        with self.assertRaisesRegex(ValueError, "reused across roles"):
            check_manifest_shape(aliased)

    def test_unsigned_overflow_and_outbound_expiry_are_rejected(self):
        outbound = dummy_envelope(1)
        inbound = dummy_envelope(2)
        manifest = dummy_manifest()
        for sample in (outbound[:146] + u64(1 << 63) + outbound[154:],
                       outbound[:74] + u64(1 << 63) + outbound[82:],
                       outbound[:154] + u64(1 << 63) + outbound[162:],
                       outbound[:154] + u64(900_002) + outbound[162:],
                       inbound[:170] + u64(0) + inbound[178:],
                       inbound[:170] + u64(1 << 63) + inbound[178:],
                       manifest[:45] + u64(1 << 63) + manifest[53:]):
            with self.assertRaises(ValueError):
                (check_manifest_shape if sample[:4] == b"ZTMA" else check_envelope_shape)(sample)


if __name__ == "__main__":
    unittest.main()
