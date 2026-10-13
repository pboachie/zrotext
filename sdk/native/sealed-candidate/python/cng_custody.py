"""Windows TPM-backed P-256 custody; no software-provider fallback or UI.

Provider observations are local platform evidence, not remote attestation or
rollback-resistant application state. Keys use fresh private namespace aliases.
"""
import ctypes
import os
import struct
import threading
import uuid
from weakref import WeakSet

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sealed_candidate import capture, point, require

PROVIDER = 'Microsoft Platform Crypto Provider'
PREFIX = 'zrotext-candidate-p256-'
SILENT = 0x40
HARDWARE = 1
NTE_PERM = 0x80090010
NTE_BAD_TYPE = 0x8009000a
_qualified = WeakSet()


class CngUnavailable(RuntimeError):
    def __init__(self, operation, status=None):
        self.operation, self.status = operation, status
        super().__init__(f'CNG unavailable: {operation}' + (f' ({status:08x})' if status is not None else ''))


class _Api:
    def __init__(self):
        if os.name != 'nt':
            raise CngUnavailable('Windows platform required')
        self.dll = ctypes.WinDLL('ncrypt.dll', winmode=0x800)
        H, P, U, W = ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p
        self.H, self.U = H, U
        signatures = {
            'NCryptOpenStorageProvider': [ctypes.POINTER(H), W, U],
            'NCryptIsAlgSupported': [H, W, U],
            'NCryptGetProperty': [H, W, P, U, ctypes.POINTER(U), U],
            'NCryptSetProperty': [H, W, P, U, U],
            'NCryptCreatePersistedKey': [H, ctypes.POINTER(H), W, W, U, U],
            'NCryptOpenKey': [H, ctypes.POINTER(H), W, U, U],
            'NCryptFinalizeKey': [H, U],
            'NCryptExportKey': [H, H, W, P, P, U, ctypes.POINTER(U), U],
            'NCryptImportKey': [H, H, W, P, ctypes.POINTER(H), P, U, U],
            'NCryptSecretAgreement': [H, H, ctypes.POINTER(H), U],
            'NCryptDeriveKey': [H, W, P, P, U, ctypes.POINTER(U), U],
            'NCryptDeleteKey': [H, U],
            'NCryptFreeObject': [H],
        }
        for name, args in signatures.items():
            fn = getattr(self.dll, name)
            fn.argtypes, fn.restype = args, U

    def call(self, name, *args):
        status = getattr(self.dll, name)(*args)
        if status:
            raise CngUnavailable(name, status)

    def property(self, handle, name):
        value, size = self.U(), self.U()
        self.call('NCryptGetProperty', handle, name, ctypes.byref(value), 4, ctypes.byref(size), SILENT)
        require(size.value == 4, 'CNG property width')
        return value.value

    def provider(self):
        handle = self.H()
        self.call('NCryptOpenStorageProvider', ctypes.byref(handle), PROVIDER, 0)
        try:
            if not self.property(handle, 'Impl Type') & HARDWARE:
                raise CngUnavailable('hardware implementation required')
            self.call('NCryptIsAlgSupported', handle, 'ECDH_P256', 0)
            return handle
        except BaseException:
            self.dll.NCryptFreeObject(handle)
            raise


def probe_platform():
    """Read-only provider capability probe; creates no key and changes no policy."""
    api = _Api()
    provider = api.provider()
    try:
        return {'provider': PROVIDER, 'hardware': True, 'ecdh_p256': True,
                'key_creation_tested': False, 'protected_reader_qualified': False}
    finally:
        api.dll.NCryptFreeObject(provider)


class HardwareRecipient:
    """A locally observed TPM provider key. Use create or open; no caller handles."""
    def __init__(self):
        raise TypeError('Use HardwareRecipient.create or HardwareRecipient.open')

    @classmethod
    def _start(cls):
        obj = object.__new__(cls)
        obj._api = _Api()
        obj._provider = obj._api.provider()
        obj._key = obj._api.H()
        obj._lock = threading.RLock()
        obj._closed = False
        return obj

    @classmethod
    def create(cls, record_pending_alias):
        """Record the fresh alias durably before creation, for crash recovery.

        The trusted callback must fsync its private receipt; caller aliases and
        overwrite flags are never accepted. Failure to record means no key created.
        """
        require(callable(record_pending_alias), 'durable pending-alias callback required')
        obj = cls._start()
        obj.name = PREFIX + str(uuid.uuid4())
        created = False
        try:
            record_pending_alias(obj.name)
            # No overwrite flag, machine-store flag, UI policy or provisioning.
            obj._api.call('NCryptCreatePersistedKey', obj._provider, ctypes.byref(obj._key),
                          'ECDH_P256', obj.name, 0, SILENT)
            created = True
            policy = obj._api.U(0)
            obj._api.call('NCryptSetProperty', obj._key, 'Export Policy', ctypes.byref(policy), 4, 0)
            obj._api.call('NCryptFinalizeKey', obj._key, SILENT)
            obj._qualify()
            _qualified.add(obj)
            return obj
        except BaseException:
            if created and obj._key.value:
                # Only the exact freshly created handle is eligible for cleanup.
                status = obj._api.dll.NCryptDeleteKey(obj._key, 0)
                if status == 0:
                    obj._key = obj._api.H()
                else:
                    obj.close()
                    raise CngUnavailable('owned key cleanup failed; use pending-alias receipt', status) from None
            obj.close()
            raise

    @classmethod
    def open(cls, name, independently_expected_public):
        require(type(name) is str and name.startswith(PREFIX), 'custody alias namespace')
        try:
            valid = str(uuid.UUID(name[len(PREFIX):])) == name[len(PREFIX):]
        except ValueError:
            valid = False
        require(valid, 'custody alias format')
        expected = capture(independently_expected_public, 65)
        point(expected)
        obj = cls._start()
        obj.name = name
        try:
            obj._api.call('NCryptOpenKey', obj._provider, ctypes.byref(obj._key), name, 0, SILENT)
            obj._qualify()
            require(obj.public_point() == expected, 'persistent custody public binding')
            _qualified.add(obj)
            return obj
        except BaseException:
            obj.close()
            raise

    def _qualify(self):
        if self._api.property(self._key, 'Export Policy') != 0:
            raise CngUnavailable('key export policy must deny export')
        # Some PCP versions return Length=0 for ECC; the exact public blob below
        # authoritatively fixes algorithm/curve/width and validates the point.
        self.observed_length_property = self._api.property(self._key, 'Length')
        size = self._api.U()
        status = self._api.dll.NCryptExportKey(self._key, 0, 'ECCPRIVATEBLOB', None,
                                              None, 0, ctypes.byref(size), SILENT)
        # PCP may reject the private blob type itself. Neither result alone is
        # proof: hardware provider, export policy, public shape and ECDH are also
        # required. This is local evidence, not remote key attestation.
        if status not in (NTE_PERM, NTE_BAD_TYPE):
            raise CngUnavailable('private export denial not observed', status)
        self.observed_private_export_status = status
        public = self.public_point()
        peer = ec.generate_private_key(ec.SECP256R1())
        peer_point = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        expected = bytearray(peer.exchange(ec.ECDH(), point(public)))
        actual = None
        try:
            actual = self._exchange(peer_point)
            require(actual == expected, 'native ECDH qualification')
        finally:
            expected[:] = bytes(len(expected))
            if actual is not None:
                actual[:] = bytes(len(actual))

    def public_point(self):
        with self._lock:
            require(not self._closed, 'closed custody')
            data, size = ctypes.create_string_buffer(72), self._api.U()
            self._api.call('NCryptExportKey', self._key, 0, 'ECCPUBLICBLOB', None,
                           data, 72, ctypes.byref(size), SILENT)
            require(size.value == 72 and struct.unpack('<II', data.raw[:8]) == (0x314b4345, 32), 'CNG ECDH public blob')
            public = b'\x04' + data.raw[8:72]
            point(public)
            return public

    def exchange(self, ephemeral):
        require_hardware(self)
        return self._exchange(ephemeral)

    def _exchange(self, ephemeral):
        ephemeral = capture(ephemeral, 65)
        point(ephemeral)
        with self._lock:
            require(not self._closed, 'closed hardware custody')
            peer, secret = self._api.H(), self._api.H()
            raw = ctypes.create_string_buffer(32)
            size = self._api.U()
            blob = ctypes.create_string_buffer(struct.pack('<II', 0x314b4345, 32) + ephemeral[1:])
            try:
                self._api.call('NCryptImportKey', self._provider, 0, 'ECCPUBLICBLOB', None,
                               ctypes.byref(peer), blob, 72, SILENT)
                self._api.call('NCryptSecretAgreement', self._key, peer, ctypes.byref(secret), SILENT)
                self._api.call('NCryptDeriveKey', secret, 'TRUNCATE', None, raw, 32, ctypes.byref(size), 0)
                require(size.value == 32, 'CNG shared secret width')
                # NCrypt raw secret is little endian; RFC9180 DH uses big endian.
                return bytearray(raw.raw[::-1])
            finally:
                ctypes.memset(raw, 0, 32)
                if secret.value:
                    self._api.dll.NCryptFreeObject(secret)
                if peer.value:
                    self._api.dll.NCryptFreeObject(peer)

    def close(self):
        with self._lock:
            if not self._closed:
                _qualified.discard(self)
                if self._key.value:
                    self._api.dll.NCryptFreeObject(self._key)
                if self._provider.value:
                    self._api.dll.NCryptFreeObject(self._provider)
                self._closed = True

    def delete(self):
        """Explicitly delete this exact opened/created key, never enumerate aliases."""
        with self._lock:
            require(self in _qualified and not self._closed, 'qualified custody required')
            # PCP rejects SILENT on deletion on some hosts. These keys were
            # created without any UI policy; no provisioning or UI fallback.
            self._api.call('NCryptDeleteKey', self._key, 0)
            self._key = self._api.H()
            self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def require_hardware(provider):
    require(type(provider) is HardwareRecipient and provider in _qualified and not provider._closed,
            'qualified hardware provider required')
    return provider


if __name__ == '__main__':
    import json
    try:
        print(json.dumps(probe_platform()))
    except CngUnavailable as error:
        print(json.dumps({'protected_reader_qualified': False, 'operation': error.operation,
                          'status': None if error.status is None else f'{error.status:08x}'}))
