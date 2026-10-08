"""The vendored-upstream exemption covers only PROVENANCE-matching content."""
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from . import privacy_guard as guard
except ImportError:
    import privacy_guard as guard

VENDORED = "android/app/src/main/cpp/wolfssl"
# Assembled at runtime so this test file never contains a scannable literal.
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
AMAZON_ID_PARTS = "AKIA" + "IOSFODNN7EXAMPLE"
HEADER_BYTES = f"/* upstream docs mention {PEM_HEADER} markers */\n".encode("utf-8")


class VendoredExemptionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="privacy-vendored-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "fixture@example.org")
        self._git("config", "user.name", "Fixture")
        header = self.root / VENDORED / "wolfssl" / "pem_example.h"
        header.parent.mkdir(parents=True)
        header.write_bytes(HEADER_BYTES)
        self.header_digest = hashlib.sha256(HEADER_BYTES).hexdigest()

    def _git(self, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(self.root), *args],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            self.fail("fixture git command failed")
        return result.stdout.decode()

    def _commit(self) -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "fixture")
        return self._git("rev-parse", "HEAD").strip()

    def _write_manifest(self):
        path = self.root / VENDORED / "PROVENANCE"
        path.write_bytes(f"Header.\n\n{self.header_digest}  wolfssl/pem_example.h\n".encode("utf-8"))

    def _findings(self) -> list[str]:
        errors = guard.scan_snapshot(self.root, self._commit(), {})
        return [error for error in errors if "commit-message" not in error]

    def test_manifest_matched_vendored_file_is_exempt(self):
        self._write_manifest()
        self.assertEqual(self._findings(), [])

    def test_exemption_holds_on_a_second_shared_cache_snapshot(self):
        # Range scans reuse one scan cache across commit trees; the manifest
        # and vendored blobs drop out of the pending-blob read on the second
        # tree and the exemption must survive that.
        self._write_manifest()
        cache: dict = {}
        first = guard.scan_snapshot(self.root, self._commit(), cache)
        self.assertEqual([error for error in first if "commit-message" not in error], [])
        (self.root / "README.md").write_bytes(b"first-party notes\n")
        second = guard.scan_snapshot(self.root, self._commit(), cache)
        self.assertEqual([error for error in second if "commit-message" not in error], [])

    def test_unlisted_vendored_file_is_fully_scanned(self):
        self._write_manifest()
        planted = self.root / VENDORED / "wolfcrypt" / "src" / "planted.c"
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_bytes(f"static const char *seed = \"{AMAZON_ID_PARTS}\";\n".encode("utf-8"))
        self.assertTrue(any("credential-shaped token" in error for error in self._findings()))

    def test_modified_vendored_file_is_fully_scanned(self):
        self._write_manifest()
        header = self.root / VENDORED / "wolfssl" / "pem_example.h"
        header.write_bytes(HEADER_BYTES + f"static const char *seed = \"{AMAZON_ID_PARTS}\";\n".encode("utf-8"))
        self.assertTrue(any("credential-shaped token" in error for error in self._findings()))

    def test_historical_smudged_manifest_digest_is_tolerated(self):
        # Pre-#1032 manifests recorded CRLF-smudged digests while the stored
        # blobs hold LF; those historical trees must stay exempt.
        self._write_manifest()
        header = self.root / VENDORED / "wolfssl" / "pem_example.h"
        crlf_digest = hashlib.sha256(HEADER_BYTES.replace(b"\n", b"\r\n")).hexdigest()
        path = self.root / VENDORED / "PROVENANCE"
        path.write_bytes(f"Header.\n\n{crlf_digest}  wolfssl/pem_example.h\n".encode("utf-8"))
        self.assertEqual(self._findings(), [])

    def test_absent_manifest_disables_the_exemption(self):
        self.assertTrue(any("private key" in error for error in self._findings()))


if __name__ == "__main__":
    unittest.main()
