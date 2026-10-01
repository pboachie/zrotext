"""Keep the locked HPKE browser fallback explicit and fail closed without WebCrypto."""
import subprocess
import unittest
from pathlib import Path


class BrowserPackageTest(unittest.TestCase):
    def test_only_known_locked_node_fallbacks_are_removed(self):
        root = Path(__file__).resolve().parents[1]
        source = r'''
import {browserModule} from "./scripts/package_conversation_browser.mjs";
import assert from "node:assert/strict";
const fallback = 'if (globalThis.crypto) return globalThis.crypto; await import("crypto");';
const changed = browserModule("vendor/common/src/algorithm.js", fallback);
assert.ok(changed.startsWith('if (globalThis.crypto) return globalThis.crypto;'));
assert.ok(!changed.includes('import("crypto")'));
assert.ok(changed.includes('Promise.reject(new Error("Browser WebCrypto required"))'));
assert.equal(browserModule("vendor/other.js", fallback), fallback);
assert.throws(() => browserModule("vendor/common/src/algorithm.js", "export const fixture = true;"), /shape changed/);
assert.throws(() => browserModule("vendor/common/src/utils/misc.js", fallback), /shape changed/);
assert.ok(!browserModule("vendor/common/src/utils/misc.js", fallback + fallback).includes('import("crypto")'));
'''
        subprocess.run(["node", "--input-type=module", "-e", source], cwd=root, check=True)


if __name__ == "__main__":
    unittest.main()
