import unittest

from write_image_receipt import image_receipt


class ImageReceiptTest(unittest.TestCase):
    def test_receipt_pins_release_to_digest(self):
        digest = "sha256:" + "a" * 64
        receipt = image_receipt("v0.1.0-rc.1", "b" * 40, digest, 123, 2)
        self.assertEqual(receipt["build_tag"], "v0.1.0-rc.1-run123-2")
        self.assertEqual(receipt["image_ref"], f"ghcr.io/pboachie/zrotext@{digest}")
        self.assertEqual(receipt["source_commit"], "b" * 40)

    def test_rejects_invalid_release_or_digest(self):
        with self.assertRaisesRegex(ValueError, "release tag"):
            image_receipt("main", "b" * 40, "sha256:" + "a" * 64, 123, 1)
        with self.assertRaisesRegex(ValueError, "Image digest"):
            image_receipt("v0.1.0-rc.1", "b" * 40, "sha256:bad", 123, 1)
        with self.assertRaisesRegex(ValueError, "Source commit"):
            image_receipt("v0.1.0-rc.1", "bad", "sha256:" + "a" * 64, 123, 1)


if __name__ == "__main__":
    unittest.main()
