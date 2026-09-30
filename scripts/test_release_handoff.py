import unittest

from release_handoff import HandoffError, handoff, marker, delivery_marker


class FakeGitHub:
    def __init__(self):
        self.issues = []
        self.comments = []
        self.writes = []
        self.merged = True
        self.fail_after_write = False
        self.fail_before_write = False

    def __call__(self, *args):
        path = next(a for a in args if a.startswith("repos/"))
        post = "POST" in args
        if not post:
            if "/pulls/" in path:
                return {"merged_at": "present" if self.merged else None}
            return [self.comments if "/comments" in path else self.issues]
        if self.fail_before_write:
            self.fail_before_write = False
            raise HandoffError("request rejected")
        self.writes.append(args)
        fields = dict(a.split("=", 1) for a in args if "=" in a)
        if "/comments" in path:
            result = {"body": fields["body"], "user": {"login": "github-actions[bot]"}}
            self.comments.append(result)
        else:
            result = {"number": len(self.issues) + 1, "body": fields["body"], "state": "open",
                      "assignees": [{"login": "pboachie"}],
                      "user": {"login": "github-actions[bot]"}}
            self.issues.append(result)
        if self.fail_after_write:
            self.fail_after_write = False
            raise HandoffError("response lost")
        return result


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()

    def run_gate(self, gate="release-candidate", **kwargs):
        return handoff("v1.2.3-rc.1", gate, [123], True, self.api, **kwargs)

    def test_initial_assignment_and_repeat_are_silent(self):
        self.assertTrue(self.run_gate()["notified"])
        self.assertFalse(self.run_gate()["notified"])
        self.assertEqual(len(self.api.writes), 1)
        self.assertIn("assignees[]=pboachie", self.api.writes[0])
        self.assertIn("@pboachie", self.api.issues[0]["body"])

    def test_new_gate_notifies_once_on_same_issue(self):
        self.run_gate()
        self.assertEqual(self.run_gate("device-cycle"), {"issue": 1, "notified": True})
        self.assertFalse(self.run_gate("device-cycle")["notified"])
        self.assertEqual(len(self.api.issues), 1)
        self.assertEqual(len(self.api.comments), 1)

    def test_lost_create_response_does_not_repeat(self):
        self.api.fail_after_write = True
        with self.assertRaises(HandoffError):
            self.run_gate()
        self.assertFalse(self.run_gate()["notified"])
        self.assertEqual(len(self.api.writes), 1)

    def test_failed_delivery_can_retry(self):
        self.api.fail_before_write = True
        with self.assertRaises(HandoffError):
            self.run_gate()
        self.assertTrue(self.run_gate()["notified"])
        self.assertEqual(len(self.api.writes), 1)

    def test_lost_comment_response_does_not_repeat(self):
        self.run_gate()
        self.api.fail_after_write = True
        with self.assertRaises(HandoffError):
            self.run_gate("device-cycle")
        self.assertFalse(self.run_gate("device-cycle")["notified"])
        self.assertEqual(len(self.api.comments), 1)

    def test_premature_request_cannot_write(self):
        with self.assertRaises(HandoffError):
            handoff("v1.2.3", "device-cycle", [123], False, self.api)
        self.api.merged = False
        with self.assertRaises(HandoffError):
            self.run_gate()
        self.assertEqual(self.api.writes, [])

    def test_free_form_or_private_inputs_cannot_write(self):
        for release, gate, prs in [("private/path", "device-cycle", [123]),
                                    ("v1.2.3\n@someone", "device-cycle", [123]),
                                    ("v1.2.3", "private details", [123]),
                                    ("v1.2.3", "device-cycle", ["private-link"]),
                                    ("v1.2.3", "device-cycle", [])]:
            with self.assertRaises(HandoffError):
                handoff(release, gate, prs, True, self.api)
        self.assertEqual(self.api.writes, [])

    def test_closed_or_reassigned_checklist_is_preserved(self):
        self.run_gate()
        issue = self.api.issues[0]
        issue["state"] = "closed"
        with self.assertRaises(HandoffError):
            self.run_gate("device-cycle")
        issue["state"] = "open"
        issue["assignees"] = []
        with self.assertRaises(HandoffError):
            self.run_gate("device-cycle")
        self.assertEqual(len(self.api.writes), 1)

    def test_spoofed_marker_does_not_suppress_delivery(self):
        self.run_gate()
        self.api.comments.append({"body": delivery_marker("device-cycle"),
                                  "user": {"login": "untrusted-contributor"}})
        self.assertTrue(self.run_gate("device-cycle")["notified"])

    def test_multiple_trusted_checklists_fail_closed(self):
        self.run_gate()
        self.api.issues.append(dict(self.api.issues[0]))
        with self.assertRaises(HandoffError):
            self.run_gate()
        self.assertEqual(len(self.api.writes), 1)

    def test_unrelated_markers_do_not_block_initial_handoff(self):
        for count in (1, 2):
            with self.subTest(count=count):
                self.api = FakeGitHub()
                self.api.issues = [{"body": marker("v1.2.3-rc.1"),
                                    "user": {"login": "untrusted-contributor"}} for _ in range(count)]
                self.assertTrue(self.run_gate()["notified"])
                self.assertFalse(self.run_gate()["notified"])
                self.assertEqual(len(self.api.writes), 1)

    def test_unrelated_markers_do_not_block_existing_checklist(self):
        self.run_gate()
        self.api.issues.extend([{"body": marker("v1.2.3-rc.1"),
                                 "user": {"login": "untrusted-contributor"}}] * 2)
        self.assertEqual(self.run_gate("device-cycle"), {"issue": 1, "notified": True})
        self.assertFalse(self.run_gate("device-cycle")["notified"])
        self.assertEqual(len(self.api.comments), 1)


if __name__ == "__main__":
    unittest.main()
