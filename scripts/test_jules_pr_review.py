"""Offline checks for Jules workflow routing and trust boundaries."""

import unittest

import jules_pr_review as review


SHA = "a" * 40


def pull_request(*, draft=False, owner="pboachie", head_repo=review.REPO):
    return {
        "number": 74, "state": "open", "draft": draft,
        "user": {"login": owner},
        "base": {"ref": "main"},
        "head": {"sha": SHA, "ref": "codex/owner-ui",
                 "repo": {"full_name": head_repo}},
    }


class ReviewRoutingTests(unittest.TestCase):
    def test_only_exact_owner_comment_commands_route(self):
        event = {
            "issue": {"number": 74, "pull_request": {"url": "https://example.test"}},
            "comment": {"id": 7, "user": {"login": "pboachie"},
                        "body": "/jules review"},
        }
        self.assertEqual(review.event_request("issue_comment", event),
                         (74, "review", "comment-7"))
        event["comment"]["body"] = "/jules address\nPlease check the latest comments"
        self.assertEqual(review.event_request("issue_comment", event),
                         (74, "address", "comment-7"))
        event["comment"]["user"]["login"] = "contributor"
        self.assertIsNone(review.event_request("issue_comment", event))
        event["comment"]["user"]["login"] = "pboachie"
        event["comment"]["body"] = "/jules review everything"
        self.assertIsNone(review.event_request("issue_comment", event))

    def test_automatic_review_only_when_owner_pr_ready(self):
        event = {"action": "ready_for_review", "pull_request": pull_request()}
        self.assertEqual(review.event_request("pull_request_target", event),
                         (74, "review", f"ready-74-{SHA}"))
        event["pull_request"]["draft"] = True
        self.assertIsNone(review.event_request("pull_request_target", event))

    def test_only_open_owner_branches_in_this_repo_are_eligible(self):
        self.assertTrue(review.eligible_pr(pull_request()))
        self.assertFalse(review.eligible_pr(pull_request(owner="contributor")))
        self.assertFalse(review.eligible_pr(pull_request(head_repo="contributor/zrotext")))
        pr = pull_request()
        pr["state"] = "closed"
        self.assertFalse(review.eligible_pr(pr))

    def test_control_markers_must_be_authored_by_actions(self):
        self.assertTrue(review.from_actions({"user": {"login": "github-actions[bot]"}}))
        self.assertFalse(review.from_actions({"user": {"login": "contributor"}}))
        self.assertIsNotNone(review.START.search(
            f"<!-- zrotext-jules-start:v1 session=sessions/123 head={SHA} "
            "mode=review trigger=comment-7 -->"))

    def test_session_links_restricted_to_jules(self):
        self.assertEqual(review.safe_session_url({"url": "https://jules.google.com/session/123"}),
                         "https://jules.google.com/session/123")
        self.assertEqual(review.safe_session_url({"url": "https://jules.google.com.evil.test/"}), "")


if __name__ == "__main__":
    unittest.main()
