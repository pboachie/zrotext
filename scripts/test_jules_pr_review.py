"""Offline checks for Jules workflow routing and trust boundaries."""

import unittest
from unittest.mock import patch

import jules_pr_review as review


SHA = "a" * 40
BASE_SHA = "b" * 40


def pull_request(*, draft=False, owner="pboachie", head_repo=review.REPO,
                 base_repo=review.REPO, base_ref="main", base_sha=BASE_SHA):
    return {
        "number": 74, "state": "open", "draft": draft,
        "user": {"login": owner},
        "base": {"ref": base_ref, "sha": base_sha,
                 "repo": {"full_name": base_repo}},
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

    def test_automatic_event_review_only_for_owner_prs(self):
        event = {"action": "ready_for_review", "pull_request": pull_request()}
        self.assertEqual(review.event_request("pull_request_target", event),
                         (74, "review", f"ready-74-{SHA}"))
        event["pull_request"]["user"]["login"] = "dependabot[bot]"
        self.assertIsNone(review.event_request("pull_request_target", event))
        event["pull_request"]["user"]["login"] = "contributor"
        self.assertIsNone(review.event_request("pull_request_target", event))
        event["pull_request"]["user"]["login"] = "pboachie"
        event["pull_request"]["draft"] = True
        self.assertIsNone(review.event_request("pull_request_target", event))

    def test_trusted_human_review_starts_advisory_address_session(self):
        event = {
            "action": "submitted", "pull_request": pull_request(),
            "review": {"id": 91, "state": "CHANGES_REQUESTED",
                       "author_association": "COLLABORATOR",
                       "user": {"login": "reviewer"}},
        }
        self.assertEqual(review.event_request("pull_request_review", event),
                         (74, "address", "review-91"))
        event["review"]["author_association"] = "NONE"
        self.assertIsNone(review.event_request("pull_request_review", event))
        event["review"]["author_association"] = "MEMBER"
        event["review"]["user"]["login"] = "github-actions[bot]"
        self.assertIsNone(review.event_request("pull_request_review", event))
        event["review"]["user"]["login"] = "reviewer"
        event["review"]["state"] = "APPROVED"
        self.assertIsNone(review.event_request("pull_request_review", event))

    def test_only_open_owner_branches_in_this_repo_are_eligible(self):
        self.assertTrue(review.eligible_pr(pull_request()))
        self.assertTrue(review.eligible_pr(pull_request(base_ref="codex/m2-parent")))
        self.assertTrue(review.eligible_pr(pull_request(owner="dependabot[bot]")))
        self.assertFalse(review.eligible_pr(pull_request(owner="contributor")))
        self.assertFalse(review.eligible_pr(pull_request(head_repo="contributor/zrotext")))
        self.assertFalse(review.eligible_pr(pull_request(base_repo="contributor/zrotext")))
        self.assertFalse(review.eligible_pr(pull_request(base_sha="not-a-commit")))
        pr = pull_request()
        pr["state"] = "closed"
        self.assertFalse(review.eligible_pr(pr))

    def test_stacked_review_uses_exact_base_commit(self):
        prompt = review.prompt_for(pull_request(base_ref="codex/m2-parent"), "review")
        self.assertIn(f"base branch codex/m2-parent at expected commit {BASE_SHA}", prompt)
        self.assertIn("only this PR's diff against its stated base commit", prompt)

    def test_stacked_review_starts_with_pinned_base_marker(self):
        posted = []

        def fake_request(url, **kwargs):
            if url == f"{review.GITHUB}/pulls/74":
                return pull_request(base_ref="codex/m2-parent")
            if url == f"{review.JULES}/sessions":
                self.assertIn(f"expected commit {BASE_SHA}", kwargs["payload"]["prompt"])
                return {"name": "sessions/789"}
            if url == f"{review.GITHUB}/issues/74/comments":
                posted.append(kwargs["payload"])
                return {}
            raise AssertionError(url)

        with patch.object(review, "pages", return_value=[]), \
             patch.object(review, "request_json", side_effect=fake_request):
            review.start_review(74, "review", "dispatch-1", "github-test", "jules-test")

        self.assertEqual(len(posted), 1)
        self.assertIn(f"head={SHA} base={BASE_SHA} mode=review", posted[0]["body"])

    def test_schedule_starts_one_missing_review_and_skips_existing_head(self):
        ready = pull_request(owner="dependabot[bot]")
        ready["number"] = 75
        already_reviewed = pull_request()
        existing = {"user": {"login": "github-actions[bot]"},
                    "body": (f"<!-- zrotext-jules-start:v1 session=sessions/123 head={SHA} "
                             "mode=review trigger=dispatch-1 -->")}
        started = []

        def fake_pages(path, _token):
            return {
                "/pulls?state=open": [ready, already_reviewed],
                "/issues/74/comments": [existing],
                "/issues/75/comments": [],
            }[path]

        with patch.object(review, "pages", side_effect=fake_pages), \
             patch.object(review, "start_review", side_effect=lambda *args: started.append(args)):
            review.start_missing_reviews("github-test", "jules-test")

        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][:2], (75, "review"))

    def test_control_markers_must_be_authored_by_actions(self):
        self.assertTrue(review.from_actions({"user": {"login": "github-actions[bot]"}}))
        self.assertFalse(review.from_actions({"user": {"login": "contributor"}}))
        self.assertIsNotNone(review.START.search(
            f"<!-- zrotext-jules-start:v1 session=sessions/123 head={SHA} "
            "mode=review trigger=comment-7 -->"))
        marker = review.START.search(
            f"<!-- zrotext-jules-start:v1 session=sessions/123 head={SHA} "
            f"base={BASE_SHA} mode=review trigger=comment-7 -->")
        self.assertEqual(marker.group(3), BASE_SHA)

    def test_session_links_restricted_to_jules(self):
        self.assertEqual(review.safe_session_url({"url": "https://jules.google.com/session/123"}),
                         "https://jules.google.com/session/123")
        self.assertEqual(review.safe_session_url({"url": "https://jules.google.com.evil.test/"}), "")

    def test_completed_review_posts_on_exact_commit_with_null_existing_body(self):
        posted = []
        start = {"user": {"login": "github-actions[bot]"},
                 "body": (f"<!-- zrotext-jules-start:v1 session=sessions/123 head={SHA} "
                          "mode=review trigger=comment-7 -->")}

        def fake_pages(path, _token):
            return {
                "/pulls?state=open": [{"number": 74}],
                "/issues/74/comments": [start],
                "/pulls/74/reviews": [{"user": {"login": "pboachie"}, "body": None}],
            }[path]

        def fake_request(url, **kwargs):
            if url == f"{review.JULES}/sessions/123":
                return {"state": "COMPLETED", "url": "https://jules.google.com/session/123"}
            if url == f"{review.GITHUB}/pulls/74" and kwargs.get("method", "GET") == "GET":
                return pull_request()
            if url.startswith(f"{review.JULES}/sessions/123/activities?"):
                return {"activities": [{"agentMessaged": {"agentMessage": "No findings."}}]}
            if url == f"{review.GITHUB}/pulls/74/reviews" and kwargs["method"] == "POST":
                posted.append(kwargs["payload"])
                return {}
            raise AssertionError(url)

        with patch.object(review, "pages", side_effect=fake_pages), \
             patch.object(review, "request_json", side_effect=fake_request):
            review.poll_reviews("github-test", "jules-test")

        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0]["event"], "COMMENT")
        self.assertEqual(posted[0]["commit_id"], SHA)
        self.assertIn("No findings.", posted[0]["body"])

    def test_changed_parent_commit_makes_stacked_result_stale(self):
        posted = []
        start = {"user": {"login": "github-actions[bot]"},
                 "body": (f"<!-- zrotext-jules-start:v1 session=sessions/456 head={SHA} "
                          f"base={BASE_SHA} mode=review trigger=dispatch-1 -->")}

        def fake_pages(path, _token):
            return {
                "/pulls?state=open": [{"number": 74}],
                "/issues/74/comments": [start],
                "/pulls/74/reviews": [],
            }[path]

        def fake_request(url, **kwargs):
            if url == f"{review.JULES}/sessions/456":
                return {"state": "COMPLETED"}
            if url == f"{review.GITHUB}/pulls/74" and kwargs.get("method", "GET") == "GET":
                return pull_request(base_sha="c" * 40)
            if url == f"{review.GITHUB}/issues/74/comments" and kwargs["method"] == "POST":
                posted.append(kwargs["payload"])
                return {}
            raise AssertionError(url)

        with patch.object(review, "pages", side_effect=fake_pages), \
             patch.object(review, "request_json", side_effect=fake_request):
            review.poll_reviews("github-test", "jules-test")

        self.assertEqual(len(posted), 1)
        self.assertIn("This result is stale", posted[0]["body"])


if __name__ == "__main__":
    unittest.main()
