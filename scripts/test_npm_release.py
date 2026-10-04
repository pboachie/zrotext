import copy
import unittest
import urllib.error
from unittest import mock

from npm_release import (ReleaseError, CHECKS, OWNER_ID, context, registry, dependency_review,
                         validate_approval, validate_checks, validate_environment,
                         validate_metadata, validate_receipt, validate_registry)
from npm_handoff import handoff
from test_release_handoff import FakeGitHub


ENV = {"GITHUB_REPOSITORY": "pboachie/zrotext", "GITHUB_REF_TYPE": "tag",
       "GITHUB_REF_NAME": "v1.2.3-rc.1", "GITHUB_SHA": "a" * 40,
       "GITHUB_EVENT_NAME": "release", "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1"}


class NpmReleaseTests(unittest.TestCase):
    def metadata(self):
        return ({"name": "zrotext", "version": "1.2.3-rc.1", "private": False, "license": "AGPL-3.0-only",
                 "publishConfig": {"access": "public", "registry": "https://registry.npmjs.org/", "provenance": True}},
                {"name": "zrotext", "version": "1.2.3-rc.1", "packages": {
                    "": {"name": "zrotext", "version": "1.2.3-rc.1"}}})

    def test_exact_preview_manifest_lock_and_changelog_required(self):
        p, lock = self.metadata()
        self.assertEqual(validate_metadata(p, lock, "## 1.2.3-rc.1\n", "v1.2.3-rc.1"), p["version"])
        for field, value in (("name", "@zrotext/sdk"), ("version", "0.0.0-development"), ("private", True),
                             ("license", "MIT"), ("dependencies", {"some-module": "1"})):
            with self.subTest(field=field), self.assertRaises(ReleaseError):
                validate_metadata({**p, field: value}, lock, "## 1.2.3-rc.1\n", "v1.2.3-rc.1")
        for broken in ({**lock, "version": "1.2.3"}, {**lock, "packages": {}}):
            with self.assertRaises(ReleaseError):
                validate_metadata(p, broken, "## 1.2.3-rc.1\n", "v1.2.3-rc.1")
        with self.assertRaises(ReleaseError):
            validate_metadata(p, lock, "## Unreleased\n", "v1.2.3-rc.1")
        with self.assertRaises(ReleaseError):
            validate_metadata(p, lock, "## 1.2.3\n", "v1.2.3")

    def test_registry_error_is_never_absence(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status), self.assertRaises(ReleaseError):
                registry(mock.Mock(side_effect=urllib.error.HTTPError("registry", status, "failed", {}, None)))
        self.assertIsNone(registry(mock.Mock(side_effect=urllib.error.HTTPError("registry", 404, "absent", {}, None))))
        with self.assertRaises(ReleaseError):
            registry(mock.Mock(side_effect=urllib.error.URLError("offline")))

    def test_registry_requires_owner_bootstrap_new_version_and_monotonic_channel(self):
        with self.assertRaises(ReleaseError):
            validate_registry(None, "1.2.3-rc.1")
        current = {"maintainers": [{"name": "elysra"}], "versions": {"1.2.2": {}}}
        validate_registry(current, "1.2.3-rc.1")
        for bad in ({**current, "maintainers": [{"name": "pboachie"}]},
                    {**current, "versions": {"1.2.3-rc.1": {}}},
                    {**current, "versions": {"1.2.3-rc.2": {}}},
                    {**current, "versions": {"1.2.3": {}}},
                    {**current, "dist-tags": {"next": "missing"}}):
            with self.assertRaises(ReleaseError):
                validate_registry(bad, "1.2.3-rc.1")

    def test_environment_cannot_be_missing_unprotected_or_have_an_alternate_reviewer(self):
        reviewer = {"type": "User", "reviewer": {"login": "pboachie", "id": OWNER_ID}}
        env = {"id": 8, "name": "npm-publication", "protection_rules": [{"type": "required_reviewers",
               "prevent_self_review": False, "reviewers": [reviewer]}],
               "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        policy = [{"type": "tag", "name": "v*-rc.*"}]
        self.assertEqual(validate_environment(env, policy), 8)
        for bad in ({}, {**env, "protection_rules": []}, {**env, "deployment_branch_policy": None}):
            with self.assertRaises(ReleaseError):
                validate_environment(bad, policy)
        changed = copy.deepcopy(env)
        changed["protection_rules"][0]["reviewers"].append(reviewer)
        with self.assertRaises(ReleaseError):
            validate_environment(changed, policy)
        changed = copy.deepcopy(env)
        changed["protection_rules"][0]["prevent_self_review"] = True
        with self.assertRaises(ReleaseError):
            validate_environment(changed, policy)
        for policy in ([{"type": "branch", "name": "v*-rc.*"}], [{"type": "tag", "name": "*"}], []):
            with self.assertRaises(ReleaseError):
                validate_environment(env, policy)

    def test_all_exact_source_checks_must_have_passed(self):
        checks = [{"name": name, "head_sha": "a" * 40, "status": "completed", "conclusion": "success",
                   "app": {"slug": "github-actions"}} for name in CHECKS]
        validate_checks([{"check_runs": checks}], "a" * 40)
        for field, value in (("conclusion", "failure"), ("conclusion", "skipped"), ("status", "queued"),
                             ("head_sha", "b" * 40), ("app", {"slug": "another-app"})):
            changed = copy.deepcopy(checks)
            changed[0][field] = value
            with self.assertRaises(ReleaseError):
                validate_checks([{"check_runs": changed}], "a" * 40)

    def test_only_fresh_exact_tag_events_can_publish(self):
        self.assertEqual(context(ENV)[0], "v1.2.3-rc.1")
        self.assertEqual(context({**ENV, "GITHUB_EVENT_NAME": "workflow_dispatch"})[0], "v1.2.3-rc.1")
        for field, value in (("GITHUB_REPOSITORY", "someone/zrotext"), ("GITHUB_REF_TYPE", "branch"),
                             ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "pull_request"),
                             ("GITHUB_REF_NAME", "v1.2.3"), ("GITHUB_SHA", "short")):
            with self.assertRaises(ReleaseError):
                context({**ENV, field: value})

    def test_actual_run_approval_must_come_from_verified_owner(self):
        review = {"state": "approved", "user": {"login": "pboachie", "id": OWNER_ID},
                  "environments": [{"id": 8, "name": "npm-publication"}]}
        validate_approval([review], 8)
        for history in ([], [{**review, "state": "rejected"}],
                        [{**review, "user": {"login": "pboachie", "id": 1}}],
                        [{**review, "environments": [{"id": 9, "name": "npm-publication"}]}]):
            with self.assertRaises(ReleaseError):
                validate_approval(history, 8)

    def test_dependency_review_uses_the_merged_pr_head_not_main(self):
        pr = {"merged_at": "present", "merge_commit_sha": "a" * 40,
              "base": {"ref": "main"}, "head": {"sha": "b" * 40}}
        check = {"name": "dependency-review", "head_sha": "b" * 40,
                 "status": "completed", "conclusion": "success", "app": {"slug": "github-actions"}}
        api = mock.Mock(side_effect=[[pr], [{"check_runs": [check]}]])
        # Paginated/slurped PR responses are a list of pages.
        api.side_effect = [[[pr]], [{"check_runs": [check]}]]
        dependency_review("a" * 40, api)
        self.assertIn("b" * 40, api.call_args_list[1].args[0])
        for prs, result in (([], check), ([pr, pr], check),
                            ([pr], {**check, "conclusion": "failure"}),
                            ([pr], {**check, "head_sha": "a" * 40})):
            api = mock.Mock(side_effect=[[prs], [{"check_runs": [result]}]])
            with self.assertRaises(ReleaseError):
                dependency_review("a" * 40, api)

    def test_receipt_rejects_changed_bytes_source_run_or_environment(self):
        info = {"filename": "zrotext-1.2.3-rc.1.tgz", "sha256": "c" * 64,
                "integrity": "sha512-synthetic", "files": ["package.json"]}
        receipt = {"schema_version": 1, "name": "zrotext", "version": "1.2.3-rc.1",
                   "tag": ENV["GITHUB_REF_NAME"], "source_commit": ENV["GITHUB_SHA"],
                   "run_id": 100, "run_attempt": 1, "environment_id": 8, **info,
                   "build_lock_sha256": "d" * 64, "public_manifest_sha256": "e" * 64,
                   "public_lock_sha256": "f" * 64}
        validate_receipt(receipt, info, ENV)
        for field, value in (("sha256", "d" * 64), ("files", []), ("source_commit", "b" * 40),
                             ("run_id", 101), ("environment_id", 0), ("build_lock_sha256", "invalid"),
                             ("unexpected", True)):
            with self.subTest(field=field), self.assertRaises(ReleaseError):
                validate_receipt({**receipt, field: value}, info, ENV)


class NpmHandoffTests(unittest.TestCase):
    def receipt(self):
        return {"name": "zrotext", "tag": ENV["GITHUB_REF_NAME"], "version": "1.2.3-rc.1",
                "source_commit": ENV["GITHUB_SHA"], "run_id": 100, "run_attempt": 1, "sha256": "b" * 64}

    def test_delivery_reuses_checklist_and_deduplicates_exact_artifact(self):
        api = FakeGitHub()
        self.assertTrue(handoff(self.receipt(), api, ENV)["notified"])
        self.assertFalse(handoff(self.receipt(), api, ENV)["notified"])
        self.assertIn("assignees[]=pboachie", api.writes[0])
        self.assertIn("npm-publication", api.issues[0]["body"])
        self.assertTrue(handoff({**self.receipt(), "sha256": "c" * 64}, api, ENV)["notified"])
        self.assertEqual(len(api.issues), 1)

    def test_lost_response_and_rejected_delivery_are_recoverable(self):
        from release_handoff import HandoffError
        api = FakeGitHub()
        api.fail_after_write = True
        with self.assertRaises(HandoffError):
            handoff(self.receipt(), api, ENV)
        self.assertFalse(handoff(self.receipt(), api, ENV)["notified"])
        api = FakeGitHub()
        api.fail_before_write = True
        with self.assertRaises(HandoffError):
            handoff(self.receipt(), api, ENV)
        self.assertTrue(handoff(self.receipt(), api, ENV)["notified"])

    def test_unsafe_or_wrong_run_receipt_never_writes(self):
        api = FakeGitHub()
        for field, value in (("version", "unsafe text"), ("name", "another-package"),
                             ("sha256", "unsafe text"), ("run_id", 101)):
            with self.assertRaises(ReleaseError):
                handoff({**self.receipt(), field: value}, api, ENV)
        self.assertFalse(api.writes)
