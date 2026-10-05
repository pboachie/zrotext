"""The CI change filter skips a suite only for paths that cannot affect it."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_changes  # noqa: E402


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=CI Test", "-c", "user.email=ci@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout


class SuitesTest(unittest.TestCase):
    def test_documentation_only_skips_both_suites(self):
        self.assertEqual(
            ci_changes.suites(["docs/SELF-HOSTING.md", "README.md", "crates/server/NOTES.md",
                               "LICENSE", ".github/PULL_REQUEST_TEMPLATE.md"]),
            {"rust": False, "android": False},
        )

    def test_quickstart_examples_read_by_rust_run_rust_only(self):
        self.assertEqual(
            ci_changes.suites(["docs/AGENT-QUICKSTART.md"]),
            {"rust": True, "android": False},
        )

    def test_android_only_skips_rust(self):
        self.assertEqual(
            ci_changes.suites(["android/app/src/main/java/A.kt", "docs/ANDROID.md"]),
            {"rust": False, "android": True},
        )

    def test_server_only_skips_android(self):
        for path in ("crates/server/src/main.rs", "web/owner/devices.js",
                     "deploy/compose/migrations/001_foundation.sql"):
            with self.subTest(path=path):
                self.assertEqual(ci_changes.suites([path]), {"rust": True, "android": False})

    def test_native_owner_inputs_run_android_and_rust(self):
        for path in ("crates/android-owner-custody/src/typed.rs",
                     "crates/root-material/src/root_backup.rs", "Cargo.toml", "Cargo.lock",
                     "rust-toolchain.toml"):
            with self.subTest(path=path):
                self.assertEqual(ci_changes.suites([path]), {"rust": True, "android": True})

    def test_shared_inputs_run_both_suites(self):
        for path in ("protocol/v1/vectors/root-backup-01.json",
                     "sdk/typescript/test/vectors/a.json",
                     ".github/workflows/ci.yml", "scripts/ci_changes.py", ".env.example",
                     "_typos.toml", ".gitattributes"):
            with self.subTest(path=path):
                self.assertEqual(ci_changes.suites([path]), {"rust": True, "android": True})

    def test_one_relevant_path_among_documentation_runs_the_suite(self):
        self.assertEqual(
            ci_changes.suites(["docs/A.md", "crates/domain/src/lib.rs"]),
            {"rust": True, "android": False},
        )

    def test_an_empty_change_runs_every_suite(self):
        self.assertEqual(ci_changes.suites([]), {"rust": True, "android": True})


class MainTest(unittest.TestCase):
    def run_main(self, event: str | None) -> str:
        env = {k: v for k, v in os.environ.items() if k != "CI_EVENT_NAME"}
        if event is not None:
            env["CI_EVENT_NAME"] = event
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("sys.stdout.write") as write, mock.patch("sys.stderr"):
            self.assertEqual(ci_changes.main(), 0)
        return "".join(call.args[0] for call in write.call_args_list)

    def test_push_runs_every_suite_without_reading_git(self):
        with mock.patch.object(ci_changes, "pull_request_paths") as paths:
            self.assertEqual(self.run_main("push"), "rust=true\nandroid=true\n")
        paths.assert_not_called()

    def test_pull_request_uses_the_filter(self):
        with mock.patch.object(ci_changes, "pull_request_paths", return_value=["docs/A.md"]):
            self.assertEqual(self.run_main("pull_request"), "rust=false\nandroid=false\n")

    def test_unreadable_change_runs_every_suite(self):
        with mock.patch.object(ci_changes, "pull_request_paths",
                               side_effect=ValueError("HEAD is not a pull request merge commit")):
            self.assertEqual(self.run_main("pull_request"), "rust=true\nandroid=true\n")


class PullRequestPathsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / "base.txt").write_text("base\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "base")

    def tearDown(self):
        self.temp.cleanup()

    def paths(self) -> list[str]:
        cwd = os.getcwd()
        os.chdir(self.repo)
        try:
            return ci_changes.pull_request_paths()
        finally:
            os.chdir(cwd)

    def test_merge_commit_lists_only_the_pull_request_changes(self):
        git(self.repo, "switch", "-q", "-c", "topic")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "A.md").write_text("a\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "topic")
        git(self.repo, "switch", "-q", "main")
        (self.repo / "main-only.rs").write_text("fn main() {}\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "main moves on")
        git(self.repo, "merge", "-q", "--no-ff", "-m", "merge", "topic")
        self.assertEqual(self.paths(), ["docs/A.md"])

    def test_a_non_merge_head_is_refused(self):
        with self.assertRaises(ValueError):
            self.paths()


if __name__ == "__main__":
    unittest.main()
