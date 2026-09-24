"""Synthetic Git repositories exercise index/history boundaries and hook safety."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from privacy_guard import diagnostic_text, forbidden_path, scan_blob, scan_line

SCRIPTS = Path(__file__).resolve().parent
SCANNER = SCRIPTS / "privacy_guard.py"
INSTALLER = SCRIPTS / "install_privacy_hooks.py"


class PatternTests(unittest.TestCase):
    def test_machine_paths(self):
        samples = ["Q:" + "/Users/" + "fixture-owner/work", "Q:" + chr(92) + "Projects" + chr(92) + "fixture-work",
                   "/home/" + "fixture-owner/work", "/Users/" + "fixture-owner/work", "/root/" + "fixture-work"]
        for sample in samples:
            with self.subTest(style=samples.index(sample)):
                self.assertTrue(scan_line(sample))
                self.assertNotIn(sample, str(scan_line(sample)))

    def test_templates_and_service_paths(self):
        for line in ("${HOME}/project", "/etc/service/config", "/opt/app/data", "/home/<operator>/project",
                     "Q:" + "/Users/<operator>/project",
                     "SERVICE_API_KEY=${SECRET_FROM_VAULT}", "POSTGRES_PASSWORD=replace-with-a-secret"):
            self.assertEqual(scan_line(line), [])

    def test_network_folders_and_age_keys(self):
        for host in ("fixture-server", "wsl.localhost"):
            path = chr(92) * 2 + host + chr(92) + "share" + chr(92) + "fixture-folder"
            self.assertIn("machine network folder", scan_line(path))
        key = "AGE-" + "SECRET-" + "KEY-1" + "A" * 58
        self.assertIn("age recovery key", scan_line(key))
        self.assertNotIn(key, str(scan_line(key)))
        self.assertTrue(forbidden_path("recovery-key.txt"))

    def test_arbitrary_environment_credentials(self):
        for key in ("VENDOR_API_KEY", "DATABASE_PASSWORD", "SERVICE_ACCESS_TOKEN", "ACCOUNT_SECRET", "ENROLLMENT_PEPPER_B64"):
            self.assertIn("embedded credential assignment", scan_line(key + "=" + "not-a-real-credential"))
        for key in ("SERVICE_TOKEN", "EXTRA_PASSWORD"):
            data = (key + ' = "' + "ABCDEFGHIJKLMNOP1234567890" + '"\n').encode()
            self.assertTrue(scan_blob("src/config.py", data))

    def test_all_assignments_and_punctuation_passwords(self):
        field = "SERVICE_TOKEN"
        value = "synthetic-not-real"
        payload = '{"PUBLIC_NAME":"fixture","' + field + '":"' + value + '"}\n'
        self.assertTrue(scan_blob("config.json", payload.encode()))
        self.assertTrue(scan_blob("src/config.py", payload.encode()))
        payload = "PUBLIC_NAME=fixture " + field + "=" + value + "\n"
        self.assertTrue(scan_blob("config.txt", payload.encode()))
        payload = "SERVICE_PASSWORD" + "=synthetic(not-real)\n"
        self.assertTrue(scan_blob("config.txt", payload.encode()))
        reference = "SERVICE_PASSWORD" + " = os.environ.get('" + "SERVICE_PASSWORD" + "')\n"
        self.assertEqual(scan_blob("src/config.py", reference.encode()), [])

    def test_unknown_diagnostic_is_never_printed(self):
        value = "synthetic-private-value"
        self.assertEqual(diagnostic_text(value), "unclassified privacy violation")
        self.assertNotIn(value, diagnostic_text(value))

    def test_private_infrastructure_and_fixtures(self):
        address = ".".join(("192", "168", "87", "19"))
        value = ("host=" + address + "\n").encode()
        self.assertTrue(scan_blob("deploy/runtime.conf", value))
        self.assertEqual(scan_blob("tests/fixtures/ip.conf", value), [])
        self.assertEqual(scan_blob("src/ip_validation.rs", value), [])
        self.assertEqual(scan_blob("deploy/runtime.conf", b"host=192.0.2.19\n"), [])
        # Credential filters still apply to fixtures; only address fixtures differ.
        token = ("sk_" + "test_" + "A" * 24 + "\n").encode()
        self.assertTrue(scan_blob("tests/fixtures/ip.conf", token))

    def test_forbidden_names(self):
        for name in (".local/operator.txt", ".env", "deploy/.env.prod", "credentials.txt", "pve-credentials.xml", "secret-vault/data", "key.p12"):
            self.assertTrue(forbidden_path(name))
        self.assertFalse(forbidden_path(".env.example"))

    def test_unknown_text_and_utf16_are_scanned(self):
        value = "SERVICE_API_KEY" + "=" + "not-a-real-credential" + "\n"
        self.assertTrue(scan_blob("payload.unknown", value.encode()))
        self.assertTrue(scan_blob("payload.txt", value.encode("utf-16")))


class GitBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="privacy-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture Author")
        self.git("config", "user.email", "author@example.test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.write("safe.md", "Public fixture.\n")
        self.commit("Initial fixture")
        self.base = self.git("rev-parse", "HEAD").stdout.decode().strip()

    def git(self, *args, check=True):
        result = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True)
        if check:
            self.assertEqual(result.returncode, 0, "Fixture Git operation failed (details hidden)")
        return result

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def scan(self, *args, stdin=None):
        return subprocess.run([sys.executable, str(SCANNER), "--repo", str(self.root), *args],
                              input=stdin, text=True, capture_output=True)

    def test_index_not_clean_working_tree(self):
        sensitive = "SERVICE_API_KEY" + "=" + "not-a-real-credential"
        self.write("config.txt", sensitive + "\n")
        self.git("add", "config.txt")
        self.write("config.txt", "Public replacement.\n")
        result = self.scan("--index")
        self.assertEqual(result.returncode, 1)
        self.assertIn("embedded credential assignment", result.stderr)
        self.assertNotIn(sensitive, result.stderr)
        self.assertNotIn("config.txt", result.stderr)

    def test_transient_leak_in_removed_commit(self):
        self.write("unsafe.txt", "SERVICE_API_KEY" + "=" + "not-a-real-credential" + "\n")
        self.commit("Add fixture")
        (self.root / "unsafe.txt").unlink()
        self.commit("Remove fixture")
        self.assertEqual(self.scan("--tree", "HEAD").returncode, 0)
        self.assertEqual(self.scan("--range", self.base, "HEAD").returncode, 1)

    def test_commit_message_and_missing_range_fail_closed(self):
        message = "Local " + "/home/" + "fixture-owner/project"
        self.git("commit", "--allow-empty", "-q", "-m", message)
        result = self.scan("--range", self.base, "HEAD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("commit-message", result.stderr)
        self.assertNotIn(message, result.stderr)
        self.assertEqual(self.scan("--range", "missing-ref", "HEAD").returncode, 2)

    def test_new_ref_scans_unpublished_ancestry(self):
        # Already published legacy messages should not block new branches.
        self.git("commit", "--allow-empty", "-q", "-m", "Legacy " + "/home/" + "fixture-owner/old")
        published = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.git("update-ref", "refs/remotes/origin/main", published)
        self.write("next.md", "Public addition.\n")
        self.commit("Public update")
        head = self.git("rev-parse", "HEAD").stdout.decode().strip()
        update = "refs/heads/topic " + head + " refs/heads/topic " + "0" * 40 + "\n"
        self.assertEqual(self.scan("--pre-push", "--remote", "origin", stdin=update).returncode, 0)
        self.write("unsafe.txt", "SERVICE_API_KEY" + "=" + "not-a-real-credential" + "\n")
        self.commit("Unpublished fixture")
        (self.root / "unsafe.txt").unlink()
        self.commit("Remove unpublished fixture")
        head = self.git("rev-parse", "HEAD").stdout.decode().strip()
        update = "refs/heads/topic " + head + " refs/heads/topic " + "0" * 40 + "\n"
        self.assertEqual(self.scan("--pre-push", "--remote", "origin", stdin=update).returncode, 1)

    def test_forbidden_tracked_file_and_secret_filename_are_redacted(self):
        name = ".local/" + "sk_" + "test_" + "B" * 24 + ".txt"
        self.write(name, "Public content.\n")
        self.git("add", "-f", name)
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(name, result.stderr)
        self.assertIn("forbidden tracked filename", result.stderr)

    def install(self, *args):
        return subprocess.run([sys.executable, str(INSTALLER), *args], cwd=self.root, capture_output=True)

    def test_installer_refuses_existing_hook(self):
        self.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n")
        self.assertEqual(self.install().returncode, 1)
        self.assertFalse((self.root / ".git/privacy-hooks").exists())

    def test_hooks_protect_an_older_linked_worktree(self):
        self.assertEqual(self.install().returncode, 0)
        linked = self.root / "older-worktree"
        self.git("worktree", "add", "-q", "-b", "older", str(linked), self.base)
        self.assertFalse((linked / "scripts/privacy_guard.py").exists())
        (linked / "unsafe.txt").write_text("SERVICE_API_KEY" + "=" + "not-a-real-credential\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(linked), "add", "unsafe.txt"], check=True, capture_output=True)
        result = subprocess.run(["git", "-C", str(linked), "commit", "-m", "Blocked"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"embedded credential assignment", result.stderr)

    def test_real_commit_message_and_push_hooks(self):
        remote = self.root / ".git" / "fixture-remote.git"
        self.git("init", "--bare", "-q", str(remote))
        self.git("remote", "add", "origin", str(remote))
        self.assertEqual(self.install().returncode, 0)
        self.git("push", "-q", "origin", "HEAD:refs/heads/main")
        bad_message = "Local " + "/home/" + "fixture-owner/project"
        blocked = self.git("commit", "--allow-empty", "-m", bad_message, check=False)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn(b"Commit message rejected", blocked.stderr)
        self.assertNotIn(bad_message.encode(), blocked.stderr)
        self.write("unsafe.txt", "SERVICE_API_KEY" + "=" + "not-a-real-credential" + "\n")
        self.git("add", "unsafe.txt")
        self.git("commit", "--no-verify", "-q", "-m", "Synthetic transient fixture")
        (self.root / "unsafe.txt").unlink()
        self.commit("Clean final tree")
        blocked = self.git("push", "origin", "HEAD:refs/heads/topic", check=False)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn(b"embedded credential assignment", blocked.stderr)
        advertised = self.git("ls-remote", "origin", "refs/heads/topic")
        self.assertEqual(advertised.stdout, b"")


if __name__ == "__main__":
    unittest.main()
