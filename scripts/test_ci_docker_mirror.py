import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import ci_docker_mirror as mirror


class DockerMirrorConfigTest(unittest.TestCase):
    def test_existing_runtime_settings_and_mirrors_survive(self):
        original = {"features": {"containerd-snapshotter": True},
                    "log-driver": "local", "registry-mirrors": [
                        "https://cache.example.test", mirror.MIRROR,
                        "https://second.example.test"]}
        prepared = mirror.mirror_config(original)
        self.assertEqual(prepared["features"], original["features"])
        self.assertEqual(prepared["log-driver"], "local")
        self.assertEqual(prepared["registry-mirrors"], [mirror.MIRROR,
                         "https://cache.example.test", "https://second.example.test"])
        self.assertEqual(original["registry-mirrors"][0], "https://cache.example.test")
        self.assertEqual(mirror.mirror_config(prepared), prepared)

    def test_missing_configuration_gets_only_documented_mirror(self):
        self.assertEqual(mirror.mirror_config({}), {"registry-mirrors": [mirror.MIRROR]})

    def test_malformed_objects_and_mirrors_refuse(self):
        for value in ([], None, "config", {"registry-mirrors": None},
                      {"registry-mirrors": "https://cache.example.test"},
                      {"registry-mirrors": [None]}, {"registry-mirrors": [""]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mirror.mirror_config(value)

    def test_duplicate_json_keys_refuse(self):
        with self.assertRaises(ValueError):
            json.loads('{"features": {}, "features": {}}', object_pairs_hook=mirror.unique_object)

    def test_other_hosts_refuse_before_filesystem_access(self):
        valid = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                 "RUNNER_OS": "Linux", "RUNNER_TEMP": "/unused"}
        for key, value in (("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("RUNNER_OS", "Windows")):
            with self.subTest(key=key), mock.patch.object(Path, "is_dir") as directory:
                with self.assertRaises(ValueError):
                    mirror.prepare_config(dict(valid, **{key: value}), "linux")
                directory.assert_not_called()
        with self.assertRaises(ValueError):
            mirror.prepare_config(valid, "win32")

    def test_invalid_source_never_creates_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                           "RUNNER_OS": "Linux", "RUNNER_TEMP": temporary}
            for source in ('{', '{"registry-mirrors": null}', '[1]', '{"debug": NaN}',
                           '{"debug": false, "debug": true}'):
                with self.subTest(source=source), mock.patch.object(Path, "exists", return_value=True), \
                     mock.patch.object(Path, "read_text", return_value=source):
                    with self.assertRaises(ValueError):
                        mirror.prepare_config(environment, "linux")
                    self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_prepared_file_preserves_source_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                           "RUNNER_OS": "Linux", "RUNNER_TEMP": temporary}
            with mock.patch.object(Path, "exists", return_value=True), \
                 mock.patch.object(Path, "read_text", return_value='{"debug": false}') as read:
                mirror.prepare_config(environment, "linux")
                read.assert_called_once_with()
                with self.assertRaises(FileExistsError):
                    mirror.prepare_config(environment, "linux")
            destination = Path(temporary) / "zrotext-docker-daemon.json"
            self.assertEqual(json.loads(destination.read_text()),
                             {"debug": False, "registry-mirrors": [mirror.MIRROR]})
            if os.name != "nt":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_absent_daemon_config_prepares_default_without_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                           "RUNNER_OS": "Linux", "RUNNER_TEMP": temporary}
            with mock.patch.object(Path, "exists", return_value=False), \
                 mock.patch.object(Path, "read_text") as read:
                mirror.prepare_config(environment, "linux")
                read.assert_not_called()
            self.assertEqual(json.loads((Path(temporary) / "zrotext-docker-daemon.json").read_text()),
                             {"registry-mirrors": [mirror.MIRROR]})

    def test_cli_refusal_withholds_input_errors(self):
        with mock.patch.object(mirror, "prepare_config", side_effect=ValueError("private value")), \
             mock.patch("sys.stderr") as error:
            self.assertEqual(mirror.main(), 1)
            self.assertNotIn("private value", str(error.write.call_args_list))

    def test_workflow_only_configures_the_hosted_image_job_before_buildx(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        self.assertEqual(workflow.count("python3 scripts/ci_docker_mirror.py"), 1)
        image_job = workflow.split("  image-scan:\n", 1)[1].split("  owner-browser:\n", 1)[0]
        self.assertIn("runs-on: ubuntu-24.04", image_job)
        self.assertLess(image_job.index("python3 scripts/ci_docker_mirror.py"),
                        image_job.index("sudo dockerd --validate"))
        self.assertLess(image_job.index("sudo dockerd --validate"), image_job.index("sudo install"))
        self.assertLess(image_job.index("sudo systemctl restart docker"),
                        image_job.index("uses: docker/setup-buildx-action@"))
        self.assertNotIn("allow-untrusted-image", image_job)
        self.assertNotIn("driver-opts:", image_job)


if __name__ == "__main__":
    unittest.main()
