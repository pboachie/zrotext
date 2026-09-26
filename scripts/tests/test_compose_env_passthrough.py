"""Exercise Compose interpolation without starting containers or using live secrets."""

import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "compose" / "compose.yaml"
PASSTHROUGH = (
    "BIND_ADDR", "SOURCE_URL", "SYNTHETIC_ALPHA_ENABLED",
    "SYNTHETIC_ALPHA_ALLOWED_ACCOUNT_IDS", "SYNTHETIC_ALPHA_ALLOWED_RECIPIENTS",
    "INBOUND_PILOT_ENABLED", "LINE_OPT_OUT_ENABLED", "ZT_DEVICE_STREAM_DIAGNOSTIC",
    "WEBHOOK_KEK_VERSION", "WEBHOOK_KEK_B64",
    "WEBHOOK_KEK_SECONDARY_VERSION", "WEBHOOK_KEK_SECONDARY_B64",
    "WEBHOOK_DELIVERY_ENABLED", "STRIPE_BILLING_TEST_ENABLED",
    "STRIPE_TEST_WEBHOOK_SECRET", "STRIPE_TEST_PRICE_IDS",
    "STRIPE_TEST_QUOTA_PLANS", "STRIPE_TEST_HOSTED_SESSIONS_ENABLED",
    "STRIPE_TEST_CHECKOUT_PRICE_ID", "STRIPE_TEST_RECONCILE_SECRET_KEY",
    "STRIPE_TEST_SESSION_SECRET_KEY", "STRIPE_TEST_SECRET_KEY",
)


class ComposeEnvironmentTest(unittest.TestCase):
    def test_feature_settings_reach_both_apps(self):
        # Give Docker only the operating-system variables it needs to find
        # the CLI/context. Never inherit this machine's deployment settings.
        system_keys = ("PATH", "SYSTEMROOT", "COMSPEC", "USERPROFILE", "APPDATA",
                       "LOCALAPPDATA", "HOME", "HOMEDRIVE", "HOMEPATH",
                       "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "DOCKER_CONFIG")
        environment = {key: os.environ[key] for key in system_keys if key in os.environ}
        probe = {key: f"probe_{key}" for key in PASSTHROUGH}
        environment.update(probe)
        database_secret = secrets.token_hex(24)
        environment.update({
            "POSTGRES_PASSWORD": database_secret,
            "RUNTIME_DATABASE_PASSWORD": secrets.token_hex(32),
            "DATABASE_URL": f"postgres://zrotext:{database_secret}@db:5432/zrotext",
            "DISPATCH_ENABLED": "true",
        })
        with tempfile.TemporaryDirectory(prefix="zt-compose-config-") as directory:
            empty_env = Path(directory) / "empty.env"
            empty_env.write_text("", encoding="utf-8")
            result = subprocess.run(
                ["docker", "compose", "--profile", "two-hub", "--env-file",
                 str(empty_env), "-f", str(COMPOSE), "config", "--format", "json"],
                env=environment, capture_output=True, text=True, timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, "Docker Compose config failed")
        config = json.loads(result.stdout)
        for service in ("app", "app_b"):
            app = config["services"][service]["environment"]
            for key, value in probe.items():
                self.assertEqual(app[key], value, f"{service} dropped {key}")
            self.assertEqual(app["DISPATCH_ENABLED"], "false")


if __name__ == "__main__":
    unittest.main()
