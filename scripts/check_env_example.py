"""Keep Rust runtime settings, the example file, and both Compose apps aligned."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
READ = re.compile(
    r'\b(?:(?:std::)?env::var(?:_os)?|required|optional_secret|optional_bool|'
    r'smtp_env_option)\s*\(\s*"([A-Z][A-Z0-9_]*)"'
)
SMTP_ALIAS = re.compile(
    r'\b(?:required_smtp_alias|smtp_alias)\s*\(\s*"([A-Z][A-Z0-9_]*)"\s*,\s*'
    r'"([A-Z][A-Z0-9_]*)"'
)
DOCUMENTED = re.compile(r'^\s*#?\s*([A-Z][A-Z0-9_]*)=', re.MULTILINE)
TEST_ONLY = {
    "ZT_AUTH_TEST_DATABASE_URL",
    "ZT_DELIVERY_TEST_DATABASE_URL",
    "ZT_INBOUND_TEST_DATABASE_URL",
    "ZT_POSTGRES_TLS_TEST_DATABASE_URL",
    "ZT_STRIPE_TEST_SECRET_KEY",
    "ZT_STRIPE_TEST_PRICE_ID",
    "ZT_STRIPE_TEST_PAID_EVENT_ID",
    "ZT_STRIPE_TEST_PAID_CUSTOMER_ID",
    "ZT_STRIPE_TEST_FAILED_EVENT_ID",
    "ZT_STRIPE_TEST_FAILED_CUSTOMER_ID",
}
# These settings belong to Compose infrastructure or to a local binary; they
# are intentionally not forwarded as app environment variables.
COMPOSE_ONLY = {
    "POSTGRES_PASSWORD", "RUNTIME_DATABASE_PASSWORD", "APP_PORT", "MIGRATIONS_DIR",
    "EDGE_BIND", "EDGE_DOMAIN", "EDGE_HTTP_PORT", "EDGE_HTTPS_PORT",
}


def compose_app_environment(source: str, service: str) -> set[str]:
    """Read environment keys from an explicit Compose app service mapping."""
    in_service = False
    in_environment = False
    keys = []
    for line in source.splitlines():
        if re.match(r"^  [a-z][a-z0-9_-]*:\s*$", line):
            in_service = line == f"  {service}:"
            in_environment = False
        elif in_service and re.match(r"^    [a-z][a-z0-9_-]*:\s*$", line):
            in_environment = line == "    environment:"
        elif in_environment:
            match = re.match(r"^      ([A-Z][A-Z0-9_]*):", line)
            if match:
                keys.append(match.group(1))
    if not keys or len(keys) != len(set(keys)):
        raise ValueError(f"missing or duplicate {service} environment mapping")
    return set(keys)


def main() -> int:
    used = set()
    for path in (ROOT / "crates").rglob("*.rs"):
        source = path.read_text(encoding="utf-8")
        used.update(READ.findall(source))
        for primary, alias in SMTP_ALIAS.findall(source):
            used.update((primary, alias))

    documented = set(DOCUMENTED.findall((ROOT / ".env.example").read_text(encoding="utf-8")))
    missing = sorted(used - TEST_ONLY - documented)
    if missing:
        print("Missing from .env.example: " + ", ".join(missing), file=sys.stderr)
        return 1
    compose = (ROOT / "deploy" / "compose" / "compose.yaml").read_text(encoding="utf-8")
    forwarded = documented - COMPOSE_ONLY
    for service in ("app", "app_b"):
        try:
            service_keys = compose_app_environment(compose, service)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        dropped = sorted(forwarded - service_keys)
        if dropped:
            print(f"Missing from Compose {service} environment: " + ", ".join(dropped),
                  file=sys.stderr)
            return 1
    print(f"Documented {len(used - TEST_ONLY)} runtime environment variables; "
          f"forwarded {len(forwarded)} to both Compose apps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
