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
    # Compiled only in the isolated native-console test harness, not runtime code.
    "ZT_TERMINAL_NATIVE_CASE",
    "ZT_OWNER_NATIVE_CASE",
    "ZT_REFRESH_NATIVE_CASE",
    "ZT_REFRESH_INTEROP_NOW",
    "ZT_REFRESH_INTEROP_PROPOSAL_HEX",
    # Compiled only under cfg(test) + conversation-simulator-tests; never a server setting.
    "ZT_CONVERSATION_SIM_DIR",
    "ZT_AUTH_TEST_DATABASE_URL",
    "ZT_DELIVERY_TEST_DATABASE_URL",
    "ZT_FAILOVER_TEST_DATABASE_URL",
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
    "STRIPE_BILLING_RECONCILIATION_KEY",
}


def runtime_reads(source: str, relative_path: str) -> set[str]:
    """Exclude fixture markers only in their isolated cfg(test) source modules."""
    reads = set(READ.findall(source))
    fixture_reads = {
        "crates/owner-cli/src/windows/conversation_refresh/native_tests.rs": {"TEMP"},
        "crates/root-material/src/archive_backup/tests.rs": {"ZT_ARCHIVE_INTEROP"},
        "crates/owner-cli/src/windows/conversation_activation/native_tests.rs": {
            "TEMP", "ZT_ACTIVATION_NATIVE_CASE", "ZT_ACTIVATION_INTEROP_NOW",
            "ZT_ACTIVATION_INTEROP_PROPOSAL_HEX",
        },
    }
    reads.difference_update(fixture_reads.get(relative_path, set()))
    if relative_path == "crates/root-material/src/conversation_activation.rs":
        tests = re.search(r'(?m)^#\[cfg\(test\)\]\r?\nmod tests \{', source)
        if tests:
            fixture = re.search(
                r'(?ms)^    #\[test\]\r?\n    fn existing_root_signs_only_preserved_activation_and_public_interop\(\) \{\r?\n.*?^    \}',
                source[tests.start():],
            )
            if fixture:
                start, end = (tests.start() + position for position in fixture.span())
                reads = {match.group(1) for match in READ.finditer(source)
                         if not (match.group(1) == "ZT_ACTIVATION_INTEROP" and start <= match.start() < end)}
    for primary, alias in SMTP_ALIAS.findall(source):
        reads.update((primary, alias))
    return reads


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
        used.update(runtime_reads(source, path.relative_to(ROOT).as_posix()))

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
