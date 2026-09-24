"""Fail CI when a Rust runtime environment setting lacks an .env.example entry."""

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
    print(f"Documented {len(used - TEST_ONLY)} runtime environment variables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
