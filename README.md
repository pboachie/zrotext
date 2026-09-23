# ZROtext

**Your phone. Your number. Your SMS API.**

ZROtext is an open-source Android SMS gateway. It is designed to connect a dedicated Android phone and its SIM to an API for sending, receiving, and tracking SMS. You can run the gateway yourself; a managed hosting service is planned.

[![CI](https://github.com/pboachie/zrotext/actions/workflows/ci.yml/badge.svg)](https://github.com/pboachie/zrotext/actions/workflows/ci.yml) [![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)

## Project status

ZROtext is in active development. The repository includes a Rust server foundation, PostgreSQL migrations, a delivery simulator, and an Android app prototype. The end-to-end SMS path is not yet complete or verified on a carrier, and the local stack is for development rather than production traffic. The [development roadmap](docs/IMPLEMENTATION.md) and [implementation record](docs/implementation-status.md) distinguish working code from planned features.

## How it is designed

- **Bring your own number.** A dedicated Android phone and SIM provide the SMS connection. Carrier charges and carrier rules still apply.
- **Honest delivery states.** The design distinguishes queued, submitted, confirmed, failed, and unknown outcomes rather than treating a network acknowledgment as carrier delivery.
- **Self-hostable source.** The application code, protocol, migrations, and generic deployment examples live in this repository under AGPLv3.
- **Managed option.** Hosted accounts, device monitoring, backups, upgrades, and billing are planned as an operated service built from the public application source.
- **Two-location architecture.** The design supports routing API and device connections across sites while keeping one authoritative database writer and fenced device ownership.

These are product goals; check the [current implementation record](docs/implementation-status.md) before relying on a capability.

## Run the development stack

Install Docker and Docker Compose, then copy `.env.example` to `.env`. Replace the example password in both `POSTGRES_PASSWORD` and `DATABASE_URL` with the same long random local value.

```sh
cp .env.example .env
docker compose --env-file .env -f deploy/compose/compose.yaml up -d --build
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

The stack runs database migrations before the API starts. Dispatch is disabled by default. To run a second local API instance against the same PostgreSQL writer, add `--profile two-hub` before `up`; it listens on `127.0.0.1:8081`. See the [Compose guide](deploy/compose/README.md) for migration and volume details.

## Documentation

- [Architecture and API contracts](docs/ARCHITECTURE.md)
- [Two-location routing and failover design](docs/MULTI-LOCATION.md)
- [Security design](docs/SECURITY-DESIGN.md)
- [Development roadmap](docs/IMPLEMENTATION.md)
- [Current implementation record](docs/implementation-status.md)

## Contributing

Issues and discussions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development checks, sign-off requirement, and pull request process. Report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md).

ZROtext is licensed under [AGPL-3.0-only](LICENSE). Contributors retain their copyright under the terms described in [CONTRIBUTING.md](CONTRIBUTING.md).
