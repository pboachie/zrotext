<p align="center"><img src="docs/assets/zrotext-mark.svg" alt="ZROtext mark" width="64"></p>
<h1 align="center">ZROtext</h1>
<p align="center"><strong>Your phone. Your number. Your SMS API.</strong></p>
<p align="center">
  <a href="https://github.com/pboachie/zrotext/actions/workflows/ci.yml"><img src="https://github.com/pboachie/zrotext/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--only-blue" alt="AGPL-3.0-only license"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-6f9b4b" alt="Contributions welcome"></a>
</p>

ZROtext is an open-source Android SMS gateway. It is designed to connect a dedicated Android phone and its SIM to an API for sending, receiving, and tracking SMS. You can run the gateway yourself; a managed hosting service is planned.

<p align="center"><img src="docs/assets/android-app-concept.png" alt="ZROtext Android gateway app design concept with sample status and message counts" width="360"></p>
<p align="center"><sub>Android app design concept · sample data · not a live connection</sub></p>

## Project status

ZROtext is in active development. The repository includes a Rust server, PostgreSQL migrations, a delivery simulator, and an Android app. The local stack is for development. Some phone and billing flows are limited to controlled tests; a hosted SMS service is not available. See the [roadmap](docs/ROADMAP.md) for planned product work.

## How it is designed

- **Bring your own number.** A dedicated Android phone and SIM provide the SMS connection. Carrier charges and carrier rules still apply.
- **Honest delivery states.** The design distinguishes queued, submitted, confirmed, failed, and unknown outcomes rather than treating a network acknowledgment as carrier delivery.
- **Self-hostable source.** The application code, protocol, migrations, and generic deployment examples live in this repository under AGPLv3.
- **Managed option.** Hosted accounts, device monitoring, backups, upgrades, and billing are planned as an operated service built from the public application source.
- **Two-location architecture.** The design supports routing API and device connections across sites while keeping one authoritative database writer and fenced device ownership.

The architecture describes intended behavior. Check the current code and release notes before relying on a capability.

## Roadmap

The [roadmap](docs/ROADMAP.md) covers gateway messaging, self-hosting, account tools, and multi-location support. It has no promised release dates.

## Design preview

These interface studies use synthetic devices, messages and traffic. Click an image to inspect it at full size.

| Fleet console concept | Two-location routing concept |
|:---:|:---:|
| <a href="docs/assets/fleet-console-concept.png"><img src="docs/assets/fleet-console-concept.png" alt="Fleet console concept with sample device health and message activity" width="620"></a> | <a href="docs/assets/two-location-concept.png"><img src="docs/assets/two-location-concept.png" alt="Two-location routing concept with one authoritative database writer" width="620"></a> |

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
- [Roadmap](docs/ROADMAP.md)
- [Self-hosting](docs/SELF-HOSTING.md)
- [Android development and testing](docs/ANDROID-TESTING.md)

## Contributing

Issues and discussions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development checks, sign-off requirement, and pull request process. Report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md).

ZROtext is licensed under [AGPL-3.0-only](LICENSE). Contributors retain their copyright under the terms described in [CONTRIBUTING.md](CONTRIBUTING.md).
