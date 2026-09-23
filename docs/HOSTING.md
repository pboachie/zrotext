# PVE-first hosting and migration

## Deployment pattern

This document describes a portable Proxmox/Linux-VM hosting pattern. Operator-specific infrastructure inventory, capacity evidence, deployment dates, financial thresholds and credentials remain outside the public repository. No live infrastructure was provisioned or verified by this planning package.

## Proposed pilot topology

```text
Public users / Android phones
          │ HTTPS + WSS
Cloudflare edge for zrotext.com (after domain purchase)
          │ outbound tunnel, dedicated zrotext connector
Dedicated zrotext Linux VM on PVE server network
          ├─ local ingress → Rust application + workers
          ├─ PostgreSQL on private container network
          ├─ encrypted backups → separate failure domain
          └─ metrics / redacted errors → existing internal observability
```

Allocate **2 vCPU, 4 GB RAM, 40–60 GB storage** as the initial request, after reading current free capacity and disk latency. Use a supported Debian stable VM, Docker Compose, non-root containers where feasible, read-only root filesystem, resource limits, bounded logs, and pinned image digests. Keep database memory/connections bounded. One app plus one PostgreSQL is enough for this explicitly disclosed pilot; replicas on the same PVE host do not provide host-level availability.

A dedicated VM keeps the application isolated from unrelated workload scheduling and maintenance. Keep zrotext out of other products' database instances and backup credentials. Do not change unrelated runner pools, routers, or existing services.

Reserve VM ID, address and DNS through the operator inventory at implementation time; no guessed IDs or static IPs. Reuse documented operational patterns but create a separate tunnel/connector and least-privilege zone credentials for zrotext. This avoids mutating a shared remote-managed ingress document. Validate the Cloudflare plan/terms for intended API traffic before enabling public service.

Cloudflare supports proxied WebSockets, but sessions can drop during edge restarts or idle periods; clients need keepalive and reconnect/reconciliation. [WebSocket behavior](https://developers.cloudflare.com/network/websockets/). Tunnel provides outbound connectivity without opening an inbound origin port. [Tunnel overview](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)

Use verified TLS for any cross-host origin hop; no copied `noTLSVerify` defaults. A same-VM isolated loopback/container hop can use local HTTP under the documented host trust boundary. Cloudflare terminates external TLS and sees routing metadata and auth transport data; sealed bodies are ciphertext. “No FCM” does not mean “no third-party processor.” Disable body/header logging and caching on API, auth, and webhook routes. Keep the device endpoint usable without browser CAPTCHA/Access challenges; it has application-level device authentication.

## Isolation before public exposure

- PVE/iLO, SSH, metrics, database and admin diagnostics stay on management/private paths. Only intended application paths are public. No origin database port mapping to the LAN.
- Deny new connections from the zrotext VM to the home/management network, except explicit monitoring/backup/DNS destinations. Being in a server VLAN alone is not sufficient lateral isolation; test host firewall and routed rules.
- Webhook worker egress blocks private, loopback, link-local and metadata destinations, including IPv6 and DNS changes. Public SaaS callbacks must not become a route into the house.
- Use dedicated DB user, backup principal, application secrets, Stripe webhook secret and tunnel token. Store only through approved secret tooling; never echo tokens or commit decrypted material. No public-fork CI on privileged home runners.
- Use a transactional email identity for zrotext with SPF/DKIM/DMARC. Existing mail infrastructure is a candidate, not authorization to reuse another product's sender/credentials.
- Add private Kuma/Prometheus/error views with redaction and an **external** uptime probe. A monitor inside the same house cannot report a total power/network outage. Status content must be reachable independently of the origin for that failure mode.

## Backups and outage behavior

Nightly logical dump plus hourly/WAL recovery strategy chosen and tested for the stated RPO. Encrypt backup archives with a separate recovery key, restore monthly to a disposable isolated VM, verify accounts, usage ledger, queued/unknown attempts, device identities and migrations. Keep 7 daily/4 weekly recovery points as a starting operational policy; metadata/content deletion documentation must account for backup expiry. Prevent replayed queue items from restored snapshots: start restored environments with dispatch disabled, reconcile with devices, and fence the original writer before re-enabling.

A copy on another volume of the same PVE host is not disaster recovery. Before real customer traffic, establish an encrypted backup in a separate physical failure domain (existing appropriate off-site storage may suffice). If none is available under the budget, paid onboarding waits; do not claim an RPO supported only by local copies. Owner must confirm UPS/runtime, internet reliability, ISP hosting terms and off-site restore access. Keep device-side unsent/inbound queues bounded, persist callbacks, and show outages/unknown states without blind resend.

Target RPO ≤1 hour and RTO ≤4 hours after a restore drill. Report actual results. No 99.9% or SLA claim for this pilot.

## Deployment readiness

Before adding or moving a location, verify capacity, independent backups, network isolation, private connectivity, writer fencing, monitoring, a restore drill and a concrete operating budget. Keep operator-specific business criteria in private notes; application behavior and public configuration must be independent of customer counts or revenue.

## Single-writer migration

1. Prepare reviewed destination config and priced resources; verify backups, versions, capacity, certificates, public endpoints, and restore in isolation. Keep destination dispatch and billing mutation workers disabled.
2. Announce a short maintenance window. Pause new outbound acceptance and claims, allow callbacks to drain, expire unexecuted leases, and persist remaining events. Devices buffer/retry inbound/callback events with stable IDs. Stripe retries or an ingress queue must survive the window.
3. Fence source writers at both app and DB access. Final dump/restore for the small pilot; streaming replication is unnecessary unless data size justifies it. Compare row counts, ledger sums, schema version, key IDs, queue/attempt states and stored event cursors. Preserve all idempotency records.
4. Switch the stable domain route to the destination, start the new writer once, allow devices to reauthenticate, and reconcile before releasing the queue. Test from mobile data, not only LAN DNS. Long-lived old sockets must close; stale grants cannot cause duplicates.
5. Verify outbound to a consented test handset, inbound reply, webhook, quota, checkout in test mode, data export, backup and external health. Monitor at least 24 hours; keep the source read-only and inaccessible to workers during rollback retention.
6. Rollback before new writes can route back to the intact source. After destination accepts writes, stop it, export/reconcile those writes and callbacks, restore the authoritative state to the source, then switch. **Never point DNS back to stale writable data.** Document operator ownership and the exact rollback boundary.

After stable migration, PVE remains an active API/device-hub location and a standby/backup location as specified in [MULTI-LOCATION.md](MULTI-LOCATION.md). Both sites may run dispatch workers against the **same authoritative writer**, with one fenced owner per device/attempt. Do not run independently writable competing queues. Backup storage still needs an appropriate independent failure domain.

## Implementation proof bundle

Private deployment repo should contain actual inventory reservations, capacity snapshot, network rule test, image digests, origin/TLS settings, sanitized config diff, secret references, backup/restore result, external WebSocket test, rollback rehearsal, budget and deployment-readiness record. Public repo receives only parameterized examples and redacted operational evidence.
