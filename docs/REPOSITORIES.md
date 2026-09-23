# Source and operations repositories

## Two repositories

| Repository | Visibility | Contents |
|---|---|---|
| `zrotext` | Public, application AGPL-3.0-only | Server, Android, authenticated dashboard, protocol, SDKs, billing/entitlement implementation, tests, migrations, public docs, generic deployment examples and release build material |
| `zrotext-ops` | Private | Production IaC/configuration, deployment promotion, secret references, private runbooks, marketing website/campaign source, unpublished copy and operating material approved for storage there |

The public repository is the source of truth for **gateway behavior**. A third party must be able to build and run a complete gateway without access to the private repository. Self-hosters get working generic deployment examples. Billing provider credentials are configuration; the code implementing hosted billing and entitlement rules stays public. Do not move behavior into private middleware to disguise a closed-source product.

The private marketing site is a separate application: homepage, pricing presentation, campaign pages and acquisition content. It links to the public documentation and gateway signup/dashboard. The authenticated dashboard, account recovery, sending, device controls and customer export are application behavior and remain public. Private marketing source must not become a build dependency of the public gateway.

Operational credentials, customer data, unpublished campaigns, and site-specific infrastructure details do not belong in the public source tree. The application must not depend on private services to build or self-host.

## Release path

```text
Public source → reviewed tag → tested signed images/APK + attestations
                                      ↓ digest/tag verification
Private deployment config → promote those artifacts → hosted gateway

Private marketing source → independent build → marketing host
```

Public CI builds/tests and can produce keyless attestations with narrowly scoped release identity; it does not receive production secrets. Fork PR jobs run on isolated unprivileged runners. Private deployment consumes immutable verified digests and injects environment configuration. Do not rebuild a modified private fork and call it the public release.

The trust statement is “our hosted gateway runs published gateway releases.” Do not broaden it to “every website we operate is built from this public repository” when the marketing site is separate. Publish release revision and source links in the app. Generic build/install material necessary for corresponding source belongs in the public repository, including required generation scripts.

Shared brand tokens/assets can be distributed under an explicit permissive asset license or separate brand package while reserving trademark rights appropriately. SDK code should use its approved permissive license and dependency boundary. Do not copy AGPL application components into a private proprietary marketing build without considering their license obligations; an independent static marketing implementation is straightforward.
