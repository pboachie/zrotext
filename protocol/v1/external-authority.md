# Independent failover authority transport

This candidate transport connects the failover executor to a customer-controlled
authority outside the writer database and its restore domain. It does not ship a
host watchdog, cloud power driver, or authority service. The customer service must
actually prevent the old host from restarting as a writer and own durable,
linearizable epoch state. A signature authenticates that service's assertion; it
does not independently prove a host stopped. Automatic failover remains off by
default and requires separate deployment acceptance.

The server reads `FAILOVER_EXTERNAL_AUTHORITY_CONFIG` only when quorum execution
is enabled. The private JSON configuration has exactly `namespace`, `url`,
`public_key_base64`, `bearer_file`, optional `ca_certificate_file`, `timeout_ms`,
and `minimum_epoch`. The namespace identifies one deployment, not a reusable
authority across deployments. The public key is a SEC1 P-256 point in standard
base64. The bearer is read from a bounded private file. HTTPS uses certificate
verification and the optional customer CA; redirects, proxy inheritance and
transport retries are disabled. Timeout is 1–5000 milliseconds for the entire
request and response. The initial epoch floor is positive and must match the
independent deployment authority; it is not a replacement for durable state.
No authority endpoint, credential or production configuration belongs here.

Every operation posts JSON to the configured endpoint. The request is
`{namespace,nonce,operation}`, with a new random UUID nonce per call. Operations
are closed objects: `fence` has `site` and `epoch`, `status` has `site`,
`read_epoch` has no other fields, and `record_epoch` has `epoch`. Site and namespace
labels contain 1–128 ASCII letters, digits, hyphens or underscores. The epoch is
the exact promotion token. There is no unfence operation.

HTTP success is exactly status 200 with JSON content type and a response of at
most 4096 bytes, containing exactly `{request,reply,signature}`. The echoed request
must match every field, including the fresh nonce. Reply variants are `fenced`,
`already_fenced`, `competing_fence`, `epoch`, `recorded`, `refused_epoch` with an
`epoch`, or `unfenced`/`unconfirmed` without extra fields. The reply must also be
valid for the requested operation: an unrelated valid signature is not evidence.
Standard base64 encodes a raw 64-byte P-256 ECDSA signature using SHA-256. The transcript is
UTF-8 `ZT/external-authority/v1` followed by NUL, then the request and reply,
each prefixed by its unsigned 32-bit big-endian byte length. Request field order
is `namespace,nonce,operation`; operation and reply start with `kind`, followed
by `site,epoch` where present. JSON has no whitespace and uses serde JSON string
escaping. The [schema](external-authority-v1.schema.json) describes shape;
request correlation and signature verification are additional mandatory checks.

The remote service serializes operations per namespace. It must commit durable
host fencing before `fenced`, preserve an existing token on a competing request,
and return `already_fenced` only for the identical token. `status` must observe
the real fence, including after the old host or authority restarts. `read_epoch`
returns the highest durably granted epoch. `record_epoch` advances that state
strictly forward after the writer CAS; equal or lower requests return
`refused_epoch` with the actual current epoch. Ambiguous hardware state, minority
partition, unavailable durable storage or disagreement returns `unconfirmed`.
The service must never reconstruct authority from the writer's restored database.
Backing up or restoring its state must preserve the independent monotonic bound.

Timeout, lost acknowledgment, malformed/oversized response, signature failure,
cross-deployment replay and uncertainty are refusals. A later explicit executor
iteration may query current status or replay the same promotion token; the
transport never resends an unknown operation. The adapter additionally latches
observed epoch rollback until restart, but that process memory is only a check
on the independent service, not the witness itself. After a writer CAS, promotion
completion remains pending and dispatch paused until the same epoch is witnessed.
Lost witness acknowledgment can converge through identical CAS replay. Restored
writer databases below the confirmed external epoch fail closed, and former
writer rejoin requires the existing confirmed-anchor fence.

The isolated tests use real HTTPS and a synthetic, separately fsynced authority
file for acknowledgment-loss and restart scenarios. They do not establish actual
watchdog behavior, replicated-service durability, deployment isolation, power
fencing, or a real-site rehearsal. Those deployment-specific checks remain required
before enablement and their evidence belongs in private operations storage.
