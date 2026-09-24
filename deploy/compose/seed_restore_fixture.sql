-- SPDX-License-Identifier: AGPL-3.0-only
-- Disposable data only. The API is stopped and dispatch remains disabled.
BEGIN;
INSERT INTO accounts (id) VALUES
  ('11111111-1111-1111-1111-111111111111'),
  ('22222222-2222-2222-2222-222222222222');

INSERT INTO devices (id, account_id, display_name, revoked_at) VALUES
  ('33333333-3333-3333-3333-333333333333',
   '11111111-1111-1111-1111-111111111111', 'synthetic-active', NULL),
  ('44444444-4444-4444-4444-444444444444',
   '22222222-2222-2222-2222-222222222222', 'synthetic-revoked',
   '2026-01-02 00:00:00+00');

INSERT INTO device_keys (device_id, account_id, signing_key_sec1, fingerprint, revoked_at) VALUES
  ('33333333-3333-3333-3333-333333333333',
   '11111111-1111-1111-1111-111111111111', decode(repeat('04', 65), 'hex'),
   decode(repeat('11', 32), 'hex'), NULL),
  ('44444444-4444-4444-4444-444444444444',
   '22222222-2222-2222-2222-222222222222', decode(repeat('04', 65), 'hex'),
   decode(repeat('22', 32), 'hex'), '2026-01-02 00:00:00+00');

INSERT INTO messages (id, account_id, device_id, recipient_e164, recipient_digest,
                      transport_mode, transport_payload, request_digest, state, expires_at) VALUES
  ('55555555-5555-5555-5555-555555555555',
   '11111111-1111-1111-1111-111111111111',
   '33333333-3333-3333-3333-333333333333', '+15555550100',
   decode(repeat('31', 32), 'hex'), 'synthetic_alpha',
   convert_to('synthetic restore payload A', 'UTF8'),
   decode(repeat('41', 32), 'hex'), 'queued', '2099-01-01 00:00:00+00'),
  ('66666666-6666-6666-6666-666666666666',
   '22222222-2222-2222-2222-222222222222',
   '44444444-4444-4444-4444-444444444444', '+15555550101',
   decode(repeat('32', 32), 'hex'), 'synthetic_alpha',
   convert_to('synthetic restore payload B', 'UTF8'),
   decode(repeat('42', 32), 'hex'), 'failed', '2099-01-01 00:00:00+00');

INSERT INTO idempotency_keys (account_id, key, request_digest, message_id, expires_at)
VALUES ('11111111-1111-1111-1111-111111111111', 'synthetic-replay-key',
        decode(repeat('41', 32), 'hex'), '55555555-5555-5555-5555-555555555555',
        '2099-01-01 00:00:00+00');

INSERT INTO dispatch_jobs (message_id, account_id, device_id) VALUES
  ('55555555-5555-5555-5555-555555555555',
   '11111111-1111-1111-1111-111111111111',
   '33333333-3333-3333-3333-333333333333');

INSERT INTO message_attempts (id, account_id, message_id, device_id, generation,
                              session_epoch, deployment_epoch, status) VALUES
  ('77777777-7777-7777-7777-777777777777',
   '22222222-2222-2222-2222-222222222222',
   '66666666-6666-6666-6666-666666666666',
   '44444444-4444-4444-4444-444444444444', 1, 1, 1, 'failed');

INSERT INTO message_events (id, account_id, message_id, attempt_id, evidence_code,
                            event_digest, observed_at, resulting_state) VALUES
  ('88888888-8888-8888-8888-888888888888',
   '22222222-2222-2222-2222-222222222222',
   '66666666-6666-6666-6666-666666666666',
   '77777777-7777-7777-7777-777777777777', 'synthetic_failure',
   decode(repeat('51', 32), 'hex'), '2026-01-02 00:00:00+00', 'failed');

INSERT INTO usage_periods (account_id, metric, period_start, period_end,
                           limit_units, reserved_units, refunded_units) VALUES
  ('11111111-1111-1111-1111-111111111111', 'outbound_message',
   '2026-01-01', '2026-02-01', 10, 1, 0),
  ('22222222-2222-2222-2222-222222222222', 'outbound_message',
   '2026-01-01', '2026-02-01', 10, 1, 1);

INSERT INTO usage_ledger (account_id, message_id, metric, period_start,
                          entry_kind, units) VALUES
  ('11111111-1111-1111-1111-111111111111',
   '55555555-5555-5555-5555-555555555555', 'outbound_message',
   '2026-01-01', 'reserve', 1),
  ('22222222-2222-2222-2222-222222222222',
   '66666666-6666-6666-6666-666666666666', 'outbound_message',
   '2026-01-01', 'reserve', 1),
  ('22222222-2222-2222-2222-222222222222',
   '66666666-6666-6666-6666-666666666666', 'outbound_message',
   '2026-01-01', 'refund', -1);
COMMIT;
