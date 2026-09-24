-- SPDX-License-Identifier: AGPL-3.0-only
-- Run against both the stopped source and the database-only restore target.
DO $$
BEGIN
  IF (SELECT count(*) FROM accounts) <> 2
    OR (SELECT count(*) FROM devices) <> 2
    OR (SELECT count(*) FROM device_keys) <> 2
    OR (SELECT count(*) FROM messages) <> 2
    OR (SELECT count(*) FROM message_attempts) <> 1
    OR (SELECT count(*) FROM dispatch_jobs) <> 1
    OR (SELECT count(*) FROM usage_ledger) <> 3
    OR NOT EXISTS (
      SELECT 1 FROM devices d JOIN device_keys k ON k.device_id = d.id
      WHERE d.id = '33333333-3333-3333-3333-333333333333'
        AND d.account_id = '11111111-1111-1111-1111-111111111111'
        AND d.revoked_at IS NULL AND k.revoked_at IS NULL
        AND k.fingerprint = decode(repeat('11', 32), 'hex'))
    OR NOT EXISTS (
      SELECT 1 FROM devices d JOIN device_keys k ON k.device_id = d.id
      WHERE d.id = '44444444-4444-4444-4444-444444444444'
        AND d.account_id = '22222222-2222-2222-2222-222222222222'
        AND d.revoked_at = '2026-01-02 00:00:00+00'
        AND k.revoked_at = d.revoked_at
        AND k.fingerprint = decode(repeat('22', 32), 'hex'))
    OR NOT EXISTS (
      SELECT 1 FROM messages m JOIN dispatch_jobs j ON j.message_id = m.id
      JOIN idempotency_keys i ON i.message_id = m.id
      WHERE m.id = '55555555-5555-5555-5555-555555555555'
        AND m.account_id = '11111111-1111-1111-1111-111111111111'
        AND m.recipient_e164 = '+15555550100'
        AND m.transport_payload = convert_to('synthetic restore payload A', 'UTF8')
        AND m.state = 'queued' AND j.grant_issued_at IS NULL
        AND i.key = 'synthetic-replay-key'
        AND i.request_digest = m.request_digest)
    OR NOT EXISTS (
      SELECT 1 FROM messages m JOIN message_attempts a ON a.message_id = m.id
      JOIN message_events e ON e.attempt_id = a.id
      WHERE m.id = '66666666-6666-6666-6666-666666666666'
        AND m.account_id = '22222222-2222-2222-2222-222222222222'
        AND m.recipient_e164 = '+15555550101'
        AND m.transport_payload = convert_to('synthetic restore payload B', 'UTF8')
        AND m.state = 'failed' AND a.status = 'failed'
        AND e.resulting_state = 'failed'
        AND e.event_digest = decode(repeat('51', 32), 'hex'))
    OR NOT EXISTS (
      SELECT 1 FROM usage_periods p JOIN usage_ledger l
        ON (l.account_id, l.metric, l.period_start) =
           (p.account_id, p.metric, p.period_start)
      WHERE p.account_id = '11111111-1111-1111-1111-111111111111'
        AND p.reserved_units = 1 AND p.refunded_units = 0
        AND l.entry_kind = 'reserve' AND l.units = 1)
    OR NOT EXISTS (
      SELECT 1 FROM usage_periods p JOIN usage_ledger l
        ON (l.account_id, l.metric, l.period_start) =
           (p.account_id, p.metric, p.period_start)
      WHERE p.account_id = '22222222-2222-2222-2222-222222222222'
        AND p.reserved_units = 1 AND p.refunded_units = 1
        AND l.entry_kind = 'refund' AND l.units = -1)
  THEN
    RAISE EXCEPTION 'synthetic restore fixture mismatch';
  END IF;
END
$$;
