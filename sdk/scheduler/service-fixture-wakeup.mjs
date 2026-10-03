// SPDX-License-Identifier: AGPL-3.0-only
// TLS fixture synchronization only; never rewrites a customer journal deadline.
import { DatabaseSync } from 'node:sqlite';
export async function waitForFixturePoll(filename, action) {
  const db = new DatabaseSync(filename, { readOnly: true });
  const started = performance.now();
  try {
    while (true) {
      const row = db.prepare('SELECT next_ms,lease_until FROM scheduled_actions WHERE action_id=?').get(action);
      if (!row || !Number.isSafeInteger(row.next_ms) || !Number.isSafeInteger(row.lease_until)) throw new Error('fixture wake unavailable');
      const now = Date.now();
      if (row.next_ms <= now && row.lease_until <= now) return;
      if (performance.now() - started >= 6000) throw new Error('fixture wake unavailable');
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  } finally { db.close(); }
}
