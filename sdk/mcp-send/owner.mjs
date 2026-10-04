// SPDX-License-Identifier: AGPL-3.0-only
// Owner-side tool for the simulator send policy. The MCP server never imports
// this file and exposes none of these operations as tools: an agent cannot
// approve recipients, lift suppression or resolve an unknown send.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { SEND_SCOPE, SendLedger, parsePolicy, recipientDigest, writeJsonAtomic } from './guard.mjs';

const E164_RE = /^\+[1-9][0-9]{7,14}$/;

export function initPolicy(path, { agentId, deviceId, now = Date.now(), ttlMs = 60 * 60 * 1000 }) {
  const policy = {
    agentId, deviceId, recipientSalt: randomBytes(32).toString('hex'),
    grant: { scopes: [SEND_SCOPE], deviceId, agentId, issuedAtMs: now, expiresAtMs: now + ttlMs },
    approvedRecipients: [], suppressedRecipients: [],
  };
  if (!parsePolicy(policy, now)) throw new Error('invalid_policy');
  writeJsonAtomic(path, policy);
}

function edit(path, change, now) {
  const policy = JSON.parse(readFileSync(path, 'utf8'));
  change(policy);
  if (!parsePolicy(policy, now)) throw new Error('invalid_policy');
  writeJsonAtomic(path, policy);
}

const update = (list, value, add) => (add ? [...new Set([...(list ?? []), value])] : (list ?? []).filter(item => item !== value));

/** Approve (or revoke) one recipient. The owner types the number; it is never read from the agent. */
export function setApproval(path, e164, approved, now = Date.now()) {
  if (!E164_RE.test(e164)) throw new Error('invalid_recipient');
  edit(path, policy => {
    const digest = recipientDigest(policy.recipientSalt, e164);
    policy.approvedRecipients = update(policy.approvedRecipients, digest, approved);
    // Approving never silently overrides an opt-out: lift suppression only on purpose.
    if (approved && policy.suppressedRecipients?.includes(digest)) throw new Error('recipient_suppressed');
  }, now);
}

export function setSuppression(path, e164, suppressed, now = Date.now()) {
  if (!E164_RE.test(e164)) throw new Error('invalid_recipient');
  edit(path, policy => {
    const digest = recipientDigest(policy.recipientSalt, e164);
    policy.suppressedRecipients = update(policy.suppressedRecipients, digest, suppressed);
    if (suppressed) policy.approvedRecipients = update(policy.approvedRecipients, digest, false);
  }, now);
}

export function resolveUnknown(ledgerPath, key, outcome) {
  return new SendLedger(ledgerPath).resolve(key, outcome);
}

async function main(argv) {
  const [command, policyPath, ...rest] = argv;
  const usage = 'usage: owner.mjs init|approve|revoke|suppress|unsuppress <policy> [--agent ID --device ID] | resolve <ledger> <key> sent|not_sent';
  if (command === 'resolve') {
    const [key, outcome] = rest;
    if (!resolveUnknown(policyPath, key, outcome)) throw new Error('not_resolved');
    return;
  }
  if (command === 'init') {
    const flag = name => rest[rest.indexOf(name) + 1];
    initPolicy(policyPath, { agentId: flag('--agent'), deviceId: flag('--device') });
    return;
  }
  const actions = { approve: [setApproval, true], revoke: [setApproval, false], suppress: [setSuppression, true], unsuppress: [setSuppression, false] };
  if (!actions[command]) throw new Error(usage);
  // Typing the number at a terminal is the approval act; piped input from an agent shell is refused.
  if (!process.stdin.isTTY) throw new Error('interactive terminal required');
  const lines = createInterface({ input: process.stdin, output: process.stderr });
  const number = (await lines.question('Recipient (E.164): ')).trim();
  lines.close();
  actions[command][0](policyPath, number, actions[command][1]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
