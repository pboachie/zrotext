#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { configuredClient } from '../../mcp/server.mjs';
import { createSession } from './adapter.mjs';

/** Bounded local newline-delimited MCP transport. No HTTP listener exists. */
export async function serve(input, write, session) {
  let pending = Buffer.alloc(0);
  const send = async response => {
    if (response === undefined) return;
    let value = JSON.stringify(response);
    if (Buffer.byteLength(value) > 262144) value = JSON.stringify({ jsonrpc: '2.0', id: response.id,
      error: { code: -32603, message: 'Response unavailable' } });
    await write(value + '\n');
  };
  try {
    for await (const chunk of input) {
      pending = Buffer.concat([pending, chunk]);
      let end;
      while ((end = pending.indexOf(10)) !== -1) {
        const line = pending.subarray(0, end);
        pending = pending.subarray(end + 1);
        if (line.length > 65536) throw new Error('Frame too large');
        let response;
        try { response = await session(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line))); }
        catch { response = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }; }
        await send(response);
      }
      if (pending.length > 65536) throw new Error('Frame too large');
    }
    if (pending.length) await send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Unterminated message' } });
  } finally { pending.fill(0); }
}

async function main() {
  if (process.argv.length !== 2 || (process.env.ZROTEXT_MCP_MODE && process.env.ZROTEXT_MCP_MODE !== 'stdio')) {
    process.stderr.write('Only local stdio is supported.\n');
    process.exitCode = 2;
    return;
  }
  try {
    const manifest = JSON.parse(await readFile(new URL('../generated/mcp/manifest.json', import.meta.url), 'utf8'));
    const session = createSession(manifest, { client: await configuredClient() });
    await serve(process.stdin, async text => {
      if (!process.stdout.write(text)) await new Promise(resolve => process.stdout.once('drain', resolve));
    }, session);
  } catch {
    process.stderr.write('Generated workflow adapter unavailable.\n');
    process.exitCode = 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
