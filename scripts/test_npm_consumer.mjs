// Exercise the exact packed artifact in a disposable consumer, without scripts.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

const [tarball, compiler] = process.argv.slice(2);
assert(tarball && compiler && isAbsolute(tarball) && isAbsolute(compiler), "provide absolute tarball and locked tsc paths");
assert(existsSync(tarball) && existsSync(compiler), "tarball and compiler must exist");
assert(Number(process.versions.node.split(".")[0]) >= 24, "consumer check requires Node >=24");
const directory = join(tmpdir(), "zrotext-npm-consumer-" + randomUUID());
mkdirSync(directory);
try {
  writeFileSync(join(directory, "package.json"), JSON.stringify({ private: true, type: "module" }));
  // Windows invokes npm's JS entry directly; avoid a shell handling input paths.
  const installArgs = ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline", "--cache", join(directory, "cache"), tarball];
  if (process.platform === "win32") {
    const npmCli = process.env.npm_execpath ?? join(process.execPath, "..", "node_modules", "npm", "bin", "npm-cli.js");
    execFileSync(process.execPath, [npmCli, ...installArgs], { cwd: directory, stdio: "pipe" });
  } else {
    execFileSync("npm", installArgs, { cwd: directory, stdio: "pipe" });
  }
  writeFileSync(join(directory, "consumer.mjs"), `
import assert from 'node:assert/strict';
import { AlphaClient, AlphaApiError, AlphaOutcomeUnknownError, requiresReconciliation,
  signWebhook, verifyWebhook, secretFromBase64Url, WebhookVerificationError } from 'zrotext';
assert.equal(typeof AlphaApiError, 'function');
assert.equal(typeof AlphaOutcomeUnknownError, 'function');
assert.equal(requiresReconciliation('unknown'), true);
assert.equal(requiresReconciliation('delivery_unknown'), true);
assert.equal(requiresReconciliation('submitted'), false);
let calls = 0;
const client = new AlphaClient({baseUrl:'https://example.invalid',apiKey:'synthetic-test',fetch: async () => { calls++; throw new Error('synthetic outage'); }});
await assert.rejects(client.getStatus('00000000-0000-0000-0000-000000000001'), AlphaOutcomeUnknownError);
assert.equal(calls,1);
const key = secretFromBase64Url('c3ludGhldGljLXRlc3Q');
const body = new TextEncoder().encode('{"id":"synthetic-event"}');
const signature = await signWebhook(key,1000,body);
await verifyWebhook({signingKey:key,timestamp:'1000',signature,body,nowSeconds:1000});
await assert.rejects(verifyWebhook({signingKey:key,timestamp:'1000',signature,body:'changed',nowSeconds:1000}), WebhookVerificationError);
await assert.rejects(import('zrotext/dist/index.js'), {code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
await assert.rejects(import('zrotext/dist/sealed.js'), {code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
`);
  execFileSync(process.execPath, [join(directory, "consumer.mjs")], { cwd: directory, stdio: "inherit" });
  writeFileSync(join(directory, "consumer.ts"), `
import { AlphaClient, type AlphaSubmitRequest, type AlphaStatus, type VerifyWebhookInput, requiresReconciliation, verifyWebhook } from 'zrotext';
const client: AlphaClient = new AlphaClient({baseUrl:'https://example.invalid',apiKey:'synthetic-test'});
const status: Promise<AlphaStatus> = client.getStatus('00000000-0000-0000-0000-000000000001');
const submit = (request: AlphaSubmitRequest) => client.submit(request,'same-key');
const verify = (input: VerifyWebhookInput): Promise<void> => verifyWebhook(input);
// @ts-expect-error sealed internals are excluded from the public exports map
import type { SealedClient } from 'zrotext/dist/sealed.js';
requiresReconciliation('unknown');
void status; void submit; void verify;
`);
  execFileSync(process.execPath, [compiler, "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", "consumer.ts"], { cwd: directory, stdio: "inherit" });
  console.log("Packed artifact consumer runtime, types, webhook and export-boundary checks passed");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
