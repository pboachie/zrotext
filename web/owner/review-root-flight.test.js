// SPDX-License-Identifier: AGPL-3.0-only
const { test } = require('node:test');
const assert = require('node:assert/strict');
const create = async () => (await import('../review/single-flight.mjs')).createReviewFlight();
const id = '10000000-0000-4000-8000-000000000001';
const other = '10000000-0000-4000-8000-000000000002';
test('pause acknowledgement waits for the actual outstanding request', async () => {
  const flight = await create();
  let finish;
  const running = flight.run(() => new Promise((resolve) => { finish = resolve; }));
  assert.equal(flight.requestPause(id), true);
  assert.equal(flight.pauseStatus(id).state, 'waiting');
  assert.equal(flight.requestPause(other), false);
  assert.equal(flight.resume(id), false);
  await assert.rejects(flight.run(() => 'new request'));
  finish('original result');
  assert.equal(await running, 'original result');
  assert.deepEqual(flight.pauseStatus(id), { version: 1, request_id: id, state: 'paused' });
  assert.equal(flight.pauseStatus(other), null);
  assert.equal(flight.resume(other), false);
  assert.equal(flight.resume(id), true);
  assert.equal(await flight.run(() => 'next request'), 'next request');
});
test('failed requests release the flight but preserve requested pause', async () => {
  const flight = await create();
  await assert.rejects(flight.run(async () => {
    flight.requestPause(id);
    throw new Error('synthetic transport uncertainty');
  }));
  assert.equal(flight.pauseStatus(id).state, 'paused');
  await assert.rejects(flight.run(() => 'retry'));
  assert.equal(flight.resume(id), true);
  assert.equal(flight.requestPause('abcdef00-0000-4000-8000-000000000001'.toUpperCase()), false);
  assert.equal(flight.requestPause('00000000-0000-0000-0000-000000000000'), false);
});
