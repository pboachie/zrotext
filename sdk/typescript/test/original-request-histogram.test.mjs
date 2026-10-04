// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import {RequestHistogram} from './original-request-histogram.mjs';
test('fixed operation totals preserve cumulative successful request costs',()=>{const h=new RequestHistogram();h.record('routine_current',1300.9);h.record('routine_current',900);h.record('original_read',75);assert.equal(h.failureLines(),'original routine requests original_read=1,75,75 routine_current=2,2200,1300\n');});
test('unknown canaries and malformed numeric values never become output',()=>{const h=new RequestHistogram();h.record('synthetic-private-canary',1);for(const value of [NaN,Infinity,-1])h.record('routine_current',value);assert.equal(h.failureLines(),'');});
test('counts and duration aggregates remain bounded',()=>{const h=new RequestHistogram();for(let i=0;i<100;i++)h.record('call_current',70000);assert.equal(h.failureLines(),'original routine requests call_current=64,60000,60000\n');});
