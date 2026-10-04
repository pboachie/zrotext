// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { rawParse, proposalParse, canonical, nested } from '../test-support/proposed-provider-action.mjs';
import { canonicalWorkflowAction } from '../dist/workflow-decisions.js';
import { validateWorkflowRequest } from '../dist/workflow-tools.js';

const vectors = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-02-proposal.json',import.meta.url)));
test('proposed provider descriptor and whole request match independent canonical vectors',()=>{
  let count=0;
  for(const v of [...vectors.positives,...vectors.binding_mutations]){
    const wire=v.canonical ?? canonical(v.descriptor);
    const parsed=rawParse(wire);
    assert.equal(canonical(parsed),wire);
    assert.equal(createHash('sha256').update(wire).digest('hex'),v.binding_digest);
    if(v.field) assert.notEqual(v.binding_digest,vectors.positives[1].binding_digest);
    assert.equal(canonical(proposalParse(nested(wire))),wire);
    count++;
  }
  assert.equal(count,37);
  assert.notEqual(vectors.positives[0].binding_digest,vectors.positives[1].binding_digest);
});
test('original standalone and nested wire refuse aliases, fields, numbers and size limits',()=>{
  let count=0;
  for(const v of [...vectors.negative_grammar,...vectors.negative_wire]){
    const wire=v.raw ?? canonical(v.input);
    assert.throws(()=>rawParse(wire),v.name);
    assert.throws(()=>proposalParse(nested(wire)),v.name);
    count++;
  }
  assert.equal(count,24);
  const base=vectors.positives[0].canonical;
  for(const wire of [
    base.slice(0,-1)+String.raw`,"\u0070rofile":"workflow-action-02"}`,
    base.replace('"profile":',String.raw`"\u0070rofile":`),
  ]){
    assert.throws(()=>rawParse(wire));
    assert.throws(()=>proposalParse(nested(wire)));
    count++;
  }
  assert.equal(count,26);
});
test('whole request refuses outer whitespace, escaped and duplicated aliases and cap',()=>{
  const descriptor=vectors.positives[0].canonical;
  const outer=nested(descriptor);
  const cases=[
    ' '+outer,
    outer.replace('"request_id":','"\\u0072equest_id":'),
    outer.replace('{"descriptor":','{"descriptor":'+descriptor+',"descriptor":'),
    outer.replace('{"descriptor":','{"\\u0064escriptor":'+descriptor+',"descriptor":'),
    outer.replace('{"descriptor":','{"descriptor_alias":'+descriptor+',"descriptor":'),
    outer.replace('"request_id":','"request_id":"00000000-0000-0000-0000-000000000002","request_id":'),
    ' '.repeat(8193-Buffer.byteLength(outer))+outer,
  ];
  assert.equal(cases.length,7);
  for(const wire of cases) assert.throws(()=>proposalParse(wire));
});
test('actual legacy SDK descriptor and workflow tool validators reject the proposed profile',()=>{
  for(const v of vectors.positives){
    assert.throws(()=>canonicalWorkflowAction(v.descriptor));
    assert.throws(()=>validateWorkflowRequest('workflow.action.propose',{
      request_id:'00000000-0000-0000-0000-000000000001',descriptor:v.descriptor,
    }));
    assert.doesNotThrow(()=>canonicalWorkflowAction(v.descriptor.action));
    assert.doesNotThrow(()=>validateWorkflowRequest('workflow.action.propose',{
      request_id:'00000000-0000-0000-0000-000000000001',descriptor:v.descriptor.action,
    }));
  }
});
