// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import punycodeModule from 'punycode/punycode.js';
import tr46 from 'tr46';
import {canonicalContactOrigin01 as origin} from '../dist/contact-origin.js';
const {encode:punycode}=punycodeModule;

test('contact origins reject malformed A-labels without rejecting valid international hosts',()=>{
  for(const host of ['xn--','xn---','xn--abc-','xn--a','xn--0','xn--xn--a--gua','xn--xn---epa',
    'xn--ab-j1t','xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz']){
    assert.throws(()=>origin('https://'+host+'.invalid'),host);
  }
  for(const value of ['https://xn--fa-hia.invalid','https://xn--bcher-kva.invalid',
    'https://xn--ls8h.example','https://xn--fa-hia.invalid:8443','https://synthetic.invalid',
    'https://a..b','https://.example','https://example.','https://[::1]'])assert.equal(origin(value),value);
  for(const value of ['http://synthetic.invalid','https://SYNTHETIC.invalid','https://synthetic.invalid/',
    'https://synthetic.invalid:443',
    'https://user@synthetic.invalid',
    'https://synthetic.invalid?',
    'https://synthetic.invalid#','https://synthetic.invalid/path','https://faß.invalid'])assert.throws(()=>origin(value),value);
});

test('generated browser validator matches locked Unicode 16 UTS46 across scalar and contextual cases',()=>{
  // The unmodified upstream package checks our browser artifact transformation.
  const labels=['faß','bücher','a\u200cb','a\u200db','a\u0300','\u0300ab','\u200c','xn--é'];
  // Exercise every endpoint/interior value in the upstream astral mark range
  // whose generated escape spelling differs from the original package.
  for(let code=0x1daa1;code<=0x1daaf;code++){
    const mark=String.fromCodePoint(code);labels.push('a'+mark+'b',mark+'ab');
  }
  for(let code=128;code<0x110000;code+=257)if(code<0xd800||code>0xdfff)labels.push('a'+String.fromCodePoint(code)+'b');
  for(const label of labels){
    const value='https://xn--'+punycode(label)+'.invalid';
    const host=value.slice(8),expected=tr46.toASCII(host,{checkBidi:true,checkJoiners:true})===host;
    if(expected)assert.equal(origin(value),value,label);
    else assert.throws(()=>origin(value),label);
  }
});
