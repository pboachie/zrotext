// SPDX-License-Identifier: AGPL-3.0-only
// @ts-check
import {contactDomainASCII16} from './contact-idna16.js';

/** Canonical historical contact origins with versioned UTS46 validation.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalContactOrigin01(value) {
  if(typeof value!=='string'||value.length<9||value.length>512||/[^\x21-\x7e]/.test(value))throw Error('Contact origin refused');
  let candidate=value;
  const domain=/^https:\/\/([^:/?#@\[\]\\]+)(?::([0-9]+))?$/.exec(value);
  if(domain&&domain[1].split('.').some(label=>label.startsWith('xn--'))){
    const host=domain[1];
    if(contactDomainASCII16(host)!==host)throw Error('Contact A-label refused');
    // Validate the remaining URL syntax without handing A-label acceptance to
    // a runtime-dependent ASCII fast path or a different Unicode table.
    candidate='https://'+host.split('.').map(label=>label.startsWith('xn--')?'idna-label':label).join('.')+(domain[2]===undefined?'':':'+domain[2]);
  }
  const url=new URL(candidate);
  if(url.protocol!=='https:'||url.origin!==candidate||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('Contact origin refused');
  return value;
}
