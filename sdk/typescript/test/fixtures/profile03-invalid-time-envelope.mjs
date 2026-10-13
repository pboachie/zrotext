// TEST ONLY: deliberately bypass policy to exercise reader authorization.
// Never import this encoder into runtime code. Keys are fresh synthetic software keys.
import { enc, join, u16, u32, u64, sha, sign, suite, inputFor, verifyAndOpen } from './profile03-outbound-fixture.mjs';

export async function encodeReaderCase(f, policy) {
  const input = inputFor(f), bound = f.authority;
  const protectedBytes = join(bound.accountId, input.messageId, bound.deviceId, bound.lineId,
    u64(bound.manifestVersion), bound.manifestDigest, f.records[4].id,
    u64(BigInt(policy.observed_ms)), u64(BigInt(policy.expires_ms)), Uint8Array.of(1, input.peer.length), input.peer);
  const prefix = join(enc.encode('ZTSE'), Uint8Array.of(3,1,0,0), u16(protectedBytes.length), protectedBytes);
  const cek = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
    const body = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,
      additionalData:join(enc.encode('ZTSE/body/v3\0'),prefix)},aes,enc.encode(input.content)));
    const wraps = [];
    for (const r of f.records.filter(r=>r.role<=3).sort((a,b)=>a.role-b.role)) {
      const suffix = join(prefix,Uint8Array.of(r.role),r.id);
      const sender = await suite.createSenderContext({recipientPublicKey:await suite.kem.deserializePublicKey(r.k.point),
        info:join(enc.encode('ZTSE/wrap/v3\0'),suffix)});
      const ciphertext = new Uint8Array(await sender.seal(cek,join(enc.encode('ZTSE/wrap-aad/v3\0'),suffix)));
      wraps.push(join(Uint8Array.of(r.role),r.id,new Uint8Array(sender.enc),ciphertext));
    }
    const unsigned = join(prefix,nonce,u32(body.length),body,Uint8Array.of(wraps.length),...wraps);
    const envelope = join(unsigned,await sign(f.records[4].k,'ZTSE/sign/v3',unsigned));
    const result = {envelope,unsignedDigest:await sha(unsigned),envelopeDigest:await sha(envelope)};
    // Even policy-invalid cases must have an authentic signature and all three
    // complete, mutually matching HPKE/AES transcripts, not just a re-signed header.
    await verifyAndOpen(f,result,input.content);
    return envelope;
  } finally { cek.fill(0); }
}
