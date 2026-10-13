package org.zrotext.candidate;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

/** Candidate software reader. Does not acknowledge messages or authorize radio effects. */
public final class SealedReader02 {
    private SealedReader02() {}
    /** Trusted application adapter must atomically check durable current selection before plaintext release. */
    public interface CurrentSelection { boolean isCurrent(byte[] account,long version,byte[] digest,byte[] signedEnvelope); }
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Reader authority refused");}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static long number(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static byte[] find(byte[][] records,int role,byte[] id)throws GeneralSecurityException{
        for(var record:records)if(record[0]==role && same(part(record,1,32),id))return record;
        throw new GeneralSecurityException("Manifest key missing");
    }
    private static void active(byte[] record,long now)throws GeneralSecurityException{need(record[148]==1 && number(record,132)<=now && now<number(record,140));}
    public static String open(byte[] input,ManifestChain.Verified manifest,long now,int recipientRole,byte[] recipientId,
            PrivateKey recipient,CurrentSelection current)throws GeneralSecurityException{
        need(manifest!=null && manifest.profile()==2 && current!=null && now>=manifest.comparisonMs() && now<manifest.expiresMs());
        byte[] b=input.clone(),id=recipientId.clone();need(b.length>=426 && b.length<=36864 && id.length==32);
        int kind=b[5];need(kind==1 || kind==2);byte[][] records=manifest.keyRecords();
        byte[] signer=find(records,kind==1?5:4,part(b,114,32));active(signer,now);
        SignedEnvelope envelope=SignedEnvelope.verify(b,2,part(signer,33,65));
        need(same(part(b,10,16),manifest.account()) && number(b,74)==manifest.version() && same(part(b,82,32),manifest.digest()));
        need(same(part(signer,114,16),part(b,58,16)));
        if(kind==2)need(same(part(signer,98,16),part(b,42,16)));
        long observed=number(b,146);need(observed>0 && observed<=now && observed>=manifest.issuedMs() && observed<manifest.expiresMs());active(signer,observed);
        if(kind==1)need(now<number(b,154) && number(b,154)<=manifest.expiresMs());
        int prefix=10+Short.toUnsignedInt(ByteBuffer.wrap(b,8,2).getShort());
        int end=prefix+16+ByteBuffer.wrap(b,prefix+12,4).getInt();int count=b[end]&255;byte[] selected=null;
        for(int i=0;i<count;i++){
            int at=end+1+146*i,role=b[at]&255;byte[] wrapId=part(b,at+1,32),record=find(records,role,wrapId);active(record,now);active(record,observed);
            int scope=Short.toUnsignedInt(ByteBuffer.wrap(record,130,2).getShort());need((scope&(kind==1?4:8))!=0);
            if(role==1)need(kind==1 && same(part(record,98,16),part(b,42,16)) && same(part(record,114,16),part(b,58,16)));
            if(role==recipientRole && same(wrapId,id))selected=record;
        }
        need(selected!=null);need(current.isCurrent(manifest.account(),manifest.version(),manifest.digest(),b.clone()));
        byte[] cek=null;
        try{
            cek=HpkeRecipient.open(recipient,part(selected,33,65),envelope.encapsulated(recipientRole,id),envelope.wrapInfo(recipientRole,id),envelope.wrapAad(recipientRole,id),envelope.wrappedKey(recipientRole,id));
            String result=CandidateBody.open(cek,envelope.nonce(),envelope.bodyAad(),envelope.bodyCiphertext());
            need(current.isCurrent(manifest.account(),manifest.version(),manifest.digest(),b.clone()));return result;
        }finally{if(cek!=null)Arrays.fill(cek,(byte)0);}
    }
}
