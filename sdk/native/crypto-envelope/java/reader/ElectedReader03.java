package org.zrotext.candidate;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Software native elected reader. Returns text, never an SMS grant or replay receipt. */
public final class ElectedReader03 {
    private ElectedReader03() {}
    public record AuthoritySnapshot(Map<String,?> authenticatedRecord,long nowMs) {}
    public interface AuthoritySource {AuthoritySnapshot read()throws GeneralSecurityException;}
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Elected reader refused");}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static long number(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static byte[] find(byte[][] records,int role,byte[] id)throws GeneralSecurityException{for(var r:records)if(r[0]==role && same(part(r,1,32),id))return r;throw new GeneralSecurityException("Elected key missing");}
    private static void active(byte[] r,long when)throws GeneralSecurityException{need(r[148]==1 && number(r,132)<=when && when<number(r,140));}
    public static String openSoftware(byte[] input,ManifestChain.Verified manifest,Election03.Proof proof,AuthoritySource source,
            byte[] expectedMessage,String expectedPeer,PrivateKey recipient)throws GeneralSecurityException{
        return openWithRecipient(input,manifest,proof,source,expectedMessage,expectedPeer,HpkeRecipient.software(recipient));
    }
    public static String openWithRecipient(byte[] input,ManifestChain.Verified manifest,Election03.Proof proof,AuthoritySource source,
            byte[] expectedMessage,String expectedPeer,HpkeRecipient.Recipient recipient)throws GeneralSecurityException{
        byte[] b=input.clone(),message=expectedMessage.clone();String peer=expectedPeer;need(b.length>=557 && b.length<=34213 && message.length==16 && !Arrays.equals(message,new byte[16]));
        AuthoritySnapshot snapshot=source.read();long now=snapshot.nowMs();var authority=Election03.requireCurrent(proof,manifest,snapshot.authenticatedRecord(),now);
        need(b[4]==3 && b[5]==1 && same(part(b,10,16),authority.field("accountId")) && same(part(b,26,16),message) && same(part(b,42,16),authority.field("deviceId")) && same(part(b,58,16),authority.field("lineId")));
        need(number(b,74)==manifest.version() && same(part(b,82,32),manifest.digest()));
        byte[][] records=manifest.keyRecords();byte[] signer=find(records,5,part(b,114,32));active(signer,now);
        need(same(part(signer,114,16),authority.field("lineId")));
        SignedEnvelope envelope=SignedEnvelope.verify(b,3,part(signer,33,65));int prefix=10+Short.toUnsignedInt(ByteBuffer.wrap(b,8,2).getShort());
        need(new String(part(b,164,prefix-164),StandardCharsets.US_ASCII).equals(peer));
        long observed=number(b,146),expires=number(b,154);need(observed>0 && observed<=now && observed>=manifest.issuedMs() && now<expires && expires<=manifest.expiresMs() && expires<=authority.number("permissionExpiresAtMs"));active(signer,observed);need(expires<=number(signer,140));
        int end=prefix+16+ByteBuffer.wrap(b,prefix+12,4).getInt();byte[] elected=authority.field("selectedReaderKeyId"),selected=null;
        for(int i=0;i<(b[end]&255);i++){
            int at=end+1+146*i,role=b[at]&255;byte[] id=part(b,at+1,32),record=find(records,role,id);active(record,now);active(record,observed);
            need((Short.toUnsignedInt(ByteBuffer.wrap(record,130,2).getShort())&4)!=0 && expires<=number(record,140));
            if(role==1){need(same(id,elected) && same(part(record,98,16),authority.field("deviceId")) && same(part(record,114,16),authority.field("lineId")));selected=record;}
        }
        need(selected!=null);byte[] cek=null;
        try{
            cek=recipient.unwrap(part(selected,33,65),envelope.encapsulated(1,elected),envelope.wrapInfo(1,elected),envelope.wrapAad(1,elected),envelope.wrappedKey(1,elected));
            String result=CandidateBody.open(cek,envelope.nonce(),envelope.bodyAad(),envelope.bodyCiphertext());
            AuthoritySnapshot after=source.read();need(after.nowMs()>=now && after.nowMs()<expires);Election03.requireCurrent(proof,manifest,after.authenticatedRecord(),after.nowMs());return result;
        }finally{if(cek!=null)Arrays.fill(cek,(byte)0);}
    }
}
