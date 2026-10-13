package org.zrotext.candidate;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Candidate ZTWT01 client encryption; no network, save, or dispatch authority. */
public final class EncryptedTemplate {
    private EncryptedTemplate(){}
    private static final byte[] DOMAIN="ZT/workflow-template/hpke/v1\0".getBytes(StandardCharsets.US_ASCII);
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Encrypted template refused");}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static long number(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static byte[] join(byte[]... values){int length=0;for(var v:values)length+=v.length;byte[] out=new byte[length];int at=0;for(var v:values){System.arraycopy(v,0,out,at,v.length);at+=v.length;}return out;}
    /** Independently expected context, captured before callbacks. Never derive it from untrusted ciphertext. */
    public static final class Scope {
        private final byte[] aad;
        public Scope(byte[] expectedAad)throws GeneralSecurityException{
            need(expectedAad!=null && expectedAad.length==222);byte[] b=expectedAad.clone();need(same(part(b,0,6),new byte[]{90,84,87,84,1,1}));
            for(int at:new int[]{6,22,38,54,70})need(!same(part(b,at,16),new byte[16]));for(int at:new int[]{86,94,102,110,118})need(number(b,at)>0);need(number(b,94)<=128);
            for(int at:new int[]{126,158,190})need(!same(part(b,at,32),new byte[32]));aad=b;
        }
        public static Scope capture(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] template,long binding,long revision,long expires,long trust,long version,byte[] peerDigest,byte[] reader,byte[] manifestDigest)throws GeneralSecurityException{
            for(var b:new byte[][]{account,device,line,interval,template})need(b.length==16);for(var b:new byte[][]{peerDigest,reader,manifestDigest})need(b.length==32);
            return new Scope(join(new byte[]{90,84,87,84,1,1},account,device,line,interval,template,ByteBuffer.allocate(40).putLong(binding).putLong(revision).putLong(expires).putLong(trust).putLong(version).array(),peerDigest,reader,manifestDigest));
        }
        public byte[] aad(){return aad.clone();}
    }
    public record Authority(ManifestChain.Verified manifest,long nowMs){}
    /** Application source must consult its current permission/selection; signed history alone is insufficient. */
    public interface AuthoritySource {Authority current()throws GeneralSecurityException;}
    private static boolean active(byte[] key,long now,int permission){return key[148]==1 && number(key,132)<=now && now<number(key,140) && (Short.toUnsignedInt(ByteBuffer.wrap(key,130,2).getShort())&permission)!=0;}
    private static byte[] authorize(Authority a,byte[] aad)throws GeneralSecurityException{
        need(a!=null && a.manifest()!=null && a.nowMs()>0 && a.manifest().profile()==2);var m=ManifestChain.continueChain(a.manifest().bytes(),a.manifest(),2,a.nowMs());long expires=number(aad,102);
        need(expires>a.nowMs() && expires-a.nowMs()<=(30L*86400000) && same(m.account(),part(aad,6,16)) && m.generation()==number(aad,110) && m.version()==number(aad,118) && same(m.digest(),part(aad,190,32)));
        byte[] reader=null;boolean signer=false;for(var key:m.keyRecords()){
            if(key[0]==2 && same(part(key,1,32),part(aad,158,32)) && active(key,a.nowMs(),8))reader=part(key,33,65);
            if(key[0]==4 && same(part(key,98,16),part(aad,22,16)) && same(part(key,114,16),part(aad,38,16)) && active(key,a.nowMs(),2) && ByteBuffer.wrap(key,130,2).getShort()==2)signer=true;
        }need(reader!=null && signer);return reader;
    }
    private static void finalCheck(Authority before,byte[] point,byte[] aad,AuthoritySource source)throws GeneralSecurityException{
        var after=source.current();byte[] current=authorize(after,aad);need(after.nowMs()>=before.nowMs() && same(point,current) && same(before.manifest().rootPoint(),after.manifest().rootPoint()) && same(before.manifest().enrolledRootPoint(),after.manifest().enrolledRootPoint()));
    }
    public static byte[] seal(Scope scope,TemplateContent content,AuthoritySource source)throws GeneralSecurityException{
        byte[] plain=null;try{byte[] aad=scope.aad();plain=content.canonical();need(plain.length>=1 && plain.length<=32768);var before=source.current();byte[] point=authorize(before,aad),wrapped=HpkeRecipient.sealContent(point,join(DOMAIN,aad),aad,plain);need(wrapped.length==65+plain.length+16);byte[] out=join(aad,part(wrapped,0,65),ByteBuffer.allocate(4).putInt(wrapped.length-65).array(),part(wrapped,65,wrapped.length-65));finalCheck(before,point,aad,source);return out;}
        finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    public static TemplateContent open(Scope scope,byte[] envelope,HpkeRecipient.ContentRecipient recipient,AuthoritySource source)throws GeneralSecurityException{
        byte[] plain=null;try{
            need(envelope!=null && envelope.length>=308 && envelope.length<=33075);byte[] wire=envelope.clone(),aad=scope.aad();need(same(part(wire,0,222),aad) && ByteBuffer.wrap(wire,287,4).getInt()==wire.length-291);var before=source.current();byte[] point=authorize(before,aad);
            plain=recipient.openContent(point,part(wire,222,65),join(DOMAIN,aad),aad,part(wire,291,wire.length-291));need(plain.length>=1 && plain.length<=32768);finalCheck(before,point,aad,source);return TemplateContent.parse(plain);
        }catch(TemplateContent.Failure error){throw new GeneralSecurityException("Encrypted template refused");}
        finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    /** Digest of transport bytes only, not plaintext or authority. */
    public static byte[] digest(byte[] envelope)throws GeneralSecurityException{need(envelope.length>=308 && envelope.length<=33075);return MessageDigest.getInstance("SHA-256").digest(envelope.clone());}
}
