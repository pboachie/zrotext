package org.zrotext.candidate;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Fresh profile02 candidate bytes; never live transport permission. */
public final class Compose02 {
    private Compose02(){}
    public record Recipient(int role,byte[] id){}
    public record Request(ManifestChain.Verified manifest,long nowMs,byte[] message,byte[] device,byte[] line,
        long observedMs,long expiresMs,String peer,String content,ProtectedSigner signer,List<Recipient> recipients){}
    private record Target(int role,byte[] id,byte[] point){}
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Candidate composition refused");}
    private static byte[] join(byte[]... values){int size=0;for(var v:values)size+=v.length;byte[] out=new byte[size];int at=0;for(var v:values){System.arraycopy(v,0,out,at,v.length);at+=v.length;}return out;}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static byte[] label(String s){return (s+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] u64(long n){return ByteBuffer.allocate(8).putLong(n).array();}
    private static long num(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static int scope(byte[] b){return Short.toUnsignedInt(ByteBuffer.wrap(b,130,2).getShort());}
    private static byte[] text(String value)throws GeneralSecurityException{
        need(!value.isEmpty() && value.length()<=32768);
        try{var encoded=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));byte[] result=new byte[encoded.remaining()];encoded.get(result);if(encoded.hasArray())Arrays.fill(encoded.array(),(byte)0);return result;}
        catch(CharacterCodingException e){throw new GeneralSecurityException("Strict text refused",e);}
    }
    private static byte[] find(byte[][] keys,int role,byte[] id)throws GeneralSecurityException{for(var key:keys)if(key[0]==role && same(part(key,1,32),id))return key;throw new GeneralSecurityException("Manifest key missing");}
    private static byte[] mac(byte[] key,byte[] data)throws GeneralSecurityException{var mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key.length==0?new byte[32]:key,"HmacSHA256"));return mac.doFinal(data);}
    private static byte[] extract(byte[] suite,byte[] salt,String label,byte[] data)throws GeneralSecurityException{return mac(salt,join("HPKE-v1".getBytes(StandardCharsets.US_ASCII),suite,label.getBytes(StandardCharsets.US_ASCII),data));}
    private static byte[] expand(byte[] suite,byte[] key,String label,byte[] info,int size)throws GeneralSecurityException{byte[] block=mac(key,join(new byte[]{0,(byte)size},"HPKE-v1".getBytes(StandardCharsets.US_ASCII),suite,label.getBytes(StandardCharsets.US_ASCII),info,new byte[]{1}));try{return Arrays.copyOf(block,size);}finally{Arrays.fill(block,(byte)0);}}
    private static byte[] encrypt(byte[] key,byte[] nonce,byte[] text,byte[] aad)throws GeneralSecurityException{var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);return cipher.doFinal(text);}
    private static byte[] point(ECPublicKey key){byte[] b=new byte[65];b[0]=4;byte[] x=key.getW().getAffineX().toByteArray(),y=key.getW().getAffineY().toByteArray();int nx=Math.min(32,x.length),ny=Math.min(32,y.length);System.arraycopy(x,x.length-nx,b,33-nx,nx);System.arraycopy(y,y.length-ny,b,65-ny,ny);return b;}
    private static byte[] wrap(byte[] point,byte[] cek,byte[] info,byte[] aad)throws GeneralSecurityException{
        var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));var ephemeral=generator.generateKeyPair();byte[] enc=point((ECPublicKey)ephemeral.getPublic()),kem={75,69,77,0,16},suite={72,80,75,69,0,16,0,1,0,1},empty=new byte[0];byte[][] buffers=new byte[6][];
        try{var dh=KeyAgreement.getInstance("ECDH");dh.init(ephemeral.getPrivate());dh.doPhase(HpkeRecipient.point(point),true);buffers[0]=dh.generateSecret();need(buffers[0].length==32);
            buffers[1]=extract(kem,empty,"eae_prk",buffers[0]);buffers[2]=expand(kem,buffers[1],"shared_secret",join(enc,point),32);
            byte[] context=join(new byte[]{0},extract(suite,empty,"psk_id_hash",empty),extract(suite,empty,"info_hash",info));buffers[3]=extract(suite,buffers[2],"secret",empty);buffers[4]=expand(suite,buffers[3],"key",context,16);buffers[5]=expand(suite,buffers[3],"base_nonce",context,12);
            return join(enc,encrypt(buffers[4],buffers[5],cek,aad));
        }finally{for(var b:buffers)if(b!=null)Arrays.fill(b,(byte)0);}
    }
    public static byte[] fresh(Request input)throws GeneralSecurityException{
        need(input.message.length==16 && input.device.length==16 && input.line.length==16 && input.recipients.size()>=2 && input.recipients.size()<=8);
        var recipients=new ArrayList<Recipient>();for(var v:input.recipients){need(v.role>=1 && v.role<=3 && v.id.length==32);recipients.add(new Recipient(v.role,v.id.clone()));}
        var r=new Request(input.manifest,input.nowMs,input.message.clone(),input.device.clone(),input.line.clone(),input.observedMs,input.expiresMs,input.peer,input.content,input.signer,List.copyOf(recipients));
        need(r.manifest.profile()==2 && r.nowMs>=0 && r.observedMs>=0 && r.expiresMs>r.observedMs && r.expiresMs-r.observedMs<=900000);
        var current=ManifestChain.continueChain(r.manifest.bytes(),r.manifest,2,r.nowMs);
        need(r.peer.matches("\\+[1-9][0-9]{1,14}"));byte[] text=text(r.content),cek=null;
        try{
            need(text.length>=1 && text.length<=32768 && !(text.length>=3 && text[0]==(byte)239 && text[1]==(byte)187 && text[2]==(byte)191));for(byte b:text)need(b!=0);
            byte[] publicPoint=r.signer.publicPoint(),signerId=sha(join(label("ZTSE/key/v1"),new byte[]{1,1},publicPoint));byte[][] keys=current.keyRecords();byte[] signer=find(keys,5,signerId);
            need(signer[148]==1 && num(signer,132)<=r.nowMs && r.nowMs<num(signer,140) && scope(signer)==1 && same(part(signer,114,16),r.line) && same(part(signer,33,65),publicPoint));
            recipients.sort(Comparator.comparingInt(Recipient::role).thenComparing(v->HexFormat.of().formatHex(v.id)));
            need(recipients.stream().filter(v->v.role==1).count()==1 && recipients.stream().filter(v->v.role==2).count()==1);var unique=new HashSet<String>();var targets=new ArrayList<Target>();
            for(var v:recipients){need(unique.add(v.role+":"+HexFormat.of().formatHex(v.id)));byte[] key=find(keys,v.role,v.id);need(key[148]==1 && num(key,132)<=r.nowMs && r.nowMs<num(key,140) && (scope(key)&4)!=0);if(v.role==1)need(same(part(key,98,16),r.device) && same(part(key,114,16),r.line));targets.add(new Target(v.role,v.id,part(key,33,65)));}
            byte[] fields=join(current.account(),r.message,r.device,r.line,u64(current.version()),current.digest(),signerId,u64(r.observedMs),u64(r.expiresMs),new byte[]{1,(byte)r.peer.length()},r.peer.getBytes(StandardCharsets.US_ASCII));
            byte[] prefix=join(new byte[]{90,84,83,69,2,1,0,0},ByteBuffer.allocate(2).putShort((short)fields.length).array(),fields);
            var random=new SecureRandom();cek=new byte[32];random.nextBytes(cek);byte[] nonce=new byte[12];random.nextBytes(nonce);byte[] body=encrypt(cek,nonce,text,join(label("ZTSE/body/v2"),prefix));var wraps=new ArrayList<byte[]>();
            for(var v:targets)wraps.add(join(new byte[]{(byte)v.role},v.id,wrap(v.point,cek,join(label("ZTSE/wrap/v2"),prefix,new byte[]{(byte)v.role},v.id),new byte[0])));
            byte[] unsigned=join(prefix,nonce,ByteBuffer.allocate(4).putInt(body.length).array(),body,new byte[]{(byte)wraps.size()},join(wraps.toArray(byte[][]::new))),envelope=join(unsigned,r.signer.signEnvelope02(unsigned));SignedEnvelope.verify(envelope,2,publicPoint);return envelope;
        }finally{Arrays.fill(text,(byte)0);if(cek!=null)Arrays.fill(cek,(byte)0);}
    }
}
