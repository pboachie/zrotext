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

/** Candidate composition and exact local retry state; never a transport grant. */
public final class Compose03 {
    private Compose03(){}
    public record Recipient(int role,byte[] id){}
    public record Request(ManifestChain.Verified manifest,Election03.Proof proof,ElectedReader03.AuthoritySource authority,
        byte[] message,long observedMs,long expiresMs,String peer,String content,ProtectedSigner signer,List<Recipient> recipients){}
    private record Target(int role,byte[] id,byte[] point){}
    private record Plan(byte[] prefix,byte[] text,List<Target> targets,byte[] publicPoint,byte[] intent,long now){}
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Candidate composition refused");}
    private static byte[] join(byte[]... values){int size=0;for(var v:values)size+=v.length;byte[] out=new byte[size];int at=0;for(var v:values){System.arraycopy(v,0,out,at,v.length);at+=v.length;}return out;}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static byte[] label(String s){return (s+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] u64(long n){return ByteBuffer.allocate(8).putLong(n).array();}
    private static long num(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static int scope(byte[] b){return Short.toUnsignedInt(ByteBuffer.wrap(b,130,2).getShort());}
    private static Request capture(Request r)throws GeneralSecurityException{
        need(r.message.length==16 && r.recipients.size()>=2 && r.recipients.size()<=8);var recipients=new ArrayList<Recipient>();
        for(var v:r.recipients){need(v.id.length==32);recipients.add(new Recipient(v.role,v.id.clone()));}
        return new Request(r.manifest,r.proof,r.authority,r.message.clone(),r.observedMs,r.expiresMs,r.peer,r.content,r.signer,List.copyOf(recipients));
    }
    private static byte[] text(String value)throws GeneralSecurityException{
        need(!value.isEmpty() && value.length()<=32768);
        try{var encoded=StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));byte[] result=new byte[encoded.remaining()];encoded.get(result);if(encoded.hasArray())Arrays.fill(encoded.array(),(byte)0);return result;}
        catch(CharacterCodingException e){throw new GeneralSecurityException("Strict text refused",e);}
    }
    private static byte[] find(byte[][] keys,int role,byte[] id)throws GeneralSecurityException{for(var key:keys)if(key[0]==role && same(part(key,1,32),id))return key;throw new GeneralSecurityException("Manifest key missing");}
    private static Plan authorize(Request r)throws GeneralSecurityException{
        var snapshot=r.authority.read();long now=snapshot.nowMs();var bound=Election03.requireCurrent(r.proof,r.manifest,snapshot.authenticatedRecord(),now);
        need(!same(r.message,new byte[16]) && r.observedMs>0 && r.observedMs<=now && now<r.expiresMs && r.expiresMs-r.observedMs<=900000);
        need(r.peer.matches("\\+[1-9][0-9]{1,14}"));byte[] text=text(r.content);boolean transferred=false;
        try{
            need(text.length>=1 && text.length<=32768 && !(text.length>=3 && text[0]==(byte)239 && text[1]==(byte)187 && text[2]==(byte)191));for(byte b:text)need(b!=0);
            byte[] point=r.signer.publicPoint(),signerId=sha(join(label("ZTSE/key/v1"),new byte[]{1,1},point));byte[][] keys=r.manifest.keyRecords();byte[] signer=find(keys,5,signerId);
            need(signer[148]==1 && num(signer,132)<=r.observedMs && now<num(signer,140) && scope(signer)==1 && same(part(signer,114,16),bound.field("lineId")) && same(part(signer,33,65),point));
            var sorted=new ArrayList<>(r.recipients);sorted.sort(Comparator.comparingInt(Recipient::role).thenComparing(v->HexFormat.of().formatHex(v.id)));
            need(sorted.stream().filter(v->v.role==1).count()==1 && sorted.stream().filter(v->v.role==2).count()==1);var unique=new HashSet<String>();var targets=new ArrayList<Target>();
            long deadline=Math.min(r.manifest.expiresMs(),Math.min(num(signer,140),bound.number("permissionExpiresAtMs")));
            for(var v:sorted){need(v.role>=1 && v.role<=3 && unique.add(v.role+":"+HexFormat.of().formatHex(v.id)));byte[] key=find(keys,v.role,v.id);
                need(key[148]==1 && num(key,132)<=r.observedMs && now<num(key,140) && (scope(key)&4)!=0);
                if(v.role==1)need(same(v.id,bound.field("selectedReaderKeyId")) && same(part(key,98,16),bound.field("deviceId")) && same(part(key,114,16),bound.field("lineId")));
                deadline=Math.min(deadline,num(key,140));targets.add(new Target(v.role,v.id.clone(),part(key,33,65)));
            }
            need(r.expiresMs<=deadline);
            byte[] fields=join(bound.field("accountId"),r.message,bound.field("deviceId"),bound.field("lineId"),u64(bound.number("manifestVersion")),bound.field("manifestDigest"),signerId,u64(r.observedMs),u64(r.expiresMs),new byte[]{1,(byte)r.peer.length()},r.peer.getBytes(StandardCharsets.US_ASCII));
            byte[] prefix=join(new byte[]{90,84,83,69,3,1,0,0},ByteBuffer.allocate(2).putShort((short)fields.length).array(),fields);
            byte[] intent=sha(join(label("ZTSE/native-outbound-intent/v1"),prefix,sha(text),join(targets.stream().map(v->join(new byte[]{(byte)v.role},v.id,v.point)).toArray(byte[][]::new)),bound.field("bindingId"),u64(bound.number("bindingGeneration")),bound.field("electionCommitment"),bound.field("electionBundleSha256")));
            var result=new Plan(prefix,text,List.copyOf(targets),point,intent,now);transferred=true;return result;
        }finally{if(!transferred)Arrays.fill(text,(byte)0);}
    }
    private static long recheck(Request r,Plan plan,long floor)throws GeneralSecurityException{var fresh=authorize(r);try{need(fresh.now>=floor && same(fresh.intent,plan.intent));return fresh.now;}finally{Arrays.fill(fresh.text,(byte)0);}}
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
    private record Composed(byte[] envelope,long now){}
    private static Composed compose(Request r,Plan plan,long floor)throws GeneralSecurityException{
        var random=new SecureRandom();byte[] cek=new byte[32];random.nextBytes(cek);
        try{byte[] nonce=new byte[12];random.nextBytes(nonce);byte[] body=encrypt(cek,nonce,plan.text,join(label("ZTSE/body/v3"),plan.prefix));var wraps=new ArrayList<byte[]>();
            for(var target:plan.targets){byte[] suffix=join(plan.prefix,new byte[]{(byte)target.role},target.id);wraps.add(join(new byte[]{(byte)target.role},target.id,wrap(target.point,cek,join(label("ZTSE/wrap/v3"),suffix),join(label("ZTSE/wrap-aad/v3"),suffix))));}
            byte[] unsigned=join(plan.prefix,nonce,ByteBuffer.allocate(4).putInt(body.length).array(),body,new byte[]{(byte)wraps.size()},join(wraps.toArray(byte[][]::new))),envelope=join(unsigned,r.signer.signEnvelope03(unsigned));SignedEnvelope.verify(envelope,3,plan.publicPoint);return new Composed(envelope,recheck(r,plan,floor));
        }finally{Arrays.fill(cek,(byte)0);}
    }
    public static byte[] fresh(Request request)throws GeneralSecurityException{var r=capture(request);var plan=authorize(r);try{return compose(r,plan,plan.now).envelope;}finally{Arrays.fill(plan.text,(byte)0);}}
    private static void write(FileChannel file,byte[] bytes)throws IOException{var b=ByteBuffer.wrap(bytes);while(b.hasRemaining())file.write(b);}
    private static byte[] read(FileChannel file,int count)throws IOException{var b=ByteBuffer.allocate(count);while(b.hasRemaining())if(file.read(b)<0)throw new EOFException("Partial journal");return b.array();}
    private static final class Clock {
        private final FileChannel file;private final byte[] header;private long floor;
        private Clock(FileChannel file,byte[] header)throws IOException,GeneralSecurityException{
            this.file=file;this.header=header;byte[] clock=read(file,8);need(same(read(file,32),sha(join(header,clock))));floor=num(clock,0);need(floor>0);
        }
        private void advance(long now)throws IOException,GeneralSecurityException{
            need(now>=floor);if(now>floor){long position=file.position();byte[] clock=u64(now);file.position(header.length);write(file,join(clock,sha(join(header,clock))));file.force(true);file.position(position);floor=now;}
        }
    }
    public static byte[] composeOrReplay(Path path,byte[] rootPin,byte[] comparedFingerprint,Request request)throws GeneralSecurityException,IOException,InterruptedException{
        byte[] pin=rootPin.clone(),fingerprint=comparedFingerprint.clone();ManifestChain.RootPin.enroll(pin,fingerprint);var r=capture(request);var plan=authorize(r);
        try{
            need(same(part(pin,5,16),r.manifest.account()) && same(part(pin,29,65),r.manifest.rootPoint()));byte[] header=join(new byte[]{90,84,74,52},pin,fingerprint),identity=part(plan.prefix,10,64);boolean created;
            FileChannel channel;
            try{channel=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=true;}
            catch(FileAlreadyExistsException e){channel=FileChannel.open(path,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);created=false;}
            try(var file=channel){
                FileLock acquired=null;for(int attempt=0;attempt<100 && acquired==null;attempt++){try{acquired=file.tryLock();}catch(OverlappingFileLockException busy){/* Another local caller owns the lock. */}if(acquired==null)Thread.sleep(50);}need(acquired!=null);
                try(var lock=acquired){
                    need(lock.isValid());if(created){byte[] initial=u64(plan.now);write(file,join(header,initial,sha(join(header,initial))));file.force(true);}need(file.size()>=header.length+40 && file.size()<=10000000);file.position(0);need(same(read(file,header.length),header));var clock=new Clock(file,header);clock.advance(plan.now);int count=0;byte[] stored=null;
                    while(file.position()<file.size()){
                        need(++count<=256 && file.size()-file.position()>=132);byte[] leading=read(file,100);int size=ByteBuffer.wrap(leading,96,4).getInt();need(size>=557 && size<=34213 && file.size()-file.position()>=size+32);byte[] envelope=read(file,size);need(same(read(file,32),sha(join(leading,envelope))));
                        if(same(part(leading,0,64),identity)){need(stored==null && same(part(leading,64,32),plan.intent));SignedEnvelope.verify(envelope,3,plan.publicPoint);need(same(part(envelope,0,plan.prefix.length),plan.prefix));int end=plan.prefix.length+16+ByteBuffer.wrap(envelope,plan.prefix.length+12,4).getInt();need((envelope[end]&255)==plan.targets.size());
                            for(int i=0;i<plan.targets.size();i++)need(envelope[end+1+146*i]==plan.targets.get(i).role && same(part(envelope,end+2+146*i,32),plan.targets.get(i).id));stored=envelope;
                        }
                    }
                    clock.advance(recheck(r,plan,clock.floor));if(stored!=null)return stored;need(count<256);var composed=compose(r,plan,clock.floor);clock.advance(composed.now);byte[] envelope=composed.envelope,record=join(identity,plan.intent,ByteBuffer.allocate(4).putInt(envelope.length).array(),envelope);write(file,record);write(file,sha(record));file.force(true);clock.advance(recheck(r,plan,clock.floor));return envelope;
                }
            }
        }finally{Arrays.fill(plan.text,(byte)0);}
    }
}
