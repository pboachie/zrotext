package org.zrotext.candidate;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Selected role-3 reply opening. Callbacks require independently authenticated grant state. */
public final class OriginalReplyReader {
    private OriginalReplyReader() {}
    private static final BigInteger ORDER=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private static final String DISCLOSURE="With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
    private static void need(boolean ok)throws GeneralSecurityException{if(!ok)throw new GeneralSecurityException("Original reply refused");}
    private static byte[] part(byte[] b,int at,int size){return Arrays.copyOfRange(b,at,at+size);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static boolean zero(byte[] b){for(byte v:b)if(v!=0)return false;return true;}
    private static long number(byte[] b,int at){return ByteBuffer.wrap(b,at,8).getLong();}
    private static byte[] fixed(byte[] b,int size)throws GeneralSecurityException{need(b!=null && b.length==size && !zero(b));return b.clone();}
    /** Independently selected scope; no field is inferred from an inbound event. */
    public static final class Scope {
        private final byte[] account,device,line,interval,connector,grant,reader;
        private final String peer;
        public Scope(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] connector,byte[] grant,byte[] reader,String peer)throws GeneralSecurityException{
            this.account=fixed(account,16);this.device=fixed(device,16);this.line=fixed(line,16);this.interval=fixed(interval,16);this.connector=fixed(connector,16);this.grant=fixed(grant,16);this.reader=fixed(reader,32);
            need(peer!=null && peer.matches("\\+[1-9][0-9]{1,14}"));this.peer=peer;
        }
        private boolean matches(Scope other){return other!=null && same(account,other.account) && same(device,other.device) && same(line,other.line) && same(interval,other.interval) && same(connector,other.connector) && same(grant,other.grant) && same(reader,other.reader) && peer.equals(other.peer);}
        byte[] checkpointBinding()throws GeneralSecurityException{
            var hash=MessageDigest.getInstance("SHA-256");hash.update("ZTSE/native/original-checkpoint-scope/v1\0".getBytes(StandardCharsets.US_ASCII));
            for(byte[] value:new byte[][]{account,device,line,interval,connector,grant,reader})hash.update(value);hash.update((byte)peer.length());hash.update(peer.getBytes(StandardCharsets.US_ASCII));return hash.digest();
        }
        byte[] checkpointAccount(){return account.clone();}
        byte[][] proofFields(){return new byte[][]{account.clone(),device.clone(),line.clone(),interval.clone(),connector.clone(),grant.clone(),reader.clone()};}
    }
    /** Verified dual-phone evidence, not a current grant or durable accepted-history receipt. */
    public static final class Selection {
        private final Scope scope;
        private final byte[] archive;
        private final List<byte[]> readers;
        private final ManifestChain.Verified activation;
        private Selection(Scope scope,byte[] archive,List<byte[]> readers,ManifestChain.Verified activation){this.scope=scope;this.archive=archive;this.readers=readers;this.activation=activation;}
    }
    public record Authority(Scope scope,String revision,long nowMs,long expiresMs,ManifestChain.Verified manifest) {}
    public interface AuthoritySource {Authority read()throws GeneralSecurityException;}
    private static final class Cursor {
        private final byte[] b;private int at;
        Cursor(byte[] b){this.b=b;}
        byte[] take(int count)throws GeneralSecurityException{need(count>=0 && count<=b.length-at);byte[] out=part(b,at,count);at+=count;return out;}
        byte[] id(int count)throws GeneralSecurityException{return fixed(take(count),count);}
        long positive()throws GeneralSecurityException{long n=number(take(8),0);need(n>0);return n;}
        int octet()throws GeneralSecurityException{return take(1)[0]&255;}
        String text()throws GeneralSecurityException{byte[] value=take(octet());for(byte v:value)need(v>=33 && v<=126);return new String(value,StandardCharsets.US_ASCII);}
    }
    private static byte[] key(ManifestChain.Verified manifest,int role,byte[] id)throws GeneralSecurityException{
        for(byte[] k:manifest.keyRecords())if(k[0]==role && same(part(k,1,32),id))return k;throw new GeneralSecurityException("Selected key absent");
    }
    private static void active(byte[] k,long now,int scope)throws GeneralSecurityException{need(k[148]==1 && now>=number(k,132) && now<number(k,140) && (Short.toUnsignedInt(ByteBuffer.wrap(k,130,2).getShort())&scope)!=0);}
    private static void signature(byte[] point,byte[] input,String domain,byte[] body)throws GeneralSecurityException{
        need(input.length==64);byte[] sig=input.clone();BigInteger r=new BigInteger(1,part(sig,0,32)),s=new BigInteger(1,part(sig,32,32));
        need(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER.shiftRight(1))<=0);
        Signature verify=Signature.getInstance("SHA256withECDSAinP1363Format");verify.initVerify(HpkeRecipient.point(point));verify.update((domain+"\0").getBytes(StandardCharsets.US_ASCII));verify.update(ByteBuffer.allocate(4).putInt(body.length).array());verify.update(body);need(verify.verify(sig));
    }
    public static Selection verifySelection(byte[] input,byte[] approval,byte[] installation,ManifestChain.Verified activation,long acceptedMs,Scope scope)throws GeneralSecurityException{
        need(input.length>=380 && input.length<=1536 && activation!=null && activation.profile()==2 && scope!=null);byte[] raw=input.clone();Cursor p=new Cursor(raw);
        need(same(p.take(5),new byte[]{90,84,67,65,2}));byte[] account=p.id(16),device=p.id(16),line=p.id(16);p.positive();byte[] interval=p.id(16);p.id(16);p.id(16);p.id(32);
        long expires=p.positive();String peer=p.text(),content=p.text();byte[] disclosure=p.take(32),archive=p.id(32),signer=p.id(32);long generation=p.positive(),previous=p.positive();p.id(32);long version=p.positive();byte[] digest=p.id(32);p.positive();p.positive();String site=p.text(),instance=p.text();
        int count=p.octet();need(count>=1 && count<=6);List<byte[]> readers=new ArrayList<>(),connectors=new ArrayList<>(),grants=new ArrayList<>();boolean chosen=false;
        for(int i=0;i<count;i++){byte[] connector=p.id(16),grant=p.id(16),reader=p.id(32);need(i==0 || Arrays.compareUnsigned(readers.get(i-1),reader)<0);for(int j=0;j<i;j++)need(!same(connectors.get(j),connector) && !same(grants.get(j),grant));chosen|=same(connector,scope.connector) && same(grant,scope.grant) && same(reader,scope.reader);connectors.add(connector);grants.add(grant);readers.add(reader);}
        need(p.at==raw.length && chosen && content.equals("conversation-content-v1") && same(disclosure,MessageDigest.getInstance("SHA-256").digest(DISCLOSURE.getBytes(StandardCharsets.UTF_8))) && site.length()>=1 && site.length()<=64 && instance.length()>=1 && instance.length()<=64 && previous<Long.MAX_VALUE && version==previous+1 && acceptedMs>0 && acceptedMs<expires && peer.equals(scope.peer) && same(account,scope.account) && same(device,scope.device) && same(line,scope.line) && same(interval,scope.interval));
        var verified=ManifestChain.continueChain(activation.bytes(),activation,2,acceptedMs);need(verified.generation()==generation && verified.version()==version && same(verified.digest(),digest) && same(verified.account(),scope.account));
        byte[] signing=key(verified,4,signer);active(signing,acceptedMs,2);need(same(part(signing,98,16),scope.device) && same(part(signing,114,16),scope.line));
        signature(part(signing,33,65),approval,"zrotext/conversation/approve/v2",raw);signature(part(signing,33,65),installation,"zrotext/conversation/install/v2",raw);
        return new Selection(scope,archive,List.copyOf(readers),verified);
    }
    private static Authority authority(Authority value,Scope scope)throws GeneralSecurityException{
        need(value!=null && scope.matches(value.scope()) && value.revision()!=null && !value.revision().isEmpty() && value.revision().length()<=128 && value.nowMs()>0 && value.nowMs()<value.expiresMs() && value.manifest()!=null && value.manifest().profile()==2);
        return new Authority(scope,value.revision(),value.nowMs(),value.expiresMs(),ManifestChain.continueChain(value.manifest().bytes(),value.manifest(),2,value.nowMs()));
    }
    public static String openSoftware(byte[] input,byte[] event,ManifestChain.Verified historical,Selection selection,Scope scope,PrivateKey recipient,AuthoritySource source)throws GeneralSecurityException{
        return openWithRecipient(input,event,historical,selection,scope,HpkeRecipient.software(recipient),source);
    }
    /** A generic injected recipient carries no hardware-custody claim. */
    public static String openWithRecipient(byte[] input,byte[] expectedEvent,ManifestChain.Verified historical,Selection selection,Scope scope,HpkeRecipient.Recipient recipient,AuthoritySource source)throws GeneralSecurityException{
        need(input.length>=426 && input.length<=34082 && historical!=null && historical.profile()==2 && selection!=null && selection.scope.matches(scope) && source!=null && recipient!=null);byte[] b=input.clone(),event=fixed(expectedEvent,16);
        need(b[4]==2 && b[5]==2 && same(part(b,26,16),event));Authority initial=authority(source.read(),scope);var current=initial.manifest();
        need(same(historical.account(),scope.account) && same(current.account(),scope.account) && historical.generation()==current.generation() && current.generation()==selection.activation.generation() && same(historical.enrolledRootPoint(),current.enrolledRootPoint()) && same(current.enrolledRootPoint(),selection.activation.enrolledRootPoint()) && historical.descendsFrom(selection.activation) && current.descendsFrom(historical));
        long observed=number(b,146);need(observed>0 && observed<=initial.nowMs() && observed<historical.expiresMs() && (historical.issuedMs()<=observed || historical.issuedMs()-observed<=300000) && same(part(b,10,16),scope.account) && same(part(b,42,16),scope.device) && same(part(b,58,16),scope.line) && number(b,74)==historical.version() && same(part(b,82,32),historical.digest()));
        byte[] signer=key(historical,4,part(b,114,32));active(signer,observed,2);need(same(part(signer,98,16),scope.device) && same(part(signer,114,16),scope.line));SignedEnvelope envelope=SignedEnvelope.verify(b,2,part(signer,33,65));int prefix=10+Short.toUnsignedInt(ByteBuffer.wrap(b,8,2).getShort()),end=prefix+16+ByteBuffer.wrap(b,prefix+12,4).getInt();
        need(new String(part(b,179,prefix-179),StandardCharsets.US_ASCII).equals(scope.peer) && (b[end]&255)==1+selection.readers.size());
        for(int i=0;i<(b[end]&255);i++){int at=end+1+146*i,role=i==0?2:3;byte[] id=i==0?selection.archive:selection.readers.get(i-1);need(b[at]==role && same(part(b,at+1,32),id));active(key(historical,role,id),observed,8);}
        byte[] selected=key(current,3,scope.reader);active(selected,initial.nowMs(),8);byte[] cek=null;
        try{
            cek=recipient.unwrap(part(selected,33,65),envelope.encapsulated(3,scope.reader),envelope.wrapInfo(3,scope.reader),envelope.wrapAad(3,scope.reader),envelope.wrappedKey(3,scope.reader));String plain=CandidateBody.open(cek,envelope.nonce(),envelope.bodyAad(),envelope.bodyCiphertext());Authority after=authority(source.read(),scope);
            need(after.revision().equals(initial.revision()) && after.nowMs()>=initial.nowMs() && after.nowMs()<initial.expiresMs() && after.nowMs()<number(selected,140) && after.manifest().generation()==current.generation() && after.manifest().version()==current.version() && same(after.manifest().rootPoint(),current.rootPoint()) && same(after.manifest().enrolledRootPoint(),current.enrolledRootPoint()) && same(after.manifest().digest(),current.digest()));return plain;
        }finally{if(cek!=null)Arrays.fill(cek,(byte)0);}
    }
}
