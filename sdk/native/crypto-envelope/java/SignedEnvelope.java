package org.zrotext.candidate;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/** Immutable signature-verified component; NOT manifest authorization or current authority. */
public final class SignedEnvelope {
    private final byte[] bytes;
    private final int profile, kind, prefixEnd, bodyEnd, count;
    private static final BigInteger ORDER = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private SignedEnvelope(byte[] bytes, int profile, int kind, int prefixEnd, int bodyEnd, int count) {
        this.bytes=bytes; this.profile=profile; this.kind=kind; this.prefixEnd=prefixEnd; this.bodyEnd=bodyEnd; this.count=count;
    }
    private static void require(boolean condition) throws GeneralSecurityException {
        if (!condition) throw new GeneralSecurityException("Invalid candidate envelope");
    }
    private static byte[] domain(String label) { return (label+"\0").getBytes(StandardCharsets.US_ASCII); }
    private static byte[] join(byte[]... parts) {
        int size=0; for(var part:parts) size+=part.length;
        byte[] out=new byte[size]; int at=0;
        for(var part:parts) { System.arraycopy(part,0,out,at,part.length); at+=part.length; } return out;
    }
    private static long u64(byte[] value,int at) throws GeneralSecurityException {
        long number=ByteBuffer.wrap(value,at,8).getLong(); require(number>=0); return number;
    }
    public static SignedEnvelope verify(byte[] input,int expectedProfile,byte[] trustedSigner) throws GeneralSecurityException {
        require(expectedProfile==2 || expectedProfile==3);
        require(input.length>=426 && input.length<=36864);
        byte[] b=input.clone(), signer=trustedSigner.clone();
        require(b[0]==90 && b[1]==84 && b[2]==83 && b[3]==69 && b[4]==expectedProfile && b[6]==0 && b[7]==0);
        int kind=b[5]; require(kind==1 || kind==2);
        // Profile03 inbound has no reviewed producer/authority contract here.
        require(expectedProfile!=3 || kind==1);
        if(expectedProfile==3 && Arrays.equals(Arrays.copyOfRange(b,26,42),new byte[16]))
            throw new GeneralSecurityException("Profile03 message identity");
        require(b.length<=(kind==1?34213:34082));
        int size=Short.toUnsignedInt(ByteBuffer.wrap(b,8,2).getShort());
        require(size>=(kind==1?157:172) && size<=(kind==1?170:185));
        int end=10+size, peerAt=10+(kind==1?153:168), peerLength=Byte.toUnsignedInt(b[peerAt]);
        require(peerLength>=3 && peerLength<=16 && size==(kind==1?154:169)+peerLength);
        require(b[peerAt+1]==43 && b[peerAt+2]>=49 && b[peerAt+2]<=57);
        for(int i=peerAt+3;i<end;i++) require(b[i]>=48 && b[i]<=57);
        u64(b,74); long observed=u64(b,146);
        if(kind==1) { long expires=u64(b,154); require(b[162]==1 && expires>observed && expires-observed<=900000); }
        else { require(Arrays.equals(Arrays.copyOfRange(b,26,42),Arrays.copyOfRange(b,154,170))); require(u64(b,170)>0); }
        long length=Integer.toUnsignedLong(ByteBuffer.wrap(b,end+12,4).getInt());
        require(length>=17 && length<=32784);
        int bodyEnd=end+16+(int)length; require(bodyEnd<b.length);
        int count=Byte.toUnsignedInt(b[bodyEnd]); require(count>=(kind==1?2:1) && count<=(kind==1?8:7));
        int unsignedEnd=bodyEnd+1+146*count; require(unsignedEnd+64==b.length);
        int devices=0,archives=0; byte[] previous=null;
        for(int i=0;i<count;i++) {
            int at=bodyEnd+1+146*i, role=Byte.toUnsignedInt(b[at]); require(role>=1 && role<=3);
            byte[] ordering=Arrays.copyOfRange(b,at,at+33);
            require(previous==null || Arrays.compareUnsigned(previous,ordering)<0); previous=ordering;
            HpkeRecipient.point(Arrays.copyOfRange(b,at+33,at+98));
            if(role==1)devices++; if(role==2)archives++;
        }
        require(devices==(kind==1?1:0) && archives==1);
        byte[] raw=Arrays.copyOfRange(b,unsignedEnd,b.length);
        BigInteger r=new BigInteger(1,Arrays.copyOfRange(raw,0,32)), s=new BigInteger(1,Arrays.copyOfRange(raw,32,64));
        require(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER.shiftRight(1))<=0);
        PublicKey publicKey=HpkeRecipient.point(signer);
        byte[] identity=MessageDigest.getInstance("SHA-256").digest(join(domain("ZTSE/key/v1"),new byte[]{1,1},signer));
        require(MessageDigest.isEqual(identity,Arrays.copyOfRange(b,114,146)));
        Signature verifier=Signature.getInstance("SHA256withECDSAinP1363Format"); verifier.initVerify(publicKey);
        verifier.update(join(domain("ZTSE/sign/v"+expectedProfile),ByteBuffer.allocate(4).putInt(unsignedEnd).array(),Arrays.copyOf(b,unsignedEnd)));
        require(verifier.verify(raw));
        return new SignedEnvelope(b,expectedProfile,kind,end,bodyEnd,count);
    }
    public int profile() { return profile; }
    public int kind() { return kind; }
    public byte[] bytes() { return bytes.clone(); }
    public byte[] protectedBytes() { return Arrays.copyOfRange(bytes,10,prefixEnd); }
    public byte[] nonce() { return Arrays.copyOfRange(bytes,prefixEnd,prefixEnd+12); }
    public byte[] bodyCiphertext() { return Arrays.copyOfRange(bytes,prefixEnd+16,bodyEnd); }
    public byte[] bodyAad() { return join(domain("ZTSE/body/v"+profile),Arrays.copyOf(bytes,prefixEnd)); }
    private int wrap(int role,byte[] identity) throws GeneralSecurityException {
        require(identity.length==32);
        for(int i=0;i<count;i++) { int at=bodyEnd+1+146*i; if(bytes[at]==role && MessageDigest.isEqual(identity,Arrays.copyOfRange(bytes,at+1,at+33))) return at; }
        throw new GeneralSecurityException("Recipient wrap missing");
    }
    private byte[] suffix(int role,byte[] identity) throws GeneralSecurityException {
        int at=wrap(role,identity); return join(Arrays.copyOf(bytes,prefixEnd),Arrays.copyOfRange(bytes,at,at+33));
    }
    public byte[] wrapInfo(int role,byte[] identity) throws GeneralSecurityException { return join(domain("ZTSE/wrap/v"+profile),suffix(role,identity)); }
    public byte[] wrapAad(int role,byte[] identity) throws GeneralSecurityException { byte[] suffix=suffix(role,identity); return profile==2?new byte[0]:join(domain("ZTSE/wrap-aad/v3"),suffix); }
    public byte[] encapsulated(int role,byte[] identity) throws GeneralSecurityException { int at=wrap(role,identity); return Arrays.copyOfRange(bytes,at+33,at+98); }
    public byte[] wrappedKey(int role,byte[] identity) throws GeneralSecurityException { int at=wrap(role,identity); return Arrays.copyOfRange(bytes,at+98,at+146); }
}
