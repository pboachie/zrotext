package org.zrotext.candidate;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

/** Immutable historical provenance. It does not prove live authorization or durable selection. */
public final class ManifestChain {
    private ManifestChain() {}
    private static final BigInteger ORDER=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private static void need(boolean value) throws GeneralSecurityException {if(!value)throw new GeneralSecurityException("Candidate manifest refused");}
    private static byte[] part(byte[] value,int at,int count){return Arrays.copyOfRange(value,at,at+count);}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static boolean zero(byte[] a){for(byte b:a)if(b!=0)return false;return true;}
    private static byte[] domain(String value){return (value+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] join(byte[]... values){int size=0;for(var value:values)size+=value.length;byte[] out=new byte[size];int at=0;for(var value:values){System.arraycopy(value,0,out,at,value.length);at+=value.length;}return out;}
    private static byte[] sha(byte[] value)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(value);}
    private static long number(byte[] value,int at)throws GeneralSecurityException{long n=ByteBuffer.wrap(value,at,8).getLong();need(n>=0);return n;}
    private static void window(long issued,long expires,long now)throws GeneralSecurityException{
        need(now>0 && issued>0 && expires>issued && expires-issued<=86400000 && now<expires);
        need(issued<=now || issued-now<=300000);
    }
    private static void signature(byte[] point,byte[] raw,String label,byte[] unsigned)throws GeneralSecurityException{
        BigInteger r=new BigInteger(1,part(raw,0,32)),s=new BigInteger(1,part(raw,32,32));
        need(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER.shiftRight(1))<=0);
        Signature verify=Signature.getInstance("SHA256withECDSAinP1363Format");verify.initVerify(HpkeRecipient.point(point));
        verify.update(join(domain(label),ByteBuffer.allocate(4).putInt(unsigned.length).array(),unsigned));need(verify.verify(raw));
    }
    public static final class RootPin {
        private final byte[] account,point;
        private RootPin(byte[] account,byte[] point){this.account=account;this.point=point;}
        /** Fingerprint must come from an independently authenticated owner comparison. */
        public static RootPin enroll(byte[] input,byte[] comparedFingerprint)throws GeneralSecurityException{
            need(input.length==94 && comparedFingerprint.length==32);byte[] b=input.clone(),compared=comparedFingerprint.clone();
            need(same(part(b,0,5),new byte[]{90,84,82,80,2}) && !zero(part(b,5,16)) && number(b,21)==1);
            HpkeRecipient.point(part(b,29,65));need(same(sha(join(domain("ZTSE/root-pin/v2"),b)),compared));
            return new RootPin(part(b,5,16),part(b,29,65));
        }
    }
    public static final class Verified {
        private final byte[] bytes,digest,account,root,previous;
        private final int profile,predecessor;
        private final long version,issued,expires,comparison;
        private Verified(byte[] b,int profile,int predecessor,long version,long issued,long expires,long comparison,byte[] digest,byte[] account,byte[] root,byte[] previous){
            this.bytes=b;this.profile=profile;this.predecessor=predecessor;this.version=version;this.issued=issued;this.expires=expires;this.comparison=comparison;this.digest=digest;this.account=account;this.root=root;this.previous=previous;
        }
        public byte[] bytes(){return bytes.clone();} public byte[] digest(){return digest.clone();}
        public byte[] account(){return account.clone();} public byte[] rootPoint(){return root.clone();}
        public int profile(){return profile;} public long version(){return version;}
        public long issuedMs(){return issued;} public long expiresMs(){return expires;} public long comparisonMs(){return comparison;}
        public byte[][] keyRecords(){int at=profile==2?151:153,count=bytes[at-1]&255;byte[][] out=new byte[count][];for(int i=0;i<count;i++)out[i]=part(bytes,at+149*i,149);return out;}
    }
    private static Verified parse(byte[] input,int profile,long now)throws GeneralSecurityException{
        need(profile==2 || profile==3);int offset=profile==2?0:2;
        need(input.length>=364+offset && input.length<=9751+offset);byte[] b=input.clone();
        need(same(part(b,0,5),new byte[]{90,84,77,65,(byte)profile}));
        int predecessor=profile==2?2:b[6]&255;need(profile==2 || b[5]==3 && (predecessor==2 || predecessor==3));
        int count=b[150+offset]&255;need(count>=1 && count<=64 && b.length==215+offset+149*count);
        byte[] account=part(b,5+offset,16),root=part(b,85+offset,65),previous=part(b,53+offset,32);
        long generation=number(b,21+offset),version=number(b,29+offset),issued=number(b,37+offset),expires=number(b,45+offset);
        need(!zero(account) && generation==1 && version>0);window(issued,expires,now);HpkeRecipient.point(root);
        byte[] last=null;Set<String> points=new HashSet<>();int owners=0,archives=0;
        for(int i=0;i<count;i++){
            int at=151+offset+149*i,role=b[at]&255,state=b[at+148]&255,scope=Short.toUnsignedInt(ByteBuffer.wrap(b,at+130,2).getShort());
            byte[] id=part(b,at+1,32),point=part(b,at+33,65),device=part(b,at+98,16),line=part(b,at+114,16),ordering=part(b,at,33);
            long from=number(b,at+132),until=number(b,at+140);
            need(role>=1 && role<=6);int[] expected={0,4,12,4,2,1,0};need(role==3?(scope==4 || scope==8 || scope==12):scope==expected[role]);
            boolean deviceBound=role==1 || role==4,lineBound=deviceBound || role==5;
            need(deviceBound?!zero(device):zero(device));need(lineBound?!zero(line):zero(line));
            need(from<=until && (state==1 || state==2));need(last==null || Arrays.compareUnsigned(last,ordering)<0);last=ordering;
            HpkeRecipient.point(point);need(same(id,sha(join(domain("ZTSE/key/v1"),role<=3?new byte[]{0,16}:new byte[]{1,1},point))));
            need(points.add(HexFormat.of().formatHex(point)));
            if(role==6){owners++;need(same(point,root) && state==1 && from<=issued && until>=expires);}if(role==2 && state==1)archives++;
        }
        need(owners==1 && archives==1);byte[] unsigned=part(b,0,b.length-64);
        signature(root,part(b,b.length-64,64),"ZTSE/manifest/v"+profile,unsigned);
        return new Verified(b,profile,predecessor,version,issued,expires,now,sha(unsigned),account,root,previous);
    }
    /** Generation-one genesis only. A signed directory object cannot enroll its own root. */
    public static Verified genesis02(byte[] input,RootPin pin,long now)throws GeneralSecurityException{
        Verified value=parse(input,2,now);need(same(value.account,pin.account) && same(value.root,pin.point) && value.version==1 && zero(value.previous));return value;
    }
    /** Revalidates every received signature, including semantic currentness at unchanged version. */
    public static Verified continueChain(byte[] input,Verified prior,int expectedProfile,long now)throws GeneralSecurityException{
        need(prior!=null && now>=prior.comparison && !(prior.profile==3 && expectedProfile==2));
        if(prior.profile==2 && expectedProfile==3)window(prior.issued,prior.expires,now);
        Verified value=parse(input,expectedProfile,now);need(same(value.account,prior.account) && same(value.root,prior.root));
        if(value.profile==prior.profile && value.version==prior.version && same(value.digest,prior.digest))return value;
        need(prior.version<Long.MAX_VALUE && value.version==prior.version+1 && same(value.previous,prior.digest));
        need(value.profile==2 || value.predecessor==prior.profile);return value;
    }
}
