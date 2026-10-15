package org.zrotext.candidate;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

/** Historical election evidence against independently authenticated application records. */
public final class Election03 {
    private Election03() {}
    private static final String[] AU={"accountId","deviceId","lineId","oldBindingId","newBindingId"};
    private static final String[] AT={"vaultGeneration","oldBindingGeneration","newBindingGeneration","priorManifestVersion","acceptedManifestVersion","acceptedAtMs"};
    private static final String[] AD={"rootFingerprint","oldBindingProofDigest","selectedReaderKeyId","priorManifestDigest","priorSignedManifestSha256","acceptedManifestDigest","acceptedSignedManifestSha256","electionCoreSha256","electionCommitment","electionBundleSha256"};
    private static final String[] CU={"accountId","deviceId","lineId","bindingId"};
    private static final String[] CT={"bindingGeneration","vaultGeneration","manifestVersion","comparedAtMs","permissionExpiresAtMs"};
    private static final String[] CD={"selectedReaderKeyId","rootFingerprint","manifestDigest","electionCommitment","electionBundleSha256"};
    private static final BigInteger ORDER=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
    private static void need(boolean value)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException("Election authority refused");}
    private static boolean same(byte[] a,byte[] b){return MessageDigest.isEqual(a,b);}
    private static byte[] part(byte[] b,int at,int count){return Arrays.copyOfRange(b,at,at+count);}
    private static byte[] join(byte[]... chunks){int size=0;for(var b:chunks)size+=b.length;byte[] out=new byte[size];int at=0;for(var b:chunks){System.arraycopy(b,0,out,at,b.length);at+=b.length;}return out;}
    private static byte[] label(String value){return (value+"\0").getBytes(StandardCharsets.US_ASCII);}
    private static byte[] sha(byte[] value)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(value);}
    private static byte[] framed(String domain,byte[] value){return join(label(domain),ByteBuffer.allocate(4).putInt(value.length).array(),value);}
    private static boolean nonzero(byte[] value){for(byte b:value)if(b!=0)return true;return false;}
    private static long num(byte[] b,int at)throws GeneralSecurityException{long n=ByteBuffer.wrap(b,at,8).getLong();need(n>0);return n;}
    private static void signature(byte[] point,byte[] raw,String domain,byte[] payload)throws GeneralSecurityException{
        BigInteger r=new BigInteger(1,part(raw,0,32)),s=new BigInteger(1,part(raw,32,32));need(r.signum()>0 && r.compareTo(ORDER)<0 && s.signum()>0 && s.compareTo(ORDER.shiftRight(1))<=0);
        Signature verifier=Signature.getInstance("SHA256withECDSAinP1363Format");verifier.initVerify(HpkeRecipient.point(point));verifier.update(framed(domain,payload));need(verifier.verify(raw));
    }
    private static final class Record {
        private final Map<String,byte[]> bytes=new HashMap<>();private final Map<String,Long> numbers=new HashMap<>();
        private Record(Map<String,?> input,String[] uuids,String[] times,String[] digests,boolean current)throws GeneralSecurityException{
            Set<String> keys=new HashSet<>();keys.addAll(Arrays.asList(uuids));keys.addAll(Arrays.asList(times));keys.addAll(Arrays.asList(digests));if(current){keys.add("profile");keys.add("manifestProfile");}
            need(input!=null && keys.equals(input.keySet()));
            for(String name:keys){Object value=input.get(name);if(Arrays.asList(times).contains(name) || name.equals("profile") || name.equals("manifestProfile")){
                need(value instanceof Long || value instanceof Integer);long n=((Number)value).longValue();need(n>0);numbers.put(name,n);
            }else{need(value instanceof byte[]);byte[] b=((byte[])value).clone();need(b.length==(Arrays.asList(uuids).contains(name)?16:32) && nonzero(b));bytes.put(name,b);}}
            if(current)need(n("profile")==3 && n("manifestProfile")==3 && n("permissionExpiresAtMs")>n("comparedAtMs"));
        }
        private byte[] b(String name){return bytes.get(name);}private long n(String name){return numbers.get(name);}
    }
    public static final class Proof {
        private final Record accepted;private final ManifestChain.Verified manifest;
        private Proof(Record accepted,ManifestChain.Verified manifest){this.accepted=accepted;this.manifest=manifest;}
        public ManifestChain.Verified acceptedManifest(){return manifest;}
    }
    public static final class Current {
        private final Record record;private Current(Record record){this.record=record;}
        public byte[] field(String name){byte[] b=record.b(name);if(b==null)throw new IllegalArgumentException("Unknown binary authority field");return b.clone();}
        public long number(String name){return record.n(name);}
    }
    /** expectedCore, acceptedRecord and both registry points require independent authentication. */
    public static Proof verify(byte[] bundleInput,byte[] expectedCore,Map<String,?> acceptedRecord,ManifestChain.Verified predecessor,
            byte[] signed02Input,byte[] signed03Input,byte[] devicePointInput,byte[] ownerPointInput)throws GeneralSecurityException{
        need(bundleInput.length==628 && expectedCore.length==500 && devicePointInput.length==65 && ownerPointInput.length==65);
        byte[] bundle=bundleInput.clone(),core=part(bundle,0,500),signed02=signed02Input.clone(),signed03=signed03Input.clone(),device=devicePointInput.clone(),owner=ownerPointInput.clone();
        Record a=new Record(acceptedRecord,AU,AT,AD,false);
        need(predecessor!=null && predecessor.profile()==2 && same(signed02,predecessor.bytes()) && a.n("acceptedAtMs")>=predecessor.comparisonMs());
        need(same(core,expectedCore.clone()) && same(part(core,0,8),new byte[]{90,84,80,69,3,1,2,3}) && !nonzero(part(core,496,4)) && nonzero(part(core,56,16)) && nonzero(part(core,352,32)));
        int[] positions={8,24,40,72,104,136,184,224,256};String[] names={"accountId","deviceId","lineId","oldBindingId","oldBindingProofDigest","rootFingerprint","priorManifestDigest","acceptedManifestDigest","selectedReaderKeyId"};
        for(int i=0;i<positions.length;i++)need(same(part(core,positions[i],a.b(names[i]).length),a.b(names[i])));
        int[] numbers={88,96,168,176,216};String[] numberNames={"oldBindingGeneration","newBindingGeneration","vaultGeneration","priorManifestVersion","acceptedManifestVersion"};
        for(int i=0;i<numbers.length;i++)need(num(core,numbers[i])==a.n(numberNames[i]));
        long issued=num(core,384),expires=num(core,392);need(issued<=a.n("acceptedAtMs") && a.n("acceptedAtMs")<expires && expires-issued<=300000 && a.n("newBindingGeneration")>a.n("oldBindingGeneration") && a.n("vaultGeneration")==1 && a.n("priorManifestVersion")<Long.MAX_VALUE && a.n("acceptedManifestVersion")==a.n("priorManifestVersion")+1);
        for(int at:new int[]{400,432,464})need(nonzero(part(core,at,32)));
        byte[][] values={signed02,signed03,core,bundle,framed("ZTSE/line/payload-profile/commitment/v1",core)};
        String[] hashes={"priorSignedManifestSha256","acceptedSignedManifestSha256","electionCoreSha256","electionBundleSha256","electionCommitment"};
        for(int i=0;i<values.length;i++)need(same(sha(values[i]),a.b(hashes[i])));
        var manifest=ManifestChain.continueChain(signed03,predecessor,3,a.n("acceptedAtMs"));
        need(same(manifest.account(),a.b("accountId")) && manifest.version()==a.n("acceptedManifestVersion") && same(manifest.digest(),a.b("acceptedManifestDigest")) && predecessor.version()==a.n("priorManifestVersion") && same(predecessor.digest(),a.b("priorManifestDigest")));
        byte[] rootPin=join(new byte[]{90,84,82,80,2},manifest.account(),ByteBuffer.allocate(8).putLong(1).array(),manifest.rootPoint());
        need(same(sha(join(label("ZTSE/root-pin/v2"),rootPin)),a.b("rootFingerprint")));
        need(same(sha(join(label("ZTSE/key/v1"),new byte[]{1,1},device)),part(core,288,32)) && same(sha(join(label("ZTSE/key/v1"),new byte[]{1,1},owner)),part(core,320,32)));
        byte[] deviceSignature=part(bundle,500,64);signature(device,deviceSignature,"ZTSE/line/payload-profile/device/v1",core);
        signature(owner,part(bundle,564,64),"ZTSE/line/payload-profile/owner/v1",join(core,sha(deviceSignature)));
        return new Proof(a,manifest);
    }
    public static Current requireCurrent(Proof proof,ManifestChain.Verified manifest,Map<String,?> authenticatedCurrent,long now)throws GeneralSecurityException{
        need(proof!=null && manifest!=null && now>0);Record a=proof.accepted,c=new Record(authenticatedCurrent,CU,CT,CD,true);
        need(now>=a.n("acceptedAtMs") && now>=c.n("comparedAtMs") && now<c.n("permissionExpiresAtMs") && now>=manifest.comparisonMs() && now<manifest.expiresMs());
        String[] cn={"accountId","deviceId","lineId","bindingId","selectedReaderKeyId","rootFingerprint","electionCommitment","electionBundleSha256"};String[] an={"accountId","deviceId","lineId","newBindingId","selectedReaderKeyId","rootFingerprint","electionCommitment","electionBundleSha256"};
        for(int i=0;i<cn.length;i++)need(same(c.b(cn[i]),a.b(an[i])));
        need(c.n("bindingGeneration")==a.n("newBindingGeneration") && c.n("vaultGeneration")==1 && c.n("manifestVersion")>=a.n("acceptedManifestVersion"));
        need(manifest.profile()==3 && manifest.version()==c.n("manifestVersion") && same(manifest.account(),c.b("accountId")) && same(manifest.digest(),c.b("manifestDigest")) && manifest.descendsFrom(proof.manifest));
        return new Current(c);
    }
}
