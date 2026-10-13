using System;
using System.Collections.Generic;
using System.Linq;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;

public static class Election03 {
    private static readonly object Permit=new();
    private static readonly string[] AU={"accountId","deviceId","lineId","oldBindingId","newBindingId"},AT={"vaultGeneration","oldBindingGeneration","newBindingGeneration","priorManifestVersion","acceptedManifestVersion","acceptedAtMs"},AD={"rootFingerprint","oldBindingProofDigest","selectedReaderKeyId","priorManifestDigest","priorSignedManifestSha256","acceptedManifestDigest","acceptedSignedManifestSha256","electionCoreSha256","electionCommitment","electionBundleSha256"};
    private static readonly string[] CU={"accountId","deviceId","lineId","bindingId"},CT={"bindingGeneration","vaultGeneration","manifestVersion","comparedAtMs","permissionExpiresAtMs"},CD={"selectedReaderKeyId","rootFingerprint","manifestDigest","electionCommitment","electionBundleSha256"};
    private static readonly BigInteger Order=new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    private static void Need(bool value){if(!value)throw new CryptographicException("Election authority refused");}
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Part(byte[] b,int at,int count)=>b.AsSpan(at,count).ToArray();
    private static byte[] Join(params byte[][] chunks){var result=new byte[chunks.Sum(b=>b.Length)];int at=0;foreach(var b in chunks){b.CopyTo(result,at);at+=b.Length;}return result;}
    private static byte[] Label(string value)=>Encoding.ASCII.GetBytes(value+"\0");
    private static byte[] Framed(string domain,byte[] value){var size=new byte[4];BinaryPrimitives.WriteInt32BigEndian(size,value.Length);return Join(Label(domain),size,value);}
    private static bool Nonzero(byte[] value)=>value.Any(b=>b!=0);
    private static long Num(byte[] b,int at){long n=BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));Need(n>0);return n;}
    private static void Signature(byte[] point,byte[] raw,string domain,byte[] payload){
        var r=new BigInteger(raw.AsSpan(0,32),true,true);var s=new BigInteger(raw.AsSpan(32,32),true,true);Need(r>0 && r<Order && s>0 && s<=Order/2);
        using var publicPoint=HpkeRecipient.Point(point);using var verifier=ECDsa.Create(publicPoint.ExportParameters(false));
        Need(verifier.VerifyData(Framed(domain,payload),raw,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    private sealed class Record {
        private readonly Dictionary<string,byte[]> bytes=new();private readonly Dictionary<string,long> numbers=new();
        internal Record(IReadOnlyDictionary<string,object> input,string[] uuids,string[] times,string[] digests,bool current){
            var keys=new HashSet<string>(uuids.Concat(times).Concat(digests));if(current){keys.Add("profile");keys.Add("manifestProfile");}Need(keys.SetEquals(input.Keys));
            foreach(var name in keys){var value=input[name];if(times.Contains(name) || name is "profile" or "manifestProfile"){
                Need(value is long or int);long n=Convert.ToInt64(value);Need(n>0);numbers.Add(name,n);
            }else{Need(value is byte[]);var b=(byte[])((byte[])value).Clone();Need(b.Length==(uuids.Contains(name)?16:32) && Nonzero(b));bytes.Add(name,b);}}
            if(current)Need(N("profile")==3 && N("manifestProfile")==3 && N("permissionExpiresAtMs")>N("comparedAtMs"));
        }
        internal byte[] B(string name)=>(byte[])bytes[name].Clone();internal long N(string name)=>numbers[name];
    }
    public sealed class Proof {
        internal object Accepted{get;}public ManifestChain.Verified AcceptedManifest{get;}
        internal Proof(object permit,object accepted,ManifestChain.Verified manifest){Need(ReferenceEquals(permit,Permit));Accepted=accepted;AcceptedManifest=manifest;}
    }
    public sealed class Current {
        private readonly Record record;
        internal Current(object permit,object value){Need(ReferenceEquals(permit,Permit));record=(Record)value;}
        public byte[] Field(string name)=>(byte[])record.B(name).Clone();public long Number(string name)=>record.N(name);
    }
    public static Proof Verify(byte[] bundleInput,byte[] expectedCore,IReadOnlyDictionary<string,object> acceptedRecord,ManifestChain.Verified predecessor,
        byte[] signed02Input,byte[] signed03Input,byte[] devicePointInput,byte[] ownerPointInput){
        Need(bundleInput.Length==628 && expectedCore.Length==500 && devicePointInput.Length==65 && ownerPointInput.Length==65);
        var bundle=(byte[])bundleInput.Clone();var core=Part(bundle,0,500);var signed02=(byte[])signed02Input.Clone();var signed03=(byte[])signed03Input.Clone();var device=(byte[])devicePointInput.Clone();var owner=(byte[])ownerPointInput.Clone();var a=new Record(acceptedRecord,AU,AT,AD,false);
        Need(predecessor.Profile==2 && Same(signed02,predecessor.Bytes()) && a.N("acceptedAtMs")>=predecessor.ComparisonMs);
        Need(Same(core,(byte[])expectedCore.Clone()) && Same(Part(core,0,8),new byte[]{90,84,80,69,3,1,2,3}) && !Nonzero(Part(core,496,4)) && Nonzero(Part(core,56,16)) && Nonzero(Part(core,352,32)));
        int[] positions={8,24,40,72,104,136,184,224,256};string[] names={"accountId","deviceId","lineId","oldBindingId","oldBindingProofDigest","rootFingerprint","priorManifestDigest","acceptedManifestDigest","selectedReaderKeyId"};
        for(int i=0;i<positions.Length;i++)Need(Same(Part(core,positions[i],a.B(names[i]).Length),a.B(names[i])));
        int[] numbers={88,96,168,176,216};string[] numberNames={"oldBindingGeneration","newBindingGeneration","vaultGeneration","priorManifestVersion","acceptedManifestVersion"};
        for(int i=0;i<numbers.Length;i++)Need(Num(core,numbers[i])==a.N(numberNames[i]));
        long issued=Num(core,384),expires=Num(core,392);Need(issued<=a.N("acceptedAtMs") && a.N("acceptedAtMs")<expires && expires-issued<=300000 && a.N("newBindingGeneration")>a.N("oldBindingGeneration") && a.N("vaultGeneration")==1 && a.N("priorManifestVersion")<long.MaxValue && a.N("acceptedManifestVersion")==a.N("priorManifestVersion")+1);
        foreach(int at in new[]{400,432,464})Need(Nonzero(Part(core,at,32)));
        byte[][] values={signed02,signed03,core,bundle,Framed("ZTSE/line/payload-profile/commitment/v1",core)};string[] hashes={"priorSignedManifestSha256","acceptedSignedManifestSha256","electionCoreSha256","electionBundleSha256","electionCommitment"};
        for(int i=0;i<values.Length;i++)Need(Same(SHA256.HashData(values[i]),a.B(hashes[i])));
        var manifest=ManifestChain.ContinueChain(signed03,predecessor,3,a.N("acceptedAtMs"));
        Need(Same(manifest.Account(),a.B("accountId")) && manifest.Version==a.N("acceptedManifestVersion") && Same(manifest.Digest(),a.B("acceptedManifestDigest")) && predecessor.Version==a.N("priorManifestVersion") && Same(predecessor.Digest(),a.B("priorManifestDigest")));
        var generation=new byte[8];BinaryPrimitives.WriteInt64BigEndian(generation,1);var rootPin=Join(new byte[]{90,84,82,80,2},manifest.Account(),generation,manifest.RootPoint());
        Need(Same(SHA256.HashData(Join(Label("ZTSE/root-pin/v2"),rootPin)),a.B("rootFingerprint")));
        Need(Same(SHA256.HashData(Join(Label("ZTSE/key/v1"),new byte[]{1,1},device)),Part(core,288,32)) && Same(SHA256.HashData(Join(Label("ZTSE/key/v1"),new byte[]{1,1},owner)),Part(core,320,32)));
        var deviceSignature=Part(bundle,500,64);Signature(device,deviceSignature,"ZTSE/line/payload-profile/device/v1",core);Signature(owner,Part(bundle,564,64),"ZTSE/line/payload-profile/owner/v1",Join(core,SHA256.HashData(deviceSignature)));
        return new Proof(Permit,a,manifest);
    }
    public static Current RequireCurrent(Proof proof,ManifestChain.Verified manifest,IReadOnlyDictionary<string,object> authenticatedCurrent,long now){
        Need(now>0);var a=(Record)proof.Accepted;var c=new Record(authenticatedCurrent,CU,CT,CD,true);
        Need(now>=a.N("acceptedAtMs") && now>=c.N("comparedAtMs") && now<c.N("permissionExpiresAtMs") && now>=manifest.ComparisonMs && now<manifest.ExpiresMs);
        string[] cn={"accountId","deviceId","lineId","bindingId","selectedReaderKeyId","rootFingerprint","electionCommitment","electionBundleSha256"},an={"accountId","deviceId","lineId","newBindingId","selectedReaderKeyId","rootFingerprint","electionCommitment","electionBundleSha256"};
        for(int i=0;i<cn.Length;i++)Need(Same(c.B(cn[i]),a.B(an[i])));
        Need(c.N("bindingGeneration")==a.N("newBindingGeneration") && c.N("vaultGeneration")==1 && c.N("manifestVersion")>=a.N("acceptedManifestVersion"));
        Need(manifest.Profile==3 && manifest.Version==c.N("manifestVersion") && Same(manifest.Account(),c.B("accountId")) && Same(manifest.Digest(),c.B("manifestDigest")) && manifest.DescendsFrom(proof.AcceptedManifest));
        return new Current(Permit,c);
    }
}
