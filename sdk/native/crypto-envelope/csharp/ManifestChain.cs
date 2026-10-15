using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Zrotext.Candidate;

/// <summary>Historical provenance, not live authorization or durable chain selection.</summary>
public static class ManifestChain {
    private static readonly object ConstructionPermit=new();
    private static readonly BigInteger Order=new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    private static void Need(bool value){if(!value)throw new CryptographicException("Candidate manifest refused");}
    private static byte[] Part(byte[] value,int at,int count)=>value.AsSpan(at,count).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static bool Zero(byte[] value){foreach(var b in value)if(b!=0)return false;return true;}
    private static byte[] Domain(string value)=>Encoding.ASCII.GetBytes(value+"\0");
    private static byte[] Join(params byte[][] values){int size=0;foreach(var value in values)size+=value.Length;var output=new byte[size];int at=0;foreach(var value in values){value.CopyTo(output,at);at+=value.Length;}return output;}
    private static long Number(byte[] value,int at){long n=BinaryPrimitives.ReadInt64BigEndian(value.AsSpan(at,8));Need(n>=0);return n;}
    private static void Window(long issued,long expires,long now){Need(now>0 && issued>0 && expires>issued && expires-issued<=86400000 && now<expires);Need(issued<=now || issued-now<=300000);}
    private static void Signature(byte[] point,byte[] raw,string label,byte[] unsigned){
        var r=new BigInteger(raw.AsSpan(0,32),true,true);var s=new BigInteger(raw.AsSpan(32,32),true,true);Need(r>0 && r<Order && s>0 && s<=Order/2);
        using var publicPoint=HpkeRecipient.Point(point);using var verifier=ECDsa.Create(publicPoint.ExportParameters(false));
        var size=new byte[4];BinaryPrimitives.WriteInt32BigEndian(size,unsigned.Length);
        Need(verifier.VerifyData(Join(Domain(label),size,unsigned),raw,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    public sealed class RootPin {
        private readonly byte[] accountBytes,pointBytes;
        internal byte[] Account=>(byte[])accountBytes.Clone();
        internal byte[] Point=>(byte[])pointBytes.Clone();
        private RootPin(byte[] account,byte[] point){accountBytes=(byte[])account.Clone();pointBytes=(byte[])point.Clone();}
        /// <summary>Fingerprint must arrive over an independently authenticated owner channel.</summary>
        public static RootPin Enroll(byte[] input,byte[] comparedFingerprint){
            Need(input.Length==94 && comparedFingerprint.Length==32);var b=(byte[])input.Clone();var compared=(byte[])comparedFingerprint.Clone();
            Need(Same(Part(b,0,5),new byte[]{90,84,82,80,2}) && !Zero(Part(b,5,16)) && Number(b,21)==1);
            using var point=HpkeRecipient.Point(Part(b,29,65));Need(Same(SHA256.HashData(Join(Domain("ZTSE/root-pin/v2"),b)),compared));
            return new RootPin(Part(b,5,16),Part(b,29,65));
        }
    }
    public sealed class Verified {
        private readonly byte[] data,digestBytes,accountBytes,rootBytes,previousBytes;
        internal byte[] Data=>(byte[])data.Clone();
        internal byte[] DigestValue=>(byte[])digestBytes.Clone();
        internal byte[] AccountValue=>(byte[])accountBytes.Clone();
        internal byte[] Root=>(byte[])rootBytes.Clone();
        internal byte[] Previous=>(byte[])previousBytes.Clone();
        internal readonly int Predecessor;
        internal Verified? Parent{get;}
        public byte[] EnrolledRootPoint(){var first=this;while(first.Parent is not null)first=first.Parent;return first.RootPoint();}
        public long Generation=>Number(data,Profile==2?21:23);
        public int Profile{get;} public long Version{get;} public long IssuedMs{get;} public long ExpiresMs{get;} public long ComparisonMs{get;}
        internal Verified(object permit,byte[] b,int profile,int predecessor,long version,long issued,long expires,long comparison,byte[] digest,byte[] account,byte[] root,byte[] previous,Verified? parent=null){Need(ReferenceEquals(permit,ConstructionPermit));data=(byte[])b.Clone();Profile=profile;Predecessor=predecessor;Version=version;IssuedMs=issued;ExpiresMs=expires;ComparisonMs=comparison;digestBytes=(byte[])digest.Clone();accountBytes=(byte[])account.Clone();rootBytes=(byte[])root.Clone();previousBytes=(byte[])previous.Clone();Parent=parent;}
        public bool DescendsFrom(Verified historical){
            if(!Same(accountBytes,historical.accountBytes) || !Same(rootBytes,historical.rootBytes))return false;
            for(Verified? value=this;value is not null;value=value.Parent)if(value.Profile==historical.Profile && value.Version==historical.Version && Same(value.digestBytes,historical.digestBytes))return true;
            return false;
        }
        public byte[] Bytes()=>(byte[])Data.Clone();public byte[] Digest()=>(byte[])DigestValue.Clone();public byte[] Account()=>(byte[])AccountValue.Clone();public byte[] RootPoint()=>(byte[])Root.Clone();
        public byte[][] KeyRecords(){int at=Profile==2?151:153,count=Data[at-1];var output=new byte[count][];for(int i=0;i<count;i++)output[i]=Part(Data,at+149*i,149);return output;}
    }
    private static Verified Parse(byte[] input,int profile,long now){
        Need(profile is 2 or 3);int offset=profile==2?0:2;Need(input.Length>=364+offset && input.Length<=9751+offset);var b=(byte[])input.Clone();
        Need(Same(Part(b,0,5),new byte[]{90,84,77,65,(byte)profile}));int predecessor=profile==2?2:b[6];Need(profile==2 || b[5]==3 && predecessor is 2 or 3);
        int count=b[150+offset];Need(count>=1 && count<=64 && b.Length==215+offset+149*count);
        var account=Part(b,5+offset,16);var root=Part(b,85+offset,65);var previous=Part(b,53+offset,32);
        long generation=Number(b,21+offset),version=Number(b,29+offset),issued=Number(b,37+offset),expires=Number(b,45+offset);
        Need(!Zero(account) && generation>0 && (profile==2 || generation==1) && version>0);Window(issued,expires,now);using var rootPoint=HpkeRecipient.Point(root);
        byte[]? last=null;var points=new HashSet<string>();int owners=0,archives=0;
        for(int i=0;i<count;i++){
            int at=151+offset+149*i,role=b[at],state=b[at+148],scope=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at+130,2));
            var id=Part(b,at+1,32);var point=Part(b,at+33,65);var device=Part(b,at+98,16);var line=Part(b,at+114,16);var ordering=Part(b,at,33);
            long from=Number(b,at+132),until=Number(b,at+140);Need(role>=1 && role<=6);int[] expected={0,4,12,4,2,1,0};Need(role==3?scope is 4 or 8 or 12:scope==expected[role]);
            bool deviceBound=role is 1 or 4,lineBound=deviceBound || role==5;Need(deviceBound?!Zero(device):Zero(device));Need(lineBound?!Zero(line):Zero(line));
            Need(from<=until && state is 1 or 2);Need(last is null || last.AsSpan().SequenceCompareTo(ordering)<0);last=ordering;
            using var checkedPoint=HpkeRecipient.Point(point);Need(Same(id,SHA256.HashData(Join(Domain("ZTSE/key/v1"),role<=3?new byte[]{0,16}:new byte[]{1,1},point))));Need(points.Add(Convert.ToHexString(point)));
            if(role==6){owners++;Need(Same(point,root) && state==1 && from<=issued && until>=expires);}if(role==2 && state==1)archives++;
        }
        Need(owners==1 && archives==1);var unsigned=Part(b,0,b.Length-64);Signature(root,Part(b,b.Length-64,64),"ZTSE/manifest/v"+profile,unsigned);
        return new Verified(ConstructionPermit,b,profile,predecessor,version,issued,expires,now,SHA256.HashData(unsigned),account,root,previous);
    }
    public static Verified Genesis02(byte[] input,RootPin pin,long now){var value=Parse(input,2,now);Need(Same(value.AccountValue,pin.Account) && Same(value.Root,pin.Point) && value.Generation==1 && value.Version==1 && Zero(value.Previous));return value;}
    public static Verified ContinueChain(byte[] input,Verified prior,int expectedProfile,long now){
        Need(now>=prior.ComparisonMs && !(prior.Profile==3 && expectedProfile==2));if(prior.Profile==2 && expectedProfile==3)Window(prior.IssuedMs,prior.ExpiresMs,now);
        var value=Parse(input,expectedProfile,now);Need(Same(value.AccountValue,prior.AccountValue) && Same(value.Root,prior.Root) && value.Generation==prior.Generation);
        if(value.Profile==prior.Profile && value.Version==prior.Version && Same(value.DigestValue,prior.DigestValue))return Linked(value,prior.Parent);
        Need(prior.Version<long.MaxValue && value.Version==prior.Version+1 && Same(value.Previous,prior.DigestValue));Need(value.Profile==2 || value.Predecessor==prior.Profile);return Linked(value,prior);
    }
    // Original-grant server acceptance time is separate from the local durable floor.
    // Internal profile02/generation-one adapter; generic ContinueChain stays unchanged.
    internal static Verified OriginalAccepted02(byte[] input,RootPin pin,Verified? prior,long at){
        if(prior is null)return Genesis02(input,pin,at);
        Need(prior.Profile==2 && prior.Generation==1 && Same(prior.AccountValue,pin.Account) && Same(prior.Root,pin.Point));
        var historical=new Verified(ConstructionPermit,prior.Data,prior.Profile,prior.Predecessor,prior.Version,prior.IssuedMs,prior.ExpiresMs,0,prior.DigestValue,prior.AccountValue,prior.Root,prior.Previous,prior.Parent);
        return ContinueChain(input,historical,2,at);
    }
    /// <summary>External new-root approval, dual signatures and anchored genesis; not durable selection.</summary>
    public static Verified Rotate02(byte[] transition,byte[] newGenesis,Verified prior,byte[] independentlyApprovedRoot,long now){
        Need(prior.Profile==2 && now>=prior.ComparisonMs && transition.Length==343 && independentlyApprovedRoot.Length==65);byte[] raw=(byte[])transition.Clone(),expected=(byte[])independentlyApprovedRoot.Clone();Need(Same(Part(raw,0,5),new byte[]{90,84,82,84,2}));
        Need(prior.Generation<long.MaxValue && Same(Part(raw,5,16),prior.AccountValue) && Number(raw,21)==prior.Generation && Number(raw,29)==prior.Generation+1 && Same(Part(raw,37,65),prior.Root) && Same(Part(raw,102,65),expected) && !Same(expected,prior.Root) && Same(Part(raw,167,32),prior.DigestValue));
        Window(Number(raw,199),Number(raw,207),now);byte[] unsigned=Part(raw,0,215);Signature(prior.Root,Part(raw,215,64),"ZTSE/root-transition/v2",unsigned);Signature(expected,Part(raw,279,64),"ZTSE/root-transition/v2",unsigned);
        var value=Parse(newGenesis,2,now);Need(value.Generation==prior.Generation+1 && value.Version==1 && Same(value.AccountValue,prior.AccountValue) && Same(value.Root,expected) && Same(value.Previous,SHA256.HashData(unsigned)));return Linked(value,prior);
    }
    private static Verified Linked(Verified v,Verified? parent)=>new(ConstructionPermit,v.Data,v.Profile,v.Predecessor,v.Version,v.IssuedMs,v.ExpiresMs,v.ComparisonMs,v.DigestValue,v.AccountValue,v.Root,v.Previous,parent);
}
