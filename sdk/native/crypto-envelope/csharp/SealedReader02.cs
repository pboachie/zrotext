using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Zrotext.Candidate;

public static class SealedReader02 {
    public interface ICurrentSelection {bool IsCurrent(byte[] account,long version,byte[] digest,byte[] signedEnvelope);}
    private static void Need(bool value){if(!value)throw new CryptographicException("Reader authority refused");}
    private static byte[] Part(byte[] b,int at,int count)=>b.AsSpan(at,count).ToArray();
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static long Number(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static byte[] Find(byte[][] records,int role,byte[] id){foreach(var record in records)if(record[0]==role && Same(Part(record,1,32),id))return record;throw new CryptographicException("Manifest key missing");}
    private static void Active(byte[] record,long now)=>Need(record[148]==1 && Number(record,132)<=now && now<Number(record,140));
    public static string Open(byte[] input,ManifestChain.Verified manifest,long now,int recipientRole,byte[] recipientId,ECDiffieHellman recipient,ICurrentSelection current){
        return OpenBound(input,manifest,manifest,now,recipientRole,recipientId,recipient,current,false);
    }
    public static string OpenHistoricalArchive(byte[] input,ManifestChain.Verified historical,ManifestChain.Verified selected,long now,byte[] recipientId,ECDiffieHellman recipient,ICurrentSelection current){
        return OpenBound(input,historical,selected,now,2,recipientId,recipient,current,true);
    }
    private static string OpenBound(byte[] input,ManifestChain.Verified manifest,ManifestChain.Verified selectedManifest,long now,int recipientRole,byte[] recipientId,ECDiffieHellman recipient,ICurrentSelection current,bool historical){
        Need(manifest.Profile==2 && selectedManifest.Profile==2 && selectedManifest.DescendsFrom(manifest) && now>=selectedManifest.ComparisonMs && now<selectedManifest.ExpiresMs);
        var b=(byte[])input.Clone();var id=(byte[])recipientId.Clone();Need(b.Length>=426 && b.Length<=36864 && id.Length==32);
        int kind=b[5];Need((kind is 1 or 2) && (!historical || kind==2));var records=manifest.KeyRecords();var signer=Find(records,kind==1?5:4,Part(b,114,32));if(!historical)Active(signer,now);
        var envelope=SignedEnvelope.Verify(b,2,Part(signer,33,65));
        Need(Same(Part(b,10,16),manifest.Account()) && Number(b,74)==manifest.Version && Same(Part(b,82,32),manifest.Digest()));
        Need(Same(Part(signer,114,16),Part(b,58,16)));if(kind==2)Need(Same(Part(signer,98,16),Part(b,42,16)));
        long observed=Number(b,146);Need(observed>0 && observed<=now && observed>=manifest.IssuedMs && observed<manifest.ExpiresMs);Active(signer,observed);if(kind==1)Need(now<Number(b,154) && Number(b,154)<=manifest.ExpiresMs);
        int prefix=10+BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2)),end=prefix+16+BinaryPrimitives.ReadInt32BigEndian(b.AsSpan(prefix+12,4)),count=b[end];byte[]? selected=null;
        for(int i=0;i<count;i++){
            int at=end+1+146*i,role=b[at];var wrapId=Part(b,at+1,32);var record=Find(records,role,wrapId);if(!historical)Active(record,now);Active(record,observed);
            int scope=BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(130,2));Need((scope&(kind==1?4:8))!=0);
            if(role==1)Need(kind==1 && Same(Part(record,98,16),Part(b,42,16)) && Same(Part(record,114,16),Part(b,58,16)));
            if(role==recipientRole && Same(wrapId,id))selected=record;
        }
        Need(selected is not null);var live=Find(selectedManifest.KeyRecords(),recipientRole,id);Active(live,now);
        Need((BinaryPrimitives.ReadUInt16BigEndian(live.AsSpan(130,2))&(kind==1?4:8))!=0 && Same(Part(live,33,65),Part(selected!,33,65)));
        Need(current.IsCurrent(selectedManifest.Account(),selectedManifest.Version,selectedManifest.Digest(),(byte[])b.Clone()));byte[]? cek=null;
        try{
            cek=HpkeRecipient.Open(recipient,Part(selected!,33,65),envelope.Encapsulated(recipientRole,id),envelope.WrapInfo(recipientRole,id),envelope.WrapAad(recipientRole,id),envelope.WrappedKey(recipientRole,id));
            var result=CandidateBody.Open(cek,envelope.Nonce(),envelope.BodyAad(),envelope.BodyCiphertext());
            Need(current.IsCurrent(selectedManifest.Account(),selectedManifest.Version,selectedManifest.Digest(),(byte[])b.Clone()));return result;
        }finally{if(cek is not null)CryptographicOperations.ZeroMemory(cek);}
    }
}
