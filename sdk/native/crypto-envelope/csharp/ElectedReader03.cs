using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;

public static class ElectedReader03 {
    public sealed record AuthoritySnapshot(IReadOnlyDictionary<string,object> AuthenticatedRecord,long NowMs);
    public interface IAuthoritySource {AuthoritySnapshot Read();}
    private static void Need(bool value){if(!value)throw new CryptographicException("Elected reader refused");}
    private static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
    private static byte[] Part(byte[] b,int at,int count)=>b.AsSpan(at,count).ToArray();
    private static long Number(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
    private static byte[] Find(byte[][] records,int role,byte[] id){foreach(var r in records)if(r[0]==role && Same(Part(r,1,32),id))return r;throw new CryptographicException("Elected key missing");}
    private static void Active(byte[] r,long when)=>Need(r[148]==1 && Number(r,132)<=when && when<Number(r,140));
    public static string OpenSoftware(byte[] input,ManifestChain.Verified manifest,Election03.Proof proof,IAuthoritySource source,byte[] expectedMessage,string expectedPeer,ECDiffieHellman recipient){
        var b=(byte[])input.Clone();var message=(byte[])expectedMessage.Clone();string peer=expectedPeer;Need(b.Length>=557 && b.Length<=34213 && message.Length==16 && !Same(message,new byte[16]));
        var snapshot=source.Read();long now=snapshot.NowMs;var authority=Election03.RequireCurrent(proof,manifest,snapshot.AuthenticatedRecord,now);
        Need(b[4]==3 && b[5]==1 && Same(Part(b,10,16),authority.Field("accountId")) && Same(Part(b,26,16),message) && Same(Part(b,42,16),authority.Field("deviceId")) && Same(Part(b,58,16),authority.Field("lineId")));
        Need(Number(b,74)==manifest.Version && Same(Part(b,82,32),manifest.Digest()));var records=manifest.KeyRecords();var signer=Find(records,5,Part(b,114,32));Active(signer,now);Need(Same(Part(signer,114,16),authority.Field("lineId")));
        var envelope=SignedEnvelope.Verify(b,3,Part(signer,33,65));int prefix=10+BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(8,2));Need(Encoding.ASCII.GetString(b,164,prefix-164)==peer);
        long observed=Number(b,146),expires=Number(b,154);Need(observed>0 && observed<=now && observed>=manifest.IssuedMs && now<expires && expires<=manifest.ExpiresMs && expires<=authority.Number("permissionExpiresAtMs"));Active(signer,observed);Need(expires<=Number(signer,140));
        int end=prefix+16+BinaryPrimitives.ReadInt32BigEndian(b.AsSpan(prefix+12,4));var elected=authority.Field("selectedReaderKeyId");byte[]? selected=null;
        for(int i=0;i<b[end];i++){
            int at=end+1+146*i,role=b[at];var id=Part(b,at+1,32);var record=Find(records,role,id);Active(record,now);Active(record,observed);
            Need((BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(130,2))&4)!=0 && expires<=Number(record,140));
            if(role==1){Need(Same(id,elected) && Same(Part(record,98,16),authority.Field("deviceId")) && Same(Part(record,114,16),authority.Field("lineId")));selected=record;}
        }
        Need(selected is not null);byte[]? cek=null;
        try{
            cek=HpkeRecipient.Open(recipient,Part(selected!,33,65),envelope.Encapsulated(1,elected),envelope.WrapInfo(1,elected),envelope.WrapAad(1,elected),envelope.WrappedKey(1,elected));
            var result=CandidateBody.Open(cek,envelope.Nonce(),envelope.BodyAad(),envelope.BodyCiphertext());var after=source.Read();Need(after.NowMs>=now && after.NowMs<expires);Election03.RequireCurrent(proof,manifest,after.AuthenticatedRecord,after.NowMs);return result;
        }finally{if(cek is not null)CryptographicOperations.ZeroMemory(cek);}
    }
}
