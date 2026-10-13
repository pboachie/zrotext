using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Zrotext.Candidate;
sealed class Current(Func<byte[],long,byte[],byte[],bool> check):SealedReader02.ICurrentSelection { public bool IsCurrent(byte[] a,long v,byte[] d,byte[] w)=>check(a,v,d,w); }
static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Reader assertion");checks++;}
    static void Refuses(Action a){try{a();}catch(Exception e)when(e is CryptographicException or ArgumentException){checks++;return;}throw new Exception("Reader accepted invalid input");}
    static void Main(){int rows=0;string? line;while((line=Console.ReadLine()) is not null){
        var f=line.Split('\t');long now=long.Parse(f[1]);var d=f.Skip(2).Select(Convert.FromHexString).ToArray();
        var manifest=ManifestChain.Genesis02(d[2],ManifestChain.RootPin.Enroll(d[0],d[1]),now);
        using var key=ECDiffieHellman.Create(new ECParameters {Curve=ECCurve.NamedCurves.nistP256,D=d[4],Q=new ECPoint {X=d[6].AsSpan(1,32).ToArray(),Y=d[6].AsSpan(33,32).ToArray()}});
        var current=new Current((a,v,h,w)=>a.SequenceEqual(manifest.Account()) && v==manifest.Version && h.SequenceEqual(manifest.Digest()));
        Check(SealedReader02.Open(d[3],manifest,now,2,d[5],key,current)==Encoding.UTF8.GetString(d[7]));
        var signer=manifest.KeyRecords().Single(r=>r[0]==4);Check(SignedEnvelope.Verify(d[8],2,signer.AsSpan(33,65).ToArray()).Kind==2);
        int backdatedCalls=0;Refuses(()=>SealedReader02.Open(d[8],manifest,now,2,d[5],key,new Current((a,v,h,w)=>{backdatedCalls++;return true;})));Check(backdatedCalls==0);
        Refuses(()=>SealedReader02.Open(d[3],manifest,now,2,d[5],key,new Current((a,v,h,w)=>false)));
        int calls=0;Refuses(()=>SealedReader02.Open(d[3],manifest,now,2,d[5],key,new Current((a,v,h,w)=>++calls==1)));Check(calls==2);
        Refuses(()=>SealedReader02.Open(d[3],manifest,now-1,2,d[5],key,current));Refuses(()=>SealedReader02.Open(d[3],manifest,manifest.ExpiresMs,2,d[5],key,current));
        Refuses(()=>SealedReader02.Open(d[3],manifest,now,1,d[5],key,current));
        foreach(int at in new[]{4,10,26,42,58,74,82,114,146,d[3].Length-1}){var changed=(byte[])d[3].Clone();changed[at]^=1;Refuses(()=>SealedReader02.Open(changed,manifest,now,2,d[5],key,current));}
        var wrongId=(byte[])d[5].Clone();wrongId[0]^=1;Refuses(()=>SealedReader02.Open(d[3],manifest,now,2,wrongId,key,current));rows++;
    }Check(rows==2);Console.WriteLine($"{checks} reader checks passed");}
}
