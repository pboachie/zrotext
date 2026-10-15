using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;
sealed class Source(Func<ElectedReader03.AuthoritySnapshot> read):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>read();}
static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Elected assertion");checks++;}
    static void Refuses(Action work){try{work();}catch(Exception e)when(e is CryptographicException or ArgumentException){checks++;return;}throw new Exception("Invalid elected envelope accepted");}
    static void Main(){
        var wire=new Dictionary<string,byte[]>();var accepted=new Dictionary<string,object>();var authority=new Dictionary<string,object>();string? line;
        while((line=Console.ReadLine()) is not null){var f=line.Split('\t');object value=f[1]=="b"?Convert.FromHexString(f[2]):long.Parse(f[2]);if(f[0].StartsWith("accepted."))accepted.Add(f[0][9..],value);else if(f[0].StartsWith("authority."))authority.Add(f[0][10..],value);else wire.Add(f[0],(byte[])value);}
        var prior=ManifestChain.Genesis02(wire["signed02"],ManifestChain.RootPin.Enroll(wire["rootPin"],wire["fingerprint"]),10000);
        var proof=Election03.Verify(wire["bundle"],wire["core"],accepted,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]);var manifest=proof.AcceptedManifest;
        var point=wire["readerPoint"];using var key=ECDiffieHellman.Create(new ECParameters {Curve=ECCurve.NamedCurves.nistP256,D=wire["readerScalar"],Q=new ECPoint {X=point.AsSpan(1,32).ToArray(),Y=point.AsSpan(33,32).ToArray()}});
        var source=new Source(()=>new(authority,30000));
        Check(ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,source,wire["message"],"+12",key)==Encoding.UTF8.GetString(wire["text"]));
        Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,source,wire["message"],"+13",key));
        Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,source,new byte[16],"+12",key));
        int calls=0;var expires=new Source(()=>new(authority,++calls==1?30000:40000));Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,expires,wire["message"],"+12",key));Check(calls==2);
        var revoked=new Dictionary<string,object>(authority);revoked["selectedReaderKeyId"]=new byte[32];int count=0;var revoke=new Source(()=>new(++count==1?authority:revoked,30000));
        Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,revoke,wire["message"],"+12",key));Check(count==2);
        Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],manifest,proof,new Source(()=>new(revoked,30000)),wire["message"],"+12",null!));
        foreach(int at in new[]{4,5,10,26,42,58,74,82,114,146,154,164,wire["envelope"].Length-1}){var changed=(byte[])wire["envelope"].Clone();changed[at]^=1;Refuses(()=>ElectedReader03.OpenSoftware(changed,manifest,proof,source,wire["message"],"+12",key));}
        Console.WriteLine($"{checks} elected reader checks passed");
    }
}
