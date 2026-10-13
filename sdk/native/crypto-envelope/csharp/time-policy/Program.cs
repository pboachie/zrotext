using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;

sealed class Authority(Dictionary<string,object> record,long now):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>new(record,now);}
static class Program {
    static string Open(Dictionary<string,byte[]> wire,Election03.Proof proof,Dictionary<string,object> authority,long now,byte[] envelope){
        var point=wire["readerPoint"];using var reader=ECDiffieHellman.Create(new ECParameters {Curve=ECCurve.NamedCurves.nistP256,D=wire["readerScalar"],Q=new ECPoint {X=point.AsSpan(1,32).ToArray(),Y=point.AsSpan(33,32).ToArray()}});
        return ElectedReader03.OpenSoftware(envelope,proof.AcceptedManifest,proof,new Authority(authority,now),wire["message"],"+12",reader);
    }
    static int Main(string[] args){
        if(args.Length==1 && args[0]=="--probe"){try{ProtectedSigner.Probe();return 0;}catch(Exception e)when(e is PlatformNotSupportedException or CryptographicException){return 77;}}
        if(args.Length!=1)throw new ArgumentException("External pending receipt required");
        bool readerMode=args[0]=="--readers";string receipt=args[0];ProtectedSigner? owner=null;
        try{
            if(!readerMode){
            owner=ProtectedSigner.Create(alias=>{using var stream=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);stream.Write(Encoding.UTF8.GetBytes(alias+"\n"));stream.Flush(true);});
            Console.WriteLine(Convert.ToHexString(owner.PublicPoint()).ToLowerInvariant());Console.Out.Flush();
            }
            int count=0;
            foreach(string block in Console.In.ReadToEnd().Replace("\r\n","\n").Trim().Split("\n\n")){
                string[] lines=block.Split('\n'),head=lines[0].Split('\t');if(head.Length!=5)throw new Exception("Policy header");
                string name=head[0];bool accept=head[1]=="true";long observed=long.Parse(head[2]),now=long.Parse(head[3]),expires=long.Parse(head[4]);
                var wire=new Dictionary<string,byte[]>();var accepted=new Dictionary<string,object>();var authority=new Dictionary<string,object>();
                foreach(string line in lines.Skip(1)){var f=line.Split('\t');object value=f[1]=="b"?Convert.FromHexString(f[2]):long.Parse(f[2]);if(f[0].StartsWith("accepted."))accepted.Add(f[0][9..],value);else if(f[0].StartsWith("authority."))authority.Add(f[0][10..],value);else wire.Add(f[0],(byte[])value);}
                // A malformed authority fixture must fail the harness, not count as a policy refusal.
                var prior=ManifestChain.Genesis02(wire["signed02"],ManifestChain.RootPin.Enroll(wire["rootPin"],wire["fingerprint"]),10000);
                var proof=Election03.Verify(wire["bundle"],wire["core"],accepted,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]);
                var recipients=proof.AcceptedManifest.KeyRecords().Where(k=>k[0] is >=1 and <=3).Select(k=>new Compose03.Recipient(k[0],k.AsSpan(1,32).ToArray())).ToArray();
                if(readerMode){
                    SignedEnvelope.Verify(wire["envelope"],3,wire["signerPoint"]);
                    string opened;
                    try{opened=Open(wire,proof,authority,now,wire["envelope"]);}catch(Exception e)when(e is CryptographicException or ArgumentException){if(accept)throw new Exception("Accepted reader policy refused: "+name,e);Console.WriteLine("READ "+name+" refused");count++;continue;}
                    if(!accept || opened!=Encoding.UTF8.GetString(wire["bodyText"]))throw new Exception("Reader policy mismatch: "+name);
                    Console.WriteLine("READ "+name+" accepted");count++;continue;
                }
                var request=new Compose03.Request(proof.AcceptedManifest,proof,new Authority(authority,now),wire["message"],observed,expires,"+12",Encoding.UTF8.GetString(wire["bodyText"]),owner!,recipients);
                byte[] envelope;
                try{envelope=Compose03.Fresh(request);}catch(Exception e)when(e is CryptographicException or ArgumentException){if(accept)throw new Exception("Accepted policy refused: "+name,e);Console.WriteLine("REFUSED "+name);count++;continue;}
                if(!accept)throw new Exception("Policy rejection missing: "+name);
                if(Open(wire,proof,authority,now,envelope)!=request.Content)throw new Exception("Native policy self-open: "+name);
                Console.WriteLine("ENVELOPE "+name+" "+Convert.ToBase64String(envelope));count++;
            }
            Console.WriteLine((readerMode?"READERS: ":"QUALIFIED: ")+$"{count} Csharp signed time-policy cases passed");return 0;
        }finally{if(owner is not null){owner.DeleteCreated();File.Delete(receipt);owner.Dispose();}}
    }
}
