using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using Zrotext.Candidate;
static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Election assertion");checks++;}
    static void Refuses(Action work){try{work();}catch(CryptographicException){checks++;return;}throw new Exception("Invalid election accepted");}
    static void Main(){
        var wire=new Dictionary<string,byte[]>();var accepted=new Dictionary<string,object>();var authority=new Dictionary<string,object>();string? line;
        while((line=Console.ReadLine()) is not null){var f=line.Split('\t');object value=f[1]=="b"?Convert.FromHexString(f[2]):long.Parse(f[2]);if(f[0].StartsWith("accepted."))accepted.Add(f[0][9..],value);else if(f[0].StartsWith("authority."))authority.Add(f[0][10..],value);else wire.Add(f[0],(byte[])value);}
        var pin=ManifestChain.RootPin.Enroll(wire["rootPin"],wire["fingerprint"]);var prior=ManifestChain.Genesis02(wire["signed02"],pin,10000);
        var proof=Election03.Verify(wire["bundle"],wire["core"],accepted,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]);
        var current=Election03.RequireCurrent(proof,proof.AcceptedManifest,authority,30000);
        Check(current.Number("manifestVersion")==2);Check(current.Field("accountId").SequenceEqual(prior.Account()));
        var exposed=current.Field("accountId");exposed[0]^=1;Check(current.Field("accountId").SequenceEqual(prior.Account()));
        foreach(var name in authority.Keys){var changed=new Dictionary<string,object>(authority);if(changed[name] is byte[] original){var b=(byte[])original.Clone();b[0]^=1;changed[name]=b;}else changed[name]=0L;Refuses(()=>Election03.RequireCurrent(proof,proof.AcceptedManifest,changed,30000));}
        Refuses(()=>Election03.RequireCurrent(proof,prior,authority,30000));Refuses(()=>Election03.RequireCurrent(proof,proof.AcceptedManifest,authority,0));Refuses(()=>Election03.RequireCurrent(proof,proof.AcceptedManifest,authority,60000));
        foreach(int at in new[]{0,56,72,88,136,184,256,288,320,352,384,400,432,464,496,500,564,627}){var changed=(byte[])wire["bundle"].Clone();changed[at]^=1;Refuses(()=>Election03.Verify(changed,wire["core"],accepted,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]));}
        foreach(var name in accepted.Keys){if(name=="newBindingId")continue;var changed=new Dictionary<string,object>(accepted);if(changed[name] is byte[] original){var b=(byte[])original.Clone();b[0]^=1;changed[name]=b;}else changed[name]=0L;Refuses(()=>Election03.Verify(wire["bundle"],wire["core"],changed,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]));}
        Refuses(()=>new Election03.Proof(new object(),new object(),prior));Refuses(()=>new Election03.Current(new object(),new object()));
        foreach(int at in new[]{500,564}){var changed=(byte[])wire["bundle"].Clone();changed[at]^=1;var rebound=new Dictionary<string,object>(accepted);rebound["electionBundleSha256"]=SHA256.HashData(changed);Refuses(()=>Election03.Verify(changed,wire["core"],rebound,prior,wire["signed02"],wire["signed03"],wire["deviceSigningPoint"],wire["ownerApprovalPoint"]));}
        ((byte[])accepted["accountId"])[0]^=1;Check(Election03.RequireCurrent(proof,proof.AcceptedManifest,authority,30000).Field("accountId").SequenceEqual(prior.Account()));
        Console.WriteLine($"{checks} election checks passed");
    }
}
