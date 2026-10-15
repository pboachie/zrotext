using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Zrotext.Candidate;

sealed class Current(Func<byte[],long,byte[],byte[],bool> check):SealedReader02.ICurrentSelection {public bool IsCurrent(byte[] a,long v,byte[] d,byte[] w)=>check(a,v,d,w);}
sealed class Authority(Dictionary<string,object> record):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>new(record,30000);}
static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Protected recipient assertion");checks++;}
    static void Refuses(Action work){try{work();}catch(Exception e)when(e is CryptographicException or ArgumentException){checks++;return;}throw new Exception("Protected refusal missing");}
    static byte[] B(JsonElement value,string name)=>Convert.FromBase64String(value.GetProperty(name).GetString()!);
    static Dictionary<string,object> Record(JsonElement value)=>value.EnumerateObject().ToDictionary(p=>p.Name,p=>p.Value.ValueKind==JsonValueKind.String?(object)Convert.FromBase64String(p.Value.GetString()!):p.Value.GetInt64());
    static JsonDocument Produce(string producer,string name,byte[] point){
        var info=new ProcessStartInfo("node"){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};info.ArgumentList.Add(Path.Combine(producer,name));info.ArgumentList.Add("--recipient-point");info.ArgumentList.Add(Convert.ToHexString(point).ToLowerInvariant());
        using var process=Process.Start(info)!;string output=process.StandardOutput.ReadToEnd();string error=process.StandardError.ReadToEnd();process.WaitForExit();if(process.ExitCode!=0)throw new Exception("Independent producer failed: "+error);return JsonDocument.Parse(output);
    }
    static void Main(string[] args){
        if(args.Length!=2)throw new ArgumentException("Expected producer directory and external pending receipt path");
        try{ProtectedRecipient.Probe();}catch(Exception e)when(e is PlatformNotSupportedException or CryptographicException){Console.WriteLine("UNQUALIFIED: read-only Windows PCP capability unavailable; no key creation attempted");return;}
        string receipt=Path.GetFullPath(args[1]);ProtectedRecipient? owner=null;bool deleted=false;
        try{
            bool recorded=false;owner=ProtectedRecipient.Create(alias=>{
                using var stream=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);
                stream.Write(Encoding.UTF8.GetBytes(alias+"\n"));stream.Flush(true);recorded=true;
            });Check(recorded);byte[] point=owner.PublicPoint();Check(point.Length==65 && point[0]==4);
            using(var reopened=ProtectedRecipient.Open(owner.Alias,point)){Check(reopened.PublicPoint().SequenceEqual(point));Refuses(()=>reopened.DeleteCreated());}
            using var other=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);var q=other.ExportParameters(false).Q;var wrong=new byte[65];wrong[0]=4;q.X!.CopyTo(wrong,1);q.Y!.CopyTo(wrong,33);Refuses(()=>ProtectedRecipient.Open(owner.Alias,wrong).Dispose());
            using(var fixture=Produce(args[0],"produce-fixture.mjs",point)){
                var f=fixture.RootElement;Check(!f.TryGetProperty("archiveScalar",out _));var manifest=ManifestChain.Genesis02(B(f,"manifest"),ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint")),10000);
                var current=new Current((a,v,d,w)=>v==manifest.Version && d.SequenceEqual(manifest.Digest()));
                foreach(string kind in new[]{"inbound","outbound"})Check(owner.OpenProfile02(B(f,kind),manifest,10000,2,B(f,"reader"),current)==f.GetProperty("text").GetString());
                Refuses(()=>owner.OpenProfile02(B(f,"inbound"),manifest,10000,2,B(f,"reader"),new Current((a,v,d,w)=>false)));
            }
            using(var fixture=Produce(args[0],"produce-election03.mjs",point)){
                var f=fixture.RootElement;Check(!f.TryGetProperty("readerScalar",out _));var prior=ManifestChain.Genesis02(B(f,"signed02"),ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint")),10000);
                var proof=Election03.Verify(B(f,"bundle"),B(f,"core"),Record(f.GetProperty("accepted")),prior,B(f,"signed02"),B(f,"signed03"),B(f,"deviceSigningPoint"),B(f,"ownerApprovalPoint"));
                var authority=new Authority(Record(f.GetProperty("authority")));Check(owner.OpenElected03(B(f,"envelope"),proof.AcceptedManifest,proof,authority,B(f,"message"),"+12")==f.GetProperty("bodyText").GetString());
                Refuses(()=>owner.OpenElected03(B(f,"envelope"),proof.AcceptedManifest,proof,authority,B(f,"message"),"+13"));
            }
            string alias=owner.Alias;owner.DeleteCreated();deleted=true;Refuses(()=>owner.PublicPoint());Refuses(()=>ProtectedRecipient.Open(alias,point).Dispose());File.Delete(receipt);
            Console.WriteLine($"QUALIFIED: {checks} native PCP recipient checks passed; owned test key deleted");
        }finally{if(owner is not null && !deleted){owner.DeleteCreated();File.Delete(receipt);}owner?.Dispose();}
    }
}
