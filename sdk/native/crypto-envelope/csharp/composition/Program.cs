using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Zrotext.Candidate;

sealed class Authority(Dictionary<string,object> record,long now=30000):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>new(record,now);}
sealed class DynamicAuthority(Func<ElectedReader03.AuthoritySnapshot> read):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>read();}
static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Composition assertion");checks++;}
    static void Refuses(Action action){try{action();}catch(Exception e)when(e is CryptographicException or ArgumentException or InvalidOperationException){checks++;return;}throw new Exception("Composition accepted invalid input");}
    static byte[] B(JsonElement d,string name)=>Convert.FromBase64String(d.GetProperty(name).GetString()!);
    static Dictionary<string,object> Record(JsonElement d)=>d.EnumerateObject().ToDictionary(p=>p.Name,p=>p.Value.ValueKind==JsonValueKind.String?(object)Convert.FromBase64String(p.Value.GetString()!):p.Value.GetInt64());
    static string RunNode(string directory,string script,string? point=null,string? input=null){
        var info=new ProcessStartInfo("node"){RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true,UseShellExecute=false};info.Environment.Remove("NODE_OPTIONS");info.Environment.Remove("NODE_PATH");info.ArgumentList.Add(Path.Combine(directory,script));
        if(point is not null){info.ArgumentList.Add("--signer-point");info.ArgumentList.Add(point);}
        using var child=Process.Start(info)!;if(input is not null)child.StandardInput.Write(input);child.StandardInput.Close();string result=child.StandardOutput.ReadToEnd(),error=child.StandardError.ReadToEnd();child.WaitForExit();if(child.ExitCode!=0)throw new Exception("Independent consumer failed: "+error);return result;
    }
    static Compose03.Request Inputs(JsonElement f,ProtectedSigner signer){
        var prior=ManifestChain.Genesis02(B(f,"signed02"),ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint")),10000);
        var proof=Election03.Verify(B(f,"bundle"),B(f,"core"),Record(f.GetProperty("accepted")),prior,B(f,"signed02"),B(f,"signed03"),B(f,"deviceSigningPoint"),B(f,"ownerApprovalPoint"));
        return new(proof.AcceptedManifest,proof,new Authority(Record(f.GetProperty("authority"))),B(f,"message"),30000,40000,"+12","Native composed 🌱",signer,proof.AcceptedManifest.KeyRecords().Where(k=>k[0] is 1 or 2).Select(k=>new Compose03.Recipient(k[0],k.AsSpan(1,32).ToArray())).ToArray());
    }
    static void Consume(string directory,JsonElement fixture,byte[] envelope){var input=JsonSerializer.Serialize(new{fixture,envelope=Convert.ToBase64String(envelope),expectedText="Native composed 🌱"});using var result=JsonDocument.Parse(RunNode(directory,"consume-native03.mjs",input:input));Check(result.RootElement.GetProperty("verified").GetBoolean() && result.RootElement.GetProperty("openedRecipients").GetInt32()==2);}
    static void Main(string[] args){
        if(args.Length==5 && args[0]=="--replay"){
            using var fixture=JsonDocument.Parse(File.ReadAllText(args[1]));using var signer=ProtectedSigner.Open(args[3],Convert.FromHexString(args[4]));var f=fixture.RootElement;Console.WriteLine(Convert.ToBase64String(Compose03.ComposeOrReplay(args[2],B(f,"rootPin"),B(f,"fingerprint"),Inputs(f,signer))));return;
        }
        if(args.Length!=2)throw new ArgumentException("Producer directory and fresh pending receipt required");
        try{ProtectedSigner.Probe();}catch(Exception e)when(e is PlatformNotSupportedException or CryptographicException){Console.WriteLine("UNQUALIFIED: read-only signing capability unavailable; no creation attempted");return;}
        string receipt=Path.GetFullPath(args[1]),folder=Path.Combine(Path.GetTempPath(),"zrotext-managed-compose-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);ProtectedSigner? owner=null;bool deleted=false;
        try{
            owner=ProtectedSigner.Create(alias=>{using var f=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);f.Write(Encoding.UTF8.GetBytes(alias+"\n"));f.Flush(true);});var signer=owner;byte[] point=signer.PublicPoint();Check(point.Length==65);
            using(var reopened=ProtectedSigner.Open(signer.Alias,point)){Check(reopened.PublicPoint().SequenceEqual(point));Refuses(reopened.DeleteCreated);}
            using(var other=ECDsa.Create(ECCurve.NamedCurves.nistP256)){var q=other.ExportParameters(false).Q;var wrong=new byte[65];wrong[0]=4;q.X!.CopyTo(wrong,1);q.Y!.CopyTo(wrong,33);Refuses(()=>ProtectedSigner.Open(signer.Alias,wrong).Dispose());}
            Refuses(()=>signer.SignEnvelope03(new byte[493]));
            using var fixture=JsonDocument.Parse(RunNode(args[0],"produce-election03.mjs",Convert.ToHexString(point).ToLowerInvariant()));var data=fixture.RootElement;var request=Inputs(data,signer);
            byte[] fresh=Compose03.Fresh(request),another=Compose03.Fresh(request);Check(!fresh.SequenceEqual(another));Consume(args[0],data,fresh);Consume(args[0],data,another);
            foreach(var bad in new[]{request with{Message=new byte[16]},request with{ObservedMs=8000},request with{ObservedMs=30001},request with{ExpiresMs=60001},request with{Peer="+01"},request with{Content=""},request with{Content="\ufeffbad"},request with{Content="bad\0"},request with{Content="\ud800"},request with{Content=new string('x',32769)},request with{Recipients=request.Recipients.Take(1).ToArray()},request with{Recipients=request.Recipients.Concat(request.Recipients).ToArray()}})Refuses(()=>Compose03.Fresh(bad));
            var revoked=Record(data.GetProperty("authority"));revoked["bindingGeneration"]=99L;Refuses(()=>Compose03.Fresh(request with{Authority=new Authority(revoked)}));
            int reads=0;var valid=Record(data.GetProperty("authority"));Refuses(()=>Compose03.Fresh(request with{Authority=new DynamicAuthority(()=>new(valid,++reads==1?30000:40000))}));Check(reads==2);
            string journal=Path.Combine(folder,"outbound.bin");byte[] pin=B(data,"rootPin"),fingerprint=B(data,"fingerprint");byte[] committed=Compose03.ComposeOrReplay(journal,pin,fingerprint,request);Check(committed.SequenceEqual(Compose03.ComposeOrReplay(journal,pin,fingerprint,request)));Consume(args[0],data,committed);
            Refuses(()=>Compose03.ComposeOrReplay(journal,pin,fingerprint,request with{Content="different"}));Refuses(()=>Compose03.ComposeOrReplay(journal,pin,fingerprint,request with{Authority=new Authority(revoked)}));
            string fixturePath=Path.Combine(folder,"fixture.json");File.WriteAllText(fixturePath,data.GetRawText());var info=new ProcessStartInfo("dotnet"){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};foreach(string arg in new[]{Assembly.GetExecutingAssembly().Location,"--replay",fixturePath,journal,signer.Alias,Convert.ToHexString(point)})info.ArgumentList.Add(arg);
            using(var child=Process.Start(info)!){string output=child.StandardOutput.ReadToEnd(),error=child.StandardError.ReadToEnd();child.WaitForExit();if(child.ExitCode!=0)throw new Exception("Replay process failed: "+error);Check(Convert.FromBase64String(output.Trim()).SequenceEqual(committed));}
            var concurrent=request with{Message=RandomNumberGenerator.GetBytes(16)};var tasks=Enumerable.Range(0,2).Select(_=>Task.Run(()=>Compose03.ComposeOrReplay(journal,pin,fingerprint,concurrent))).ToArray();Task.WaitAll(tasks);Check(tasks[0].Result.SequenceEqual(tasks[1].Result));
            int afterReads=0;var interrupted=request with{Message=RandomNumberGenerator.GetBytes(16)};
            Refuses(()=>Compose03.ComposeOrReplay(journal,pin,fingerprint,interrupted with{Authority=new DynamicAuthority(()=>new(++afterReads==4?revoked:valid,30000))}));Check(afterReads==4);
            long persisted=new FileInfo(journal).Length;byte[] recovered=Compose03.ComposeOrReplay(journal,pin,fingerprint,interrupted);Check(new FileInfo(journal).Length==persisted);SignedEnvelope.Verify(recovered,3,point);
            string partial=Path.Combine(folder,"partial.bin");File.Copy(journal,partial);using(var f=new FileStream(partial,FileMode.Append))f.Write(new byte[]{1,2,3});Refuses(()=>Compose03.ComposeOrReplay(partial,pin,fingerprint,request));
            string alias=signer.Alias;signer.DeleteCreated();deleted=true;Refuses(()=>signer.SignEnvelope03(fresh.AsSpan(0,fresh.Length-64).ToArray()));Refuses(()=>ProtectedSigner.Open(alias,point).Dispose());File.Delete(receipt);
            foreach(string file in new[]{journal,fixturePath,partial})File.Delete(file);Directory.Delete(folder);Console.WriteLine($"QUALIFIED: {checks} native protected composition/replay checks passed; owned key deleted");
        }finally{if(owner is not null){try{if(!deleted){owner.DeleteCreated();File.Delete(receipt);}}finally{owner.Dispose();}}}
    }
}
