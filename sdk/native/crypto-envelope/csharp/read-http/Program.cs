using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;

ProtectedRecipient? owner=null;string? receipt=null;
try {
if(args.SequenceEqual(new[]{"--hardware"})) {
    ProtectedRecipient.Probe();receipt=Path.Combine(Path.GetTempPath(),"zrotext-managed-read-owned-"+Guid.NewGuid().ToString("N")+".json");
    owner=ProtectedRecipient.Create(name=>{using var stream=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None);stream.Write(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{pending_alias=name})));stream.Flush(true);});
    Console.WriteLine(JsonSerializer.Serialize(new{ @public=Convert.ToHexString(owner.PublicPoint()).ToLowerInvariant() }));Console.Out.Flush();
} else if(args.Length!=0)throw new ArgumentException("Unsupported arguments");
using var input=JsonDocument.Parse(Console.In.ReadToEnd());var p=input.RootElement;var f=p.GetProperty("Fixture");
if(owner is not null && f.TryGetProperty("originalScalar",out _))throw new Exception("Native scalar exposed");
byte[] B(string name)=>Convert.FromBase64String(f.GetProperty(name).GetString()!);
var root=ManifestChain.RootPin.Enroll(B("rootPin"),B("fingerprint"));
var prior=ManifestChain.Genesis02(B("predecessor"),root,10000);var active=ManifestChain.ContinueChain(B("activation"),prior,2,10000);
var scope=new OriginalReplyReader.Scope(B("account"),B("device"),B("line"),B("interval"),B("connector"),B("readGrant"),B("originalReader"),"+12");
string folder=Path.Combine(Path.GetTempPath(),"zrotext-managed-current-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);string path=Path.Combine(folder,"history.dat");
try
{
    var checkpoint=OriginalReplyCheckpoint.Create(path,B("rootPin"),B("fingerprint"),scope,new[]{prior,active},10000);
    using var transport=new OriginalHttp(p.GetProperty("Origin").GetString()!,4000,p.GetProperty("Roots").GetString()!);
    var client=new OriginalCurrentClient(transport,checkpoint,B("rootPin"),B("fingerprint"),scope,10000);
    int index=0;var times=p.GetProperty("Clock").EnumerateArray().Select(t=>t.GetInt64()).ToArray();
    long Clock()
    {
        if(index==0)
        {
            try { client.CurrentAsync(p.GetProperty("Grant").GetString()!,()=>10000).GetAwaiter().GetResult();throw new Exception("Reentrant current accepted"); }
            catch(OriginalHttp.Failure) { /* No additional request may be dispatched. */ }
        }
        return times[Math.Min(index++,times.Length-1)];
    }
    using var key=owner is not null ? null : ECDiffieHellman.Create(new ECParameters { Curve=ECCurve.NamedCurves.nistP256,D=B("originalScalar") });
    var result=new Dictionary<string,object>{{"ok",false}};
    try { var value=owner is null ? await client.ReadSoftwareAsync(p.GetProperty("Grant").GetString()!,B("event"),key!,Clock,p.GetProperty("Baseline").GetInt64()) : await client.ReadProtectedAsync(p.GetProperty("Grant").GetString()!,B("event"),owner,Clock,p.GetProperty("Baseline").GetInt64());result["ok"]=true;result["plaintext"]=value.Plaintext;result["digest"]=Convert.ToHexString(value.EnvelopeDigest).ToLowerInvariant();result["baseline"]=value.AcceptedManifestVersion;result["version"]=value.Authority.Manifest.Version; }
    catch(OriginalHttp.Failure) { /* Only operation under test may refuse. */ }
    var reopened=OriginalReplyCheckpoint.Open(path,B("rootPin"),B("fingerprint"),scope);var saved=reopened.ReadSnapshot(scope,50000);
    result["revision"]=saved.Revision;result["floor"]=saved.ComparisonMs;result["history"]=saved.History.Count;result["rollback_refused"]=false;
    try { reopened.ReadSnapshot(scope,saved.ComparisonMs-1); } catch(CryptographicException) { result["rollback_refused"]=true; }
    Console.WriteLine(JsonSerializer.Serialize(result));
}
finally { File.Delete(path);Directory.Delete(folder); }
} finally {
    if(owner is not null) {
        string name=owner.Alias;byte[]? point=null;try{point=owner.PublicPoint();}finally{owner.DeleteCreated();}
        try{using var reopened=ProtectedRecipient.Open(name,point);throw new Exception("Deleted key reopened");}catch(CryptographicException){}
        using(var file=new FileStream(receipt!,FileMode.Create,FileAccess.Write,FileShare.None)){file.Write(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{owned_key_deleted=true})));file.Flush(true);}
        Console.WriteLine(JsonSerializer.Serialize(new{owned_key_deleted=true}));Console.Out.Flush();owner.Dispose();
    }
}
