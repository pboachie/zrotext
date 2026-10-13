using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;

using var input=JsonDocument.Parse(Console.In.ReadToEnd());var p=input.RootElement;var f=p.GetProperty("Fixture");
byte[] B(string name)=>Convert.FromBase64String(f.GetProperty(name).GetString()!);
var root=ManifestChain.RootPin.Enroll(B("rootPin"),B("fingerprint"));
var prior=ManifestChain.Genesis02(B("predecessor"),root,10000);var active=ManifestChain.ContinueChain(B("activation"),prior,2,10000);
var scope=new OriginalReplyReader.Scope(B("account"),B("device"),B("line"),B("interval"),B("connector"),B("readGrant"),B("originalReader"),"+12");
string folder=Path.Combine(Path.GetTempPath(),"zrotext-managed-current-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);string path=Path.Combine(folder,"history.dat");
try
{
    var checkpoint=OriginalReplyCheckpoint.Create(path,B("rootPin"),B("fingerprint"),scope,new[]{prior,active},10000);
    using var transport=new OriginalHttp(p.GetProperty("Origin").GetString()!,1000,p.GetProperty("Roots").GetString()!);
    var client=new OriginalCurrentClient(transport,checkpoint,B("rootPin"),B("fingerprint"),scope,10000);
    int index=0;var times=p.GetProperty("Clock").EnumerateArray().Select(t=>t.GetInt64()).ToArray();
    long Clock()
    {
        if(index==0)
        {
            try { client.CurrentAsync(p.GetProperty("Grant").GetString()!,()=>10000).GetAwaiter().GetResult();throw new Exception("Reentrant current accepted"); }
            catch(OriginalHttp.Failure) { /* No additional request may be dispatched. */ }
        }
        if(p.GetProperty("Conflict").GetBoolean() && index==2)
        {
            var other=OriginalReplyCheckpoint.Open(path,B("rootPin"),B("fingerprint"),scope);var old=other.ReadSnapshot(scope,10000);
            other.Accept(scope,old.History,old.Revision,10000,(m,n)=>n);
        }
        return times[Math.Min(index++,times.Length-1)];
    }
    var result=new Dictionary<string,object>{{"ok",false}};
    try { var value=(await client.CurrentAsync(p.GetProperty("Grant").GetString()!,Clock)).Authority;result["ok"]=true;result["now"]=value.NowMs;result["version"]=value.Manifest.Version; }
    catch(OriginalHttp.Failure) { /* Only operation under test may refuse. */ }
    if(p.GetProperty("Retry").GetBoolean())
    {
        try { await client.CurrentAsync(p.GetProperty("Grant").GetString()!,()=>10000);result["stale_refused"]=false; }
        catch(OriginalHttp.Failure) { result["stale_refused"]=true; }
    }
    var reopened=OriginalReplyCheckpoint.Open(path,B("rootPin"),B("fingerprint"),scope);var saved=reopened.ReadSnapshot(scope,50000);
    result["revision"]=saved.Revision;result["floor"]=saved.ComparisonMs;result["history"]=saved.History.Count;result["rollback_refused"]=false;
    try { reopened.ReadSnapshot(scope,saved.ComparisonMs-1); } catch(CryptographicException) { result["rollback_refused"]=true; }
    Console.WriteLine(JsonSerializer.Serialize(result));
}
finally { File.Delete(path);Directory.Delete(folder); }
