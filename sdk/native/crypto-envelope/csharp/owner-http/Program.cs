using System.Text.Json;
using Zrotext.Candidate;
using var input=JsonDocument.Parse(Console.In.ReadToEnd());var p=input.RootElement;var f=p.GetProperty("Fixture");byte[] B(string name)=>Convert.FromBase64String(f.GetProperty(name).GetString()!);
var root=ManifestChain.RootPin.Enroll(B("rootPin"),B("fingerprint"));var prior=ManifestChain.Genesis02(B("predecessor"),root,10000);var active=ManifestChain.ContinueChain(B("activation"),prior,2,10000);
var scope=new OriginalReplyReader.Scope(B("account"),B("device"),B("line"),B("interval"),B("connector"),B("readGrant"),B("originalReader"),"+12");
string path=Path.Combine(p.GetProperty("Directory").GetString()!,"reply.db"),file=Path.Combine(p.GetProperty("Directory").GetString()!,"intent.bin");
var checkpoint=p.GetProperty("Resume").GetBoolean()?OriginalReplyCheckpoint.Open(path,B("rootPin"),B("fingerprint"),scope):OriginalReplyCheckpoint.Create(path,B("rootPin"),B("fingerprint"),scope,new[]{prior,active},10000);
using var transport=new OriginalHttp(p.GetProperty("Origin").GetString()!,4000,p.GetProperty("Roots").GetString()!);var client=new OriginalCurrentClient(transport,checkpoint,B("rootPin"),B("fingerprint"),scope,10000);
var result=new Dictionary<string,object?>{{"ok",false},{"unknown",false}};
try {
    if(!p.GetProperty("Resume").GetBoolean()) {
        var request=new byte[16];request[15]=(byte)(p.GetProperty("Invalid").GetBoolean()?0:1);byte[]? selected=null;if(p.GetProperty("Active").GetBoolean()){selected=new byte[16];selected[15]=2;}
        var prepared=client.PrepareOwnerReview(B("event"),request,selected);var raw=prepared.Bytes();var snapshot=prepared.Bytes();raw[0]^=1;if(!prepared.Bytes().SequenceEqual(snapshot))throw new Exception("Intent alias");
        using var stream=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.None);stream.Write(snapshot);stream.Flush(true);
    }
    var bytes=File.ReadAllBytes(file);int corrupt=p.GetProperty("Corrupt").GetInt32();if(corrupt>=0)bytes[corrupt]^=1;else if(corrupt==-2)bytes=bytes[..^1];
    var intent=client.RestoreOwnerReview(bytes);result["record"]=Convert.ToHexString(intent.Bytes()).ToLowerInvariant();int index=0;var times=p.GetProperty("Clock").EnumerateArray().Select(t=>t.GetInt64()).ToArray();
    long Clock(){if(index==0){try{client.CurrentAsync(p.GetProperty("Grant").GetString()!,()=>10000).GetAwaiter().GetResult();throw new Exception("Reentrant current accepted");}catch(OriginalHttp.Failure){}}return times[Math.Min(index++,times.Length-1)];}
    var value=p.GetProperty("Status").GetBoolean()?await client.StatusOwnerReviewAsync(p.GetProperty("Grant").GetString()!,intent,Clock):await client.ConsumeOwnerReviewAsync(p.GetProperty("Grant").GetString()!,intent,Clock);
    result["ok"]=true;result["event"]=Convert.ToHexString(value.Event).ToLowerInvariant();result["consumption"]=Convert.ToHexString(value.Consumption).ToLowerInvariant();result["active"]=value.ActiveRequest is null?null:Convert.ToHexString(value.ActiveRequest).ToLowerInvariant();result["now"]=value.Authority.Authority.NowMs;
} catch(OriginalHttp.Failure error){result["unknown"]=error.Unknown;result["error"]=error.Message;}
var saved=checkpoint.ReadSnapshot(scope,50000);result["revision"]=saved.Revision;result["floor"]=saved.ComparisonMs;Console.WriteLine(JsonSerializer.Serialize(result));
