using System.Text.Json;
using System.Diagnostics;
using Zrotext.Candidate;
using var document=JsonDocument.Parse(Console.In.ReadToEnd());var p=document.RootElement;var f=p.GetProperty("Fixture");
byte[] B(JsonElement o,string key)=>Convert.FromBase64String(o.GetProperty(key).GetString()!);
long N(string key,long fallback=0)=>p.TryGetProperty(key,out var value)?value.GetInt64():fallback;
OwnerTemplate.Binding Binding(bool changed){var o=f.GetProperty("binding");var device=B(o,"device");if(changed)device[0]^=1;return new(B(o,"account"),device,B(o,"line"),B(o,"interval"),B(o,"session"),o.GetProperty("generation").GetInt64(),o.GetProperty("peer").GetString()!,B(o,"phoneReader"),B(o,"archiveReader"));}
var pin=ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint"));var manifest=ManifestChain.Genesis02(B(f,"manifest"),pin,10000);var binding=Binding(false);var other=Binding(true);int current=0,session=0,reviews=0;
var currentEntered=new ManualResetEventSlim();var currentRelease=new ManualResetEventSlim();var reviewEntered=new ManualResetEventSlim();var reviewRelease=new ManualResetEventSlim();
var operations=p.GetProperty("Ops").EnumerateArray().Select(v=>v.GetString()!).ToArray();
OwnerTemplate.Current Source(){int at=Interlocked.Increment(ref current);if(N("CurrentBlockAt")==at){currentEntered.Set();if(!currentRelease.Wait(10000))throw new Exception("Current release missing");}if(N("CurrentFailAt")==at)throw new OwnerTemplate.Failure();if(N("CurrentSleepAt")==at)Thread.Sleep((int)N("SleepMS"));var mode=p.GetProperty("Mode").GetString();var times=p.GetProperty("Now").EnumerateArray().ToArray();return new(mode=="binding"?other:binding,manifest,times[Math.Min(at-1,times.Length-1)].GetInt64(),N("ValidForMS"),mode!="owner-dead",mode!="consent-dead",mode!="inactive");}
OwnerTemplate.Session Credentials(){int at=Interlocked.Increment(ref session);return new(p.GetProperty(p.TryGetProperty("SessionOrigin",out _)?"SessionOrigin":"Origin").GetString()!,p.GetProperty("Cookie").GetString()!,p.GetProperty("CSRF").GetString()!+(N("SessionChangeAt")==at?"-changed":""));}
void Review(OwnerTemplate.Review value){int at=Interlocked.Increment(ref reviews);if(operations.Contains("race-prepare") && at==1){reviewEntered.Set();if(!reviewRelease.Wait(10000))throw new Exception("Review release missing");}Thread.Sleep((int)N("ReviewSleepMS"));if(p.TryGetProperty("ReviewFail",out var reject) && reject.GetBoolean())throw new Exception("Synthetic review refusal");}
byte[] wire=p.TryGetProperty("Envelope",out _)?B(p,"Envelope"):B(f,"envelope");var scope=new EncryptedTemplate.Scope(wire[..222]);string request=p.GetProperty("RequestID").GetString()!;int expected=p.GetProperty("Expected").GetInt32();OwnerTemplate.Ticket? ticket=null;
using var client=new OwnerTemplate(p.GetProperty("Origin").GetString()!,binding,B(f.GetProperty("scope"),"templateId"),Source,Credentials,p.GetProperty("Enabled").GetBoolean(),(int)N("TimeoutMS"),p.GetProperty("Roots").GetString()!,Review);
var results=new List<Dictionary<string,object>>();var watch=Stopwatch.StartNew();
try{
 for(int i=0;i<operations.Length;i++){
  if(p.TryGetProperty("DelayMS",out var delay) && i<delay.GetArrayLength())Thread.Sleep(delay[i].GetInt32());var op=operations[i];var row=new Dictionary<string,object>{{"accepted",false},{"unknown",false},{"ack",false},{"matches",false}};
  try{
   switch(op){
    case "prepare":ticket=client.PrepareSave(scope,request,expected,wire);break;
    case "race-prepare":
     var first=Task.Run(()=>client.PrepareSave(scope,request,expected,wire));
     try{if(!reviewEntered.Wait(3000))throw new Exception("Review not entered");try{client.PrepareSave(scope,request,expected,wire);throw new Exception("Concurrent prepare accepted");}catch(OwnerTemplate.Failure e){if(e.Code!="busy")throw;}}
     finally{reviewRelease.Set();}
     ticket=first.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();break;
    case "close-commit":
     var selected=ticket;var attempt=Task.Run<OwnerTemplate.Failure?>(()=>{try{client.Commit(selected);return null;}catch(OwnerTemplate.Failure e){return e;}});
     try{if(!currentEntered.Wait(3000))throw new Exception("Current not entered");client.Dispose();}finally{currentRelease.Set();}
     var error=attempt.WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();if(error is null)throw new Exception("Closed commit acknowledged");throw error;
    case "commit":case "retry":var ack=op=="commit"?client.Commit(ticket):client.RetryUnknown(ticket);row["ack"]=true;row["digest"]=ack.Identity.EncryptedDigest;break;
    case "read":case "verify":var snapshot=op=="read"?client.ReadLatest():client.VerifyUnknown(ticket);row["ack"]=snapshot.RequestAcknowledged;row["matches"]=snapshot.MatchesPending;row["digest"]=snapshot.EncryptedDigest;break;
    case "mutate":wire[^1]^=1;break;
    case "close":client.Dispose();break;
    default:throw new Exception("Unknown operation");
   }
   row["accepted"]=true;
  }catch(OwnerTemplate.Failure e){row["unknown"]=e.Unknown;row["code"]=e.Code;}
  var pending=client.Pending();row["pending"]=pending is not null;if(pending is not null){row["pendingID"]=pending.RequestId;row["pendingDigest"]=pending.EncryptedDigest;}results.Add(row);
 }
}finally{client.Dispose();reviewRelease.Set();currentRelease.Set();}
double elapsed=watch.Elapsed.TotalSeconds;Thread.Sleep((int)N("SettleMS"));Console.WriteLine(JsonSerializer.Serialize(new{results,elapsed,currentCalls=current,sessionCalls=session,reviewCalls=reviews}));
