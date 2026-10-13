using System.Text.Json;
using System.Diagnostics;
using Zrotext.Candidate;
if(args.SequenceEqual(new[]{"--probe"})){try{ProtectedRecipient.Probe();Console.WriteLine("{\"available\":true}");}catch(System.Security.Cryptography.CryptographicException){Console.WriteLine("{\"available\":false}");}return;}
ProtectedRecipient? owner=null,recipient=null;string? receipt=null;
try{
 if(args.SequenceEqual(new[]{"--hardware"})){
  ProtectedRecipient.Probe();receipt=Path.Combine(Path.GetTempPath(),"zrotext-opening-owned-"+Guid.NewGuid().ToString("N")+".json");
  owner=ProtectedRecipient.Create(name=>{using var file=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None);file.Write(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{pending_alias=name})));file.Flush(true);});
  recipient=ProtectedRecipient.Open(owner.Alias,owner.PublicPoint());Console.WriteLine(JsonSerializer.Serialize(new{@public=Convert.ToHexString(owner.PublicPoint()).ToLowerInvariant()}));Console.Out.Flush();
 }else if(args.Length!=0)throw new ArgumentException("Unsupported arguments");
using var document=JsonDocument.Parse(Console.In.ReadToEnd());var p=document.RootElement;var f=p.GetProperty("Fixture");if(recipient is not null && f.TryGetProperty("archiveScalar",out _))throw new Exception("Native scalar exposed");
byte[] B(JsonElement o,string key)=>Convert.FromBase64String(o.GetProperty(key).GetString()!);
long N(string key,long fallback=0)=>p.TryGetProperty(key,out var value)?value.GetInt64():fallback;
OwnerTemplate.Binding Binding(bool changed){var o=f.GetProperty("binding");var device=B(o,"device");if(changed)device[0]^=1;return new(B(o,"account"),device,B(o,"line"),B(o,"interval"),B(o,"session"),o.GetProperty("generation").GetInt64(),o.GetProperty("peer").GetString()!,B(o,"phoneReader"),B(o,"archiveReader"));}
var pin=ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint"));var manifest=ManifestChain.Genesis02(B(f,"manifest"),pin,10000);var binding=Binding(false);var other=Binding(true);int current=0,session=0;OwnerTemplate? supplied=null;
OwnerTemplate.Current Source(){int at=++current;if(N("ProviderCloseAt")==at)recipient?.Dispose();if(N("ClientCloseAt")==at)supplied?.Dispose();if(N("CurrentFailAt")==at)throw new OwnerTemplate.Failure();if(N("CurrentSleepAt")==at)Thread.Sleep((int)N("SleepMS"));var mode=p.GetProperty("Mode").GetString();var times=p.GetProperty("Now").EnumerateArray().ToArray();return new(mode=="binding"?other:binding,manifest,times[Math.Min(at-1,times.Length-1)].GetInt64(),N("ValidForMS"),mode!="owner-dead",mode!="consent-dead",mode!="inactive");}
OwnerTemplate.Session Credentials(){int at=++session;return new(p.GetProperty(p.TryGetProperty("SessionOrigin",out _)?"SessionOrigin":"Origin").GetString()!,p.GetProperty("Cookie").GetString()!,p.GetProperty("CSRF").GetString()!+(N("SessionChangeAt")==at?"-changed":""));}
object Failure(OwnerTemplate.Failure e)=>new{accepted=false,code=e.Code,unknown=e.Unknown};
var results=new List<object>();var watch=Stopwatch.StartNew();
try{using var client=new OwnerTemplate(p.GetProperty("Origin").GetString()!,binding,B(f.GetProperty("scope"),"templateId"),Source,Credentials,p.GetProperty("Enabled").GetBoolean(),(int)N("TimeoutMS"),p.GetProperty("Roots").GetString()!,_=>{});
 supplied=client;
 if(p.TryGetProperty("SetupPending",out var pending) && pending.GetBoolean()){
  var wire=B(f,"envelope");var ticket=client.PrepareSave(new EncryptedTemplate.Scope(wire[..222]),"00000000-0000-0000-0000-000000000041",0,wire);
  try{client.Commit(ticket);throw new Exception("Expected unknown");}catch(OwnerTemplate.Failure expected){if(!expected.Unknown)throw;}current=session=0;
 }
 if(p.TryGetProperty("ClientInitiallyClosed",out _))client.Dispose();
 using var opening=new OwnerTemplate.Opening(client,p.GetProperty("Origin").GetString()!,p.TryGetProperty("DedicatedMismatch",out _)?other:binding,B(f.GetProperty("scope"),"templateId"),Source,Credentials,p.GetProperty("Enabled").GetBoolean(),(int)N("TimeoutMS"),p.GetProperty("Roots").GetString()!);
 var scalar=recipient is null?B(f,"archiveScalar"):new byte[32];if(recipient is not null)scalar[31]=1;if(p.TryGetProperty("WrongKey",out var wrong) && wrong.GetBoolean())scalar[31]^=1;
 using var key=System.Security.Cryptography.ECDiffieHellman.Create(new System.Security.Cryptography.ECParameters{Curve=System.Security.Cryptography.ECCurve.NamedCurves.nistP256,D=scalar});
 for(int i=0;i<N("Reads",1);i++){try{var value=recipient is null?opening.OpenLatestSoftware(key):opening.OpenLatest(recipient);results.Add(new{accepted=true,digest=value.EncryptedDigest,ack=value.RequestAcknowledged,pending=value.MatchesPending,text=value.Preview.Text,segments=value.Preview.Estimate});}catch(OwnerTemplate.Failure e){results.Add(Failure(e));}}
}catch(OwnerTemplate.Failure e){for(int i=0;i<N("Reads",1);i++)results.Add(Failure(e));}
double elapsed=watch.Elapsed.TotalSeconds;Thread.Sleep((int)N("SettleMS"));Console.WriteLine(JsonSerializer.Serialize(new{results,elapsed,currentCalls=current,sessionCalls=session}));

}finally{
 recipient?.Dispose();
 if(owner is not null){
  string name=owner.Alias;byte[]? point=null;try{point=owner.PublicPoint();}finally{owner.DeleteCreated();}
  try{using var reopened=ProtectedRecipient.Open(name,point);throw new Exception("Deleted key reopened");}catch(System.Security.Cryptography.CryptographicException){}
  using(var file=new FileStream(receipt!,FileMode.Create,FileAccess.Write,FileShare.None)){file.Write(System.Text.Encoding.UTF8.GetBytes("{\"owned_key_deleted\":true}"));file.Flush(true);}
  Console.WriteLine("{\"owned_key_deleted\":true}");Console.Out.Flush();owner.Dispose();
 }
}
