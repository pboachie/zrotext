using System.Text.Json;
using System.Diagnostics;
using Zrotext.Candidate;
using var document=JsonDocument.Parse(Console.In.ReadToEnd());var p=document.RootElement;var f=p.GetProperty("Fixture");
byte[] B(JsonElement o,string key)=>Convert.FromBase64String(o.GetProperty(key).GetString()!);
long N(string key,long fallback=0)=>p.TryGetProperty(key,out var value)?value.GetInt64():fallback;
OwnerTemplate.Binding Binding(bool changed){var o=f.GetProperty("binding");var device=B(o,"device");if(changed)device[0]^=1;return new(B(o,"account"),device,B(o,"line"),B(o,"interval"),B(o,"session"),o.GetProperty("generation").GetInt64(),o.GetProperty("peer").GetString()!,B(o,"phoneReader"),B(o,"archiveReader"));}
var pin=ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint"));var manifest=ManifestChain.Genesis02(B(f,"manifest"),pin,10000);var envelope=B(f,"envelope");var storeScope=new EncryptedTemplate.Scope(envelope[..222]);string requestId=Guid.NewGuid().ToString();var request=new TemplateStore.SaveRequest(storeScope,requestId,0,envelope);
if(request.Revision!=1 || request.Headers()["idempotency-key"]!=requestId || !request.Body().SequenceEqual(envelope) || request.Path!="/v1/owner/workflow/templates")throw new Exception("Save framing mismatch");var copied=request.Body();copied[0]^=1;if(!request.Body().SequenceEqual(envelope))throw new Exception("Mutable stored request");
if(request.Receipt(System.Text.Encoding.UTF8.GetBytes("{\"revision\":1}"))!=1)throw new Exception("Receipt mismatch");
foreach(string invalid in new[]{"{\"revision\":1} ","{\"revision\":1,\"revision\":1}","{\"revision\":2}","{\"revision\":1,\"sent\":true}","[]","{\"revision\":1.0}"}){try{request.Receipt(System.Text.Encoding.UTF8.GetBytes(invalid));throw new Exception("Invalid receipt accepted");}catch(System.Security.Cryptography.CryptographicException){}}
foreach(int revision in new[]{-1,1,128}){try{new TemplateStore.SaveRequest(storeScope,requestId,revision,envelope);throw new Exception("Invalid CAS accepted");}catch(System.Security.Cryptography.CryptographicException){}}
try{new TemplateStore.SaveRequest(storeScope,"",0,envelope);throw new Exception("Empty identity accepted");}catch(System.Security.Cryptography.CryptographicException){}
var binding=Binding(false);var other=Binding(true);int current=0,session=0;
OwnerTemplate.Current Source(){int at=++current;if(N("CurrentFailAt")==at)throw new OwnerTemplate.Failure();if(N("CurrentSleepAt")==at)Thread.Sleep((int)N("SleepMS"));var mode=p.GetProperty("Mode").GetString();var times=p.GetProperty("Now").EnumerateArray().ToArray();return new(mode=="binding"?other:binding,manifest,times[Math.Min(at-1,times.Length-1)].GetInt64(),N("ValidForMS"),mode!="owner-dead",mode!="consent-dead",mode!="inactive");}
OwnerTemplate.Session Credentials(){int at=++session;return new(p.GetProperty(p.TryGetProperty("SessionOrigin",out _)?"SessionOrigin":"Origin").GetString()!,p.GetProperty("Cookie").GetString()!,p.GetProperty("CSRF").GetString()!+(N("SessionChangeAt")==at?"-changed":""));}
object Failure(OwnerTemplate.Failure e)=>new{accepted=false,code=e.Code,unknown=e.Unknown};
if(p.TryGetProperty("Lifecycle",out _)){LifecycleTest.Run(p.GetProperty("Origin").GetString()!,binding,B(f.GetProperty("scope"),"templateId"),Credentials,p.GetProperty("Roots").GetString()!);Console.WriteLine("{\"lifecycle\":4}");return;}
var results=new List<object>();var phases=new PhaseMeasurements();var watch=Stopwatch.StartNew();
try{using var client=new MeasuredClient(phases,()=>new OwnerTemplate(p.GetProperty("Origin").GetString()!,binding,B(f.GetProperty("scope"),"templateId"),Source,Credentials,p.GetProperty("Enabled").GetBoolean(),(int)N("TimeoutMS"),p.GetProperty("Roots").GetString()!));
 for(int i=0;i<N("Reads",1);i++){try{var value=client.ReadLatest();results.Add(new{accepted=true,digest=value.EncryptedDigest,ack=value.RequestAcknowledged,pending=value.MatchesPending});}catch(OwnerTemplate.Failure e){results.Add(Failure(e));}}
}catch(OwnerTemplate.Failure e){for(int i=0;i<N("Reads",1);i++)results.Add(Failure(e));}
double elapsed=watch.Elapsed.TotalSeconds;Thread.Sleep((int)N("SettleMS"));Console.WriteLine(JsonSerializer.Serialize(new{results,elapsed,currentCalls=current,sessionCalls=session,phases=new{constructorSeconds=phases.ConstructorSeconds,requestSeconds=phases.RequestSeconds,disposalSeconds=phases.DisposalSeconds}}));

sealed class PhaseMeasurements {
 public double? ConstructorSeconds,DisposalSeconds;public List<double> RequestSeconds {get;}=new();
}
sealed class MeasuredClient:IDisposable {
 readonly OwnerTemplate client;readonly PhaseMeasurements phases;
 public MeasuredClient(PhaseMeasurements phases,Func<OwnerTemplate> constructor){this.phases=phases;long start=Stopwatch.GetTimestamp();try{client=constructor();}finally{phases.ConstructorSeconds=Stopwatch.GetElapsedTime(start).TotalSeconds;}}
 public OwnerTemplate.Snapshot ReadLatest(){long start=Stopwatch.GetTimestamp();try{return client.ReadLatest();}finally{phases.RequestSeconds.Add(Stopwatch.GetElapsedTime(start).TotalSeconds);}}
 public void Dispose(){long start=Stopwatch.GetTimestamp();try{client.Dispose();}finally{phases.DisposalSeconds=Stopwatch.GetElapsedTime(start).TotalSeconds;}}
}
