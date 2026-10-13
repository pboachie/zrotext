using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
namespace Zrotext.Candidate;
/// <summary>Cold opaque current snapshots, never decryption or save/send acknowledgement.</summary>
public sealed class OwnerTemplate:IDisposable {
 public sealed class Failure:Exception {public string Code{get;}public bool Unknown{get;}public Failure(string code="read_refused",bool unknown=false):base("Owner template "+code){Code=code;Unknown=unknown;}}
 private static void Need(bool b){if(!b)throw new Failure("invalid_request");}
 private static byte[] Bytes(byte[] b,int size){Need(b.Length==size && b.Any(v=>v!=0));return (byte[])b.Clone();}
 public sealed class Binding {
  private readonly byte[][] ids,readers;internal byte[][] Ids=>ids.Select(v=>(byte[])v.Clone()).ToArray();internal byte[][] Readers=>readers.Select(v=>(byte[])v.Clone()).ToArray();internal readonly long Generation;internal readonly string Peer;
  public Binding(byte[] account,byte[] device,byte[] line,byte[] interval,byte[] session,long generation,string peer,byte[] phoneReader,byte[] archiveReader){ids=new[]{Bytes(account,16),Bytes(device,16),Bytes(line,16),Bytes(interval,16),Bytes(session,16)};readers=new[]{Bytes(phoneReader,32),Bytes(archiveReader,32)};Need(generation>0 && Regex.IsMatch(peer,@"\A\+[1-9][0-9]{1,14}\z"));Generation=generation;Peer=peer;}
  internal Binding Copy()=>new(Ids[0],Ids[1],Ids[2],Ids[3],Ids[4],Generation,Peer,Readers[0],Readers[1]);
  internal bool Same(Binding b)=>Generation==b.Generation && Peer==b.Peer && Ids.Zip(b.Ids).All(v=>v.First.SequenceEqual(v.Second)) && Readers.Zip(b.Readers).All(v=>v.First.SequenceEqual(v.Second));
 }
 public sealed class Current {
  internal readonly Binding Binding;internal readonly ManifestChain.Verified Manifest;internal readonly long NowMs,ValidForMs;internal readonly bool OwnerLive,ConsentLive,Active;
  public Current(Binding binding,ManifestChain.Verified manifest,long nowMs,long validForMs,bool ownerLive,bool consentLive,bool active){Binding=binding.Copy();Manifest=manifest;NowMs=nowMs;ValidForMs=validForMs;OwnerLive=ownerLive;ConsentLive=consentLive;Active=active;}
 }
 public sealed record Session(string Origin,string Cookie,string Csrf){public override string ToString()=>"OwnerTemplate.Session[redacted]";}
 public sealed class Snapshot {
  private readonly EncryptedTemplate.Scope scope;private readonly byte[] wire;private readonly string digest;
  internal Snapshot(EncryptedTemplate.Scope scope,byte[] wire,string digest){this.scope=scope;this.wire=(byte[])wire.Clone();this.digest=digest;}
  public EncryptedTemplate.Scope Scope=>scope;public byte[] Envelope()=>(byte[])wire.Clone();public string EncryptedDigest=>digest;public bool RequestAcknowledged=>false;public bool MatchesPending=>false;
 }
 private static readonly SemaphoreSlim Admission=new(8,8);
 private readonly object gate=new();private readonly string origin,path;private readonly Binding binding;private readonly byte[] template;private readonly Func<Current> source;private readonly Func<Session> sessions;private readonly int timeout;private readonly OwnerTemplateTransport transport;
 private bool closed,busy;private long now,head;private ManifestChain.Verified? prior;private string? headDigest;
 private sealed class Work(long deadline){internal long Deadline=deadline;internal bool Done;internal Snapshot? Result;internal Failure? Error;}
 private static long Tick()=>Stopwatch.GetTimestamp();private static long Span(long ms)=>ms*Stopwatch.Frequency/1000;
 public OwnerTemplate(string origin,Binding binding,byte[] template,Func<Current> source,Func<Session> sessions,bool enabled=false,int timeoutMs=10000,string additionalRootsPem=""){
  try{Need(Uri.TryCreate(origin,UriKind.Absolute,out var u) && u.Scheme=="https" && u.Host.Length>0 && origin==u.GetLeftPart(UriPartial.Authority) && !origin.Contains('@') && !origin[8..].Contains('/'));Need(source is not null && sessions is not null && timeoutMs>=1 && timeoutMs<=10000);this.origin=origin;this.binding=binding.Copy();this.template=Bytes(template,16);this.source=source!;this.sessions=sessions!;timeout=timeoutMs;closed=!enabled;path="/v1/owner/workflow/templates/"+TemplateStore.Uuid(this.template);transport=new(origin,timeoutMs,additionalRootsPem);}catch{throw new Failure("invalid_request");}
 }
 public void Dispose(){lock(gate){closed=true;Monitor.PulseAll(gate);}transport.Dispose();}
 private void Live(Work w){lock(gate){if(closed)throw new Failure("closed");if(Tick()>=w.Deadline){closed=true;Monitor.PulseAll(gate);transport.Dispose();throw new Failure("deadline");}}}
 private int Remaining(Work w){Live(w);lock(gate){return (int)Math.Max(1,(w.Deadline-Tick())*1000/Stopwatch.Frequency);}}
 public Snapshot ReadLatest(){
  Work w;lock(gate){if(closed)throw new Failure("closed");if(busy)throw new Failure("busy");if(!Admission.Wait(0))throw new Failure("capacity");busy=true;w=new(Tick()+Span(timeout));}
  try{_ = Task.Run(()=>{try{var value=Read(w);lock(gate){w.Result=value;}}catch(Exception error){lock(gate){w.Error=error as Failure??new Failure();}}finally{lock(gate){w.Done=true;busy=false;Monitor.PulseAll(gate);}Admission.Release();}});}catch{lock(gate){busy=false;}Admission.Release();throw new Failure("capacity");}
  lock(gate){for(;;){Live(w);if(w.Done){if(w.Error is not null)throw w.Error;return w.Result!;}Monitor.Wait(gate,Remaining(w));}}
 }
 private Session Credentials(Work w){Live(w);var s=sessions();Live(w);Need(s is not null && s.Origin==origin && s.Cookie.Length>=1 && s.Cookie.Length<=4096 && s.Cookie.Contains('=') && s.Cookie.All(c=>c>=32 && c<=126) && s.Csrf.Length>=1 && s.Csrf.Length<=256 && s.Csrf.All(c=>c>=33 && c<=126));return s!;}
 private static bool Active(byte[] k,long at,int permission)=>k[148]==1 && TemplateStore.Number(k,132)<=at && at<TemplateStore.Number(k,140) && (BinaryPrimitives.ReadUInt16BigEndian(k.AsSpan(130,2))&permission)!=0;
 private void Authorize(Work w,EncryptedTemplate.Scope? scope,Session session){
  try{Live(w);long start=Tick();var a=source();Live(w);Need(a is not null && binding.Same(a.Binding) && a.OwnerLive && a.ConsentLive && a.Active && a.NowMs>0 && a.NowMs>=now && a.ValidForMs>0 && a.ValidForMs<=60000 && a.Manifest.Profile==2);
   var m=ManifestChain.ContinueChain(a!.Manifest.Bytes(),a.Manifest,2,a.NowMs);Need(TemplateStore.Same(m.Account(),binding.Ids[0]));if(prior is not null)Need(TemplateStore.Same(m.RootPoint(),prior.RootPoint()) && TemplateStore.Same(m.EnrolledRootPoint(),prior.EnrolledRootPoint()) && m.Generation==prior.Generation && m.Version>=prior.Version && (m.Version!=prior.Version || TemplateStore.Same(m.Digest(),prior.Digest())));
   byte[]? reader=null,phone=null;foreach(var k in m.KeyRecords()){if(k[0]==2 && TemplateStore.Same(k[1..33],binding.Readers[1]) && Active(k,a.NowMs,8))reader=k;if(k[0]==4 && TemplateStore.Same(k[98..114],binding.Ids[1]) && TemplateStore.Same(k[114..130],binding.Ids[2]) && Active(k,a.NowMs,2) && BinaryPrimitives.ReadUInt16BigEndian(k.AsSpan(130,2))==2)phone=k;}
   Need(reader is not null && phone is not null);long expiry=Math.Min(TemplateStore.Number(m.Bytes(),45),Math.Min(TemplateStore.Number(reader!,140),TemplateStore.Number(phone!,140)));
   if(scope is not null){var aad=scope.Aad();for(int i=0;i<4;i++)Need(TemplateStore.Same(aad[(6+16*i)..(22+16*i)],binding.Ids[i]));Need(TemplateStore.Same(aad[70..86],template) && TemplateStore.Number(aad,86)==binding.Generation && TemplateStore.Same(aad[158..190],binding.Readers[1]) && TemplateStore.Number(aad,110)==m.Generation && TemplateStore.Number(aad,118)==m.Version && TemplateStore.Same(aad[190..222],m.Digest()) && TemplateStore.Same(aad[126..158],SHA256.HashData(Encoding.UTF8.GetBytes(binding.Peer))));long expires=TemplateStore.Number(aad,102);Need(expires>a.NowMs && expires-a.NowMs<=30L*86400000);expiry=Math.Min(expiry,expires);}
   long duration=Math.Min(a.ValidForMs,expiry-a.NowMs);Need(duration>0);lock(gate){w.Deadline=Math.Min(w.Deadline,start+Span(duration));Monitor.PulseAll(gate);}Need(Credentials(w)==session);Live(w);prior=m;now=a.NowMs;
  }catch{Dispose();throw new Failure("owner_changed");}
 }
 private Snapshot Read(Work w){
  var session=Credentials(w);Authorize(w,null,session);if(Credentials(w)!=session){Dispose();throw new Failure("owner_changed");}
  byte[] wire;try{wire=transport.Get(path,session,Remaining(w));}catch(Failure e){if(e.Code=="owner_changed")Dispose();throw;}
  Live(w);var scope=TemplateStore.Parse(wire);long revision=TemplateStore.Number(scope.Aad(),94);Need(revision>=head);Authorize(w,scope,session);using var point=HpkeRecipient.Point(wire[222..287]);string digest=TemplateStore.Hex(SHA256.HashData(wire));Authorize(w,scope,session);Need(revision!=head || digest==headDigest);Live(w);head=revision;headDigest=digest;return new(scope,wire,digest);
 }
}
