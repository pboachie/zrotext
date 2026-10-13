using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;

using(var boundary=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)){
 var q=boundary.ExportParameters(false).Q;var point=new byte[65];point[0]=4;q.X!.CopyTo(point,1);q.Y!.CopyTo(point,33);
 foreach(int size in new[]{1,31,32,33,32768}){
  var plain=Enumerable.Repeat((byte)7,size).ToArray();var wrap=HpkeRecipient.SealContent(point,Array.Empty<byte>(),Array.Empty<byte>(),plain);
  if(!plain.SequenceEqual(HpkeRecipient.OpenContent(boundary,point,wrap[..65],Array.Empty<byte>(),Array.Empty<byte>(),wrap[65..])))throw new Exception("Content boundary mismatch");
  bool accepted=false;try{HpkeRecipient.Open(boundary,point,wrap[..65],Array.Empty<byte>(),Array.Empty<byte>(),wrap[65..]);accepted=true;}catch(CryptographicException){}
  if(accepted!=(size==32))throw new Exception("CEK boundary widened");
 }
 foreach(int size in new[]{0,32769}){try{HpkeRecipient.SealContent(point,Array.Empty<byte>(),Array.Empty<byte>(),new byte[size]);throw new Exception("Content size accepted");}catch(CryptographicException){}}
}
ProtectedRecipient? owner=null;string? receipt=null;
try {
if(args.SequenceEqual(new[]{"--hardware"})) {
    ProtectedRecipient.Probe();receipt=Path.Combine(Path.GetTempPath(),"zrotext-managed-template-owned-"+Guid.NewGuid().ToString("N")+".json");
    owner=ProtectedRecipient.Create(name=>{using var stream=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None);stream.Write(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{pending_alias=name})));stream.Flush(true);});
    Console.WriteLine(JsonSerializer.Serialize(new{ @public=Convert.ToHexString(owner.PublicPoint()).ToLowerInvariant() }));Console.Out.Flush();
} else if(args.Length!=0)throw new ArgumentException("Unsupported arguments");
using var input=JsonDocument.Parse(Console.In.ReadToEnd());var p=input.RootElement;var f=p.GetProperty("Fixture");
if(owner is not null && f.TryGetProperty("archiveScalar",out _))throw new Exception("Native scalar exposed");
byte[] B(JsonElement o,string name)=>Convert.FromBase64String(o.GetProperty(name).GetString()!);
var root=ManifestChain.RootPin.Enroll(B(f,"rootPin"),B(f,"fingerprint"));var manifest=ManifestChain.Genesis02(B(f,"manifest"),root,10000);
using var key=owner is null?ECDiffieHellman.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=B(f,"archiveScalar")}):null;
HpkeRecipient.IContentRecipient recipient=owner is not null?owner:HpkeRecipient.SoftwareContent(key!);
var results=new List<Dictionary<string,object>>();
foreach(var c in p.GetProperty("Cases").EnumerateArray()){
 var result=new Dictionary<string,object>{{"accepted",false}};int calls=0;var times=c.GetProperty("Clock").EnumerateArray().Select(v=>v.GetInt64()).ToArray();
 EncryptedTemplate.Authority Source(){int at=calls++;if(at>0 && c.GetProperty("FailFinal").GetBoolean())throw new CryptographicException("Synthetic revoked authority");return new(manifest,times[Math.Min(at,times.Length-1)]);}
 var content=c.GetProperty("Mode").GetString()=="seal"?TemplateContent.Parse(B(c,"Canonical")):null;
 try{
  var s=c.GetProperty("Scope");long N(string name)=>s.GetProperty(name).GetInt64();
  var scope=EncryptedTemplate.Scope.Capture(B(s,"accountId"),B(s,"deviceId"),B(s,"lineId"),B(s,"intervalId"),B(s,"templateId"),N("bindingGeneration"),N("revision"),N("expiresMs"),N("trustGeneration"),N("manifestVersion"),B(s,"peerDigest"),B(s,"readerId"),B(s,"manifestDigest"));
  var value=content is not null?EncryptedTemplate.Seal(scope,content,Source):EncryptedTemplate.Open(scope,B(c,"Envelope"),recipient,Source).Canonical();
  result["accepted"]=true;result[content is not null?"envelope":"canonical"]=Convert.ToBase64String(value);
 }catch(CryptographicException){}catch(TemplateContent.Failure){}
 result["calls"]=calls;results.Add(result);
}
Console.WriteLine(JsonSerializer.Serialize(new{cases=results}));Console.Out.Flush();

} finally {
    if(owner is not null) {
        string name=owner.Alias;byte[]? point=null;try{point=owner.PublicPoint();}finally{owner.DeleteCreated();}
        try{using var reopened=ProtectedRecipient.Open(name,point);throw new Exception("Deleted key reopened");}catch(CryptographicException){}
        using(var file=new FileStream(receipt!,FileMode.Create,FileAccess.Write,FileShare.None)){file.Write(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{owned_key_deleted=true})));file.Flush(true);}
        Console.WriteLine(JsonSerializer.Serialize(new{owned_key_deleted=true}));Console.Out.Flush();owner.Dispose();
    }
}
