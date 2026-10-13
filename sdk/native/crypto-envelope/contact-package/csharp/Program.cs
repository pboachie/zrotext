using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;
if(args.Length>1 && args[1]=="--probe"){try{ProtectedContactSigner.Probe();}catch(CryptographicException){Environment.Exit(77);}return;}
using var session=args.Length>1 && args[1]=="--hardware"?new ContactSession(args[2]):null;
using var input=JsonDocument.Parse(Console.In.ReadToEnd());

var parser=new ContactOrigin(args[0]);
var results=new List<object>();
foreach(var request in input.RootElement.EnumerateArray()){
    try{
        string operation=request.GetProperty("operation").GetString()!;
        if(operation=="origin"){results.Add(new{accepted=parser.Accepts(request.GetProperty("origin").GetString()!)});continue;}
        var f=request.GetProperty("fixture");byte[] D(string key)=>Convert.FromBase64String(f.GetProperty(key).GetString()!);
        string which=request.TryGetProperty("statement",out var name)?name.GetString()!:"statement";
        var pin=ManifestChain.RootPin.Enroll(D("rootPin"),D("fingerprint"));var manifest=ManifestChain.Genesis02(D("manifest"),pin,10000);
        if(which=="nextStatement")manifest=ManifestChain.ContinueChain(D("nextManifest"),manifest,2,10000);
        var statement=ContactField.VerifyStatement(D(which),manifest,D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),parser);
        if(operation=="statement"){results.Add(new{accepted=true});continue;}
        string field=request.TryGetProperty("field",out var fieldName)?fieldName.GetString()!:"name";byte[] raw=D(field);
        ContactField.Verified verified;
        if(operation=="verify")verified=ContactField.Verify(raw,statement,D("contact"),D("routing"));
        else if(operation=="produce"){
            if(session is not null){verified=session.Produce(f,statement,manifest,raw,request,parser);}
            else{
            byte[] scalar=request.TryGetProperty("scalar",out var scalarValue)?Convert.FromBase64String(scalarValue.GetString()!):new byte[32];if(!request.TryGetProperty("scalar",out _))scalar[31]=7;
            byte[] publicPoint=manifest.RootPoint();using var key=ECDsa.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,Q=new ECPoint{X=publicPoint.AsSpan(1,32).ToArray(),Y=publicPoint.AsSpan(33,32).ToArray()},D=scalar});
            using var cancel=new CancellationTokenSource();if(request.TryGetProperty("cancel",out var cancelled) && cancelled.GetBoolean())cancel.Cancel();
            var expected=new ContactField.Expected(D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),D("contact"),D("routing"),parser);
            verified=ContactField.ProduceSoftware(key,statement,expected,raw.AsSpan(0,raw.Length-64).ToArray(),cancel.Token);}
        }else throw new Exception("Unknown probe mode");
        results.Add(new{accepted=true,bytes=Convert.ToBase64String(verified.Bytes())});
    }catch{results.Add(new{accepted=false});}
}
Console.WriteLine(JsonSerializer.Serialize(results));

sealed class ContactSession:IDisposable{
    private ProtectedContactSigner? key;private readonly string receipt;private byte[]? point;private string alias="";
    private void Record(string state){using var file=new FileStream(receipt,FileMode.Create,FileAccess.Write,FileShare.None);file.Write(JsonSerializer.SerializeToUtf8Bytes(new{alias,state}));file.Flush(true);}
    public ContactSession(string receipt){this.receipt=receipt;try{key=ProtectedContactSigner.Create(value=>{alias=value;Record("pending");});point=key.PublicPoint();Console.WriteLine(JsonSerializer.Serialize(new{alias,@public=Convert.ToBase64String(point)}));Console.Out.Flush();}catch{if(key is not null)Dispose();throw;}}
    public ContactField.Verified Produce(JsonElement f,ContactField.Statement statement,ManifestChain.Verified manifest,byte[] raw,JsonElement request,ContactOrigin parser){
        byte[] D(string name)=>Convert.FromBase64String(f.GetProperty(name).GetString()!);
        byte[] u=raw.AsSpan(0,raw.Length-64).ToArray();manifest.Digest().CopyTo(u,102);statement.Digest().CopyTo(u,134);
        SHA256.HashData(System.Text.Encoding.ASCII.GetBytes("ZTSE/key/v1\0").Concat(new byte[]{1,1}).Concat(point!).ToArray()).CopyTo(u,214);
        var expected=new ContactField.Expected(D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),D("contact"),D("routing"),parser);
        using var borrowed=ProtectedContactSigner.Open(alias,point!);bool refused=false;try{borrowed.DeleteCreated();}catch(CryptographicException){refused=true;}if(!refused)throw new Exception("Borrowed deletion accepted");
        if(request.TryGetProperty("closed",out var closed) && closed.GetBoolean())borrowed.Dispose();
        using var cancel=new CancellationTokenSource();if(request.TryGetProperty("cancel",out var cancelled) && cancelled.GetBoolean())cancel.Cancel();
        return ContactField.ProduceProtected(borrowed,statement,expected,u,cancel.Token);
    }
    public void Dispose(){key!.DeleteCreated();if(point is not null){bool refused=false;try{using var reopened=ProtectedContactSigner.Open(alias,point);}catch(CryptographicException){refused=true;}if(!refused)throw new Exception("Deleted key reopened");}Record("owned_key_deleted");Console.WriteLine("{\"owned_key_deleted\":true}");Console.Out.Flush();}
}
