using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;
using var input=JsonDocument.Parse(Console.In.ReadToEnd());
if(args.Length>1 && args[1]=="--hardware"){Console.WriteLine(JsonSerializer.Serialize(ContactProtectedTest.Run(input.RootElement,args[0],args[2])));return;}
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
            byte[] scalar=request.TryGetProperty("scalar",out var scalarValue)?Convert.FromBase64String(scalarValue.GetString()!):new byte[32];if(!request.TryGetProperty("scalar",out _))scalar[31]=7;
            using var publicKey=HpkeRecipient.Point(manifest.RootPoint());var parameters=publicKey.ExportParameters(false);parameters.D=scalar;using var key=ECDsa.Create(parameters);
            using var cancel=new CancellationTokenSource();if(request.TryGetProperty("cancel",out var cancelled) && cancelled.GetBoolean())cancel.Cancel();
            var expected=new ContactField.Expected(D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),D("contact"),D("routing"),parser);
            verified=ContactField.ProduceSoftware(key,statement,expected,raw.AsSpan(0,raw.Length-64).ToArray(),cancel.Token);
        }else throw new Exception("Unknown probe mode");
        results.Add(new{accepted=true,bytes=Convert.ToBase64String(verified.Bytes())});
    }catch{results.Add(new{accepted=false});}
}
Console.WriteLine(JsonSerializer.Serialize(results));
