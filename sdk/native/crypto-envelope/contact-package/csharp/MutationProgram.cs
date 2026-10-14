using System.Text.Json;
using System.Security.Cryptography;
using Zrotext.Candidate;
using M=Zrotext.Candidate.ContactField.Mutation;
using var input=JsonDocument.Parse(Console.In.ReadToEnd());
var parser=new ContactOrigin(args[0]);var results=new List<object>();
string Option(JsonElement r,string key,string fallback)=>r.TryGetProperty(key,out var v) && v.ValueKind!=JsonValueKind.Null?v.GetString()!:fallback;
long Legacy(string n)=>n=="converted"?7:0;
foreach(var r in input.RootElement.EnumerateArray()){
    var output=new Dictionary<string,object>{{"accepted",false},{"mutationVerified",false}};
    try{
        var f=r.GetProperty("fixture");byte[] D(string k)=>Convert.FromBase64String(f.GetProperty(k).GetString()!);
        var pin=ManifestChain.RootPin.Enroll(D("rootPin"),D("fingerprint"));var m=ManifestChain.Genesis02(D("manifest"),pin,10000);var n=ManifestChain.ContinueChain(D("nextManifest"),m,2,10000);
        var first=ContactField.VerifyStatement(D("statement"),m,D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),parser);var next=ContactField.VerifyStatement(D("nextStatement"),n,D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),parser);
        ContactField.Statement Statement(string name)=>name is "update" or "clear" or "replacement" or "nextStatement"?next:first;
        var expected=new ContactField.Expected(D("account"),f.GetProperty("origin").GetString()!,D("fingerprint"),D("contact"),D("routing"),parser);
        var fields=new Dictionary<string,ContactField.Verified>();foreach(string name in new[]{"name","notes","replacement"})fields[name]=ContactField.Verify(D(name),Statement(name),D("contact"),D("routing"));
        ContactField.Verified[] Replacements(string name)=>name switch{"create" or "converted"=>new[]{fields["name"],fields["notes"]},"update"=>new[]{fields["replacement"]},_=>Array.Empty<ContactField.Verified>()};
        M.Transition? Previous(string name){if(name=="none")return null;if(name is not ("create" or "update"))throw new Exception("Unknown predecessor");return M.VerifyTransition(name=="update"?Previous("create"):null,M.Verify(D(name),Statement(name),expected,Legacy(name)),Replacements(name));}
        ECDsa Key(byte[] scalar){var raw=m.RootPoint();var p=new ECParameters{Curve=ECCurve.NamedCurves.nistP256,Q=new ECPoint{X=raw.AsSpan(1,32).ToArray(),Y=raw.AsSpan(33,32).ToArray()},D=scalar};return ECDsa.Create(p);}
        string op=r.GetProperty("operation").GetString()!,which=Option(r,"mutation","create");byte[] scalar=new byte[32];scalar[31]=7;
        if(op=="produce-chain"){
            var generated=new Dictionary<string,string>();M.Transition? previous=null;ContactField.Statement? ps=null;using var key=Key(scalar);
            foreach(string name in new[]{"create","update","clear","converted"}){if(name=="converted"){previous=null;ps=null;}byte[] u=D(name).AsSpan(0,304).ToArray();if(previous is not null)previous.Mutation.Digest().CopyTo(u,70);
                previous=M.ProduceSoftware(key,Statement(name),expected,u,Legacy(name),previous,ps,Replacements(name));ps=Statement(name);generated[name]=Convert.ToBase64String(previous.Mutation.Bytes());}
            output["accepted"]=true;output["mutations"]=generated;results.Add(output);continue;
        }
        var selected=Statement(Option(r,"statement",which));string prior=Option(r,"previous",which=="update"?"create":which=="clear"?"update":"none");var previousValue=Previous(prior);
        var fs=Replacements(which);if(r.TryGetProperty("replacements",out var supplied))fs=supplied.EnumerateArray().Select(v=>fields[v.GetString()!]).ToArray();
        long l=r.TryGetProperty("legacy",out var lv)?lv.GetInt64():Legacy(which);
        if(op=="produce"){
            var ps=previousValue is null?null:Statement(prior);if(r.TryGetProperty("previousStatement",out var p))ps=p.GetString()=="none"?null:Statement(p.GetString()!);
            if(r.TryGetProperty("scalar",out var sv))scalar=Convert.FromBase64String(sv.GetString()!);using var key=Key(scalar);using var cancellation=new CancellationTokenSource();if(r.TryGetProperty("cancel",out var cv) && cv.GetBoolean())cancellation.Cancel();
            byte[] raw=D(which);if(raw.Length!=368)throw new Exception("Mutation width");var value=M.ProduceSoftware(key,selected,expected,raw.AsSpan(0,304).ToArray(),l,previousValue,ps,fs,cancellation.Token);output["bytes"]=Convert.ToBase64String(value.Mutation.Bytes());
        }else{var mutation=M.Verify(D(which),selected,expected,l);output["mutationVerified"]=true;if(op!="verify"){var value=M.VerifyTransition(previousValue,mutation,fs);var retained=new Dictionary<string,string>();for(int i=1;i<=2;i++){var field=value.Field(i);if(field is not null)retained[i==1?"name":"notes"]=Convert.ToBase64String(field.Bytes());}output["fields"]=retained;}}
        output["accepted"]=true;
    }catch{/* Preserve the independently verified mutation marker on transition refusal. */}
    results.Add(output);
}
Console.WriteLine(JsonSerializer.Serialize(results));
