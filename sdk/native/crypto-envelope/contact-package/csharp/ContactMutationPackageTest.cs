using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using M=Zrotext.Candidate.ContactField.Mutation;
using Zrotext.Candidate;
namespace Zrotext.Consumer;
// Synthetic native acceptance only; excluded from runtime artifact inventories.
internal static class ContactMutationPackageTest {
    private sealed record Plan(ContactField.Statement Statement,byte[] Unsigned,long Legacy,M.Transition? Previous,ContactField.Statement? PreviousStatement,ContactField.Verified[] Fields);
    private static M.Transition Call(ProtectedContactSigner key,ContactField.Expected e,Plan p,CancellationToken cancellation=default)=>M.ProduceProtected(key,p.Statement,e,p.Unsigned,p.Legacy,p.Previous,p.PreviousStatement,p.Fields,cancellation);
    internal static object Run(ProtectedContactSigner key,JsonObject f,JsonElement outputs,ContactOrigin parser){
        byte[] D(string name)=>Convert.FromBase64String(f[name]!.GetValue<string>());
        var pin=ManifestChain.RootPin.Enroll(D("rootPin"),D("fingerprint"));var m=ManifestChain.Genesis02(D("manifest"),pin,10000);var n=ManifestChain.ContinueChain(D("nextManifest"),m,2,10000);
        var first=ContactField.VerifyStatement(D("statement"),m,D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),parser);var next=ContactField.VerifyStatement(D("nextStatement"),n,D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),parser);
        var expected=new ContactField.Expected(D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),D("contact"),D("routing"),parser);
        var fields=new Dictionary<string,ContactField.Verified>();var encoded=new Dictionary<string,string>();string[] names={"name","notes","replacement"};
        for(int i=0;i<3;i++){string bytes=outputs[i].GetProperty("bytes").GetString()!;fields[names[i]]=ContactField.Verify(Convert.FromBase64String(bytes),i==2?next:first,D("contact"),D("routing"));encoded[names[i]]=bytes;}
        var mutations=new Dictionary<string,string>();M.Transition? previous=null;ContactField.Statement? ps=null;int refused=0;
        foreach(string name in new[]{"create","update","clear","converted"}){
            if(name is "create" or "converted"){previous=null;ps=null;}var st=name is "update" or "clear"?next:first;byte[] u=D(name).AsSpan(0,304).ToArray(),statement=st.Bytes();int at=40+BinaryPrimitives.ReadUInt16BigEndian(statement.AsSpan(38,2))+24;
            statement.AsSpan(at+32,32).CopyTo(u.AsSpan(118));st.Digest().CopyTo(u,150);if(previous is not null)previous.Mutation.Digest().CopyTo(u,70);
            string?[] slots=name=="clear"?new string?[]{null,"replacement"}:name=="update"?new[]{"name","replacement"}:new[]{"name","notes"};
            for(int i=0;i<2;i++)if(slots[i] is string slot){var field=fields[slot];u[222+41*i]=1;field.Bytes().AsSpan(38,8).CopyTo(u.AsSpan(223+41*i));field.Digest().CopyTo(u,231+41*i);}
            var replacements=name=="clear"?Array.Empty<ContactField.Verified>():name=="update"?new[]{fields["replacement"]}:new[]{fields["name"],fields["notes"]};
            var plan=new Plan(st,u,name=="converted"?7:0,previous,ps,replacements);var value=Call(key,expected,plan);
            using(var borrowed=ProtectedContactSigner.Open(key.Alias,key.PublicPoint())){try{borrowed.DeleteCreated();throw new Exception("Borrowed deletion accepted");}catch(CryptographicException){}borrowed.Dispose();try{Call(borrowed,expected,plan);throw new Exception("Closed mutation accepted");}catch(CryptographicException){refused++;}}
            using(var cancel=new CancellationTokenSource()){cancel.Cancel();try{Call(key,expected,plan,cancel.Token);throw new Exception("Cancelled mutation accepted");}catch(CryptographicException){refused++;}}
            byte[] contact=D("contact");contact[0]^=1;var foreign=new ContactField.Expected(D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),contact,D("routing"),parser);
            try{Call(key,foreign,plan);throw new Exception("Foreign mutation accepted");}catch(CryptographicException){refused++;}
            mutations[name]=Convert.ToBase64String(value.Mutation.Bytes());previous=value;ps=st;
        }
        return new{fields=encoded,mutations,refusals=refused};
    }
}
