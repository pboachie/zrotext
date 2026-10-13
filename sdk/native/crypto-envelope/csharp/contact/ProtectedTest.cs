using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Buffers.Binary;
namespace Zrotext.Candidate;
// Private native setup signing is test-only. Runtime capability remains field-only.
internal static class ContactProtectedTest {
    internal static object Run(JsonElement input,string directory,string receipt,bool mutationMode=false){
        var f=JsonNode.Parse(input.GetRawText())!.AsObject();var parser=new ContactOrigin(directory);
        byte[] D(string name)=>Convert.FromBase64String(f[name]!.GetValue<string>());
        void Set(string name,byte[] bytes)=>f[name]=Convert.ToBase64String(bytes);
        static byte[] Join(params byte[][] items)=>items.SelectMany(x=>x).ToArray();
        static byte[] Domain(string label)=>Encoding.ASCII.GetBytes(label+"\0");
        void Write(string alias,string state){using var file=new FileStream(receipt,FileMode.Create,FileAccess.Write,FileShare.None);file.Write(JsonSerializer.SerializeToUtf8Bytes(new{alias,state}));file.Flush(true);}
        ProtectedContactSigner? key=null,borrowed=null;string alias="";byte[]? point=null;int controls=0;
        try{
            key=ProtectedContactSigner.Create(value=>{alias=value;Write(value,"pending");});point=key.PublicPoint();
            var sign=typeof(ProtectedContactSigner).GetMethod("SignDigest",BindingFlags.NonPublic|BindingFlags.Instance)!;
            byte[] Setup(string label,byte[] unsigned){byte[] length=new byte[4];BinaryPrimitives.WriteInt32BigEndian(length,unsigned.Length);byte[] digest=SHA256.HashData(Join(Domain(label),length,unsigned));return Join(unsigned,(byte[])sign.Invoke(key,new object[]{digest})!);}
            byte[] rootId=SHA256.HashData(Join(Domain("ZTSE/key/v1"),new byte[]{1,1},point)),one=new byte[8];BinaryPrimitives.WriteInt64BigEndian(one,1);
            byte[] pin=Join(new byte[]{90,84,82,80,2},D("account"),one,point);Set("rootPin",pin);Set("fingerprint",SHA256.HashData(Join(Domain("ZTSE/root-pin/v2"),pin)));
            byte[] raw=D("manifest"),first=raw.AsSpan(0,raw.Length-64).ToArray();point.CopyTo(first,85);
            for(int i=0;i<first[150];i++){int at=151+149*i;if(first[at]==6){rootId.CopyTo(first,at+1);point.CopyTo(first,at+33);}}
            Set("manifest",Setup("ZTSE/manifest/v2",first));byte[] next=(byte[])first.Clone();BinaryPrimitives.WriteInt64BigEndian(next.AsSpan(29,8),2);SHA256.HashData(first).CopyTo(next,53);Set("nextManifest",Setup("ZTSE/manifest/v2",next));
            foreach(string name in new[]{"statement","nextStatement"}){raw=D(name);byte[] u=raw.AsSpan(0,raw.Length-64).ToArray();int at=40+BinaryPrimitives.ReadUInt16BigEndian(u.AsSpan(38,2))+24;D("fingerprint").CopyTo(u,at);SHA256.HashData(name=="statement"?first:next).CopyTo(u,at+32);Set(name,Setup("ZT/contact-reader/authorization/v1",u));}
            var root=ManifestChain.RootPin.Enroll(D("rootPin"),D("fingerprint"));var m=ManifestChain.Genesis02(D("manifest"),root,10000);var successor=ManifestChain.ContinueChain(D("nextManifest"),m,2,10000);
            var expected=new ContactField.Expected(D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),D("contact"),D("routing"),parser);
            var prepared=new List<(ContactField.Statement,byte[])>();var outputs=new List<object>();
            foreach(string name in new[]{"name","notes","replacement"}){
                string which=name=="replacement"?"nextStatement":"statement";var manifest=name=="replacement"?successor:m;
                var statement=ContactField.VerifyStatement(D(which),manifest,D("account"),f["origin"]!.GetValue<string>(),D("fingerprint"),parser);
                raw=D(name);byte[] u=raw.AsSpan(0,raw.Length-64).ToArray();manifest.Digest().CopyTo(u,102);statement.Digest().CopyTo(u,134);rootId.CopyTo(u,214);prepared.Add((statement,u));
                var produced=ContactField.ProduceProtected(key,statement,expected,u);outputs.Add(new{statement=which,bytes=Convert.ToBase64String(produced.Bytes())});controls++;
            }
            var (st,unsignedField)=prepared[0];borrowed=ProtectedContactSigner.Open(alias,point);ContactField.ProduceProtected(borrowed,st,expected,unsignedField);controls++;borrowed.Dispose();
            try{ContactField.ProduceProtected(borrowed,st,expected,unsignedField);throw new Exception("Closed signer accepted");}catch(CryptographicException){controls++;}
            var gate=typeof(ProtectedContactSigner).GetField("gate",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(key)!;
            var admission=(SemaphoreSlim)typeof(ContactField).GetField("Admission",BindingFlags.NonPublic|BindingFlags.Static)!.GetValue(null)!;
            var cancelled=Enumerable.Range(0,4).Select(_=>new CancellationTokenSource()).ToArray();bool[] refused=new bool[4];var callers=new Thread[4];
            try{lock(gate){
                for(int i=0;i<4;i++){int at=i;callers[i]=new Thread(()=>{try{ContactField.ProduceProtected(key,st,expected,unsignedField,cancelled[at].Token);}catch(CryptographicException){refused[at]=true;}});callers[i].Start();}
                if(!SpinWait.SpinUntil(()=>admission.CurrentCount==0,2000))throw new Exception("Four workers not admitted");
                Thread.Sleep(200);foreach(var cancel in cancelled)cancel.Cancel();
                for(int i=0;i<4;i++)if(!callers[i].Join(1000)||!refused[i])throw new Exception("Provider wait defeated cancellation");
                if(admission.CurrentCount!=0)throw new Exception("Unsettled workers released admission");
                try{ContactField.ProduceProtected(key,st,expected,unsignedField);throw new Exception("Fifth worker admitted");}catch(CryptographicException){controls++;}
            }}finally{foreach(var cancel in cancelled)cancel.Dispose();}
            if(!SpinWait.SpinUntil(()=>admission.CurrentCount==4,2000))throw new Exception("Worker admission leaked");controls++;
            bool timedOut=false;var elapsed=System.Diagnostics.Stopwatch.StartNew();
            lock(gate){var caller=new Thread(()=>{try{ContactField.ProduceProtected(key,st,expected,unsignedField);}catch(CryptographicException){timedOut=true;}});caller.Start();if(!caller.Join(12000)||!timedOut||elapsed.Elapsed.TotalSeconds<9.5||elapsed.Elapsed.TotalSeconds>12||admission.CurrentCount!=3)throw new Exception("Provider deadline/retained admission failed");}
            if(!SpinWait.SpinUntil(()=>admission.CurrentCount==4,2000))throw new Exception("Timed out worker did not settle");controls++;
            var result=new Dictionary<string,object>{{"fixture",f},{"outputs",outputs},{"controls",controls}};if(mutationMode)result["mutation"]=ContactMutationProtectedTest.Run(key,f,JsonSerializer.SerializeToElement(outputs),parser);return result;
        }finally{
            borrowed?.Dispose();if(key is not null){key.DeleteCreated();if(point is not null){try{using var reopened=ProtectedContactSigner.Open(alias,point);throw new Exception("Deleted key reopened");}catch(CryptographicException){}}Write(alias,"owned_key_deleted");}
        }
    }
}
