using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;
static class Program {
    static int checks;
    static void Check(bool v){if(!v)throw new Exception("Composition02 assertion");checks++;}
    static void Refuses(Action a){try{a();}catch(Exception e)when(e is CryptographicException or ArgumentException or InvalidOperationException){checks++;return;}throw new Exception("Invalid composition02 accepted");}
    static void Emit(byte[] b)=>Console.WriteLine("ENVELOPE "+Convert.ToBase64String(b));
    static Compose02.Request Request(Dictionary<string,byte[]> f,ProtectedSigner signer){var m=ManifestChain.Genesis02(f["manifest"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);return new(m,10000,Enumerable.Repeat((byte)49,16).ToArray(),f["device"],f["line"],10000,20000,"+12","Native composed02 🌱",signer,m.KeyRecords().Where(k=>k[0] is 1 or 2).Select(k=>new Compose02.Recipient(k[0],k.AsSpan(1,32).ToArray())).ToArray());}
    static void Main(string[] args){
        if(args.Length==4 && args[0]=="--replay"){
            var f=File.ReadAllLines(args[2]).Select(line=>line.Split('\t')).ToDictionary(v=>v[0],v=>Convert.FromHexString(v[1]));var m=ManifestChain.Genesis02(f["manifest"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);var key=m.KeyRecords().Single(k=>k[0]==5);
            using var signer=ProtectedSigner.Open(File.ReadAllText(args[1]).Trim(),key.AsSpan(33,65).ToArray());var r=Request(f,signer);
            Check(f["expected"].SequenceEqual(Compose02.ComposeOrReplay(args[3],f["rootPin"],f["fingerprint"],r,()=>new(m,11000))));return;
        }
        if(args.Length==1 && args[0]=="--probe"){try{ProtectedSigner.Probe();}catch(Exception e)when(e is PlatformNotSupportedException or CryptographicException){Environment.Exit(77);}return;}
        if(args.Length!=1)throw new ArgumentException("Pending receipt required");string receipt=args[0];ProtectedSigner? owner=null;bool deleted=false;
        try{
            owner=ProtectedSigner.Create(name=>{using var f=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough);f.Write(Encoding.UTF8.GetBytes(name+"\n"));f.Flush(true);});var signer=owner;Console.WriteLine(Convert.ToHexString(signer.PublicPoint()).ToLowerInvariant());Console.Out.Flush();
            var f=Console.In.ReadToEnd().Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(line=>line.Trim().Split('\t')).ToDictionary(v=>v[0],v=>Convert.FromHexString(v[1]));
            var manifest=ManifestChain.Genesis02(f["manifest"],ManifestChain.RootPin.Enroll(f["rootPin"],f["fingerprint"]),10000);var recipients=manifest.KeyRecords().Where(k=>k[0] is 1 or 2).Select(k=>new Compose02.Recipient(k[0],k.AsSpan(1,32).ToArray())).ToArray();
            var r=new Compose02.Request(manifest,10000,Enumerable.Repeat((byte)49,16).ToArray(),f["device"],f["line"],10000,20000,"+12","Native composed02 🌱",signer,recipients);
            byte[] first=Compose02.Fresh(r),second=Compose02.Fresh(r);Check(!first.SequenceEqual(second));Emit(first);Emit(second);Emit(Compose02.Fresh(r with{Message=new byte[16],ObservedMs=0,ExpiresMs=1}));
            foreach(var bad in new[]{r with{Message=Array.Empty<byte>()},r with{Message=new byte[15]},r with{Device=new byte[16]},r with{Line=new byte[16]},r with{NowMs=9999},r with{NowMs=100000},r with{ObservedMs=-1},r with{ExpiresMs=10000},r with{ExpiresMs=910001},r with{Peer="+01"},r with{Content=""},r with{Content="\ufeffbad"},r with{Content="bad\0"},r with{Content="\ud800"},r with{Content=new string('x',32769)},r with{Recipients=recipients.Take(1).ToArray()},r with{Recipients=new[]{recipients[0],recipients[0]}},r with{Recipients=new[]{new Compose02.Recipient(1,new byte[32]),recipients[1]}}})Refuses(()=>Compose02.Fresh(bad));
            string journal=Path.Combine(Path.GetTempPath(),"zrotext-retry02-"+Guid.NewGuid()+".journal");
            try{
                long now=10000;Func<Compose02.Current> current=()=>new(manifest,now);
                byte[] committed=Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current);Emit(committed);Check(committed.SequenceEqual(Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current)));
                now=11000;Check(committed.SequenceEqual(Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current)));now=10000;Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current));now=11000;
                Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,null!));Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r with{Content="changed"},current));Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r with{ObservedMs=0},current));
                now=20000;Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current));now=11000;
                var retained=ManifestChain.ContinueChain(f["currentRetained"],manifest,2,11000);var revoked=ManifestChain.ContinueChain(f["currentRevoked"],manifest,2,11000);
                Check(committed.SequenceEqual(Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,()=>new(retained,11000))));Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,()=>new(revoked,11000)));
                string fixture=Path.GetTempFileName();try{File.WriteAllLines(fixture,f.Select(v=>v.Key+"\t"+Convert.ToHexString(v.Value)).Append("expected\t"+Convert.ToHexString(committed)));var start=new System.Diagnostics.ProcessStartInfo("dotnet"){UseShellExecute=false};foreach(var value in new[]{typeof(Program).Assembly.Location,"--replay",receipt,fixture,journal})start.ArgumentList.Add(value);using var child=System.Diagnostics.Process.Start(start)!;child.WaitForExit();Check(child.ExitCode==0);}finally{File.Delete(fixture);}
                byte[] stable=File.ReadAllBytes(journal);using(var file=new FileStream(journal,FileMode.Append))file.WriteByte(1);Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current));File.WriteAllBytes(journal,stable);
                var a=Task.Run(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current));var b=Task.Run(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current));Task.WaitAll(a,b);Check(a.Result.SequenceEqual(b.Result));
                var rotated=ManifestChain.Rotate02(f["transition"],f["newManifest"],manifest,f["newPoint"],11000);var rotatedRequest=r with{Manifest=rotated,NowMs=11000};Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,()=>new(rotated,11000)));
                File.Delete(journal);byte[] rotatedBytes=Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],rotatedRequest,()=>new(rotated,11000));Check(rotatedBytes.SequenceEqual(Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],rotatedRequest,()=>new(rotated,11000))));Console.WriteLine("ROTATED "+Convert.ToBase64String(rotatedBytes));
                File.Delete(journal);int calls=0;Refuses(()=>Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,()=>++calls==6?throw new CryptographicException("Simulated postcommit authority loss"):new(manifest,11000)));Check(calls==6);byte[] saved=File.ReadAllBytes(journal);Check(Compose02.ComposeOrReplay(journal,f["rootPin"],f["fingerprint"],r,current).SequenceEqual(saved.AsSpan(270,saved.Length-302).ToArray()));
            }finally{File.Delete(journal);}
            Refuses(()=>signer.SignEnvelope03(first.AsSpan(0,first.Length-64).ToArray()));Refuses(()=>signer.SignEnvelope02(new byte[493]));signer.DeleteCreated();deleted=true;Refuses(()=>Compose02.Fresh(r));File.Delete(receipt);
            Console.WriteLine($"QUALIFIED: {checks} native Csharp profile02 composition checks passed; owned key deleted");
        }finally{if(owner is not null){try{if(!deleted){owner.DeleteCreated();File.Delete(receipt);}}finally{owner.Dispose();}}}
    }
}
