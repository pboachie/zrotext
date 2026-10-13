using System.Security.Cryptography;
using System.Text;
using Zrotext.Candidate;
sealed class Source(Func<ElectedReader03.AuthoritySnapshot> read):ElectedReader03.IAuthoritySource {public ElectedReader03.AuthoritySnapshot Read()=>read();}
static class Program {
    static int checks;static void Check(bool value){if(!value)throw new Exception("Election journal assertion");checks++;}
    static void Refuses(Action action){try{action();}catch(Exception e)when(e is CryptographicException or ArgumentException or IOException){checks++;return;}throw new Exception("Election journal should refuse");}
    static void Main(string[] args){
        var wire=new Dictionary<string,byte[]>();var accepted=new Dictionary<string,object>();var authority=new Dictionary<string,object>();string rawInput=Console.In.ReadToEnd();foreach(string line in rawInput.Split('\n',StringSplitOptions.RemoveEmptyEntries)){var f=line.Trim().Split('\t');object value=f[1]=="b"?Convert.FromHexString(f[2]):long.Parse(f[2]);if(f[0].StartsWith("accepted."))accepted.Add(f[0][9..],value);else if(f[0].StartsWith("authority."))authority.Add(f[0][10..],value);else wire.Add(f[0],(byte[])value);}
        byte[] externalCore=(byte[])wire["core"].Clone();var expected=new ElectionJournal.Expectations(externalCore,accepted,wire["deviceSigningPoint"],wire["ownerApprovalPoint"]);externalCore[0]^=1;
        if(args.Length==1){var restored=new ElectionJournal(args[0],wire["rootPin"],wire["fingerprint"],expected).ReadSnapshot(30000);Check(restored.Revision==2 && restored.Proof is not null);return;}
        string path=Path.Combine(Path.GetTempPath(),"zrotext-election-"+Guid.NewGuid()+".journal");try{
            var journal=new ElectionJournal(path,wire["rootPin"],wire["fingerprint"],expected);Check(journal.Accept(wire["signed02"],null,0,10000).Revision==1);Refuses(()=>journal.Accept(wire["signed03"],null,1,10000));
            for(int at=0;at<628;at++){byte[] changed=(byte[])wire["bundle"].Clone();changed[at]^=1;Refuses(()=>journal.Accept(wire["signed03"],changed,1,(long)accepted["acceptedAtMs"]));}Check(journal.ReadSnapshot(10000).Revision==1);
            var selected=journal.Accept(wire["signed03"],wire["bundle"],1,(long)accepted["acceptedAtMs"]);Check(selected.Revision==2 && selected.Proof is not null);var restored=new ElectionJournal(path,wire["rootPin"],wire["fingerprint"],expected).ReadSnapshot(30000);Check(restored.Manifest!.Version==2);
            Refuses(()=>new ElectionJournal(path,wire["rootPin"],wire["fingerprint"],null).ReadSnapshot(30000));var wrong=new Dictionary<string,object>(accepted);byte[] binding=(byte[])((byte[])wrong["newBindingId"]).Clone();binding[0]^=1;wrong["newBindingId"]=binding;var changedExpected=new ElectionJournal.Expectations(wire["core"],wrong,wire["deviceSigningPoint"],wire["ownerApprovalPoint"]);Refuses(()=>new ElectionJournal(path,wire["rootPin"],wire["fingerprint"],changedExpected).ReadSnapshot(30000));
            var start=new System.Diagnostics.ProcessStartInfo("dotnet"){UseShellExecute=false,RedirectStandardInput=true};start.ArgumentList.Add(typeof(Program).Assembly.Location);start.ArgumentList.Add(path);using(var child=System.Diagnostics.Process.Start(start)!){child.StandardInput.Write(rawInput);child.StandardInput.Close();child.WaitForExit();Check(child.ExitCode==0);}
            using var key=ECDiffieHellman.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=wire["readerScalar"],Q=new ECPoint{X=wire["readerPoint"].AsSpan(1,32).ToArray(),Y=wire["readerPoint"].AsSpan(33,32).ToArray()}});
            Check(ElectedReader03.OpenSoftware(wire["envelope"],restored.Manifest!,restored.Proof!,new Source(()=>new(authority,30000)),wire["message"],"+12",key)==Encoding.UTF8.GetString(wire["text"]));
            Refuses(()=>journal.ReadSnapshot(29999));byte[] stable=File.ReadAllBytes(path);using(var file=new FileStream(path,FileMode.Append))file.WriteByte(1);Refuses(()=>journal.ReadSnapshot(30000));File.WriteAllBytes(path,stable);byte[] torn=(byte[])stable.Clone();torn[130]^=1;File.WriteAllBytes(path,torn);Refuses(()=>journal.ReadSnapshot(30000));File.WriteAllBytes(path,Array.Empty<byte>());Refuses(()=>journal.ReadSnapshot(30000));File.WriteAllBytes(path,stable);Refuses(()=>journal.Accept(wire["successor"],null,1,30000));
            int successes=0;Action append=()=>{try{journal.Accept(wire["successor"],null,2,30000);Interlocked.Increment(ref successes);}catch(CryptographicException){}};Task.WaitAll(Task.Run(append),Task.Run(append));Check(successes==1);Check(journal.ReadSnapshot(30000).Manifest!.Version==3);Refuses(()=>journal.Accept(wire["signed02"],null,3,30000));Refuses(()=>journal.Accept(wire["signed03"],wire["bundle"],3,30000));
            journal.ReadSnapshot(30001);Refuses(()=>new ElectionJournal(path,wire["rootPin"],wire["fingerprint"],expected).ReadSnapshot(30000));
            string lifecycle=path+".lifecycle";try{var live=new ElectionJournal(lifecycle,wire["rootPin"],wire["fingerprint"],expected);live.Accept(wire["signed02"],null,0,10000);var active=live.Accept(wire["signed03"],wire["bundle"],1,(long)accepted["acceptedAtMs"]);int calls=0;
                Refuses(()=>ElectedReader03.OpenSoftware(wire["envelope"],active.Manifest!,active.Proof!,new Source(()=>{var now=live.ReadSnapshot(30000);if(!now.Manifest!.Digest().SequenceEqual(active.Manifest!.Digest()))throw new CryptographicException("Selection changed");if(++calls==1)live.Accept(wire["successor"],null,2,30000);return new(authority,30000);}),wire["message"],"+12",key));Check(calls==1 && live.ReadSnapshot(30000).Revision==3);
            }finally{File.Delete(lifecycle);}
            Console.WriteLine($"{checks} Csharp durable election checks passed");
        }finally{File.Delete(path);}
    }
}
