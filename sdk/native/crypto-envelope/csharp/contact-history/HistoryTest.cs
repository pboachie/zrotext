using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace Zrotext.Candidate;
/// <summary>Restart, CAS, replay, fork, terminal and reduction controls over real signed history.</summary>
public static class HistoryTest {
    static int checks;
    static void Refuse(Action action){try{action();}catch(InvalidOperationException ex)when(ex.Message.StartsWith("Contact local history")){checks++;return;}catch(IOException){checks++;return;}catch(CryptographicException){checks++;return;}throw new InvalidOperationException("Expected history refusal");}
    static byte[] D(Dictionary<string,byte[]> f,string key)=>f[key];
    static byte[] Edit(byte[] raw,int at,byte[] value){byte[] output=(byte[])raw.Clone();Array.Copy(value,0,output,at,value.Length);return output;}
    static int Main(string[] args){
        string asset=args[0],path=args[1],origin=args[2],mode=args.Length>3?args[3]:"";
        var f=new Dictionary<string,byte[]>();foreach(string line in Console.In.ReadToEnd().Split('\n',StringSplitOptions.RemoveEmptyEntries)){var parts=line.Trim().Split('\t');f[parts[0]]=Convert.FromHexString(parts[1].Trim());}
        var parser=new ContactOrigin(asset);
        byte[] pin=D(f,"rootPin"),fingerprint=D(f,"fingerprint"),account=D(f,"account"),contact=D(f,"contact"),routing=D(f,"routing");
        var first=ManifestChain.Genesis02(D(f,"manifest"),ManifestChain.RootPin.Enroll(pin,fingerprint),10000);
        var second=ManifestChain.ContinueChain(D(f,"nextManifest"),first,2,10000);
        var s1=ContactField.VerifyStatement(D(f,"statement"),first,account,origin,fingerprint,parser);
        var s2=ContactField.VerifyStatement(D(f,"nextStatement"),second,account,origin,fingerprint,parser);
        var expected=new ContactField.Expected(account,origin,fingerprint,contact,routing,parser);
        var name=ContactField.Verify(D(f,"name"),s1,contact,routing);
        var notes=ContactField.Verify(D(f,"notes"),s1,contact,routing);
        var replacement=ContactField.Verify(D(f,"replacement"),s2,contact,routing);
        var create=ContactField.Mutation.VerifyTransition(null,ContactField.Mutation.Verify(D(f,"create"),s1,expected,0),new[]{name,notes});
        var update=ContactField.Mutation.VerifyTransition(create,ContactField.Mutation.Verify(D(f,"update"),s2,expected,0),new[]{replacement});
        var clear=ContactField.Mutation.VerifyTransition(update,ContactField.Mutation.Verify(D(f,"clear"),s2,expected,0),Array.Empty<ContactField.Verified>());
        byte[] scalar=new byte[32];scalar[31]=7;
        byte[] rootPoint=first.RootPoint();
        ECDsa rootKey=ECDsa.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=scalar,
            Q=new ECPoint{X=rootPoint[1..33],Y=rootPoint[33..65]}});
        byte[] forkUnsigned=(byte[])D(f,"update")[..304].Clone();Array.Fill(forkUnsigned,(byte)0x42,54,16);
        byte[] forkFieldUnsigned=(byte[])D(f,"replacement")[..^64].Clone();Array.Fill(forkFieldUnsigned,(byte)0x42,198,16);
        var forkField=ContactField.Verify(ContactField.ProduceSoftware(rootKey,s2,expected,forkFieldUnsigned).Bytes(),s2,contact,routing);
        Array.Copy(forkField.Digest(),0,forkUnsigned,272,32);
        var fork=ContactField.Mutation.ProduceSoftware(rootKey,s2,expected,forkUnsigned,0,create,s1,new[]{forkField});
        switch(mode){
            case "--partial":{
                using var file=new FileStream(path,FileMode.Append,FileAccess.Write);file.Write(new byte[]{0,0},0,2);file.Flush(true);
                Environment.Exit(19);return 0;}
            case "--seed":{
                using var seeder=ContactHistory.Create(path,pin,fingerprint,account,origin,8,new[]{first},10000);
                seeder.Accept(null,new[]{first},create,s1);
                Console.WriteLine("Seeded revision one");return 0;}
            case "--advance":{
                using var j=ContactHistory.Open(path,pin,fingerprint,account,origin,8);
                var holder=j.Lookup(contact).TokenField;
                try{j.Accept(holder!,new[]{first,second},update,s2);Console.WriteLine("CAS won");}
                catch(InvalidOperationException){Environment.Exit(3);}
                return 0;}
            case "--compete":{
                using var racer=ContactHistory.Open(path,pin,fingerprint,account,origin,8);
                var racerToken=racer.Lookup(contact).TokenField;
                try{racer.Accept(racerToken!,new[]{first,second},fork,s2);Console.WriteLine("unexpected fork win");}
                catch(InvalidOperationException){Environment.Exit(3);}
                return 0;}
            case "--digest":{
                Console.WriteLine(ContactHistory.FileDigest(path));return 0;}
            case "--verify":{
                using var j=ContactHistory.Open(path,pin,fingerprint,account,origin,8);
                if(j.Lookup(contact).Metadata!.Revision!=2)throw new InvalidOperationException("Child CAS state");
                Console.WriteLine("Restart CAS verified");return 0;}
            case "--refused":{
                Refuse(()=>ContactHistory.Open(path,pin,fingerprint,account,origin,8));
                Console.WriteLine("Interrupted append refused");return 0;}
            default:{
                Refuse(()=>ContactHistory.Open(path,pin,fingerprint,account,origin,8));
                using var j=ContactHistory.Create(path,pin,fingerprint,account,origin,8,new[]{first},10000);
                Refuse(()=>ContactHistory.Create(path,pin,fingerprint,account,origin,8,new[]{first},10000));
                byte[] wrongFp=(byte[])fingerprint.Clone();wrongFp[0]^=1;
                Refuse(()=>ContactHistory.Open(path,pin,wrongFp,account,origin,8));
                byte[] wrongAccount=(byte[])account.Clone();wrongAccount[0]^=1;
                Refuse(()=>ContactHistory.Open(path,pin,fingerprint,wrongAccount,origin,8));
                if(j.Lookup(contact).Reason!="unobserved")throw new InvalidOperationException("Unobserved");
                Refuse(()=>j.Accept(null,new[]{first},update,s2));
                using(var fresh=ContactHistory.Create(path+".cold",pin,fingerprint,account,origin,8,new[]{first,second},10000))
                    Refuse(()=>fresh.Accept(null,new[]{first,second},update,s2));
                File.Delete(path+".cold");
                var saved=j.Accept(null,new[]{first},create,s1);
                if(!saved.Accepted || saved.Metadata!.Revision!=1)throw new InvalidOperationException("Cold create");
                var holder=saved.TokenField!;
                var replay=j.Accept(holder,new[]{first},create,s1);
                if(!replay.Accepted || replay.Metadata!.Revision!=1)throw new InvalidOperationException("Replay");
                Refuse(()=>j.Accept(null,new[]{first},create,s1));
                var advanced=j.Accept(holder,new[]{first,second},fork,s2);
                if(!advanced.Accepted || advanced.Metadata.Revision!=2 || advanced.Metadata.ManifestVersion!=2)throw new InvalidOperationException("Root advance");
                Refuse(()=>j.Accept(advanced.TokenField!,new[]{first,second},update,s2));
                using(var reduced=ContactHistory.Open(path,pin,fingerprint,account,origin,8,true)){
                    var reducedRow=reduced.Lookup(contact);
                    if(reducedRow.Accepted || reducedRow.Reason!="reduction_only")throw new InvalidOperationException("Reduction lookup");
                    Refuse(()=>reduced.Accept(reducedRow.TokenField!,new[]{first,second},update,s2));
                    if(reduced.MarkUnavailable(reducedRow.TokenField!).Reason!="local_stop")throw new InvalidOperationException("Reduction stop");
                }
                Refuse(()=>j.MarkUnavailable(advanced.TokenField!));
                if(j.Lookup(contact).Reason!="local_stop")throw new InvalidOperationException("Terminal lookup");
                Refuse(()=>j.Accept(j.Lookup(contact).TokenField!,new[]{first,second},clear,s2));
                j.Dispose();
                Refuse(()=>j.Lookup(contact));
                using(var reopened=ContactHistory.Open(path,pin,fingerprint,account,origin,8)){
                    if(reopened.Lookup(contact).Reason!="local_stop")throw new InvalidOperationException("Terminal restart");
                    Refuse(()=>reopened.Accept(holder,new[]{first,second},update,s2));
                }
                byte[] other=(byte[])contact.Clone();other[0]^=1;
                var expectedOther=new ContactField.Expected(account,origin,fingerprint,other,routing,parser);
                byte[] otherNameUnsigned=Edit((byte[])D(f,"name")[..^64].Clone(),22,other);Array.Fill(otherNameUnsigned,(byte)0x42,198,16);
                byte[] otherNotesUnsigned=Edit((byte[])D(f,"notes")[..^64].Clone(),22,other);Array.Fill(otherNotesUnsigned,(byte)0x42,198,16);
                var otherName=ContactField.Verify(ContactField.ProduceSoftware(rootKey,s1,expectedOther,otherNameUnsigned).Bytes(),s1,other,routing);
                var otherNotes=ContactField.Verify(ContactField.ProduceSoftware(rootKey,s1,expectedOther,otherNotesUnsigned).Bytes(),s1,other,routing);
                byte[] unsigned=(byte[])D(f,"create")[..304].Clone();
                Array.Copy(other,0,unsigned,22,16);Array.Fill(unsigned,(byte)0x42,54,16);
                Array.Copy(otherName.Digest(),0,unsigned,231,32);Array.Copy(otherNotes.Digest(),0,unsigned,272,32);
                var otherCreate=ContactField.Mutation.ProduceSoftware(rootKey,s1,expectedOther,unsigned,0,null,null,new[]{otherName,otherNotes});
                var boundedPath=path+".bounded";
                using(var bounded=ContactHistory.Create(boundedPath,pin,fingerprint,account,origin,1,new[]{first},10000)){
                    bounded.Accept(null,new[]{first},create,s1);
                    Refuse(()=>bounded.Accept(null,new[]{first},otherCreate,s1));
                }
                File.Delete(boundedPath);
                byte[] bytes=File.ReadAllBytes(path);string bad=path+".bad";
                foreach(int at in new[]{0,4,98,130,161,bytes.Length-33,bytes.Length-1}){
                    byte[] copy=(byte[])bytes.Clone();copy[at]^=1;File.WriteAllBytes(bad,copy);
                    Refuse(()=>ContactHistory.Open(bad,pin,fingerprint,account,origin,8));
                }
                File.Delete(bad);
                Console.WriteLine($"C# contact history {checks} controls passed");
                return 0;}
        }
    }
}
