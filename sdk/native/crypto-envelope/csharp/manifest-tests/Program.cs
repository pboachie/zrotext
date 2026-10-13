using System;
using System.Linq;
using System.Security.Cryptography;
using Zrotext.Candidate;

static class Program {
    static int checks;
    static void Check(bool value){if(!value)throw new Exception("Manifest assertion");checks++;}
    static void Refuses(Action work){try{work();}catch(CryptographicException){checks++;return;}throw new Exception("Accepted invalid provenance");}
    static byte[] Hex(string value)=>Convert.FromHexString(value);
    static void Main(){
        int rows=0;string? line;
        while((line=Console.ReadLine()) is not null){
            var f=line.Split('\t');long now=long.Parse(f[1]);var pin=Hex(f[2]);var fingerprint=Hex(f[3]);var manifest=Hex(f[4]);
            var root=ManifestChain.RootPin.Enroll(pin,fingerprint);var original=ManifestChain.Genesis02(manifest,root,now);
            Check(original.Digest().SequenceEqual(Hex(f[5])));Check(original.Profile==2 && original.Version==1);
            Check(ManifestChain.ContinueChain(manifest,original,2,now).Digest().SequenceEqual(original.Digest()));
            var exposed=original.Bytes();exposed[0]^=1;Check(original.Bytes()[0]==90);
            var wrong=(byte[])fingerprint.Clone();wrong[0]^=1;Refuses(()=>ManifestChain.RootPin.Enroll(pin,wrong));
            Refuses(()=>ManifestChain.Genesis02(manifest,root,original.ExpiresMs));
            Refuses(()=>ManifestChain.ContinueChain(manifest,original,2,now-1));
            foreach(int at in new[]{0,21,29,53,85,150,151,manifest.Length-1}){
                var altered=(byte[])manifest.Clone();altered[at]^=1;Refuses(()=>ManifestChain.Genesis02(altered,root,now));
            }
            Refuses(()=>ManifestChain.Genesis02(manifest[..^1],root,now));
            if(f.Length==10){
                var first=Hex(f[6]);var next=Hex(f[7]);var alternate=Hex(f[8]);long later=long.Parse(f[9]);
                var p3=ManifestChain.ContinueChain(first,original,3,now);Check(p3.Profile==3 && p3.Version==2);
                var successor=ManifestChain.ContinueChain(next,p3,3,later);Check(successor.Version==3);
                Check(ManifestChain.ContinueChain(alternate,p3,3,later).Digest().SequenceEqual(p3.Digest()));
                Refuses(()=>ManifestChain.ContinueChain(next,original,3,now));Refuses(()=>ManifestChain.ContinueChain(manifest,p3,2,now));
                Refuses(()=>ManifestChain.ContinueChain(first,original,3,original.ExpiresMs));Refuses(()=>ManifestChain.ContinueChain(first,successor,3,later));
            }
            rows++;
        }
        Check(rows==2);Console.WriteLine($"{checks} manifest checks passed");
    }
}
