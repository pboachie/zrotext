package org.zrotext.candidate;
import java.util.*;
import java.security.GeneralSecurityException;

public final class ManifestTest {
    private ManifestTest() {}
    interface Attempt {void run() throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException expected){checks++;return;}throw new AssertionError("Accepted invalid provenance");}
    static byte[] hex(String value){return HexFormat.of().parseHex(value);}
    public static void main(String[] args)throws Exception{
        Scanner input=new Scanner(System.in);int rows=0;
        while(input.hasNextLine()){
            String[] f=input.nextLine().split("\t");long now=Long.parseLong(f[1]);byte[] pin=hex(f[2]),fingerprint=hex(f[3]),manifest=hex(f[4]);
            var root=ManifestChain.RootPin.enroll(pin,fingerprint);var original=ManifestChain.genesis02(manifest,root,now);
            check(Arrays.equals(original.digest(),hex(f[5])));check(original.profile()==2 && original.version()==1);
            check(Arrays.equals(ManifestChain.continueChain(manifest,original,2,now).digest(),original.digest()));
            var exposed=original.bytes();exposed[0]^=1;check(original.bytes()[0]==90);
            byte[] wrong=fingerprint.clone();wrong[0]^=1;refuses(()->ManifestChain.RootPin.enroll(pin,wrong));
            refuses(()->ManifestChain.genesis02(manifest,root,original.expiresMs()));
            refuses(()->ManifestChain.genesis02(manifest,root,0));
            refuses(()->ManifestChain.continueChain(manifest,original,2,now-1));
            for(int at:new int[]{0,21,29,53,85,150,151,manifest.length-1}){
                byte[] altered=manifest.clone();altered[at]^=1;refuses(()->ManifestChain.genesis02(altered,root,now));
            }
            refuses(()->ManifestChain.genesis02(Arrays.copyOf(manifest,manifest.length-1),root,now));
            if(f.length==10){
                byte[] first=hex(f[6]),next=hex(f[7]),alternate=hex(f[8]);long later=Long.parseLong(f[9]);
                var p3=ManifestChain.continueChain(first,original,3,now);check(p3.profile()==3 && p3.version()==2);
                var successor=ManifestChain.continueChain(next,p3,3,later);check(successor.version()==3);
                check(Arrays.equals(ManifestChain.continueChain(alternate,p3,3,later).digest(),p3.digest()));
                refuses(()->ManifestChain.continueChain(next,original,3,now));
                refuses(()->ManifestChain.continueChain(manifest,p3,2,now));
                refuses(()->ManifestChain.continueChain(first,original,3,original.expiresMs()));
                refuses(()->ManifestChain.continueChain(first,successor,3,later));
            }
            rows++;
        }
        check(rows==2);System.out.println(checks+" manifest checks passed");
    }
}
