package org.zrotext.candidate;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class ReaderTest {
    private ReaderTest() {}
    interface Attempt {void run()throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    static void refuses(Attempt a)throws Exception{try{a.run();}catch(GeneralSecurityException|IllegalArgumentException expected){checks++;return;}throw new AssertionError("Reader accepted invalid input");}
    public static void main(String[] args)throws Exception{
        Scanner input=new Scanner(System.in);int rows=0;
        while(input.hasNextLine()){
            String[] f=input.nextLine().split("\t");long now=Long.parseLong(f[1]);byte[][] d=new byte[11][];for(int i=0;i<11;i++)d[i]=HexFormat.of().parseHex(f[i+2]);
            var manifest=ManifestChain.genesis02(d[2],ManifestChain.RootPin.enroll(d[0],d[1]),now);
            var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));
            var key=KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,d[4]),parameters.getParameterSpec(ECParameterSpec.class)));
            SealedReader02.CurrentSelection current=(account,version,digest,wire)->Arrays.equals(account,manifest.account()) && version==manifest.version() && Arrays.equals(digest,manifest.digest());
            var next=ManifestChain.continueChain(d[9],manifest,2,now);var rotated=ManifestChain.continueChain(d[10],manifest,2,now);
            check(next.descendsFrom(manifest) && !manifest.descendsFrom(next) && !next.descendsFrom(rotated));
            var refreshed=ManifestChain.continueChain(d[9],next,2,now);check(refreshed.descendsFrom(manifest));
            SealedReader02.CurrentSelection live=(a,v,h,w)->v==next.version() && Arrays.equals(h,next.digest());
            if(f[0].equals("inbound"))check(SealedReader02.openHistoricalArchive(d[3],manifest,refreshed,now,d[5],key,live).equals(new String(d[7],StandardCharsets.UTF_8)));
            else refuses(()->SealedReader02.openHistoricalArchive(d[3],manifest,next,now,d[5],key,live));
            int[] rotatedCalls={0};refuses(()->SealedReader02.openHistoricalArchive(d[3],manifest,rotated,now,d[5],null,(a,v,h,w)->{rotatedCalls[0]++;return true;}));check(rotatedCalls[0]==0);
            check(SealedReader02.open(d[3],manifest,now,2,d[5],key,current).equals(new String(d[7],StandardCharsets.UTF_8)));
            byte[] signer=Arrays.stream(manifest.keyRecords()).filter(r->r[0]==4).findFirst().orElseThrow();
            check(SignedEnvelope.verify(d[8],2,Arrays.copyOfRange(signer,33,98)).kind()==2);
            int[] backdatedCalls={0};refuses(()->SealedReader02.open(d[8],manifest,now,2,d[5],key,(a,v,h,w)->{backdatedCalls[0]++;return true;}));check(backdatedCalls[0]==0);
            refuses(()->SealedReader02.open(d[3],manifest,now,2,d[5],key,(a,v,h,w)->false));
            int[] calls={0};refuses(()->SealedReader02.open(d[3],manifest,now,2,d[5],key,(a,v,h,w)->++calls[0]==1));check(calls[0]==2);
            refuses(()->SealedReader02.open(d[3],manifest,now-1,2,d[5],key,current));
            refuses(()->SealedReader02.open(d[3],manifest,manifest.expiresMs(),2,d[5],key,current));
            refuses(()->SealedReader02.open(d[3],manifest,now,1,d[5],key,current));
            for(int at:new int[]{4,10,26,42,58,74,82,114,146,d[3].length-1}){
                var changed=d[3].clone();changed[at]^=1;refuses(()->SealedReader02.open(changed,manifest,now,2,d[5],key,current));
            }
            var wrongId=d[5].clone();wrongId[0]^=1;refuses(()->SealedReader02.open(d[3],manifest,now,2,wrongId,key,current));
            rows++;
        }
        check(rows==2);System.out.println(checks+" reader checks passed");
    }
}
