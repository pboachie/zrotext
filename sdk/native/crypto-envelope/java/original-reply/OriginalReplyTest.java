package org.zrotext.candidate;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public final class OriginalReplyTest {
    private OriginalReplyTest(){}
    interface Action {void run()throws Exception;}
    static int checks;
    static void refuse(Action action)throws Exception{try{action.run();}catch(GeneralSecurityException|IllegalArgumentException e){checks++;return;}throw new AssertionError("Expected refusal");}
    static PrivateKey scalar(byte[] scalar)throws Exception{var p=AlgorithmParameters.getInstance("EC");p.init(new ECGenParameterSpec("secp256r1"));return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,scalar),p.getParameterSpec(ECParameterSpec.class)));}
    static byte[] high(byte[] input){byte[] b=input.clone(),s=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16).subtract(new BigInteger(1,Arrays.copyOfRange(b,32,64))).toByteArray();Arrays.fill(b,32,64,(byte)0);System.arraycopy(s,Math.max(0,s.length-32),b,64-Math.min(32,s.length),Math.min(32,s.length));return b;}
    public static void main(String[] args)throws Exception{
        Map<String,byte[]> f=new HashMap<>();for(String line:new String(System.in.readAllBytes(),StandardCharsets.UTF_8).lines().toList()){String[] v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}
        var prior=ManifestChain.genesis02(f.get("predecessor"),ManifestChain.RootPin.enroll(f.get("rootPin"),f.get("fingerprint")),10000);
        var active=ManifestChain.continueChain(f.get("activation"),prior,2,10000);var successor=ManifestChain.continueChain(f.get("successor"),active,2,10000);var revoked=ManifestChain.continueChain(f.get("revoked"),active,2,10000);
        var scope=new OriginalReplyReader.Scope(f.get("account"),f.get("device"),f.get("line"),f.get("interval"),f.get("connector"),f.get("readGrant"),f.get("originalReader"),"+12");
        byte[] raw=f.get("selection"),approval=f.get("approval"),installation=f.get("installation");var selection=OriginalReplyReader.verifySelection(raw,approval,installation,active,10000,scope);
        for(int i=0;i<raw.length;i++){byte[] bad=raw.clone();bad[i]^=1;refuse(()->OriginalReplyReader.verifySelection(bad,approval,installation,active,10000,scope));}
        refuse(()->OriginalReplyReader.verifySelection(raw,high(approval),installation,active,10000,scope));refuse(()->OriginalReplyReader.verifySelection(raw,approval,high(installation),active,10000,scope));
        for(long when:new long[]{0,20000,Long.MAX_VALUE})refuse(()->OriginalReplyReader.verifySelection(raw,approval,installation,active,when,scope));
        refuse(()->OriginalReplyReader.verifySelection(raw,approval,installation,prior,10000,scope));
        byte[] wrong=f.get("connector").clone();wrong[0]^=1;var wrongScope=new OriginalReplyReader.Scope(f.get("account"),f.get("device"),f.get("line"),f.get("interval"),wrong,f.get("readGrant"),f.get("originalReader"),"+12");
        refuse(()->OriginalReplyReader.verifySelection(raw,approval,installation,active,10000,wrongScope));
        PrivateKey recipient=scalar(f.get("originalScalar"));String text=new String(f.get("text"),StandardCharsets.UTF_8);
        for(var current:List.of(active,successor)){int[] calls={0};String value=OriginalReplyReader.openSoftware(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->{calls[0]++;return new OriginalReplyReader.Authority(scope,"1",10000,20000,current);});if(!value.equals(text)||calls[0]!=2)throw new AssertionError("Open");checks++;}
        var finalStates=List.of(new OriginalReplyReader.Authority(scope,"2",10000,20000,active),new OriginalReplyReader.Authority(scope,"1",9999,20000,active),new OriginalReplyReader.Authority(scope,"1",20000,20000,active),new OriginalReplyReader.Authority(scope,"1",10000,10000,active),new OriginalReplyReader.Authority(wrongScope,"1",10000,20000,active),new OriginalReplyReader.Authority(scope,"1",10000,20000,successor),new OriginalReplyReader.Authority(scope,"1",10000,20000,revoked));
        for(var after:finalStates){int[] calls={0};refuse(()->OriginalReplyReader.openSoftware(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->++calls[0]==1?new OriginalReplyReader.Authority(scope,"1",10000,20000,active):after));if(calls[0]!=2)throw new AssertionError("Final callback not exercised");}
        for(String name:List.of("archiveOnly","inbound")){int[] calls={0};refuse(()->OriginalReplyReader.openSoftware(f.get(name),f.get("event"),active,selection,scope,recipient,()->{calls[0]++;return new OriginalReplyReader.Authority(scope,"1",10000,20000,name.equals("inbound")?revoked:active);}));if(calls[0]!=1)throw new AssertionError("Early refusal");}
        byte[] badEvent=f.get("event").clone();badEvent[0]^=1;refuse(()->OriginalReplyReader.openSoftware(f.get("inbound"),badEvent,active,selection,scope,recipient,()->{throw new AssertionError("Event before callback");}));
        byte[] wrongScalar=new byte[32];wrongScalar[31]=11;refuse(()->OriginalReplyReader.openSoftware(f.get("inbound"),f.get("event"),active,selection,scope,scalar(wrongScalar),()->new OriginalReplyReader.Authority(scope,"1",10000,20000,active)));
        raw[0]^=1;approval[0]^=1;installation[0]^=1;f.get("account")[0]^=1;
        if(!OriginalReplyReader.openSoftware(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->new OriginalReplyReader.Authority(scope,"1",10000,20000,active)).equals(text))throw new AssertionError("Aliased proof");
        System.out.println("Java original replies: "+checks+" controls passed");
    }
}
