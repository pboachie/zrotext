package org.zrotext.candidate;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public final class OriginalProtectedTest {
    private OriginalProtectedTest(){}
    interface Action {void run()throws Exception;}
    static int checks;
    static void refuse(Action action)throws Exception{try{action.run();}catch(GeneralSecurityException|IllegalArgumentException e){checks++;return;}throw new AssertionError("Expected refusal");}
    public static void main(String[] args)throws Exception{
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedRecipient.probe();}catch(GeneralSecurityException e){System.exit(77);}return;}
        if(args.length!=1)throw new IllegalArgumentException("Pending receipt required");Path receipt=Path.of(args[0]);ProtectedRecipient owner=null;
        try{
            owner=ProtectedRecipient.create(alias->{try(var stream=FileChannel.open(receipt,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,StandardOpenOption.SYNC)){var b=StandardCharsets.UTF_8.encode(alias+"\n");while(b.hasRemaining())stream.write(b);stream.force(true);}});
            System.out.println(HexFormat.of().formatHex(owner.publicPoint()));System.out.flush();
            Map<String,byte[]> f=new HashMap<>();for(String line:new String(System.in.readAllBytes(),StandardCharsets.UTF_8).lines().toList()){String[] v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}if(f.containsKey("originalScalar"))throw new AssertionError("Native scalar present");
            var prior=ManifestChain.genesis02(f.get("predecessor"),ManifestChain.RootPin.enroll(f.get("rootPin"),f.get("fingerprint")),10000);var active=ManifestChain.continueChain(f.get("activation"),prior,2,10000);var successor=ManifestChain.continueChain(f.get("successor"),active,2,10000);var revoked=ManifestChain.continueChain(f.get("revoked"),active,2,10000);
            var scope=new OriginalReplyReader.Scope(f.get("account"),f.get("device"),f.get("line"),f.get("interval"),f.get("connector"),f.get("readGrant"),f.get("originalReader"),"+12");var selection=OriginalReplyReader.verifySelection(f.get("selection"),f.get("approval"),f.get("installation"),active,10000,scope);
            var recipient=owner;String expected=new String(f.get("text"),StandardCharsets.UTF_8);String alias=owner.alias();byte[] point=owner.publicPoint();
            for(var current:List.of(active,successor)){int[] calls={0};String value=OriginalReplyReader.openWithRecipient(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->{calls[0]++;return new OriginalReplyReader.Authority(scope,"1",10000,20000,current);});if(!value.equals(expected)||calls[0]!=2)throw new AssertionError("Native opening");checks++;}
            var reopened=ProtectedRecipient.open(alias,point);try(reopened){
                if(!OriginalReplyReader.openWithRecipient(f.get("inbound"),f.get("event"),active,selection,scope,reopened,()->new OriginalReplyReader.Authority(scope,"1",10000,20000,active)).equals(expected))throw new AssertionError("Reopened");checks++;refuse(reopened::deleteCreated);
            }
            refuse(()->OriginalReplyReader.openWithRecipient(f.get("inbound"),f.get("event"),active,selection,scope,reopened,()->new OriginalReplyReader.Authority(scope,"1",10000,20000,active)));
            for(var current:List.of(revoked)){refuse(()->OriginalReplyReader.openWithRecipient(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->new OriginalReplyReader.Authority(scope,"1",10000,20000,current)));}
            int[] calls={0};refuse(()->OriginalReplyReader.openWithRecipient(f.get("inbound"),f.get("event"),active,selection,scope,recipient,()->new OriginalReplyReader.Authority(scope,++calls[0]==1?"1":"2",10000,20000,active)));if(calls[0]!=2)throw new AssertionError("Final check");
            KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));var q=((java.security.interfaces.ECPublicKey)g.generateKeyPair().getPublic()).getW();byte[] wrong=new byte[65];wrong[0]=4;byte[] x=q.getAffineX().toByteArray(),y=q.getAffineY().toByteArray();System.arraycopy(x,Math.max(0,x.length-32),wrong,33-Math.min(32,x.length),Math.min(32,x.length));System.arraycopy(y,Math.max(0,y.length-32),wrong,65-Math.min(32,y.length),Math.min(32,y.length));refuse(()->{try(var ignored=ProtectedRecipient.open(alias,wrong)){ignored.publicPoint();}});
            owner.deleteCreated();owner=null;Files.delete(receipt);refuse(()->{try(var ignored=ProtectedRecipient.open(alias,point)){ignored.publicPoint();}});
            System.out.println("QUALIFIED: Java protected original reply "+checks+" controls passed");
        }finally{if(owner!=null){owner.deleteCreated();Files.delete(receipt);owner.close();}}
    }
}
