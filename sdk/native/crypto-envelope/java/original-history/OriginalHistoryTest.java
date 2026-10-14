package org.zrotext.candidate;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

public final class OriginalHistoryTest {
    private OriginalHistoryTest(){}
    interface Action{void run()throws Exception;}
    static int checks;
    static void refuse(Action a)throws Exception{try{a.run();}catch(GeneralSecurityException|java.io.IOException|IllegalArgumentException e){checks++;return;}throw new AssertionError("Expected history refusal");}
    public static void main(String[] args)throws Exception{
        Path path=Path.of(args[1]);Map<String,byte[]> f=new HashMap<>();for(String line:new String(System.in.readAllBytes(),StandardCharsets.UTF_8).lines().toList()){var v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}
        var scope=new OriginalReplyReader.Scope(f.get("account"),f.get("device"),f.get("line"),f.get("interval"),f.get("connector"),f.get("readGrant"),f.get("originalReader"),"+12");
        var prior=ManifestChain.genesis02(f.get("predecessor"),ManifestChain.RootPin.enroll(f.get("rootPin"),f.get("fingerprint")),10000);var active=ManifestChain.continueChain(f.get("activation"),prior,2,10000);var successor=ManifestChain.continueChain(f.get("successor"),active,2,10000);var revoked=ManifestChain.continueChain(f.get("revoked"),active,2,10000);var history=List.of(prior,active,successor);
        if(args[0].equals("--partial")){try(var file=FileChannel.open(path,StandardOpenOption.WRITE,StandardOpenOption.APPEND)){file.write(ByteBuffer.wrap(new byte[]{0,0}));file.force(true);Runtime.getRuntime().halt(19);}return;}
        if(args[0].equals("--advance")){var j=OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),scope);try{j.accept(scope,history,3,10006,(m,n)->n);System.out.println("CAS won");}catch(GeneralSecurityException e){System.exit(3);}return;}
        if(args[0].equals("--verify")){var j=OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),scope);if(j.snapshot(scope,10006).revision()!=4)throw new AssertionError("Child CAS state");System.out.println("Restart CAS verified");return;}
        if(args[0].equals("--refused")){refuse(()->OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),scope));System.out.println("Interrupted append refused");return;}
        refuse(()->OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),scope));var j=OriginalReplyCheckpoint.create(path,f.get("rootPin"),f.get("fingerprint"),scope,List.of(prior,active),10000);
        refuse(()->OriginalReplyCheckpoint.create(path,f.get("rootPin"),f.get("fingerprint"),scope,List.of(prior,active),10000));byte[] wrong=f.get("readGrant").clone();wrong[0]^=1;var wrongScope=new OriginalReplyReader.Scope(f.get("account"),f.get("device"),f.get("line"),f.get("interval"),f.get("connector"),wrong,f.get("originalReader"),"+12");
        refuse(()->OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),wrongScope));refuse(()->j.snapshot(scope,9999));refuse(()->j.snapshot(scope,Long.MAX_VALUE));
        var read=j.snapshot(scope,10001);if(read.revision()!=1 || read.comparisonMs()!=10000)throw new AssertionError("Snapshot mutated floor");checks++;
        refuse(()->j.accept(scope,history,0,10001,(m,n)->{throw new AssertionError("CAS before fence");}));refuse(()->j.accept(scope,history,1,10001,(m,n)->{throw new GeneralSecurityException("Fence refused");}));refuse(()->j.accept(scope,history,1,10001,(m,n)->9999));refuse(()->j.accept(scope,history,1,10001,(m,n)->Long.MAX_VALUE));
        if(j.snapshot(scope,10000).revision()!=1)throw new AssertionError("Failed fence committed");checks++;
        var next=j.accept(scope,history,1,10002,(m,n)->10003);if(next.revision()!=2 || next.comparisonMs()!=10003)throw new AssertionError("Advance");checks++;
        refuse(()->j.snapshot(scope,10002));refuse(()->j.accept(scope,List.of(prior,active,revoked),2,10003,(m,n)->n));refuse(()->j.accept(scope,List.of(prior,active),2,10003,(m,n)->n));
        var reopened=OriginalReplyCheckpoint.open(path,f.get("rootPin"),f.get("fingerprint"),scope);var restored=reopened.snapshot(scope,10004).history();var selection=OriginalReplyReader.verifySelection(f.get("selection"),f.get("approval"),f.get("installation"),restored.get(1),10000,scope);
        var p=AlgorithmParameters.getInstance("EC");p.init(new java.security.spec.ECGenParameterSpec("secp256r1"));var key=KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.ECPrivateKeySpec(new java.math.BigInteger(1,f.get("originalScalar")),p.getParameterSpec(java.security.spec.ECParameterSpec.class)));
        var committed=reopened.accept(scope,history,2,10004,(m,n)->10005);String plain=OriginalReplyReader.openSoftware(f.get("inbound"),f.get("event"),restored.get(1),selection,scope,key,()->new OriginalReplyReader.Authority(scope,"1",10005,20000,committed.history().get(2)));if(!plain.equals(new String(f.get("text"),StandardCharsets.UTF_8)))throw new AssertionError("Restored opening");checks++;
        byte[] bytes=Files.readAllBytes(path);Path bad=path.resolveSibling(path.getFileName()+".bad");
        for(int at:new int[]{0,4,98,130,161,162,166,174,182,bytes.length-33,bytes.length-1}){byte[] copy=bytes.clone();copy[at]^=1;Files.write(bad,copy);refuse(()->OriginalReplyCheckpoint.open(bad,f.get("rootPin"),f.get("fingerprint"),scope));}Files.delete(bad);
        refuse(()->reopened.snapshot(scope,10004));System.out.println("Java original history "+checks+" controls passed");
    }
}
