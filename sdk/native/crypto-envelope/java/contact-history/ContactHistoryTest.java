package org.zrotext.candidate;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Restart, CAS, replay, fork, terminal and reduction controls over real signed history. */
public final class ContactHistoryTest {
    private ContactHistoryTest(){}
    interface Action{void run()throws Exception;}
    static int checks;
    static void refuse(Action a)throws Exception{try{a.run();}catch(GeneralSecurityException|java.io.IOException|IllegalArgumentException e){checks++;return;}throw new AssertionError("Expected history refusal");}
    static byte[] d(Map<String,byte[]> f,String key){return f.get(key);}
    static KeyPair key(byte[] root,byte[] scalar)throws Exception{
        ECPublicKey point=(ECPublicKey)HpkeRecipient.point(root);
        return new KeyPair(point,KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,scalar),point.getParams())));
    }
    static byte[] edit(byte[] raw,int at,byte[] value){byte[] out=raw.clone();System.arraycopy(value,0,out,at,value.length);return out;}
    public static void main(String[] args)throws Exception{
        Path path=Path.of(args[1]);String origin=args[2];
        Map<String,byte[]> f=new HashMap<>();for(String line:new String(System.in.readAllBytes(),StandardCharsets.UTF_8).lines().toList()){var v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}
        var parser=new ContactOrigin(Path.of(args[0]));
        byte[] pin=d(f,"rootPin"),fingerprint=d(f,"fingerprint"),account=d(f,"account"),contact=d(f,"contact"),routing=d(f,"routing");
        var first=ManifestChain.genesis02(d(f,"manifest"),ManifestChain.RootPin.enroll(pin,fingerprint),10000);
        var second=ManifestChain.continueChain(d(f,"nextManifest"),first,2,10000);
        var s1=ContactField.verifyStatement(d(f,"statement"),first,account,origin,fingerprint,parser);
        var s2=ContactField.verifyStatement(d(f,"nextStatement"),second,account,origin,fingerprint,parser);
        var expected=new ContactField.Expected(account,origin,fingerprint,contact,routing,parser);
        var name=ContactField.verify(d(f,"name"),s1,contact,routing);
        var notes=ContactField.verify(d(f,"notes"),s1,contact,routing);
        var replacement=ContactField.verify(d(f,"replacement"),s2,contact,routing);
        var create=ContactField.Mutation.transition(null,ContactField.Mutation.verify(d(f,"create"),s1,expected,0),List.of(name,notes));
        var update=ContactField.Mutation.transition(create,ContactField.Mutation.verify(d(f,"update"),s2,expected,0),List.of(replacement));
        var clear=ContactField.Mutation.transition(update,ContactField.Mutation.verify(d(f,"clear"),s2,expected,0),List.of());
        byte[] scalar=new byte[32];scalar[31]=7;KeyPair rootKey=key(first.rootPoint(),scalar);
        byte[] forkUnsigned=java.util.Arrays.copyOf(d(f,"update"),304);java.util.Arrays.fill(forkUnsigned,54,70,(byte)0x42);
        byte[] forkFieldUnsigned=java.util.Arrays.copyOf(d(f,"replacement"),d(f,"replacement").length-64);java.util.Arrays.fill(forkFieldUnsigned,198,214,(byte)0x42);
        var forkField=ContactField.verify(ContactField.produceSoftware(rootKey,s2,expected,forkFieldUnsigned,new AtomicBoolean()).bytes(),s2,contact,routing);
        System.arraycopy(forkField.digest(),0,forkUnsigned,272,32);
        var fork=ContactField.Mutation.produceSoftware(rootKey,s2,expected,forkUnsigned,0,create,s1,List.of(forkField),new AtomicBoolean());
        if(args.length>3 && args[3].equals("--partial")){try(var file=FileChannel.open(path,StandardOpenOption.WRITE,StandardOpenOption.APPEND)){file.write(ByteBuffer.wrap(new byte[]{0,0}));file.force(true);Runtime.getRuntime().halt(19);}return;}
        if(args.length>3 && args[3].equals("--seed")){var j=ContactHistory.create(path,pin,fingerprint,account,origin,8,List.of(first),10000);j.accept(null,List.of(first),create,s1);System.out.println("Seeded revision one");return;}
        if(args.length>3 && args[3].equals("--advance")){var j=ContactHistory.open(path,pin,fingerprint,account,origin,8,false);var holder=j.lookup(contact).token();try{j.accept(holder,List.of(first,second),update,s2);System.out.println("CAS won");}catch(GeneralSecurityException e){System.err.println(e.getMessage());System.exit(3);}return;}
        if(args.length>3 && args[3].equals("--compete")){var j=ContactHistory.open(path,pin,fingerprint,account,origin,8,false);var holder=j.lookup(contact).token();
            try{j.accept(holder,List.of(first,second),fork,s2);System.out.println("unexpected fork win");}catch(GeneralSecurityException e){System.err.println(e.getMessage());System.exit(3);}return;}
        if(args.length>3 && args[3].equals("--digest")){System.out.println(ContactHistory.fileDigest(path));return;}
        if(args.length>3 && args[3].equals("--verify")){var j=ContactHistory.open(path,pin,fingerprint,account,origin,8,false);if(j.lookup(contact).metadata().revision()!=2)throw new AssertionError("Child CAS state");System.out.println("Restart CAS verified");return;}
        if(args.length>3 && args[3].equals("--refused")){refuse(()->ContactHistory.open(path,pin,fingerprint,account,origin,8,false));System.out.println("Interrupted append refused");return;}
        refuse(()->ContactHistory.open(path,pin,fingerprint,account,origin,8,false));
        var j=ContactHistory.create(path,pin,fingerprint,account,origin,8,List.of(first),10000);
        refuse(()->ContactHistory.create(path,pin,fingerprint,account,origin,8,List.of(first),10000));
        byte[] wrongFp=fingerprint.clone();wrongFp[0]^=1;
        refuse(()->ContactHistory.open(path,pin,wrongFp,account,origin,8,false));
        byte[] wrongAccount=account.clone();wrongAccount[0]^=1;
        refuse(()->ContactHistory.open(path,pin,fingerprint,wrongAccount,origin,8,false));
        if(!j.lookup(contact).reason().equals("unobserved"))throw new AssertionError("Unobserved");checks++;
        refuse(()->j.accept(null,List.of(first),update,s2));
        var fresh=ContactHistory.create(path.resolveSibling("cold.dat"),pin,fingerprint,account,origin,8,List.of(first,second),10000);
        refuse(()->fresh.accept(null,List.of(first,second),update,s2));
        fresh.close();java.nio.file.Files.delete(path.resolveSibling("cold.dat"));
        var saved=j.accept(null,List.of(first),create,s1);
        if(!saved.accepted() || saved.metadata().revision()!=1)throw new AssertionError("Cold create");
        var holder=saved.token();
        var replay=j.accept(holder,List.of(first),create,s1);
        if(!replay.accepted() || replay.metadata().revision()!=1)throw new AssertionError("Replay");
        refuse(()->j.accept(null,List.of(first),create,s1));
        var advanced=j.accept(holder,List.of(first,second),fork,s2);
        if(!advanced.accepted() || advanced.metadata().revision()!=2 || advanced.metadata().manifestVersion()!=2)throw new AssertionError("Root advance");
        refuse(()->j.accept(advanced.token(),List.of(first,second),update,s2));
        var reduced=ContactHistory.open(path,pin,fingerprint,account,origin,8,true);
        var reducedRow=reduced.lookup(contact);
        if(reducedRow.accepted() || !reducedRow.reason().equals("reduction_only"))throw new AssertionError("Reduction lookup");
        refuse(()->reduced.accept(reducedRow.token(),List.of(first,second),update,s2));
        if(reduced.markUnavailable(reducedRow.token()).reason().equals("local_stop"))checks++;else throw new AssertionError("Reduction stop");
        reduced.close();
        refuse(()->j.markUnavailable(advanced.token()));
        if(!j.lookup(contact).reason().equals("local_stop"))throw new AssertionError("Terminal lookup");
        refuse(()->j.accept(j.lookup(contact).token(),List.of(first,second),clear,s2));
        j.close();
        refuse(()->j.lookup(contact));
        var reopened=ContactHistory.open(path,pin,fingerprint,account,origin,8,false);
        if(!reopened.lookup(contact).reason().equals("local_stop"))throw new AssertionError("Terminal restart");
        refuse(()->reopened.accept(holder,List.of(first,second),update,s2));
        reopened.close();
        byte[] other=contact.clone();other[0]^=1;
        var expectedOther=new ContactField.Expected(account,origin,fingerprint,other,routing,parser);
        byte[] otherNameUnsigned=edit(java.util.Arrays.copyOf(d(f,"name"),d(f,"name").length-64),22,other);java.util.Arrays.fill(otherNameUnsigned,198,214,(byte)66);
        byte[] otherNotesUnsigned=edit(java.util.Arrays.copyOf(d(f,"notes"),d(f,"notes").length-64),22,other);java.util.Arrays.fill(otherNotesUnsigned,198,214,(byte)66);
        var otherName=ContactField.verify(ContactField.produceSoftware(rootKey,s1,expectedOther,otherNameUnsigned,new AtomicBoolean()).bytes(),s1,other,routing);
        var otherNotes=ContactField.verify(ContactField.produceSoftware(rootKey,s1,expectedOther,otherNotesUnsigned,new AtomicBoolean()).bytes(),s1,other,routing);
        byte[] unsigned=java.util.Arrays.copyOf(d(f,"create"),304);
        System.arraycopy(other,0,unsigned,22,16);java.util.Arrays.fill(unsigned,54,70,(byte)66);
        System.arraycopy(otherName.digest(),0,unsigned,231,32);System.arraycopy(otherNotes.digest(),0,unsigned,272,32);
        var otherCreate=ContactField.Mutation.produceSoftware(rootKey,s1,expectedOther,unsigned,0,null,null,List.of(otherName,otherNotes),new AtomicBoolean());
        var bounded=ContactHistory.create(path.resolveSibling("bounded.dat"),pin,fingerprint,account,origin,1,List.of(first),10000);
        bounded.accept(null,List.of(first),create,s1);
        refuse(()->bounded.accept(null,List.of(first),otherCreate,s1));
        bounded.close();
        byte[] bytes=Files.readAllBytes(path);Path bad=path.resolveSibling(path.getFileName()+".bad");
        for(int at:new int[]{0,4,98,130,161,bytes.length-33,bytes.length-1}){byte[] copy=bytes.clone();copy[at]^=1;Files.write(bad,copy);refuse(()->ContactHistory.open(bad,pin,fingerprint,account,origin,8,false));}
        Files.delete(bad);Files.deleteIfExists(path.resolveSibling("bounded.dat"));
        System.out.println("Java contact history "+checks+" controls passed");
    }
}
