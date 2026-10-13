package org.zrotext.candidate;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public final class ComposeTest {
    private ComposeTest(){}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Composition assertion");checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException|IllegalArgumentException expected){checks++;return;}throw new AssertionError("Invalid composition accepted");}
    record Data(Map<String,byte[]> wire,Map<String,Object> accepted,Map<String,Object> authority){}
    static Data parse(String input){
        Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
        for(String line:input.lines().toList()){String[] f=line.split("\t");Object v=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),v);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),v);else wire.put(f[0],(byte[])v);}return new Data(wire,accepted,authority);
    }
    static Compose03.Request inputs(Data d,ProtectedSigner signer)throws Exception{
        var w=d.wire;var prior=ManifestChain.genesis02(w.get("signed02"),ManifestChain.RootPin.enroll(w.get("rootPin"),w.get("fingerprint")),10000);
        var proof=Election03.verify(w.get("bundle"),w.get("core"),d.accepted,prior,w.get("signed02"),w.get("signed03"),w.get("deviceSigningPoint"),w.get("ownerApprovalPoint"));
        var recipients=new ArrayList<Compose03.Recipient>();for(var k:proof.acceptedManifest().keyRecords())if(k[0]==1 || k[0]==2)recipients.add(new Compose03.Recipient(k[0],Arrays.copyOfRange(k,1,33)));
        return new Compose03.Request(proof.acceptedManifest(),proof,()->new ElectedReader03.AuthoritySnapshot(d.authority,30000),w.get("message"),30000,40000,"+12","Native composed \uD83C\uDF31",signer,recipients);
    }
    static Compose03.Request changed(Compose03.Request r,byte[] message,long observed,long expires,String peer,String content,ElectedReader03.AuthoritySource source,List<Compose03.Recipient> recipients){return new Compose03.Request(r.manifest(),r.proof(),source,message,observed,expires,peer,content,r.signer(),recipients);}
    static Compose03.Request withClock(Compose03.Request r,Data d,long now){return changed(r,r.message(),r.observedMs(),r.expiresMs(),r.peer(),r.content(),()->new ElectedReader03.AuthoritySnapshot(d.authority,now),r.recipients());}
    static byte[] randomMessage(){byte[] b=new byte[16];new SecureRandom().nextBytes(b);return b;}
    static void emit(byte[] envelope){System.out.println("ENVELOPE "+Base64.getEncoder().encodeToString(envelope));}
    public static void main(String[] args)throws Exception{
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedSigner.probe();}catch(GeneralSecurityException e){System.exit(77);}return;}
        if((args.length==5 || args.length==6) && args[0].equals("--replay")){Data d=parse(Files.readString(Path.of(args[1])));try(var signer=ProtectedSigner.open(args[3],HexFormat.of().parseHex(args[4]))){System.out.println(Base64.getEncoder().encodeToString(Compose03.composeOrReplay(Path.of(args[2]),d.wire.get("rootPin"),d.wire.get("fingerprint"),withClock(inputs(d,signer),d,args.length==6?Long.parseLong(args[5]):30000))));}return;}
        if(args.length!=1)throw new IllegalArgumentException("Pending receipt required");Path receipt=Path.of(args[0]),folder=Files.createTempDirectory("zrotext-java-compose-");ProtectedSigner owner=null;boolean deleted=false;
        try{
            owner=ProtectedSigner.create(alias->{try(var f=FileChannel.open(receipt,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,StandardOpenOption.SYNC)){var b=StandardCharsets.UTF_8.encode(alias+"\n");while(b.hasRemaining())f.write(b);f.force(true);}});final var signer=owner;byte[] point=signer.publicPoint();check(point.length==65);System.out.println(HexFormat.of().formatHex(point));System.out.flush();
            try(var reopened=ProtectedSigner.open(signer.alias(),point)){check(Arrays.equals(reopened.publicPoint(),point));refuses(reopened::deleteCreated);}refuses(()->signer.signEnvelope03(new byte[493]));
            var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));var other=(java.security.interfaces.ECPublicKey)generator.generateKeyPair().getPublic();byte[] wrong=new byte[65];wrong[0]=4;byte[] x=other.getW().getAffineX().toByteArray(),y=other.getW().getAffineY().toByteArray();int nx=Math.min(32,x.length),ny=Math.min(32,y.length);System.arraycopy(x,x.length-nx,wrong,33-nx,nx);System.arraycopy(y,y.length-ny,wrong,65-ny,ny);refuses(()->{try(var unexpected=ProtectedSigner.open(signer.alias(),wrong)){unexpected.publicPoint();}});
            String raw=new String(System.in.readAllBytes(),StandardCharsets.UTF_8);Data d=parse(raw);var r=inputs(d,signer);byte[] pin=d.wire.get("rootPin"),fingerprint=d.wire.get("fingerprint");
            byte[] first=Compose03.fresh(r),second=Compose03.fresh(r);check(!Arrays.equals(first,second));emit(first);emit(second);
            for(String text:new String[]{"","\ufeffbad","bad\0","\ud800","x".repeat(32769)})refuses(()->Compose03.fresh(changed(r,r.message(),30000,40000,r.peer(),text,r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,new byte[16],30000,40000,r.peer(),r.content(),r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,r.message(),8000,40000,r.peer(),r.content(),r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,r.message(),30001,40000,r.peer(),r.content(),r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,r.message(),30000,60001,r.peer(),r.content(),r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,r.message(),30000,40000,"+01",r.content(),r.authority(),r.recipients())));
            refuses(()->Compose03.fresh(changed(r,r.message(),30000,40000,r.peer(),r.content(),r.authority(),r.recipients().subList(0,1))));
            var duplicate=new ArrayList<>(r.recipients());duplicate.addAll(r.recipients());refuses(()->Compose03.fresh(changed(r,r.message(),30000,40000,r.peer(),r.content(),r.authority(),duplicate)));
            Map<String,Object> revoked=new HashMap<>(d.authority);revoked.put("bindingGeneration",99L);ElectedReader03.AuthoritySource bad=()->new ElectedReader03.AuthoritySnapshot(revoked,30000);
            refuses(()->Compose03.fresh(changed(r,r.message(),30000,40000,r.peer(),r.content(),bad,r.recipients())));
            int[] calls={0};var expires=changed(r,r.message(),30000,40000,r.peer(),r.content(),()->new ElectedReader03.AuthoritySnapshot(d.authority,++calls[0]==1?30000:40000),r.recipients());refuses(()->Compose03.fresh(expires));check(calls[0]==2);
            Path journal=folder.resolve("outbound.bin");byte[] committed=Compose03.composeOrReplay(journal,pin,fingerprint,r);check(Arrays.equals(committed,Compose03.composeOrReplay(journal,pin,fingerprint,r)));emit(committed);
            refuses(()->Compose03.composeOrReplay(journal,pin,fingerprint,changed(r,r.message(),30000,40000,r.peer(),"different",r.authority(),r.recipients())));
            refuses(()->Compose03.composeOrReplay(journal,pin,fingerprint,changed(r,r.message(),30000,40000,r.peer(),r.content(),bad,r.recipients())));
            Path context=folder.resolve("context.tsv");Files.writeString(context,raw);var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),ComposeTest.class.getName(),"--replay",context.toString(),journal.toString(),signer.alias(),HexFormat.of().formatHex(point)).start();String out=new String(child.getInputStream().readAllBytes(),StandardCharsets.UTF_8),error=new String(child.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(child.waitFor()!=0)throw new AssertionError("Replay process failed: "+error);check(Arrays.equals(Base64.getDecoder().decode(out.trim()),committed));
            var concurrent=changed(r,randomMessage(),30000,40000,r.peer(),r.content(),r.authority(),r.recipients());var pool=Executors.newFixedThreadPool(2);try{var a=pool.submit(()->Compose03.composeOrReplay(journal,pin,fingerprint,concurrent));var b=pool.submit(()->Compose03.composeOrReplay(journal,pin,fingerprint,concurrent));check(Arrays.equals(a.get(),b.get()));}finally{pool.shutdown();}
            int[] after={0};byte[] next=randomMessage();var interrupted=changed(r,next,30000,40000,r.peer(),r.content(),()->new ElectedReader03.AuthoritySnapshot(++after[0]==4?revoked:d.authority,30000),r.recipients());refuses(()->Compose03.composeOrReplay(journal,pin,fingerprint,interrupted));check(after[0]==4);long length=Files.size(journal);Compose03.composeOrReplay(journal,pin,fingerprint,changed(r,next,30000,40000,r.peer(),r.content(),r.authority(),r.recipients()));check(Files.size(journal)==length);
            Path partial=folder.resolve("partial.bin");Files.copy(journal,partial);Files.write(partial,new byte[]{1,2,3},StandardOpenOption.APPEND);refuses(()->Compose03.composeOrReplay(partial,pin,fingerprint,r));
            check(Arrays.equals(committed,Compose03.composeOrReplay(journal,pin,fingerprint,withClock(r,d,31000))));
            var rollback=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),ComposeTest.class.getName(),"--replay",context.toString(),journal.toString(),signer.alias(),HexFormat.of().formatHex(point),"30000").start();String rollbackOut=new String(rollback.getInputStream().readAllBytes(),StandardCharsets.UTF_8),rollbackError=new String(rollback.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);check(rollback.waitFor()!=0 && rollbackOut.isEmpty() && rollbackError.contains("Candidate composition refused"));
            check(Arrays.equals(committed,Compose03.composeOrReplay(journal,pin,fingerprint,withClock(r,d,31000))));
            int[] laterCalls={0};var later=changed(r,randomMessage(),30000,40000,r.peer(),r.content(),()->new ElectedReader03.AuthoritySnapshot(d.authority,++laterCalls[0]==4?32000:31000),r.recipients());Compose03.composeOrReplay(journal,pin,fingerprint,later);check(laterCalls[0]==4);
            refuses(()->Compose03.composeOrReplay(journal,pin,fingerprint,withClock(r,d,31000)));
            byte[] torn=Files.readAllBytes(journal);torn[130]^=1;Files.write(partial,torn);refuses(()->Compose03.composeOrReplay(partial,pin,fingerprint,withClock(r,d,32000)));
            byte[] legacy=Files.readAllBytes(journal);legacy[3]=51;Files.write(partial,legacy);refuses(()->Compose03.composeOrReplay(partial,pin,fingerprint,withClock(r,d,32000)));
            String alias=signer.alias();signer.deleteCreated();deleted=true;refuses(()->signer.signEnvelope03(Arrays.copyOf(first,first.length-64)));refuses(()->{try(var unexpected=ProtectedSigner.open(alias,point)){unexpected.publicPoint();}});Files.delete(receipt);
            for(var file:List.of(journal,context,partial))Files.delete(file);Files.delete(folder);System.out.println("QUALIFIED: "+checks+" native Java composition/replay checks passed; owned key deleted");
        }finally{if(owner!=null){try{if(!deleted){owner.deleteCreated();Files.delete(receipt);}}finally{owner.close();}}}
    }
}
