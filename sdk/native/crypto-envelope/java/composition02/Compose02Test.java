package org.zrotext.candidate;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public final class Compose02Test {
    private Compose02Test(){}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean v){if(!v)throw new AssertionError("Composition02 assertion");checks++;}
    static void refuses(Attempt action)throws Exception{try{action.run();}catch(GeneralSecurityException|IllegalArgumentException expected){checks++;return;}throw new AssertionError("Invalid composition02 accepted");}
    static void emit(byte[] b){System.out.println("ENVELOPE "+Base64.getEncoder().encodeToString(b));}
    static Compose02.Request change(Compose02.Request r,byte[] message,byte[] device,byte[] line,long now,long observed,long expires,String peer,String content,List<Compose02.Recipient> recipients){return new Compose02.Request(r.manifest(),now,message,device,line,observed,expires,peer,content,r.signer(),recipients);}
    public static void main(String[] args)throws Exception{
        if(args.length==4 && args[0].equals("--replay")){
            Map<String,byte[]> f=new HashMap<>();for(String line:Files.readAllLines(Path.of(args[2]))){String[] v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}
            var m=ManifestChain.genesis02(f.get("manifest"),ManifestChain.RootPin.enroll(f.get("rootPin"),f.get("fingerprint")),10000);byte[] point=Arrays.stream(m.keyRecords()).filter(k->k[0]==5).findFirst().orElseThrow();
            try(var signer=ProtectedSigner.open(Files.readString(Path.of(args[1])).trim(),Arrays.copyOfRange(point,33,98))){var targets=new ArrayList<Compose02.Recipient>();for(var k:m.keyRecords())if(k[0]==1 || k[0]==2)targets.add(new Compose02.Recipient(k[0],Arrays.copyOfRange(k,1,33)));byte[] id=new byte[16];Arrays.fill(id,(byte)49);
                var r=new Compose02.Request(m,10000,id,f.get("device"),f.get("line"),10000,20000,"+12","Native composed02 \uD83C\uDF31",signer,targets);
                check(Arrays.equals(f.get("expected"),Compose02.composeOrReplay(Path.of(args[3]),f.get("rootPin"),f.get("fingerprint"),r,()->new Compose02.Current(m,11000))));
            }return;
        }
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedSigner.probe();}catch(GeneralSecurityException e){System.exit(77);}return;}
        if(args.length!=1)throw new IllegalArgumentException("Pending receipt required");Path receipt=Path.of(args[0]);ProtectedSigner owner=null;boolean deleted=false;
        try{
            owner=ProtectedSigner.create(name->{try(var f=FileChannel.open(receipt,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,StandardOpenOption.SYNC)){var b=StandardCharsets.UTF_8.encode(name+"\n");while(b.hasRemaining())f.write(b);f.force(true);}});final var signer=owner;System.out.println(HexFormat.of().formatHex(signer.publicPoint()));System.out.flush();
            Map<String,byte[]> f=new HashMap<>();for(String line:new String(System.in.readAllBytes(),StandardCharsets.UTF_8).lines().toList()){String[] v=line.split("\t");f.put(v[0],HexFormat.of().parseHex(v[1]));}
            var manifest=ManifestChain.genesis02(f.get("manifest"),ManifestChain.RootPin.enroll(f.get("rootPin"),f.get("fingerprint")),10000);var recipients=new ArrayList<Compose02.Recipient>();for(var k:manifest.keyRecords())if(k[0]==1 || k[0]==2)recipients.add(new Compose02.Recipient(k[0],Arrays.copyOfRange(k,1,33)));
            byte[] message=new byte[16];Arrays.fill(message,(byte)49);var r=new Compose02.Request(manifest,10000,message,f.get("device"),f.get("line"),10000,20000,"+12","Native composed02 \uD83C\uDF31",signer,recipients);
            byte[] first=Compose02.fresh(r),second=Compose02.fresh(r);check(!Arrays.equals(first,second));emit(first);emit(second);emit(Compose02.fresh(change(r,new byte[16],r.device(),r.line(),10000,0,1,r.peer(),r.content(),recipients)));
            for(byte[] id:new byte[][]{new byte[0],new byte[15]})refuses(()->Compose02.fresh(change(r,id,r.device(),r.line(),10000,10000,20000,r.peer(),r.content(),recipients)));
            refuses(()->Compose02.fresh(change(r,message,new byte[16],r.line(),10000,10000,20000,r.peer(),r.content(),recipients)));refuses(()->Compose02.fresh(change(r,message,r.device(),new byte[16],10000,10000,20000,r.peer(),r.content(),recipients)));
            for(long now:new long[]{9999,100000})refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),now,10000,20000,r.peer(),r.content(),recipients)));
            refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),10000,-1,20000,r.peer(),r.content(),recipients)));
            for(long expiry:new long[]{10000,910001})refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),10000,10000,expiry,r.peer(),r.content(),recipients)));
            refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),10000,10000,20000,"+01",r.content(),recipients)));
            for(String text:new String[]{"","\ufeffbad","bad\0","\ud800","x".repeat(32769)})refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),10000,10000,20000,r.peer(),text,recipients)));
            for(var targets:List.of(recipients.subList(0,1),List.of(recipients.get(0),recipients.get(0)),List.of(new Compose02.Recipient(1,new byte[32]),recipients.get(1))))refuses(()->Compose02.fresh(change(r,message,r.device(),r.line(),10000,10000,20000,r.peer(),r.content(),targets)));
            Path journal=Files.createTempFile("zrotext-retry02-",".journal");Files.delete(journal);
            try{
                long[] now={10000};Compose02.CurrentSource current=()->new Compose02.Current(manifest,now[0]);
                byte[] committed=Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current);emit(committed);
                check(Arrays.equals(committed,Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current)));
                now[0]=11000;check(Arrays.equals(committed,Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current)));now[0]=10000;
                refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current));now[0]=11000;
                refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,null));
                refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),change(r,message,r.device(),r.line(),10000,10000,20000,r.peer(),"changed",recipients),current));
                refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),change(r,message,r.device(),r.line(),10000,0,20000,r.peer(),r.content(),recipients),current));
                now[0]=20000;refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current));now[0]=11000;
                var retained=ManifestChain.continueChain(f.get("currentRetained"),manifest,2,11000);var revoked=ManifestChain.continueChain(f.get("currentRevoked"),manifest,2,11000);
                check(Arrays.equals(committed,Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,()->new Compose02.Current(retained,11000))));refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,()->new Compose02.Current(revoked,11000)));
                Path fixture=Files.createTempFile("zrotext-retry-fixture-",".tsv");try{var lines=new ArrayList<String>();for(var entry:f.entrySet())lines.add(entry.getKey()+"\t"+HexFormat.of().formatHex(entry.getValue()));lines.add("expected\t"+HexFormat.of().formatHex(committed));Files.write(fixture,lines);var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),Compose02Test.class.getName(),"--replay",receipt.toString(),fixture.toString(),journal.toString()).inheritIO().start();check(child.waitFor()==0);}finally{Files.delete(fixture);}
                byte[] stable=Files.readAllBytes(journal);Files.write(journal,new byte[]{1},StandardOpenOption.APPEND);refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current));Files.write(journal,stable);
                var pool=java.util.concurrent.Executors.newFixedThreadPool(2);try{var a=pool.submit(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current));var b=pool.submit(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current));check(Arrays.equals(a.get(),b.get()));}finally{pool.shutdown();}
                var rotated=ManifestChain.rotate02(f.get("transition"),f.get("newManifest"),manifest,f.get("newPoint"),11000);var rotatedRequest=new Compose02.Request(rotated,11000,message,r.device(),r.line(),10000,20000,r.peer(),r.content(),signer,recipients);
                refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,()->new Compose02.Current(rotated,11000)));
                Files.delete(journal);byte[] rotatedBytes=Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),rotatedRequest,()->new Compose02.Current(rotated,11000));check(Arrays.equals(rotatedBytes,Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),rotatedRequest,()->new Compose02.Current(rotated,11000))));System.out.println("ROTATED "+Base64.getEncoder().encodeToString(rotatedBytes));
                Files.delete(journal);int[] calls={0};refuses(()->Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,()->{if(++calls[0]==6)throw new GeneralSecurityException("Simulated postcommit authority loss");return new Compose02.Current(manifest,11000);}));
                check(calls[0]==6);byte[] saved=Files.readAllBytes(journal);check(Arrays.equals(Compose02.composeOrReplay(journal,f.get("rootPin"),f.get("fingerprint"),r,current),Arrays.copyOfRange(saved,270,saved.length-32)));
            }finally{Files.deleteIfExists(journal);}
            refuses(()->signer.signEnvelope03(Arrays.copyOf(first,first.length-64)));refuses(()->signer.signEnvelope02(new byte[493]));signer.deleteCreated();deleted=true;refuses(()->Compose02.fresh(r));Files.delete(receipt);
            System.out.println("QUALIFIED: "+checks+" native Java profile02 composition checks passed; owned key deleted");
        }finally{if(owner!=null){try{if(!deleted){owner.deleteCreated();Files.delete(receipt);}}finally{owner.close();}}}
    }
}
