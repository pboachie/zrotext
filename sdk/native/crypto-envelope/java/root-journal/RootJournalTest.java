package org.zrotext.candidate;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
public final class RootJournalTest {
    private RootJournalTest(){}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean v){if(!v)throw new AssertionError("Root assertion");checks++;}
    static void refuses(Attempt action)throws Exception{try{action.run();}catch(GeneralSecurityException|IllegalArgumentException|java.io.EOFException expected){checks++;return;}throw new AssertionError("Invalid root history accepted");}
    public static void main(String[] args)throws Exception{
        String input=new String(System.in.readAllBytes(),StandardCharsets.UTF_8);Map<String,byte[]> f=new HashMap<>();long value=0;for(String row:input.lines().toList()){String[] p=row.split("\t");if(p[0].equals("now_ms"))value=Long.parseLong(p[1]);else f.put(p[0],HexFormat.of().parseHex(p[1]));}final long now=value;
        byte[] pin=f.get("old_root_pin_b64"),fp=f.get("old_root_fingerprint_b64"),old=f.get("old_manifest_b64"),transition=f.get("transition_b64"),point=f.get("new_root_point_b64"),fresh=f.get("new_manifest_b64");
        if(args.length==1){var restored=new RootJournal(Path.of(args[0]),pin,fp,Map.of(2L,point)).snapshot(now);check(restored.revision()==2 && restored.manifest().generation()==2);System.out.println("restored");return;}
        var prior=ManifestChain.genesis02(old,ManifestChain.RootPin.enroll(pin,fp),now);var rotated=ManifestChain.rotate02(transition,fresh,prior,point,now);check(rotated.generation()==2 && rotated.version()==1 && !rotated.descendsFrom(prior));check(Arrays.equals(ManifestChain.continueChain(fresh,rotated,2,now).digest(),rotated.digest()));
        refuses(()->ManifestChain.continueChain(fresh,prior,2,now));refuses(()->ManifestChain.genesis02(fresh,ManifestChain.RootPin.enroll(pin,fp),now));refuses(()->ManifestChain.RootPin.enroll(f.get("new_root_pin_b64"),f.get("new_root_fingerprint_b64")));
        for(byte[] expected:new byte[][]{prior.rootPoint(),new byte[65]})refuses(()->ManifestChain.rotate02(transition,fresh,prior,expected,now));refuses(()->ManifestChain.rotate02(transition,fresh,prior,point,now-1));refuses(()->ManifestChain.rotate02(transition,old,prior,point,now));
        for(int kind=0;kind<2;kind++){byte[] bytes=kind==0?transition:fresh;for(int at=0;at<bytes.length;at++){byte[] changed=bytes.clone();changed[at]^=1;final int target=kind;refuses(()->ManifestChain.rotate02(target==0?changed:transition,target==1?changed:fresh,prior,point,now));}}
        var order=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);for(int at:new int[]{215,279}){byte[] changed=transition.clone(),high=order.subtract(new BigInteger(1,Arrays.copyOfRange(changed,at+32,at+64))).toByteArray();System.arraycopy(high,high.length-32,changed,at+32,32);refuses(()->ManifestChain.rotate02(changed,fresh,prior,point,now));}
        Path folder=Files.createTempDirectory("zrotext-root-journal-"),path=folder.resolve("roots.bin"),copy=folder.resolve("copy.bin");
        try{
            byte[] mutable=point.clone();var store=new RootJournal(path,pin,fp,Map.of(2L,mutable));Arrays.fill(mutable,(byte)0);check(store.accept(old,null,0,now).revision()==1);byte[] before=Files.readAllBytes(path);refuses(()->store.accept(old,transition,1,now));check(Arrays.equals(Files.readAllBytes(path),before));
            var pool=Executors.newFixedThreadPool(2);try{Callable<Boolean> attempt=()->{try{store.accept(fresh,transition,1,now);return true;}catch(GeneralSecurityException conflict){return false;}};var a=pool.submit(attempt);var b=pool.submit(attempt);check(a.get()!=b.get());}finally{pool.shutdown();}
            var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),RootJournalTest.class.getName(),path.toString()).start();child.getOutputStream().write(input.getBytes(StandardCharsets.UTF_8));child.getOutputStream().close();String out=new String(child.getInputStream().readAllBytes(),StandardCharsets.UTF_8),error=new String(child.getErrorStream().readAllBytes(),StandardCharsets.UTF_8);if(child.waitFor()!=0)throw new AssertionError(error);check(out.trim().equals("restored"));
            refuses(()->new RootJournal(path,pin,fp,Map.of()).snapshot(now));refuses(()->new RootJournal(path,pin,fp,Map.of(2L,prior.rootPoint())).snapshot(now));check(store.snapshot(now+1).manifest().generation()==2);refuses(()->new RootJournal(path,pin,fp,Map.of(2L,point)).snapshot(now));
            Files.copy(path,copy);Files.write(copy,new byte[]{1,2,3},StandardOpenOption.APPEND);refuses(()->new RootJournal(copy,pin,fp,Map.of(2L,point)).snapshot(now+1));byte[] damaged=Files.readAllBytes(path);damaged[130]^=1;Files.write(copy,damaged);refuses(()->new RootJournal(copy,pin,fp,Map.of(2L,point)).snapshot(now+1));Files.write(copy,new byte[0]);refuses(()->new RootJournal(copy,pin,fp,Map.of(2L,point)).snapshot(now+1));
            Path dynamic=folder.resolve("dynamic.bin");var nativeStore=new RootJournal(dynamic,f.get("dynamic.rootPin"),f.get("dynamic.fingerprint"),Map.of(2L,f.get("dynamic.newPoint")));
            var oldValue=nativeStore.accept(f.get("dynamic.manifest"),null,0,10000).manifest();var newValue=nativeStore.accept(f.get("dynamic.newManifest"),f.get("dynamic.transition"),1,11000).manifest();nativeStore.accept(f.get("dynamic.newSuccessor"),null,2,11000);
            var selected=new RootJournal(dynamic,f.get("dynamic.rootPin"),f.get("dynamic.fingerprint"),Map.of(2L,f.get("dynamic.newPoint"))).snapshot(11000).manifest();var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));var key=KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,f.get("dynamic.archiveScalar")),parameters.getParameterSpec(ECParameterSpec.class)));
            SealedReader02.CurrentSelection current=(a,v,h,w)->Arrays.equals(a,selected.account()) && v==selected.version() && Arrays.equals(h,selected.digest());check(SealedReader02.openHistoricalArchive(f.get("dynamic.newInbound"),newValue,selected,11000,f.get("dynamic.reader"),key,current).equals(new String(f.get("dynamic.text"),StandardCharsets.UTF_8)));
            int[] called={0};refuses(()->SealedReader02.openHistoricalArchive(f.get("dynamic.inbound"),oldValue,selected,11000,f.get("dynamic.reader"),key,(a,v,h,w)->{called[0]++;return true;}));check(called[0]==0);refuses(()->SealedReader02.openHistoricalArchive(f.get("dynamic.newInbound"),newValue,selected,11000,f.get("dynamic.reader"),key,(a,v,h,w)->false));Path changing=folder.resolve("changing.bin");var liveStore=new RootJournal(changing,f.get("dynamic.rootPin"),f.get("dynamic.fingerprint"),Map.of(2L,f.get("dynamic.newPoint")));liveStore.accept(f.get("dynamic.manifest"),null,0,10000);liveStore.accept(f.get("dynamic.newManifest"),f.get("dynamic.transition"),1,11000);int[] callbacks={0};
            SealedReader02.CurrentSelection live=(a,v,h,w)->{try{if(++callbacks[0]==2)liveStore.accept(f.get("dynamic.newSuccessor"),null,2,11000);var actual=liveStore.snapshot(11000).manifest();return Arrays.equals(a,actual.account()) && v==actual.version() && Arrays.equals(h,actual.digest());}catch(Exception refused){return false;}};
            refuses(()->SealedReader02.openHistoricalArchive(f.get("dynamic.newInbound"),newValue,newValue,11000,f.get("dynamic.reader"),key,live));check(callbacks[0]==2);Files.delete(changing);Files.delete(dynamic);
            System.out.println("Java root transition/journal: "+checks+" checks passed");
        }finally{Files.deleteIfExists(path);Files.deleteIfExists(copy);Files.delete(folder);}
    }
}
