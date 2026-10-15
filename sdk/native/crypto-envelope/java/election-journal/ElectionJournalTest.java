package org.zrotext.candidate;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
public final class ElectionJournalTest {
    private ElectionJournalTest(){}
    interface Attempt{void run()throws Exception;}static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Election journal assertion");checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException|IllegalArgumentException|java.io.IOException expected){checks++;return;}throw new AssertionError("Election journal should refuse");}
    public static void main(String[] args)throws Exception{
        Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
        String rawInput=new String(System.in.readAllBytes(),StandardCharsets.UTF_8);Scanner input=new Scanner(rawInput);while(input.hasNextLine()){
            String[] f=input.nextLine().split("\t");Object value=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);
            if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),value);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),value);else wire.put(f[0],(byte[])value);
        }
        byte[] externalCore=wire.get("core").clone();var expected=new ElectionJournal.Expectations(externalCore,accepted,wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint"));externalCore[0]^=1;
        if(args.length==1){var restored=new ElectionJournal(Path.of(args[0]),wire.get("rootPin"),wire.get("fingerprint"),expected).snapshot(30000);check(restored.revision()==2 && restored.proof()!=null);return;}
        Path path=Files.createTempFile("zrotext-election-",".journal");Files.delete(path);
        try{
            var journal=new ElectionJournal(path,wire.get("rootPin"),wire.get("fingerprint"),expected);check(journal.accept(wire.get("signed02"),null,0,10000).revision()==1);
            refuses(()->journal.accept(wire.get("signed03"),null,1,10000));
            for(int at=0;at<628;at++){byte[] changed=wire.get("bundle").clone();changed[at]^=1;refuses(()->journal.accept(wire.get("signed03"),changed,1,((Number)accepted.get("acceptedAtMs")).longValue()));}
            check(journal.snapshot(10000).revision()==1);
            var selected=journal.accept(wire.get("signed03"),wire.get("bundle"),1,((Number)accepted.get("acceptedAtMs")).longValue());check(selected.revision()==2 && selected.proof()!=null);
            var restored=new ElectionJournal(path,wire.get("rootPin"),wire.get("fingerprint"),expected).snapshot(30000);check(restored.manifest().version()==2);
            refuses(()->new ElectionJournal(path,wire.get("rootPin"),wire.get("fingerprint"),null).snapshot(30000));
            var wrong=new HashMap<String,Object>(accepted);byte[] binding=((byte[])wrong.get("newBindingId")).clone();binding[0]^=1;wrong.put("newBindingId",binding);var changedExpected=new ElectionJournal.Expectations(wire.get("core"),wrong,wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint"));refuses(()->new ElectionJournal(path,wire.get("rootPin"),wire.get("fingerprint"),changedExpected).snapshot(30000));
            var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),ElectionJournalTest.class.getName(),path.toString()).redirectError(ProcessBuilder.Redirect.INHERIT).redirectOutput(ProcessBuilder.Redirect.INHERIT).start();try(var stream=child.getOutputStream()){stream.write(rawInput.getBytes(StandardCharsets.UTF_8));}check(child.waitFor()==0);
            var params=AlgorithmParameters.getInstance("EC");params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));var key=KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.ECPrivateKeySpec(new java.math.BigInteger(1,wire.get("readerScalar")),params.getParameterSpec(java.security.spec.ECParameterSpec.class)));
            check(ElectedReader03.openSoftware(wire.get("envelope"),restored.manifest(),restored.proof(),()->new ElectedReader03.AuthoritySnapshot(authority,30000),wire.get("message"),"+12",key).equals(new String(wire.get("text"),StandardCharsets.UTF_8)));
            refuses(()->journal.snapshot(29999));
            byte[] stable=Files.readAllBytes(path);Files.write(path,new byte[]{1},StandardOpenOption.APPEND);refuses(()->journal.snapshot(30000));Files.write(path,stable);byte[] torn=stable.clone();torn[130]^=1;Files.write(path,torn);refuses(()->journal.snapshot(30000));Files.write(path,new byte[0]);refuses(()->journal.snapshot(30000));Files.write(path,stable);
            refuses(()->journal.accept(wire.get("successor"),null,1,30000));
            var pool=java.util.concurrent.Executors.newFixedThreadPool(2);try{var successes=new java.util.concurrent.atomic.AtomicInteger();var tasks=new ArrayList<java.util.concurrent.Future<?>>();for(int i=0;i<2;i++)tasks.add(pool.submit(()->{try{journal.accept(wire.get("successor"),null,2,30000);successes.incrementAndGet();}catch(GeneralSecurityException expectedFailure){}catch(Exception failure){throw new RuntimeException(failure);}}));for(var task:tasks)task.get();check(successes.get()==1);}finally{pool.shutdown();}
            check(journal.snapshot(30000).manifest().version()==3);refuses(()->journal.accept(wire.get("signed02"),null,3,30000));refuses(()->journal.accept(wire.get("signed03"),wire.get("bundle"),3,30000));
            journal.snapshot(30001);refuses(()->new ElectionJournal(path,wire.get("rootPin"),wire.get("fingerprint"),expected).snapshot(30000));
            Path lifecycle=Files.createTempFile("zrotext-election-lifecycle-",".journal");Files.delete(lifecycle);try{
                var live=new ElectionJournal(lifecycle,wire.get("rootPin"),wire.get("fingerprint"),expected);live.accept(wire.get("signed02"),null,0,10000);var active=live.accept(wire.get("signed03"),wire.get("bundle"),1,((Number)accepted.get("acceptedAtMs")).longValue());int[] calls={0};
                refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),active.manifest(),active.proof(),()->{try{var now=live.snapshot(30000);if(!Arrays.equals(now.manifest().digest(),active.manifest().digest()))throw new GeneralSecurityException("Selection changed");if(++calls[0]==1)live.accept(wire.get("successor"),null,2,30000);return new ElectedReader03.AuthoritySnapshot(authority,30000);}catch(java.io.IOException|InterruptedException e){throw new GeneralSecurityException(e);}},wire.get("message"),"+12",key));check(calls[0]==1 && live.snapshot(30000).revision()==3);
            }finally{Files.deleteIfExists(lifecycle);}
            System.out.println(checks+" Java durable election checks passed");
        }finally{Files.deleteIfExists(path);}
    }
}
