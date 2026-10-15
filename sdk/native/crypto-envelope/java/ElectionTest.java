package org.zrotext.candidate;
import java.util.*;
import java.security.GeneralSecurityException;

public final class ElectionTest {
    private ElectionTest() {}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException expected){checks++;return;}throw new AssertionError("Invalid election accepted");}
    public static void main(String[] args)throws Exception{
        Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
        Scanner input=new Scanner(System.in);while(input.hasNextLine()){
            String[] f=input.nextLine().split("\t");Object value=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);
            if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),value);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),value);else wire.put(f[0],(byte[])value);
        }
        var pin=ManifestChain.RootPin.enroll(wire.get("rootPin"),wire.get("fingerprint"));
        var prior=ManifestChain.genesis02(wire.get("signed02"),pin,10000);
        var proof=Election03.verify(wire.get("bundle"),wire.get("core"),accepted,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint"));
        var current=Election03.requireCurrent(proof,proof.acceptedManifest(),authority,30000);
        check(current.number("manifestVersion")==2);check(Arrays.equals(current.field("accountId"),prior.account()));
        byte[] exposed=current.field("accountId");exposed[0]^=1;check(Arrays.equals(current.field("accountId"),prior.account()));
        for(String name:authority.keySet()){
            Map<String,Object> changed=new HashMap<>(authority);Object value=changed.get(name);
            if(value instanceof byte[]){byte[] b=((byte[])value).clone();b[0]^=1;changed.put(name,b);}else changed.put(name,0L);
            refuses(()->Election03.requireCurrent(proof,proof.acceptedManifest(),changed,30000));
        }
        refuses(()->Election03.requireCurrent(proof,prior,authority,30000));
        refuses(()->Election03.requireCurrent(proof,proof.acceptedManifest(),authority,0));
        refuses(()->Election03.requireCurrent(proof,proof.acceptedManifest(),authority,60000));
        for(int at:new int[]{0,56,72,88,136,184,256,288,320,352,384,400,432,464,496,500,564,627}){
            byte[] changed=wire.get("bundle").clone();changed[at]^=1;
            refuses(()->Election03.verify(changed,wire.get("core"),accepted,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint")));
        }
        for(String name:accepted.keySet()){
            Map<String,Object> changed=new HashMap<>(accepted);Object value=changed.get(name);
            if(value instanceof byte[]){byte[] b=((byte[])value).clone();b[0]^=1;changed.put(name,b);}else changed.put(name,0L);
            // newBindingId is authenticated commit-only data absent from the signed core.
            if(name.equals("newBindingId"))continue;
            refuses(()->Election03.verify(wire.get("bundle"),wire.get("core"),changed,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint")));
        }
        for(int at:new int[]{500,564}){
            byte[] changed=wire.get("bundle").clone();changed[at]^=1;Map<String,Object> rebound=new HashMap<>(accepted);
            rebound.put("electionBundleSha256",java.security.MessageDigest.getInstance("SHA-256").digest(changed));
            refuses(()->Election03.verify(changed,wire.get("core"),rebound,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint")));
        }
        ((byte[])accepted.get("accountId"))[0]^=1;
        check(Arrays.equals(Election03.requireCurrent(proof,proof.acceptedManifest(),authority,30000).field("accountId"),prior.account()));
        System.out.println(checks+" election checks passed");
    }
}
