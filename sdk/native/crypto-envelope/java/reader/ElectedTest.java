package org.zrotext.candidate;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class ElectedTest {
    private ElectedTest() {}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError();checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException|IllegalArgumentException expected){checks++;return;}throw new AssertionError("Invalid elected envelope accepted");}
    public static void main(String[] args)throws Exception{
        Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
        Scanner input=new Scanner(System.in);while(input.hasNextLine()){
            String[] f=input.nextLine().split("\t");Object value=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);
            if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),value);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),value);else wire.put(f[0],(byte[])value);
        }
        var prior=ManifestChain.genesis02(wire.get("signed02"),ManifestChain.RootPin.enroll(wire.get("rootPin"),wire.get("fingerprint")),10000);
        var proof=Election03.verify(wire.get("bundle"),wire.get("core"),accepted,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint"));var manifest=proof.acceptedManifest();
        var parameters=AlgorithmParameters.getInstance("EC");parameters.init(new ECGenParameterSpec("secp256r1"));
        var key=KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,wire.get("readerScalar")),parameters.getParameterSpec(ECParameterSpec.class)));
        ElectedReader03.AuthoritySource source=()->new ElectedReader03.AuthoritySnapshot(authority,30000);
        check(ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,source,wire.get("message"),"+12",key).equals(new String(wire.get("text"),StandardCharsets.UTF_8)));
        refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,source,wire.get("message"),"+13",key));
        refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,source,new byte[16],"+12",key));
        int[] calls={0};ElectedReader03.AuthoritySource expires=()->new ElectedReader03.AuthoritySnapshot(authority,++calls[0]==1?30000:40000);
        refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,expires,wire.get("message"),"+12",key));check(calls[0]==2);
        Map<String,Object> revoked=new HashMap<>(authority);revoked.put("selectedReaderKeyId",new byte[32]);
        int[] count={0};ElectedReader03.AuthoritySource revoke=()->new ElectedReader03.AuthoritySnapshot(++count[0]==1?authority:revoked,30000);
        refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,revoke,wire.get("message"),"+12",key));check(count[0]==2);
        refuses(()->ElectedReader03.openSoftware(wire.get("envelope"),manifest,proof,()->new ElectedReader03.AuthoritySnapshot(revoked,30000),wire.get("message"),"+12",null));
        for(int at:new int[]{4,5,10,26,42,58,74,82,114,146,154,164,wire.get("envelope").length-1}){
            byte[] changed=wire.get("envelope").clone();changed[at]^=1;refuses(()->ElectedReader03.openSoftware(changed,manifest,proof,source,wire.get("message"),"+12",key));
        }
        System.out.println(checks+" elected reader checks passed");
    }
}
